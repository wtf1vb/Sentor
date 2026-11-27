// Strategy checker - port of Go app.go checker section (CheckerStart/Stop/
// State/Select, applyStrategy, runStrategyTests, probeHost, bestStrategy).
// Пробы: YouTube (HTTP-задержка) + Discord API/Gateway в трёх режимах
// HTTP/1.1, строго TLS 1.2, строго TLS 1.3 (TSPU режут их по-разному).
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};


use crate::logging::log_add;
use crate::models::{CheckResult, CheckerState};
use crate::paths;
use crate::sysinfo;
use crate::tools::run_hidden;

struct CheckerInner {
    running: bool,
    done: bool,
    auto: bool,
    restore: bool,
    prev: String,
    stop: Option<Arc<AtomicBool>>,
    logs: Vec<String>,
    results: Vec<CheckResult>,
}

static CHECKER: Mutex<CheckerInner> = Mutex::new(CheckerInner {
    running: false,
    done: false,
    auto: false,
    restore: false,
    prev: String::new(),
    stop: None,
    logs: Vec::new(),
    results: Vec::new(),
});

fn clog(s: &str) {
    let mut c = CHECKER.lock().unwrap_or_else(|e| e.into_inner());
    c.logs.push(s.to_string());
}

fn append_result(r: CheckResult) {
    CHECKER.lock().unwrap_or_else(|e| e.into_inner()).results.push(r);
}

fn is_stopped(flag: &Arc<AtomicBool>) -> bool {
    flag.load(Ordering::Relaxed)
}

// sleepOrStop: true = остановлены во время сна
fn sleep_or_stop(d: Duration, flag: &Arc<AtomicBool>) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if is_stopped(flag) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    is_stopped(flag)
}

// CheckerStart запускает проверку всех стратегий.
pub fn checker_start(tools: &Path, auto_select: bool) -> String {
    let was_running = sysinfo::process_running(paths::WINWS_NAME);
    let prev = paths::selected_strategy(tools);
    let flag = {
        let mut c = CHECKER.lock().unwrap_or_else(|e| e.into_inner());
        if c.running {
            return "already".to_string();
        }
        c.running = true;
        c.done = false;
        c.auto = auto_select;
        c.restore = was_running;
        c.prev = prev;
        let flag = Arc::new(AtomicBool::new(false));
        c.stop = Some(flag.clone());
        c.logs = Vec::new();
        c.results = Vec::new();
        flag
    };
    let tools_owned = tools.to_path_buf();
    std::thread::spawn(move || run_strategy_tests(&tools_owned, flag));
    "ok".to_string()
}

// CheckerStop прерывает проверку.
pub fn checker_stop() -> String {
    let mut c = CHECKER.lock().unwrap_or_else(|e| e.into_inner());
    let running = c.running;
    if let Some(f) = c.stop.take() {
        f.store(true, Ordering::Relaxed);
    }
    drop(c);
    if !running {
        return "Проверка и так не идёт".to_string();
    }
    "⏹ Останавливаю…".to_string()
}

// stopCheckerForClose — синхронная уборка при закрытии окна проверки.
pub fn stop_checker_for_close(tools: &Path) {
    let (running, restore, prev) = {
        let mut c = CHECKER.lock().unwrap_or_else(|e| e.into_inner());
        // Читаем restore/prev ДО затирания: restore=false нужен, чтобы поток
        // проверки сам ничего не восстанавливал (иначе — двойной рестарт
        // профиля), а восстановление делает этот обработчик после taskkill.
        // Раньше restore читался уже затёртым → восстановление было мертво.
        let (running, restore, prev) = (c.running, c.restore, c.prev.clone());
        c.restore = false;
        c.auto = false;
        if let Some(f) = c.stop.take() {
            f.store(true, Ordering::Relaxed);
        }
        (running, restore, prev)
    };
    if !running {
        return;
    }
    let _ = run_hidden("taskkill", &["/F", "/IM", paths::WINWS_NAME]);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let still = CHECKER.lock().unwrap_or_else(|e| e.into_inner()).running;
        if !still || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = run_hidden("taskkill", &["/F", "/IM", paths::WINWS_NAME]);
    if !restore || prev.is_empty() {
        return;
    }
    let (dir, ok) = paths::zapret_dir(tools);
    if ok {
        apply_strategy(tools, &dir, &prev);
    }
}

pub fn checker_state(tools: &Path) -> CheckerState {
    let (running, done, logs, results) = {
        let c = CHECKER.lock().unwrap_or_else(|e| e.into_inner());
        (c.running, c.done, c.logs.clone(), c.results.clone())
    };
    CheckerState {
        running,
        done,
        logs,
        results,
        // чтение файла — ВНЕ мьютекса: диск под CHECKER блокировал бы все
        // операции чекера (и наоборот) на каждый опрос UI
        selected: paths::selected_strategy(tools),
    }
}

// applyStrategy перезапускает winws с выбранным профилем и запоминает выбор.
pub fn apply_strategy(tools: &Path, dir: &Path, name: &str) -> String {
    // имя может прийти с фронтенда (checker_select) — без валидации
    // `cmd /c` запускал произвольный .bat на диске
    if !paths::valid_strategy_name(dir, name) {
        return "❌ Недопустимое имя стратегии".to_string();
    }
    let bat = dir.join(name);
    if !bat.exists() {
        return "❌ Стратегия не найдена".to_string();
    }
    let _ = run_hidden("taskkill", &["/F", "/IM", paths::WINWS_NAME]);
    std::thread::sleep(Duration::from_millis(500));
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new("cmd");
    cmd.args(["/c", &bat.display().to_string()])
        .current_dir(dir)
        .creation_flags(0x08000000)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    log_add("zapret", &format!("применён профиль: {}", name));
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return format!("❌ Ошибка запуска: {}", e),
    };
    if let Some(mut out) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = out.read_to_string(&mut s);
            for line in s.lines() {
                if !line.trim().is_empty() {
                    log_add("zapret", line.trim_end_matches('\r'));
                }
            }
        });
    }
    if let Some(mut err) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = err.read_to_string(&mut s);
            for line in s.lines() {
                if !line.trim().is_empty() {
                    log_add("zapret", line.trim_end_matches('\r'));
                }
            }
        });
    }
    std::thread::spawn(move || {
        let mut c = child;
        let _ = c.wait();
    });
    // Не рапортуем об успехе, пока winws реально не появился.
    for _ in 0..16 {
        std::thread::sleep(Duration::from_millis(500));
        if sysinfo::process_running(paths::WINWS_NAME) {
            crate::tools::save_selected_strategy_pub(tools, name);
            return format!("✅ Профиль выбран и запущен: {}", name);
        }
    }
    let _ = run_hidden("taskkill", &["/F", "/IM", paths::WINWS_NAME]);
    "⚠️ Профиль выбран, но winws не запустился за 8 секунд — смотри панель «Логи»".to_string()
}

// CheckerSelect применяет выбранный профиль.
pub fn checker_select(tools: &Path, name: &str) -> String {
    let running = CHECKER.lock().unwrap_or_else(|e| e.into_inner()).running;
    if running {
        return "❌ Дождись окончания проверки".to_string();
    }
    let (dir, ok) = paths::zapret_dir(tools);
    if !ok {
        return "❌ Zapret не установлен".to_string();
    }
    apply_strategy(tools, &dir, name)
}

fn http_latency(url: &str, timeout: Duration) -> Result<i64, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;
    let t0 = Instant::now();
    let resp = client.get(url).send().map_err(|e| e.to_string())?;
    let mut sink = Vec::new();
    let _ = resp.take(4096).read_to_end(&mut sink);
    Ok(t0.elapsed().as_millis() as i64)
}

// rustls-клиент, зажатый одной версией TLS (для строгих проб T12/T13).
fn pinned_tls_client(version: &'static rustls::SupportedProtocolVersion, timeout: Duration) -> Option<reqwest::blocking::Client> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[version])
        .with_root_certificates(roots)
        .with_no_client_auth();
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .use_preconfigured_tls(config)
        .build()
        .ok()
}

fn http1_client(timeout: Duration) -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .http1_only()
        .build()
        .ok()
}

#[derive(Clone, Copy)]
struct HostProbe {
    http1: bool,
    tls12: bool,
    tls13: bool,
    ms: i64,
}
// ms=-1 в дефолте (не 0!): паника пробы подставляла default с ms=0, и стратегия
// с «0 мс» гарантированно выигрывала автоселект в best_strategy.
impl Default for HostProbe {
    fn default() -> Self {
        HostProbe { http1: false, tls12: false, tls13: false, ms: -1 }
    }
}

// probeHost проверяет хост в трёх режимах — HTTP/1.1, строго TLS 1.2, строго
// TLS 1.3. Возвращает флаги успехов и минимальную задержку среди успешных.
fn probe_host(url: &str, timeout: Duration) -> HostProbe {
    let mut out = HostProbe::default();
    let test = |client: Option<reqwest::blocking::Client>| -> Option<i64> {
        let client = client?;
        let t0 = Instant::now();
        let resp = client.get(url).send().ok()?;
        let mut sink = Vec::new();
        let _ = resp.take(4096).read_to_end(&mut sink);
        Some(t0.elapsed().as_millis() as i64)
    };
    if let Some(d) = test(http1_client(timeout)) {
        out.http1 = true;
        out.ms = d;
    }
    if let Some(d) = test(pinned_tls_client(&rustls::version::TLS12, timeout)) {
        out.tls12 = true;
        if out.ms < 0 || d < out.ms {
            out.ms = d;
        }
    }
    if let Some(d) = test(pinned_tls_client(&rustls::version::TLS13, timeout)) {
        out.tls13 = true;
        if out.ms < 0 || d < out.ms {
            out.ms = d;
        }
    }
    out
}

// tlsMark — компактная строка итогов трёх режимов: HTTP✓ T12✓ T13✗
fn tls_mark(http1: bool, t12: bool, t13: bool) -> String {
    let m = |b: bool| if b { "✓" } else { "✗" };
    format!("HTTP{} T12{} T13{}", m(http1), m(t12), m(t13))
}

// restorePrevious возвращает профиль, выбранный до проверки.
fn restore_previous(tools: &Path) {
    let (restore, prev) = {
        let c = CHECKER.lock().unwrap_or_else(|e| e.into_inner());
        (c.restore, c.prev.clone())
    };
    if !restore {
        return;
    }
    if !prev.is_empty() {
        let (d, ok) = paths::zapret_dir(tools);
        if ok {
            clog(&format!("↩ Возвращаю прежний профиль: {}", prev));
            clog(&apply_strategy(tools, &d, &prev));
            return;
        }
    }
    clog("ℹ️ Прежний профиль не выбран — winws оставлен остановленным");
}

fn finish_stopped(tools: &Path) {
    clog("⏹ Проверка остановлена");
    restore_previous(tools);
}

// bestStrategy — самый быстрый рабочий профиль; каждая закрытая проба
// добавляет штраф 500 мс: приоритет у максимально открытого пути в Discord.
fn best_strategy() -> String {
    let c = CHECKER.lock().unwrap_or_else(|e| e.into_inner());
    let mut best = String::new();
    let mut best_score: i64 = 0;
    for r in &c.results {
        if !r.ok || r.latency_ms < 0 {
            continue;
        }
        let probes = [r.api_http, r.api_tls12, r.api_tls13, r.gateway_http, r.gateway_tls12, r.gateway_tls13]
            .iter()
            .filter(|b| **b)
            .count();
        let score = r.latency_ms + (6 - probes) as i64 * 500;
        if best.is_empty() || score < best_score {
            best = r.name.clone();
            best_score = score;
        }
    }
    best
}

#[derive(Default)]
struct ProbeRes {
    yt_ms: i64,
    yt_err: String,
    api: HostProbe,
    gw: HostProbe,
}

// runStrategyTests — проверка всех стратегий по очереди.
fn run_strategy_tests(tools: &Path, flag: Arc<AtomicBool>) {
    // Go: defer { running=false, done=true } — Drop-гард на все выходы
    struct Finish;
    impl Drop for Finish {
        fn drop(&mut self) {
            let mut c = CHECKER.lock().unwrap_or_else(|e| e.into_inner());
            c.running = false;
            c.done = true;
        }
    }
    let _finish = Finish;

    let (dir, ok) = paths::zapret_dir(tools);
    if !ok {
        clog("❌ Zapret не установлен");
        return;
    }
    let strats = paths::list_strategies(&dir);
    if strats.is_empty() {
        clog(&format!("❌ Стратегии (.bat) не найдены в {}", dir.display()));
        return;
    }
    clog("🛑 Останавливаю winws перед проверкой…");
    let _ = run_hidden("taskkill", &["/F", "/IM", paths::WINWS_NAME]);
    if sleep_or_stop(Duration::from_millis(600), &flag) {
        finish_stopped(tools);
        return;
    }
    clog(&format!("🔎 Проверяю {} стратегий (YouTube + Discord)…", strats.len()));
    for s in &strats {
        if is_stopped(&flag) {
            finish_stopped(tools);
            return;
        }
        clog(&format!("▶ {}", s));
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/c", dir.join(s).display().to_string().as_str()])
            .current_dir(&dir)
            .creation_flags(0x08000000);
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                clog(&format!("   ❌ не удалось запустить: {}", e));
                append_result(CheckResult {
                    name: s.clone(),
                    ..Default::default()
                });
                continue;
            }
        };
        let child = Arc::new(Mutex::new(child));
        {
            let c2 = child.clone();
            std::thread::spawn(move || {
                // Репер НЕ держит мьютекс на время wait(): cmd.exe жив, пока
                // жив winws, поэтому блокирующий wait() под локом вешал бы
                // все пути остановки (kill() не мог бы взять child.lock()).
                // Периодический try_wait с освобождением лока: захват всегда
                // занимает микросекунды.
                loop {
                    let exited = match c2.lock() {
                        Ok(mut c) => matches!(c.try_wait(), Ok(Some(_)) | Err(_)),
                        Err(_) => break, // лок отравлен — репер больше не нужен
                    };
                    if exited {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
            });
        }
        if sleep_or_stop(Duration::from_secs(3), &flag) {
            if let Ok(mut c) = child.lock() {
                let _ = c.kill();
            }
            let _ = run_hidden("taskkill", &["/F", "/IM", paths::WINWS_NAME]);
            finish_stopped(tools);
            return;
        }
        if !sysinfo::process_running(paths::WINWS_NAME) {
            clog("   🔴 winws не поднялся");
            append_result(CheckResult {
                name: s.clone(),
                ..Default::default()
            });
            if let Ok(mut c) = child.lock() {
                let _ = c.kill();
            }
            if sleep_or_stop(Duration::from_millis(500), &flag) {
                finish_stopped(tools);
                return;
            }
            continue;
        }
        // пробы параллельно: YouTube + discord.com/api/v9/gateway + gateway.discord.gg
        let (tx, rx) = std::sync::mpsc::channel::<ProbeRes>();
        std::thread::spawn(move || {
            let mut pr = ProbeRes::default();
            let t1 = std::thread::spawn(|| http_latency("https://www.youtube.com/generate_204", Duration::from_secs(7)));
            let t2 = std::thread::spawn(|| probe_host("https://discord.com/api/v9/gateway", Duration::from_secs(7)));
            let t3 = std::thread::spawn(|| probe_host("https://gateway.discord.gg", Duration::from_secs(7)));
            match t1.join() {
                Ok(Ok(ms)) => pr.yt_ms = ms,
                Ok(Err(e)) => pr.yt_err = e,
                Err(_) => pr.yt_err = "probe panic".into(),
            }
            pr.api = t2.join().unwrap_or_default();
            pr.gw = t3.join().unwrap_or_default();
            let _ = tx.send(pr);
        });
        let pr = loop {
            if is_stopped(&flag) {
                if let Ok(mut c) = child.lock() {
                    let _ = c.kill();
                }
                let _ = run_hidden("taskkill", &["/F", "/IM", paths::WINWS_NAME]);
                finish_stopped(tools);
                return;
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(pr) => break pr,
                // Disconnected = поток пробы умер: без этой ветки цикл ждал бы
                // вечно до ручной остановки
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let mut dead = ProbeRes::default();
                    dead.yt_err = "probe thread died".into();
                    break dead;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            }
        };
        let mut res = CheckResult {
            name: s.clone(),
            ..Default::default()
        };
        res.api_http = pr.api.http1;
        res.api_tls12 = pr.api.tls12;
        res.api_tls13 = pr.api.tls13;
        res.api_ms = pr.api.ms;
        res.gateway_http = pr.gw.http1;
        res.gateway_tls12 = pr.gw.tls12;
        res.gateway_tls13 = pr.gw.tls13;
        res.gateway_ms = pr.gw.ms;
        let api_ok = pr.api.http1 || pr.api.tls12 || pr.api.tls13;
        let gw_ok = pr.gw.http1 || pr.gw.tls12 || pr.gw.tls13;
        res.discord_ok = api_ok && gw_ok;
        let mut dc_lat: i64 = -1;
        if pr.api.ms >= 0 {
            dc_lat = pr.api.ms;
        }
        if pr.gw.ms >= 0 && (dc_lat < 0 || pr.gw.ms < dc_lat) {
            dc_lat = pr.gw.ms;
        }
        let api_str = if api_ok {
            format!("[{}] {} ms", tls_mark(pr.api.http1, pr.api.tls12, pr.api.tls13), pr.api.ms)
        } else {
            "✗".to_string()
        };
        let gw_str = if gw_ok {
            format!("[{}] {} ms", tls_mark(pr.gw.http1, pr.gw.tls12, pr.gw.tls13), pr.gw.ms)
        } else {
            "✗".to_string()
        };
        if pr.yt_err.is_empty() {
            res.ok = true;
            res.latency_ms = pr.yt_ms;
            if dc_lat >= 0 && dc_lat < res.latency_ms {
                res.latency_ms = dc_lat;
            }
            clog(&format!(
                "   🟢 работает — YouTube {} ms · API {} · Gateway {}",
                pr.yt_ms, api_str, gw_str
            ));
        } else if api_ok || gw_ok {
            res.ok = true;
            res.latency_ms = dc_lat;
            clog(&format!("   🟡 YouTube недоступен · API {} · Gateway {}", api_str, gw_str));
        } else {
            clog("   🔴 не работает (YouTube, Discord API и Gateway недоступны)");
        }
        append_result(res);
        let _ = run_hidden("taskkill", &["/F", "/IM", paths::WINWS_NAME]);
        if let Ok(mut c) = child.lock() {
            let _ = c.kill();
        }
        if sleep_or_stop(Duration::from_millis(600), &flag) {
            finish_stopped(tools);
            return;
        }
    }
    clog("✅ Проверка завершена");
    // Stop мог прийти в самом конце: не применяем автопрофиль после «Остановить»
    if is_stopped(&flag) {
        finish_stopped(tools);
        return;
    }
    let auto = CHECKER.lock().unwrap_or_else(|e| e.into_inner()).auto;
    if auto {
        let best = best_strategy();
        if best.is_empty() {
            clog("⚠️ Рабочих стратегий нет — автоприменять нечего");
        } else {
            clog(&format!("🏆 Автовыбор лучшего профиля: {}", best));
            let (d, ok) = paths::zapret_dir(tools);
            if ok {
                clog(&apply_strategy(tools, &d, &best));
                return;
            }
        }
    }
    restore_previous(tools);
}

