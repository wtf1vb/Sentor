// IPC commands - port of the Go App methods (stage 4 skeleton).
// Real: status/traffic/logs/verify, vpn + pwdtt stores.
// Stubs: everything that needs networking/tunnels - returns Go-zero values
// or a clear "not ported yet" message and logs a [stub] line.
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use tauri::Manager;

use crate::logging::{clear_logs as buf_clear, get_logs as buf_get, log_add, save_logs_text as buf_text};
use crate::models::*;
use crate::paths;
use crate::state::AppState;
use crate::store;

// ---------- процесс/утилиты ----------

#[tauri::command]
pub fn ping() -> String {
    "pong".into()
}

// внутренняя остановка VPN для модулей-туннелей (cqstt/wdtt): TUN-маршруты общие
pub fn vpn_disconnect_cmd(app: &tauri::AppHandle) -> String {
    let st = app.state::<std::sync::Arc<AppState>>();
    st.conn.stop(app);
    "ok".to_string()
}

// Диагностика WebView: фронтенд-зонд пишет сюда состояние шима/IPC.
// Пишем в каталог tools (а не в захардкоженный dev-путь исходников).
#[tauri::command]
pub fn diag_report(state: tauri::State<'_, std::sync::Arc<AppState>>, data: String) {
    let tools = state.tools();
    let path = tools.join("diag.log");
    let _ = std::fs::write(&path, data.as_bytes());
    log_add("diag", &data);
}

#[tauri::command]
pub fn open_url(url: String) {
    // URL может прийти из недоверенных подписок (webPageUrl/supportUrl/announce),
    // поэтому: 1) только http/https; 2) без кавычек и управляющих символов;
    // 3) ShellExecuteW вместо `cmd /c start`, чтобы метасимволы cmd (&, |, ^, %)
    // не могли превратить ссылку в выполнение произвольной команды.
    let u = url.trim();
    let ok_scheme = u.starts_with("http://") || u.starts_with("https://");
    let ok_chars = !u.is_empty()
        && !u.chars().any(|c| c.is_control() || matches!(c, '"' | '<' | '>'));
    if !ok_scheme || !ok_chars {
        log_add("open_url", &format!("отклонён небезопасный URL ({} байт)", url.len()));
        return;
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        let wide: Vec<u16> = std::ffi::OsStr::new(u)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            // SW_SHOWNORMAL = 1; lpOperation = NULL → shell сам выберет "open".
            ShellExecuteW(
                std::ptr::null_mut(),
                std::ptr::null(),
                wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            );
        }
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(u).spawn();
    }
}

// isPE проверяет, что файл существует, не пустой и начинается с "MZ".
fn is_pe(path: &Path) -> (i64, bool) {
    let Ok(mut f) = std::fs::File::open(path) else {
        return (0, false);
    };
    let size = f.metadata().map(|m| m.len() as i64).unwrap_or(0);
    let mut hdr = [0u8; 2];
    if f.read_exact(&mut hdr).is_err() {
        return (size, false);
    }
    (size, hdr[0] == b'M' && hdr[1] == b'Z')
}

// ---------- статус / трафик ----------

#[tauri::command]
pub fn get_status(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Status {
    let tools = state.tools();
    let (zdir, installed) = paths::zapret_dir(&tools);
    let strategies = if installed { paths::list_strategies(&zdir) } else { Vec::new() };
    Status {
        tools_dir: tools.display().to_string(),
        is_admin: crate::sysinfo::is_admin(),
        zapret_installed: installed,
        zapret_dir: zdir.display().to_string(),
        strategies,
        zapret_running: crate::sysinfo::process_running_cached(paths::WINWS_NAME),
        tg_installed: tools.join("tgproxy").join(paths::TG_EXE_NAME).exists(),
        tg_running: crate::sysinfo::process_running_cached(paths::TG_EXE_NAME),
        selected: paths::selected_strategy(&tools),
    }
}

// GetTraffic — накопленный трафик и текущая скорость (точный порт Go-логики
// с baseline счётчика релея; переживает рестарты через traffic.json).
#[tauri::command(async)]
pub fn get_traffic(state: tauri::State<'_, std::sync::Arc<AppState>>) -> TrafficInfo {
    // async): опрос каждую секунду читает/пишет файлы (sync_all в
    // traffic.json каждые 15 с) — это не должно выполняться на главном потоке
    let tools = state.tools();
    let mut st = state.traffic.lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    if !st.loaded {
        let (totals, relay_pid, relay_prev) = store::load_traffic_totals(&tools);
        st.totals = totals;
        st.relay_pid = relay_pid;
        st.relay_prev = relay_prev;
        st.loaded = true;
    }
    let mut info = TrafficInfo {
        telegram_bytes: *st.totals.get("telegram").unwrap_or(&0),
        telegram_rate: 0,
        telegram_running: crate::sysinfo::process_running_cached(paths::TG_EXE_NAME),
        discord_running: crate::sysinfo::process_running_cached(paths::WINWS_NAME),
    };
    let Some(last) = st.last_sample else {
        st.last_sample = Some(now);
        return info;
    };
    let dt = now.duration_since(last).as_secs_f64();
    if dt < 0.2 {
        return info;
    }
    let mut d_tg: u64 = 0;
    let stats_path = paths::relay_stats_path(&tools);
    if let Ok(data) = std::fs::read(&stats_path) {
        if let Ok(s) = serde_json::from_slice::<RelayStats>(&data) {
            if s.pid > 0 && s.port > 0 {
                if st.relay_pid == -1 {
                    // Старый traffic.json: принимаем счётчик за baseline.
                    st.relay_pid = s.pid;
                    st.relay_prev = s.bytes;
                } else if s.pid != st.relay_pid {
                    // Новый процесс релея — его счётчик с нуля.
                    d_tg = s.bytes;
                    st.relay_pid = s.pid;
                    st.relay_prev = s.bytes;
                } else if s.bytes < st.relay_prev {
                    // Счётчик обнулился при том же pid.
                    d_tg = s.bytes;
                    st.relay_prev = s.bytes;
                } else {
                    d_tg = s.bytes - st.relay_prev;
                    st.relay_prev = s.bytes;
                }
            }
        }
    }
    let tg = st.totals.entry("telegram".into()).or_insert(0);
    *tg += d_tg;
    info.telegram_rate = (d_tg as f64 / dt) as u64;
    info.telegram_bytes = *st.totals.get("telegram").unwrap();
    st.last_sample = Some(now);
    let need_save = match st.last_save {
        None => true,
        Some(l) => now.duration_since(l).as_secs_f64() > 15.0,
    };
    if need_save {
        st.last_save = Some(now);
        store::save_traffic_totals(&tools, *st.totals.get("telegram").unwrap(), st.relay_pid, st.relay_prev);
    }
    info
}

// ---------- проверка установки ----------

#[tauri::command]
pub async fn verify_install(state: tauri::State<'_, std::sync::Arc<AppState>>, which: String) -> Result<VerifyResult, String> {
    let st = state.inner().clone();
    // Панику воркера показываем как ошибку проверки, а не «успешно пусто»
    Ok(tauri::async_runtime::spawn_blocking(move || verify_install_impl(&st, &which))
        .await
        .unwrap_or_else(|e| VerifyResult {
            ok: false,
            report: format!("❌ сбой проверки (поток упал): {}", e),
        }))
}

fn verify_install_impl(state: &AppState, which: &str) -> VerifyResult {
    let tools = state.tools();
    let mut ok = true;
    let mut b = String::new();
    let mut line = |good: bool, text: &str| {
        if good {
            b.push_str("✅ ");
        } else {
            b.push_str("❌ ");
            ok = false;
        }
        b.push_str(text);
        b.push('\n');
    };
    match which {
        "zapret" => {
            let root = tools.join("zapret");
            let (dir, installed) = paths::zapret_dir(&tools);
            if !installed {
                return VerifyResult {
                    ok: false,
                    report: format!("❌ Zapret не установлен (в {} нет winws.exe). Нажми «Установить».", root.display()),
                };
            }
            let (size, pe) = is_pe(&paths::find_file(&root, paths::WINWS_NAME, 4));
            line(pe && size > 0, &format!("winws.exe ({} КБ)", size / 1024));
            line(
                !paths::find_file(&root, "WinDivert64.sys", 4).as_os_str().is_empty(),
                "WinDivert64.sys (драйвер)",
            );
            line(
                !paths::find_file(&root, "WinDivert.dll", 4).as_os_str().is_empty(),
                "WinDivert.dll",
            );
            let n = paths::list_strategies(&dir).len();
            line(n > 0, &format!("стратегий (.bat): {}", n));
            let v = paths::read_version(&tools, "zapret");
            if !v.is_empty() {
                b.push_str(&format!("ℹ️ версия: {}\n", v));
            }
            if crate::sysinfo::process_running(paths::WINWS_NAME) {
                b.push_str("✅ winws сейчас запущен — Zapret работает\n");
            } else {
                b.push_str("ℹ️ winws сейчас не запущен — включи кнопку Discord, чтобы проверить в деле\n");
            }
            if !ok {
                b.push_str("Файлы повреждены или удалены антивирусом: добавь папку в исключения и нажми «Переустановить».");
            }
        }
        "tg" => {
            let exe = tools.join("tgproxy").join(paths::TG_EXE_NAME);
            if !exe.exists() {
                return VerifyResult {
                    ok: false,
                    report: format!("❌ {} не найден. Нажми «Установить».", paths::TG_EXE_NAME),
                };
            }
            let (size, pe) = is_pe(&exe);
            line(pe && size > 0, &format!("{} ({} КБ)", paths::TG_EXE_NAME, size / 1024));
            let v = paths::read_version(&tools, "tgproxy");
            if !v.is_empty() {
                line(true, &format!("версия: {}", v));
            }
            if crate::sysinfo::process_running(paths::TG_EXE_NAME) {
                line(true, "процесс прокси запущен");
                // фактический backend-порт из конфига tg-ws-proxy (find_tg_config)
                let port = crate::relay::cfg_port(crate::relay::find_tg_config(&tools).as_ref());
                match port.parse::<i32>() {
                    Ok(p) if p > 0 => {
                        line(crate::conn::port_open(p), &format!("порт 127.0.0.1:{} отвечает", p));
                    }
                    _ => line(true, "порт из конфига tg-ws-proxy не определён"),
                }
            } else {
                line(true, "процесс прокси не запущен");
            }
        }
        unknown => {
            // мусорный параметр раньше давал «успешный» пустой отчёт
            return VerifyResult {
                ok: false,
                report: format!("❌ Неизвестный объект проверки: {}", unknown),
            };
        }
    }
    while b.ends_with('\n') {
        b.pop();
    }
    VerifyResult { ok, report: b }
}

// ---------- логи ----------

#[tauri::command]
pub fn get_logs() -> String {
    buf_get()
}

#[tauri::command]
pub async fn save_logs_file() -> Result<String, String> {
    // rfd::FileDialog — модальный COM-диалог: в синхронной команде он шёл
    // инлайн на главном потоке внутри IPC-колбэка (риск фриза/дедлока, см.
    // комментарий к open_checker). Диалог + запись — в отдельном потоке.
    Ok(tauri::async_runtime::spawn_blocking(|| {
        let default_name = format!("sentor-log-{}", chrono::Local::now().format("%Y-%m-%d_%H-%M"));
        let path: Option<PathBuf> = rfd::FileDialog::new()
            .set_title("Куда сохранить лог")
            .add_filter("Текст (*.txt;*.log)", &["txt", "log"])
            .set_file_name(&format!("{}.txt", default_name))
            .save_file();
        let Some(path) = path else {
            return String::new();
        };
        let text = buf_text();
        match std::fs::write(&path, text.as_bytes()) {
            Ok(_) => format!("✅ Лог сохранён: {}", path.display()),
            Err(e) => format!("❌ Не смог записать файл: {}", e),
        }
    })
    .await
    .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub fn clear_logs() {
    buf_clear();
}

// ---------- инструменты: zapret / tgproxy ----------

#[tauri::command]
pub fn open_tools_folder(state: tauri::State<'_, std::sync::Arc<AppState>>) -> String {
    let tools = state.tools();
    use std::os::windows::process::CommandExt;
    if let Err(e) = std::process::Command::new("explorer")
        .arg(&tools)
        .creation_flags(0x08000000)
        .spawn()
    {
        log_add("ui", &format!("не удалось открыть папку инструментов: {}", e));
    }
    "ok".to_string()
}

#[tauri::command]
pub async fn install_zapret(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::tools::install_zapret(&st.tools()))
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub async fn update_zapret(state: tauri::State<'_, std::sync::Arc<AppState>>, app: tauri::AppHandle) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::tools::update_zapret(Some(&app), &st.tools()))
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub async fn install_tg_proxy(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::tools::install_tg_proxy(&st.tools()))
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub async fn update_tg_proxy(state: tauri::State<'_, std::sync::Arc<AppState>>, app: tauri::AppHandle) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::tools::update_tg_proxy(Some(&app), &st.tools()))
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub async fn start_strategy(state: tauri::State<'_, std::sync::Arc<AppState>>, name: String) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::tools::start_strategy(&st, &name))
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub async fn stop_zapret() -> Result<String, String> {
    Ok(tauri::async_runtime::spawn_blocking(crate::tools::stop_zapret)
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub async fn start_tg_proxy(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::tools::start_tg_proxy(&st))
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub async fn stop_tg_proxy(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::tools::stop_tg_proxy(&st.tools()))
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub fn add_to_telegram(state: tauri::State<'_, std::sync::Arc<AppState>>, direct: Option<bool>) -> String {
    crate::tools::add_to_telegram(&state.tools(), direct.unwrap_or(false))
}

// ToolSources — откуда качаются утилиты (кнопка «Источники»)
#[tauri::command]
pub fn tool_sources() -> ToolSources {
    crate::tools::tool_sources()
}

#[tauri::command]
pub async fn check_updates(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Result<UpdateInfo, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::tools::check_updates(&st.tools()))
        .await
        .map_err(|e| format!("❌ check_updates: {}", e))?)
}

// ---------- checker ----------

#[tauri::command]
pub fn checker_start(state: tauri::State<'_, std::sync::Arc<AppState>>, auto_select: bool) -> String {
    crate::checker::checker_start(&state.tools(), auto_select)
}

#[tauri::command]
pub fn checker_stop() -> String {
    crate::checker::checker_stop()
}

#[tauri::command]
pub fn checker_state(state: tauri::State<'_, std::sync::Arc<AppState>>) -> CheckerState {
    crate::checker::checker_state(&state.tools())
}

#[tauri::command]
pub async fn checker_select(state: tauri::State<'_, std::sync::Arc<AppState>>, name: String) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::checker::checker_select(&st.tools(), &name))
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub async fn open_checker(app: tauri::AppHandle) -> String {
    // Окно проверки открывается В ТОМ ЖЕ процессе: раньше тут спавнился свой
    // exe с --checker, но single-instance-плагин держит мьютекс на идентификатор
    // приложения и немедленно гасил второй процесс (колбэк первого показывал
    // только main-окно — окно проверки не открывалось никогда). Повторный
    // вызов просто поднимает уже открытое окно; закрытие обрабатывает
    // on_window_event (label == "checker" → stop_checker_for_close).
    use tauri::Manager;
    if let Some(w) = app.get_webview_window("checker") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return "🪟 Окно проверки уже открыто".to_string();
    }
    // ВАЖНО: команда обязана быть async. Синхронные команды Tauri на Windows
    // выполняются инлайн НА ГЛАВНОМ ПОТОКЕ внутри WebView2-колбэка IPC, а
    // WebviewWindowBuilder::build() в этом контексте ДЕДЛОКИТСЯ и даёт белое
    // зависшее окно (прямое предупреждение в доках tauri::WebviewWindowBuilder:
    // «On Windows, this function deadlocks when used in a synchronous command
    // and event handlers»). run_on_main_thread из sync-команды ничего не
    // менял: send_user_message видит «уже на главном потоке» и выполняет
    // замыкание инлайн — build() по-прежнему шёл внутри IPC-колбэка.
    // async-команда уходит в async_runtime::spawn (рабочий поток tokio):
    // run_on_main_thread теперь реально постит замыкание в event loop, а
    // этот поток ждёт результата через мьютекс, не блокируя ни event loop,
    // ни runtime.
    let app2 = app.clone();
    let created = std::sync::Arc::new(std::sync::Mutex::new(Err("не выполнено".to_string())));
    let created2 = created.clone();
    let _ = app.run_on_main_thread(move || {
        let res = tauri::WebviewWindowBuilder::new(
            &app2,
            "checker",
            tauri::WebviewUrl::App("checker/index.html".into()),
        )
        .title("Sentor — Проверка стратегий")
        .inner_size(1150.0, 740.0)
        .center()
        .build();
        *created2.lock().unwrap_or_else(|e| e.into_inner()) = res.map(|_| ()).map_err(|e| e.to_string());
    });
    let res = created.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match res {
        Ok(_) => "🪟 Окно проверки открыто".to_string(),
        Err(e) => format!("❌ Окно проверки не открылось: {}", e),
    }
}

// ---------- pwdtt ----------

#[tauri::command]
pub fn pwdtt_servers(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Vec<PwdttServer> {
    store::load_pwdtt_servers(&state.tools())
}

#[tauri::command]
pub fn pwdtt_save_server(state: tauri::State<'_, std::sync::Arc<AppState>>, s: PwdttServer) -> String {
    let mut s = s;
    s.id = s.id.trim().to_string();
    s.name = s.name.trim().to_string();
    s.peer = s.peer.trim().to_string();
    s.password = s.password.trim().to_string();
    if s.name.is_empty() || s.peer.is_empty() || s.password.is_empty() {
        return "⚠️ Укажи имя, адрес (host:port) и пароль".to_string();
    }
    // pwdttHashList: нужен хотя бы один непустой хеш
    if !s.hashes.lines().any(|l| !l.trim().is_empty()) {
        return "⚠️ Нужен хотя бы один хеш VK-звонка".to_string();
    }
    if s.id.is_empty() {
        s.id = uuid::Uuid::new_v4().to_string();
    }
    let tools = state.tools();
    let _guard = state.pwdtt_store.lock().unwrap_or_else(|e| e.into_inner());
    let mut list = store::load_pwdtt_servers(&tools);
    let mut replaced = false;
    for x in list.iter_mut() {
        if x.id == s.id {
            *x = s.clone();
            replaced = true;
            break;
        }
    }
    if !replaced {
        list.push(s.clone());
    }
    match store::save_pwdtt_servers(&tools, &list) {
        Err(e) => format!("❌ Не удалось сохранить сервер: {}", e),
        Ok(_) => format!("✅ Сервер сохранён: {}", s.name),
    }
}

#[tauri::command]
pub fn pwdtt_remove_server(state: tauri::State<'_, std::sync::Arc<AppState>>, id: String) -> String {
    let tools = state.tools();
    let _guard = state.pwdtt_store.lock().unwrap_or_else(|e| e.into_inner());
    let list = store::load_pwdtt_servers(&tools);
    let mut out = Vec::new();
    let mut found = false;
    let mut removed_name = String::new();
    for x in list {
        if x.id == id {
            found = true;
            removed_name = x.name;
            continue;
        }
        out.push(x);
    }
    if !found {
        return "⚠️ Сервер не найден".to_string();
    }
    match store::save_pwdtt_servers(&tools, &out) {
        Err(e) => format!("❌ Не удалось удалить сервер: {}", e),
        Ok(_) => format!("🗑 Удалено: {}", removed_name),
    }
    // (порт pwdtt-сессии: если удалён активный сервер — глушим сессию на этапе туннелей)
}

#[tauri::command]
pub async fn pwdtt_connect(
    state: tauri::State<'_, std::sync::Arc<AppState>>,
    id: String,
) -> Result<String, String> {
    // connect() тяжёлый: conn.stop() (смерть ядра до ~10 с + исчезновение TUN
    // до ~8 с) + старт ядра, а при провале — полный vpn_connect_impl. Раньше
    // всё это шло на главном потоке — UI висел до ~12 с на каждый «Подключить»
    // WDTT. Как cqstt_connect — в отдельный поток.
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || {
        let tools = st.tools();
        let list = store::load_pwdtt_servers(&tools);
        let Some(server) = list.iter().find(|x| x.id == id) else {
            return "❌ Сервер не найден".to_string();
        };
        let server = server.clone();
        match crate::wdtt_session::connect(&server) {
            Ok(()) => format!("⏳ Подключаюсь: {}", server.name),
            Err(e) => e,
        }
    })
    .await
    .unwrap_or_else(|_| "❌ Сбой потока подключения".into()))
}

#[tauri::command]
pub async fn pwdtt_disconnect() -> Result<String, String> {
    // disconnect гоняет teardown (kill sing-box + ожидание выхода до 2 с) —
    // как cqstt_disconnect, не на главном потоке.
    Ok(tauri::async_runtime::spawn_blocking(crate::wdtt_session::disconnect)
        .await
        .unwrap_or_else(|_| "❌ Сбой потока остановки".into()))
}

#[tauri::command]
pub fn pwdtt_import_link(link: String) -> String {
    match crate::wdtt_session::import_link_impl(&link) {
        Ok((name, peer)) => format!("✅ Добавлено из ссылки: {} ({})", name, peer),
        Err(e) => e,
    }
}

#[tauri::command]
pub fn pwdtt_send_captcha(token: String) -> String {
    crate::wdtt_session::send_captcha(&token)
}

#[tauri::command]
pub fn pwdtt_status() -> PwdttStatusInfo {
    crate::wdtt_session::status()
}

#[tauri::command]
pub fn pwdtt_log() -> String {
    crate::wdtt_session::log_text()
}

// ---------- cqstt (CSQTT — туннель через TURN/RTP) ----------

// порт, который CSQTT-сервер слушает по умолчанию (вешается в панель сервера)
pub const CQSTT_DEFAULT_PORT: u16 = 46000;

// peer без порта → дописываем дефолтный :46000 (голый host в ядро передавать нельзя)
fn cqstt_with_default_port(peer: &str) -> String {
    let p = peer.trim();
    // чистый IPv6-литерал без порта: p.contains(':') истинно, но порта нет —
    // раньше в ядро уходил peer без порта. Оборачиваем в скобки + дефолт.
    if p.parse::<std::net::Ipv6Addr>().is_ok() {
        return format!("[{}]:{}", p, CQSTT_DEFAULT_PORT);
    }
    if p.contains(':') {
        return p.to_string();
    }
    format!("{}:{}", p, CQSTT_DEFAULT_PORT)
}

#[tauri::command]
pub fn cqstt_servers(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Vec<CqsttServer> {
    store::load_cqstt_servers(&state.tools())
}

#[tauri::command]
pub fn cqstt_save_server(state: tauri::State<'_, std::sync::Arc<AppState>>, s: CqsttServer) -> String {
    let tools = state.tools();
    let mut s = s;
    if s.peer.trim().is_empty() {
        return "❌ Укажи адрес сервера (host:port)".into();
    }
    s.peer = cqstt_with_default_port(&s.peer);
    if s.name.trim().is_empty() {
        s.name = s.peer.trim().to_string();
    }
    if s.password.trim().is_empty() {
        return "❌ Укажи пароль клиента из панели CSQTT-сервера".into();
    }
    if crate::cqstt_session::hash_list(&s.hashes).is_empty() {
        return "❌ Нужен хотя бы один VK-хеш".into();
    }
    if s.id.trim().is_empty() {
        s.id = uuid::Uuid::new_v4().to_string();
    }
    let _guard = state.cqstt_store.lock().unwrap_or_else(|e| e.into_inner());
    let mut list = store::load_cqstt_servers(&tools);
    // dedupe по (peer, password)
    let key = format!("{}|{}", s.peer.trim(), s.password.trim());
    if let Some(existing) = list.iter_mut().find(|x| format!("{}|{}", x.peer.trim(), x.password.trim()) == key) {
        existing.name = s.name.clone();
        existing.hashes = s.hashes.clone();
        existing.workers = s.workers;
        existing.obfs = s.obfs.clone();
        existing.transport = s.transport.clone();
        existing.fingerprint = s.fingerprint.clone();
        existing.device_id = s.device_id.clone();
        if store::save_cqstt_servers(&tools, &list).is_err() {
            return "❌ Не удалось сохранить".into();
        }
        return format!("✅ Сервер обновлён: {}", s.name);
    }
    list.push(s.clone());
    if store::save_cqstt_servers(&tools, &list).is_err() {
        return "❌ Не удалось сохранить".into();
    }
    format!("✅ Сервер сохранён: {}", s.name)
}

#[tauri::command]
pub fn cqstt_remove_server(state: tauri::State<'_, std::sync::Arc<AppState>>, id: String) -> String {
    let tools = state.tools();
    let mut name = id.clone();
    let _guard = state.cqstt_store.lock().unwrap_or_else(|e| e.into_inner());
    let mut list = store::load_cqstt_servers(&tools);
    list.retain(|s| {
        if s.id == id {
            name = s.name.clone();
            false
        } else {
            true
        }
    });
    if store::save_cqstt_servers(&tools, &list).is_err() {
        return "❌ Не удалось сохранить список".into();
    }
    format!("🗑 Удалено: {}", name)
}

#[tauri::command]
pub async fn cqstt_connect(
    state: tauri::State<'_, std::sync::Arc<AppState>>,
    id: String,
) -> Result<String, String> {
    // connect() тяжёлый (wintun/маршруты) и раньше паниковал прямо на
    // main-потоке, убивая всё приложение: гоняем в отдельном потоке
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || {
        let tools = st.tools();
        let server = {
            let _guard = st.cqstt_store.lock().unwrap_or_else(|e| e.into_inner());
            store::load_cqstt_servers(&tools).into_iter().find(|s| s.id == id)
        };
        let Some(server) = server else {
            return "❌ Сервер не найден".to_string();
        };
        match crate::cqstt_session::connect(&server) {
            Ok(()) => format!("⏳ Подключаюсь: {}", server.name),
            Err(e) => e,
        }
    })
    .await
    .unwrap_or_else(|_| "❌ Сбой потока подключения".into()))
}

#[tauri::command]
pub fn cqstt_disconnect() -> String {
    // НЕ блокирующий вызов: раньше синхронная команда гоняла на главном потоке
    // Tauri до 10 с ожидания ядра + ~10 с уборки маршрутов — окно зависало.
    // Теперь мгновенно ставит фазу disconnecting, остальное уходит в фон.
    crate::cqstt_session::disconnect_in_background()
}

#[tauri::command]
pub fn cqstt_import_link(state: tauri::State<'_, std::sync::Arc<AppState>>, link: String) -> String {
    // Конвертация WDTT-ссылок (wdtt:// / qwdtt://config) в CSQTT-сервер:
    // WDTT и CSQTT — разные сервисы, dtls/wg-порты из ссылки не подходят,
    // поэтому берём из неё host, пароль и VK-хеши, а порт назначаем
    // CSQTT-шный по умолчанию (:46000) — при желании правится в форме.
    // State нужен cqstt_save_server_inner: запись cqstt.json под общим
    // мьютексом (см. там).
    let trimmed_link = link.trim();
    let low = trimmed_link.to_lowercase();
    if low.starts_with("wdtt://") || low.starts_with("qwdtt://config?") {
        let p = match crate::wdtt_session::pwdtt_parse_link(trimmed_link) {
            Ok(p) => p,
            Err(e) => return format!("❌ {}", e),
        };
        let host = p
            .peer
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(p.peer.as_str())
            .trim()
            .to_string();
        // Хеши берём из СЫРОЙ ссылки с сохранением регистра: pwdtt_parse_link
        // приводит их к нижнему регистру (у WDTT они регистронезависимы), а
        // VK-хеши CSQTT регистрозависимы — искажённый хеш сервер молча
        // отбраковывает («Все воркеры завершены» без TUNCONF)
        let raw_hashes = if low.starts_with("wdtt://") {
            let mut rest = trimmed_link["wdtt://".len()..].to_string();
            if let Some(i) = rest.rfind('#') {
                rest.truncate(i);
            }
            let f: Vec<&str> = rest.split(':').collect();
            if f.len() > 5 {
                f[5..].join("\n")
            } else {
                String::new()
            }
        } else {
            // qwdtt://config?hashes= — query-парсер регистр не искажает
            p.hashes.clone()
        };
        let mut hs: Vec<String> = Vec::new();
        for part in raw_hashes.split([',', ';', '\n', ' ']) {
            let h = part.trim();
            if !h.is_empty() && !hs.contains(&h.to_string()) {
                hs.push(h.to_string());
            }
        }
        hs.truncate(6);
        if hs.is_empty() {
            // Раньше ссылка без хешей сохранялась как «✅ Добавлено», а
            // подключение всегда падало с «нет хешей VK» — то же предупреждение,
            // что у cqstt_save_server.
            return "❌ В ссылке нет VK-хешей — CSQTT-сервер без них не работает (нужен хотя бы один хеш VK-звонка)".into();
        }
        let s = CqsttServer {
            id: String::new(),
            name: p.name,
            peer: format!("{}:{}", host, CQSTT_DEFAULT_PORT),
            password: p.password,
            hashes: hs.join("\n"),
            workers: 0,
            obfs: None,
            transport: None,
            fingerprint: None,
            device_id: None,
        };
        let mut msg = cqstt_save_server_inner(&state, s);
        if msg.starts_with("✅") {
            msg.push_str(" · порт взяли CSQTT-шный :46000 (wdtt-порты — другой сервис), поправь в форме если у тебя другой");
        }
        return msg;
    }
    // csqtt:// ссылки: plaintext v2 (connect?v=2&host=...), legacy (password@host:port)
    let link = trimmed_link;
    let Some(rest) = link.strip_prefix("csqtt://") else {
        return "❌ Это не ссылка csqtt:// (или wdtt://)".into();
    };
    if rest.starts_with("connect?") || rest.starts_with("connect/") {
        // v2: connect?v=2&host=<ip>&peer=<port>&password=<pw>&hashes=<..>&power=<n>
        let q = rest.trim_start_matches("connect").trim_start_matches(['?', '/']);
        match csqtt_parse_v2(q) {
            Ok(s) => cqstt_save_server_inner(&state, s),
            Err(e) => e,
        }
    } else if let Some((b64pw, hostport)) = rest.split_once('@') {
        // legacy: csqtt://<password>@host:port (password мог быть url-encoded)
        let password = crate::tools::url_decode(b64pw);
        if hostport.is_empty() || password.is_empty() {
            return "❌ В ссылке нет host или password".into();
        }
        let s = CqsttServer {
            id: String::new(),
            name: String::new(),
            peer: hostport.to_string(),
            password,
            hashes: String::new(),
            workers: 0,
            obfs: None,
            transport: None,
            fingerprint: None,
            device_id: None,
        };
        cqstt_save_server_inner(&state, s)
    } else {
        "❌ Непонятный формат csqtt://-ссылки (зашифрованные ссылки v2.0 пока не поддерживаются — используй plaintext из панели)".into()
    }
}

// csqtt v2: connect?v=2&host=<ip>&peer=<port>&password=<pw>&hashes=<..>&power=<n>
// Вынесено из cqstt_import_link для тестируемости.
fn csqtt_parse_v2(q: &str) -> Result<CqsttServer, String> {
    let mut host = String::new();
    let mut port = String::new();
    let mut password = String::new();
    let mut hashes = String::new();
    let mut workers: i32 = 0;
    let mut name = String::new();
    for pair in q.split(['&', ';']) {
        let (k, v) = match pair.split_once('=') {
            Some(x) => x,
            None => continue,
        };
        // полный percent-decode: раньше декодировался только %2C, и
        // пароль/хеши с %40/%20 уезжали в сервер закодированными
        let v = crate::tools::url_decode(v.trim());
        match k.trim().to_lowercase().as_str() {
            "host" => host = v,
            "peer" | "port" => port = v, // копим отдельно: парсер зависел от порядка ключей
            "password" | "pass" => password = v,
            "hashes" | "vk" => hashes = v.replace(',', "\n"),
            "power" | "workers" => workers = v.parse().unwrap_or(0),
            "name" => name = v,
            _ => {}
        }
    }
    // host и порт собираем ПОСЛЕ цикла: в ссылке «connect?v=2&peer=46000&host=…»
    // peer приходил раньше host, попытка дописать порт к пустому host
    // молча теряла его, и сервер сохранялся с дефолтным :46000
    let host = if host.contains(':') {
        host
    } else if port.contains(':') {
        port // peer уже «host:port»
    } else if !host.is_empty() && !port.is_empty() {
        format!("{}:{}", host, port)
    } else {
        host
    };
    if host.is_empty() || password.is_empty() {
        return Err("❌ В ссылке нет host или password".into());
    }
    Ok(CqsttServer {
        id: String::new(),
        name,
        peer: host,
        password,
        hashes,
        workers,
        obfs: None,
        transport: None,
        fingerprint: None,
        device_id: None,
    })
}

fn cqstt_save_server_inner(state: &AppState, s: CqsttServer) -> String {
    // переиспользуем сохранение: готовим AppData-заглушку нельзя — сохраняем напрямую
    let tools = state.tools();
    let mut s = s;
    s.peer = cqstt_with_default_port(&s.peer);
    if s.name.trim().is_empty() {
        s.name = s.peer.clone();
    }
    if s.workers <= 0 {
        s.workers = 18;
    }
    // Сериализация read-modify-write cqstt.json: все остальные писатели берут
    // cqstt_store (см. state.rs). Раньше импорт из ссылки писал файл БЕЗ
    // мьютекса — потерянный апдейт при параллельном сохранении из формы.
    let _guard = state.cqstt_store.lock().unwrap_or_else(|e| e.into_inner());
    let mut list = store::load_cqstt_servers(&tools);
    if let Some(existing) = list.iter_mut().find(|x| x.peer == s.peer && x.password == s.password) {
        existing.hashes = s.hashes.clone();
        existing.workers = s.workers;
        existing.name = s.name.clone();
    } else {
        s.id = uuid::Uuid::new_v4().to_string();
        list.push(s.clone());
    }
    if store::save_cqstt_servers(&tools, &list).is_err() {
        return "❌ Не удалось сохранить".into();
    }
    format!("✅ Добавлено из ссылки: {} ({})", s.name, s.peer)
}

#[tauri::command]
pub fn cqstt_send_captcha(token: String) -> String {
    crate::cqstt_session::send_captcha(&token)
}

#[tauri::command]
pub fn cqstt_status() -> CqsttStatusInfo {
    crate::cqstt_session::status()
}

#[tauri::command]
pub fn cqstt_log() -> String {
    crate::cqstt_session::log_text()
}

// ---------- vpn ----------

#[tauri::command]
pub fn vpn_list(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Vec<VpnProxy> {
    store::load_vpn_proxies(&state.tools())
}

#[tauri::command]
pub fn vpn_list_subscriptions(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Vec<VpnSubscription> {
    store::load_vpn_subs(&state.tools())
}

#[tauri::command]
pub fn vpn_get_settings(state: tauri::State<'_, std::sync::Arc<AppState>>) -> VpnSettings {
    store::load_vpn_settings(&state.tools())
}

#[tauri::command(async)]
pub fn vpn_set_settings(state: tauri::State<'_, std::sync::Arc<AppState>>, s: VpnSettings) -> String {
    // async): под «connected» команда берёт мьютекс conn.inner, который
    // stop()/kill_core держат до ~10 с — на главном потоке это фриз UI
    let tools = state.tools();
    let s = s.normalize(); // normalize на входе: мусор (testThreads:0) не оседает в файле
    let old = {
        let _guard = state.vpn_store.lock().unwrap_or_else(|e| e.into_inner());
        let old = store::load_vpn_settings(&tools);
        if let Err(e) = store::save_vpn_settings(&tools, &s) {
            return format!("❌ Настройки не сохранены на диск: {}", e);
        }
        old
    };
    if s.system_proxy != old.system_proxy {
        // Во время «starting» ничего применять не нужно: run() перед финальной
        // установкой перечитывает настройки свежими. Применяем только на живом
        // «connected» — под мьютексом менеджера (как в Go).
        let conn = &state.conn;
        let inner = conn.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.state.phase == "connected" {
            if s.system_proxy {
                crate::sysproxy::set_system_proxy(&tools, &format!("127.0.0.1:{}", crate::conn::vpn_local()));
            } else {
                crate::sysproxy::clear_system_proxy(&tools);
            }
        }
    }
    // Блокировка рекламы применяется СРАЗУ (не на следующее подключение):
    // ON → поднять DNS-блокировщик и переключить DNS адаптеров, OFF →
    // остановить и вернуть исходные DNS. Фоново: netsh занимает до секунд.
    if s.ads_block.unwrap_or(false) != old.ads_block.unwrap_or(false) {
        let tools2 = tools.clone();
        let on = s.ads_block.unwrap_or(false);
        std::thread::spawn(move || {
            let msg = if on {
                crate::adsdns::adsdns_start(&tools2)
            } else {
                crate::adsdns::adsdns_stop(&tools2)
            };
            crate::logging::log_add("adsdns", &msg);
        });
    }
    "ok".to_string()
}

#[tauri::command(async)]
pub fn vpn_remove(state: tauri::State<'_, std::sync::Arc<AppState>>, app: tauri::AppHandle, id: String) -> String {
    // async): при удалении активного сервера stop() ждёт смерти ядра и TUN
    // до ~10 с — на главном потоке это фриз UI (как в vpn_disconnect)
    let tools = state.tools();
    let was_active = {
        // stop() ждёт смерти ядра до ~10 с — держим vpn_store закрытым только
        // на файловые операции, отключение выполняем после снятия guard'а
        // (иначе все параллельные операции с хранилищем стоят на мьютексе).
        let _guard = state.vpn_store.lock().unwrap_or_else(|e| e.into_inner());
        let list = store::load_vpn_proxies(&tools);
        let mut out = Vec::new();
        let mut found = false;
        for x in list {
            if x.id == id {
                found = true;
                continue;
            }
            out.push(x);
        }
        if found {
            if let Err(e) = store::save_vpn_proxies(&tools, &out) {
                return format!("❌ Не удалось удалить (не сохранилось на диск): {}", e);
            }
        } else {
            return "⚠️ Не найден".to_string();
        }
        id == state.conn.active_id()
    };
    if was_active {
        state.conn.stop(&app);
    }
    "🗑 Удалено".to_string()
}

#[tauri::command(async)]
pub fn vpn_remove_subscription(state: tauri::State<'_, std::sync::Arc<AppState>>, app: tauri::AppHandle, id: String) -> String {
    // async): см. vpn_remove — stop() активного сервера до ~10 с вне UI-потока
    let tools = state.tools();
    let (need_stop, msg) = {
        // stop() до ~10 с — вне guard'а vpn_store (см. vpn_remove)
        let _guard = state.vpn_store.lock().unwrap_or_else(|e| e.into_inner());
        let subs = store::load_vpn_subs(&tools);
        let mut out = Vec::new();
        let mut found = false;
        for x in subs {
            if x.id == id {
                found = true;
                continue;
            }
            out.push(x);
        }
        if !found {
            return "⚠️ Подписка не найдена".to_string();
        }
        if let Err(e) = store::save_vpn_subs(&tools, &out) {
            return format!("❌ Подписка не удалена (не сохранилось на диск): {}", e);
        }
        // Серверы из подписки удаляем, но добавленные вручную ключи оставляем:
        // отцепляем их от подписки (SubID=""), сами не удаляем.
        let proxies = store::load_vpn_proxies(&tools);
        let mut kept = Vec::new();
        for mut p in proxies {
            if p.sub_id.as_deref() == Some(id.as_str()) {
                if p.manual.unwrap_or(false) {
                    p.sub_id = Some(String::new());
                    p.manual = Some(false);
                    kept.push(p);
                }
                continue;
            }
            kept.push(p);
        }
        if let Err(e) = store::save_vpn_proxies(&tools, &kept) {
            log_add(
                "vpn",
                &format!("не удалось обновить proxies.json после удаления подписки: {}", e),
            );
        }
        let active = state.conn.active_id();
        if !active.is_empty() && !kept.iter().any(|p| p.id == active) {
            (true, "🗑 Подписка удалена (вместе с её серверами)".to_string())
        } else {
            (false, "🗑 Подписка удалена".to_string())
        }
    };
    if need_stop {
        // активный сервер был из удалённой подписки — отключаемся
        state.conn.stop(&app);
    }
    msg
}

#[tauri::command]
pub fn vpn_add_link(state: tauri::State<'_, std::sync::Arc<AppState>>, link: String, sub_id: String) -> String {
    use crate::vpnlinks::parse_link;
    let link = link.trim().to_string();
    if link.is_empty() {
        return "⚠️ Вставь ссылку сервера".to_string();
    }
    let tools = state.tools();
    let _guard = state.vpn_store.lock().unwrap_or_else(|e| e.into_inner());
    // Happ/INCY/V2RayTun-ссылки — это подписки, их место в карточке «Подписки»
    let low_in = link.to_lowercase();
    if low_in.starts_with("happ://") || low_in.starts_with("incy://") || low_in.starts_with("v2raytun://") {
        return "ℹ️ Это ссылка подписки — вставь её в карточку «Подписки» ниже (заведётся как подписка и будет обновляться)".to_string();
    }
    // Сначала пробуем всю вставку как одну ссылку (в fragment могут быть
    // пробелы), иначе — как пачку строк/токенов.
    let mut candidates: Vec<String> = Vec::new();
    if link.contains('\r') || link.contains('\n') {
        for ln in link.replace("\r\n", "\n").split('\n') {
            let ln = ln.trim();
            if ln.is_empty() {
                continue;
            }
            if parse_link(ln).is_ok() {
                candidates.push(ln.to_string());
            } else {
                candidates.extend(ln.split_whitespace().map(|s| s.to_string()));
            }
        }
    } else if parse_link(&link).is_err() {
        candidates = link.split_whitespace().map(|s| s.to_string()).collect();
    } else {
        candidates.push(link.clone());
    }
    let mut list = store::load_vpn_proxies(&tools);
    let mut sub_name = String::new();
    if !sub_id.is_empty() {
        for s in store::load_vpn_subs(&tools) {
            if s.id == sub_id {
                sub_name = s.name;
            }
        }
    }
    let (mut added, mut dupes, mut bad) = (0i32, 0i32, 0i32);
    let mut first: Option<VpnProxy> = None;
    for cand in &candidates {
        let Ok(p) = parse_link(cand) else {
            bad += 1;
            continue;
        };
        let dup = list.iter().any(|x| x.raw == p.raw);
        if dup {
            dupes += 1;
            continue;
        }
        let mut p = p;
        if !sub_name.is_empty() {
            p.sub_id = Some(sub_id.clone());
            p.manual = Some(true);
        }
        if first.is_none() {
            first = Some(p.clone());
        }
        list.push(p);
        added += 1;
    }
    let save_err = store::save_vpn_proxies(&tools, &list);
    if added == 0 {
        if dupes > 0 {
            return format!("⚠️ Все {} уже есть в списке", dupes);
        }
        return "❌ Не распознал ни одной ссылки".to_string();
    }
    let where_s = if !sub_name.is_empty() {
        format!(" → в подписку «{}»", sub_name)
    } else {
        String::new()
    };
    if let Err(e) = save_err {
        return format!("⚠️ Распознано {}, но НЕ СОХРАНЕНО на диск: {}", added, e);
    }
    if added == 1 {
        let f = first.unwrap();
        return format!(
            "✅ Добавлено: {} — {} {}:{}{}",
            f.name,
            f.proto.to_uppercase(),
            f.host,
            f.port,
            where_s
        );
    }
    let mut extra: Vec<String> = Vec::new();
    if !sub_name.is_empty() {
        extra.push(format!("в подписку «{}»", sub_name));
    }
    if dupes > 0 {
        extra.push(format!("дублей: {}", dupes));
    }
    if bad > 0 {
        extra.push(format!("не распознано: {}", bad));
    }
    let suffix = if extra.is_empty() {
        String::new()
    } else {
        format!(" ({})", extra.join(", "))
    };
    format!("✅ Добавлено серверов: {}{}", added, suffix)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// VpnRefreshSubscription — три фазы: (1) под мьютексом читаем параметры
// подписки, (2) БЕЗ мьютекса сетевая работа (до 30-60 с), (3) под мьютексом
// сливаем результат.
fn refresh_subscription_impl(state: &AppState, id: &str) -> String {
    use crate::subfetch::SubFetchInfo;
    let tools = state.tools();
    // Фаза 1: параметры подписки
    let (sub_name, sub_url) = {
        let _guard = state.vpn_store.lock().unwrap_or_else(|e| e.into_inner());
        let subs = store::load_vpn_subs(&tools);
        let mut found = None;
        for s in &subs {
            if s.id == id {
                found = Some((s.name.clone(), s.url.clone()));
                break;
            }
        }
        match found {
            Some(x) => x,
            None => return "⚠️ Подписка не найдена".to_string(),
        }
    };
    // Фаза 2: сеть БЕЗ мьютекса
    let low = sub_url.to_lowercase();
    let mut resolved_url = String::new();
    let info_cell = std::cell::RefCell::new(SubFetchInfo::default());
    let body;
    if low.starts_with("happ://") || low.starts_with("incy://") || low.starts_with("v2raytun://") {
        // клиентская ссылка: расшифровываем заново при каждом обновлении
        let (inner, text, _) = match crate::happcrypt::vpn_resolve_link(&sub_url, 0) {
            Err(e) => return format!("❌ {}: {}", sub_name, e),
            Ok(x) => x,
        };
        if !text.is_empty() {
            resolved_url = String::new(); // расшифровалось в готовое тело — URL нет
            body = text;
        } else {
            resolved_url = inner.clone();
            let st = store::load_vpn_settings(&tools);
            match crate::subfetch::sub_fetch_content_info(
                inner.trim(),
                st.spoof_ua.trim(),
                st.spoof_hwid.trim(),
                st.spoof_os.trim(),
                0,
                Some(&info_cell),
                None,
            ) {
                Err(e) => return format!("❌ {}: {}", sub_name, e),
                Ok(b) => body = b,
            }
        }
    } else {
        let st = store::load_vpn_settings(&tools);
        match crate::subfetch::sub_fetch_content_info(
            &sub_url,
            st.spoof_ua.trim(),
            st.spoof_hwid.trim(),
            st.spoof_os.trim(),
            0,
            Some(&info_cell),
            None,
        ) {
            Err(e) => return format!("❌ {}: {}", sub_name, e),
            Ok(b) => body = b,
        }
    }
    let info = info_cell.into_inner();
    let proxies_from_body = crate::subparse::parse_subscription_body(&tools, &body);
    if proxies_from_body.is_empty() {
        return format!("⚠️ {}: сервер вернул пустой или нераспознанный ответ", sub_name);
    }
    // Фаза 3: мерж под мьютексом
    let _guard = state.vpn_store.lock().unwrap_or_else(|e| e.into_inner());
    // подписку могли удалить, пока качали — не resurrect-им её
    let mut subs = store::load_vpn_subs(&tools);
    let still = subs.iter().any(|s| s.id == id);
    if !still {
        return format!("⚠️ {}: подписка удалена во время обновления", sub_name);
    }
    let mut kept: Vec<VpnProxy> = Vec::new();
    for p in store::load_vpn_proxies(&tools) {
        // Ручные ключи, добавленные в фильтре этой подписки, обновление
        // не должно удалять — они не пришли из тела подписки.
        if p.sub_id.as_deref() != Some(id) || p.manual.unwrap_or(false) {
            kept.push(p);
        }
    }
    let st = store::load_vpn_settings(&tools);
    let no_dupes = st.sub_no_dupes.unwrap_or(true);
    let (mut added, mut dupes) = (0i32, 0i32);
    for mut p in proxies_from_body {
        let mut dup = false;
        for x in &kept {
            // Дубли внутри одной подписки режем только при включённом запрете;
            // совпадение с ручным ключом — всегда дубль; разные подписки — разные ключи.
            let same_scope = x.sub_id.as_deref().map(|s| s.is_empty()).unwrap_or(true)
                || x.manual.unwrap_or(false)
                || (no_dupes && x.sub_id.as_deref() == Some(id));
            if !same_scope {
                continue;
            }
            if !p.raw.is_empty() && x.raw == p.raw {
                dup = true;
                break;
            }
            if x.proto == p.proto && x.host == p.host && x.port == p.port && x.name == p.name {
                dup = true;
                break;
            }
        }
        if dup {
            dupes += 1;
            continue;
        }
        p.sub_id = Some(id.to_string());
        p.manual = Some(false);
        kept.push(p);
        added += 1;
    }
    let save_err = store::save_vpn_proxies(&tools, &kept);
    let count = kept.iter().filter(|p| p.sub_id.as_deref() == Some(id)).count() as i64;
    for s in subs.iter_mut() {
        if s.id == id {
            s.updated_at = now_unix();
            s.resolved_url = if resolved_url.is_empty() { None } else { Some(resolved_url.clone()) };
            // метаданные панели: перезаписываем только непустыми значениями
            let t = crate::subparse::sub_maybe_b64(&info.profile_title);
            if !t.is_empty() {
                s.profile_title = Some(t.clone());
                // Имя подписки: если пользователь не задал своё (имя пустое,
                // «подписка» или совпадает с хостом ссылки), показываем
                // profile-title панели — человек осмысленное название вместо
                // начала адреса подписки.
                if is_auto_sub_name(&s.name, &s.url) {
                    s.name = t;
                }
            }
            let a = crate::subparse::sub_maybe_b64(&info.announce);
            if !a.is_empty() {
                s.announce = Some(a);
            } else if !info.announce_url.is_empty() {
                s.announce = Some(info.announce_url.clone());
            }
            if !info.web_page_url.is_empty() {
                s.web_page_url = Some(info.web_page_url.clone());
            }
            if !info.support_url.is_empty() {
                s.support_url = Some(info.support_url.clone());
            }
            let (up, down, total, exp) = crate::subparse::parse_sub_userinfo(&info.userinfo);
            if up > 0 || down > 0 || total > 0 || exp > 0 {
                s.info_upload = Some(up);
                s.info_download = Some(down);
                s.info_total = Some(total);
                s.info_expire = Some(exp);
            }
            // считаем ВСЕ серверы подписки, а не только добавленные
            s.count = count;
        }
    }
    let save_err2 = store::save_vpn_subs(&tools, &subs);
    if save_err.is_err() || save_err2.is_err() {
        let err_txt = save_err2.err().or_else(|| save_err.err()).unwrap_or_default();
        return format!("⚠️ {}: обновление НЕ сохранено на диск: {}", sub_name, err_txt);
    }
    // запрет дубликатов ВКЛЮЧЁН — дубли серверов режутся, показываем сколько
    if no_dupes {
        return format!(
            "✅ {}: обновлено — {} серверов (добавлено: {}, дублей пропущено: {})",
            sub_name, count, added, dupes
        );
    }
    // запрет ВЫКЛЮЧЕН — серверы не режутся (кроме совпадения с ручными ключами)
    if dupes > 0 {
        return format!(
            "✅ {}: обновлено — {} серверов (добавлено: {}, совпало с ручными ключами: {})",
            sub_name, count, added, dupes
        );
    }
    format!("✅ {}: обновлено — {} серверов (добавлено: {})", sub_name, count, added)
}

#[tauri::command]
pub async fn vpn_refresh_subscription(state: tauri::State<'_, std::sync::Arc<AppState>>, id: String) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || refresh_subscription_impl(&st, &id))
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub async fn vpn_refresh_all_subscriptions(state: tauri::State<'_, std::sync::Arc<AppState>>, app: tauri::AppHandle) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || refresh_all_impl(&st, &app))
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

fn refresh_all_impl(state: &AppState, app: &tauri::AppHandle) -> String {
    use tauri::Emitter;
    let tools = state.tools();
    let subs = {
        let _guard = state.vpn_store.lock().unwrap_or_else(|e| e.into_inner());
        store::load_vpn_subs(&tools)
    };
    if subs.is_empty() {
        return "⚠️ Подписок нет — добавь хотя бы одну".to_string();
    }
    // Одна подписка может качаться до 90 с (ретраи), поэтому ход публикуется
    // событием «subRefreshAll» (done/total/name) — фронтенд показывает прогресс.
    let total = subs.len() as i32;
    let (mut ok, mut bad) = (0i32, 0i32);
    let mut bad_names: Vec<String> = Vec::new();
    for (i, s) in subs.iter().enumerate() {
        let _ = app.emit(
            "subRefreshAll",
            serde_json::json!({"done": i as i32, "total": total, "name": s.name}),
        );
        let r = refresh_subscription_impl(state, &s.id);
        if r.starts_with("✅") {
            ok += 1;
        } else {
            bad += 1;
            if bad_names.len() < 4 {
                bad_names.push(s.name.clone());
            }
        }
    }
    let _ = app.emit("subRefreshAll", serde_json::json!({"done": total, "total": total, "name": ""}));
    let mut out = format!("🔄 Все подписки: успешно {}, с ошибками {} (из {})", ok, bad, total);
    if !bad_names.is_empty() {
        out += &format!(" — не обновились: {}", bad_names.join(", "));
    }
    log_add("vpn", &out);
    out
}

#[tauri::command]
pub async fn vpn_add_subscription(state: tauri::State<'_, std::sync::Arc<AppState>>, name: String, link: String) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || vpn_add_subscription_impl(&st, name, link))
        .await
                .unwrap_or_else(|e| format!("❌ {}", e)))
}

// is_auto_sub_name — имя подписки сгенерировано автоматически (не задано
// пользователем): пустое, «подписка» или совпадает с хостом ссылки.
// Такое имя можно безболезненно заменить на profile-title панели.
fn is_auto_sub_name(name: &str, url: &str) -> bool {
    let n = name.trim();
    if n.is_empty() || n == "подписка" {
        return true;
    }
    if let Ok(u) = url::Url::parse(url.trim()) {
        if let Some(h) = u.host_str() {
            return n.eq_ignore_ascii_case(h);
        }
    }
    false
}

fn vpn_add_subscription_impl(state: &AppState, name: String, link: String) -> String {
    use crate::models::VpnSubscription;
    let link = link.trim().to_string();
    let low = link.to_lowercase();
    let has_url = low.starts_with("http://") || low.starts_with("https://");
    let client_link =
        low.starts_with("happ://") || low.starts_with("incy://") || low.starts_with("v2raytun://");
    // Happ/INCY/V2RayTun-ссылка: проверяем расшифровку и вытаскиваем имя
    let mut name = name;
    let mut resolved = String::new();
    if client_link {
        let (inner, _, inner_name) = match crate::happcrypt::vpn_resolve_link(&link, 0) {
            Err(e) => return format!("❌ Ссылка не расшифровывается: {}", e),
            Ok(x) => x,
        };
        if !inner_name.is_empty() {
            name = inner_name;
        }
        resolved = inner;
    }
    let name = name.trim().to_string();
    let name = if name.is_empty() {
        let mut n = String::new();
        if has_url {
            if let Ok(u) = url::Url::parse(&link) {
                if let Some(h) = u.host_str() {
                    n = h.to_string();
                }
            }
        }
        if n.is_empty() {
            n = "подписка".to_string();
        }
        n
    } else {
        name
    };
    let tools = state.tools();
    let new_id;
    {
        let _guard = state.vpn_store.lock().unwrap_or_else(|e| e.into_inner());
        let mut subs = store::load_vpn_subs(&tools);
        // дубликаты: по сырой ссылке и по расшифрованному URL
        if has_url || client_link {
            let mut dup_name = String::new();
            for x in &subs {
                let mut matched = x.url == link;
                if !matched
                    && !resolved.is_empty()
                    && (x.resolved_url.as_deref() == Some(resolved.as_str())
                        || (x.resolved_url.is_none() && x.url == resolved))
                {
                    matched = true;
                }
                if !matched && x.resolved_url.as_deref() == Some(link.as_str()) {
                    matched = true;
                }
                if matched {
                    dup_name = x.name.clone();
                    break;
                }
            }
            if !dup_name.is_empty() {
                let st = store::load_vpn_settings(&tools);
                if st.sub_no_dupes.unwrap_or(true) {
                    return format!("⚠️ Такая подписка уже есть: {}", dup_name);
                }
            }
        }
        new_id = crate::vpnlinks::new_id();
        subs.push(VpnSubscription {
            id: new_id.clone(),
            name: name.clone(),
            url: link.clone(),
            resolved_url: if resolved.is_empty() { None } else { Some(resolved) },
            added_at: now_unix(),
            updated_at: 0,
            count: 0,
            profile_title: None,
            announce: None,
            web_page_url: None,
            support_url: None,
            info_upload: None,
            info_download: None,
            info_total: None,
            info_expire: None,
        });
        if let Err(e) = store::save_vpn_subs(&tools, &subs) {
            return format!("❌ Подписка не сохранена на диск: {}", e);
        }
    }
    if !has_url && !client_link {
        if !link.is_empty() {
            // нераспознанная схема (foo://bar): обновление будет падать
            return format!(
                "⚠️ Подписка «{}» создана, но ссылка не распознана (нет http(s)://, happ://, incy://, v2raytun://) — обновление будет падать",
                name
            );
        }
        // пустая подписка — ключи добавляются вручную
        return format!(
            "✅ Подписка «{}» создана (пустая). Выбери её в фильтре «👁 Фильтр» и добавляй ключи через «Добавить прокси»",
            name
        );
    }
    // сразу качаем/расшифровываем — НАМЕРЕННО без vpnStoreMu: сеть длится
    // до 30-60 с с ретраями
    refresh_subscription_impl(&state, &new_id)
}

#[tauri::command]
pub fn vpn_add_warp_config(state: tauri::State<'_, std::sync::Arc<AppState>>, name: String, conf: String) -> String {
    crate::warp::add_warp_config(&state, &name, &conf)
}

#[tauri::command(async)]
pub fn vpn_connect(
    state: tauri::State<'_, std::sync::Arc<AppState>>,
    app: tauri::AppHandle,
    id: String,
    force: Option<bool>,
) -> String {
    // async) — команда уходит с главного потока на пул: установка ядра
    // (скачивание + распаковка) фризила UI на десятки секунд. Синхронная
    // сигнатура сохранена специально: async fn со State требует Result и
    // меняет контракт фронтенда.
    // force=true — «Всё равно подключиться»: пропустить пробу трафика после
    // «Сервер недоступен» на проверке (старые вызовы без force — как раньше).
    vpn_connect_impl(&state, app, id, force.unwrap_or(false))
}

pub(crate) fn vpn_connect_impl(state: &std::sync::Arc<AppState>, app: tauri::AppHandle, id: String, force: bool) -> String {
    let tools = state.tools();
    // настройки и сервер — под vpnStoreMu (как в Go). Авто-включение режима и
    // обратная запись settings.json — под ТЕМ ЖЕ guard'ом: запись вне лока
    // давала lost update с параллельным vpn_set_settings.
    let (st, p) = {
        let _guard = state.vpn_store.lock().unwrap_or_else(|e| e.into_inner());
        let mut st = store::load_vpn_settings(&tools);
        let mut found = None;
        for x in store::load_vpn_proxies(&tools) {
            if x.id == id {
                found = Some(x);
            }
        }
        let p = match found {
            Some(p) => p,
            None => return "❌ Сервер не найден".to_string(),
        };
        // если не выбран ни один режим — по умолчанию TUN (sing-box) или
        // системный прокси; WARP не трогаем — он всегда полный TUN
        if p.proto != "warp" && !st.tun && !st.system_proxy {
            if st.core == "sing-box" {
                st.tun = true;
                log_add("core", "режим не выбран — автоматически включён TUN (по умолчанию)");
            } else {
                st.system_proxy = true;
                log_add("core", "режим не выбран — включён системный прокси (TUN только у sing-box)");
            }
            if let Err(e) = store::save_vpn_settings(&tools, &st) {
                // Обратная запись критична (см. комментарий выше): при отказе
                // диск/лок фактический режим (TUN/прокси в памяти) разойдётся
                // с settings.json — после рестарта UI показывал бы не то,
                // что реально включено. Молча глотать ошибку нельзя.
                log_add(
                    "vpn",
                    &format!("не удалось сохранить авто-включённый режим в settings.json: {}", e),
                );
            }
        }
        (st, p)
    };
    // (проверка WDTT пропущена: pwdtt-туннель ещё не перенесён)
    // автовыбор ядра по ключу: xhttp — только xray, hysteria2 — только sing-box
    let core = crate::vpnconfig::core_for_key(&p, &st.core);
    if p.proto != "warp" {
        // WARP-конфиги работают встроенным ядром без внешнего sing-box/xray
        if !paths::vpn_core_exe_for(&tools, &core).exists() {
            let r = crate::tools::vpn_install_core(&tools, &core);
            if r.starts_with("❌") {
                return r;
            }
        }
        // xhttp-ключ + TUN: для цепочки sing-box.exe и wintun.dll тоже нужны
        if core == "xray" && st.tun && !paths::vpn_core_exe_for(&tools, "sing-box").exists() {
            let r = crate::tools::vpn_install_core(&tools, "sing-box");
            if r.starts_with("❌") {
                return format!("❌ Для TUN-цепочки нужен sing-box, установка не удалась: {}", r);
            }
        }
    }
    // Подключение глушит «Тест задержки»: его временные ядра делят с пробой
    // сеть, а на ключ во время его же пинга приходят два соединения.
    crate::ping::vpn_ping_kill_all();
    let (ok, err) = state.conn.clone().start(app, p.clone(), core, st, force);
    if !ok {
        return err;
    }
    format!("⏳ Подключаюсь: {}", p.name)
}

#[tauri::command(async)]
pub fn vpn_disconnect(state: tauri::State<'_, std::sync::Arc<AppState>>, app: tauri::AppHandle) -> String {
    // async): stop() ждёт смерти ядра (до 2 с) и исчезновения TUN-адаптера
    // (до 8 с) под мьютексом — на главном потоке это фриз UI на ~10 с.
    state.conn.stop(&app);
    "✅ Отключено".to_string()
}

#[tauri::command]
pub async fn vpn_export_warp_conf(
    state: tauri::State<'_, std::sync::Arc<AppState>>,
    id: String,
) -> Result<String, String> {
    // rfd-диалог в отдельном потоке (см. save_logs_file)
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::warp::export_warp_conf(&st, &id))
        .await
        .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub async fn vpn_import_warp_conf(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Result<String, String> {
    // диалог выбора .conf → чтение (BOM/UTF-16) → добавление как сервера.
    // rfd-диалог + файловый I/O — в отдельном потоке (см. save_logs_file).
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Выбери конфиг AmneziaWG / WireGuard")
            .add_filter("Конфиги (*.conf;*.txt)", &["conf", "txt"])
            .add_filter("Все файлы (*.*)", &["*"])
            .pick_file()
        else {
            return String::new(); // отмена
        };
        let Ok(data) = std::fs::read(&path) else {
            return "❌ Не смог прочитать файл".to_string();
        };
        let base = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        crate::warp::add_warp_config(&st, &base, &crate::warp::warp_decode_conf_file(&data))
    })
    .await
    .unwrap_or_else(|e| format!("❌ {}", e)))
}

#[tauri::command]
pub async fn vpn_generate_warp_conf(endpoint: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || crate::warp::generate_warp_conf(&endpoint))
        .await
        .map_err(|e| format!("❌ {}", e))?
        .map_err(|e| format!("❌ {}", e))
}

#[tauri::command]
pub async fn vpn_install_core(state: tauri::State<'_, std::sync::Arc<AppState>>, core: String) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::tools::vpn_install_core(&st.tools(), &core))
        .await
        .unwrap_or_else(|e| format!("❌ {}", e)))
}

// (реальные реализации vpn_refresh_subscription / vpn_refresh_all_subscriptions /
// vpn_add_subscription — выше, рядом с refresh_subscription_impl)

#[tauri::command]
pub async fn vpn_ping(state: tauri::State<'_, std::sync::Arc<AppState>>, id: String) -> Result<i64, String> {
    let st = state.inner().clone();
    // панику воркера не глотаем молча: лог + «сервер мёртв», как раньше
    Ok(tauri::async_runtime::spawn_blocking(move || crate::ping::vpn_ping(&st.tools(), &id))
        .await
        .unwrap_or_else(|e| {
            log_add("ping", &format!("vpn_ping упал: {}", e));
            -1
        }))
}

#[tauri::command]
pub async fn vpn_ping_through(state: tauri::State<'_, std::sync::Arc<AppState>>, id: String) -> Result<i64, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::ping::vpn_ping_through(&st, &id))
        .await
        .unwrap_or_else(|e| {
            log_add("ping", &format!("vpn_ping_through упал: {}", e));
            -1
        }))
}

#[tauri::command]
pub async fn vpn_check_ip(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Result<String, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::geo::check_ip(&st))
        .await
        .map_err(|e| format!("❌ check_ip: {}", e))?)
}

#[tauri::command(async)]
pub fn vpn_status(state: tauri::State<'_, std::sync::Arc<AppState>>, app: tauri::AppHandle) -> VpnStatusInfo {
    // async): опрос статуса берёт conn.inner (который stop() держит до ~10 с),
    // при «висящей» фазе сам делает stop_attempt, и в «connected» проверяет
    // порт TCP-connect'ом — всё это не должно выполняться на главном потоке
    crate::conn::vpn_status_impl(&state.conn, &app)
}

#[tauri::command]
pub async fn vpn_traffic(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Result<VpnTrafficInfo, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::conn::vpn_traffic_impl(st.conn.is_connected()))
        .await
        .map_err(|e| format!("❌ traffic: {}", e))?)
}

#[tauri::command]
pub async fn vpn_geo(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Result<VpnGeoInfo, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::geo::vpn_geo(&st))
        .await
        .map_err(|e| format!("❌ geo: {}", e))?)
}

#[tauri::command]
pub async fn vpn_servers_geo(state: tauri::State<'_, std::sync::Arc<AppState>>) -> Result<HashMap<String, ServerGeo>, String> {
    let st = state.inner().clone();
    Ok(tauri::async_runtime::spawn_blocking(move || crate::geo::servers_geo(&st))
        .await
        .map_err(|e| format!("❌ servers_geo: {}", e))?)
}

#[tauri::command]
pub fn vpn_services() -> VpnServicesInfo {
    crate::geo::services_info()
}

#[tauri::command]
pub fn vpn_flags() -> HashMap<String, String> {
    crate::geo::vpn_flags()
}

#[tauri::command]
pub fn vpn_start_service_checks(state: tauri::State<'_, std::sync::Arc<AppState>>) -> String {
    crate::geo::start_service_checks(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::io::{BufRead, BufReader, Write};

    // Полный флоу VpnRefreshSubscription на мок-сервере с ИЗОЛИРОВАННЫМ
    // tools-каталогом (реальный D:\NetTools не трогается).
    #[test]
    fn refresh_subscription_end_to_end() {
        let tmp = std::env::temp_dir().join(format!("sentor-test-{}", uuid::Uuid::new_v4()));
        let tools = tmp.join("NetTools");
        std::fs::create_dir_all(tools.join("vpn")).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // тело: дубль внутри подписки (режется при noDupes) + уникальный
        let body = "vless://u@1.1.1.1:443#Alpha\nvless://u@1.1.1.1:443#Alpha\nvless://v@2.2.2.2:443#Beta\n";
        let title_payload = base64::engine::general_purpose::STANDARD.encode("Тест профиль".as_bytes());
        let server = std::thread::spawn(move || {
            for _ in 0..1 {
                let (mut sock, _) = listener.accept().unwrap();
                {
                    let mut r = BufReader::new(&sock);
                    loop {
                        let mut line = String::new();
                        let _ = r.read_line(&mut line);
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                    }
                }
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nProfile-Title: base64:{}\r\nSubscription-Userinfo: upload=1; download=2; total=10; expire=1790000000\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    title_payload,
                    body.len()
                );
                let _ = sock.write_all(hdr.as_bytes());
                let _ = sock.write_all(body.as_bytes());
            }
        });

        let sub_url = format!("http://{}/sub.txt", addr);
        let subs = format!(
            r#"[{{"id":"testsub","name":"Мок-подписка","url":"{}","addedAt":1,"updatedAt":0,"count":0}}]"#,
            sub_url
        );
        std::fs::write(tools.join("vpn").join("subscriptions.json"), subs).unwrap();

        let state = AppState::new();
        state.tools_dir.set(tools.clone()).unwrap();

        let result = refresh_subscription_impl(&state, "testsub");
        assert!(result.starts_with("✅"), "got: {}", result);
        assert!(result.contains("обновлено — 2 серверов"), "got: {}", result);
        assert!(result.contains("дублей пропущено: 1"), "got: {}", result);

        let proxies: Vec<VpnProxy> = serde_json::from_str(
            &std::fs::read_to_string(tools.join("vpn").join("proxies.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].sub_id.as_deref(), Some("testsub"));
        assert_eq!(proxies[0].manual, Some(false));

        let subs: Vec<VpnSubscription> = serde_json::from_str(
            &std::fs::read_to_string(tools.join("vpn").join("subscriptions.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(subs[0].count, 2);
        assert!(subs[0].updated_at > 0);
        assert_eq!(subs[0].profile_title.as_deref(), Some("Тест профиль"));
        assert_eq!(subs[0].info_total, Some(10));

        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn auto_sub_name_detection() {
        // auto (пустое, «подписка», хост ссылки) — можно переименовать в profile-title
        assert!(is_auto_sub_name("", "https://sub.example.com/s"));
        assert!(is_auto_sub_name("подписка", "https://sub.example.com/s"));
        assert!(is_auto_sub_name("SUB.Example.com", "https://sub.example.com/s"));
        assert!(is_auto_sub_name("подписка", "happ://crypt2AAAAAAAAAA"));
        // имя задано пользователем — не трогаем
        assert!(!is_auto_sub_name("Моя подписка", "https://sub.example.com/s"));
        assert!(!is_auto_sub_name("Мок-подписка", "https://sub.example.com/s"));
    }

    #[test]
    fn cqstt_default_port_cases() {
        assert_eq!(cqstt_with_default_port("1.2.3.4"), "1.2.3.4:46000");
        assert_eq!(cqstt_with_default_port("example.com:55000"), "example.com:55000");
        // голый IPv6 без порта раньше уходил в ядро БЕЗ порта (p.contains(':')
        // «защищал» его от дописывания)
        assert_eq!(cqstt_with_default_port("2001:db8::1"), "[2001:db8::1]:46000");
        assert_eq!(cqstt_with_default_port("[2001:db8::1]:46000"), "[2001:db8::1]:46000");
    }

    #[test]
    fn csqtt_v2_link_order_and_decode() {
        // порядок ключей не должен влиять: peer приходил раньше host, и порт
        // молча терялся; percent-escape в пароле декодируются целиком
        let s1 = csqtt_parse_v2("v=2&peer=55000&host=1.2.3.4&password=p%40w&hashes=h1%2Ch2").unwrap();
        assert_eq!(s1.peer, "1.2.3.4:55000");
        assert_eq!(s1.password, "p@w");
        assert_eq!(s1.hashes, "h1\nh2");
        let s2 = csqtt_parse_v2("v=2&host=5.6.7.8&peer=46000&password=x").unwrap();
        assert_eq!(s2.peer, "5.6.7.8:46000");
        // peer уже «host:port»
        let s3 = csqtt_parse_v2("v=2&peer=9.9.9.9:47000&password=x").unwrap();
        assert_eq!(s3.peer, "9.9.9.9:47000");
    }
}
