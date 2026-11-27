// Latency testing - port of Go VpnPing/VpnPingThrough and the temp-core
// ping workers (vpn.go). Тест задержки: временное ядро на свободном порту,
// URLTest дважды (Throne-схема), опционально стресс-проверка канала.
use std::net::{IpAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::logging::log_add;
use crate::paths;
use crate::store;

// icmpPing — обычный ICMP-пинг до хоста через системный IcmpSendEcho
// (права админа не нужны, домены резолвятся сами).
pub fn icmp_ping(host: &str, timeout: Duration) -> Result<i64, String> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = format!("{}:0", host)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .filter(|a| a.is_ipv4())
        .collect();
    let addr = addrs.first().ok_or("нет IPv4-адреса")?;
    let ip: IpAddr = addr.ip();
    let IpAddr::V4(v4) = ip else {
        return Err("не IPv4-адрес".into());
    };
    let ip_u32 = u32::from(v4).to_be();

    use windows_sys::Win32::NetworkManagement::IpHelper::{IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho};
    unsafe {
        let h = IcmpCreateFile();
        if h.is_null() {
            return Err("IcmpCreateFile failed".into());
        }
        let req = [0u8; 8]; // данные Echo Request
        let mut reply = [0u8; 1 << 12];
        let t0 = Instant::now();
        let n = IcmpSendEcho(
            h,
            ip_u32,
            req.as_ptr() as *const std::ffi::c_void,
            req.len() as u16,
            std::ptr::null(),
            reply.as_mut_ptr() as *mut std::ffi::c_void,
            reply.len() as u32,
            timeout.as_millis() as u32,
        );
        let result = if n == 0 {
            Err("нет ответа".to_string())
        } else {
            // ICMP_ECHO_REPLY: Status — смещение 4 (как в Go: reply[4:8])
            let status = u32::from_le_bytes([reply[4], reply[5], reply[6], reply[7]]);
            if status != 0 {
                Err(format!("ICMP status {}", status))
            } else {
                Ok(t0.elapsed().as_millis() as i64)
            }
        };
        IcmpCloseHandle(h);
        result
    }
}

// vpnTcpPing — прямое TCP-подключение к серверу
pub fn vpn_tcp_ping(host: &str, port: i32, timeout: Duration) -> i64 {
    let t0 = Instant::now();
    let target = format!("{}:{}", host, port);
    use std::net::ToSocketAddrs;
    let Ok(addrs) = target.to_socket_addrs() else {
        return -1;
    };
    // Перебираем ВСЕ адреса (A + AAAA): первый из резолва может быть нерабочим
    // (битый AAAA/приоритет v6) — раньше это давало ложный «сервер мёртв».
    for addr in addrs {
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return t0.elapsed().as_millis() as i64;
        }
    }
    -1
}

pub fn vpn_icmp_host_ping(host: &str, timeout: Duration) -> i64 {
    icmp_ping(host, timeout).unwrap_or(-1)
}

// normalizeTestUrl — приводит тестовый URL к виду со схемой; пусто → дефолт.
pub fn normalize_test_url(u: &str, def: &str) -> String {
    let t = u.trim();
    if t.is_empty() {
        return def.to_string();
    }
    if !t.starts_with("http://") && !t.starts_with("https://") {
        return format!("https://{}", t);
    }
    t.to_string()
}

// ---------- реестр временных ядер пинговки ----------

static PING_REGISTRY: Mutex<Vec<Arc<Mutex<std::process::Child>>>> = Mutex::new(Vec::new());

fn ping_register(child: Arc<Mutex<std::process::Child>>) {
    PING_REGISTRY.lock().unwrap_or_else(|e| e.into_inner()).push(child);
}

// Предохранитель от «100 потоков = 100 sing-box разом»: реальный потолок
// одновременных временных ядер. Фронт шлёт N воркеров (testThreads), лишние
// ждут очереди здесь. Абсолютный кап 16 — 700 конфигов не должны ронять UI.
static PING_ACTIVE: Mutex<usize> = Mutex::new(0);
static PING_CV: std::sync::Condvar = std::sync::Condvar::new();

const PING_CORES_HARD_CAP: usize = 16;

struct PingPermit;

impl PingPermit {
    fn acquire(max: usize) -> PingPermit {
        let max = max.clamp(1, PING_CORES_HARD_CAP);
        let mut active = PING_ACTIVE.lock().unwrap_or_else(|e| e.into_inner());
        while *active >= max {
            active = PING_CV.wait(active).unwrap();
        }
        *active += 1;
        PingPermit
    }
}

impl Drop for PingPermit {
    fn drop(&mut self) {
        let mut active = PING_ACTIVE.lock().unwrap_or_else(|e| e.into_inner());
        *active -= 1;
        drop(active);
        PING_CV.notify_one();
    }
}

// vpnPingKillAll гасит все временные ядра пинговки (вызывается при подключении).
pub fn vpn_ping_kill_all() {
    let mut reg = PING_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    for child in reg.drain(..) {
        if let Ok(mut c) = child.lock() {
            let _ = c.kill();
        }
    }
}

// VpnPing — быстрый пинг: TCP к серверу (WARP — ICMP дважды).
pub fn vpn_ping(tools: &Path, id: &str) -> i64 {
    let list = store::load_vpn_proxies(tools);
    let Some(p) = list.iter().find(|x| x.id == id) else {
        return -1;
    };
    if p.proto == "warp" {
        // WARP-endpoint — UDP: TCP-пинг неприменим; ICMP у Cloudflare бывает
        // потерян — пробуем дважды
        if let Ok(ms) = icmp_ping(&p.host, Duration::from_secs(3)) {
            return ms;
        }
        return icmp_ping(&p.host, Duration::from_secs(3)).unwrap_or(-1);
    }
    let t0 = Instant::now();
    let target = format!("{}:{}", p.host, p.port);
    use std::net::ToSocketAddrs;
    let Ok(addrs) = target.to_socket_addrs() else {
        return -1;
    };
    // как в vpn_tcp_ping: перебираем все адреса резолва
    for addr in addrs {
        if TcpStream::connect_timeout(&addr, Duration::from_secs(4)).is_ok() {
            return t0.elapsed().as_millis() as i64;
        }
    }
    -1
}

// VpnPingThrough — настоящая проверка «как при подключении»: временный конфиг,
// ядро на свободном порту, запрос тестового URL через туннель. Ядро останавливается.
pub fn vpn_ping_through(state: &crate::state::AppState, id: &str) -> i64 {
    let tools = state.tools();
    let list = store::load_vpn_proxies(&tools);
    let Some(p) = list.iter().find(|x| x.id == id) else {
        return -1;
    };
    let p = p.clone();
    let st = store::load_vpn_settings(&tools);
    let timeout_sec = st.test_timeout.clamp(1, 30) as u64;
    let timeout = Duration::from_secs(timeout_sec);
    // методы проверки: http — через туннель; tcp/icmp — прямые проверки сервера
    match st.ping_method.as_str() {
        "tcp" => return vpn_tcp_ping(&p.host, p.port, timeout),
        "icmp" => return vpn_icmp_host_ping(&p.host, timeout),
        _ => {}
    }
    if p.proto == "warp" {
        // WARP в vpnOutbound не поддерживается — http-пинга через временное
        // ядро для него нет; ICMP-ветка живёт в vpn_ping
        return -1;
    }
    // автовыбор ядра по ключу: xhttp — xray, hysteria2 — sing-box
    let core = crate::vpnconfig::core_for_key(&p, &st.core);
    if !paths::vpn_core_exe_for(&tools, &core).exists() {
        // ядро ещё не распаковано — ставим, иначе xhttp-ключи вечно ✗
        let r = crate::tools::vpn_install_core(&tools, &core);
        if r.starts_with("❌") {
            return -1;
        }
    }
    // Предохранитель: не больше PING_CORES_HARD_CAP временных ядер разом,
    // остальные воркеры фронта ждут очереди (700 конфигов ≠ 700 sing-box).
    let _permit = PingPermit::acquire(st.test_threads.max(1) as usize);
    // свободный порт для временного инбаунда
    let port = {
        let Ok(ln) = std::net::TcpListener::bind("127.0.0.1:0") else {
            return -1;
        };
        let port = ln.local_addr().map(|a| a.port() as i32).unwrap_or(0);
        drop(ln);
        port
    };
    if port == 0 {
        return -1;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // id приходит из UI — в имя файла попадают только безопасные символы
    let safe_id: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cfg_path: PathBuf = paths::vpn_dir(&tools).join(format!("test_{}_{}.json", safe_id, stamp));
    let build_ok = match core.as_str() {
        "sing-box" => crate::vpnconfig::write_vpn_config(&tools, &p, port, false, true, &cfg_path, 0, ""),
        "xray" => crate::vpnconfig::build_xray_config(&tools, &p, port, &cfg_path, false),
        _ => Err("неизвестное ядро".into()),
    };
    if build_ok.is_err() {
        return -1;
    }
    use std::os::windows::process::CommandExt;
    let exe = paths::vpn_core_exe_for(&tools, &core);
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(["run", "-c"])
        .arg(&cfg_path)
        .current_dir(paths::vpn_core_dir(&tools))
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    log_add("ping", &format!("тест: {} ({})", p.name, p.proto));
    if p.proto == "hysteria2" {
        // диагностика hy2: какие параметры есть в ссылке (без значений)
        let mut keys: Vec<String> = p
            .extra
            .as_ref()
            .map(|e| e.keys().filter(|k| k.as_str() != "cred").cloned().collect())
            .unwrap_or_default();
        keys.sort();
        log_add("ping", &format!("hy2 параметры: {}", keys.join(", ")));
    }
    let Ok(mut child) = cmd.spawn() else {
        let _ = std::fs::remove_file(&cfg_path);
        return -1;
    };
    // ошибки тестового ядра — в общий лог
    if let Some(mut out) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut out, &mut s);
            for line in s.lines() {
                if !line.trim().is_empty() {
                    log_add("ping", line.trim_end_matches('\r'));
                }
            }
        });
    }
    if let Some(mut err) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut err, &mut s);
            for line in s.lines() {
                if !line.trim().is_empty() {
                    log_add("ping", line.trim_end_matches('\r'));
                }
            }
        });
    }
    // Job Object + реестр: kill при подключении гасит все тестовые ядра.
    // Дескриптор закрывается автоматически (Drop) на выходе из функции —
    // после kill ядра, так что KILL_ON_JOB_CLOSE ничему живому не навредят.
    let job = crate::conn::new_kill_on_close_job();
    if let Some(job) = &job {
        job.attach(child.id());
    }
    let child_arc = Arc::new(Mutex::new(child));
    ping_register(child_arc.clone());
    // ждём подъёма инбаунда; битый конфиг: ядро вышло сразу — не ждём весь таймаут
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if crate::conn::port_open(port) {
            break;
        }
        let exited = child_arc.lock().ok().and_then(|mut c| c.try_wait().ok()).map(|s| s.is_some()).unwrap_or(true);
        if exited {
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    if !crate::conn::port_open(port) {
        if let Ok(mut c) = child_arc.lock() {
            let _ = c.kill();
        }
        let _ = std::fs::remove_file(&cfg_path);
        // сняться с учёта
        PING_REGISTRY.lock().unwrap_or_else(|e| e.into_inner()).retain(|c| !Arc::ptr_eq(c, &child_arc));
        return -1;
    }
    // Инбаунд обоих ядер говорит HTTP/CONNECT: sing-box — mixed, xray — http.
    let proxy = format!("http://127.0.0.1:{}", port);
    // порт — наш, URL валиден почти всегда; без unwrap: не распарсился —
    // обычный «сервер мёртв» с уборкой, а не паника потока
    let Ok(proxy_cfg) = reqwest::Proxy::all(&proxy) else {
        if let Ok(mut c) = child_arc.lock() {
            let _ = c.kill();
        }
        let _ = std::fs::remove_file(&cfg_path);
        PING_REGISTRY.lock().unwrap_or_else(|e| e.into_inner()).retain(|c| !Arc::ptr_eq(c, &child_arc));
        return -1;
    };
    let client = match reqwest::blocking::Client::builder().proxy(proxy_cfg).timeout(timeout).build() {
        Ok(c) => c,
        Err(_) => {
            if let Ok(mut c) = child_arc.lock() {
                let _ = c.kill();
            }
            let _ = std::fs::remove_file(&cfg_path);
            PING_REGISTRY.lock().unwrap_or_else(|e| e.into_inner()).retain(|c| !Arc::ptr_eq(c, &child_arc));
            return -1;
        }
    };
    let test_url = normalize_test_url(&st.test_url.clone().unwrap_or_default(), "https://www.gstatic.com/generate_204");
    // Throne-схема URLTest (twice): холодный конфиг тестируется дважды — первый
    // проход прогревает рукопожатие, задержка берётся из второго (тёплого).
    let mut ms: i64 = -1;
    let mut last_err = String::new();
    for _ in 0..2 {
        let t0 = Instant::now();
        match client.get(&test_url).send() {
            Err(e) => {
                // Транзиентный сбой ТЁПЛОГО прохода при уже измерённом холодном
                // не должен обнулять результат: связь есть. Ошибка холодного
                // прохода (ms ещё -1) — честный провал.
                if ms < 0 {
                    last_err = e.to_string();
                }
                break;
            }
            Ok(resp) => {
                if resp.status().as_u16() >= 400 {
                    last_err = format!("HTTP {}", resp.status().as_u16());
                    break;
                }
                ms = t0.elapsed().as_millis() as i64;
            }
        }
    }
    if !last_err.is_empty() {
        log_add("ping", &format!("urltest: {}", last_err));
        if let Ok(mut c) = child_arc.lock() {
            let _ = c.kill();
        }
        let _ = std::fs::remove_file(&cfg_path);
        PING_REGISTRY.lock().unwrap_or_else(|e| e.into_inner()).retain(|c| !Arc::ptr_eq(c, &child_arc));
        return -1;
    }
    if st.test_throughput.unwrap_or(false) {
        let (n, secs) = crate::conn::throughput_stress(&client, 1, 128 * 1024, Duration::from_secs(5));
        if n < 128 * 1024 {
            log_add("ping", &format!("throughput: {} КБ за {:.1} с — ключ не качает", n / 1024, secs));
            if let Ok(mut c) = child_arc.lock() {
                let _ = c.kill();
            }
            let _ = std::fs::remove_file(&cfg_path);
            PING_REGISTRY.lock().unwrap_or_else(|e| e.into_inner()).retain(|c| !Arc::ptr_eq(c, &child_arc));
            return -1;
        }
    }
    // уборка: kill ядра → удаление конфига → снятие с учёта; дескриптор Job
    // закроется Drop'ом на выходе (KILL_ON_JOB_CLOSE добьёт остатки)
    if let Ok(mut c) = child_arc.lock() {
        let _ = c.kill();
    }
    let _ = std::fs::remove_file(&cfg_path);
    PING_REGISTRY.lock().unwrap_or_else(|e| e.into_inner()).retain(|c| !Arc::ptr_eq(c, &child_arc));
    ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_test_url_cases() {
        assert_eq!(normalize_test_url("", "https://def.example/204"), "https://def.example/204");
        assert_eq!(normalize_test_url("google.com", "d"), "https://google.com");
        assert_eq!(normalize_test_url("  http://x.y/204  ", "d"), "http://x.y/204");
        assert_eq!(normalize_test_url("https://a.b/", "d"), "https://a.b/");
    }

    #[test]
    fn tcp_ping_localhost() {
        let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ln.local_addr().unwrap().port() as i32;
        std::thread::spawn(move || {
            for _ in 0..5 {
                let _ = ln.accept();
            }
        });
        let ms = vpn_tcp_ping("127.0.0.1", port, Duration::from_secs(2));
        assert!(ms >= 0);
        let bad = vpn_tcp_ping("127.0.0.1", 1, Duration::from_millis(300));
        assert_eq!(bad, -1);
    }
}
