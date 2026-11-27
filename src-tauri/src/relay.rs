// Telegram counting relay - port of Go relay.go runRelayProcess and tg config helpers.
// Runs as a separate no-GUI process: sentor.exe --relay <listenPort> <backendPort> <statsFile>
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::models::RelayStats;

pub fn write_relay_stats(path: &str, s: &RelayStats) {
    let Ok(b) = serde_json::to_vec(s) else {
        eprintln!("relay stats marshal: failed");
        return;
    };
    let tmp = format!("{}.tmp", path);
    if let Err(e) = std::fs::write(&tmp, &b) {
        // stats перестал писаться (диск, права) — главный процесс будет
        // считать релей по устаревшим данным; хотя бы оставим след в stderr
        eprintln!("relay stats write: {}", e);
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        eprintln!("relay stats rename: {}", e);
    }
}

pub fn run_relay_process(listen: &str, backend: &str, stats_path: &str) {
    let Ok(port) = listen.parse::<u16>() else {
        std::process::exit(1);
    };
    let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) else {
        std::process::exit(1); // порт занят — главный процесс увидит мёртвый pid и пересоздаст
    };
    let total = Arc::new(AtomicU64::new(0));
    let actual_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut s = RelayStats {
        bytes: 0,
        pid: std::process::id() as i32,
        port: actual_port as i32,
    };
    write_relay_stats(stats_path, &s);
    {
        let total = total.clone();
        let path = stats_path.to_string();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(1));
            s.bytes = total.load(Ordering::Relaxed);
            write_relay_stats(&path, &s);
        });
    }
    // Порт tg-ws-proxy мог смениться (прокси перезапущен на другой порт при
    // живом релее) — перечитываем конфиг не чаще раза в 30 секунд.
    let tools_dir = Path::new(stats_path).parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let backend_state = Arc::new(Mutex::new((backend.to_string(), Instant::now())));

    // Лимит одновременных соединений: легальный трафик Telegram — единицы
    // WS-соединений; зависший/злобный локальный клиент раньше плодил сотни
    // потоков (по 2 потока + 2 сокета на соединение, живут до 15 мин).
    const RELAY_MAX_CONNS: usize = 128;
    let active = Arc::new(AtomicU64::new(0));

    for incoming in listener.incoming() {
        let Ok(client) = incoming else {
            // транзиентный сбой Accept не должен убивать релей целиком
            eprintln!("relay accept error");
            std::thread::sleep(Duration::from_millis(200));
            continue;
        };
        if active.load(Ordering::Relaxed) >= RELAY_MAX_CONNS as u64 {
            let client = client;
            let _ = client.shutdown(Shutdown::Both);
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let total = total.clone();
        let backend_state = backend_state.clone();
        let tools_dir = tools_dir.clone();
        let active2 = active.clone();
        std::thread::spawn(move || {
            handle_conn(client, total, backend_state, tools_dir);
            active2.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

// handle_conn — тело одного соединения: подключение к бэкенду и две трубы.
fn handle_conn(
    mut client: TcpStream,
    total: Arc<AtomicU64>,
    backend_state: Arc<Mutex<(String, Instant)>>,
    tools_dir: PathBuf,
) {
    let backend_port = backend_now(&backend_state, &tools_dir);
    let Ok(backend_addr) = format!("127.0.0.1:{}", backend_port).parse::<std::net::SocketAddr>() else {
        return;
    };
    let Ok(mut backend) = TcpStream::connect_timeout(&backend_addr, Duration::from_secs(3)) else {
        return;
    };
    let Ok(mut backend2) = backend.try_clone() else { return };
    let Ok(mut client2) = client.try_clone() else { return };
    let t1_total = total.clone();
    let t2_total = total.clone();
    // Клиент → бэкенд: EOF клиента — половинно закрываем бэкенд,
    // чтобы он мог ещё дописать ответ.
    let t1 = std::thread::spawn(move || {
        let r = pipe(&mut backend, &mut client, &t1_total);
        match r {
            Ok(_) => { let _ = backend.shutdown(Shutdown::Write); }
            Err(_) => {
                let _ = backend.shutdown(Shutdown::Both);
                let _ = client.shutdown(Shutdown::Both);
            }
        }
    });
    // Бэкенд → клиент
    let t2 = std::thread::spawn(move || {
        let r = pipe(&mut client2, &mut backend2, &t2_total);
        match r {
            Ok(_) => { let _ = client2.shutdown(Shutdown::Write); }
            Err(_) => {
                let _ = backend2.shutdown(Shutdown::Both);
                let _ = client2.shutdown(Shutdown::Both);
            }
        }
    });
    let _ = t1.join();
    let _ = t2.join();
}

// Idle-таймаут релея: WS-соединения Telegram могут легально молчать минуты,
// но соединение с молчаливо пропавшим пиром (обрыв без RST/FIN) раньше
// держало по 3 потока и 2 сокета вечно. 15 минут generous-порог.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

// Копирование одного направления с подсчётом записанных байт.
fn pipe(dst: &mut TcpStream, src: &mut TcpStream, total: &AtomicU64) -> std::io::Result<()> {
    let _ = src.set_read_timeout(Some(RELAY_IDLE_TIMEOUT));
    let _ = dst.set_write_timeout(Some(Duration::from_secs(30)));
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                dst.write_all(&buf[..n])?;
                total.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "relay idle timeout"));
            }
            Err(e) => return Err(e),
        }
    }
}

fn backend_now(state: &Mutex<(String, Instant)>, tools_dir: &Path) -> String {
    // poison-safe: паника другого потока не должна каскадно убивать релей
    let mut st = state.lock().unwrap_or_else(|e| e.into_inner());
    if st.1.elapsed() > Duration::from_secs(30) {
        if let Some(m) = find_tg_config(tools_dir) {
            if let Some(p) = cfg_port_strict(Some(&m)) {
                st.0 = p;
            }
        }
        st.1 = Instant::now();
    }
    st.0.clone()
}

// ---------- конфиг tg-ws-proxy (порт app.go: findTgConfig/readConfigJSON/cfgPort) ----------

pub fn find_tg_config(tools_dir: &Path) -> Option<serde_json::Map<String, serde_json::Value>> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let base = PathBuf::from(appdata);
        dirs.push(base.join("TgWsProxy"));
        dirs.push(base.join("tgwsproxy"));
        dirs.push(base.join("tg-ws-proxy"));
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let base = PathBuf::from(local);
        dirs.push(base.join("TgWsProxy"));
        dirs.push(base.join("tgwsproxy"));
        dirs.push(base.join("tg-ws-proxy"));
    }
    dirs.push(tools_dir.join("tgproxy"));
    for d in dirs {
        if let Some(m) = read_config_json(&d, 2) {
            return Some(m);
        }
    }
    None
}

fn read_config_json(dir: &Path, depth: i32) -> Option<serde_json::Map<String, serde_json::Value>> {
    if depth < 0 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for e in entries.flatten() {
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            subdirs.push(e.path());
            continue;
        }
        let name = e.file_name().to_string_lossy().to_string();
        let ext = Path::new(&name)
            .extension()
            .map(|x| x.to_string_lossy().to_string())
            .unwrap_or_default();
        if !ext.eq_ignore_ascii_case("json") {
            continue;
        }
        if let Ok(data) = std::fs::read(e.path()) {
            if let Ok(serde_json::Value::Object(m)) = serde_json::from_slice::<serde_json::Value>(&data) {
                if !m.is_empty() {
                    return Some(m);
                }
            }
        }
    }
    for d in subdirs {
        if let Some(m) = read_config_json(&d, depth - 1) {
            return Some(m);
        }
    }
    None
}

// cfgPort — порт из конфига tg-ws-proxy или дефолт «1443» (для показа пользователю).
pub fn cfg_port(m: Option<&serde_json::Map<String, serde_json::Value>>) -> String {
    match cfg_port_strict(m) {
        Some(p) => p,
        None => "1443".to_string(),
    }
}

// cfgPortStrict — порт из конфига tg-ws-proxy или None (без маскировки
// «конфиг не найден» под валидный порт).
pub fn cfg_port_strict(m: Option<&serde_json::Map<String, serde_json::Value>>) -> Option<String> {
    let m = m?;
    match m.get("port") {
        Some(serde_json::Value::Number(v)) => {
            let n = v.as_f64()?;
            if n > 0.0 && n < 65536.0 {
                Some((n as i64).to_string())
            } else {
                None
            }
        }
        Some(serde_json::Value::String(v)) => {
            let t = v.trim();
            match t.parse::<i64>() {
                Ok(n) if n > 0 && n < 65536 => Some(n.to_string()),
                _ => None,
            }
        }
        _ => None,
    }
}
