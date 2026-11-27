// Tools dir and file paths - port of Go findToolsDir/toolsDir/zapretDir and friends.
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const DEFAULT_TOOLS_DIR: &str = "D:\\NetTools";
pub const WINWS_NAME: &str = "winws.exe";
pub const TG_EXE_NAME: &str = "TgWsProxy_windows.exe";
// WARP-ядро (amneziawg-go, вынесенный в процесс): живёт в
// tools\vpn\core рядом с wintun.dll
pub const WARP_HELPER_EXE: &str = "SentorWarp.exe";

// findToolsDir — D:\NetTools → C:\NetTools → ProgramData\NetTools — путь
// без кириллицы; Temp — последнее средство (путь с кириллицей).
pub fn find_tools_dir() -> PathBuf {
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from(DEFAULT_TOOLS_DIR),
        PathBuf::from("C:\\NetTools"),
    ];
    if let Some(pd) = std::env::var_os("ProgramData") {
        let pd = PathBuf::from(pd).join("NetTools");
        if !pd.as_os_str().is_empty() {
            candidates.push(pd);
        }
    }
    for d in candidates {
        if std::fs::create_dir_all(&d).is_err() {
            continue;
        }
        // папка может существовать, но быть защищённой от записи — проверяем сразу
        let probe = d.join(".write_test");
        if std::fs::File::create(&probe).is_ok() {
            let _ = std::fs::remove_file(&probe);
            return d;
        }
    }
    std::env::temp_dir().join("NetTools")
}

pub fn traffic_file(tools: &Path) -> PathBuf {
    tools.join("traffic.json")
}

pub fn relay_stats_path(tools: &Path) -> PathBuf {
    tools.join("tg_relay_stats.json")
}

pub fn selected_strategy_file(tools: &Path) -> PathBuf {
    tools.join("selected_strategy.txt")
}

pub fn version_file(tools: &Path, name: &str) -> PathBuf {
    tools.join(format!("{}_version.txt", name))
}

pub fn vpn_dir(tools: &Path) -> PathBuf {
    tools.join("vpn")
}

pub fn vpn_proxies_path(tools: &Path) -> PathBuf {
    vpn_dir(tools).join("proxies.json")
}

pub fn vpn_settings_path(tools: &Path) -> PathBuf {
    vpn_dir(tools).join("settings.json")
}

pub fn vpn_ports_path(tools: &Path) -> PathBuf {
    vpn_dir(tools).join("ports.json")
}

pub fn vpn_subs_path(tools: &Path) -> PathBuf {
    vpn_dir(tools).join("subscriptions.json")
}

pub fn vpn_core_dir(tools: &Path) -> PathBuf {
    vpn_dir(tools).join("core")
}

pub fn vpn_core_exe_for(tools: &Path, core: &str) -> PathBuf {
    match core {
        "xray" => vpn_core_dir(tools).join("xray.exe"),
        _ => vpn_core_dir(tools).join("sing-box.exe"),
    }
}

pub fn vpn_config_path_for(tools: &Path, core: &str) -> PathBuf {
    match core {
        "xray" => vpn_dir(tools).join("config_xray.json"),
        _ => vpn_dir(tools).join("config.json"),
    }
}

pub fn pwdtt_dir(tools: &Path) -> PathBuf {
    tools.join("wdtt")
}

// ---------- DNS-блокировщик рекламы (adsdns) ----------

// heartbeat живого блокировщика {pid, at} — обновляется каждые 2 с
pub fn adsdns_state_file(tools: &Path) -> PathBuf {
    tools.join("adsdns_state.json")
}

// бэкап DNS адаптеров до переключения на 127.0.0.1
pub fn adsdns_backup_file(tools: &Path) -> PathBuf {
    tools.join("ads_dns_backup.json")
}

// ---------- CSQTT (туннель через TURN/RTP) ----------

pub fn cqstt_dir(tools: &Path) -> PathBuf {
    tools.join("cqstt")
}

// сюда распаковывается вшитый csqtt-client.exe + wintun.dll
pub fn cqstt_core_dir(tools: &Path) -> PathBuf {
    cqstt_dir(tools).join("core")
}

pub fn cqstt_client_exe(tools: &Path) -> PathBuf {
    cqstt_core_dir(tools).join("csqtt-client.exe")
}

pub fn cqstt_servers_path(tools: &Path) -> PathBuf {
    cqstt_dir(tools).join("cqstt.json")
}

pub fn cqstt_log_path(tools: &Path) -> PathBuf {
    cqstt_dir(tools).join("session.log")
}

pub fn pwdtt_servers_path(tools: &Path) -> PathBuf {
    pwdtt_dir(tools).join("pwdtt.json")
}

pub fn pwdtt_log_path(tools: &Path) -> PathBuf {
    pwdtt_dir(tools).join("session.log")
}

// valid_strategy_name — имя стратегии приходит с фронтенда и уходит в
// `cmd /c <путь>`: без валидации "..\..\x.bat" (и абсолютные пути) запускали
// произвольный .bat на диске. Правило: чистый basename *.bat, канонизированный
// путь обязан остаться внутри каталога стратегий.
pub fn valid_strategy_name(dir: &Path, name: &str) -> bool {
    let t = name.trim();
    if t.is_empty()
        || t != name
        || t.len() > 200
        || t.contains('\\')
        || t.contains('/')
        || t.contains(':')
        || t.contains("..")
        || t.chars().any(|c| c == '"' || c.is_control())
        || !t.to_lowercase().ends_with(".bat")
    {
        return false;
    }
    let p = dir.join(t);
    match (p.canonicalize(), dir.canonicalize()) {
        (Ok(p), Ok(d)) => p.starts_with(&d),
        _ => false,
    }
}

// findFile — рекурсивный поиск файла (без учёта регистра) с ограничением глубины.
pub fn find_file(root: &Path, name: &str, depth: i32) -> PathBuf {
    if depth < 0 {
        return PathBuf::new();
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return PathBuf::new();
    };
    let mut dirs = Vec::new();
    for e in entries.flatten() {
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if !is_dir && e.file_name().eq_ignore_ascii_case(name) {
            return e.path();
        }
        if is_dir {
            dirs.push(e.path());
        }
    }
    for d in dirs {
        let p = find_file(&d, name, depth - 1);
        if !p.as_os_str().is_empty() {
            return p;
        }
    }
    PathBuf::new()
}

// listStrategies — .bat-файлы в каталоге (service.bat и _* исключаются), отсортированы.
pub fn list_strategies(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_lowercase();
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir || !name.ends_with(".bat") {
            continue;
        }
        if name == "service.bat" || name.starts_with('_') {
            continue;
        }
        out.push(e.file_name().to_string_lossy().to_string());
    }
    out.sort();
    out
}

// zapretDir — каталог с winws.exe и стратегиями; bool = установлен.
// Рекурсивный поиск winws.exe по дереву zapret дорогой: get_status дёргает
// его на каждый опрос UI. TTL-кэш 3 с: результат установки/удаления виден
// не позже чем через 3 с (специальная инвалидация не нужна — операций
// install/update в сессии единицы).
pub fn zapret_dir(tools: &Path) -> (PathBuf, bool) {
    static CACHE: OnceLock<Mutex<Option<(Instant, PathBuf, bool)>>> = OnceLock::new();
    const TTL: Duration = Duration::from_secs(3);
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    {
        let c = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((ts, dir, installed)) = c.as_ref() {
            if ts.elapsed() < TTL {
                return (dir.clone(), *installed);
            }
        }
    }
    let (dir, installed) = zapret_dir_uncached(tools);
    *cache.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), dir.clone(), installed));
    (dir, installed)
}

fn zapret_dir_uncached(tools: &Path) -> (PathBuf, bool) {
    let root = tools.join("zapret");
    let winws = find_file(&root, WINWS_NAME, 4);
    if winws.as_os_str().is_empty() {
        return (root, false);
    }
    // winws.exe лежит в bin\, а стратегии (.bat) — уровнем выше: поднимаемся
    // от каталога winws до каталога с .bat-файлами
    let mut dir = winws
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| root.clone());
    for _ in 0..3 {
        if !list_strategies(&dir).is_empty() {
            return (dir, true);
        }
        let parent = match dir.parent() {
            Some(p) => p.to_path_buf(),
            None => break,
        };
        if parent == dir {
            break;
        }
        dir = parent;
    }
    (
        winws
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or(dir),
        true,
    )
}

pub fn selected_strategy(tools: &Path) -> String {
    std::fs::read_to_string(selected_strategy_file(tools))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn read_version(tools: &Path, name: &str) -> String {
    std::fs::read_to_string(version_file(tools, name))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}
