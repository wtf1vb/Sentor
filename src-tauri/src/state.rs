// Shared application state - port of Go App struct fields used at stage 4.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

pub struct TrafficState {
    pub totals: HashMap<String, u64>,
    pub loaded: bool,
    pub last_sample: Option<Instant>,
    pub last_save: Option<Instant>,
    // -1 = baseline неизвестен (файл старого формата)
    pub relay_pid: i32,
    pub relay_prev: u64,
}

impl Default for TrafficState {
    fn default() -> Self {
        let mut totals = HashMap::new();
        totals.insert("telegram".to_string(), 0u64);
        TrafficState {
            totals,
            loaded: false,
            last_sample: None,
            last_save: None,
            relay_pid: 0,
            relay_prev: 0,
        }
    }
}

pub struct AppState {
    pub tools_dir: OnceLock<PathBuf>,
    pub traffic: Mutex<TrafficState>,
    // сериализует read-modify-write proxies/subs/settings (Go vpnStoreMu)
    pub vpn_store: Mutex<()>,
    // сериализует read-modify-write pwdtt.json (Go pwdttStoreMu)
    pub pwdtt_store: Mutex<()>,
    // сериализует read-modify-write cqstt.json
    pub cqstt_store: Mutex<()>,
    // менеджер подключения (Go vpnConnManager)
    pub conn: std::sync::Arc<crate::conn::ConnManager>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            tools_dir: OnceLock::new(),
            traffic: Mutex::new(TrafficState::default()),
            vpn_store: Mutex::new(()),
            pwdtt_store: Mutex::new(()),
            cqstt_store: Mutex::new(()),
            conn: std::sync::Arc::new(crate::conn::ConnManager::new()),
        }
    }

    pub fn tools(&self) -> PathBuf {
        self.tools_dir
            .get_or_init(crate::paths::find_tools_dir)
            .clone()
    }
}
