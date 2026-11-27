// Process/admin checks - port of Go processRunning/processRunningCached/isAdmin.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

pub fn is_admin() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

pub fn process_running(name: &str) -> bool {
    unsafe {
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = false;
        if Process32FirstW(h, &mut entry) != 0 {
            loop {
                let exe = String::from_utf16_lossy(&entry.szExeFile);
                let exe = exe.trim_end_matches('\0');
                if exe.eq_ignore_ascii_case(name) {
                    found = true;
                    break;
                }
                if Process32NextW(h, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(h);
        found
    }
}

// processRunningCached — с TTL 2 с: опросы UI (GetTraffic/GetStatus) иначе
// на каждый тик гоняют полные снимки процессов.
struct CacheEntry {
    on: bool,
    at: Instant,
}

static CACHE: Mutex<Option<HashMap<String, CacheEntry>>> = Mutex::new(None);

pub fn process_running_cached(name: &str) -> bool {
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let map = cache.get_or_insert_with(HashMap::new);
    if let Some(c) = map.get(name) {
        if c.at.elapsed() < Duration::from_secs(2) {
            return c.on;
        }
    }
    let on = process_running(name);
    map.insert(name.to_string(), CacheEntry { on, at: Instant::now() });
    on
}

// invalidate_process_cache — сброс закешированного статуса после
// start/stop: иначе UI ещё до 2 с видит «работает» для убитого процесса
// (или наоборот), и кнопка переключения реагирует со второго клика.
pub fn invalidate_process_cache(name: &str) {
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = cache.as_mut() {
        map.remove(name);
    }
}
