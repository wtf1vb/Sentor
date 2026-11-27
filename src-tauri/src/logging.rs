// Ring buffer log - port of Go logAdd/GetLogs/ClearLogs (app.go).
// Дополнение поверх порта: строки компонента "warp" дублируются событием
// warpLog — живой лог сессии прямо на странице WARP (handshake, IP, ошибки).
use std::sync::{Mutex, OnceLock};

use tauri::Emitter;

const LOG_BUF_MAX: usize = 5000;

static LOG_LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

// Хендл приложения для эмита событий из log_add: ставится один раз в setup.
static APP_HANDLE: OnceLock<tauri::AppHandle> = OnceLock::new();

pub fn set_app_handle(h: tauri::AppHandle) {
    let _ = APP_HANDLE.set(h);
}

// logAdd — строка в общий лог-буфер (хранятся последние LOG_BUF_MAX строк).
pub fn log_add(component: &str, s: &str) {
    let s = s.trim();
    if s.is_empty() {
        return;
    }
    let line = format!("{} [{}] {}", chrono::Local::now().format("%H:%M:%S"), component, s);
    {
        let mut g = LOG_LINES.lock().unwrap_or_else(|e| e.into_inner());
        g.push(line.clone());
        if g.len() > LOG_BUF_MAX {
            let cut = g.len() - LOG_BUF_MAX;
            g.drain(0..cut);
        }
    }
    // Живой лог WARP на его странице: всё, что пишет conn::run_warp, пробы и
    // сам SentorWarp.exe (через stream_to_log с source "warp"), уходит в UI.
    if component == "warp" {
        if let Some(h) = APP_HANDLE.get() {
            let _ = h.emit("warpLog", line);
        }
    }
}

// GetLogs — весь буфер одной строкой (для панели «Логи» в UI).
pub fn get_logs() -> String {
    let g = LOG_LINES.lock().unwrap_or_else(|e| e.into_inner());
    g.join("\n")
}

// SaveLogsFile — текст буфера для записи в файл.
pub fn save_logs_text() -> String {
    let g = LOG_LINES.lock().unwrap_or_else(|e| e.into_inner());
    g.join("\n")
}

// ClearLogs — очистить буфер.
pub fn clear_logs() {
    let mut g = LOG_LINES.lock().unwrap_or_else(|e| e.into_inner());
    g.clear();
}
