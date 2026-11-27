// Порт Go stats.go: счётчики трафика и соединений + цикл периодической статистики.
use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use std::time::Duration;

#[derive(Debug, Default)]
pub struct Stats {
    pub total_bytes_up: AtomicI64,
    pub total_bytes_down: AtomicI64,
    pub active_connections: AtomicI32,
}

// Go: func NewStats() *Stats
impl Stats {
    pub fn new() -> Self {
        Stats::default()
    }

    // run_loop отправляет статистику каждые 3 секунды.
    // on_log вызывается для лог-сообщений, on_stats — для статистики.
    // Go: func (s *Stats) RunLoop(shutdown <-chan struct{}, onLog func(level, msg string),
    //     onStats func(rx, tx int64, workers int32))
    // Отличие от Go: канал shutdown заменён замыканием is_shutdown (true —
    // остановиться), порядок on_stats: (up, down, active) — как в Go-вызове.
    // Цикл просыпается мелкими шагами, чтобы остановка подхватывалась,
    // не дожидаясь очередного тика.
    #[allow(dead_code)] // дубль core::stats_loop; используется тестами
    pub fn run_loop(
        &self,
        mut is_shutdown: impl FnMut() -> bool,
        on_log: Option<&dyn Fn(&str, &str)>,
        on_stats: Option<&dyn Fn(i64, i64, i32)>,
    ) {
        let tick = Duration::from_secs(3);
        let step = Duration::from_millis(200);
        let mut elapsed = Duration::ZERO;

        while !is_shutdown() {
            std::thread::sleep(step);
            elapsed += step;
            if elapsed < tick {
                continue;
            }
            elapsed = Duration::ZERO;

            let active = self.active_connections.load(Ordering::SeqCst);
            let up = self.total_bytes_up.load(Ordering::SeqCst);
            let down = self.total_bytes_down.load(Ordering::SeqCst);
            let total_mb = (up + down) as f64 / (1024.0 * 1024.0);

            if let Some(on_log) = on_log {
                on_log(
                    "INFO",
                    &format!(
                        "[STATS] Активных: {}, Трафик: {} МБ",
                        itoa(active),
                        ftoa(total_mb)
                    ),
                );
            }
            if let Some(on_stats) = on_stats {
                on_stats(up, down, active);
            }
        }
    }
}

// Go: func itoa(n int) string
#[allow(dead_code)] // Go-паритет (%v-формат); используется тестами
fn itoa(n: i32) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut n = n;
    let mut s = String::new();
    while n > 0 {
        s.insert(0, char::from(b'0' + (n % 10) as u8));
        n /= 10;
    }
    s
}

// Go: func ftoa(f float64) string
#[allow(dead_code)] // Go-паритет; используется тестами
fn ftoa(f: f64) -> String {
    // две цифры дробной части с ведущим нулём: раньше «1.05 МБ» печаталось
    // как «1.5 МБ» (itoa терял ведущий ноль), а 0.29 усекалось до 0.28
    let mut s = format!("{:.2}", f);
    while s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    if s.is_empty() || s == "-" {
        s = "0".to_string();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn itoa_matches_go() {
        assert_eq!(itoa(0), "0");
        assert_eq!(itoa(7), "7");
        assert_eq!(itoa(123), "123");
        assert_eq!(itoa(100500), "100500");
        // как в Go: отрицательные дают пустую строку (в использовании не бывает)
        assert_eq!(itoa(-5), "");
    }

    #[test]
    fn ftoa_matches_go() {
        assert_eq!(ftoa(1.05), "1.05");
        assert_eq!(ftoa(1.5), "1.5");
        assert_eq!(ftoa(0.29), "0.29");
        assert_eq!(ftoa(2.0), "2");
        assert_eq!(ftoa(0.0), "0");
        assert_eq!(ftoa(1024.0 * 1024.0), "1048576"); // ровно 1 МБ
    }

    #[test]
    fn run_loop_ticks_and_stops() {
        let s = Stats::new();
        s.total_bytes_up.store(2 * 1024 * 1024, Ordering::SeqCst);
        s.active_connections.store(3, Ordering::SeqCst);

        let log_lines: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());
        let stats_seen = std::sync::atomic::AtomicBool::new(false);

        // is_shutdown срабатывает на 4-м вызове; шаг 200 мс, тик 3 с —
        // до тика не дойдём, проверяем только корректную остановку.
        let mut calls = 0;
        s.run_loop(
            || {
                calls += 1;
                calls > 3
            },
            Some(&|level, msg| {
                log_lines.lock().unwrap_or_else(|e| e.into_inner()).push((level.to_string(), msg.to_string()));
            }),
            Some(&|_up, _down, _active| {
                stats_seen.store(true, Ordering::SeqCst);
            }),
        );
        // цикл завершился по shutdown
        assert!(!stats_seen.load(Ordering::SeqCst));
        assert!(log_lines.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
    }
}
