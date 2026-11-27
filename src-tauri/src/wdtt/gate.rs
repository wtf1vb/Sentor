// Порт Go allocation_gate.go: allocationGate ограничивает частоту TURN Allocate
// попыток. Один gate на ядро — воркеры делят квоту, не блокируя чужие ядра.
use std::sync::Mutex;
use std::time::{Duration, Instant};

// Go: allocateGateInterval = 100 * time.Millisecond
#[allow(dead_code)] // интервал захардкожен в core.rs; пригодится при DTLS
pub const ALLOCATE_GATE_INTERVAL: Duration = Duration::from_millis(100);

pub struct AllocationGate {
    next: Mutex<Option<Instant>>,
    interval: Duration,
}

impl AllocationGate {
    // Go: func newAllocationGate(interval time.Duration) *allocationGate
    pub fn new(interval: Duration) -> Self {
        AllocationGate {
            next: Mutex::new(None),
            interval,
        }
    }

    // wait выделяет ближайший слот и ждёт до его наступления.
    // Go: func (g *allocationGate) Wait(ctx context.Context) error
    // Отличие от Go: context.Context отмены в синхронном порте нет — метод
    // просто спит до слота; отмену при остановке ядра делает вызывающий код
    // (session.rs/core.rs) на своей стороне.
    pub fn wait(&self) {
        let due = {
            let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let due = match *next {
                Some(t) if t > now => t,
                _ => now,
            };
            *next = Some(due + self.interval);
            due
        };

        let wait = due.saturating_duration_since(Instant::now());
        if wait > Duration::ZERO {
            std::thread::sleep(wait);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_spaces_calls() {
        let g = AllocationGate::new(Duration::from_millis(60));
        let t0 = Instant::now();

        g.wait(); // первый — мгновенно
        assert!(t0.elapsed() < Duration::from_millis(40));

        g.wait(); // второй — ждёт интервал
        assert!(t0.elapsed() >= Duration::from_millis(50));
    }
}
