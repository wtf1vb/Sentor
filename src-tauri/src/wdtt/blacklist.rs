// Порт Go blacklist.go: TurnBlacklist — глобальный блек-лист для TURN-адресов.
// Если адрес вернул ошибку (486, unreachable, timeout и т.д.),
// он блокируется на указанное время, чтобы не создавать лишнюю нагрузку.
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

pub struct TurnBlacklist {
    bans: RwLock<HashMap<String, Instant>>, // addr -> banUntil
    ttl: Duration,                          // время блокировки
}

// new создает новый блек-лист с заданным TTL.
// Go: func NewTurnBlacklist(ttl time.Duration) *TurnBlacklist
impl TurnBlacklist {
    pub fn new(ttl: Duration) -> Self {
        TurnBlacklist {
            bans: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    // is_banned проверяет, забанен ли адрес.
    // Если время бана истекло — адрес автоматически разбанивается.
    // Go: func (b *TurnBlacklist) IsBanned(addr string) bool
    pub fn is_banned(&self, addr: &str) -> bool {
        let ban_until = {
            let g = self.bans.read().unwrap_or_else(|e| e.into_inner());
            match g.get(addr) {
                Some(t) => *t,
                None => return false,
            }
        };

        // Если срок бана истек — удаляем запись и возвращаем false
        if Instant::now() > ban_until {
            self.bans
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(addr);
            return false;
        }

        true
    }

    // ban добавляет адрес в блек-лист на TTL.
    // Если адрес уже забанен — продлевает бан.
    // Go: func (b *TurnBlacklist) Ban(addr string)
    pub fn ban(&self, addr: &str) {
        let mut g = self.bans.write().unwrap_or_else(|e| e.into_inner());
        g.insert(addr.to_string(), Instant::now() + self.ttl);
    }

    // clear сбрасывает весь блек-лист (для тестов или форсированного сброса).
    // Go: func (b *TurnBlacklist) Clear()
    pub fn clear(&self) {
        let mut g = self.bans.write().unwrap_or_else(|e| e.into_inner());
        *g = HashMap::new();
    }

    // len возвращает количество забаненных адресов.
    // Go: func (b *TurnBlacklist) Len() int
    #[allow(dead_code)] // интроспекция для тестов/отладки
    pub fn len(&self) -> usize {
        let g = self.bans.read().unwrap_or_else(|e| e.into_inner());
        g.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // get_banned возвращает список всех забаненных адресов (для логов).
    // Go: func (b *TurnBlacklist) GetBanned() []string
    #[allow(dead_code)]
    pub fn get_banned(&self) -> Vec<String> {
        let g = self.bans.read().unwrap_or_else(|e| e.into_inner());
        g.keys().cloned().collect()
    }
}

// TTL = 5 минут; Go: var GlobalBlacklist = NewTurnBlacklist(5 * time.Minute).
// В Rust глобальные значения берутся через global_blacklist() (OnceLock).
static GLOBAL_BLACKLIST: OnceLock<TurnBlacklist> = OnceLock::new();

pub fn global_blacklist() -> &'static TurnBlacklist {
    GLOBAL_BLACKLIST.get_or_init(|| TurnBlacklist::new(Duration::from_secs(5 * 60)))
}

pub fn global_blacklist_is_banned(addr: &str) -> bool {
    global_blacklist().is_banned(addr)
}

pub fn global_blacklist_ban(addr: &str) {
    global_blacklist().ban(addr)
}

pub fn global_blacklist_clear() {
    global_blacklist().clear()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_and_auto_expire() {
        let b = TurnBlacklist::new(Duration::from_millis(40));
        assert!(!b.is_banned("1.2.3.4:3478"));

        b.ban("1.2.3.4:3478");
        assert!(b.is_banned("1.2.3.4:3478"));
        assert_eq!(b.len(), 1);
        assert_eq!(b.get_banned(), vec!["1.2.3.4:3478".to_string()]);

        // продление бана
        b.ban("1.2.3.4:3478");
        assert!(b.is_banned("1.2.3.4:3478"));

        std::thread::sleep(Duration::from_millis(80));
        // истёк — запись удалена автоматически
        assert!(!b.is_banned("1.2.3.4:3478"));
        assert_eq!(b.len(), 0);

        b.ban("5.6.7.8:3478");
        b.clear();
        assert!(b.is_empty());
    }
}
