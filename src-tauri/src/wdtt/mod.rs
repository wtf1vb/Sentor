// WDTT (VK-звонки через TURN) — порт Go pwdttcore + pwdtt.go/pwdtt_wg.go.
//
// СТАТУС: сессии ведёт ВНЕШНЕЕ ядро wdtt-core.exe (client/core из
// ildarmaga/pwdtt-client, см. wdtt_session.rs) — транспорт (TURN Allocate +
// DTLS через pion) здесь не реализован, GETCONF уходил голым текстом в TCP
// и всегда давал read timeout. Модуль оставлен как референс/фолбэк: из него
// живёт normalize_vk_join_hash (нормализация хешей), остальное — dead code.
#![allow(dead_code)]
//
// КОНТРАКТ МОДУЛЕЙ (кто что портирует — не менять имена без согласования):
//   protocol.rs   — TCP/UDP-протокол GETCONF/SendAuth (Go protocol.go)
//   obfs.rs       — обфускация соединения (Go obfs.go)
//   namegen.rs    — генерация имён устройств (Go namegen.go)
//   blacklist.rs  — чёрный список хостов (Go blacklist.go)
//   dns.rs        — DNS-резолвер (Go dns.go)
//   gate.rs       — allocation gate (Go allocation_gate.go)
//   stats.rs      — статистика (Go stats.go)
//   profiles.rs   — профили (Go profiles.go)
//   captcha.rs    — капча v2 (Go captcha_v2.go)
//   slider.rs     — капча-слайдер (Go captcha_v2_slider.go)
//   vk.rs         — VK-авторизация (Go vk_auth.go)
//   creds.rs      — VK-креды (Go creds_vkcalls.go)
//   session.rs    — DTLS/TURN-сессия (Go session.go)
//   dispatcher.rs — диспетчер событий (Go dispatcher.go)
//   workers.rs    — пул воркеров (Go worker_group.go)
//   core.rs       — фасад Core (Go main.go): New/Start/Stop/Pause/Resume/SolveCaptcha
//
// Туннель (Go pwdtt_wg.go) НЕ портируется в лоб: wg_config из события
// поднимается через sing-box amnezia-wg endpoint (см. wdtt_session.rs).

// --- листовые модули (Agent A, готово) ---
pub mod protocol;
pub mod obfs;
pub mod namegen;
pub mod blacklist;
pub mod dns;
pub mod gate;
pub mod stats;
pub mod profiles;

// --- VK/капчи (Agent B) ---
pub mod captcha;
pub mod slider;
pub mod vk;
pub mod creds;

// --- сессия/воркеры/ядро (Agent C) ---
pub mod session;
pub mod dispatcher;
pub mod workers;
pub mod core;

use serde::Serialize;

// Event — событие от ядра (порт Go Event из pwdttcore/main.go).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WdttEvent {
    State {
        status: String, // "connecting" | "connected" | "disconnected"
    },
    Log {
        level: String,  // "INFO" | "WARN" | "ERROR" | "DEBUG"
        message: String,
    },
    Stats {
        active: i32,
        bytes_up: i64,
        bytes_down: i64,
    },
    #[allow(dead_code)] // Go-паритет EventError; ошибки идут через Error-событие
    Error {
        message: String,
    },
    Event {
        name: String,           // "wg_config" | "captcha_required" | "ready"
        data: String,           // JSON-строка
        turn_ips: Vec<String>,  // IP-адреса TURN-серверов (для exclude routes)
    },
}

// PwdttCoreConfig — параметры запуска ядра (порт Go Config; заполняется из
// models::PwdttServer).
#[derive(Debug, Clone)]
pub struct PwdttCoreConfig {
    pub peer_addr: String,      // адрес:порт VPS-сервера
    pub password: String,       // пароль подключения
    pub hashes: Vec<String>,    // хеши VK-звонков
    pub device_id: String,      // уникальный ID устройства
    pub workers: usize,         // количество воркеров (кратное 9)
    pub local_port: u16,        // локальный порт
    pub captcha_mode: String,   // auto | rjs | wv
    pub obfs_mode: String,      // audio | video
    pub fingerprint: String,    // chrome | android | ios | safari | firefox
}

impl PwdttCoreConfig {
    pub fn from_parts(
        peer_addr: String,
        password: String,
        hashes: Vec<String>,
        device_id: String,
        workers: usize,
        local_port: u16,
        captcha_mode: String,
        obfs_mode: String,
        fingerprint: String,
    ) -> Self {
        PwdttCoreConfig {
            peer_addr,
            password,
            hashes,
            device_id,
            workers,
            local_port,
            captcha_mode,
            obfs_mode,
            fingerprint,
        }
    }
}

// panic_msg — текст паники потока для лога: «let _ = h.join()» раньше глушил
// паники воркеров, и группа «тихо» уменьшалась без следов в логах.
pub(crate) fn panic_msg(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "неизвестная паника".to_string()
    }
}
