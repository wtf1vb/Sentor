// Data transfer structs - mirrors of the Go structs (JSON tags preserved
// so the Rust port reads/writes the same config files as the Go app).
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------- status / tools ----------

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub tools_dir: String,
    pub is_admin: bool,
    pub zapret_installed: bool,
    pub zapret_dir: String,
    pub strategies: Vec<String>,
    pub zapret_running: bool,
    pub tg_installed: bool,
    pub tg_running: bool,
    pub selected: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrafficInfo {
    pub telegram_bytes: u64,
    pub telegram_rate: u64,
    pub telegram_running: bool,
    pub discord_running: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResult {
    pub ok: bool,
    pub report: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub zapret_has: bool,
    pub zapret_installed: String,
    pub zapret_latest: String,
    pub zapret_update: bool,
    pub tg_has: bool,
    pub tg_installed: String,
    pub tg_latest: String,
    pub tg_update: bool,
    pub error: String,
}

// источники утилит для кнопки «Источники» (установка/обновление)
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ToolSources {
    pub zapret_repo: String,
    pub zapret_releases: String,
    pub zapret_api: String,
    pub zapret_asset: String,
    pub tg_repo: String,
    pub tg_releases: String,
    pub tg_api: String,
    pub tg_asset: String,
}

// ---------- checker ----------

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub name: String,
    pub ok: bool,
    pub latency_ms: i64,
    pub discord_ok: bool,
    pub api_http: bool,
    pub api_tls12: bool,
    pub api_tls13: bool,
    pub api_ms: i64,
    pub gateway_http: bool,
    pub gateway_tls12: bool,
    pub gateway_tls13: bool,
    pub gateway_ms: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CheckerState {
    pub running: bool,
    pub done: bool,
    pub logs: Vec<String>,
    pub results: Vec<CheckResult>,
    pub selected: String,
}

// ---------- vpn ----------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct VpnProxy {
    pub id: String,
    pub proto: String, // vless | trojan | vmess | ss | hysteria2
    pub name: String,
    pub host: String,
    pub port: i32,
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manual: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct VpnSubscription {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_url: Option<String>,
    pub added_at: i64,
    pub updated_at: i64,
    pub count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_page_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info_upload: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info_download: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info_total: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info_expire: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VpnSettings {
    #[serde(default = "default_core")]
    pub core: String,
    pub system_proxy: bool,
    pub tun: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_stack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_id: Option<String>,
    pub spoof_os: String,
    pub spoof_hwid: String,
    pub spoof_ua: String,
    pub test_threads: i32,
    pub test_timeout: i32,
    pub ping_method: String, // http | tcp | icmp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_throughput: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_no_dupes: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_direct_custom: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_proxy_custom: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_block_custom: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ads_block: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_presets: Option<HashMap<String, bool>>,
}

impl Default for VpnSettings {
    fn default() -> Self {
        // Go: s := VpnSettings{Core: "sing-box"} before json.Unmarshal.
        VpnSettings {
            core: default_core(),
            system_proxy: false,
            tun: false,
            tun_stack: None,
            test_url: None,
            selected_id: None,
            spoof_os: String::new(),
            spoof_hwid: String::new(),
            spoof_ua: String::new(),
            test_threads: 0,
            test_timeout: 0,
            ping_method: String::new(),
            test_throughput: None,
            sub_no_dupes: None,
            route_mode: None,
            route_direct_custom: None,
            route_proxy_custom: None,
            route_block_custom: None,
            ads_block: None,
            route_presets: None,
        }
    }
}

fn default_core() -> String {
    "sing-box".into()
}

impl VpnSettings {
    // Port of the normalization part of Go loadVpnSettings.
    pub fn normalize(mut self) -> Self {
        if self.core == "mihomo" {
            self.core = "xray".into();
        }
        if self.core != "sing-box" && self.core != "xray" {
            self.core = "sing-box".into();
        }
        if self.test_threads <= 0 || self.test_threads > 200 {
            self.test_threads = 8;
        }
        if self.test_timeout <= 0 || self.test_timeout > 30 {
            self.test_timeout = 5;
        }
        match self.ping_method.as_str() {
            "http" | "tcp" | "icmp" => {}
            _ => self.ping_method = "http".into(),
        }
        // для старых настроек без поля — запрет дубликатов включён по умолчанию
        if self.sub_no_dupes.is_none() {
            self.sub_no_dupes = Some(true);
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VpnStatusInfo {
    pub running: bool,
    pub active_id: String,
    pub active_name: String,
    pub port: i32,
    pub core_installed: bool,
    pub system_proxy_on: bool,
    pub ip: String,
    // внешний IPv6 туннеля (пусто — туннель без v6-маршрута)
    pub ip6: String,
    pub since: i64,
    // жив ли DNS-блокировщик рекламы (тумблер «Блокировать рекламу»)
    pub adsdns_running: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServiceCheck {
    pub name: String,
    pub ok: bool,
    pub ms: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VpnServicesInfo {
    pub checking: bool,
    pub at: i64,
    pub through: String,
    pub services: Vec<ServiceCheck>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde()]
pub struct VpnTrafficInfo {
    pub down: u64,
    pub up: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VpnGeoInfo {
    pub ok: bool,
    pub ip: String,
    pub city: String,
    pub country: String,
    pub country_code: String,
    pub isp: String,
    pub lat: f64,
    pub lon: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServerGeo {
    pub lat: f64,
    pub lon: f64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub city: String,
}

// ---------- connection state ----------

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VpnConnState {
    pub phase: String, // idle | starting | connected | failed
    #[serde(skip_serializing_if = "String::is_empty")]
    pub step: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub since: i64,
    // true — последняя попытка упала на пробе трафика («Сервер недоступен: …»):
    // сервер поднялся, но проверку не прошёл. UI показывает под ошибкой кнопку
    // «Всё равно подключиться» (vpn_connect с force=true). На остальных
    // ошибках (ядро не поднялось, TUN не открылся) кнопки нет — там
    // принудительное подключение бессмысленно.
    #[serde(skip_serializing_if = "is_false")]
    pub can_force: bool,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
}

// ---------- pwdtt ----------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PwdttServer {
    pub id: String,
    pub name: String,
    pub peer: String, // host:dtlsPort
    pub password: String,
    pub hashes: String, // по одному хешу в строке
    pub workers: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_tcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

// ---------- cqstt (CSQTT — туннель через TURN/RTP) ----------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct CqsttServer {
    pub id: String,
    pub name: String,
    pub peer: String, // host:port (по умолчанию :46000)
    pub password: String,
    pub hashes: String, // VK-хеши, по одному в строке (до 6)
    pub workers: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,    // audio | video | unified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>, // udp | tcp_tls
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>, // chrome | safari | firefox | edge | opera
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CqsttStatusInfo {
    pub running: bool,
    pub phase: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub since: i64,
    pub active: i32,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub workers: i32,
    // этап подключения для живой схемы пути (ТЫ→CSQTT→VK TURN→ИНТЕРНЕТ):
    // 0=idle, 1=старт, 2=ядро запущено, 3=VK TURN готовы, 4=адаптер+маршруты
    pub stage: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for CqsttStatusInfo {
    fn default() -> Self {
        // пустая phase = idle для фронтенда (паритет с PwdttStatusInfo)
        CqsttStatusInfo {
            running: false,
            phase: String::new(),
            name: String::new(),
            id: None,
            since: 0,
            active: 0,
            bytes_up: 0,
            bytes_down: 0,
            workers: 0,
            stage: 0,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PwdttStatusInfo {
    pub running: bool,
    pub phase: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub since: i64,
    pub active: i32,
    pub bytes_up: i64,
    pub bytes_down: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for PwdttStatusInfo {
    fn default() -> Self {
        // Go zero value has Phase "" but fresh state is "disconnected".
        // Use "" to mirror Go exactly (frontend treats falsy phase as idle).
        PwdttStatusInfo {
            running: false,
            phase: String::new(),
            name: String::new(),
            id: None,
            since: 0,
            active: 0,
            bytes_up: 0,
            bytes_down: 0,
            error: None,
        }
    }
}

// ---------- traffic / relay ----------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct TrafficFileState {
    pub telegram: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde()]
pub struct RelayStats {
    pub bytes: u64,
    pub pid: i32,
    pub port: i32,
}
