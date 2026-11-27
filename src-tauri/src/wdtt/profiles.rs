// Порт Go profiles.go: профили браузерных отпечатков для VK-запросов.
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

// Go: type Profile struct (json-теги совпадают с именами полей)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub sec_ch_ua: String,
    #[serde(default)]
    pub sec_ch_ua_mobile: String,
    #[serde(default)]
    pub sec_ch_ua_platform: String,
}

// SavedProfile — Profile с сохранёнными данными устройства.
// В Go Profile встроен в структуру (плоский JSON) → serde(flatten).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SavedProfile {
    #[serde(default)]
    #[serde(flatten)]
    pub profile: Profile,
    #[serde(default)]
    pub device_json: String,
    #[serde(default)]
    pub browser_fp: String,
}

// Go: const profileFile = "vk_profile.json"
pub const PROFILE_FILE: &str = "vk_profile.json";

// profilePath — файл сохранённого профиля в %APPDATA%\Sentor: CWD у GUI-приложения
// непредсказуем (ярлык может дать C:\Windows\System32), и профиль «терялся».
// Go: func profilePath() string
pub fn profile_path() -> PathBuf {
    if let Some(dir) = user_config_dir() {
        if !dir.as_os_str().is_empty() {
            let sentor_dir = dir.join("Sentor");
            // Go: os.MkdirAll(filepath.Join(dir, "Sentor"), 0o755)
            if std::fs::create_dir_all(&sentor_dir).is_ok() {
                return sentor_dir.join(PROFILE_FILE);
            }
        }
    }
    PathBuf::from(PROFILE_FILE) // фолбэк: как раньше, рядом с CWD
}

// user_config_dir — аналог Go os.UserConfigDir.
#[cfg(target_os = "windows")]
fn user_config_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(PathBuf::from)
}

#[cfg(target_os = "macos")]
fn user_config_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn user_config_dir() -> Option<PathBuf> {
    // Go os.UserConfigDir: XDG_CONFIG_HOME или $HOME/.config
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))
}

// Go: func LoadProfileFromDisk() (*SavedProfile, error)
pub fn load_profile_from_disk() -> Result<SavedProfile, String> {
    let data = std::fs::read(profile_path()).map_err(|e| e.to_string())?;
    serde_json::from_slice(&data).map_err(|e| e.to_string())
}

// make_profile — вспомогательный конструктор (в Go литералы структуры).
fn make_profile(user_agent: &str, sec_ch_ua: &str, sec_ch_ua_mobile: &str, sec_ch_ua_platform: &str) -> Profile {
    Profile {
        user_agent: user_agent.to_string(),
        sec_ch_ua: sec_ch_ua.to_string(),
        sec_ch_ua_mobile: sec_ch_ua_mobile.to_string(),
        sec_ch_ua_platform: sec_ch_ua_platform.to_string(),
    }
}

// Go: var profileList — порядок важен: index 5 («safari»), последний («firefox»)
fn profile_list() -> &'static [Profile] {
    static LIST: OnceLock<Vec<Profile>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![
            make_profile(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
                "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"",
                "?0",
                "\"Windows\"",
            ),
            make_profile(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
                "\"Chromium\";v=\"145\", \"Not-A.Brand\";v=\"99\", \"Google Chrome\";v=\"145\"",
                "?0",
                "\"Windows\"",
            ),
            make_profile(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
                "\"Chromium\";v=\"144\", \"Not-A.Brand\";v=\"8\", \"Google Chrome\";v=\"144\"",
                "?0",
                "\"Windows\"",
            ),
            make_profile(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
                "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Microsoft Edge\";v=\"146\"",
                "?0",
                "\"Windows\"",
            ),
            make_profile(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
                "\"Chromium\";v=\"145\", \"Not-A.Brand\";v=\"99\", \"Microsoft Edge\";v=\"145\"",
                "?0",
                "\"Windows\"",
            ),
            make_profile(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
                "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"",
                "?0",
                "\"macOS\"",
            ),
            make_profile(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
                "\"Chromium\";v=\"145\", \"Not-A.Brand\";v=\"99\", \"Google Chrome\";v=\"145\"",
                "?0",
                "\"macOS\"",
            ),
            make_profile(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
                "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"",
                "?0",
                "\"Linux\"",
            ),
            make_profile(
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
                "\"Chromium\";v=\"144\", \"Not-A.Brand\";v=\"8\", \"Google Chrome\";v=\"144\"",
                "?0",
                "\"Linux\"",
            ),
            make_profile(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                "\"Firefox\";v=\"132\", \"Not-A.Brand\";v=\"8\", \"Mozilla Firefox\";v=\"132\"",
                "?0",
                "\"Windows\"",
            ),
        ]
    })
}

// Go: var androidProfiles
fn android_profiles() -> &'static [Profile] {
    static LIST: OnceLock<Vec<Profile>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![make_profile(
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
            "\"Chromium\";v=\"129\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"129\"",
            "?1",
            "\"Android\"",
        )]
    })
}

// Go: var iosProfiles
fn ios_profiles() -> &'static [Profile] {
    static LIST: OnceLock<Vec<Profile>> = OnceLock::new();
    LIST.get_or_init(|| {
        vec![make_profile(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
            "\"Safari\";v=\"17\", \"Not-A.Brand\";v=\"24\", \"Apple Safari\";v=\"17\"",
            "?1",
            "\"iOS\"",
        )]
    })
}

// activeFingerprint — atomic: пишется в Core.start(), читается из горутин
// воркеров/капчи; при повторном Start() нового Core старые горутины ещё живы.
// Go: var activeFingerprint atomic.Value // string; init() → Store("chrome")
// В Rust — Mutex<String>: пустая строка означает «chrome» (значение из init()).
static ACTIVE_FINGERPRINT: Mutex<String> = Mutex::new(String::new());

// Go: func SetActiveFingerprint(fp string)
pub fn set_active_fingerprint(fp: &str) {
    *ACTIVE_FINGERPRINT.lock().unwrap_or_else(|e| e.into_inner()) = fp.to_string();
}

// Go: func GetActiveFingerprint() string
pub fn get_active_fingerprint() -> String {
    let g = ACTIVE_FINGERPRINT.lock().unwrap_or_else(|e| e.into_inner());
    if !g.is_empty() {
        g.clone()
    } else {
        "chrome".to_string() // как в Go: init() хранит "chrome"
    }
}

// Go: func getRandomProfile() Profile
pub fn get_random_profile() -> Profile {
    match get_active_fingerprint().as_str() {
        "android" => {
            let list = android_profiles();
            list[fastrand::usize(..list.len())].clone()
        }
        "ios" => {
            let list = ios_profiles();
            list[fastrand::usize(..list.len())].clone()
        }
        "safari" => {
            // настоящего Safari-профиля в списке нет; раньше «safari» отдавал
            // Edge 145 на Windows — наименее ожидаемый выбор. Берём macOS-Chrome:
            // та же платформа Apple, десктопный клиент
            profile_list()[5].clone()
        }
        "firefox" => {
            let list = profile_list();
            list[list.len() - 1].clone()
        }
        _ => profile_list()[fastrand::usize(..3)].clone(),
    }
}

// tlsProfileForUA — TLS-отпечаток под UA: жёсткий Chrome_146 при UA Firefox —
// готовый антибот-сигнал (JA3 Chrome при Firefox-заголовках).
// Go: func tlsProfileForUA(ua string) profiles.ClientProfile
// Отличие от Go: в Rust нет tls-client (reqwest+rustls не позволяет задать JA3),
// поэтому возвращаем имя профиля строкой как метку для вызывающего кода.
#[allow(dead_code)] // reqwest не задаёт JA3 — пригодится при переходе на wreq
pub fn tls_profile_for_ua(ua: &str) -> &'static str {
    if ua.contains("Firefox/") {
        // ровно та версия, что в profileList
        "Firefox_132"
    } else {
        "Chrome_146"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_profile_json_roundtrip() {
        let json = r#"{"user_agent":"UA","sec_ch_ua":"X","sec_ch_ua_mobile":"?0","sec_ch_ua_platform":"\"Windows\"","device_json":"{}","browser_fp":"fp123"}"#;
        let sp: SavedProfile = serde_json::from_str(json).expect("parse");
        assert_eq!(sp.profile.user_agent, "UA");
        assert_eq!(sp.profile.sec_ch_ua_platform, "\"Windows\"");
        assert_eq!(sp.device_json, "{}");
        assert_eq!(sp.browser_fp, "fp123");

        let back = serde_json::to_string(&sp).expect("serialize");
        assert!(back.contains("\"user_agent\""));
        assert!(back.contains("\"device_json\""));
    }

    #[test]
    fn missing_fields_default_to_empty() {
        let sp: SavedProfile = serde_json::from_str("{}").expect("parse");
        assert_eq!(sp.profile.user_agent, "");
        assert_eq!(sp.device_json, "");
    }

    #[test]
    fn default_fingerprint_is_chrome() {
        // до первого SetActiveFingerprint — «chrome» (Go init())
        assert_eq!(get_active_fingerprint(), "chrome");
    }

    #[test]
    fn random_profiles_match_fingerprint() {
        set_active_fingerprint("android");
        let p = get_random_profile();
        assert!(p.user_agent.contains("Android"));
        assert_eq!(p.sec_ch_ua_mobile, "?1");

        set_active_fingerprint("ios");
        let p = get_random_profile();
        assert!(p.user_agent.contains("iPhone"));

        set_active_fingerprint("safari");
        let p = get_random_profile();
        assert!(p.sec_ch_ua_platform.contains("macOS"));

        set_active_fingerprint("firefox");
        let p = get_random_profile();
        assert!(p.user_agent.contains("Firefox/132"));

        set_active_fingerprint("chrome");
        let p = get_random_profile();
        assert!(p.user_agent.contains("Chrome/14"));

        // вернуть значение по умолчанию
        set_active_fingerprint("");
    }

    #[test]
    fn tls_profile_by_ua() {
        assert_eq!(tls_profile_for_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"), "Firefox_132");
        assert_eq!(tls_profile_for_ua("Mozilla/5.0 (Windows NT 10.0) Chrome/146.0.0.0"), "Chrome_146");
    }
}
