// VK Smart Captcha v2 — порт Go pwdttcore/captcha_v2.go.
//
// Автоматическое решение VK Smart Captcha (checkbox + slider через slider.rs):
// PoW (sha256), captchaNotRobot.{settings,componentDone,check,endSession},
// вытаскивание debug_info из скрипта капчи.
//
// Отклонения от Go:
//  - net/http+fhttp (tls-client) → reqwest::blocking; TLS-отпечаток и порядок
//    заголовков (HeaderOrderKey) reqwest контролировать не умеет.
//  - context.Context → Arc<AtomicBool> (cancel): паузы прерываемы, PoW-цикл
//    проверяет cancel каждые 4096 nonce; in-flight HTTP-запросы прервать нельзя.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::blocking::Client;
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::profiles::{Profile, SavedProfile};
use crate::logging::log_add;

const CAPTCHA_V2_API_VERSION: &str = "5.131";
const CAPTCHA_V2_SCRIPT_VERSION: &str = "1.1.1370";
pub(crate) const CAPTCHA_V2_DEVICE_INFO: &str = r#"{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1040,"innerWidth":1920,"innerHeight":970,"devicePixelRatio":1,"language":"ru-RU","languages":["ru-RU","ru","en-US","en"],"webdriver":false,"hardwareConcurrency":8,"notificationsPermission":"default"}"#;

const CAPTCHA_V2_MAX_ATTEMPTS: usize = 10;

macro_rules! re {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new($pattern).unwrap())
        }
    };
}

re!(re_pow_input, r#"const\s+powInput\s*=\s*"([^"]+)""#);
re!(re_difficulty, r#"const\s+difficulty\s*=\s*(\d+)"#);
re!(re_window_init, r#"(?s)window\.init\s*=\s*(\{.*?\})\s*;"#);
re!(re_script_src, r#"src="(https://[^"]+not_robot_captcha[^"]+)""#);
re!(re_debug_info, r#"debug_info:(?:[^"]*\|\|)?"([a-fA-F0-9]{64})""#);
re!(re_version, r#"vkid/([0-9.]*)/not_robot_captcha\.js"#);

// Кэш debug_info: scriptURL -> значение (Go sync.Map).
fn debug_cache() -> &'static Mutex<HashMap<String, String>> {
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// fastrand-замена Go math/rand.Intn(n): число в [0, n).
pub(crate) fn rand_below(n: i64) -> i64 {
    if n <= 0 {
        0
    } else {
        fastrand::u64(0..n as u64) as i64
    }
}

/// Go select { <-ctx.Done(); <-time.After(d) }: true = доспали полностью,
/// false = отмена (cancel). Отмена не портирована как in-flight, но паузы
/// и длинные циклы проверяют флаг.
pub(crate) fn sleep_or_cancel(d: Duration, cancel: &AtomicBool) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }
    !cancel.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════
// Ошибки капчи (Go errCaptchaV2RateLimit / errCaptchaV2Bot / captchaV2ShowTypeError)
// ═══════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub enum CaptchaError {
    /// Go errCaptchaV2RateLimit: "captcha session rate limit reached".
    RateLimit,
    /// Go errCaptchaV2Bot: "captcha bot challenge" + контекст.
    Bot(String),
    /// Go captchaV2ShowTypeError: "captcha show type mismatch: X".
    ShowType { show_type: String },
    /// Go *VkCaptchaError (code 14 от VK API).
    Vk(VkCaptchaError),
    /// Остальные ошибки (Go fmt.Errorf).
    Msg(String),
}

impl std::fmt::Display for CaptchaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptchaError::RateLimit => write!(f, "captcha session rate limit reached"),
            CaptchaError::Bot(ctx) => write!(f, "captcha bot challenge: {}", ctx),
            CaptchaError::ShowType { show_type } => {
                write!(f, "captcha show type mismatch: {}", show_type)
            }
            CaptchaError::Vk(e) => write!(f, "{}", e.display()),
            CaptchaError::Msg(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for CaptchaError {}

// ═══════════════════════════════════════════════════
// VkCaptchaError (Go VkCaptchaError)
// ═══════════════════════════════════════════════════

#[derive(Debug, Clone, Default)]
pub struct VkCaptchaError {
    pub error_code: i32,
    pub error_msg: String,
    pub captcha_sid: String,
    pub captcha_img: String,
    pub redirect_uri: String,
    pub session_token: String,
    pub captcha_ts: String,
    pub captcha_attempt: String,
}

impl VkCaptchaError {
    // Go (*VkCaptchaError).Error().
    pub fn display(&self) -> String {
        if self.error_code != 0 && self.error_code != 14 {
            if !self.error_msg.is_empty() {
                return format!("VK API error {}: {}", self.error_code, self.error_msg);
            }
            return format!("VK API error {}", self.error_code);
        }
        if !self.redirect_uri.is_empty() {
            return format!("VK captcha required: redirect_uri, sid={:?}", self.captcha_sid);
        }
        if !self.captcha_img.is_empty() {
            return format!("VK captcha required: captcha_img, sid={:?}", self.captcha_sid);
        }
        if !self.captcha_sid.is_empty() {
            return format!("VK captcha required: sid={:?}", self.captcha_sid);
        }
        if !self.error_msg.is_empty() {
            return format!("VK captcha required: {}", self.error_msg);
        }
        "VK captcha required".to_string()
    }
}

// Go %.0f для float64 из JSON.
fn fmt_f64_int(v: f64) -> String {
    format!("{:.0}", v)
}

// parseVkCaptchaError — разбор error-объекта VK API.
pub fn parse_vk_captcha_error(err_data: &Value) -> VkCaptchaError {
    let obj = err_data.as_object();
    let get = |k: &str| -> &Value {
        obj.map(|o| o.get(k).unwrap_or(&Value::Null)).unwrap_or(&Value::Null)
    };

    let error_code = get("error_code").as_f64().unwrap_or(0.0) as i32;
    let redirect_uri = get("redirect_uri").as_str().unwrap_or("").to_string();
    let error_msg = get("error_msg").as_str().unwrap_or("").to_string();
    let captcha_img = get("captcha_img").as_str().unwrap_or("").to_string();

    let mut captcha_sid = get("captcha_sid").as_str().unwrap_or("").to_string();
    if captcha_sid.is_empty() {
        if let Some(sid_num) = get("captcha_sid").as_f64() {
            captcha_sid = fmt_f64_int(sid_num);
        }
    }

    let mut session_token = String::new();
    if !redirect_uri.is_empty() {
        if let Ok(parsed) = url::Url::parse(&redirect_uri) {
            session_token = parsed
                .query_pairs()
                .find(|(k, _)| k == "session_token")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
        }
    }

    let captcha_ts = match get("captcha_ts") {
        Value::Number(_) => get("captcha_ts").as_f64().map(fmt_f64_int).unwrap_or_default(),
        Value::String(s) => s.clone(),
        _ => String::new(),
    };

    let captcha_attempt = match get("captcha_attempt") {
        Value::Number(_) => get("captcha_attempt").as_f64().map(fmt_f64_int).unwrap_or_default(),
        Value::String(s) => s.clone(),
        _ => String::new(),
    };

    VkCaptchaError {
        error_code,
        error_msg,
        captcha_sid,
        captcha_img,
        redirect_uri,
        session_token,
        captcha_ts,
        captcha_attempt,
    }
}

// ═══════════════════════════════════════════════════
// page / init (Go captchaV2Init и parseCaptchaV2Page)
// ═══════════════════════════════════════════════════

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CaptchaV2Init {
    #[serde(default)]
    pub data: CaptchaV2InitData,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CaptchaV2InitData {
    #[serde(default, rename = "show_captcha_type")]
    pub show_captcha_type: String,
    #[serde(default, rename = "captcha_settings")]
    pub captcha_settings: Vec<CaptchaV2InitSetting>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CaptchaV2InitSetting {
    #[serde(default, rename = "type")]
    pub setting_type: String,
    #[serde(default)]
    pub settings: String,
}

#[derive(Debug, Clone, Default)]
pub struct CaptchaV2Page {
    pub pow_input: String,
    pub pow_difficulty: i32,
    pub script_url: String,
    pub init: Option<CaptchaV2Init>,
}

// ═══════════════════════════════════════════════════
// Сессия (Go captchaV2Session)
// ═══════════════════════════════════════════════════

pub struct CaptchaSession {
    pub client: Client,
    pub profile: Profile,
    pub saved_profile: Option<SavedProfile>,
    /// Go s.ctx — отмена (Arc<AtomicBool> вместо context.Context).
    pub cancel: Arc<AtomicBool>,
}

/// solveVkCaptchaV2 — автоматическое решение VK Smart Captcha (v2).
/// (в Go — экспортируемый API; внутри порта используется _attempts-вариант)
#[allow(dead_code)]
pub fn solve_vk_captcha_v2(
    cancel: &Arc<AtomicBool>,
    client: &Client,
    captcha_err: &VkCaptchaError,
    profile: &Profile,
    saved_profile: Option<&SavedProfile>,
) -> Result<String, CaptchaError> {
    solve_vk_captcha_v2_attempts(cancel, client, captcha_err, profile, saved_profile, CAPTCHA_V2_MAX_ATTEMPTS)
}

/// solveVkCaptchaV2Attempts — то же с ограничением числа попыток.
pub fn solve_vk_captcha_v2_attempts(
    cancel: &Arc<AtomicBool>,
    client: &Client,
    captcha_err: &VkCaptchaError,
    profile: &Profile,
    saved_profile: Option<&SavedProfile>,
    max_attempts: usize,
) -> Result<String, CaptchaError> {
    if captcha_err.session_token.is_empty() {
        return Err(CaptchaError::Msg("no session_token in redirect_uri".to_string()));
    }
    let max_attempts = if max_attempts < 1 { 10 } else { max_attempts };
    log_add(
        "wdtt",
        &format!("[КАПЧА] Решаю VK Smart Captcha автоматически (v2, попыток={})...", max_attempts),
    );

    let s = CaptchaSession {
        client: client.clone(),
        profile: profile.clone(),
        saved_profile: saved_profile.cloned(),
        cancel: cancel.clone(),
    };

    for attempt in 1..=max_attempts {
        match s.solve_once(captcha_err) {
            Ok(token) => return Ok(token),
            Err(solve_err) => {
                log_add("wdtt", &format!("[КАПЧА] v2 попытка {} ошибка: {}", attempt, solve_err));
                if matches!(solve_err, CaptchaError::RateLimit) {
                    log_add("wdtt", "[КАПЧА] Превышен лимит сессии капчи. Ожидаю 5 секунд...");
                    if !sleep_or_cancel(Duration::from_secs(5), &s.cancel) {
                        return Err(CaptchaError::Msg("context canceled".to_string()));
                    }
                    continue;
                }

                // нарастающий backoff (раньше таймер создавался, но не использовался —
                // реальная пауза всегда была случайными 1.5-2.7 с)
                let backoff_steps = (attempt as i64).min(10);
                let delay = 1500 + rand_below(1200) + backoff_steps * 500;
                if !sleep_or_cancel(Duration::from_millis(delay as u64), &s.cancel) {
                    return Err(CaptchaError::Msg("context canceled".to_string()));
                }
            }
        }
    }
    Err(CaptchaError::Msg(format!("v2 captcha attempts exhausted ({})", max_attempts)))
}

impl CaptchaSession {
    #[allow(unused_assignments)] // token: инициал перезаписывается в цикле до чтения
    fn solve_once(&self, captcha_err: &VkCaptchaError) -> Result<String, CaptchaError> {
        let html = self.fetch_captcha_html(&captcha_err.redirect_uri)?;

        let page = parse_captcha_v2_page(&html)?;
        if page.pow_input.is_empty() {
            return Err(CaptchaError::Msg("failed to find PoW settings".to_string()));
        }

        let mut slider_settings = String::new();
        if let Some(init) = &page.init {
            for setting in &init.data.captcha_settings {
                if setting.setting_type == "slider" {
                    slider_settings = setting.settings.clone();
                }
            }
        }
        if let Some(init) = &page.init {
            if init.data.show_captcha_type == "slider" && slider_settings.is_empty() {
                return Err(CaptchaError::Msg("failed to find slider captcha settings".to_string()));
            }
        }

        log_add("wdtt", &format!("[КАПЧА] v2 solving pow difficulty={}", page.pow_difficulty));
        let hash = solve_captcha_pow_v2(&self.cancel, &page.pow_input, page.pow_difficulty);
        if hash.is_empty() {
            return Err(CaptchaError::Msg("captcha pow failed".to_string()));
        }
        log_add("wdtt", "[КАПЧА] v2 pow solved");

        let base = captcha_v2_base_values(&captcha_err.session_token);
        self.captcha_request("captchaNotRobot.settings", &base)
            .map_err(|e| CaptchaError::Msg(format!("captcha settings failed: {}", e)))?;

        let mut browser_fp = captcha_v2_browser_fp()?;
        if let Some(sp) = &self.saved_profile {
            let trimmed = sp.browser_fp.trim();
            if !trimmed.is_empty() {
                browser_fp = trimmed.to_string();
            }
        }

        if let Some(caps) = re_version().captures(&page.script_url) {
            if let Some(m) = caps.get(1) {
                if m.as_str() != CAPTCHA_V2_SCRIPT_VERSION {
                    log_add(
                        "wdtt",
                        &format!(
                            "[КАПЧА] v2 script version drift: known={} latest={}",
                            CAPTCHA_V2_SCRIPT_VERSION,
                            m.as_str()
                        ),
                    );
                }
            }
        }

        let debug_info = self
            .fetch_debug_info(&page.script_url)
            .map_err(|e| {
                CaptchaError::Msg(format!(
                    "failed to fetch debug info: {} (script_version={})",
                    e, CAPTCHA_V2_SCRIPT_VERSION
                ))
            })?;

        let mut show_type = page
            .init
            .as_ref()
            .map(|i| i.data.show_captcha_type.clone())
            .unwrap_or_default();
        let mut token = String::new();
        // счётчик переключений типа: сервер, чередующий show_captcha_type
        // (checkbox → slider → checkbox …), крутил цикл бесконечно — каждый круг
        // это успешные HTTP-запросы под глобальным vkRequestMu, блокирующие
        // все стримы
        let mut switches = 0;
        loop {
            log_add("wdtt", &format!("[КАПЧА] v2 solving show_type={}", show_type));
            let res = match show_type.as_str() {
                "slider" => self.solve_slider_captcha(
                    &captcha_err.session_token,
                    &browser_fp,
                    &hash,
                    &slider_settings,
                    &debug_info,
                ),
                "checkbox" | "" => self.solve_checkbox_captcha(
                    &captcha_err.session_token,
                    &browser_fp,
                    &hash,
                    &debug_info,
                ),
                other => {
                    return Err(CaptchaError::Msg(format!("unsupported captcha type: {}", other)));
                }
            };
            match res {
                Ok(t) => {
                    token = t;
                    break;
                }
                Err(CaptchaError::Bot(_))
                    if !show_type.eq_ignore_ascii_case("slider") && !slider_settings.is_empty() =>
                {
                    switches += 1;
                    if switches > 6 {
                        return Err(CaptchaError::Msg(format!(
                            "captcha type ping-pong: {} переключений — сдаюсь",
                            switches
                        )));
                    }
                    log_add("wdtt", "[КАПЧА] v2 checkbox returned BOT, trying slider");
                    show_type = "slider".to_string();
                }
                Err(CaptchaError::ShowType { show_type: st }) if !st.is_empty() => {
                    switches += 1;
                    if switches > 6 {
                        return Err(CaptchaError::Msg(format!(
                            "captcha type ping-pong: {} переключений show_type — сдаюсь",
                            switches
                        )));
                    }
                    show_type = st;
                }
                Err(e) => return Err(e),
            }
        }

        if let Err(end_err) = self.captcha_request("captchaNotRobot.endSession", &base) {
            log_add("wdtt", &format!("[КАПЧА] v2 endSession failed: {}", end_err));
        }
        Ok(token)
    }

    pub fn fetch_captcha_html(&self, redirect_uri: &str) -> Result<String, CaptchaError> {
        // GET-навигация документа: Origin браузеры на cross-site navigate не шлют
        // вообще (пустое значение в do_raw = удалить заголовок)
        let body = self.do_raw(
            Method::GET,
            redirect_uri,
            None,
            &[
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                ("Sec-Fetch-Dest", "document"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-Site", "cross-site"),
                ("Origin", ""),
            ],
        )?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    fn fetch_debug_info(&self, script_url: &str) -> Result<String, CaptchaError> {
        if let Some(cached) = debug_cache().lock().unwrap_or_else(|e| e.into_inner()).get(script_url) {
            return Ok(cached.clone());
        }
        let body = self.do_raw(
            Method::GET,
            script_url,
            None,
            &[
                ("Accept", "text/javascript,*/*"),
                // Origin/Referer должны совпадать (страница id.vk.com шлёт fetch с
                // себя): раньше уходила пара Origin: vk.com + Referer: id.vk.com —
                // детектируемый антиботом признак
                ("Origin", "https://id.vk.com"),
                ("Referer", "https://id.vk.com/"),
            ],
        )?;
        let text = String::from_utf8_lossy(&body);
        let caps = re_debug_info()
            .captures(&text)
            .ok_or_else(|| CaptchaError::Msg("debug_info match not found".to_string()))?;
        let v = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| CaptchaError::Msg("debug_info match not found".to_string()))?;
        debug_cache().lock().unwrap_or_else(|e| e.into_inner()).insert(script_url.to_string(), v.clone());
        log_add("wdtt", &format!("[КАПЧА] v2 debug_info fetched url={}", script_url));
        Ok(v)
    }

    pub fn captcha_request(&self, method: &str, form: &[(String, String)]) -> Result<Value, CaptchaError> {
        let endpoint = format!("https://api.vk.ru/method/{}?v={}", method, CAPTCHA_V2_API_VERSION);
        let body = self.do_raw(
            Method::POST,
            &endpoint,
            Some(form),
            &[
                ("Origin", "https://id.vk.com"),
                ("Referer", "https://id.vk.com/"),
                ("Priority", "u=1, i"),
            ],
        )?;
        let out: Value = serde_json::from_slice(&body)
            .map_err(|e| CaptchaError::Msg(format!("captcha api decode: {}", e)))?;
        // VK API возвращает ошибки в теле 200 OK: раньше settings/componentDone/
        // endSession молча шли дальше и падали позже с бессмысленной диагностикой,
        // сжигая попытки
        if let Some(err_obj) = out.get("error").filter(|v| v.is_object()) {
            let code = super::vk::vk_error_code(err_obj.get("error_code").unwrap_or(&Value::Null));
            let msg = err_obj.get("error_msg").and_then(|v| v.as_str()).unwrap_or("");
            if code == 14 {
                return Err(CaptchaError::Vk(parse_vk_captcha_error(err_obj)));
            }
            return Err(CaptchaError::Msg(format!("captcha api error {}: {}", code, msg)));
        }
        Ok(out)
    }

    pub fn perform_captcha_check(
        &self,
        session_token: &str,
        browser_fp: &str,
        hash: &str,
        answer_json: &str,
        cursor: &str,
        debug_info: &str,
    ) -> Result<CaptchaV2Check, CaptchaError> {
        let values: Vec<(String, String)> = vec![
            ("session_token".into(), session_token.into()),
            ("domain".into(), "vk.com".into()),
            ("adFp".into(), String::new()),
            ("accelerometer".into(), "[]".into()),
            ("gyroscope".into(), "[]".into()),
            ("motion".into(), "[]".into()),
            ("cursor".into(), cursor.into()),
            ("taps".into(), "[]".into()),
            ("connectionRtt".into(), "[]".into()),
            ("connectionDownlink".into(), "[]".into()),
            ("browser_fp".into(), browser_fp.into()),
            ("hash".into(), hash.into()),
            (
                "answer".into(),
                base64::engine::general_purpose::STANDARD.encode(answer_json.as_bytes()),
            ),
            ("debug_info".into(), debug_info.into()),
            ("access_token".into(), String::new()),
        ];
        let resp = self
            .captcha_request("captchaNotRobot.check", &values)
            .map_err(|e| CaptchaError::Msg(format!("captcha check failed: {}", e)))?;
        let check = parse_captcha_v2_check(&resp)?;
        if !check.show_type.is_empty() {
            log_add(
                "wdtt",
                &format!("[КАПЧА] v2 check status={} show_type={}", check.status, check.show_type),
            );
        } else {
            log_add("wdtt", &format!("[КАПЧА] v2 check status={}", check.status));
        }
        Ok(check)
    }

    pub fn solve_checkbox_captcha(
        &self,
        session_token: &str,
        browser_fp: &str,
        hash: &str,
        debug_info: &str,
    ) -> Result<String, CaptchaError> {
        let mut device_json = CAPTCHA_V2_DEVICE_INFO.to_string();
        if let Some(sp) = &self.saved_profile {
            let trimmed = sp.device_json.trim();
            if !trimmed.is_empty() {
                device_json = trimmed.to_string();
            }
        }
        self.captcha_request(
            "captchaNotRobot.componentDone",
            &[
                ("session_token".to_string(), session_token.to_string()),
                ("domain".to_string(), "vk.com".to_string()),
                ("adFp".to_string(), String::new()),
                ("browser_fp".to_string(), browser_fp.to_string()),
                ("device".to_string(), device_json),
                ("access_token".to_string(), String::new()),
            ],
        )
        .map_err(|e| CaptchaError::Msg(format!("captcha componentDone failed: {}", e)))?;

        if !sleep_or_cancel(Duration::from_millis((400 + rand_below(250)) as u64), &self.cancel) {
            return Err(CaptchaError::Msg("context canceled".to_string()));
        }

        let check = self.perform_captcha_check(session_token, browser_fp, hash, "{}", "[]", debug_info)?;
        if !check.show_type.is_empty() && !check.show_type.eq_ignore_ascii_case("checkbox") {
            return Err(CaptchaError::ShowType { show_type: check.show_type });
        }
        if check.status.eq_ignore_ascii_case("error_limit") {
            return Err(CaptchaError::RateLimit);
        }
        if check.status.eq_ignore_ascii_case("bot") {
            return Err(CaptchaError::Bot(format!(
                "checkbox captcha rejected: status={}",
                check.status
            )));
        }
        if !check.status.eq_ignore_ascii_case("ok") {
            return Err(CaptchaError::Msg(format!(
                "checkbox captcha rejected: status={}",
                check.status
            )));
        }
        if check.success_token.is_empty() {
            return Err(CaptchaError::Msg("captcha success token not found".to_string()));
        }
        Ok(check.success_token)
    }

    fn do_raw(
        &self,
        method: Method,
        endpoint: &str,
        form: Option<&[(String, String)]>,
        extra_headers: &[(&'static str, &str)],
    ) -> Result<Vec<u8>, CaptchaError> {
        let mut headers = HeaderMap::new();
        // UA берём из профиля: раньше был жёстко зашит Chrome/120 при
        // sec-ch-ua от профиля 144-146 и TLS-отпечатке Chrome_146 — готовый
        // антибот-сигнал. Реальный Firefox заголовков семейства sec-ch-ua
        // не шлёт вовсе — для него их не добавляем даже если они заполнены.
        // (см. apply_browser_profile)
        apply_browser_profile(&mut headers, &self.profile);
        header_set(&mut headers, "Accept", "*/*");
        header_set(&mut headers, "Sec-Fetch-Site", "same-site");
        header_set(&mut headers, "Sec-Fetch-Mode", "cors");
        header_set(&mut headers, "Sec-Fetch-Dest", "empty");
        header_set(&mut headers, "Origin", "https://vk.com");
        header_set(&mut headers, "Referer", "https://vk.com/");
        if form.is_some() {
            header_set(&mut headers, "Content-Type", "application/x-www-form-urlencoded");
        }
        for (k, v) in extra_headers {
            if v.is_empty() {
                // пустое значение = «убрать заголовок»: GET-навигация не шлёт Origin
                headers.remove(*k);
                continue;
            }
            header_set(&mut headers, k, v);
        }

        let body = form.map(captcha_v2_encode_form).unwrap_or_default();
        let resp = self
            .client
            .request(method, endpoint)
            .headers(headers)
            .body(body)
            .send()
            .map_err(|e| CaptchaError::Msg(e.to_string()))?;

        // Статус не проверялся: 403/429/5xx от антибот-эджа превращались в
        // бессмысленные «decode/match not found», и retry-логика честно сжигала
        // все попытки против заведомо заблокированного эндпоинта
        let status = resp.status();
        if status != StatusCode::OK {
            return Err(CaptchaError::Msg(format!("captcha api http {}", status.as_u16())));
        }
        // 200 тоже ограничиваем: аномальный ответ без лимита мог выделить гигабайты
        let bytes = resp.bytes().map_err(|e| CaptchaError::Msg(e.to_string()))?;
        let cap = bytes.len().min(1 << 20);
        Ok(bytes[..cap].to_vec())
    }
}

// Go: HTTP/2-заголовки вcaptcha-запросах; reqwest шлёт то, что задано в HeaderMap.
pub(crate) fn header_set(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

/// applyBrowserProfileFhttp — заголовки браузерного профиля для запроса.
pub fn apply_browser_profile(headers: &mut HeaderMap, profile: &Profile) {
    header_set(headers, "User-Agent", &profile.user_agent);
    let is_firefox = profile.user_agent.contains("Firefox/");
    if !is_firefox {
        if !profile.sec_ch_ua.is_empty() {
            header_set(headers, "sec-ch-ua", &profile.sec_ch_ua);
        }
        if !profile.sec_ch_ua_mobile.is_empty() {
            header_set(headers, "sec-ch-ua-mobile", &profile.sec_ch_ua_mobile);
        }
        if !profile.sec_ch_ua_platform.is_empty() {
            header_set(headers, "sec-ch-ua-platform", &profile.sec_ch_ua_platform);
        }
    }
    header_set(headers, "Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7");
    // DNT больше не шлём: современный Chrome его не отправляет — лишний
    // антибот-сигнал
}

// ═══════════════════════════════════════════════════
// Вспомогательные функции
// ═══════════════════════════════════════════════════

#[derive(Debug, Clone, Default)]
pub struct CaptchaV2Check {
    pub status: String,
    pub success_token: String,
    pub show_type: String,
}

fn parse_captcha_v2_check(raw: &Value) -> Result<CaptchaV2Check, CaptchaError> {
    let resp = raw
        .get("response")
        .and_then(|v| v.as_object())
        .ok_or_else(|| CaptchaError::Msg(format!("invalid captcha check response: {}", raw)))?;
    let out = CaptchaV2Check {
        status: captcha_v2_stringify_any(resp.get("status").unwrap_or(&Value::Null)),
        success_token: captcha_v2_stringify_any(resp.get("success_token").unwrap_or(&Value::Null)),
        show_type: captcha_v2_stringify_any(resp.get("show_captcha_type").unwrap_or(&Value::Null)),
    };
    if out.status.is_empty() {
        return Err(CaptchaError::Msg(format!("captcha check status missing: {}", raw)));
    }
    Ok(out)
}

pub fn captcha_v2_base_values(session_token: &str) -> Vec<(String, String)> {
    vec![
        ("session_token".to_string(), session_token.to_string()),
        ("domain".to_string(), "vk.com".to_string()),
        ("adFp".to_string(), String::new()),
        ("access_token".to_string(), String::new()),
    ]
}

pub fn captcha_v2_browser_fp() -> Result<String, CaptchaError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| CaptchaError::Msg(format!("browser fp generate: {}", e)))?;
    Ok(b.iter().map(|x| format!("{:02x}", x)).collect())
}

// solveCaptchaPoWV2 — PoW: sha256(input+nonce) с hex-префиксом из нулей.
pub fn solve_captcha_pow_v2(cancel: &AtomicBool, input: &str, difficulty: i32) -> String {
    // Go: начальная пауза нечувствительна к ctx
    thread::sleep(Duration::from_millis((200 + rand_below(300)) as u64));
    if input.is_empty() || difficulty <= 0 {
        return String::new();
    }
    // Эквивалент Go-проверки strings.HasPrefix(hashHex, target): первые
    // `difficulty` hex-цифр нулевые ⇔ floor(difficulty/2) нулевых байт и при
    // нечётном — старший нибл следующего байта нулевой (без построения hex-строки).
    let diff = difficulty as usize;
    let full_bytes = diff / 2;
    let odd = diff % 2 == 1;
    for nonce in 1..=10_000_000i64 {
        if nonce % 4096 == 0 && cancel.load(Ordering::Relaxed) {
            // Go: case <-ctx.Done(): return ""
            return String::new();
        }
        let sum = Sha256::digest(format!("{}{}", input, nonce).as_bytes());
        if hash_has_zero_nibble_prefix(&sum, full_bytes, odd) {
            return sum.iter().map(|x| format!("{:02x}", x)).collect();
        }
    }
    String::new()
}

fn hash_has_zero_nibble_prefix(hash: &[u8], full_bytes: usize, odd: bool) -> bool {
    // защита от аномально большой difficulty (Go просто не находил префикс)
    if full_bytes > hash.len() || (odd && full_bytes >= hash.len()) {
        return false;
    }
    hash[..full_bytes].iter().all(|&b| b == 0) && (!odd || hash[full_bytes] & 0xF0 == 0)
}

pub fn captcha_v2_encode_form(values: &[(String, String)]) -> String {
    if values.is_empty() {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::with_capacity(values.len());
    for (k, v) in values {
        parts.push(format!("{}={}", query_escape(k), query_escape(v)));
    }
    parts.join("&")
}

/// captchaV2QueryEscape / neturl.QueryEscape (семантика совпадает, общая функция).
pub fn query_escape(s: &str) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    for &c in s.as_bytes() {
        match c {
            b' ' => out.push(b'+'),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(c),
            _ => {
                out.push(b'%');
                out.push(UPPER[(c >> 4) as usize]);
                out.push(UPPER[(c & 0xF) as usize]);
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// captchaV2StringifyAny — строковое представление JSON-значения как в Go.
pub fn captcha_v2_stringify_any(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                // Go strconv.FormatFloat(v, 'f', -1, 64)
                format!("{}", n.as_f64().unwrap_or(0.0))
            }
        }
        Value::Bool(b) => b.to_string(),
        // Go: json.Marshal значения
        other => other.to_string(),
    }
}

fn parse_captcha_v2_page(html: &str) -> Result<CaptchaV2Page, CaptchaError> {
    let mut page = CaptchaV2Page::default();

    let caps = re_window_init()
        .captures(html)
        .ok_or_else(|| CaptchaError::Msg("captcha init json not found".to_string()))?;
    let init_json = caps
        .get(1)
        .map(|m| m.as_str())
        .ok_or_else(|| CaptchaError::Msg("captcha init json not found".to_string()))?;
    let init: CaptchaV2Init = serde_json::from_str(init_json)
        .map_err(|e| CaptchaError::Msg(format!("captcha init json parse: {}", e)))?;
    page.init = Some(init);

    let caps = re_script_src()
        .captures(html)
        .ok_or_else(|| CaptchaError::Msg("captcha script url not found".to_string()))?;
    page.script_url = caps
        .get(1)
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| CaptchaError::Msg("captcha script url not found".to_string()))?;

    if let Some(m) = re_pow_input().captures(html).and_then(|c| c.get(1)) {
        page.pow_input = m.as_str().to_string();
    }
    if page.pow_input.is_empty() {
        return Ok(page);
    }

    let caps = re_difficulty()
        .captures(html)
        .ok_or_else(|| CaptchaError::Msg("captcha difficulty const not found".to_string()))?;
    let diff_str = caps
        .get(1)
        .map(|m| m.as_str())
        .ok_or_else(|| CaptchaError::Msg("captcha difficulty const not found".to_string()))?;
    match diff_str.parse::<i32>() {
        Ok(difficulty) if difficulty > 0 => page.pow_difficulty = difficulty,
        _ => return Err(CaptchaError::Msg(format!("invalid captcha difficulty {:?}", diff_str))),
    }
    Ok(page)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_escape() {
        assert_eq!(query_escape("hello world&x=1"), "hello+world%26x%3D1");
        assert_eq!(query_escape("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(query_escape("100%"), "100%25");
    }

    #[test]
    fn test_encode_form() {
        let form = vec![
            ("session_token".to_string(), "a b".to_string()),
            ("domain".to_string(), "vk.com".to_string()),
        ];
        assert_eq!(captcha_v2_encode_form(&form), "session_token=a+b&domain=vk.com");
        assert_eq!(captcha_v2_encode_form(&[]), "");
    }

    #[test]
    fn test_stringify_any() {
        assert_eq!(captcha_v2_stringify_any(&Value::Null), "");
        assert_eq!(captcha_v2_stringify_any(&Value::String("ok".into())), "ok");
        assert_eq!(captcha_v2_stringify_any(&serde_json::json!(5)), "5");
        assert_eq!(captcha_v2_stringify_any(&serde_json::json!(5.5)), "5.5");
        assert_eq!(captcha_v2_stringify_any(&Value::Bool(true)), "true");
    }

    #[test]
    fn test_pow_prefix_helper() {
        let zero_hash = [0u8; 32];
        assert!(hash_has_zero_nibble_prefix(&zero_hash, 3, true));
        let mut h = [0xFFu8; 32];
        h[0] = 0;
        h[1] = 0;
        h[2] = 0x0F;
        // hex: "00000f..." → ровно 5 нулевых hex-цифр (2 полных байта + старший нибл)
        assert!(hash_has_zero_nibble_prefix(&h, 2, true));
        assert!(!hash_has_zero_nibble_prefix(&h, 3, false));
        assert!(!hash_has_zero_nibble_prefix(&h, 3, true));
        // аномальная difficulty не должна паниковать
        assert!(!hash_has_zero_nibble_prefix(&zero_hash, 40, false));
        assert!(!hash_has_zero_nibble_prefix(&zero_hash, 64, true));
    }

    #[test]
    fn test_solve_pow_small_difficulty() {
        let cancel = AtomicBool::new(false);
        let hash = solve_captcha_pow_v2(&cancel, "test", 1);
        assert!(hash.starts_with('0'));
        assert_eq!(hash.len(), 64);
        assert_eq!(solve_captcha_pow_v2(&cancel, "", 2), "");
        assert_eq!(solve_captcha_pow_v2(&cancel, "x", 0), "");
    }

    #[test]
    fn test_parse_vk_captcha_error() {
        let err = serde_json::json!({
            "error_code": 14,
            "error_msg": "Captcha needed",
            "redirect_uri": "https://api.vk.com/captcha?session_token=abc123",
            "captcha_sid": 6287487,
            "captcha_ts": 1700000000
        });
        let e = parse_vk_captcha_error(&err);
        assert_eq!(e.error_code, 14);
        assert_eq!(e.session_token, "abc123");
        assert_eq!(e.captcha_sid, "6287487");
        assert_eq!(e.captcha_ts, "1700000000");
        assert!(e.display().contains("redirect_uri"));
    }

    #[test]
    fn test_vk_captcha_error_display() {
        let mut e = VkCaptchaError::default();
        assert_eq!(e.display(), "VK captcha required");
        e.captcha_sid = "42".into();
        assert_eq!(e.display(), "VK captcha required: sid=\"42\"");
        e.error_code = 29;
        assert_eq!(e.display(), "VK API error 29");
    }
}
