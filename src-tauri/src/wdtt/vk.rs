// VK-авторизация и цепочка получения TURN-кредов — порт Go
// pwdttcore/vk_auth.go.
//
// Легаси-путь (login.vk.ru → get_anonym_token → calls.getAnonymousToken →
// OK CDN fb.do) с капчей, кэш кредов по пулу стримов, глобальный троттлинг
// запросов к VK, хранение VK-кредов (env/embedded/known).
//
// Отклонения от Go:
//  - context.Context → Arc<AtomicBool> (cancel): паузы прерываемы
//    (sleep_or_cancel), in-flight HTTP-запросы прервать нельзя;
//  - tls-client (JA3-профиль по UA, cookie jar) → reqwest::blocking без
//    cookie-хранилища (фича `cookies` не включена в Cargo.toml);
//  - WebView-режим капчи (CaptchaResultChan + протокол CAPTCHA_SOLVE в stdout)
//    в Rust-порте отсутствует: режим "wv" и WBV-фолбэки возвращают ошибку
//    «требуется режим auto/rjs»; логика rjs/auto (Go v2) портирована полностью;
//  - getVKAuthMode/getCaptchaMode — делегирование в activeCore через
//    super::core::get_vk_auth_mode / super::core::get_captcha_mode (core.rs).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use serde_json::Value;
use uuid::Uuid;

use super::captcha::{
    apply_browser_profile, header_set, parse_vk_captcha_error, query_escape, rand_below,
    sleep_or_cancel, solve_vk_captcha_v2_attempts, VkCaptchaError,
};
use super::creds::{
    as_call_unavailable, describe_vkcalls_failure, get_vk_creds_via_vkcalls_path, WdttError,
};
use super::namegen::generate_name;
use super::profiles::{get_random_profile, load_profile_from_disk, Profile, SavedProfile};
use crate::logging::log_add;

// ═══════════════════════════════════════════════════
// VK-креды (Go VKCredentials / loadVKCredentials / deobf)
// ═══════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct VKCredentials {
    pub client_id: String,
    pub client_secret: String,
}

fn deobf(s: &str, shift: i32) -> String {
    let bytes: Vec<u8> = s.bytes().map(|b| (b as i32 + shift) as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// Глобальный список кредов (Go vkCredentialsList + vkCredentialsMu):
// запись (SetActiveClientIds) и чтения (fetch_vk_creds из параллельных воркеров,
// get_active_client_ids_string) под RwLock — в Go torn read заголовка слайса мог
// уронить процесс index-out-of-range в горячем пути всех воркеров.
static VK_CREDENTIALS_LIST: RwLock<Option<Vec<VKCredentials>>> = RwLock::new(None);

// Ленивая инициализация (Go: var vkCredentialsList = loadVKCredentials() при старте).
fn vk_credentials_snapshot() -> Vec<VKCredentials> {
    {
        let g = VK_CREDENTIALS_LIST.read().unwrap();
        if let Some(v) = g.as_ref() {
            return v.clone();
        }
    }
    let mut w = VK_CREDENTIALS_LIST.write().unwrap();
    if w.is_none() {
        *w = Some(load_vk_credentials());
    }
    w.as_ref().unwrap().clone()
}

fn load_vk_credentials() -> Vec<VKCredentials> {
    if let Ok(env) = std::env::var("WDTT_VK_CREDENTIALS") {
        if !env.is_empty() {
            match parse_vk_credentials_env(&env) {
                Ok(creds) if !creds.is_empty() => {
                    log_add(
                        "wdtt",
                        &format!("[VK Auth] Loaded {} VK credential set(s) from environment", creds.len()),
                    );
                    return creds;
                }
                Ok(_) => {}
                Err(err) => {
                    log_add(
                        "wdtt",
                        &format!("[VK Auth] WDTT_VK_CREDENTIALS parse error: {}; using fallback", err),
                    );
                }
            }
        }
    }
    log_add("wdtt", "[VK Auth] WARNING: using embedded VK credentials.");
    vec![
        VKCredentials {
            client_id: deobf(";535939", -3),
            client_secret: deobf("oPUvWlPF|Sqs8yirogpq", -3),
        },
        VKCredentials {
            client_id: deobf("95;:7;:", -3),
            client_secret: deobf("PxD{IdNG\\GRLF}JqHRks", -3),
        },
    ]
}

fn parse_vk_credentials_env(env: &str) -> Result<Vec<VKCredentials>, String> {
    let mut out: Vec<VKCredentials> = Vec::new();
    for pair in env.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let parts: Vec<&str> = pair.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("invalid credential pair {:?} (expected id:secret)", pair));
        }
        let id = parts[0].trim();
        let secret = parts[1].trim();
        if id.is_empty() || secret.is_empty() {
            return Err(format!("empty id or secret in pair {:?}", pair));
        }
        out.push(VKCredentials { client_id: id.to_string(), client_secret: secret.to_string() });
    }
    if out.is_empty() {
        return Err("no credentials found".to_string());
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════
// Ошибки (Go CallUnavailableError / fatalCallError / vkErrorCode)
// ═══════════════════════════════════════════════════

// Go vkErrorCode: float64 | int | string → int.
pub fn vk_error_code(raw: &Value) -> i32 {
    match raw {
        Value::Number(n) => n.as_f64().map(|v| v as i32).unwrap_or(0),
        Value::String(s) => s.parse::<i32>().unwrap_or(0),
        _ => 0,
    }
}

// Go fatalCallError: фатальные ошибки звонков (951/954, 9000..9999).
pub fn fatal_call_error(resp: &Value) -> Option<WdttError> {
    let err_obj = resp.get("error").and_then(|v| v.as_object())?;

    let code = vk_error_code(err_obj.get("error_code").unwrap_or(&Value::Null));
    let matched = code == 951 || code == 954 || (9000..=9999).contains(&code);
    if !matched {
        return None;
    }

    let msg = err_obj.get("error_msg").and_then(|v| v.as_str()).unwrap_or("").to_string();
    Some(WdttError::CallUnavailable { code, message: msg })
}

// Go knownVKCredentials.
#[allow(dead_code)] // Go-паритет: embedded-креды; активный путь — env/embedded
fn known_vk_credential(id: &str) -> Option<VKCredentials> {
    match id {
        "6287487" => Some(VKCredentials {
            client_id: "6287487".to_string(),
            client_secret: "MuAxFaKDYDOICzGnEOhp".to_string(),
        }),
        "8202606" => Some(VKCredentials {
            client_id: "8202606".to_string(),
            client_secret: "lMRsTiMCyPnp5vfoldmn".to_string(),
        }),
        _ => None,
    }
}

// Go SetActiveClientIds.
#[allow(dead_code)] // закрепление client_id из конфига не перенесено в UI
pub fn set_active_client_ids(ids: &str) {
    if ids.is_empty() {
        return;
    }
    let mut new_creds: Vec<VKCredentials> = Vec::new();
    for id in ids.split(',') {
        let id = id.trim();
        if let Some(cred) = known_vk_credential(id) {
            new_creds.push(cred);
        }
    }
    if !new_creds.is_empty() {
        *VK_CREDENTIALS_LIST.write().unwrap() = Some(new_creds);
    }
}

// Go GetActiveClientIdsString.
#[allow(dead_code)]
pub fn get_active_client_ids_string() -> String {
    let creds = vk_credentials_snapshot();
    creds.iter().map(|c| c.client_id.as_str()).collect::<Vec<_>>().join(", ")
}

// ═══════════════════════════════════════════════════
// Кэш TURN-кредов по пулу стримов (Go TurnCredentials / StreamCredentialsCache)
// ═══════════════════════════════════════════════════

const VK_CREDENTIAL_ATTEMPT_LIMIT: usize = 4;

#[derive(Debug, Clone, Default)]
pub struct TurnCredentials {
    pub username: String,
    pub password: String,
    pub server_addrs: Vec<String>,
    /// Go time.Time (нулевое значение = нет кеша) → Option<Instant>.
    pub expires_at: Option<Instant>,
    pub link: String,
}

pub struct StreamCredentialsCache {
    creds: Mutex<TurnCredentials>,
    error_count: AtomicI32,
    last_error_time: AtomicI64,
}

// Go: credentialLifetime = 10m, cacheSafetyMargin = 60s → срок жизни кеша.
const CREDENTIAL_TTL: Duration = Duration::from_secs(10 * 60 - 60);
const MAX_CACHE_ERRORS: i32 = 3;
const ERROR_WINDOW_SECS: i64 = 10;

const STREAMS_PER_CACHE: i32 = 10;

fn get_cache_id(stream_id: i32) -> i32 {
    stream_id / STREAMS_PER_CACHE
}

static CREDENTIALS_STORE: OnceLock<Mutex<HashMap<i32, Arc<StreamCredentialsCache>>>> = OnceLock::new();

fn credentials_store() -> &'static Mutex<HashMap<i32, Arc<StreamCredentialsCache>>> {
    CREDENTIALS_STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_stream_cache(stream_id: i32) -> Arc<StreamCredentialsCache> {
    let cache_id = get_cache_id(stream_id);
    let mut store = credentials_store().lock().unwrap_or_else(|e| e.into_inner());
    store.entry(cache_id).or_insert_with(|| Arc::new(StreamCredentialsCache::new())).clone()
}

impl StreamCredentialsCache {
    fn new() -> Self {
        StreamCredentialsCache {
            creds: Mutex::new(TurnCredentials::default()),
            error_count: AtomicI32::new(0),
            last_error_time: AtomicI64::new(0),
        }
    }

    fn invalidate(&self, stream_id: i32) {
        *self.creds.lock().unwrap_or_else(|e| e.into_inner()) = TurnCredentials::default();
        self.error_count.store(0, Ordering::Relaxed);
        self.last_error_time.store(0, Ordering::Relaxed);

        log_add("wdtt", &format!("[STREAM {}] [VK Auth] Credentials cache invalidated", stream_id));
    }
}

// Go isAuthError.
#[allow(dead_code)] // строковая классификация; Auth-ошибки идут типом SessionErrorType
pub fn is_auth_error(err: &WdttError) -> bool {
    let err_str = err.to_string();
    err_str.contains("401")
        || err_str.contains("Unauthorized")
        || err_str.contains("authentication")
        || err_str.contains("invalid credential")
        || err_str.contains("stale nonce")
}

// Go handleAuthError.
pub fn handle_auth_error(stream_id: i32) -> bool {
    let cache = get_stream_cache(stream_id);
    let cache_id = get_cache_id(stream_id);

    let now = now_unix();

    if now - cache.last_error_time.load(Ordering::Relaxed) > ERROR_WINDOW_SECS {
        cache.error_count.store(0, Ordering::Relaxed);
    }

    let count = cache.error_count.fetch_add(1, Ordering::Relaxed) + 1;
    cache.last_error_time.store(now, Ordering::Relaxed);

    log_add(
        "wdtt",
        &format!("[STREAM {}] Auth error (cache={}, count={}/{})", stream_id, cache_id, count, MAX_CACHE_ERRORS),
    );

    if count >= MAX_CACHE_ERRORS {
        log_add(
            "wdtt",
            &format!("[VK Auth] Multiple auth errors detected ({}), invalidating cache {}", count, cache_id),
        );
        cache.invalidate(stream_id);
        return true;
    }
    false
}

// ═══════════════════════════════════════════════════
// Глобальный капча-лок и режимы (Go globalCaptchaLockout / getCaptchaMode /
// getVKAuthMode)
// ═══════════════════════════════════════════════════

static GLOBAL_CAPTCHA_LOCKOUT: AtomicI64 = AtomicI64::new(0);

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// Go: captchaAutoWebViewTimeout = 10s, captchaManualWebViewTimeout = 60s,
// captchaSelectedWebViewTimeout = 120s.
const CAPTCHA_AUTO_WEBVIEW_TIMEOUT: Duration = Duration::from_secs(10);
const CAPTCHA_MANUAL_WEBVIEW_TIMEOUT: Duration = Duration::from_secs(60);
const CAPTCHA_SELECTED_WEBVIEW_TIMEOUT: Duration = Duration::from_secs(120);

// Go normalizeCaptchaMode / normalizeVKAuthMode / set-режимы живут в core.rs
// (activeCore хранит их в cfg; делегирование — super::core::get_*_mode ниже).

// Go getVKAuthMode — пакетная функция, делегирует в activeCore (core.rs).
fn get_vk_auth_mode() -> String {
    super::core::get_vk_auth_mode()
}

// Go getCaptchaMode — пакетная функция, делегирует в activeCore (core.rs).
fn get_captcha_mode() -> String {
    super::core::get_captcha_mode()
}

fn vk_delay_random(min_ms: i64, max_ms: i64) {
    let ms = min_ms + rand_below(max_ms - min_ms + 1);
    thread::sleep(Duration::from_millis(ms as u64));
}

// ═══════════════════════════════════════════════════
// Кэшированное получение кредов (Go getVkCredsCached)
// ═══════════════════════════════════════════════════

fn get_vk_creds_cached(
    cancel: &Arc<AtomicBool>,
    link: &str,
    stream_id: i32,
) -> Result<(String, String, Vec<String>), WdttError> {
    let cache = get_stream_cache(stream_id);
    let cache_id = get_cache_id(stream_id);

    // быстрый путь (Go RLock)
    {
        let c = cache.creds.lock().unwrap_or_else(|e| e.into_inner());
        if c.link == link && c.expires_at.map(|t| Instant::now() < t).unwrap_or(false)
            && !c.server_addrs.is_empty()
        {
            let expires =
                c.expires_at.map(|t| t.duration_since(Instant::now())).unwrap_or_default();
            let u = c.username.clone();
            let p = c.password.clone();
            let addrs = c.server_addrs.clone();
            drop(c);
            // Возвращается ВЕСЬ список адресов (выбор по stream_id делает
            // звонящий), поэтому «selected=адрес» в логе было враньём
            log_add(
                "wdtt",
                &format!(
                    "[STREAM {}] [VK Auth] Using cached credentials (cache={}, expires in {}, urls={})",
                    stream_id,
                    cache_id,
                    fmt_go_duration(expires),
                    addrs.len()
                ),
            );
            return Ok((u, p, addrs));
        }
    }

    // медленный путь с повторной проверкой (Go Lock + double-check)
    let mut c = cache.creds.lock().unwrap_or_else(|e| e.into_inner());
    if c.link == link && c.expires_at.map(|t| Instant::now() < t).unwrap_or(false)
        && !c.server_addrs.is_empty()
    {
        return Ok((c.username.clone(), c.password.clone(), c.server_addrs.clone()));
    }

    let (user, pass, addrs) = fetch_vk_creds_serialized(cancel, link, stream_id)?;

    *c = TurnCredentials {
        username: user.clone(),
        password: pass.clone(),
        server_addrs: addrs.clone(),
        expires_at: Some(Instant::now() + CREDENTIAL_TTL),
        link: link.to_string(),
    };
    Ok((user, pass, addrs))
}

// ═══════════════════════════════════════════════════
// Троттлинг (Go vkRequestMu / globalLastVkFetchTime / fetchVkCredsSerialized)
// ═══════════════════════════════════════════════════

static VK_REQUEST_MU: Mutex<()> = Mutex::new(());
static GLOBAL_LAST_VK_FETCH_TIME: Mutex<Option<Instant>> = Mutex::new(None);

// Слот VK-замка: сериализация нужна СЕТЕВОЙ фазе цепочки (rate limit VK),
// но не ожиданию человека. Решение капчи (WebView — до 60-120 с, слайдер/PoW —
// секунды) раньше шло под удерживаемым VK_REQUEST_MU — все стримы всех сессий
// простаивали, пока пользователь не решит капчу. park отпускает замок,
// resume забирает обратно перед продолжением сетевой фазы.
type VkMuSlot = Option<std::sync::MutexGuard<'static, ()>>;

fn park_vk_mu(slot: &mut VkMuSlot) {
    *slot = None;
}

fn resume_vk_mu(slot: &mut VkMuSlot) {
    if slot.is_none() {
        *slot = Some(VK_REQUEST_MU.lock().unwrap_or_else(|e| e.into_inner()));
    }
}

fn fetch_vk_creds_serialized(
    cancel: &Arc<AtomicBool>,
    link: &str,
    stream_id: i32,
) -> Result<(String, String, Vec<String>), WdttError> {
    let mut mu_slot: VkMuSlot = Some(VK_REQUEST_MU.lock().unwrap_or_else(|e| e.into_inner()));

    let min_interval = Duration::from_millis((3000 + rand_below(3000)) as u64);
    {
        let last = GLOBAL_LAST_VK_FETCH_TIME.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = *last {
            let elapsed = t.elapsed();
            if elapsed < min_interval {
                let wait = min_interval - elapsed;
                log_add(
                    "wdtt",
                    &format!(
                        "[STREAM {}] [VK Auth] Throttling: waiting {} to prevent rate limit...",
                        stream_id,
                        fmt_go_duration(wait)
                    ),
                );
                drop(last);
                // Go: select { <-ctx.Done() → ctx.Err(); <-time.After(wait) }
                if !sleep_or_cancel(wait, cancel) {
                    return Err(WdttError::Msg("context canceled".to_string()));
                }
            }
        }
    }

    let result = fetch_vk_creds(cancel, link, stream_id, &mut mu_slot);
    // Go defer: отметка времени после завершения запроса (в т.ч. при ошибке)
    *GLOBAL_LAST_VK_FETCH_TIME.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    result
}

// Go shouldRetryVKCallsOutdatedToken.
fn should_retry_vkcalls_outdated_token(err: Option<&WdttError>) -> bool {
    let Some(err) = err else { return false };
    match err {
        WdttError::Failure { step, source, .. } if step.starts_with("step5 ") => {
            source.to_string().to_lowercase().contains("error.webrtc.auth.anonym_token.outdated")
        }
        _ => false,
    }
}

// vk_resp_cut — ответ VK в тексте ошибки обрезаем до 200 символов: полный
// JSON на неожиданных ответах мог утащить токен/секрет в лог
fn vk_resp_cut(resp: &Value) -> String {
    match serde_json::to_string(resp) {
        Ok(b) => {
            let t: String = b.chars().take(200).collect();
            if b.chars().count() > 200 {
                format!("{}…", t)
            } else {
                t
            }
        }
        Err(e) => format!("(unmarshallable: {})", e),
    }
}

// ═══════════════════════════════════════════════════
// Основная цепочка (Go fetchVkCreds)
// ═══════════════════════════════════════════════════

pub fn fetch_vk_creds(
    cancel: &Arc<AtomicBool>,
    link: &str,
    stream_id: i32,
    mu_slot: &mut VkMuSlot,
) -> Result<(String, String, Vec<String>), WdttError> {
    if now_unix() < GLOBAL_CAPTCHA_LOCKOUT.load(Ordering::Relaxed) {
        return Err(WdttError::Msg("CAPTCHA_WAIT_REQUIRED: global lockout active".to_string()));
    }

    if get_vk_auth_mode() == "vkcalls" {
        let mut result = get_vk_creds_via_vkcalls_path(cancel, link, stream_id);
        // VK occasionally expires its freshly issued anonymous token between
        // steps 4 and 5. Retry the whole short-lived chain once rather than
        // dropping into the much less reliable CAPTCHA fallback.
        if should_retry_vkcalls_outdated_token(result.as_ref().err()) {
            log_add(
                "wdtt",
                &format!("[STREAM {}] [VK Auth] Fresh anonymous token was outdated; retrying VK Calls once", stream_id),
            );
            if !sleep_or_cancel(Duration::from_millis(750), cancel) {
                return Err(WdttError::Msg("context canceled".to_string()));
            }
            result = get_vk_creds_via_vkcalls_path(cancel, link, stream_id);
        }
        match result {
            Ok(creds) => {
                log_add("wdtt", &format!("[STREAM {}] [VK Auth] Success via VK Calls path", stream_id));
                return Ok(creds);
            }
            Err(err) => {
                if let Some(call_err) = as_call_unavailable(&err) {
                    log_add(
                        "wdtt",
                        &format!("[STREAM {}] [VK Auth] VK Calls path returned non-retryable call error: {}", stream_id, call_err),
                    );
                    return Err(call_err);
                }
                log_add(
                    "wdtt",
                    &format!(
                        "[STREAM {}] [VK Auth] VK Calls path failed ({}), falling back to legacy",
                        stream_id,
                        describe_vkcalls_failure(&err)
                    ),
                );
            }
        }
    } else {
        log_add("wdtt", &format!("[STREAM {}] [VK Auth] Legacy mode selected, skipping VK Calls path", stream_id));
    }

    let mut last_err: Option<WdttError> = None;

    for attempt in 0..VK_CREDENTIAL_ATTEMPT_LIMIT {
        let creds_list = vk_credentials_snapshot();
        if creds_list.is_empty() {
            // Go упал бы с index-out-of-range; здесь — явная ошибка
            return Err(WdttError::Msg("no VK credentials configured".to_string()));
        }
        let creds = creds_list[attempt % creds_list.len()].clone();
        log_add(
            "wdtt",
            &format!(
                "[STREAM {}] [VK Auth] Trying credentials: client_id={} (attempt {}/{})",
                stream_id,
                creds.client_id,
                attempt + 1,
                VK_CREDENTIAL_ATTEMPT_LIMIT
            ),
        );

        match get_token_chain(cancel, link, stream_id, &creds, mu_slot) {
            Ok(turn_creds) => {
                log_add(
                    "wdtt",
                    &format!("[STREAM {}] [VK Auth] Success with client_id={}", stream_id, creds.client_id),
                );
                return Ok(turn_creds);
            }
            Err(err) => {
                log_add(
                    "wdtt",
                    &format!("[STREAM {}] [VK Auth] Failed with client_id={}: {}", stream_id, creds.client_id, err),
                );

                if let Some(call_err) = as_call_unavailable(&err) {
                    return Err(call_err);
                }

                let err_str = err.to_string();
                if err_str.contains("CAPTCHA_WAIT_REQUIRED") || err_str.contains("FATAL_CAPTCHA") {
                    return Err(err);
                }

                if err_str.contains("error_code:29")
                    || err_str.contains("error_code: 29")
                    || err_str.contains("Rate limit")
                {
                    log_add(
                        "wdtt",
                        &format!("[STREAM {}] [VK Auth] Rate limit detected, trying next credentials...", stream_id),
                    );
                }

                last_err = Some(err);
            }
        }

        if attempt % creds_list.len() == creds_list.len() - 1 && attempt + 1 < VK_CREDENTIAL_ATTEMPT_LIMIT {
            let wait = Duration::from_millis((900 + rand_below(900)) as u64);
            let cycle_word = if creds_list.len() > 1 { "All VK credentials failed" } else { "VK credential failed" };
            log_add(
                "wdtt",
                &format!(
                    "[STREAM {}] [VK Auth] {}, retrying after {}...",
                    stream_id,
                    cycle_word,
                    fmt_go_duration(wait)
                ),
            );
            if !sleep_or_cancel(wait, cancel) {
                return Err(WdttError::Msg("context canceled".to_string()));
            }
        }
    }

    Err(WdttError::Msg(format!(
        "all VK credentials failed: {}",
        last_err.map(|e| e.to_string()).unwrap_or_default()
    )))
}

// ═══════════════════════════════════════════════════
// Легаси-цепочка токенов (Go getTokenChain)
// ═══════════════════════════════════════════════════

fn get_token_chain(
    cancel: &Arc<AtomicBool>,
    link: &str,
    stream_id: i32,
    creds: &VKCredentials,
    mu_slot: &mut VkMuSlot,
) -> Result<(String, String, Vec<String>), WdttError> {
    let profile = get_random_profile();

    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| WdttError::Msg(format!("failed to initialize tls_client: {}", e)))?;

    let name = generate_name();
    let escaped_name = query_escape(&name);

    log_add(
        "wdtt",
        &format!("[STREAM {}] [VK Auth] Identity - Name: {} | UA: {}", stream_id, name, profile.user_agent),
    );

    let do_request = |data: &str, url: &str| -> Result<Value, WdttError> {
        // Go: parsedURL.Hostname() → req.Host; reqwest ставит Host из URL сам
        let mut headers = HeaderMap::new();
        apply_browser_profile(&mut headers, &profile);
        header_set(&mut headers, "Content-Type", "application/x-www-form-urlencoded");
        header_set(&mut headers, "Accept", "*/*");
        header_set(&mut headers, "Origin", "https://vk.ru");
        header_set(&mut headers, "Referer", "https://vk.ru/");
        header_set(&mut headers, "Sec-Fetch-Site", "same-site");
        header_set(&mut headers, "Sec-Fetch-Mode", "cors");
        header_set(&mut headers, "Sec-Fetch-Dest", "empty");
        header_set(&mut headers, "Priority", "u=1, i");

        let http_resp = client
            .post(url)
            .headers(headers)
            .body(data.to_string())
            .send()
            .map_err(|e| WdttError::Msg(e.to_string()))?;

        let status = http_resp.status();
        if status.as_u16() != 200 {
            // 403/429/5xx от антибот-эджа раньше падали в json.Unmarshal как
            // «invalid character '<'» и сжигали все попытки с бессмысленной
            // диагностикой — возвращаем честный статус
            let bytes = http_resp.bytes().unwrap_or_default();
            let head = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]);
            return Err(WdttError::Msg(format!("http {}: {}", status.as_u16(), head.trim())));
        }

        let bytes = http_resp.bytes().map_err(|e| WdttError::Msg(e.to_string()))?;
        let body = &bytes[..bytes.len().min(1 << 20)];
        let resp: Value = serde_json::from_slice(body).map_err(|e| WdttError::Msg(e.to_string()))?;
        Ok(resp)
    };

    // все подставляемые значения эскейпим: «+» в токене превратился бы в
    // пробел, «&» разрезал бы form-тело
    let data = format!(
        "client_id={}&token_type=messages&client_secret={}&version=1&app_id={}",
        query_escape(&creds.client_id),
        query_escape(&creds.client_secret),
        query_escape(&creds.client_id)
    );
    let resp = do_request(&data, "https://login.vk.ru/?act=get_anonym_token")?;
    let data_map = resp
        .get("data")
        .and_then(|v| v.as_object())
        .ok_or_else(|| WdttError::Msg(format!("unexpected anon token response: {}", vk_resp_cut(&resp))))?;
    let token1 = data_map
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WdttError::Msg(format!("missing access_token in response: {}", vk_resp_cut(&resp))))?
        .to_string();

    vk_delay_random(100, 150);

    let preview_data = format!(
        "vk_join_link=https://vk.ru/call/join/{}&fields=photo_200&access_token={}",
        query_escape(link),
        query_escape(&token1)
    );
    let preview_url = format!(
        "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id={}",
        query_escape(&creds.client_id)
    );
    match do_request(&preview_data, &preview_url) {
        Ok(resp) => {
            if let Some(call_err) = fatal_call_error(&resp) {
                log_add(
                    "wdtt",
                    &format!(
                        "[STREAM {}] [VK Auth] getCallPreview returned non-retryable call error: {}",
                        stream_id, call_err
                    ),
                );
                return Err(call_err);
            }
        }
        Err(err) => {
            log_add(
                "wdtt",
                &format!("[STREAM {}] [VK Auth] Warning: getCallPreview failed: {}", stream_id, err),
            );
        }
    }

    vk_delay_random(200, 400);

    let mut data = format!(
        "vk_join_link=https://vk.ru/call/join/{}&name={}&access_token={}",
        query_escape(link),
        // escaped_name уже закодирован в query_escape(&name) — двойное
        // кодирование посылало VK литеральные «%D0%A1...» вместо имени
        escaped_name,
        query_escape(&token1)
    );
    let url_addr = format!(
        "https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id={}",
        query_escape(&creds.client_id)
    );

    let saved_profile: Option<SavedProfile> = match load_profile_from_disk() {
        Ok(sp) => Some(sp),
        Err(perr) => {
            // отсутствие файла — норма (первый запуск); остальное — в лог
            // (Go os.IsNotExist; load_profile_from_disk возвращает String)
            let perr_low = perr.to_lowercase();
            if !perr_low.contains("os error 2") && !perr_low.contains("not found") {
                log_add(
                    "wdtt",
                    &format!("[STREAM {}] [VK Auth] сохранённый профиль не прочитан: {}", stream_id, perr),
                );
            }
            None
        }
    };

    #[allow(unused_assignments)] // token2: инициал перезаписывается до чтения
    let mut token2 = String::new();
    let mut attempt: i32 = 0;
    loop {
        let resp = do_request(&data, &url_addr)?;

        if let Some(err_obj) = resp.get("error").filter(|v| v.is_object()) {
            if let Some(call_err) = fatal_call_error(&resp) {
                log_add(
                    "wdtt",
                    &format!(
                        "[STREAM {}] [VK Auth] getAnonymousToken returned non-retryable call error: {}",
                        stream_id, call_err
                    ),
                );
                return Err(call_err);
            }

            let captcha_err = parse_vk_captcha_error(err_obj);
            if !captcha_err.redirect_uri.is_empty() && !captcha_err.session_token.is_empty() {
                if attempt >= 3 {
                    log_add("wdtt", &format!("[STREAM {}] [Captcha] Max attempts reached", stream_id));
                    GLOBAL_CAPTCHA_LOCKOUT.store(now_unix() + 60, Ordering::Relaxed);
                    return Err(WdttError::Msg("CAPTCHA_WAIT_REQUIRED".to_string()));
                }

                // Решение капчи — БЕЗ глобального VK-замка: иначе все стримы
                // стояли на VK_REQUEST_MU, пока пользователь решает капчу.
                // Сетевые запросы после капчи снова идут под замком.
                park_vk_mu(mu_slot);
                let success_token =
                    match solve_captcha_by_selected_mode(cancel, stream_id, attempt + 1, &captcha_err, &client, &profile, saved_profile.as_ref()) {
                        Ok(t) => t,
                        Err(solve_err) => {
                            resume_vk_mu(mu_slot);
                            log_add(
                                "wdtt",
                                &format!("[STREAM {}] [Captcha] Solve failed: {}", stream_id, solve_err),
                            );
                            GLOBAL_CAPTCHA_LOCKOUT.store(now_unix() + 60, Ordering::Relaxed);
                            return Err(WdttError::Msg("CAPTCHA_WAIT_REQUIRED".to_string()));
                        }
                    };
                resume_vk_mu(mu_slot);

                let mut captcha_attempt = captcha_err.captcha_attempt.clone();
                if captcha_attempt == "0" || captcha_attempt.is_empty() {
                    captcha_attempt = "1".to_string();
                }

                data = format!(
                    "vk_join_link=https://vk.ru/call/join/{}&name={}&captcha_key=&captcha_sid={}&is_sound_captcha=0&success_token={}&captcha_ts={}&captcha_attempt={}&access_token={}",
                    // link эскейпим: «:» и «/» в URL-хеше не должны резать form-тело
                    query_escape(link),
                    escaped_name,
                    captcha_err.captcha_sid,
                    query_escape(&success_token),
                    captcha_err.captcha_ts,
                    captcha_attempt,
                    token1
                );
                attempt += 1;
                continue;
            }
            return Err(WdttError::Msg(format!("VK API error: {}", vk_resp_cut(err_obj))));
        }

        let resp_map = resp
            .get("response")
            .and_then(|v| v.as_object())
            .ok_or_else(|| WdttError::Msg(format!("unexpected getAnonymousToken response: {}", vk_resp_cut(&resp))))?;
        token2 = resp_map
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WdttError::Msg(format!("missing token in response: {}", vk_resp_cut(&resp))))?
            .to_string();
        break;
    }

    vk_delay_random(100, 150);

    let session_data = format!(
        r#"{{"version":2,"device_id":"{}","client_version":1.1,"client_type":"SDK_JS"}}"#,
        Uuid::new_v4()
    );
    let data = format!(
        "session_data={}&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA",
        query_escape(&session_data)
    );
    let resp = do_request(&data, "https://calls.okcdn.ru/fb.do")?;
    let token3 = resp
        .get("session_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WdttError::Msg(format!("missing session_key in response: {}", vk_resp_cut(&resp))))?
        .to_string();

    vk_delay_random(100, 150);

    let data = format!(
        "joinLink={}&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken={}&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key={}",
        query_escape(link),
        query_escape(&token2),
        query_escape(&token3)
    );
    let resp = do_request(&data, "https://calls.okcdn.ru/fb.do")?;
    // ошибка OK API приходит в теле 200 OK — без проверки диагностика была бы
    // «missing turn_server in response» вместо реальной причины
    if let Some(err_obj) = resp.get("error").filter(|v| v.is_object()) {
        let code = err_obj.get("error_code").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let msg = err_obj.get("error_msg").and_then(|v| v.as_str()).unwrap_or("");
        return Err(WdttError::Msg(format!("joinConversationByLink error {}: {}", code, msg)));
    }

    let ts_raw = resp
        .get("turn_server")
        .and_then(|v| v.as_object())
        .ok_or_else(|| WdttError::Msg(format!("missing turn_server in response: {}", vk_resp_cut(&resp))))?;
    let user = ts_raw
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WdttError::Msg("missing username in turn_server".to_string()))?
        .to_string();
    let pass = ts_raw
        .get("credential")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WdttError::Msg("missing credential in turn_server".to_string()))?
        .to_string();
    let urls_raw = ts_raw
        .get("urls")
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| WdttError::Msg("missing or empty urls in turn_server".to_string()))?;

    log_add("wdtt", &format!("[STREAM {}] [VK Auth] TURN urls ({} total):", stream_id, urls_raw.len()));
    for (i, u) in urls_raw.iter().enumerate() {
        log_add("wdtt", &format!("[STREAM {}] [VK Auth]   [{}] {}", stream_id, i, u));
    }

    let mut addresses: Vec<String> = Vec::new();
    for u in urls_raw {
        let Some(url_str) = u.as_str() else { continue };
        let clean = url_str.split('?').next().unwrap_or(url_str);
        let mut address = clean.to_string();
        for p in ["turns:", "turn:", "stuns:", "stun:"] {
            // stun: URL тоже встречается в urls — без среза префикса в список
            // адресов уезжал «stun:host:port», и dial фейлился
            if address.to_lowercase().starts_with(p) {
                address = address[p.len()..].to_string();
                break;
            }
        }
        addresses.push(address);
    }

    if addresses.is_empty() {
        return Err(WdttError::Msg("no valid TURN addresses found".to_string()));
    }

    Ok((user, pass, addresses))
}

// ═══════════════════════════════════════════════════
// Выбор режима капчи (Go solveCaptchaBySelectedMode)
// ═══════════════════════════════════════════════════

fn solve_captcha_by_selected_mode(
    cancel: &Arc<AtomicBool>,
    stream_id: i32,
    attempt: i32,
    captcha_err: &VkCaptchaError,
    client: &Client,
    profile: &Profile,
    saved_profile: Option<&SavedProfile>,
) -> Result<String, WdttError> {
    match get_captcha_mode().as_str() {
        "wv" => {
            log_add(
                "wdtt",
                &format!("[STREAM {}] [КАПЧА] WBV: режим из настроек Android (attempt {})", stream_id, attempt),
            );
            return request_web_view_captcha(cancel, stream_id, captcha_err, "selected", CAPTCHA_SELECTED_WEBVIEW_TIMEOUT);
        }
        "rjs" => {
            log_add(
                "wdtt",
                &format!("[STREAM {}] [КАПЧА] RJS: Go v2 выбран в настройках (attempt {})", stream_id, attempt),
            );
            match solve_vk_captcha_v2_attempts(cancel, client, captcha_err, profile, saved_profile, 2) {
                Ok(token) => return Ok(token),
                Err(solve_err) => {
                    log_add(
                        "wdtt",
                        &format!("[STREAM {}] [КАПЧА] RJS: ошибка, fallback на WBV Auto: {}", stream_id, solve_err),
                    );
                    return request_web_view_captcha(cancel, stream_id, captcha_err, "auto", CAPTCHA_AUTO_WEBVIEW_TIMEOUT);
                }
            }
        }
        _ => {}
    }

    log_add(
        "wdtt",
        &format!("[STREAM {}] [КАПЧА] AUTO: старт цепочки (captcha attempt {})", stream_id, attempt),
    );

    let mut last_err: WdttError;
    match solve_vk_captcha_v2_attempts(cancel, client, captcha_err, profile, saved_profile, 2) {
        Ok(token) => {
            log_add("wdtt", &format!("[STREAM {}] [КАПЧА] AUTO: Go v2 решил капчу", stream_id));
            return Ok(token);
        }
        Err(solve_err) => {
            last_err = WdttError::Msg(solve_err.to_string());
            log_add(
                "wdtt",
                &format!("[STREAM {}] [КАПЧА] AUTO: Go v2 не решил за 2 попытки: {}", stream_id, last_err),
            );
        }
    }

    for wbv_attempt in 1..=2 {
        log_add(
            "wdtt",
            &format!(
                "[STREAM {}] [КАПЧА] AUTO: WBV Auto попытка {}/2 (timeout {})",
                stream_id,
                wbv_attempt,
                fmt_go_duration(CAPTCHA_AUTO_WEBVIEW_TIMEOUT)
            ),
        );
        match request_web_view_captcha(cancel, stream_id, captcha_err, "auto", CAPTCHA_AUTO_WEBVIEW_TIMEOUT) {
            Ok(token) => {
                log_add("wdtt", &format!("[STREAM {}] [КАПЧА] AUTO: WBV Auto решил капчу", stream_id));
                return Ok(token);
            }
            Err(solve_err) => {
                last_err = WdttError::Msg(solve_err.to_string());
                if is_webview_captcha_timeout(&last_err) {
                    log_add(
                        "wdtt",
                        &format!("[STREAM {}] [КАПЧА] AUTO: WBV Auto timeout {}/2", stream_id, wbv_attempt),
                    );
                } else {
                    log_add(
                        "wdtt",
                        &format!("[STREAM {}] [КАПЧА] AUTO: WBV Auto ошибка {}/2: {}", stream_id, wbv_attempt, last_err),
                    );
                }
            }
        }

        if !sleep_or_cancel(Duration::from_millis((250 + rand_below(250)) as u64), cancel) {
            return Err(WdttError::Msg("context canceled".to_string()));
        }
    }

    log_add("wdtt", &format!("[STREAM {}] [КАПЧА] AUTO: финальная Go v2 попытка после WBV", stream_id));
    match solve_vk_captcha_v2_attempts(cancel, client, captcha_err, profile, saved_profile, 1) {
        Ok(token) => {
            log_add("wdtt", &format!("[STREAM {}] [КАПЧА] AUTO: финальная Go v2 решила капчу", stream_id));
            return Ok(token);
        }
        Err(solve_err) => {
            last_err = WdttError::Msg(solve_err.to_string());
            log_add(
                "wdtt",
                &format!("[STREAM {}] [КАПЧА] AUTO: финальная Go v2 ошибка: {}", stream_id, last_err),
            );
        }
    }

    log_add(
        "wdtt",
        &format!("[STREAM {}] [КАПЧА] AUTO: автоцепочка не прошла, открыт ручной WebView", stream_id),
    );
    let solve_err = match request_web_view_captcha(cancel, stream_id, captcha_err, "manual", CAPTCHA_MANUAL_WEBVIEW_TIMEOUT) {
        Ok(token) => {
            log_add("wdtt", &format!("[STREAM {}] [КАПЧА] AUTO: ручной WebView решил капчу", stream_id));
            return Ok(token);
        }
        Err(e) => e,
    };
    Err(WdttError::Msg(format!(
        "automatic captcha chain failed: {}; manual fallback failed: {}",
        last_err, solve_err
    )))
}

// Go requestWebViewCaptcha: печатает CAPTCHA_SOLVE|... в stdout и ждёт токен
// из CaptchaResultChan — GUI-протокол десктопного WebView. В Rust-порте роль
// stdout играет событие ядра "captcha_solve" (wdtt_session форвардит его в UI),
// роль канала — core::captcha_drain/captcha_wait: пользователь решает капчу,
// UI передаёт токен через PwdttSendCaptcha → Core::solve_captcha → канал.
fn request_web_view_captcha(
    cancel: &Arc<AtomicBool>,
    stream_id: i32,
    captcha_err: &VkCaptchaError,
    mode: &str,
    timeout: Duration,
) -> Result<String, WdttError> {
    if captcha_err.redirect_uri.is_empty() || captcha_err.session_token.is_empty() {
        return Err(WdttError::Msg("webview captcha data is incomplete".to_string()));
    }
    let mode = mode.trim().to_lowercase();
    let mode = if mode != "manual" && mode != "selected" { "auto".to_string() } else { mode };

    // Сначала осушаем канал от протухших токенов (контракт Go SolveCaptcha),
    // затем просим UI показать панель ввода капчи.
    crate::wdtt::core::captcha_drain();
    let data = serde_json::json!({
        "streamId": stream_id,
        "mode": mode,
        "url": captcha_err.redirect_uri,
    })
    .to_string();
    crate::wdtt::core::emit_event_named("captcha_solve", &data);
    log_add(
        "wdtt",
        &format!(
            "[STREAM {}] [КАПЧА] WBV({}): жду ручной ввод токена до {} с",
            stream_id,
            mode,
            timeout.as_secs()
        ),
    );

    // Ожидание токена с учётом отмены: captcha_wait короткими квантами,
    // чтобы Stop не оставлял воркер висеть до полного таймаута.
    let deadline = Instant::now() + timeout;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(WdttError::Msg("context canceled".to_string()));
        }
        match crate::wdtt::core::captcha_wait(Duration::from_millis(250)) {
            Some(t) => {
                let t = t.trim().to_string();
                if t.is_empty() {
                    continue;
                }
                return Ok(t);
            }
            None => {}
        }
        if Instant::now() >= deadline {
            // Формулировка важна: is_webview_captcha_timeout ищет "timed out".
            return Err(WdttError::Msg(format!(
                "webview captcha timed out after {}s",
                timeout.as_secs()
            )));
        }
    }
}

// Go isWebViewCaptchaTimeout.
fn is_webview_captcha_timeout(err: &WdttError) -> bool {
    err.to_string().to_lowercase().contains("timed out")
}

// ═══════════════════════════════════════════════════
// Публичная точка входа (Go GetCreds)
// ═══════════════════════════════════════════════════

pub fn get_creds(
    cancel: &Arc<AtomicBool>,
    link: &str,
    stream_id: i32,
) -> Result<(String, String, Vec<String>), WdttError> {
    get_vk_creds_cached(cancel, link, stream_id)
}

// ═══════════════════════════════════════════════════
// Форматирование Duration в стиле Go (%v): "8m59s", "2.345s", "45s"
// ═══════════════════════════════════════════════════

fn fmt_go_duration(d: Duration) -> String {
    let total_ms = d.as_millis();
    let h = total_ms / 3_600_000;
    let m = (total_ms % 3_600_000) / 60_000;
    let s = (total_ms % 60_000) / 1000;
    let ms = total_ms % 1000;
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{}h", h));
    }
    if m > 0 || h > 0 {
        out.push_str(&format!("{}m", m));
    }
    if ms > 0 {
        out.push_str(&format!("{}.{:03}s", s, ms));
    } else {
        out.push_str(&format!("{}s", s));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_deobf() {
        assert_eq!(deobf(";535939", -3), "8202606");
        assert_eq!(deobf("95;:7;:", -3), "6287487");
        assert_eq!(deobf("oPUvWlPF|Sqs8yirogpq", -3), "lMRsTiMCyPnp5vfoldmn");
        assert_eq!(deobf("PxD{IdNG\\GRLF}JqHRks", -3), "MuAxFaKDYDOICzGnEOhp");
    }

    #[test]
    fn test_parse_vk_credentials_env() {
        let creds = parse_vk_credentials_env(" 123:abc , 456:def ").unwrap();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].client_id, "123");
        assert_eq!(creds[1].client_secret, "def");
        assert!(parse_vk_credentials_env("noseparator").is_err());
        assert!(parse_vk_credentials_env(":secret").is_err());
        assert!(parse_vk_credentials_env("  ,, ").is_err());
    }

    #[test]
    fn test_vk_error_code() {
        assert_eq!(vk_error_code(&json!(14)), 14);
        assert_eq!(vk_error_code(&json!(14.9)), 14);
        assert_eq!(vk_error_code(&json!("14")), 14);
        assert_eq!(vk_error_code(&json!("abc")), 0);
        assert_eq!(vk_error_code(&Value::Null), 0);
    }

    #[test]
    fn test_fatal_call_error() {
        assert!(fatal_call_error(&json!({})).is_none());
        assert!(fatal_call_error(&json!({"error": {"error_code": 500}})).is_none());
        assert!(fatal_call_error(&json!({"error": {"error_code": 951}})).is_some());
        assert!(fatal_call_error(&json!({"error": {"error_code": 9005, "error_msg": "no call"}})).is_some());
        match fatal_call_error(&json!({"error": {"error_code": 954, "error_msg": "call ended"}})) {
            Some(WdttError::CallUnavailable { code, message }) => {
                assert_eq!(code, 954);
                assert_eq!(message, "call ended");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_is_auth_error() {
        assert!(is_auth_error(&WdttError::Msg("http 401".into())));
        assert!(is_auth_error(&WdttError::Msg("Unauthorized".into())));
        assert!(!is_auth_error(&WdttError::Msg("timeout".into())));
    }

    #[test]
    fn test_should_retry_outdated_token() {
        use super::super::creds::VKCallsFailureKind;
        let e = WdttError::Failure {
            step: "step5 vchat.joinConversationByLink".into(),
            kind: VKCallsFailureKind::OKCDN,
            source: Box::new(WdttError::Msg(
                "error_code=102 error.webrtc.auth.anonym_token.outdated".into(),
            )),
        };
        assert!(should_retry_vkcalls_outdated_token(Some(&e)));
        let e2 = WdttError::Failure {
            step: "step1 auth.getAnonymToken".into(),
            kind: VKCallsFailureKind::VKApi,
            source: Box::new(WdttError::Msg("error.webrtc.auth.anonym_token.outdated".into())),
        };
        assert!(!should_retry_vkcalls_outdated_token(Some(&e2)));
        assert!(!should_retry_vkcalls_outdated_token(None));
    }

    #[test]
    fn test_fmt_go_duration() {
        assert_eq!(fmt_go_duration(Duration::from_millis(2345)), "2.345s");
        assert_eq!(fmt_go_duration(Duration::from_secs(45)), "45s");
        assert_eq!(fmt_go_duration(Duration::from_secs(8 * 60 + 59)), "8m59s");
        assert_eq!(fmt_go_duration(Duration::from_secs(60)), "1m0s");
    }

    #[test]
    fn test_get_cache_id() {
        let ids: [i32; 4] = [0, 9, 10, 23];
        assert_eq!(get_cache_id(ids[0]), 0);
        assert_eq!(get_cache_id(ids[1]), 0);
        assert_eq!(get_cache_id(ids[2]), 1);
        assert_eq!(get_cache_id(ids[3]), 2);
    }
}
