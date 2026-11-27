// VK Calls — альтернативный путь получения TURN-кредов — порт Go
// pwdttcore/creds_vkcalls.go.
//
// Пять шагов: auth.getAnonymToken → messages.getCallPreview →
// messages.getAnonymCallToken → auth.anonymLogin (OK CDN) →
// vchat.joinConversationByLink (OK CDN).
//
// Здесь же живут общие типы ошибок слоя кредов (Go vkCallsFailure и родственные
// типы ошибок vk_auth.go приведены к одному enum WdttError).
//
// Отклонения от Go:
//  - tls-client (профиль Chrome_146, cookie jar) → reqwest::blocking без
//    cookie-хранилища (фича `cookies` не включена в Cargo.toml);
//  - context.Context → Arc<AtomicBool> (cancel): проверяется между шагами,
//    in-flight HTTP-запросы прервать нельзя.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use serde_json::Value;

use super::captcha::{header_set, parse_vk_captcha_error, query_escape, VkCaptchaError};
use super::profiles::Profile;
use crate::logging::log_add;

const VK_CONNECT_CLIENT_ID: &str = "8093730";
const VK_CALLS_API_HOST: &str = "api.vk.me";
const VK_CALLS_ANON_API_VERSION: &str = "5.276";

pub(crate) fn vk_calls_profile() -> Profile {
    Profile {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36".to_string(),
        sec_ch_ua: "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"".to_string(),
        sec_ch_ua_mobile: "?0".to_string(),
        sec_ch_ua_platform: "\"Windows\"".to_string(),
    }
}

// ═══════════════════════════════════════════════════
// Общая ошибка слоя кредов
// (Go: vkCallsFailure + vkCallsVKAPIError + vkCallsOKAPIError +
//  CallUnavailableError + VkCaptchaError в одном enum)
// ═══════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VKCallsFailureKind {
    Skipped,
    Setup,
    Network,
    Decode,
    VKApi,
    Captcha,
    Call,
    OKCDN,
    Parse,
}

impl VKCallsFailureKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            VKCallsFailureKind::Skipped => "skipped",
            VKCallsFailureKind::Setup => "setup",
            VKCallsFailureKind::Network => "network",
            VKCallsFailureKind::Decode => "decode",
            VKCallsFailureKind::VKApi => "vk_api",
            VKCallsFailureKind::Captcha => "captcha",
            VKCallsFailureKind::Call => "call_unavailable",
            VKCallsFailureKind::OKCDN => "okcdn_api",
            VKCallsFailureKind::Parse => "parse",
        }
    }
}

#[derive(Debug, Clone)]
pub enum WdttError {
    /// Go CallUnavailableError.
    CallUnavailable { code: i32, message: String },
    /// Go *VkCaptchaError.
    Captcha(VkCaptchaError),
    /// Go vkCallsVKAPIError.
    VKApi { code: i32, message: String },
    /// Go vkCallsOKAPIError.
    OKApi { code: i32, message: String },
    /// Go vkCallsFailure (шаг + вид + причина).
    Failure { step: String, kind: VKCallsFailureKind, source: Box<WdttError> },
    /// Остальные ошибки (Go fmt.Errorf).
    Msg(String),
}

impl std::fmt::Display for WdttError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WdttError::CallUnavailable { code, message } => {
                // 951/954 — звонок неактивен: ссылка устарела или звонок
                // завершён. Подсказка прямо в тексте, чтобы в логе было
                // видно, ЧТО делать (а не только «call unavailable»).
                let hint = if *code == 951 || *code == 954 {
                    " — VK не принял звонок: ссылка устарела или звонок завершён, нужен свежий хеш активного VK-звонка"
                } else {
                    ""
                };
                if !message.is_empty() {
                    write!(f, "VK returns error: {} (error_code={}){}", message, code, hint)
                } else {
                    write!(f, "VK call is unavailable (error_code={}){}", code, hint)
                }
            }
            WdttError::Captcha(e) => write!(f, "{}", e.display()),
            WdttError::VKApi { code, message } => {
                if message.is_empty() {
                    write!(f, "error_code={}", code)
                } else {
                    write!(f, "error_code={} {}", code, message)
                }
            }
            WdttError::OKApi { code, message } => {
                if message.is_empty() {
                    write!(f, "error_code={}", code)
                } else {
                    write!(f, "error_code={} {}", code, message)
                }
            }
            WdttError::Failure { step, kind, source } => {
                write!(f, "step={} kind={}: {}", step, kind.as_str(), source)
            }
            WdttError::Msg(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for WdttError {}

// Конверсия в String: workers.rs вызывает vk::get_creds(...) через `?` в
// Result<(), String> (Go-порт теряет типизацию ошибки на границе группы).
impl From<WdttError> for String {
    fn from(e: WdttError) -> String {
        e.to_string()
    }
}

// Go newVKCallsFailure (nil err → "unknown error" в Go; в Rust источник всегда есть).
pub(crate) fn new_vkcalls_failure(step: &str, kind: VKCallsFailureKind, err: WdttError) -> WdttError {
    WdttError::Failure { step: step.to_string(), kind, source: Box::new(err) }
}

// Go describeVKCallsFailure.
pub(crate) fn describe_vkcalls_failure(err: &WdttError) -> String {
    err.to_string()
}

// Go asCallUnavailableError: errors.As разворачивает vkCallsFailure.
pub(crate) fn as_call_unavailable(err: &WdttError) -> Option<WdttError> {
    match err {
        WdttError::CallUnavailable { .. } => Some(err.clone()),
        WdttError::Failure { source, .. } => as_call_unavailable(source),
        _ => None,
    }
}

// Go vkCallsAPIErrorKind.
pub(crate) fn vk_calls_api_error_kind(err: &WdttError) -> VKCallsFailureKind {
    match err {
        WdttError::CallUnavailable { .. } => VKCallsFailureKind::Call,
        WdttError::Failure { source, .. } => vk_calls_api_error_kind(source),
        WdttError::Captcha(_) => VKCallsFailureKind::Captcha,
        _ => VKCallsFailureKind::VKApi,
    }
}

// ═══════════════════════════════════════════════════
// Извлечение значений из ответов (Go extractVKCallsStr / extractVKCallsFloat)
// ═══════════════════════════════════════════════════

// Имя типа в формулировках Go (%T) — для одинаковых текстов диагностик.
fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "<nil>",
        Value::Bool(_) => "bool",
        Value::Number(_) => "float64",
        Value::String(_) => "string",
        Value::Array(_) => "[]interface {}",
        Value::Object(_) => "map[string]interface {}",
    }
}

pub(crate) fn extract_vkcalls_str(resp: &Value, keys: &[&str]) -> Result<String, String> {
    let mut cur = resp;
    for k in keys {
        match cur.get(k) {
            Some(v) => cur = v,
            None => {
                return Err(format!("expected map at key {:?}, got {}", k, json_type_name(cur)))
            }
        }
    }
    cur.as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("expected string at end of path, got {}", json_type_name(cur)))
}

pub(crate) fn extract_vkcalls_float(resp: &Value, keys: &[&str]) -> Result<f64, String> {
    let mut cur = resp;
    for k in keys {
        match cur.get(k) {
            Some(v) => cur = v,
            None => {
                return Err(format!("expected map at key {:?}, got {}", k, json_type_name(cur)))
            }
        }
    }
    cur.as_f64()
        .ok_or_else(|| format!("expected float64 at end of path, got {}", json_type_name(cur)))
}

pub(crate) fn parse_vkcalls_turn_addresses(resp: &Value) -> Vec<String> {
    let Some(turn_server) = resp.get("turn_server").and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let Some(urls) = turn_server.get("urls").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut addrs: Vec<String> = Vec::new();
    for (i, u) in urls.iter().enumerate() {
        let Some(s) = u.as_str() else {
            log_add(
                "wdtt",
                &format!("[VKCalls] turn_server.urls[{}]=<non-string>, skipping", i),
            );
            continue;
        };
        let clean = s.split('?').next().unwrap_or(s);
        let mut addr = clean.to_string();
        for p in ["turns:", "turn:", "stuns:", "stun:"] {
            // stun: тоже приходит в urls — без среза префикса уезжал
            // «stun:host:port» и dial фейлился
            if addr.to_lowercase().starts_with(p) {
                addr = addr[p.len()..].to_string();
                break;
            }
        }
        log_add("wdtt", &format!("[VKCalls] turn_server.urls[{}]={}", i, addr));
        addrs.push(addr);
    }
    addrs
}

// ═══════════════════════════════════════════════════
// Разбор ошибок API (Go vkCallsAPIError / vkCallsOKError)
// ═══════════════════════════════════════════════════

pub(crate) fn vk_calls_api_error(resp: &Value) -> Option<WdttError> {
    let err_obj = resp.get("error").and_then(|v| v.as_object())?;
    // error_code может прийти и строкой: раньше он тихо превращался в 0,
    // и объект ошибки с пустым msg молча игнорировался
    let code = super::vk::vk_error_code(err_obj.get("error_code").unwrap_or(&Value::Null));
    let msg = err_obj.get("error_msg").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if code == 0 && msg.is_empty() {
        return None;
    }
    if let Some(call_err) = super::vk::fatal_call_error(resp) {
        return Some(call_err);
    }
    if code == 14 {
        if let Ok(err_json) = serde_json::to_string(err_obj) {
            log_add(
                "wdtt",
                &format!("[VKCalls] captcha error response: {}", truncate_vkcalls_log(&err_json, 300)),
            );
        }
        return Some(WdttError::Captcha(parse_vk_captcha_error(&Value::Object(err_obj.clone()))));
    }
    Some(WdttError::VKApi { code, message: msg })
}

pub(crate) fn vk_calls_ok_error(resp: &Value) -> Option<WdttError> {
    let code = resp.get("error_code").and_then(|v| v.as_f64())?;
    if code == 0.0 {
        return None;
    }
    let msg = resp.get("error_msg").and_then(|v| v.as_str()).unwrap_or("").to_string();
    Some(WdttError::OKApi { code: code as i32, message: msg })
}

pub(crate) fn truncate_vkcalls_log(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    // Go режет по байтам; здесь не рвём UTF-8-символ
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

// describe_vkcalls_resp — для диагностики парсинга: ТОЛЬКО имена полей ответа.
// truncate_vkcalls_resp отдавал первые 300 символов JSON, где лежат
// anonym_token/secret/session_key — секреты оседали в логе при каждой
// ошибке парсинга (а ошибки парсинга как раз случаются на неожиданных телах).
pub(crate) fn describe_vkcalls_resp(resp: &Value) -> String {
    fn keys_of(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, val) in m {
                    out.push(k.clone());
                    keys_of(val, out);
                }
            }
            Value::Array(a) => {
                for val in a {
                    keys_of(val, out);
                }
            }
            _ => {}
        }
    }
    let mut ks = Vec::new();
    keys_of(resp, &mut ks);
    ks.sort();
    ks.dedup();
    if ks.is_empty() {
        "<no fields>".to_string()
    } else {
        format!("fields: {}", ks.join(","))
    }
}

// ═══════════════════════════════════════════════════
// Основной путь VK Calls (Go getVKCredsViaVKCallsPath)
// ═══════════════════════════════════════════════════

// VK переехал на vk.ru: рабочее ядро CSQTT создаёт звонки с join-ссылками
// https://vk.ru/call/join/…, а vk.com-формат VK API отвергает («Invalid join
// link», 954). Перебираем форматы: vk.ru → vk.com (на случай отката VK).
const VK_CALL_LINK_BASES: [&str; 2] = ["https://vk.ru/call/join/", "https://vk.com/call/join/"];

pub(crate) fn get_vk_creds_via_vkcalls_path(
    cancel: &Arc<AtomicBool>,
    link: &str,
    stream_id: i32,
) -> Result<(String, String, Vec<String>), WdttError> {
    let mut last: Option<WdttError> = None;
    for base in VK_CALL_LINK_BASES {
        match get_vk_creds_via_vkcalls_path_base(cancel, link, stream_id, base) {
            Ok(v) => return Ok(v),
            Err(e) => {
                // «Invalid join link» = формат ссылки не принят — пробуем следующий
                if e.to_string().contains("Invalid join link") {
                    log_add(
                        "wdtt",
                        &format!("[VKCalls] {base} отвергнут (Invalid join link) — пробую следующий формат ссылки"),
                    );
                    last = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| WdttError::Msg("VK Calls: все форматы join-ссылки отклонены".into())))
}

fn get_vk_creds_via_vkcalls_path_base(
    cancel: &Arc<AtomicBool>,
    link: &str,
    stream_id: i32,
    link_base: &str,
) -> Result<(String, String, Vec<String>), WdttError> {
    if std::env::var("VK_SKIP_VKCALLS").map(|v| v == "1").unwrap_or(false) {
        return Err(new_vkcalls_failure(
            "preflight",
            VKCallsFailureKind::Skipped,
            WdttError::Msg("disabled by VK_SKIP_VKCALLS=1".to_string()),
        ));
    }

    let device_id = uuid::Uuid::new_v4().to_string();
    let name = super::namegen::generate_name();
    let profile = vk_calls_profile();
    let link_url = query_escape(&format!("{}{}", link_base, link));
    let name_enc = query_escape(&name);

    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| {
            new_vkcalls_failure(
                "setup",
                VKCallsFailureKind::Setup,
                WdttError::Msg(format!("create tls client: {}", e)),
            )
        })?;

    log_add(
        "wdtt",
        &format!(
            "[STREAM {}] [VKCalls] Identity - Name: {} | device_id={} | TLS=Chrome_146 | UA: {}",
            stream_id, name, device_id, profile.user_agent
        ),
    );

    let do_request = |step: &str, url: &str| -> Result<Value, WdttError> {
        // Go: ctx в NewRequestWithContext прерывал in-flight запрос; здесь —
        // проверка перед запросом (in-flight в reqwest::blocking не отменить)
        if cancel.load(Ordering::Relaxed) {
            return Err(WdttError::Msg("context canceled".to_string()));
        }
        let mut headers = HeaderMap::new();
        header_set(&mut headers, "User-Agent", &profile.user_agent);
        header_set(&mut headers, "Accept", "*/*");
        // Accept-Encoding вручную НЕ ставим: при ручном «br, zstd» сервер мог
        // ответить несжатым-для-нас телом (json.Unmarshal падал на мусоре) —
        // транспорт добавит заголовок сам и прозрачно распакует
        header_set(&mut headers, "Accept-Language", "en-GB,en;q=0.9");

        let http_resp = client
            .post(url)
            .headers(headers)
            .body("")
            .send()
            .map_err(|e| {
                new_vkcalls_failure(
                    step,
                    VKCallsFailureKind::Network,
                    WdttError::Msg(format!("request failed: {}", e)),
                )
            })?;

        let status = http_resp.status();
        if status != reqwest::StatusCode::OK {
            // 403/429 от антибот-эджа раньше проваливались в unmarshal как
            // «<!DOCTYPE…» и уходили в легаси-фолбэк с невнятной диагностикой
            let bytes = http_resp.bytes().unwrap_or_default();
            let head = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]);
            return Err(new_vkcalls_failure(
                step,
                VKCallsFailureKind::Network,
                WdttError::Msg(format!(
                    "http {}: {}",
                    status.as_u16(),
                    truncate_vkcalls_log(head.trim(), 200)
                )),
            ));
        }

        // 200 тоже ограничиваем (Go io.LimitReader 1MB): лимит ДО чтения —
        // раньше тело скачивалось ЦЕЛИКОМ и лишь потом обрезалось, враждебный
        // сервер раздувал память (клиентский таймаут не исключал это)
        let mut limited = http_resp.take(1 << 20);
        let mut buf = Vec::new();
        limited.read_to_end(&mut buf).map_err(|e| {
            new_vkcalls_failure(
                step,
                VKCallsFailureKind::Network,
                WdttError::Msg(format!("read response: {}", e)),
            )
        })?;
        let resp: Value = serde_json::from_slice(&buf).map_err(|e| {
            new_vkcalls_failure(
                step,
                VKCallsFailureKind::Decode,
                WdttError::Msg(format!(
                    "unmarshal JSON: {}, body: {}",
                    e,
                    truncate_vkcalls_log(&String::from_utf8_lossy(&buf), 200)
                )),
            )
        })?;
        Ok(resp)
    };

    let step1 = "step1 auth.getAnonymToken";
    let step1_url = format!(
        "https://{}/method/auth.getAnonymToken?v={}&client_id={}&link={}&device_id={}&anonymName={}&lang=en",
        VK_CALLS_API_HOST, VK_CALLS_ANON_API_VERSION, VK_CONNECT_CLIENT_ID,
        link_url, device_id, name_enc,
    );
    let resp1 = do_request(step1, &step1_url)?;
    // VK-ошибка (рейт-лимит, невалидный link) приходит в теле 200 OK:
    // без проверки диагностика была бы «parse token: expected map…»
    if let Some(api_err) = vk_calls_api_error(&resp1) {
        return Err(new_vkcalls_failure(step1, vk_calls_api_error_kind(&api_err), api_err));
    }
    let anonym_token = extract_vkcalls_str(&resp1, &["response", "token"]).map_err(|e| {
        new_vkcalls_failure(
            step1,
            VKCallsFailureKind::Parse,
            WdttError::Msg(format!("parse token: {} (resp: {})", e, describe_vkcalls_resp(&resp1))),
        )
    })?;
    let anonym_token_enc = query_escape(&anonym_token);
    log_add(
        "wdtt",
        &format!("[STREAM {}] [VKCalls] step1 OK, anonymous_token ({} chars)", stream_id, anonym_token.len()),
    );

    let step2 = "step2 messages.getCallPreview";
    let step2_url = format!(
        "https://{}/method/messages.getCallPreview?v={}&anonymous_token={}&device_id={}&extended=1&fields=first_name,last_name,photo_200&lang=en&link={}",
        VK_CALLS_API_HOST, VK_CALLS_ANON_API_VERSION, anonym_token_enc, device_id, link_url,
    );
    let resp2 = do_request(step2, &step2_url)?;
    if let Some(api_err) = vk_calls_api_error(&resp2) {
        match &api_err {
            WdttError::Captcha(captcha_err) => {
                log_add(
                    "wdtt",
                    &format!(
                        "[STREAM {}] [VKCalls] step2 captcha gate appeared (sid={:?}, redirect_uri={})",
                        stream_id,
                        captcha_err.captcha_sid,
                        !captcha_err.redirect_uri.is_empty()
                    ),
                );
            }
            WdttError::CallUnavailable { .. } => {
                log_add(
                    "wdtt",
                    &format!("[STREAM {}] [VKCalls] step2 non-retryable call error: {}", stream_id, api_err),
                );
            }
            _ => {}
        }
        return Err(new_vkcalls_failure(step2, vk_calls_api_error_kind(&api_err), api_err));
    }
    let user_id_float = extract_vkcalls_float(&resp2, &["response", "user_id"]).map_err(|e| {
        new_vkcalls_failure(
            step2,
            VKCallsFailureKind::Parse,
            WdttError::Msg(format!("parse user_id: {} (resp: {})", e, describe_vkcalls_resp(&resp2))),
        )
    })?;
    let user_id_str = format!("{:.0}", user_id_float);
    let secret = extract_vkcalls_str(&resp2, &["response", "secret"]).map_err(|e| {
        new_vkcalls_failure(
            step2,
            VKCallsFailureKind::Parse,
            WdttError::Msg(format!("parse secret: {}", e)),
        )
    })?;
    log_add(
        "wdtt",
        &format!("[STREAM {}] [VKCalls] step2 OK, user_id={}, secret ({} chars)", stream_id, user_id_str, secret.len()),
    );

    let step3 = "step3 messages.getAnonymCallToken";
    let step3_url = format!(
        "https://{}/method/messages.getAnonymCallToken?v={}&anonymous_token={}&device_id={}&link={}&name={}&user_id={}&secret={}&lang=en",
        VK_CALLS_API_HOST, VK_CALLS_ANON_API_VERSION, anonym_token_enc, device_id, link_url,
        name_enc, user_id_str, query_escape(&secret),
    );
    let resp3 = do_request(step3, &step3_url)?;
    if let Some(api_err) = vk_calls_api_error(&resp3) {
        match &api_err {
            WdttError::Captcha(captcha_err) => {
                log_add(
                    "wdtt",
                    &format!(
                        "[STREAM {}] [VKCalls] step3 captcha gate appeared (sid={:?}, redirect_uri={})",
                        stream_id,
                        captcha_err.captcha_sid,
                        !captcha_err.redirect_uri.is_empty()
                    ),
                );
            }
            WdttError::CallUnavailable { .. } => {
                log_add(
                    "wdtt",
                    &format!("[STREAM {}] [VKCalls] step3 non-retryable call error: {}", stream_id, api_err),
                );
            }
            _ => {}
        }
        return Err(new_vkcalls_failure(step3, vk_calls_api_error_kind(&api_err), api_err));
    }
    let ok_anonym_token = extract_vkcalls_str(&resp3, &["response", "token"]).map_err(|e| {
        new_vkcalls_failure(
            step3,
            VKCallsFailureKind::Parse,
            WdttError::Msg(format!("parse token: {} (resp: {})", e, describe_vkcalls_resp(&resp3))),
        )
    })?;
    log_add(
        "wdtt",
        &format!("[STREAM {}] [VKCalls] step3 OK, OK anonymToken ({} chars)", stream_id, ok_anonym_token.len()),
    );

    let ok_device_id = uuid::Uuid::new_v4().to_string();
    let step4 = "step4 auth.anonymLogin";
    let step4_url = format!(
        "https://calls.okcdn.ru/fb.do?session_data={}&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA",
        query_escape(&format!(
            "{{\"version\":2,\"device_id\":\"{}\",\"client_version\":\"1.0.1\"}}",
            ok_device_id
        )),
    );
    let resp4 = do_request(step4, &step4_url)?;
    let session_key = extract_vkcalls_str(&resp4, &["session_key"]).map_err(|e| {
        new_vkcalls_failure(
            step4,
            VKCallsFailureKind::Parse,
            WdttError::Msg(format!("parse session_key: {} (resp: {})", e, describe_vkcalls_resp(&resp4))),
        )
    })?;
    log_add(
        "wdtt",
        &format!("[STREAM {}] [VKCalls] step4 OK, OK session_key ({} chars)", stream_id, session_key.len()),
    );

    let step5 = "step5 vchat.joinConversationByLink";
    let step5_url = format!(
        "https://calls.okcdn.ru/fb.do?joinLink={}&isVideo=false&protocolVersion=5&anonymToken={}&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key={}",
        query_escape(link),
        query_escape(&ok_anonym_token),
        query_escape(&session_key),
    );
    let resp5 = do_request(step5, &step5_url)?;
    if let Some(ok_err) = vk_calls_ok_error(&resp5) {
        return Err(new_vkcalls_failure(
            step5,
            VKCallsFailureKind::OKCDN,
            WdttError::Msg(format!("{} (resp: {})", ok_err, describe_vkcalls_resp(&resp5))),
        ));
    }

    let user = extract_vkcalls_str(&resp5, &["turn_server", "username"]).map_err(|e| {
        new_vkcalls_failure(
            step5,
            VKCallsFailureKind::Parse,
            WdttError::Msg(format!("parse username: {} (resp: {})", e, describe_vkcalls_resp(&resp5))),
        )
    })?;
    let pass = extract_vkcalls_str(&resp5, &["turn_server", "credential"]).map_err(|e| {
        new_vkcalls_failure(
            step5,
            VKCallsFailureKind::Parse,
            WdttError::Msg(format!("parse credential: {}", e)),
        )
    })?;
    let addrs = parse_vkcalls_turn_addresses(&resp5);
    if addrs.is_empty() {
        return Err(new_vkcalls_failure(
            step5,
            VKCallsFailureKind::Parse,
            WdttError::Msg("turn_server.urls empty".to_string()),
        ));
    }

    log_add("wdtt", &format!("[STREAM {}] [VKCalls] SUCCESS, TURN urls={}", stream_id, addrs.len()));
    Ok((user, pass, addrs))
}

// Go cloneStringSlice — в Rust Vec<String>.clone() делает то же самое; отдельная
// функция не нужна.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_truncate_log() {
        assert_eq!(truncate_vkcalls_log("abc", 5), "abc");
        assert_eq!(truncate_vkcalls_log("abcdef", 3), "abc...");
        // не рвём многобайтовый символ
        let s = "привет";
        let t = truncate_vkcalls_log(s, 4);
        assert!(t.ends_with("..."));
        assert!(t.trim_end_matches('.').chars().count() <= 4);
    }

    #[test]
    fn test_extract_str() {
        let resp = json!({"response": {"token": "abc"}});
        assert_eq!(extract_vkcalls_str(&resp, &["response", "token"]).unwrap(), "abc");
        assert!(extract_vkcalls_str(&resp, &["response", "missing"]).is_err());
        assert!(extract_vkcalls_str(&resp, &["nope"]).is_err());
        let num = json!({"session_key": 42});
        assert!(extract_vkcalls_str(&num, &["session_key"]).is_err());
    }

    #[test]
    fn test_extract_float() {
        let resp = json!({"response": {"user_id": 123.0}});
        assert_eq!(extract_vkcalls_float(&resp, &["response", "user_id"]).unwrap(), 123.0);
        let s = json!({"response": {"user_id": "123"}});
        assert!(extract_vkcalls_float(&s, &["response", "user_id"]).is_err());
    }

    #[test]
    fn test_parse_turn_addresses() {
        let resp = json!({
            "turn_server": {
                "urls": [
                    "turn:turn-1.vk.com:3478?transport=udp",
                    "turns:turn-2.vk.com:5349",
                    "stun:stun.vk.com:3478",
                    42
                ]
            }
        });
        let addrs = parse_vkcalls_turn_addresses(&resp);
        assert_eq!(addrs, vec!["turn-1.vk.com:3478", "turn-2.vk.com:5349", "stun.vk.com:3478"]);
        assert!(parse_vkcalls_turn_addresses(&json!({})).is_empty());
    }

    #[test]
    fn test_ok_error() {
        assert!(vk_calls_ok_error(&json!({"turn_server": {}})).is_none());
        assert!(vk_calls_ok_error(&json!({"error_code": 0})).is_none());
        match vk_calls_ok_error(&json!({"error_code": 500, "error_msg": "internal"})) {
            Some(WdttError::OKApi { code, message }) => {
                assert_eq!(code, 500);
                assert_eq!(message, "internal");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_api_error_kind_and_unwrap() {
        let call_err = WdttError::CallUnavailable { code: 951, message: "no".into() };
        let wrapped = new_vkcalls_failure("step2 x", VKCallsFailureKind::Setup, call_err.clone());
        assert!(matches!(as_call_unavailable(&wrapped), Some(WdttError::CallUnavailable { .. })));
        assert!(matches!(vk_calls_api_error_kind(&wrapped), VKCallsFailureKind::Call));
        // 951/954 получают подсказку про устаревший звонок (Display в WdttError)
        assert_eq!(
            wrapped.to_string(),
            "step=step2 x kind=setup: VK returns error: no (error_code=951) — VK не принял звонок: ссылка устарела или звонок завершён, нужен свежий хеш активного VK-звонка"
        );
    }

    #[test]
    fn test_failure_display_no_message() {
        let e = WdttError::VKApi { code: 29, message: String::new() };
        assert_eq!(e.to_string(), "error_code=29");
    }
}
