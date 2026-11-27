// Subscription fetching - port of Go subfetch.go (fetch_url_content flow).
//
// TLS fingerprints: the Go version uses bogdanfinn/tls-client with OkHttp-Android
// profiles. The Rust stack here is reqwest+rustls (no JA3 impersonation): the
// wreq/BoringSSL route needs cmake/clang, which are absent on this machine.
// For raw-text subscription hosts this makes no difference; revisit if a panel
// starts blocking by fingerprint.
//
// Заголовки — ровно как у настоящего Happ-клиента: gzip-only, Accept: */*,
// без Connection (на HTTP/2 его не существует), X-HWID (только на хост
// исходного URL), X-Device-Os + X-OS-Version.
use std::cell::RefCell;
use std::collections::HashSet;
use std::io::Read;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use regex::Regex;

use crate::logging::log_add;
use crate::vpnlinks::b64_decode;

pub const DEFAULT_UA: &str = "Happ/4.8.0/Android/17771400994551771562";
const LAST_RESORT_UA: &str = "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36";
const DEFAULT_OS: &str = "Android 14";
const BODY_LIMIT: usize = 8 << 20; // 8 МБ
const MAX_HTML: usize = 100000;

// SubFetchInfo — метаданные подписки из HTTP-заголовков панели:
// profile-title (название профиля), subscription-userinfo (трафик/срок),
// announce (объявление), profile-web-page-url (сайт) и support-url (поддержка).
#[derive(Debug, Default, Clone)]
pub struct SubFetchInfo {
    pub profile_title: String,
    pub userinfo: String,
    pub announce: String,
    pub announce_url: String,
    pub web_page_url: String,
    pub support_url: String,
}

impl SubFetchInfo {
    // Каждое поле заполняется первым непустым значением (в цепочке редиректов
    // заголовки не должны затираться пустыми промежуточными ответами).
    fn take(cur: &mut String, h: &reqwest::header::HeaderMap, key: &str) {
        if cur.is_empty() {
            if let Some(v) = h.get(key).and_then(|x| x.to_str().ok()) {
                *cur = v.trim().to_string();
            }
        }
    }

    pub fn set_from(&mut self, h: &reqwest::header::HeaderMap) {
        Self::take(&mut self.profile_title, h, "Profile-Title");
        Self::take(&mut self.userinfo, h, "Subscription-Userinfo");
        Self::take(&mut self.announce, h, "Announce");
        Self::take(&mut self.announce_url, h, "Announce-Url");
        Self::take(&mut self.web_page_url, h, "Profile-Web-Page-Url");
        Self::take(&mut self.support_url, h, "Support-Url");
    }
}

fn client() -> &'static reqwest::blocking::Client {
    static CLI: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLI.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            // S1: авто-редиректы отключены — reqwest повторял запрос со ВСЕМИ
            // заголовками на кросс-хост 30x, и X-HWID/X-Device-Os утекали
            // стороннему домену. Редиректы следуем вручную (см. sub_fetch_get).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client")
    })
}

// sanitize_net_err — S2: Display ошибки reqwest содержит полный URL запроса
// (с ?token=...&hwid=...), который оседал в логах и UI. Режем query/fragment.
fn sanitize_net_err(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"https?://[^\s"')]+"#).unwrap());
    re.replace_all(s, |c: &regex::Captures| {
        let u = c.get(0).map(|m| m.as_str()).unwrap_or_default();
        match url::Url::parse(u) {
            Ok(mut parsed) => {
                parsed.set_query(None);
                parsed.set_fragment(None);
                parsed.to_string()
            }
            Err(_) => u.to_string(),
        }
    })
    .to_string()
}

// subFetchGet — один GET с заголовками OkHttp-клиента, gzip распаковываем сами.
// deadline — общий бюджет загрузки подписки: проверяется перед КАЖДЫМ хопом
// (раньше 10 хопов × 30 с могли длиться до 300 с, игнорируя бюджет уровня выше).
pub fn sub_fetch_get(
    try_url: &str,
    ua: &str,
    hwid: &str,
    os_name: &str,
    orig_host: &str,
    info: Option<&RefCell<SubFetchInfo>>,
    deadline: Instant,
) -> Result<String, String> {
    // S1: редиректы 30x следуем вручную и пересобираем заголовки на КАЖДЫЙ
    // хоп: X-HWID уходит только на хост исходного URL (meta/js-редиректы
    // обрабатываются уровнем выше и здесь не видны).
    let mut current = try_url.trim().to_string();
    let mut resp = None;
    for _hop in 0..10 {
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            return Err("истёк общий бюджет времени загрузки подписки".into());
        }
        let cli = client();
        let mut req = cli
            .request(reqwest::Method::GET, &current)
            .header("User-Agent", ua)
            .header("Accept", "*/*")
            .header("Accept-Encoding", "gzip");
        // остаток бюджета меньше дефолтного таймаута клиента — режем таймаут
        // запроса, чтобы один хоп не вылезал за бюджет
        if rem < Duration::from_secs(30) {
            req = req.timeout(rem);
        }
        let send_hwid = !hwid.is_empty()
            && (orig_host.is_empty()
                || url::Url::parse(&current)
                    .ok()
                    .map(|u| {
                        u.host_str()
                            .map(|h| h.eq_ignore_ascii_case(orig_host))
                            .unwrap_or(false)
                    })
                    .unwrap_or(false));
        if send_hwid {
            req = req.header("X-HWID", hwid);
        }
        if !os_name.is_empty() {
            req = req.header("X-Device-Os", os_name);
            req = req.header("X-OS-Version", os_name);
        }
        let r = req.send().map_err(|e| sanitize_net_err(&e.to_string()))?;
        let status = r.status().as_u16();
        if (300..400).contains(&status) {
            let loc = r
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().to_string())
                .unwrap_or_default();
            let next = absolutize_redirect(&loc, &current);
            if !next.is_empty() && next != current {
                // Редирект на клиентскую схему: HTTP-клиент по happ:// не ходит —
                // отдаём ссылку наружу специальной ошибкой, верхний уровень
                // развернёт её через vpn_resolve_link (как входную клиентскую).
                if is_client_link(&next) {
                    return Err(format!("CLIENT_LINK:{}", next));
                }
                if scheme_downgrade(&current, &next) {
                    return Err("редирект https→http заблокирован: токен подписки ушёл бы открытым текстом".into());
                }
                current = next;
                continue;
            }
            // 30x без Location / зацикленный — отдаём как есть (ошибка ниже)
        }
        resp = Some(r);
        break;
    }
    let resp = resp.ok_or_else(|| "нет ответа".to_string())?;
    if resp.status().as_u16() >= 400 {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    if let Some(cell) = info {
        cell.borrow_mut().set_from(resp.headers());
    }
    // лимит с запасом в 1 байт: переполнение — явная ошибка, а не тихая обрезка
    let mut body: Vec<u8> = Vec::new();
    resp.take(BODY_LIMIT as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|e| e.to_string())?;
    if body.len() > BODY_LIMIT {
        return Err("тело подписки больше 8 МБ — загрузка прервана".into());
    }
    if body.len() > 2 && body[0] == 0x1f && body[1] == 0x8b {
        // gzip заявлен, но бит — раньше бинарный мусор уходил дальше как
        // «тело подписки» и ломало парсинг с невнятной ошибкой
        let mut plain: Vec<u8> = Vec::new();
        let dec = flate2::read::GzDecoder::new(&body[..]);
        dec.take(BODY_LIMIT as u64 + 1)
            .read_to_end(&mut plain)
            .map_err(|e| format!("gzip: {}", e))?;
        if plain.len() > BODY_LIMIT {
            return Err("распакованное тело подписки больше 8 МБ — загрузка прервана".into());
        }
        body = plain;
    }
    Ok(String::from_utf8_lossy(&body).to_string())
}

// ---------- regex helpers ----------

fn re_meta_refresh() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Захват до кавычки; «;»-рез делается В КОДЕ после декода сущностей.
        // Резать по «;» в regex (как раньше) было нельзя: «;» внутри «&amp;»
        // обрезала сам URL («x=1&amp;b=2» → «x=1&amp»)
        Regex::new(r#"(?i)<meta\s+http-equiv=["']?refresh["']?[^>]*content=["']([^"']*url=([^"']+))"#).unwrap()
    })
}

fn re_js_redirects() -> &'static Vec<Regex> {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        vec![
            Regex::new(r#"(?i)window\.location\.href\s*=\s*['"]([^'"]+)['"]"#).unwrap(),
            Regex::new(r#"(?i)location\.href\s*=\s*['"]([^'"]+)['"]"#).unwrap(),
            Regex::new(r#"(?i)window\.location\.replace\(['"]([^'"]+)['"]"#).unwrap(),
            Regex::new(r#"(?i)window\.location\s*=\s*['"]([^'"]+)['"]"#).unwrap(),
            Regex::new(r#"(?i)location\s*=\s*['"]([^'"]+)['"]"#).unwrap(),
        ]
    })
}

fn re_data_redirect() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?i)data-redirect=["']([^"']+)["']"#).unwrap())
}

fn re_first_link() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?i)<a\s+[^>]*href=["']([^"']+)["']"#).unwrap())
}

fn re_const_raw() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?s)(?:const|var|let)\s+RAW\s*=\s*["']([^"']+)["']"#).unwrap())
}

fn re_data_block() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:const|var|let)\s+DATA\s*=\s*").unwrap())
}

// extractRedirectFromHTML — meta refresh / window.location / data-redirect / первая ссылка
pub fn extract_redirect_from_html(page: &str) -> String {
    // URL из HTML может содержать сущности («&amp;» в query) — декодируем
    let get = |s: &str| html_escape::decode_html_entities(s).trim().to_string();
    if let Some(m) = re_meta_refresh().captures(page) {
        if let Some(g) = m.get(2) {
            // Сначала декод HTML-сущностей, ПОТОМ «;»-рез: content="0;url=/a;jwt=x"
            // → путь режется по «;» как раньше, а «;» внутри «&amp;» больше не
            // встречается (уже декодирована) и URL не рвёт
            let decoded = get(g.as_str());
            return match decoded.find(';') {
                Some(i) => decoded[..i].trim().to_string(),
                None => decoded,
            };
        }
    }
    for re in re_js_redirects() {
        if let Some(m) = re.captures(page) {
            if let Some(g) = m.get(1) {
                return get(g.as_str());
            }
        }
    }
    if let Some(m) = re_data_redirect().captures(page) {
        if let Some(g) = m.get(1) {
            return get(g.as_str());
        }
    }
    if let Some(m) = re_first_link().captures(page) {
        if let Some(g) = m.get(1) {
            let l = get(g.as_str());
            let low2 = l.to_lowercase();
            // первая попавшаяся ссылка может быть якорем/навигацией — это не редирект
            if !low2.starts_with('#')
                && !low2.starts_with("javascript:")
                && !low2.starts_with("mailto:")
                && !low2.starts_with("tel:")
            {
                return l;
            }
        }
    }
    String::new()
}

// extractDataBlock — const DATA = {...} из фронт-страниц подписок: links[] + subUrl
pub fn extract_data_block(html: &str) -> (Vec<String>, String) {
    let Some(loc) = re_data_block().find(html) else {
        return (Vec::new(), String::new());
    };
    let rest = &html[loc.end()..];
    let mut de = serde_json::Deserializer::from_str(rest).into_iter::<serde_json::Value>();
    let Some(Ok(serde_json::Value::Object(obj))) = de.next() else {
        return (Vec::new(), String::new());
    };
    let mut links = Vec::new();
    if let Some(serde_json::Value::Array(arr)) = obj.get("links") {
        for it in arr {
            if let serde_json::Value::String(s) = it {
                let t = s.trim();
                if !t.is_empty() {
                    links.push(t.to_string());
                }
            }
        }
    }
    let sub_url = obj
        .get("subUrl")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    (links, sub_url)
}

// is_client_link(s) — happ:// / incy:// / v2raytun://
pub fn is_client_link(s: &str) -> bool {
    let low = s.trim().to_lowercase();
    low.starts_with("happ://") || low.starts_with("incy://") || low.starts_with("v2raytun://")
}

// scheme_downgrade — переход https→http в цепочке редиректов. Подписочный URL
// почти всегда содержит токен (и к нему добавляется hwid в query): компрометиро-
// ванная панель или MITM могли 302-ом увести запрос на http, и секреты ушли бы
// открытым текстом. Такой переход блокируется.
fn scheme_downgrade(from: &str, to: &str) -> bool {
    let f = from.trim().to_lowercase();
    let t = to.trim().to_lowercase();
    f.starts_with("https://") && t.starts_with("http://")
}

// looks_like_subscription — «похоже на подписку»: есть ссылка(-и), либо тело
// декодируется из base64 в текст со ссылками/переводами строк. Порог len>50
// отбрасывал валидные подписки из одного узла (<50 байт).
fn looks_like_subscription(text: &str) -> bool {
    let t = text.trim();
    if t.is_empty() {
        return false;
    }
    if t.to_lowercase().contains("://") {
        return true;
    }
    if let Ok(dec) = crate::vpnlinks::b64_decode(t) {
        let d = dec.trim();
        if d.contains("://") || d.contains('\n') {
            return true;
        }
    }
    false
}

// looksLikeHTML — HTML-страница по совокупности тегов
pub fn looks_like_html(low: &str) -> bool {
    low.contains("<html")
        || low.contains("<!doctype")
        || low.contains("<meta")
        || low.contains("<body")
}

// absolutizeRedirect — относительный редирект от базового URL (RFC 3986)
pub fn absolutize_redirect(redir: &str, base: &str) -> String {
    let low = redir.to_lowercase();
    if low.starts_with("http://") || low.starts_with("https://") || is_client_link(redir) {
        return redir.to_string();
    }
    url::Url::parse(base)
        .ok()
        .and_then(|b| b.join(redir).ok())
        .map(|u| u.to_string())
        .unwrap_or_else(|| redir.to_string())
}

// resolveDataLinks разворачивает клиентские ссылки и URL из DATA-блока
// HTML-обёртки: иначе такие ссылки молча терялись при парсинге подписки.
// base_url — страница, с которой взят блок: переход https→http блокируется.
pub fn resolve_data_links(
    links: &[String],
    custom_ua: &str,
    custom_hwid: &str,
    custom_os: &str,
    depth: i32,
    deadline: Instant,
    base_url: &str,
) -> Vec<String> {
    let mut out = Vec::with_capacity(links.len());
    for l in links {
        let l = l.trim();
        if l.is_empty() {
            continue;
        }
        let mut l = l.to_string();
        if is_client_link(&l) {
            match crate::happcrypt::vpn_resolve_link(&l, 0) {
                Err(e) => {
                    log_add("decrypt", &format!("клиентская ссылка из DATA не расшифровалась: {}", e));
                    continue;
                }
                Ok((inner_url, body, _)) => {
                    let b = body.trim();
                    if !b.is_empty() {
                        out.push(b.to_string());
                        continue;
                    }
                    let inner = inner_url.trim();
                    if inner.is_empty() {
                        continue;
                    }
                    l = inner.to_string();
                }
            }
        }
        let low = l.to_lowercase();
        if low.starts_with("http://") || low.starts_with("https://") {
            if scheme_downgrade(base_url, &l) {
                log_add("decrypt", "ссылка из DATA https→http заблокирована (токен ушёл бы открытым текстом)");
                continue;
            }
            match sub_fetch_content(&l, custom_ua, custom_hwid, custom_os, depth + 1, Some(deadline)) {
                Err(e) => {
                    log_add("decrypt", &format!("ссылка из DATA не загрузилась: {}", e));
                    continue;
                }
                Ok(b) => {
                    let b = b.trim();
                    if !b.is_empty() {
                        out.push(b.to_string());
                    }
                }
            }
            continue;
        }
        out.push(l);
    }
    out
}

// subFetchContent — полный флоу fetch_url_content из бота.
pub fn sub_fetch_content(
    raw_url: &str,
    custom_ua: &str,
    custom_hwid: &str,
    custom_os: &str,
    depth: i32,
    budget: Option<Instant>,
) -> Result<String, String> {
    sub_fetch_content_info(
        raw_url,
        custom_ua,
        custom_hwid,
        custom_os,
        depth,
        None,
        budget,
    )
}

// subFetchContentInfo — ядро subFetchContent + захват метаданных подписки.
pub fn sub_fetch_content_info(
    raw_url: &str,
    custom_ua: &str,
    custom_hwid: &str,
    custom_os: &str,
    depth: i32,
    info: Option<&RefCell<SubFetchInfo>>,
    budget: Option<Instant>,
) -> Result<String, String> {
    let deadline = budget.unwrap_or_else(|| Instant::now() + Duration::from_secs(90));
    if Instant::now() > deadline {
        return Err("истёк общий бюджет времени загрузки подписки (90 с)".into());
    }
    if depth > 3 {
        return Err("слишком глубокая вложенность редиректов".into());
    }
    // Клиентские схемы могут встретиться не только во входной ссылке,
    // но и в HTML-редиректе: сначала разворачиваем их.
    if is_client_link(raw_url) {
        let (inner_url, body, _) = crate::happcrypt::vpn_resolve_link(raw_url, 0)
            .map_err(|e| format!("клиентская ссылка не расшифровалась: {}", e))?;
        let b = body.trim();
        if !b.is_empty() {
            return Ok(b.to_string());
        }
        let inner = inner_url.trim();
        if inner.is_empty() {
            return Err("клиентская ссылка не содержит подписки".into());
        }
        if inner.eq_ignore_ascii_case(raw_url.trim()) {
            return Err("циклическая клиентская ссылка".into());
        }
        return sub_fetch_content_info(inner, custom_ua, custom_hwid, custom_os, depth + 1, info, Some(deadline));
    }
    // ОС — дефолт как в боте: подписки с обязательной ОС иначе отвечают «Доступ без ОС»
    let os_name = {
        let t = custom_os.trim();
        if t.is_empty() {
            DEFAULT_OS.to_string()
        } else {
            t.to_string()
        }
    };
    let chosen_ua = {
        let t = custom_ua.trim();
        if t.is_empty() {
            DEFAULT_UA.to_string()
        } else {
            t.to_string()
        }
    };
    // ОДИН UA на всю загрузку — настоящий клиент не меняет отпечаток
    let u = url::Url::parse(raw_url).map_err(|e| e.to_string())?;
    let orig_host = u.host_str().unwrap_or("").to_string();
    let mut url_with_hwid = raw_url.to_string();
    let hwid = custom_hwid.trim();
    if !hwid.is_empty() {
        // через Query().Set: раньше hwid= дописывался в хвост строки и уезжал
        // ПОСЛЕ #fragment (сервер его не видел) или удваивал «?». Дублирующийся
        // параметр не добавляем: некоторые панели берут первое вхождение.
        let mut u2 = u.clone();
        if !u2.query_pairs().any(|(k, _)| k == "hwid") {
            u2.query_pairs_mut().append_pair("hwid", hwid);
        }
        url_with_hwid = u2.to_string();
    }

    #[derive(Clone)]
    struct Attempt {
        u: String,
        ua: String,
    }
    let mut attempts = vec![
        Attempt { u: raw_url.to_string(), ua: chosen_ua.clone() },
        Attempt { u: url_with_hwid.clone(), ua: chosen_ua.clone() },
    ];
    let mut tried: HashSet<String> = HashSet::new();
    let mut fallback_used = false;

    let mut content = String::new();
    let mut content_base = raw_url.to_string();
    while content.is_empty() {
        if attempts.is_empty() {
            if !fallback_used && deadline.duration_since(Instant::now()) > Duration::from_secs(1) {
                // Mozilla — отдельный последний заход для «тупых» серверов
                fallback_used = true;
                attempts = vec![
                    Attempt { u: raw_url.to_string(), ua: LAST_RESORT_UA.to_string() },
                    Attempt { u: url_with_hwid.clone(), ua: LAST_RESORT_UA.to_string() },
                ];
            } else {
                break;
            }
        }
        let at = attempts.remove(0);
        let key = format!("{}\u{0}{}", at.u, at.ua);
        if !tried.insert(key) {
            continue;
        }
        if deadline.duration_since(Instant::now()) < Duration::from_secs(1) {
            break;
        }
        // настоящий клиент не стреляет запросами вплотную — микро-пауза
        let pause_ms = 200 + fastrand::u64(0..600);
        std::thread::sleep(Duration::from_millis(pause_ms));
        // Клиентская ссылка, пришедшая через HTML-редирект или DATA-блок:
        // разворачиваем как входную.
        if is_client_link(&at.u) {
            if let Ok((inner, body, _)) = crate::happcrypt::vpn_resolve_link(&at.u, 0) {
                let b = body.trim();
                if !b.is_empty() {
                    content = b.to_string();
                    content_base = at.u.clone();
                    break;
                }
                let inner = inner.trim();
                if !inner.is_empty() {
                    attempts.insert(0, Attempt { u: inner.to_string(), ua: at.ua.clone() });
                }
                continue;
            }
            // не расшифровалась — попробуем как обычный URL (упадёт с понятной ошибкой)
        }
        let text = sub_fetch_get(
            &at.u,
            &at.ua,
            hwid,
            &os_name,
            &orig_host,
            info,
            deadline,
        );
        let text = match text {
            Err(e) => {
                // 30x-редирект на клиентскую схему: разворачиваем как входную
                // (раньше попытка просто терялась — http-клиент по happ:// не ходит)
                if let Some(link) = e.strip_prefix("CLIENT_LINK:") {
                    if let Ok((inner, body, _)) = crate::happcrypt::vpn_resolve_link(link, 0) {
                        let b = body.trim();
                        if !b.is_empty() {
                            content = b.to_string();
                            content_base = link.to_string();
                            break;
                        }
                        let inner = inner.trim();
                        if !inner.is_empty() {
                            attempts.insert(0, Attempt { u: inner.to_string(), ua: at.ua.clone() });
                            continue;
                        }
                        continue;
                    }
                }
                let cut = at.ua.chars().take(20).collect::<String>();
                log_add("decrypt", &format!("загрузка не удалась ({}): {}", cut, e));
                continue;
            }
            Ok(t) => t,
        };
        let text = text.trim().to_string();
        let low = text.to_lowercase();
        // HTML-страница: с редиректом — идём по ссылке с тем же UA;
        // без редиректа — сохраняем как контент, RAW/DATA разберём после цикла.
        if looks_like_html(&low) && text.len() < MAX_HTML {
            let redir = extract_redirect_from_html(&text);
            if !redir.is_empty() {
                let abs = absolutize_redirect(&redir, &at.u);
                if scheme_downgrade(&at.u, &abs) {
                    log_add("decrypt", "HTML-редирект https→http заблокирован (токен ушёл бы открытым текстом)");
                    continue;
                }
                attempts.insert(0, Attempt { u: abs, ua: at.ua.clone() });
                continue;
            }
            content = text;
            content_base = at.u.clone();
            break;
        }
        if text.len() > 50 || looks_like_subscription(&text) {
            content = text;
            content_base = at.u.clone();
        }
    }
    if content.is_empty() {
        return Err("не удалось загрузить подписку ни с одного маршрута".into());
    }

    let low = content.to_lowercase();
    if looks_like_html(&low) {
        // HTML-обёртка: RAW-переменная → DATA → редирект-ссылка
        if let Some(m) = re_const_raw().captures(&content) {
            if let Some(g) = m.get(1) {
                let extracted = g.as_str().trim().to_string();
                let el = extracted.to_lowercase();
                if is_client_link(&extracted) {
                    let (inner_url, body, _) = crate::happcrypt::vpn_resolve_link(&extracted, 0)
                        .map_err(|e| format!("клиентская ссылка из HTML не расшифровалась: {}", e))?;
                    let b = body.trim();
                    if !b.is_empty() {
                        return Ok(b.to_string());
                    }
                    if !inner_url.is_empty() {
                        return sub_fetch_content_info(
                            inner_url.trim(),
                            custom_ua,
                            custom_hwid,
                            custom_os,
                            depth + 1,
                            info,
                            Some(deadline),
                        );
                    }
                    return Err("клиентская ссылка из HTML не содержит подписки".into());
                }
                if el.starts_with("http://") || el.starts_with("https://") {
                    if scheme_downgrade(&content_base, &extracted) {
                        return Err("RAW-редирект https→http заблокирован (токен ушёл бы открытым текстом)".into());
                    }
                    return sub_fetch_content_info(
                        &extracted,
                        custom_ua,
                        custom_hwid,
                        custom_os,
                        depth + 1,
                        info,
                        Some(deadline),
                    );
                }
                return Ok(extracted);
            }
        }
        let (links, sub_url) = extract_data_block(&content);
        if !links.is_empty() {
            let resolved = resolve_data_links(&links, custom_ua, custom_hwid, custom_os, depth, deadline, &content_base);
            if resolved.is_empty() {
                return Err("DATA-блок не содержит распознанных ссылок".into());
            }
            return Ok(resolved.join("\n"));
        } else if !sub_url.is_empty() {
            let abs = absolutize_redirect(&sub_url, &content_base);
            if scheme_downgrade(&content_base, &abs) {
                return Err("DATA subUrl https→http заблокирован (токен ушёл бы открытым текстом)".into());
            }
            return sub_fetch_content_info(
                &abs,
                custom_ua,
                custom_hwid,
                custom_os,
                depth + 1,
                info,
                Some(deadline),
            );
        }
        if content.len() < MAX_HTML {
            let redir = extract_redirect_from_html(&content);
            if !redir.is_empty() {
                return sub_fetch_content_info(
                    &absolutize_redirect(&redir, &content_base),
                    custom_ua,
                    custom_hwid,
                    custom_os,
                    depth + 1,
                    info,
                    Some(deadline),
                );
            }
        }
        return Err("HTML-ответ не содержит подписки (RAW/DATA/редирект не найдены)".into());
    }

    // Тело подписки может само быть клиентской ссылкой — разворачиваем её так же.
    if is_client_link(&content) {
        return sub_fetch_content_info(
            content.trim(),
            custom_ua,
            custom_hwid,
            custom_os,
            depth + 1,
            info,
            Some(deadline),
        );
    }
    // base64-тело: внутри может быть URL подписки — идём по нему
    if !content.contains("://") && content.len() > 50 {
        if let Ok(dec) = b64_decode(content.trim()) {
            let dec = dec.trim().to_string();
            let dl = dec.to_lowercase();
            if dl.starts_with("http://") || dl.starts_with("https://") || is_client_link(&dec) {
                if scheme_downgrade(&content_base, &dec) {
                    return Err("URL из base64-тела https→http заблокирован (токен ушёл бы открытым текстом)".into());
                }
                return sub_fetch_content_info(&dec, custom_ua, custom_hwid, custom_os, depth + 1, info, Some(deadline));
            }
            if !dl.is_empty() && (dec.contains("://") || dec.contains('\n')) {
                return Ok(dec);
            }
        }
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::io::{BufRead, BufReader, Write};

    #[test]
    fn meta_refresh_redirect() {
        let page = r#"<html><head><meta http-equiv="refresh" content="0; url=https://panel.example/get_sub.php?x=1&amp;b=2"></head></html>"#;
        assert_eq!(extract_redirect_from_html(page), "https://panel.example/get_sub.php?x=1&b=2");
    }

    #[test]
    fn js_redirect() {
        let page = "<script>window.location.href='https://x.example/sub';</script>";
        assert_eq!(extract_redirect_from_html(page), "https://x.example/sub");
    }

    #[test]
    fn first_link_skips_anchors() {
        // Go проверяет только ПЕРВУЮ ссылку: javascript-якорь = «редиректа нет»
        let page = r#"<a href="javascript:void(0)">x</a><a href="/real/sub">sub</a>"#;
        assert_eq!(extract_redirect_from_html(page), "");
        let page2 = r#"<a href="/real/sub">sub</a>"#;
        assert_eq!(extract_redirect_from_html(page2), "/real/sub");
    }

    #[test]
    fn absolutize_cases() {
        assert_eq!(
            absolutize_redirect("/get_sub.php", "https://panel.example/panel/user"),
            "https://panel.example/get_sub.php"
        );
        assert_eq!(
            absolutize_redirect("get_sub.php", "https://panel.example/panel/user"),
            "https://panel.example/panel/get_sub.php"
        );
        assert_eq!(
            absolutize_redirect("//mirror.example/sub", "https://panel.example/panel"),
            "https://mirror.example/sub"
        );
        assert_eq!(
            absolutize_redirect("happ://crypt-xxx", "https://panel.example"),
            "happ://crypt-xxx"
        );
    }

    #[test]
    fn data_block_parsing() {
        let page = r#"<html><script>const DATA = {"links":["ss://AAA@1.2.3.4:1#x","  ","vless://u@h:443#y"],"subUrl":"/sub.php"};</script></html>"#;
        let (links, sub) = extract_data_block(page);
        assert_eq!(links.len(), 2);
        assert_eq!(links[0], "ss://AAA@1.2.3.4:1#x");
        assert_eq!(sub, "/sub.php");
    }

    #[test]
    fn const_raw_extraction() {
        let page = r#"<script>var RAW = "vless://u@h:443#raw";</script>"#;
        let m = re_const_raw().captures(page).unwrap();
        assert_eq!(m.get(1).unwrap().as_str(), "vless://u@h:443#raw");
    }

    #[test]
    fn html_detection() {
        assert!(looks_like_html("<!doctype html><body>"));
        assert!(looks_like_html("<meta charset=utf-8>"));
        assert!(!looks_like_html("vless://u@h:443#x"));
        assert!(!looks_like_html(&format!("ss://{}", "A".repeat(200))));
    }

    #[test]
    fn info_headers_first_non_empty() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert("Profile-Title", "main title".parse().unwrap());
        let mut info = SubFetchInfo {
            profile_title: String::new(),
            userinfo: "upload=1".into(),
            ..Default::default()
        };
        info.set_from(&h);
        assert_eq!(info.profile_title, "main title");
        // непустое значение не затирается промежуточным ответом
        h.clear();
        h.insert("Profile-Title", "second".parse().unwrap());
        info.set_from(&h);
        assert_eq!(info.profile_title, "main title");
        assert_eq!(info.userinfo, "upload=1");
    }

    // Полный флоу на локальном сервере: /a → meta-refresh на /b → /b отдаёт
    // base64-тело подписки.
    #[test]
    fn full_flow_meta_redirect_and_base64() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{}", addr);
        // тело >50 символов: фильтр len>50 (как в Go) отсекает короткие ответы
        let expected = "vless://u@5.5.5.5:443#final-0123456789-0123456789-0123456789";
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(expected.as_bytes());
        let base_for_server = base.clone();
        let server = std::thread::spawn(move || {
            let base = base_for_server;
            for _ in 0..2 {
                let (sock, _) = listener.accept().unwrap();
                let mut w = std::io::BufWriter::new(&sock);
                let peek = {
                    let mut r = BufReader::new(&sock);
                    let mut first = String::new();
                    let _ = r.read_line(&mut first);
                    // дочитываем заголовки
                    loop {
                        let mut line = String::new();
                        let _ = r.read_line(&mut line);
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                    }
                    first
                };
                if peek.contains("GET /a") {
                    let page = format!(
                        "<html><head><meta http-equiv=\"refresh\" content=\"0; url={}/b\"></head></html>",
                        base
                    );
                    let _ = write!(w, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", page.len(), page);
                } else {
                    let _ = write!(w, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body_b64.len(), body_b64);
                }
                let _ = w.flush();
            }
        });
        let got = sub_fetch_content(&format!("{}/a", base), "", "", "", 0, None).unwrap();
        assert_eq!(got, expected);
        server.join().unwrap();
    }

    // Gzip-тело распаковывается: сервер отдаёт gzip-сжатую подписку.
    #[test]
    fn gzip_body() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let plain = "vless://u@6.6.6.6:443#gzip-test-0123456789-0123456789-0123456789";
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(plain.as_bytes()).unwrap();
        let gz = enc.finish().unwrap();
        let gz_len = gz.len();
        let server = std::thread::spawn(move || {
            for _ in 0..1 {
                let (mut sock, _) = listener.accept().unwrap();
                {
                    let mut r = BufReader::new(&sock);
                    loop {
                        let mut line = String::new();
                        let _ = r.read_line(&mut line);
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                    }
                }
                let _ = write!(
                    sock,
                    "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    gz_len
                );
                let _ = sock.write_all(&gz);
            }
        });
        let got = sub_fetch_content(&format!("http://{}/gz", addr), "", "", "", 0, None).unwrap();
        assert_eq!(got, plain);
        server.join().unwrap();
    }
}
