// Link parsing - port of Go vpnParseLink/vpnParseUserHost/vpnParseVmess/vpnParseSS
// and helpers vpnNewID/vpnB64/vpnPortOK (vpn.go).
use base64::engine::general_purpose::{
    STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
};
use base64::Engine;
use serde_json::Value;
use std::collections::HashMap;

use crate::models::VpnProxy;

pub fn new_id() -> String {
    let u = uuid::Uuid::new_v4().simple().to_string();
    u[..12].to_string()
}

pub fn port_ok(port: i32) -> bool {
    port > 0 && port < 65536
}

// parse_port — порты в панелях приходят и числом, и строкой, и «443.0»
// (float в строке): строковый parse::<i32> давал 0, и узел молча выбрасывался
pub fn parse_port(s: &str) -> i32 {
    let t = s.trim();
    if let Ok(n) = t.parse::<i32>() {
        return n;
    }
    t.parse::<f64>().map(|f| f as i32).unwrap_or(0)
}

fn percent_decode(s: &str) -> Option<String> {
    percent_encoding::percent_decode_str(s).decode_utf8().ok().map(|c| c.to_string())
}

// vpnB64 — если паддинга не хватает, пробуем дополненную версию (std и url),
// потом все четыре варианта кодировок. Переносы строк/пробелы внутри
// (типичная вставка vmess-ключа из буфера) вырезаем до декодирования.
pub fn b64_decode(s: &str) -> Result<String, String> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let s = compact.trim();
    let pad = (4 - s.len() % 4) % 4;
    if pad > 0 {
        let s2 = format!("{}{}", s, "=".repeat(pad));
        if let Ok(d) = STANDARD.decode(s2.as_bytes()) {
            return Ok(String::from_utf8_lossy(&d).to_string());
        }
        if let Ok(d) = URL_SAFE.decode(s2.as_bytes()) {
            return Ok(String::from_utf8_lossy(&d).to_string());
        }
    }
    for dec in [STANDARD, URL_SAFE, STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
        if let Ok(d) = dec.decode(s.as_bytes()) {
            return Ok(String::from_utf8_lossy(&d).to_string());
        }
    }
    Err("не удалось декодировать base64".into())
}

pub fn parse_link(link: &str) -> Result<VpnProxy, String> {
    let link = link.trim();
    let low = link.to_lowercase();
    // Схемы приводим к нижнему регистру: некоторые клиенты копируют VLESS://…
    if low.starts_with("vmess://") {
        return parse_vmess(&format!("vmess://{}", &link[8..]));
    }
    if low.starts_with("vless://") {
        return parse_user_host(&format!("vless://{}", &link[8..]), "vless");
    }
    if low.starts_with("trojan://") {
        return parse_user_host(&format!("trojan://{}", &link[9..]), "trojan");
    }
    if low.starts_with("hysteria2://") {
        return parse_user_host(&format!("hysteria2://{}", &link[12..]), "hysteria2");
    }
    if low.starts_with("hy2://") {
        return parse_user_host(&format!("hysteria2://{}", &link[6..]), "hysteria2");
    }
    if low.starts_with("ss://") {
        return parse_ss(&format!("ss://{}", &link[5..]));
    }
    Err("неизвестная ссылка — поддерживаются vless://, trojan://, vmess://, ss://, hysteria2://, а happ://, incy:// и v2raytun:// добавляй как подписку".into())
}

fn parse_user_host(link: &str, proto: &str) -> Result<VpnProxy, String> {
    let u = url::Url::parse(link).map_err(|e| format!("не удалось разобрать ссылку: {}", e))?;
    let host = u.host_str().unwrap_or("").to_string();
    let port = u.port().unwrap_or(0) as i32;
    if host.is_empty() || !port_ok(port) {
        return Err("в ссылке нет адреса или порта".into());
    }
    // fragment декодируется один раз (как url.Parse в Go): повторное
    // декодирование портило имена («50%25» → «P»).
    let mut name = u.fragment().and_then(|f| percent_decode(f)).unwrap_or_default();
    if name.is_empty() {
        name = host.clone();
    }
    let mut extra: HashMap<String, String> = HashMap::new();
    for (k, v) in u.query_pairs() {
        extra.entry(k.to_lowercase()).or_insert_with(|| v.to_string());
    }
    // Декодированные username/password: пере-экранированная строка искажала
    // пароль. Для hy2 «user:pass» целиком является auth-строкой.
    let username = percent_decode(u.username()).unwrap_or_default();
    let password = u.password().and_then(|p| percent_decode(p)).unwrap_or_default();
    if !username.is_empty() || u.password().is_some() {
        let cred = if u.password().is_some() {
            format!("{}:{}", username, password)
        } else {
            username
        };
        extra.insert("cred".into(), cred);
    }
    Ok(VpnProxy {
        id: new_id(),
        proto: proto.into(),
        name,
        host,
        port,
        raw: link.into(),
        sub_id: None,
        manual: None,
        extra: Some(extra),
    })
}

fn parse_vmess(link: &str) -> Result<VpnProxy, String> {
    let body = link.strip_prefix("vmess://").unwrap_or(link);
    let dec = b64_decode(body).map_err(|e| format!("vmess: {}", e))?;
    let j: serde_json::Map<String, Value> = serde_json::from_str(&dec)
        .map_err(|_| "vmess: внутри ссылки не JSON".to_string())?;
    let get = |k: &str| -> String {
        match j.get(k) {
            Some(Value::String(s)) => s.trim().to_string(),
            Some(Value::Number(n)) => (n.as_f64().unwrap_or(0.0) as i64).to_string(),
            _ => String::new(),
        }
    };
    let host = get("add");
    let port: i32 = parse_port(&get("port"));
    if host.is_empty() || !port_ok(port) {
        return Err("vmess: нет адреса или порта".into());
    }
    let mut name = get("ps");
    if name.is_empty() {
        name = host.clone();
    }
    let mut net_type = get("net");
    if net_type.is_empty() {
        net_type = "tcp".into();
    }
    let mut tls_sec = String::new();
    if get("tls").eq_ignore_ascii_case("tls") {
        tls_sec = "tls".into();
    }
    // часть панелей пишет tls как boolean: {"tls": true}
    if matches!(j.get("tls"), Some(Value::Bool(true))) {
        tls_sec = "tls".into();
    }
    let mut extra = HashMap::new();
    extra.insert("cred".into(), get("id"));
    extra.insert("aid".into(), get("aid"));
    extra.insert("type".into(), net_type);
    extra.insert("path".into(), get("path"));
    extra.insert("host".into(), get("host"));
    extra.insert("security".into(), tls_sec);
    extra.insert("sni".into(), get("sni"));
    extra.insert("fp".into(), get("fp"));
    Ok(VpnProxy {
        id: new_id(),
        proto: "vmess".into(),
        name,
        host,
        port,
        raw: link.into(),
        sub_id: None,
        manual: None,
        extra: Some(extra),
    })
}

fn parse_ss(link: &str) -> Result<VpnProxy, String> {
    let mut body = link.strip_prefix("ss://").unwrap_or(link).to_string();
    let mut name = String::new();
    if let Some(i) = body.find('#') {
        // PathUnescape, а не QueryUnescape: во fragment «+» — литерал.
        name = percent_decode(&body[i + 1..]).unwrap_or_default();
        body.truncate(i);
    }
    if let Some(i) = body.find('?') {
        body.truncate(i); // плагины пока не поддерживаем
    }
    let (mut user_info, host_part) = if let Some(at) = body.rfind('@') {
        (body[..at].to_string(), body[at + 1..].to_string())
    } else {
        let dec = b64_decode(&body).map_err(|e| format!("ss: {}", e))?;
        let at = dec.rfind('@').ok_or("ss: в ссылке нет @")?;
        (dec[..at].to_string(), dec[at + 1..].to_string())
    };
    if !user_info.contains(':') {
        if let Ok(d) = b64_decode(&user_info) {
            user_info = d;
        }
    }
    let (method, pass) = user_info
        .split_once(':')
        .ok_or("ss: нет пароля")?;
    // SIP002: method/password percent-encoded, «+» в userinfo — ЛИТЕРАЛ.
    // QueryUnescape-семантика («+» → пробел) искажала пароли вида «a+b»
    let mut method = method.to_string();
    let mut pass = pass.to_string();
    if method.contains('%') {
        if let Some(d) = percent_decode(&method) {
            method = d;
        }
    }
    if pass.contains('%') {
        if let Some(d) = percent_decode(&pass) {
            pass = d;
        }
    }
    let host_part = host_part.trim().trim_end_matches('/').to_string();
    let (host, port_s) = split_host_port(&host_part).ok_or("ss: нет порта")?;
    let port: i32 = parse_port(&port_s);
    if host.is_empty() || !port_ok(port) {
        return Err("ss: нет адреса или порта".into());
    }
    if name.is_empty() {
        name = host.clone();
    }
    let mut extra = HashMap::new();
    extra.insert("method".into(), method);
    extra.insert("cred".into(), pass);
    Ok(VpnProxy {
        id: new_id(),
        proto: "ss".into(),
        name,
        host,
        port,
        raw: link.into(),
        sub_id: None,
        manual: None,
        extra: Some(extra),
    })
}

// Go net.SplitHostPort для "host:port" и "[v6]:port".
fn split_host_port(s: &str) -> Option<(String, String)> {
    if let Some(rb) = s.rfind(']') {
        if !s.starts_with('[') {
            return None;
        }
        let host = s[1..rb].to_string();
        let port = s[rb + 1..].strip_prefix(':')?;
        if port.is_empty() {
            return None;
        }
        Some((host, port.to_string()))
    } else {
        let (h, p) = s.rsplit_once(':')?;
        // «2001:db8::443» без скобок — это IPv6 без порта, а не host:port
        // (Go вернул бы «too many colons»): раньше хост-мусор «2001:db8:»
        // уходил дальше в конфиг и пинг
        if h.contains(':') {
            return None;
        }
        Some((h.to_string(), p.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_link() {
        let p = parse_link(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=ws&path=%2Fpath#Мой%20сервер",
        )
        .unwrap();
        assert_eq!(p.proto, "vless");
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.name, "Мой сервер");
        let extra = p.extra.unwrap();
        assert_eq!(extra.get("cred").unwrap(), "b831381d-6324-4d53-ad4f-8cda48b30811");
        assert_eq!(extra.get("security").unwrap(), "tls");
        assert_eq!(extra.get("path").unwrap(), "/path");
    }

    #[test]
    fn vless_uppercase_scheme() {
        let p = parse_link("VLESS://uuid@example.com:443#X").unwrap();
        assert_eq!(p.proto, "vless");
        assert_eq!(p.host, "example.com");
    }

    #[test]
    fn vmess_link() {
        let json = r#"{"add":"1.2.3.4","port":443,"ps":"Тест VM","id":"u-1","aid":"0","net":"ws","tls":"tls","path":"/p","host":"h.com","sni":"s.com","fp":"chrome"}"#;
        let link = format!("vmess://{}", STANDARD.encode(json.as_bytes()));
        let p = parse_link(&link).unwrap();
        assert_eq!(p.proto, "vmess");
        assert_eq!(p.host, "1.2.3.4");
        assert_eq!(p.port, 443);
        assert_eq!(p.name, "Тест VM");
        let extra = p.extra.unwrap();
        assert_eq!(extra.get("security").unwrap(), "tls");
        assert_eq!(extra.get("type").unwrap(), "ws");
        assert_eq!(extra.get("cred").unwrap(), "u-1");
    }

    #[test]
    fn vmess_bool_tls() {
        let json = r#"{"add":"1.2.3.4","port":8443,"id":"u","tls":true}"#;
        let link = format!("vmess://{}", STANDARD.encode(json.as_bytes()));
        let p = parse_link(&link).unwrap();
        let extra = p.extra.unwrap();
        assert_eq!(extra.get("security").unwrap(), "tls");
        assert_eq!(extra.get("type").unwrap(), "tcp");
    }

    #[test]
    fn ss_userinfo_b64() {
        // aes-256-gcm:pass в base64 + хост в открытом виде
        let link = "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#SS%20Name";
        let p = parse_link(link).unwrap();
        assert_eq!(p.proto, "ss");
        assert_eq!(p.host, "1.2.3.4");
        assert_eq!(p.port, 8388);
        assert_eq!(p.name, "SS Name");
        let extra = p.extra.unwrap();
        assert_eq!(extra.get("method").unwrap(), "aes-256-gcm");
        assert_eq!(extra.get("cred").unwrap(), "pass");
    }

    #[test]
    fn ss_whole_b64() {
        let inner = "aes-128-gcm:p%2F%2Bss@9.9.9.9:443";
        let link = format!("ss://{}", STANDARD.encode(inner.as_bytes()));
        let p = parse_link(&link).unwrap();
        assert_eq!(p.host, "9.9.9.9");
        assert_eq!(p.port, 443);
        let extra = p.extra.unwrap();
        // SIP002: percent-encoded password декодируется
        assert_eq!(extra.get("method").unwrap(), "aes-128-gcm");
        assert_eq!(extra.get("cred").unwrap(), "p/+ss");
    }

    #[test]
    fn hy2_link() {
        let p = parse_link("hy2://p%40ss@hy.example.com:8443?sni=real.com&insecure=1#Hy2").unwrap();
        assert_eq!(p.proto, "hysteria2");
        assert_eq!(p.host, "hy.example.com");
        assert_eq!(p.port, 8443);
        let extra = p.extra.unwrap();
        assert_eq!(extra.get("cred").unwrap(), "p@ss");
        assert_eq!(extra.get("sni").unwrap(), "real.com");
    }

    #[test]
    fn unknown_and_subscription_links() {
        assert!(parse_link("happ://crypt-xxx").is_err());
        assert!(parse_link("http://example.com").is_err());
        assert!(parse_link("vless://uuid@host:notaport").is_err());
    }
}
