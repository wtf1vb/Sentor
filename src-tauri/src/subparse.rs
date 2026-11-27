// Subscription body parsing and converters - port of Go vpnParseSubscriptionBody,
// vpnDetectBodyFormat, vpnProxyFromOutbound, vpnProxiesFromJSON, vpnProxiesFromClash
// and the userinfo helpers (vpn.go).
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;

use crate::logging::log_add;
use crate::models::VpnProxy;
use crate::vpnlinks::{b64_decode, new_id, parse_link, parse_port, port_ok};
use crate::subfetch::is_client_link;

// parseSubUserinfo — разбор заголовка subscription-userinfo:
// «upload=12; download=34; total=56; expire=1712345678».
pub fn parse_sub_userinfo(s: &str) -> (i64, i64, i64, i64) {
    let (mut up, mut down, mut total, mut expire) = (0i64, 0i64, 0i64, 0i64);
    for part in s.split(';') {
        let Some((k, v)) = part.trim().split_once('=') else {
            continue;
        };
        let Ok(v) = v.trim().parse::<i64>() else {
            continue;
        };
        match k.trim().to_lowercase().as_str() {
            "upload" => up = v,
            "download" => down = v,
            "total" => total = v,
            "expire" => expire = v,
            _ => {}
        }
    }
    (up, down, total, expire)
}

// subMaybeB64 — profile-title и announce часто приходят как «base64:…».
pub fn sub_maybe_b64(s: &str) -> String {
    let s = s.trim();
    if s.len() > 7 && s.get(..7).map(|p| p.eq_ignore_ascii_case("base64:")).unwrap_or(false) {
        let rest = s[7..].trim();
        if let Ok(dec) = b64_decode(rest) {
            let dec = dec.trim().to_string();
            if !dec.is_empty() {
                return dec;
            }
        }
        // декод не удался: пустая строка теряла название профиля/объявление
        // полностью — оставляем исходник
        return s.to_string();
    }
    s.to_string()
}

// ---------- конвертеры форматов ----------

fn vpn_j_str(m: &serde_json::Map<String, Value>, k: &str) -> String {
    m.get(k)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn vpn_j_int(m: &serde_json::Map<String, Value>, k: &str) -> i32 {
    m.get(k).and_then(|v| v.as_f64()).map(|f| f as i32).unwrap_or(0)
}

fn vpn_j_bool(m: &serde_json::Map<String, Value>, k: &str) -> bool {
    m.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn obj(v: &Value) -> Option<&serde_json::Map<String, Value>> {
    v.as_object()
}

// vpnProxyFromOutbound — outbound из sing-box JSON → VpnProxy
fn proxy_from_outbound(m: &serde_json::Map<String, Value>) -> Option<VpnProxy> {
    let mut proto = vpn_j_str(m, "type").to_lowercase();
    if proto == "shadowsocks" {
        proto = "ss".into();
    }
    let host = vpn_j_str(m, "server");
    let port = vpn_j_int(m, "server_port");
    if host.is_empty() || !port_ok(port) {
        return None;
    }
    match proto.as_str() {
        "vless" | "vmess" | "trojan" | "ss" | "hysteria2" => {}
        _ => return None, // direct/block/other — не серверы
    }
    let mut extra: HashMap<String, String> = HashMap::new();
    match proto.as_str() {
        "vless" | "vmess" => {
            extra.insert("cred".into(), vpn_j_str(m, "uuid"));
            if proto == "vmess" {
                extra.insert("aid".into(), vpn_j_int(m, "alter_id").to_string());
            }
        }
        "trojan" | "hysteria2" => {
            extra.insert("cred".into(), vpn_j_str(m, "password"));
            if proto == "hysteria2" {
                // из sing-box JSON обфускация и порты-хопы терялись молча —
                // ключ с обязательным obfs не подключался
                if let Some(o) = m.get("obfs").and_then(obj) {
                    let ot = vpn_j_str(o, "type");
                    if !ot.is_empty() {
                        extra.insert("obfs".into(), ot);
                        let op = vpn_j_str(o, "password");
                        if !op.is_empty() {
                            extra.insert("obfs-password".into(), op);
                        }
                    }
                }
                let sp = match m.get("server_ports") {
                    // sing-box сериализует server_ports МАССИВОМ ["2000:4000", …]:
                    // строковый vpn_j_str молча терял mport целиком, и
                    // port hopping у ключей из sing-box-конфигов не работал
                    Some(Value::Array(arr)) => {
                        let mut parts = Vec::new();
                        for it in arr {
                            if let Some(s) = it.as_str() {
                                let t = s.trim();
                                if !t.is_empty() {
                                    parts.push(t.to_string());
                                }
                            }
                        }
                        parts.join(",")
                    }
                    _ => vpn_j_str(m, "server_ports"),
                };
                if !sp.is_empty() {
                    extra.insert("mport".into(), sp);
                }
            }
        }
        "ss" => {
            extra.insert("method".into(), vpn_j_str(m, "method"));
            extra.insert("cred".into(), vpn_j_str(m, "password"));
        }
        _ => {}
    }
    let flow = vpn_j_str(m, "flow");
    if !flow.is_empty() {
        extra.insert("flow".into(), flow);
    }
    // TLS ставим только если он реально включён: "tls": {"enabled": false}
    // не должен конвертироваться как TLS-ключ.
    if let Some(t) = m.get("tls").and_then(obj) {
        if vpn_j_bool(t, "enabled") {
            let sni = vpn_j_str(t, "server_name");
            if !sni.is_empty() {
                extra.insert("sni".into(), sni);
            }
            if vpn_j_bool(t, "insecure") {
                extra.insert("allowInsecure".into(), "1".into());
            }
            if let Some(u) = t.get("utls").and_then(obj) {
                let fp = vpn_j_str(u, "fingerprint");
                if !fp.is_empty() {
                    extra.insert("fp".into(), fp);
                }
            }
            match t.get("reality").and_then(obj) {
                Some(rl) => {
                    let pk = vpn_j_str(rl, "public_key");
                    if !pk.is_empty() {
                        extra.insert("security".into(), "reality".into());
                        extra.insert("pbk".into(), pk);
                        let sid = vpn_j_str(rl, "short_id");
                        if !sid.is_empty() {
                            extra.insert("sid".into(), sid);
                        }
                    } else {
                        // reality-объект есть, но public_key пуст (битая панель):
                        // без фолбэка узел уходил в конфиг ВООБЩЕ без TLS,
                        // хотя tls.enabled=true
                        extra.insert("security".into(), "tls".into());
                    }
                }
                None => {
                    extra.insert("security".into(), "tls".into());
                }
            }
        }
    }
    if let Some(tr) = m.get("transport").and_then(obj) {
        let tt = vpn_j_str(tr, "type");
        if !tt.is_empty() {
            extra.insert("type".into(), tt);
        }
        let pt = vpn_j_str(tr, "path");
        if !pt.is_empty() {
            extra.insert("path".into(), pt);
        }
        if let Some(hh) = tr.get("headers").and_then(obj) {
            let h = vpn_j_str(hh, "Host");
            if !h.is_empty() {
                extra.insert("host".into(), h);
            }
        }
        let sn = vpn_j_str(tr, "service_name");
        if !sn.is_empty() {
            extra.insert("servicename".into(), sn);
        }
    }
    let mut name = vpn_j_str(m, "tag");
    if name.is_empty() {
        name = host.clone();
    }
    Some(VpnProxy {
        id: new_id(),
        proto,
        name,
        host,
        port,
        raw: String::new(),
        sub_id: None,
        manual: None,
        extra: Some(extra),
    })
}

// v2rayN-JSON (массив объектов v/ps/add/port/id/...): распространённый формат
// панелей. Отличается от sing-box outbound именами полей; протокол в объекте
// не указан — эвристика: scy (vmess-шифр) есть → vmess, иначе vless.
fn v2rayn_str(m: &serde_json::Map<String, Value>, k: &str) -> String {
    match m.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn proxy_from_v2rayn(m: &serde_json::Map<String, Value>) -> Option<VpnProxy> {
    let host = v2rayn_str(m, "add").trim().to_string();
    // порт бывает и «443», и 443.0 (float): строковый parse::<i32> давал 0,
    // и узел молча выбрасывался
    let port = parse_port(v2rayn_str(m, "port").trim());
    let cred = v2rayn_str(m, "id").trim().to_string();
    if host.is_empty() || !port_ok(port) || cred.is_empty() {
        return None;
    }
    let proto = if !v2rayn_str(m, "scy").trim().is_empty() { "vmess" } else { "vless" };
    let mut extra: HashMap<String, String> = HashMap::new();
    extra.insert("cred".into(), cred);
    if proto == "vmess" {
        let aid = v2rayn_str(m, "aid");
        if !aid.is_empty() {
            extra.insert("aid".into(), aid);
        }
    }
    let flow = v2rayn_str(m, "flow");
    if !flow.is_empty() {
        extra.insert("flow".into(), flow);
    }
    let net = v2rayn_str(m, "net").trim().to_lowercase();
    match net.as_str() {
        "ws" | "grpc" | "httpupgrade" | "xhttp" | "h2" | "h2c" => {
            let t = if net == "h2c" { "h2".to_string() } else { net.clone() };
            extra.insert("type".into(), t);
        }
        "" | "tcp" => {}
        _ => {
            extra.insert("type".into(), net);
        }
    }
    let path = v2rayn_str(m, "path");
    if !path.is_empty() {
        extra.insert("path".into(), path);
    }
    let host_hdr = v2rayn_str(m, "host");
    if !host_hdr.is_empty() {
        extra.insert("host".into(), host_hdr);
    }
    // tls: "tls" | "reality" | "" (v2rayN пишет строкой)
    let tls = v2rayn_str(m, "tls").trim().to_lowercase();
    let sni = v2rayn_str(m, "sni").trim().to_string();
    let fp = v2rayn_str(m, "fp").trim().to_string();
    let pbk = v2rayn_str(m, "pbk").trim().to_string();
    if tls == "reality" || !pbk.is_empty() {
        extra.insert("security".into(), "reality".into());
        if !pbk.is_empty() {
            extra.insert("pbk".into(), pbk);
        }
        let sid = v2rayn_str(m, "sid").trim().to_string();
        if !sid.is_empty() {
            extra.insert("sid".into(), sid);
        }
    } else if tls == "tls" || !sni.is_empty() {
        extra.insert("security".into(), "tls".into());
    }
    if !sni.is_empty() {
        extra.insert("sni".into(), sni);
    }
    if !fp.is_empty() {
        extra.insert("fp".into(), fp);
    }
    let alpn = v2rayn_str(m, "alpn").trim().to_string();
    if !alpn.is_empty() {
        extra.insert("alpn".into(), alpn);
    }
    let mut name = v2rayn_str(m, "ps");
    if name.is_empty() {
        name = host.clone();
    }
    Some(VpnProxy {
        id: new_id(),
        proto: proto.into(),
        name,
        host,
        port,
        raw: String::new(),
        sub_id: None,
        manual: None,
        extra: Some(extra),
    })
}

pub fn proxies_from_json(body: &str) -> Vec<VpnProxy> {
    let Ok(root) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let mut out: Vec<VpnProxy> = Vec::new();
    let add_obj = |m: &serde_json::Map<String, Value>, out: &mut Vec<VpnProxy>| {
        // сначала sing-box/xray outbound (по полю "type"), затем v2rayN
        // (по полям add/id — у sing-box таких нет)
        if let Some(p) = proxy_from_outbound(m) {
            out.push(p);
            return;
        }
        if m.contains_key("add") && m.contains_key("id") {
            if let Some(p) = proxy_from_v2rayn(m) {
                out.push(p);
            }
        }
    };
    match &root {
        Value::Array(arr) => {
            for it in arr {
                match it {
                    Value::String(s) => {
                        if let Ok(p) = parse_link(s) {
                            out.push(p);
                        }
                    }
                    Value::Object(m) => add_obj(m, &mut out),
                    _ => {}
                }
            }
        }
        Value::Object(r) => {
            if let Some(Value::Array(ob)) = r.get("outbounds") {
                for it in ob {
                    if let Value::Object(m) = it {
                        add_obj(m, &mut out);
                    }
                }
            }
        }
        _ => {}
    }
    out
}

// clashNode — прокси из clash/mihomo YAML
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ClashReality {
    #[serde(rename = "public-key")]
    public_key: String,
    #[serde(rename = "short-id")]
    short_id: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ClashWS {
    path: String,
    headers: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ClashGRPC {
    #[serde(rename = "grpc-service-name")]
    service_name: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ClashNode {
    name: String,
    #[serde(rename = "type")]
    node_type: String,
    server: String,
    port: i32,
    uuid: String,
    password: String,
    cipher: String,
    #[serde(rename = "alterId")]
    alter_id: i32,
    tls: bool,
    servername: String,
    sni: String,
    network: String,
    flow: String,
    #[serde(rename = "client-fingerprint")]
    client_fp: String,
    #[serde(rename = "skip-cert-verify")]
    skip_verify: bool,
    #[serde(rename = "reality-opts")]
    reality: Option<ClashReality>,
    #[serde(rename = "ws-opts")]
    ws: Option<ClashWS>,
    #[serde(rename = "grpc-opts")]
    grpc: Option<ClashGRPC>,
    obfs: String,
    #[serde(rename = "obfs-password")]
    obfs_password: String,
    ports: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct ClashCfg {
    // Поузловой разбор: ноды идут как сырые Value, каждая конвертируется
    // отдельно. Строгая типизация на весь документ теряла ВСЕ узлы подписки
    // из-за одной ноды с нетипизированным полем (port: "443", tls: "true",
    // числовой заголовок в ws-opts) — панели такое выдают регулярно.
    proxies: Vec<serde_yaml::Value>,
}

fn clash_ports_string(v: Option<&serde_yaml::Value>) -> String {
    let Some(v) = v else { return String::new() };
    match v {
        serde_yaml::Value::String(s) => s.trim().to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Sequence(arr) => {
            let mut parts = Vec::new();
            for it in arr {
                match it {
                    serde_yaml::Value::String(s) => {
                        let t = s.trim();
                        if !t.is_empty() {
                            parts.push(t.to_string());
                        }
                    }
                    serde_yaml::Value::Number(n) => parts.push(n.to_string()),
                    _ => {}
                }
            }
            parts.join(",")
        }
        _ => String::new(),
    }
}

pub fn proxies_from_clash(body: &str) -> Vec<VpnProxy> {
    let Ok(cfg) = serde_yaml::from_str::<ClashCfg>(body) else {
        return Vec::new();
    };
    if cfg.proxies.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for raw in cfg.proxies {
        // одна битая нода пропускается с логом, остальные продолжают работать
        let Ok(n) = serde_yaml::from_value::<ClashNode>(raw) else {
            skipped += 1;
            continue;
        };
        let mut proto = n.node_type.to_lowercase();
        if proto == "shadowsocks" {
            proto = "ss".into();
        }
        match proto.as_str() {
            "vless" | "vmess" | "trojan" | "ss" | "hysteria2" => {}
            _ => continue,
        }
        if n.server.is_empty() || !port_ok(n.port) {
            continue;
        }
        let mut extra: HashMap<String, String> = HashMap::new();
        match proto.as_str() {
            "vless" | "vmess" => {
                extra.insert("cred".into(), n.uuid.clone());
                if proto == "vmess" {
                    extra.insert("aid".into(), n.alter_id.to_string());
                }
                if !n.flow.is_empty() {
                    extra.insert("flow".into(), n.flow.clone());
                }
            }
            "trojan" | "hysteria2" => {
                extra.insert("cred".into(), n.password.clone());
                if proto == "hysteria2" {
                    if !n.obfs.is_empty() {
                        extra.insert("obfs".into(), n.obfs.clone());
                    }
                    if !n.obfs_password.is_empty() {
                        extra.insert("obfs-password".into(), n.obfs_password.clone());
                    }
                    let ports = clash_ports_string(n.ports.as_ref());
                    if !ports.is_empty() {
                        extra.insert("mport".into(), ports);
                    }
                }
            }
            "ss" => {
                extra.insert("method".into(), n.cipher.clone());
                extra.insert("cred".into(), n.password.clone());
            }
            _ => {}
        }
        let mut sec = String::new();
        if n.tls || proto == "trojan" || proto == "hysteria2" {
            sec = "tls".into();
        }
        if let Some(rl) = &n.reality {
            if !rl.public_key.is_empty() {
                sec = "reality".into();
                extra.insert("pbk".into(), rl.public_key.clone());
                extra.insert("sid".into(), rl.short_id.clone());
            }
        }
        if !sec.is_empty() {
            extra.insert("security".into(), sec);
        }
        let mut sni = n.servername.clone();
        if sni.is_empty() {
            sni = n.sni.clone();
        }
        if !sni.is_empty() {
            extra.insert("sni".into(), sni);
        }
        if !n.client_fp.is_empty() {
            extra.insert("fp".into(), n.client_fp.clone());
        }
        if n.skip_verify {
            extra.insert("allowInsecure".into(), "1".into());
        }
        if !n.network.is_empty() && n.network != "tcp" {
            extra.insert("type".into(), n.network.clone());
        }
        if let Some(ws) = &n.ws {
            extra.insert("path".into(), ws.path.clone());
            let mut h = ws.headers.get("Host").cloned().unwrap_or_default();
            if h.is_empty() {
                h = ws.headers.get("host").cloned().unwrap_or_default();
            }
            if !h.is_empty() {
                extra.insert("host".into(), h);
            }
        }
        if let Some(grpc) = &n.grpc {
            extra.insert("servicename".into(), grpc.service_name.clone());
        }
        let mut name = n.name.clone();
        if name.is_empty() {
            name = n.server.clone();
        }
        out.push(VpnProxy {
            id: new_id(),
            proto,
            name,
            host: n.server.clone(),
            port: n.port,
            raw: String::new(),
            sub_id: None,
            manual: None,
            extra: Some(extra),
        });
    }
    if skipped > 0 {
        log_add(
            "vpn",
            &format!("clash: пропущено нод с некорректными полями: {} (остальные добавлены)", skipped),
        );
    }
    out
}

// vpnParseSubscriptionBody — определяет формат тела и превращает в серверы:
// base64 (в т.ч. вложенный) → JSON → YAML (clash) → построчные ссылки.
pub fn parse_subscription_body(tools: &Path, body: &str) -> Vec<VpnProxy> {
    detect_body_format(tools, body.trim(), 0)
}

fn detect_body_format(tools: &Path, body: &str, depth: i32) -> Vec<VpnProxy> {
    if depth > 2 || body.is_empty() {
        return Vec::new();
    }
    // JSON: объект с outbounds (sing-box/v2ray-стиль) или массив ссылок/объектов
    if body.starts_with('{') || body.starts_with('[') {
        let px = proxies_from_json(body);
        if !px.is_empty() {
            return px;
        }
    }
    // YAML: clash/mihomo-конфиг с секцией proxies
    if body.starts_with("proxies:") || body.contains("\nproxies:") {
        let px = proxies_from_clash(body);
        if !px.is_empty() {
            return px;
        }
    }
    // base64: декодируем и пробуем снова (внутри может быть JSON/YAML/ссылки)
    if !body.contains("://") {
        if let Ok(dec) = b64_decode(body) {
            let px = detect_body_format(tools, dec.trim(), depth + 1);
            if !px.is_empty() {
                return px;
            }
        }
    }
    // построчные ссылки
    let mut out = Vec::new();
    // Внутренние загрузки ограничиваем и по числу, и по бюджету: раньше каждая
    // клиентская ссылка получала свежий 90-с дедлайн без лимита ширины —
    // подписка из N ссылок могла висеть часами.
    let mut inner_fetches = 0usize;
    const INNER_FETCH_MAX: usize = 8;
    const INNER_FETCH_BUDGET: Duration = Duration::from_secs(20);
    for line in body.split('\n') {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        if !line.contains("://") {
            continue;
        }
        // Тело подписки может само состоять из happ/incy/v2raytun-ссылок
        if is_client_link(line) {
            match crate::happcrypt::vpn_resolve_link(line, 0) {
                Err(e) => {
                    log_add("decrypt", &format!("клиентская ссылка в подписке не расшифровалась: {}", e));
                    continue;
                }
                Ok((inner_url, text, _)) => {
                    if !text.trim().is_empty() {
                        out.extend(detect_body_format(tools, text.trim(), depth + 1));
                        continue;
                    }
                    if !inner_url.is_empty() {
                        if inner_fetches >= INNER_FETCH_MAX {
                            log_add(
                                "sub",
                                &format!("внутренних загрузок больше {} — остальные пропущены", INNER_FETCH_MAX),
                            );
                        } else {
                            inner_fetches += 1;
                            let budget = Instant::now() + INNER_FETCH_BUDGET;
                            if let Ok(fetched) = fetch_subscription_budgeted(tools, inner_url.trim(), Some(budget)) {
                                out.extend(detect_body_format(tools, &fetched, depth + 1));
                            }
                        }
                    }
                    continue;
                }
            }
        }
        if let Ok(p) = parse_link(line) {
            out.push(p);
        }
    }
    out
}

// Загрузка с ограниченным бюджетом — для внутренних ссылок из тела подписки
// (см. detect_body_format): без него каждая ссылка получала свои 90 с.
fn fetch_subscription_budgeted(tools: &Path, link: &str, budget: Option<Instant>) -> Result<String, String> {
    let st = crate::store::load_vpn_settings(tools);
    crate::subfetch::sub_fetch_content_info(
        link,
        st.spoof_ua.trim(),
        st.spoof_hwid.trim(),
        st.spoof_os.trim(),
        0,
        None,
        budget,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn userinfo_parsing() {
        let (up, down, total, exp) = parse_sub_userinfo("upload=12; download=34; total=56; expire=1712345678");
        assert_eq!((up, down, total, exp), (12, 34, 56, 1712345678));
        let (up, down, total, exp) = parse_sub_userinfo("garbage; Upload=5; expire=abc");
        assert_eq!((up, down, total, exp), (5, 0, 0, 0));
    }

    #[test]
    fn maybe_b64() {
        let payload = base64::engine::general_purpose::STANDARD.encode("Мой профиль".as_bytes());
        assert_eq!(sub_maybe_b64(&format!("base64:{}", payload)), "Мой профиль");
        assert_eq!(sub_maybe_b64("Happ"), "Happ");
        // декод не удался — возвращается исходник (пустая строка теряла
        // название профиля/объявление полностью)
        assert_eq!(sub_maybe_b64("base64:!!!not-b64!!!"), "base64:!!!not-b64!!!");
    }

    #[test]
    fn json_outbounds() {
        let body = r#"{"outbounds":[
            {"type":"vless","tag":"srv-1","server":"1.1.1.1","server_port":443,"uuid":"u-1","flow":"xtls-rprx-vision",
             "tls":{"enabled":true,"server_name":"ex.com","utls":{"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"PBK","short_id":"SID"}},
             "transport":{"type":"ws","path":"/wspath","headers":{"Host":"h.com"}}},
            {"type":"shadowsocks","tag":"ss1","server":"2.2.2.2","server_port":8388,"method":"aes-128-gcm","password":"pp"},
            {"type":"direct","tag":"direct"}
        ]}"#;
        let px = proxies_from_json(body);
        assert_eq!(px.len(), 2);
        assert_eq!(px[0].proto, "vless");
        assert_eq!(px[0].host, "1.1.1.1");
        assert_eq!(px[0].port, 443);
        let e = px[0].extra.as_ref().unwrap();
        assert_eq!(e.get("cred").unwrap(), "u-1");
        assert_eq!(e.get("flow").unwrap(), "xtls-rprx-vision");
        assert_eq!(e.get("security").unwrap(), "reality");
        assert_eq!(e.get("pbk").unwrap(), "PBK");
        assert_eq!(e.get("sid").unwrap(), "SID");
        assert_eq!(e.get("sni").unwrap(), "ex.com");
        assert_eq!(e.get("fp").unwrap(), "chrome");
        assert_eq!(e.get("type").unwrap(), "ws");
        assert_eq!(e.get("path").unwrap(), "/wspath");
        assert_eq!(e.get("host").unwrap(), "h.com");
        assert_eq!(px[1].proto, "ss");
        assert_eq!(px[1].extra.as_ref().unwrap().get("method").unwrap(), "aes-128-gcm");
    }

    #[test]
    fn json_array_of_strings() {
        let body = r#"["vless://u@h.io:443#one","ss://YWVzLTI1Ni1nY206cGFzcw==@2.2.2.2:8388#two"]"#;
        let px = proxies_from_json(body);
        assert_eq!(px.len(), 2);
        assert_eq!(px[0].proto, "vless");
        assert_eq!(px[1].proto, "ss");
    }

    #[test]
    fn json_v2rayn_array() {
        let body = r#"[
            {"v":"2","ps":"DE-1","add":"de.example.com","port":"443","id":"uuid-abc","aid":"0",
             "net":"ws","host":"cdn.example.com","path":"/wsp","tls":"tls","sni":"de.example.com","fp":"chrome"},
            {"v":"2","ps":"NL-1","add":"nl.example.com","port":8443,"id":"uuid-def","aid":0,
             "scy":"auto","net":"tcp","tls":""}
        ]"#;
        let px = proxies_from_json(body);
        assert_eq!(px.len(), 2);
        assert_eq!(px[0].proto, "vless");
        assert_eq!(px[0].host, "de.example.com");
        assert_eq!(px[0].port, 443);
        assert_eq!(px[0].name, "DE-1");
        let e = px[0].extra.as_ref().unwrap();
        assert_eq!(e.get("cred").unwrap(), "uuid-abc");
        assert_eq!(e.get("security").unwrap(), "tls");
        assert_eq!(e.get("sni").unwrap(), "de.example.com");
        assert_eq!(e.get("type").unwrap(), "ws");
        assert_eq!(e.get("path").unwrap(), "/wsp");
        assert_eq!(e.get("host").unwrap(), "cdn.example.com");
        assert_eq!(px[1].proto, "vmess");
        assert_eq!(px[1].port, 8443);
        let e1 = px[1].extra.as_ref().unwrap();
        assert_eq!(e1.get("aid").unwrap(), "0");
        assert!(!e1.contains_key("security"));
    }

    #[test]
    fn json_hysteria2_keeps_obfs_and_ports() {
        let body = r#"{"outbounds":[{"type":"hysteria2","tag":"hy2","server":"4.4.4.4","server_port":443,
            "password":"pw","obfs":{"type":"salamander","password":"op"},"server_ports":"2000-4000,5000-6000"}]}"#;
        let px = proxies_from_json(body);
        assert_eq!(px.len(), 1);
        let e = px[0].extra.as_ref().unwrap();
        assert_eq!(e.get("cred").unwrap(), "pw");
        assert_eq!(e.get("obfs").unwrap(), "salamander");
        assert_eq!(e.get("obfs-password").unwrap(), "op");
        assert_eq!(e.get("mport").unwrap(), "2000-4000,5000-6000");
    }

    #[test]
    fn json_tls_disabled_not_tls() {
        let body = r#"{"outbounds":[{"type":"vless","tag":"x","server":"h","server_port":443,"uuid":"u","tls":{"enabled":false}}]}"#;
        let px = proxies_from_json(body);
        assert_eq!(px.len(), 1);
        let e = px[0].extra.as_ref().unwrap();
        assert!(!e.contains_key("security"));
    }

    #[test]
    fn clash_yaml() {
        let body = r#"
proxies:
  - name: "RU-1"
    type: vless
    server: 3.3.3.3
    port: 443
    uuid: uuid-1
    tls: true
    servername: real.sni
    network: ws
    client-fingerprint: chrome
    reality-opts:
      public-key: pubk
      short-id: "0123"
    ws-opts:
      path: /ws
      headers:
        Host: ws.host
  - name: "HY"
    type: hysteria2
    server: 4.4.4.4
    port: 36812
    password: secret
    obfs: salamander
    obfs-password: obfsp
    ports: 2000-4000,5000-6000
  - name: "bad"
    type: http
    server: 5.5.5.5
    port: 80
"#;
        let px = proxies_from_clash(body);
        assert_eq!(px.len(), 2);
        assert_eq!(px[0].proto, "vless");
        let e = px[0].extra.as_ref().unwrap();
        assert_eq!(e.get("cred").unwrap(), "uuid-1");
        assert_eq!(e.get("security").unwrap(), "reality");
        assert_eq!(e.get("pbk").unwrap(), "pubk");
        assert_eq!(e.get("sid").unwrap(), "0123");
        assert_eq!(e.get("sni").unwrap(), "real.sni");
        assert_eq!(e.get("type").unwrap(), "ws");
        assert_eq!(e.get("path").unwrap(), "/ws");
        assert_eq!(e.get("host").unwrap(), "ws.host");
        assert_eq!(e.get("fp").unwrap(), "chrome");
        assert_eq!(px[1].proto, "hysteria2");
        let e = px[1].extra.as_ref().unwrap();
        assert_eq!(e.get("cred").unwrap(), "secret");
        assert_eq!(e.get("obfs").unwrap(), "salamander");
        assert_eq!(e.get("obfs-password").unwrap(), "obfsp");
        assert_eq!(e.get("mport").unwrap(), "2000-4000,5000-6000");
        // hysteria2: TLS подразумевается
        assert_eq!(e.get("security").unwrap(), "tls");
    }

    #[test]
    fn body_format_line_links_with_comments() {
        let body = "# comment\n\nvless://u@1.1.1.1:443#a\n// commented\nnot-a-link\nss://YWVzLTI1Ni1nY206cGFzcw==@2.2.2.2:8388#b\n";
        let px = parse_subscription_body(Path::new("Z:\\nonexistent"), body);
        assert_eq!(px.len(), 2);
        assert_eq!(px[0].proto, "vless");
        assert_eq!(px[1].proto, "ss");
    }

    #[test]
    fn body_format_nested_base64() {
        let inner = "vless://u@7.7.7.7:443#nested\nvless://u2@8.8.8.8:443#nested2";
        let outer = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let px = parse_subscription_body(Path::new("Z:\\nonexistent"), &outer);
        assert_eq!(px.len(), 2);
        assert_eq!(px[0].host, "7.7.7.7");
    }
}
