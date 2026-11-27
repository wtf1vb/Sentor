// sing-box config building - port of Go vpnTlsObj/vpnOutbound/writeVpnConfig
// and the small helpers (spoofFingerprint/vpnInsecure/vpnPortRanges).
// NOTE: route rules (route_rules.go) are NOT ported yet — buildRouteRules
// treated as empty here. Режим «всё через VPN» работает и без них
// (route.final = proxy); adsBlock/presets подключатся вместе с route_rules.
use serde_json::{json, Map, Value};
use std::path::Path;

use crate::logging::log_add;
use crate::models::VpnProxy;
use crate::store;

pub fn vpn_extra(p: &VpnProxy, key: &str, def: &str) -> String {
    if let Some(e) = &p.extra {
        if let Some(v) = e.get(key) {
            if !v.is_empty() {
                return v.clone();
            }
        }
    }
    def.to_string()
}

pub fn spoof_fingerprint(ua: &str) -> String {
    let l = ua.to_lowercase();
    if l.contains("firefox") {
        "firefox".into()
    } else if l.contains("safari") || l.contains("iphone") || l.contains("ipad") || l.contains("ios") {
        "safari".into()
    } else if l.contains("edge") {
        "edge".into()
    } else {
        "chrome".into()
    }
}

// vpnSingboxFingerprint фильтрует отпечаток под то, что понимает uTLS sing-box.
pub fn vpn_singbox_fingerprint(fp: &str) -> String {
    let t = fp.trim().to_lowercase();
    match t.as_str() {
        "chrome" | "firefox" | "safari" | "ios" | "android" | "edge" | "360" | "qq" | "random" | "randomized" => t,
        _ => String::new(),
    }
}

// vpnInsecure понимает camelCase из конвертеров и lowercase из query-строк.
pub fn vpn_insecure(p: &VpnProxy) -> bool {
    for key in ["allowInsecure", "allowinsecure", "insecure", "skip-cert-verify", "skip_cert_verify"] {
        let v = vpn_extra(p, key, "").trim().to_lowercase();
        if v == "1" || v == "true" || v == "yes" {
            return true;
        }
    }
    false
}

// vpnPortRanges — «2000-4000,5000-6000» → ["2000:4000","5000:6000"].
// Соло-порт «5000» нормализуем в «5000:5000»: голое число sing-box отвергает.
// Сегменты уже в sing-box-формате («2000:4000» — из server_ports импорта
// sing-box JSON) пропускаем как есть: раньше «2000:4000» не содержал '-',
// раздувался до «2000:4000-2000:4000» и ломал конфиг.
pub fn vpn_port_ranges(mp: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in mp.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part.contains(':') {
            out.push(part.to_string());
            continue;
        }
        let part = if !part.contains('-') {
            format!("{}-{}", part, part)
        } else {
            part.to_string()
        };
        out.push(part.replacen('-', ":", 1));
    }
    out
}

pub fn vpn_tls_obj(p: &VpnProxy, spoof_ua: &str) -> Option<Value> {
    if p.proto == "ss" {
        return None;
    }
    let mut sec = vpn_extra(p, "security", "");
    if sec.is_empty() && p.proto != "vless" && p.proto != "vmess" {
        sec = "tls".into(); // trojan/hysteria2 — всегда TLS
    }
    let enabled = sec == "tls" || sec == "reality";
    let mut o = Map::new();
    o.insert("enabled".into(), json!(enabled));
    if !enabled {
        return Some(Value::Object(o));
    }
    o.insert(
        "server_name".into(),
        json!(vpn_extra(p, "sni", &vpn_extra(p, "host", &p.host))),
    );
    if vpn_insecure(p) {
        o.insert("insecure".into(), json!(true));
    }
    let mut fp = vpn_extra(p, "fp", "");
    if fp.is_empty() {
        fp = spoof_fingerprint(spoof_ua);
    }
    // hysteria2 не поддерживает uTLS — sing-box отвечает
    // "unsupported usage for uTLS" и соединение не работает
    if p.proto == "hysteria2" {
        fp = String::new();
    }
    let fp = vpn_singbox_fingerprint(&fp);
    if !fp.is_empty() {
        o.insert("utls".into(), json!({"enabled": true, "fingerprint": fp}));
    }
    if sec == "reality" {
        // у sing-box outbound-reality НЕТ поля handshake — иначе
        // «decode config: unknown field "handshake"»
        o.insert(
            "reality".into(),
            json!({"enabled": true, "public_key": vpn_extra(p, "pbk", ""), "short_id": vpn_extra(p, "sid", "")}),
        );
    }
    // ALPN: раньше читался только xray-путём — ключи с обязательным ALPN
    // (серверы с h2) через sing-box молча ломались. У sing-box это массив строк.
    let alpn = vpn_extra(p, "alpn", "");
    if !alpn.is_empty() {
        let list: Vec<String> = alpn
            .split(',')
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect();
        if !list.is_empty() {
            o.insert("alpn".into(), json!(list));
        }
    }
    Some(Value::Object(o))
}

pub fn vpn_outbound(p: &VpnProxy, spoof_ua: &str) -> Result<Value, String> {
    let cred = vpn_extra(p, "cred", "");
    let mut o = Map::new();
    o.insert("tag".into(), json!("proxy"));
    o.insert("server".into(), json!(p.host));
    o.insert("server_port".into(), json!(p.port));
    match p.proto.as_str() {
        "vless" => {
            if cred.is_empty() {
                return Err("в vless-ссылке нет UUID".into());
            }
            o.insert("type".into(), json!("vless"));
            o.insert("uuid".into(), json!(cred));
            let f = vpn_extra(p, "flow", "");
            if !f.is_empty() {
                o.insert("flow".into(), json!(f));
            }
        }
        "trojan" => {
            if cred.is_empty() {
                return Err("в trojan-ссылке нет пароля".into());
            }
            o.insert("type".into(), json!("trojan"));
            o.insert("password".into(), json!(cred));
        }
        "vmess" => {
            if cred.is_empty() {
                return Err("в vmess-ссылке нет UUID".into());
            }
            o.insert("type".into(), json!("vmess"));
            o.insert("uuid".into(), json!(cred));
            let aid: i64 = vpn_extra(p, "aid", "").parse().unwrap_or(0);
            o.insert("alter_id".into(), json!(aid));
            o.insert("security".into(), json!("auto"));
        }
        "ss" => {
            // как в xray-пути: пустые method/cred — ошибка генерации, а не
            // невнятный отказ ядра при старте
            if vpn_extra(p, "method", "").is_empty() || cred.is_empty() {
                return Err("в ss-ключе нет метода или пароля".into());
            }
            o.insert("type".into(), json!("shadowsocks"));
            o.insert("method".into(), json!(vpn_extra(p, "method", "")));
            o.insert("password".into(), json!(cred));
        }
        "hysteria2" => {
            o.insert("type".into(), json!("hysteria2"));
            o.insert("password".into(), json!(cred));
            let op = vpn_extra(p, "obfs-password", "");
            if !op.is_empty() {
                o.insert("obfs".into(), json!({"type": vpn_extra(p, "obfs", "salamander"), "password": op}));
            }
            // mport — port hopping: реальные UDP-порты сервера в диапазоне
            let mp = vpn_extra(p, "mport", "");
            if !mp.is_empty() {
                let sps = vpn_port_ranges(&mp);
                if !sps.is_empty() {
                    o.insert("server_ports".into(), json!(sps));
                }
            }
        }
        other => return Err(format!("протокол {} пока не поддерживается", other)),
    }
    if let Some(t) = vpn_tls_obj(p, spoof_ua) {
        o.insert("tls".into(), t);
    }
    let nt = vpn_extra(p, "type", &vpn_extra(p, "net", "tcp")).to_lowercase();
    match nt.as_str() {
        "ws" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("ws"));
            t.insert("path".into(), json!(vpn_extra(p, "path", "/")));
            let h = vpn_extra(p, "host", "");
            if !h.is_empty() {
                t.insert("headers".into(), json!({"Host": h}));
            }
            o.insert("transport".into(), Value::Object(t));
        }
        "grpc" => {
            o.insert("transport".into(), json!({"type": "grpc", "service_name": vpn_extra(p, "servicename", "")}));
        }
        "h2" | "http" => {
            // у sing-box host в http-транспорте — массив
            let mut t = Map::new();
            t.insert("type".into(), json!("http"));
            t.insert("path".into(), json!(vpn_extra(p, "path", "/")));
            let h = vpn_extra(p, "host", "");
            if !h.is_empty() {
                t.insert("host".into(), json!([h]));
            }
            o.insert("transport".into(), Value::Object(t));
        }
        "httpupgrade" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("httpupgrade"));
            t.insert("path".into(), json!(vpn_extra(p, "path", "/")));
            let h = vpn_extra(p, "host", "");
            if !h.is_empty() {
                t.insert("host".into(), json!(h));
            }
            o.insert("transport".into(), Value::Object(t));
        }
        "xhttp" | "splithttp" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("splithttp"));
            t.insert("path".into(), json!(vpn_extra(p, "path", "/")));
            let h = vpn_extra(p, "host", "");
            if !h.is_empty() {
                t.insert("host".into(), json!([h]));
            }
            o.insert("transport".into(), Value::Object(t));
        }
        _ => {}
    }
    Ok(Value::Object(o))
}

pub fn write_vpn_config(
    tools: &Path,
    p: &VpnProxy,
    port: i32,
    with_tun: bool,
    with_dns: bool,
    cfg_path: &Path,
    api_port: i32,
    tun_name: &str,
) -> Result<(), String> {
    let settings = store::load_vpn_settings(tools);
    let out = vpn_outbound(p, &settings.spoof_ua)?;
    let mut inbounds = vec![json!({
        "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port
    })];
    // auto_detect_interface всегда: привязка к текущему дефолт-интерфейсу —
    // при смене сети и наличии других туннелей соединение не уходит в петлю
    let mut route = Map::new();
    route.insert("final".into(), json!("proxy"));
    route.insert("auto_detect_interface".into(), json!(true));
    let mut cfg = Map::new();
    cfg.insert("log".into(), json!({"level": "info"}));
    cfg.insert("outbounds".into(), json!([out, {"type": "direct", "tag": "direct"}]));
    if with_tun {
        // TUN забирает весь трафик (включая DNS)
        let mut tun = Map::new();
        tun.insert("type".into(), json!("tun"));
        tun.insert("tag".into(), json!("tun"));
        tun.insert("interface_name".into(), json!(tun_name));
        // IPv6-адрес обязателен: sing-box добавляет ::/0-маршрут только при
        // наличии IPv6-адреса на TUN. Без него на dual-stack Windows IPv6
        // уходил через физический интерфейс мимо туннеля (утечка реального IP/DNS)
        tun.insert("address".into(), json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"]));
        tun.insert("auto_route".into(), json!(true));
        // стек TUN: system | gvisor | mixed; пусто = дефолт sing-box
        let tun_stack = settings.tun_stack.clone().unwrap_or_default();
        if !tun_stack.is_empty() {
            tun.insert("stack".into(), json!(tun_stack));
        }
        inbounds.push(Value::Object(tun));
    }
    if with_tun || with_dns {
        // DNS как в продакшене: DoH через туннель + системный резолвер для
        // адресов, которые ядро дозванивает само
        let mut dns = Map::new();
        dns.insert(
            "servers".into(),
            json!([
                {"tag": "dns", "type": "https", "server": "1.1.1.1", "detour": "proxy"},
                {"tag": "dns-local", "type": "local"}
            ]),
        );
        if with_tun {
            // hijack-dns: без него DNS приложений уходил в final=proxy как
            // обычный UDP:53 — «Подключено, но страницы не открываются»
            route.insert(
                "rules".into(),
                json!([{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}]),
            );
        }
        route.insert("default_domain_resolver".into(), json!("dns-local"));
        cfg.insert("dns".into(), Value::Object(dns));
    }
    // маршрутизация (route_rules.rs): только в основном конфиге подключения —
    // во временных пинг-конфигах (apiPort==0) правила только замедляли бы старт
    if api_port > 0 {
        let rr = crate::route_rules::build_route_rules(&settings);
        if !rr.is_empty() {
            crate::route_rules::inject_sing_box(&mut route, &rr, tools);
            if let Some(dns) = cfg.get_mut("dns").and_then(|v| v.as_object_mut()) {
                crate::route_rules::inject_sing_box_dns(dns, &rr, tools);
            }
            log_add("route", &format!("правила: {}", rr.route_summary()));
        }
    }
    cfg.insert("inbounds".into(), json!(inbounds));
    cfg.insert("route".into(), Value::Object(route));
    // встроенный clash-API — счётчики трафика для графика скорости.
    // ТОЛЬКО в основном конфиге: в тестовых конфигах порт уже занят главным ядром.
    if api_port > 0 {
        cfg.insert(
            "experimental".into(),
            json!({"clash_api": {"external_controller": format!("127.0.0.1:{}", api_port)}}),
        );
    }
    let data = serde_json::to_string_pretty(&Value::Object(cfg)).map_err(|e| e.to_string())?;
    let _ = std::fs::create_dir_all(crate::paths::vpn_dir(tools));
    std::fs::write(cfg_path, data.as_bytes()).map_err(|e| e.to_string())
}

// coreForKey — каким ядром работать с этим ключом: xhttp есть только
// у Xray, hysteria2 — только у sing-box; остальное — выбранное ядро.
pub fn core_for_key(p: &VpnProxy, preferred: &str) -> String {
    let net = vpn_extra(p, "type", &vpn_extra(p, "net", "tcp")).to_lowercase();
    if net == "xhttp" || net == "splithttp" {
        return "xray".into();
    }
    if p.proto == "hysteria2" {
        return "sing-box".into();
    }
    preferred.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(proto: &str, extra: serde_json::Value) -> VpnProxy {
        let mut map = std::collections::HashMap::new();
        if let Value::Object(o) = extra {
            for (k, v) in o {
                if let Value::String(s) = v {
                    map.insert(k, s);
                }
            }
        }
        VpnProxy {
            id: "t".into(),
            proto: proto.into(),
            name: "t".into(),
            host: "1.2.3.4".into(),
            port: 443,
            raw: String::new(),
            sub_id: None,
            manual: None,
            extra: Some(map),
        }
    }

    #[test]
    fn vless_reality_ws_config() {
        let p = proxy("vless", serde_json::json!({
            "cred": "u-1", "flow": "xtls-rprx-vision", "security": "reality",
            "pbk": "PUB", "sid": "SID", "sni": "real.sni", "fp": "chrome",
            "type": "ws", "path": "/ws", "host": "ws.host"
        }));
        let out = vpn_outbound(&p, "").unwrap();
        assert_eq!(out["type"], "vless");
        assert_eq!(out["tls"]["enabled"], true);
        assert_eq!(out["tls"]["server_name"], "real.sni");
        assert_eq!(out["tls"]["reality"]["public_key"], "PUB");
        assert_eq!(out["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(out["transport"]["type"], "ws");
        assert_eq!(out["transport"]["headers"]["Host"], "ws.host");
    }

    #[test]
    fn ss_no_tls_even_without_security() {
        let p = proxy("ss", serde_json::json!({"method": "aes-128-gcm", "cred": "pw"}));
        let out = vpn_outbound(&p, "").unwrap();
        assert_eq!(out["type"], "shadowsocks");
        assert!(out.get("tls").is_none());
        assert!(out.get("transport").is_none());
    }

    #[test]
    fn trojan_default_tls_and_hysteria_mport() {
        let p = proxy("trojan", serde_json::json!({"cred": "pw"}));
        let out = vpn_outbound(&p, "Happ/3.26.0/iOS/123").unwrap();
        assert_eq!(out["tls"]["enabled"], true);
        // fp из spoof-ua (iOS → safari)
        assert_eq!(out["tls"]["utls"]["fingerprint"], "safari");

        let h = proxy("hysteria2", serde_json::json!({"cred": "pw", "mport": "2000-4000,5000", "obfs-password": "op"}));
        let out = vpn_outbound(&h, "").unwrap();
        assert_eq!(out["obfs"]["type"], "salamander");
        assert_eq!(out["server_ports"], json!(["2000:4000", "5000:5000"]));
        // hysteria2 без uTLS
        assert!(out["tls"].get("utls").is_none());
    }

    #[test]
    fn missing_cred_is_error() {
        let p = proxy("vless", serde_json::json!({}));
        assert!(vpn_outbound(&p, "").is_err());
    }

    #[test]
    fn port_ranges_singbox_colon_format() {
        // server_ports из sing-box JSON приходят уже с ':' — раньше сегмент без
        // '-' раздувался в «2000:4000-2000:4000» и ломал конфиг
        assert_eq!(vpn_port_ranges("2000:4000,5000:6000"), vec!["2000:4000", "5000:6000"]);
        assert_eq!(vpn_port_ranges("2000-4000,5000"), vec!["2000:4000", "5000:5000"]);
    }

    #[test]
    fn fingerprint_filter() {
        assert_eq!(vpn_singbox_fingerprint("Chrome"), "chrome");
        assert_eq!(vpn_singbox_fingerprint("unsafe"), "");
        assert_eq!(vpn_singbox_fingerprint("  randomized "), "randomized");
    }
}

// ---------- Xray (XHTTP и прочие Xray-транспорты) ----------

// xrayOutbound — VpnProxy в outbound Xray. Hysteria2 ядро не умеет.
pub fn xray_outbound(p: &VpnProxy, spoof_ua: &str) -> Result<Value, String> {
    let cred = vpn_extra(p, "cred", "");
    let mut net = vpn_extra(p, "type", &vpn_extra(p, "net", "tcp")).to_lowercase();
    if net == "splithttp" {
        net = "xhttp".into();
    }
    let mut sec = vpn_extra(p, "security", "");
    // TLS по умолчанию — только трояну; ss без явного security — голый ss
    if sec.is_empty() && p.proto == "trojan" {
        sec = "tls".into();
    }
    let mut fp = vpn_extra(p, "fp", "");
    if fp.is_empty() {
        fp = spoof_fingerprint(spoof_ua);
    }
    let sni = vpn_extra(p, "sni", &vpn_extra(p, "host", &p.host));

    let mut out: Map<String, Value> = Map::new();
    match p.proto.as_str() {
        "vless" => {
            if cred.is_empty() {
                return Err("в vless-ссылке нет UUID".into());
            }
            let mut user = Map::new();
            user.insert("id".into(), json!(cred));
            user.insert("encryption".into(), json!("none"));
            // flow (xtls-rprx-vision) живёт только на голом tcp; с ws/xhttp
            // Xray отвергает конфиг
            let flow = vpn_extra(p, "flow", "");
            if !flow.is_empty() && net == "tcp" {
                user.insert("flow".into(), json!(flow));
            }
            out.insert("protocol".into(), json!("vless"));
            out.insert(
                "settings".into(),
                json!({"vnext": [{"address": p.host, "port": p.port, "users": [Value::Object(user)]}]}),
            );
        }
        "vmess" => {
            if cred.is_empty() {
                return Err("в vmess-ссылке нет UUID".into());
            }
            let aid: i64 = vpn_extra(p, "aid", "").parse().unwrap_or(0);
            out.insert("protocol".into(), json!("vmess"));
            out.insert(
                "settings".into(),
                json!({"vnext": [{"address": p.host, "port": p.port, "users": [{"id": cred, "alterId": aid, "security": "auto"}]}]}),
            );
        }
        "trojan" => {
            if cred.is_empty() {
                return Err("в trojan-ссылке нет пароля".into());
            }
            out.insert("protocol".into(), json!("trojan"));
            out.insert(
                "settings".into(),
                json!({"servers": [{"address": p.host, "port": p.port, "password": cred}]}),
            );
        }
        "ss" => {
            if cred.is_empty() || vpn_extra(p, "method", "").is_empty() {
                // как в sing-box-пути: пустые method/cred — ошибка генерации, а
                // не невнятный отказ xray при старте (раньше проверялся только
                // пароль, и конфиг с пустым method уходил в ядро)
                return Err("в ss-ссылке нет метода или пароля".into());
            }
            out.insert("protocol".into(), json!("shadowsocks"));
            out.insert(
                "settings".into(),
                json!({"servers": [{"address": p.host, "port": p.port, "method": vpn_extra(p, "method", ""), "password": cred}]}),
            );
        }
        other => return Err(format!("ядро Xray не поддерживает {} — для него выбери sing-box", other)),
    }
    out.insert("tag".into(), json!("proxy"));

    let mut ss = Map::new();
    ss.insert("network".into(), json!(net));
    match sec.as_str() {
        "tls" => {
            ss.insert("security".into(), json!("tls"));
            let mut tls = Map::new();
            tls.insert("serverName".into(), json!(sni));
            // vpnInsecure понимает и camelCase из подписок, и lowercase из query
            if vpn_insecure(p) {
                tls.insert("allowInsecure".into(), json!(true));
            }
            if !fp.is_empty() {
                tls.insert("fingerprint".into(), json!(fp));
            }
            let alpn = vpn_extra(p, "alpn", "");
            if !alpn.is_empty() {
                let list: Vec<String> = alpn
                    .split(',')
                    .map(|a| a.trim().to_string())
                    .filter(|a| !a.is_empty())
                    .collect();
                if !list.is_empty() {
                    tls.insert("alpn".into(), json!(list));
                }
            }
            ss.insert("tlsSettings".into(), Value::Object(tls));
        }
        "reality" => {
            ss.insert("security".into(), json!("reality"));
            ss.insert(
                "realitySettings".into(),
                json!({
                    "show": false, "fingerprint": fp, "serverName": sni,
                    "publicKey": vpn_extra(p, "pbk", ""), "shortId": vpn_extra(p, "sid", ""), "spiderX": "/"
                }),
            );
        }
        _ => {}
    }
    let path = vpn_extra(p, "path", "/");
    let host = vpn_extra(p, "host", &sni);
    match net.as_str() {
        "ws" => {
            ss.insert("wsSettings".into(), json!({"path": path, "headers": {"Host": host}}));
        }
        "grpc" => {
            ss.insert("grpcSettings".into(), json!({"serviceName": vpn_extra(p, "servicename", "")}));
        }
        "httpupgrade" => {
            ss.insert("httpupgradeSettings".into(), json!({"path": path, "host": host}));
        }
        // h2 — штатное значение в clash-подписках и vless-ссылках (type=h2):
        // раньше уходило network=h2 без httpSettings, сервер отклонял ключ
        "h2" | "http" => {
            ss.insert("httpSettings".into(), json!({"path": path, "host": [host]}));
        }
        "xhttp" => {
            // mode из ключа: auto/packet-up/stream-up/stream-one
            let mut mode = vpn_extra(p, "mode", "auto").to_lowercase();
            if mode != "auto" && mode != "packet-up" && mode != "stream-up" && mode != "stream-one" {
                mode = "auto".into();
            }
            ss.insert("xhttpSettings".into(), json!({"mode": mode, "path": path, "host": host}));
        }
        _ => {}
    }
    out.insert("streamSettings".into(), Value::Object(ss));
    Ok(Value::Object(out))
}

// buildXrayConfig — http-инбаунд (системный прокси) + outbound.
pub fn build_xray_config(tools: &Path, p: &VpnProxy, port: i32, cfg_path: &Path, with_route: bool) -> Result<(), String> {
    let settings = store::load_vpn_settings(tools);
    let outbound = xray_outbound(p, &settings.spoof_ua)?;
    let mut outbounds = vec![outbound, json!({"protocol": "freedom", "tag": "direct"})];
    let mut cfg = Map::new();
    cfg.insert("log".into(), json!({"loglevel": "warning"}));
    cfg.insert("inbounds".into(), json!([{"listen": "127.0.0.1", "port": port, "protocol": "http"}]));
    if with_route {
        let rr = crate::route_rules::build_route_rules(&settings);
        if !rr.is_empty() {
            let (obs, _) = crate::route_rules::inject_xray(&mut cfg, &rr, std::mem::take(&mut outbounds));
            outbounds = obs;
            log_add("route", &format!("правила (xray): {}", rr.route_summary()));
        }
    }
    cfg.insert("outbounds".into(), json!(outbounds));
    store::atomic_write_json(cfg_path, &Value::Object(cfg))
}

// buildXrayChainConfig — outbound-конфиг для TUN-цепочки: SOCKS5-инбаунд
// с UDP вместо HTTP (UDP-пакеты идут в Xray поверх XUDP).
pub fn build_xray_chain_config(tools: &Path, p: &VpnProxy, port: i32, cfg_path: &Path) -> Result<(), String> {
    let settings = store::load_vpn_settings(tools);
    let outbound = xray_outbound(p, &settings.spoof_ua)?;
    let cfg = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"auth": "noauth", "udp": true}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
    });
    store::atomic_write_json(cfg_path, &cfg)
}

// writeChainTunConfig — конфиг sing-box «TUN-фронта» для цепочки xray+TUN:
// sing-box забирает весь трафик (mixed + tun) и заворачивает его в
// SOCKS-инбаунд xray; адрес сервера исключается правилом direct.
pub fn write_chain_tun_config(
    tools: &Path,
    server_ip: &str,
    x_port: i32,
    port: i32,
    api_port: i32,
    cfg_path: &Path,
    tun_name: &str,
) -> Result<(), String> {
    let settings = store::load_vpn_settings(tools);
    let mut tun = Map::new();
    tun.insert("type".into(), json!("tun"));
    tun.insert("tag".into(), json!("tun"));
    tun.insert("interface_name".into(), json!(tun_name));
    // IPv6-адрес обязателен: без него sing-box не добавляет ::/0-маршрут и
    // IPv6-трафик уходит мимо TUN-цепочки (см. write_vpn_config)
    tun.insert("address".into(), json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"]));
    tun.insert("auto_route".into(), json!(true));
    let tun_stack = settings.tun_stack.clone().unwrap_or_default();
    if !tun_stack.is_empty() {
        tun.insert("stack".into(), json!(tun_stack));
    }
    let server_cidr = if server_ip.contains(':') {
        format!("{}/128", server_ip)
    } else {
        format!("{}/32", server_ip)
    };
    let mut cfg = Map::new();
    cfg.insert("log".into(), json!({"level": "info"}));
    cfg.insert(
        "inbounds".into(),
        json!([
            {"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port},
            Value::Object(tun)
        ]),
    );
    cfg.insert(
        "outbounds".into(),
        json!([
            // socks-аутбаунд к инбаунду xray: TCP через CONNECT, UDP через
            // SOCKS5 UDP ASSOCIATE (http-аутбаунд UDP не умеет вовсе)
            {"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": x_port, "version": "5"},
            {"type": "direct", "tag": "direct"}
        ]),
    );
    let mut route = Map::new();
    route.insert("final".into(), json!("proxy"));
    route.insert("auto_detect_interface".into(), json!(true));
    route.insert(
        "rules".into(),
        json!([
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
            {"ip_cidr": [server_cidr], "outbound": "direct"}
        ]),
    );
    route.insert("default_domain_resolver".into(), json!("dns-local"));
    cfg.insert("route".into(), Value::Object(route));
    cfg.insert(
        "dns".into(),
        json!({"servers": [
            {"tag": "dns", "type": "https", "server": "1.1.1.1", "detour": "proxy"},
            {"tag": "dns-local", "type": "local"}
        ]}),
    );
    cfg.insert(
        "experimental".into(),
        json!({"clash_api": {"external_controller": format!("127.0.0.1:{}", api_port)}}),
    );
    // маршрутизация — на sing-box-фронте: в сам xray правила не дублируем
    let rr = crate::route_rules::build_route_rules(&settings);
    if !rr.is_empty() {
        if let Some(r) = cfg.get_mut("route").and_then(|v| v.as_object_mut()) {
            crate::route_rules::inject_sing_box(r, &rr, tools);
        }
        if let Some(d) = cfg.get_mut("dns").and_then(|v| v.as_object_mut()) {
            crate::route_rules::inject_sing_box_dns(d, &rr, tools);
        }
        log_add("route", &format!("правила: {}", rr.route_summary()));
    }
    let data = serde_json::to_string_pretty(&Value::Object(cfg)).map_err(|e| e.to_string())?;
    let _ = std::fs::create_dir_all(crate::paths::vpn_dir(tools));
    std::fs::write(cfg_path, data.as_bytes()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod xray_tests {
    use super::*;

    #[test]
    fn vless_xhttp_config() {
        let p = VpnProxy {
            id: "t".into(),
            proto: "vless".into(),
            name: "t".into(),
            host: "5.6.7.8".into(),
            port: 2096,
            raw: String::new(),
            sub_id: None,
            manual: None,
            extra: Some({
                let mut m = std::collections::HashMap::new();
                m.insert("cred".to_string(), "u-9".to_string());
                m.insert("type".to_string(), "splithttp".to_string());
                m.insert("path".to_string(), "/xpath".to_string());
                m.insert("security".to_string(), "tls".to_string());
                m.insert("sni".to_string(), "x.example.com".to_string());
                m
            }),
        };
        let out = xray_outbound(&p, "").unwrap();
        assert_eq!(out["protocol"], "vless");
        let ss = &out["streamSettings"];
        assert_eq!(ss["network"], "xhttp");
        assert_eq!(ss["security"], "tls");
        assert_eq!(ss["tlsSettings"]["serverName"], "x.example.com");
        assert_eq!(ss["xhttpSettings"]["mode"], "auto");
        assert_eq!(ss["xhttpSettings"]["path"], "/xpath");
    }

    #[test]
    fn ss_bare_no_tls_and_hysteria_rejected() {
        let mut p = VpnProxy {
            id: "t".into(),
            proto: "ss".into(),
            name: "t".into(),
            host: "1.1.1.1".into(),
            port: 8388,
            raw: String::new(),
            sub_id: None,
            manual: None,
            extra: Some({
                let mut m = std::collections::HashMap::new();
                m.insert("method".to_string(), "aes-128-gcm".to_string());
                m.insert("cred".to_string(), "pw".to_string());
                m
            }),
        };
        let out = xray_outbound(&p, "").unwrap();
        assert!(out["streamSettings"].get("security").is_none());

        p.proto = "hysteria2".into();
        assert!(xray_outbound(&p, "").is_err());
    }
}
