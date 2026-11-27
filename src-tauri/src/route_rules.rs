// Traffic routing rules - port of Go route_rules.go.
// Режимы «всё через VPN» / «РФ напрямую» / «избирательный», блок рекламы
// (Hagezi PRO, локальный rule-set .srs) и ручные списки доменов.
// Списки вшиты в exe (assets/route): itdoginfo/allow-domains + пресеты сервисов.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::logging::log_add;
use crate::models::VpnSettings;

const MODE_ALL: &str = "all";
const MODE_RU_DIRECT: &str = "ru-direct";
const MODE_SELECTIVE: &str = "selective";

const PRESETS: [&str; 4] = ["youtube", "telegram", "discord", "openai"];

// вшитые списки (go:embed → include_bytes!)
fn embedded_list(name: &str) -> Option<&'static [u8]> {
    match name {
        "ru_direct.lst" => Some(include_bytes!("../assets/route/ru_direct.lst")),
        "svc_youtube.lst" => Some(include_bytes!("../assets/route/svc_youtube.lst")),
        "svc_telegram.lst" => Some(include_bytes!("../assets/route/svc_telegram.lst")),
        "svc_discord.lst" => Some(include_bytes!("../assets/route/svc_discord.lst")),
        "svc_openai.lst" => Some(include_bytes!("../assets/route/svc_openai.lst")),
        "ads_pro.lst.gz" => Some(include_bytes!("../assets/route/ads_pro.lst.gz")),
        "ads_pro.srs" => Some(include_bytes!("../assets/route/ads_pro.srs")),
        _ => None,
    }
}

// normalizeRouteMode — неизвестное/пустое значение = прежнее поведение.
pub fn normalize_route_mode(m: &str) -> String {
    match m {
        MODE_RU_DIRECT | MODE_SELECTIVE => m.to_string(),
        _ => MODE_ALL.to_string(),
    }
}

// Быстрый эквивалент route_domain_re: метки из [a-z0-9-] (не начинающиеся/
// заканчивающиеся на '-') через точку, минимум две метки. Ручной валидатор
// вместо regex: 213k доменов рекламы regex-ом парсятся минутами.
fn is_domain(s: &str) -> bool {
    if !s.contains('.') {
        return false;
    }
    for label in s.split('.') {
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return false;
        }
        let ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        if !ok(b[0]) || !ok(b[b.len() - 1]) {
            return false;
        }
        if !b.iter().all(|&c| ok(c) || c == b'-') {
            return false;
        }
    }
    true
}

// parse_cidr — канонизация: «1.2.3.4/8» → «1.0.0.0/8» (немаскированные
// хост-биты ядра трактуют по-разному или отвергают конфиг).
fn parse_cidr(s: &str) -> Option<String> {
    let (ip_s, prefix_s) = s.split_once('/')?;
    let ip: IpAddr = ip_s.parse().ok()?;
    let prefix: u8 = prefix_s.parse().ok()?;
    let masked = match ip {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return None;
            }
            let bits = u32::from(v4);
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
            IpAddr::V4(Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return None;
            }
            let bits = u128::from(v6);
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix as u32) };
            IpAddr::V6(Ipv6Addr::from(bits & mask))
        }
    };
    Some(format!("{}/{}", masked, prefix))
}

// routeParseLine — строка списка → домен или CIDR (None — пропустить).
pub fn route_parse_line(ln: &str) -> (String, String) {
    let mut s = ln.trim().to_lowercase();
    if s.is_empty() || s.starts_with('#') || s.starts_with('!') {
        return (String::new(), String::new());
    }
    // «example.com # комментарий» — обрезаем по пробелу/табу/#
    if let Some(i) = s.find(|c| c == ' ' || c == '\t' || c == '#') {
        s.truncate(i);
        s = s.trim().to_string();
    }
    if s.is_empty() {
        return (String::new(), String::new());
    }
    let s = s.strip_prefix("full:").unwrap_or(&s);
    // «domain:example.com» = домен и поддомены — это ровно текущая семантика
    // суффикс-матча; раньше такие строки (частый формат чужих списков) молча
    // выбрасывались, т.к. is_domain отвергал «:»
    let s = s.strip_prefix("domain:").unwrap_or(s);
    let s = s.strip_prefix("*.").unwrap_or(s);
    let mut s = s.strip_suffix('.').unwrap_or(s).to_string();
    // [fd00::1] в скобках: парсер IP скобки не принимает — строка тихо терялась
    if s.starts_with('[') && s.ends_with(']') {
        s = s[1..s.len() - 1].to_string();
    }
    if s.contains('/') {
        if let Some(c) = parse_cidr(&s) {
            return (String::new(), c);
        }
    } else if let Ok(ip) = s.parse::<IpAddr>() {
        // голый IP → /32 (IPv4) или /128 (IPv6)
        return match ip {
            IpAddr::V4(_) => (String::new(), format!("{}/32", s)),
            IpAddr::V6(_) => (String::new(), format!("{}/128", s)),
        };
    } else if is_domain(&s) {
        return (s, String::new());
    }
    (String::new(), String::new())
}

// routeExtract — строки → уникальные отсортированные домены и CIDR.
// HashSet (как map в Go): Vec::contains на 600k строк — O(n²), минуты.
pub fn route_extract(lines: &[&str]) -> (Vec<String>, Vec<String>) {
    let mut dm: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut cm: std::collections::HashSet<String> = std::collections::HashSet::new();
    for ln in lines {
        let (d, c) = route_parse_line(ln);
        if !d.is_empty() {
            dm.insert(d);
        }
        if !c.is_empty() {
            cm.insert(c);
        }
    }
    let mut domains: Vec<String> = dm.into_iter().collect();
    let mut cidrs: Vec<String> = cm.into_iter().collect();
    domains.sort();
    cidrs.sort();
    (domains, cidrs)
}

fn route_read_lines(name: &str) -> Vec<String> {
    match embedded_list(name) {
        Some(data) => String::from_utf8_lossy(data).split('\n').map(|s| s.to_string()).collect(),
        None => Vec::new(),
    }
}

// ---------- реклама: домены из gzip + кэш в памяти ----------

static ADS_CACHE: Mutex<Option<std::sync::Arc<Vec<String>>>> = Mutex::new(None);

pub fn route_ads_domains() -> std::sync::Arc<Vec<String>> {
    let mut g = ADS_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = g.as_ref() {
        return c.clone();
    }
    let data = match embedded_list("ads_pro.lst.gz") {
        Some(d) => d,
        None => {
            *g = Some(std::sync::Arc::new(Vec::new()));
            return g.as_ref().unwrap().clone();
        }
    };
    let mut dec = flate2::read::GzDecoder::new(data);
    let mut raw = String::new();
    if std::io::Read::read_to_string(&mut dec, &mut raw).is_err() {
        *g = Some(std::sync::Arc::new(Vec::new()));
        return g.as_ref().unwrap().clone();
    }
    let lines: Vec<&str> = raw.split('\n').collect();
    let (domains, _) = route_extract(&lines);
    let arc = std::sync::Arc::new(domains);
    *g = Some(arc.clone());
    arc
}

// ---------- сборка правил по настройкам ----------

#[derive(Debug, Default)]
pub struct RouteRuleSet {
    pub mode: String,
    pub direct_domains: Vec<String>,
    pub direct_cidrs: Vec<String>,
    pub proxy_domains: Vec<String>,
    pub proxy_cidrs: Vec<String>,
    pub block_domains: Vec<String>,
    pub block_cidrs: Vec<String>,
    pub ads: bool,
    pub ads_count: usize,
}

impl RouteRuleSet {
    pub fn is_empty(&self) -> bool {
        !self.ads
            && self.direct_domains.len()
                + self.direct_cidrs.len()
                + self.proxy_domains.len()
                + self.proxy_cidrs.len()
                + self.block_domains.len()
                + self.block_cidrs.len()
                == 0
    }

    // routeSummary — строка для лога: что реально попало в конфиг.
    pub fn route_summary(&self) -> String {
        let mut b = String::new();
        match self.mode.as_str() {
            MODE_RU_DIRECT => b.push_str("напрямую"),
            MODE_SELECTIVE => b.push_str("избирательный"),
            _ => b.push_str("всё через VPN"),
        }
        let mut part = |name: &str, n: usize| {
            if n > 0 {
                b.push_str(&format!(" · {} {}", name, n));
            }
        };
        part("direct", self.direct_domains.len() + self.direct_cidrs.len());
        part("proxy", self.proxy_domains.len() + self.proxy_cidrs.len());
        part("блок", self.block_domains.len() + self.block_cidrs.len());
        if self.ads {
            b.push_str(&format!(" · реклама {}", self.ads_count));
        }
        b
    }
}

// buildRouteRules — списки правил по настройкам.
pub fn build_route_rules(s: &VpnSettings) -> RouteRuleSet {
    let mut rr = RouteRuleSet {
        mode: normalize_route_mode(&s.route_mode.clone().unwrap_or_default()),
        ..Default::default()
    };
    // блок — во всех режимах: ручной список всегда, реклама по тумблеру
    let block = s.route_block_custom.clone().unwrap_or_default();
    if !block.trim().is_empty() {
        let lines: Vec<&str> = block.split('\n').collect();
        let (d, c) = route_extract(&lines);
        rr.block_domains = d;
        rr.block_cidrs = c;
    }
    rr.ads = s.ads_block.unwrap_or(false);
    if rr.ads {
        rr.ads_count = route_ads_domains().len();
    }
    let mut d_lines: Vec<String> = Vec::new();
    if rr.mode == MODE_RU_DIRECT {
        d_lines.extend(route_read_lines("ru_direct.lst"));
    }
    let direct = s.route_direct_custom.clone().unwrap_or_default();
    if !direct.trim().is_empty() {
        d_lines.extend(direct.split('\n').map(|x| x.to_string()));
    }
    if !d_lines.is_empty() {
        let refs: Vec<&str> = d_lines.iter().map(|x| x.as_str()).collect();
        let (d, c) = route_extract(&refs);
        rr.direct_domains = d;
        rr.direct_cidrs = c;
    }
    if rr.mode == MODE_SELECTIVE {
        let mut p_lines: Vec<String> = Vec::new();
        for key in PRESETS {
            if s.route_presets.as_ref().and_then(|m| m.get(key)).copied().unwrap_or(false) {
                p_lines.extend(route_read_lines(&format!("svc_{}.lst", key)));
            }
        }
        let proxy = s.route_proxy_custom.clone().unwrap_or_default();
        if !proxy.trim().is_empty() {
            p_lines.extend(proxy.split('\n').map(|x| x.to_string()));
        }
        if !p_lines.is_empty() {
            let refs: Vec<&str> = p_lines.iter().map(|x| x.as_str()).collect();
            let (d, c) = route_extract(&refs);
            rr.proxy_domains = d;
            rr.proxy_cidrs = c;
        }
    }
    rr
}

// ---------- sing-box ----------

// ensureAdsSrs — разворачивает вшитый ads_pro.srs в vpn\lists (один раз).
pub fn ensure_ads_srs(tools: &Path) -> (PathBuf, bool) {
    let dir = crate::paths::vpn_dir(tools).join("lists");
    let path = dir.join("ads_pro.srs");
    if let Ok(st) = std::fs::metadata(&path) {
        if st.len() > 0 {
            return (path, true);
        }
    }
    let blob = match embedded_list("ads_pro.srs") {
        Some(b) => b,
        None => return (PathBuf::new(), false),
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return (PathBuf::new(), false);
    }
    // tmp + rename: обрыв посреди записи оставлял обрезанный файл ненулевого
    // размера, и проверка «size > 0» навсегда консервировала его. Имя tmp
    // уникально: два параллельных подключения писали в один .tmp, смешанное
    // содержимое уезжало в rename и консервировало битый .srs.
    use std::sync::atomic::{AtomicU64, Ordering};
    static SRS_SEQ: AtomicU64 = AtomicU64::new(0);
    let tmp = PathBuf::from(format!(
        "{}.{}.{}.tmp",
        path.display(),
        std::process::id(),
        SRS_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let write_ok = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(blob)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_ok {
        let _ = std::fs::remove_file(&tmp);
        log_add("route", &format!("ads_pro.srs не записался: {}", e));
        return (PathBuf::new(), false);
    }
    if std::fs::rename(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return (PathBuf::new(), false);
    }
    (path, true)
}

fn add_rule(rules: &mut Vec<Value>, r: Map<String, Value>) {
    rules.push(Value::Object(r));
}

// routeInjectSingBox — дописывает в route-объект правила блок/direct/proxy.
// Вызывается ПОСЛЕ служебных правил (sniff, hijack-dns): матчинг сверху вниз.
// Реклама — локальным rule-set'ом: 213k доменов инлайном раздули бы JSON.
pub fn inject_sing_box(route: &mut Map<String, Value>, rr: &RouteRuleSet, tools: &Path) {
    if rr.is_empty() {
        return;
    }
    let mut rules: Vec<Value> = route
        .get("rules")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if rr.ads {
        let (path, ok) = ensure_ads_srs(tools);
        if ok {
            let sets: Vec<Value> = route
                .get("rule_set")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut sets = sets;
            sets.push(json!({"type": "local", "tag": "route-ads", "path": path.display().to_string(), "format": "binary"}));
            route.insert("rule_set".into(), json!(sets));
            add_rule(&mut rules, json!({"rule_set": ["route-ads"], "action": "reject"}).as_object().unwrap().clone());
        } else {
            // srs не записался (диск недоступен) — редкий фолбэк инлайном
            let d = route_ads_domains();
            if !d.is_empty() {
                add_rule(&mut rules, json!({"domain_suffix": d, "action": "reject"}).as_object().unwrap().clone());
            }
        }
    }
    if !rr.block_domains.is_empty() || !rr.block_cidrs.is_empty() {
        let mut r = Map::new();
        r.insert("action".into(), json!("reject"));
        if !rr.block_domains.is_empty() {
            r.insert("domain_suffix".into(), json!(rr.block_domains));
        }
        if !rr.block_cidrs.is_empty() {
            r.insert("ip_cidr".into(), json!(rr.block_cidrs));
        }
        add_rule(&mut rules, r);
    }
    if !rr.direct_domains.is_empty() || !rr.direct_cidrs.is_empty() {
        let mut r = Map::new();
        r.insert("outbound".into(), json!("direct"));
        if !rr.direct_domains.is_empty() {
            r.insert("domain_suffix".into(), json!(rr.direct_domains));
        }
        if !rr.direct_cidrs.is_empty() {
            r.insert("ip_cidr".into(), json!(rr.direct_cidrs));
        }
        add_rule(&mut rules, r);
    }
    if !rr.proxy_domains.is_empty() || !rr.proxy_cidrs.is_empty() {
        let mut r = Map::new();
        r.insert("outbound".into(), json!("proxy"));
        if !rr.proxy_domains.is_empty() {
            r.insert("domain_suffix".into(), json!(rr.proxy_domains));
        }
        if !rr.proxy_cidrs.is_empty() {
            r.insert("ip_cidr".into(), json!(rr.proxy_cidrs));
        }
        add_rule(&mut rules, r);
    }
    if !rules.is_empty() {
        route.insert("rules".into(), json!(rules));
    }
    if rr.mode == MODE_SELECTIVE {
        route.insert("final".into(), json!("direct")); // всё мимо пресетов — напрямую
    }
}

// routeInjectSingBoxDNS — DNS-правила под режим. Домены мимо VPN резолвятся
// системно, домены через VPN — DoH по туннелю, реклама/блок — reject на DNS.
pub fn inject_sing_box_dns(dns: &mut Map<String, Value>, rr: &RouteRuleSet, tools: &Path) {
    if rr.is_empty() {
        return;
    }
    let mut dr: Vec<Value> = Vec::new();
    if rr.ads {
        let (_, ok) = ensure_ads_srs(tools);
        if ok {
            dr.push(json!({"rule_set": ["route-ads"], "action": "reject"}));
        } else {
            let d = route_ads_domains();
            if !d.is_empty() {
                dr.push(json!({"domain_suffix": d, "action": "reject"}));
            }
        }
    }
    if !rr.block_domains.is_empty() {
        dr.push(json!({"domain_suffix": rr.block_domains, "action": "reject"}));
    }
    if !rr.direct_domains.is_empty() {
        dr.push(json!({"domain_suffix": rr.direct_domains, "server": "dns-local"}));
    }
    if !rr.proxy_domains.is_empty() {
        dr.push(json!({"domain_suffix": rr.proxy_domains, "server": "dns"}));
    }
    if dr.is_empty() {
        return;
    }
    dns.insert("rules".into(), json!(dr));
    if rr.mode == MODE_SELECTIVE {
        // избирательный режим: дефолтный резолвер — системный, DoH только для
        // proxy-доменов. Серверы ищем ПО ТЕГУ, а не по позиции.
        if let Some(servers) = dns.get_mut("servers").and_then(|v| v.as_array_mut()) {
            if servers.len() >= 2 {
                let mut dns_idx = None;
                let mut local_idx = None;
                for (i, sv) in servers.iter().enumerate() {
                    if let Some(m) = sv.as_object() {
                        match m.get("tag").and_then(|t| t.as_str()) {
                            Some("dns") => dns_idx = Some(i),
                            Some("dns-local") => local_idx = Some(i),
                            _ => {}
                        }
                    }
                }
                if let (Some(di), Some(li)) = (dns_idx, local_idx) {
                    servers.swap(di, li);
                }
            }
        }
    }
}

// ---------- xray (готово для этапа xray-конфигов) ----------

// routeInjectXray — routing.rules + blackhole.
// ВАЖНО: в Xray домен БЕЗ префикса матчит ПОДСТРОКУ («yandex.net» ловил и
// yandex.netflix.com, а gosuslugi.ru.evil.com уходил в direct). Префикс
// "domain:" матчит домен и поддомены — как domain_suffix у sing-box.
fn xray_domain_list(domains: &[String]) -> Vec<String> {
    domains
        .iter()
        .filter(|d| !d.is_empty())
        .map(|d| {
            if d.contains(':') {
                // префикс xray уже указан (domain:/full:/geosite:) — не дублируем
                d.clone()
            } else {
                format!("domain:{}", d)
            }
        })
        .collect()
}

pub fn inject_xray(
    cfg: &mut Map<String, Value>,
    rr: &RouteRuleSet,
    mut outbounds: Vec<Value>,
) -> (Vec<Value>, bool) {
    if rr.is_empty() {
        return (outbounds, false);
    }
    let mut rules: Vec<Value> = Vec::new();
    let mut need_block = false;
    if rr.ads {
        let d = route_ads_domains();
        if !d.is_empty() {
            rules.push(json!({"type": "field", "domain": xray_domain_list(&d), "outboundTag": "block"}));
            need_block = true;
        }
    }
    if !rr.block_domains.is_empty() {
        rules.push(json!({"type": "field", "domain": xray_domain_list(&rr.block_domains), "outboundTag": "block"}));
        need_block = true;
    }
    if !rr.block_cidrs.is_empty() {
        rules.push(json!({"type": "field", "ip": rr.block_cidrs, "outboundTag": "block"}));
        need_block = true;
    }
    if !rr.direct_domains.is_empty() {
        rules.push(json!({"type": "field", "domain": xray_domain_list(&rr.direct_domains), "outboundTag": "direct"}));
    }
    if !rr.direct_cidrs.is_empty() {
        rules.push(json!({"type": "field", "ip": rr.direct_cidrs, "outboundTag": "direct"}));
    }
    if !rr.proxy_domains.is_empty() {
        rules.push(json!({"type": "field", "domain": xray_domain_list(&rr.proxy_domains), "outboundTag": "proxy"}));
    }
    if !rr.proxy_cidrs.is_empty() {
        rules.push(json!({"type": "field", "ip": rr.proxy_cidrs, "outboundTag": "proxy"}));
    }
    // явный catch-all: в xray непокрытый трафик идёт в ПЕРВЫЙ outbound,
    // а в избирательном режиме он должен уходить напрямую
    let final_tag = if rr.mode == MODE_SELECTIVE { "direct" } else { "proxy" };
    rules.push(json!({"type": "field", "network": "tcp,udp", "outboundTag": final_tag}));
    if need_block {
        outbounds.push(json!({"protocol": "blackhole", "tag": "block"}));
    }
    // При AsIs ip-правила матчили только буквальные IP-соединения: включаем
    // сниффинг и IPIfNonMatch, если есть CIDR-правила.
    let has_cidrs = !rr.block_cidrs.is_empty() || !rr.direct_cidrs.is_empty() || !rr.proxy_cidrs.is_empty();
    let strategy = if has_cidrs { "IPIfNonMatch" } else { "AsIs" };
    if has_cidrs {
        if let Some(inbs) = cfg.get_mut("inbounds").and_then(|v| v.as_array_mut()) {
            for inb in inbs.iter_mut() {
                if let Some(m) = inb.as_object_mut() {
                    m.insert(
                        "sniffing".into(),
                        json!({"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": false}),
                    );
                }
            }
        }
    }
    cfg.insert(
        "routing".into(),
        json!({"domainStrategy": strategy, "rules": rules}),
    );
    (outbounds, need_block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line_cases() {
        assert_eq!(route_parse_line("Example.COM"), ("example.com".to_string(), String::new()));
        assert_eq!(route_parse_line("  full:sub.example.com  "), ("sub.example.com".to_string(), String::new()));
        assert_eq!(route_parse_line("*.wild.example.com"), ("wild.example.com".to_string(), String::new()));
        assert_eq!(route_parse_line("# comment"), (String::new(), String::new()));
        assert_eq!(route_parse_line("example.com # заметка"), ("example.com".to_string(), String::new()));
        assert_eq!(route_parse_line("1.2.3.4"), (String::new(), "1.2.3.4/32".to_string()));
        assert_eq!(route_parse_line("1.2.3.4/8"), (String::new(), "1.0.0.0/8".to_string()));
        assert_eq!(route_parse_line("[fd00::1]"), (String::new(), "fd00::1/128".to_string()));
        assert_eq!(route_parse_line("not_a_domain!!"), (String::new(), String::new()));
    }

    #[test]
    fn built_from_settings_all_with_ads_and_block() {
        let s = VpnSettings {
            route_mode: Some("all".into()),
            ads_block: Some(true),
            route_block_custom: Some("blocked.example\n1.2.3.0/24".into()),
            ..Default::default()
        };
        let rr = build_route_rules(&s);
        assert_eq!(rr.mode, MODE_ALL);
        assert!(rr.ads);
        // Hagezi PRO — сотни тысяч доменов
        assert!(rr.ads_count > 100000, "ads_count={}", rr.ads_count);
        assert!(rr.block_domains.contains(&"blocked.example".to_string()));
        assert_eq!(rr.block_cidrs, vec!["1.2.3.0/24".to_string()]);
        assert!(rr.route_summary().contains("реклама"));
    }

    #[test]
    fn selective_mode_presets_and_final_direct() {
        let s = VpnSettings {
            route_mode: Some("selective".into()),
            route_presets: Some({
                let mut m = std::collections::HashMap::new();
                m.insert("youtube".to_string(), true);
                m
            }),
            ..Default::default()
        };
        let rr = build_route_rules(&s);
        assert_eq!(rr.mode, MODE_SELECTIVE);
        assert!(!rr.proxy_domains.is_empty());
        assert!(rr.proxy_domains.iter().any(|d| d.contains("youtube")));
        let mut route = Map::new();
        route.insert("final".into(), json!("proxy"));
        let tools = std::path::Path::new("Z:\\nonexistent");
        inject_sing_box(&mut route, &rr, tools);
        assert_eq!(route.get("final").unwrap(), "direct");
        let rules = route.get("rules").unwrap().as_array().unwrap();
        assert!(rules.iter().any(|r| r.get("outbound") == Some(&json!("proxy"))));
    }

    #[test]
    fn ru_direct_whitelist() {
        let s = VpnSettings {
            route_mode: Some("ru-direct".into()),
            ..Default::default()
        };
        let rr = build_route_rules(&s);
        assert!(!rr.direct_domains.is_empty());
        // вшитый itdoginfo-список содержит российские домены
        assert!(rr.direct_domains.iter().any(|d| d.ends_with(".ru")));
    }

    #[test]
    fn dns_inject_and_selective_swap() {
        let s = VpnSettings {
            route_mode: Some("selective".into()),
            route_presets: Some({
                let mut m = std::collections::HashMap::new();
                m.insert("telegram".to_string(), true);
                m
            }),
            ..Default::default()
        };
        let rr = build_route_rules(&s);
        let mut dns = Map::new();
        dns.insert(
            "servers".into(),
            json!([{"tag": "dns", "type": "https"}, {"tag": "dns-local", "type": "local"}]),
        );
        inject_sing_box_dns(&mut dns, &rr, Path::new("Z:\\nonexistent"));
        let servers = dns.get("servers").unwrap().as_array().unwrap();
        // в избирательном режиме дефолтный резолвер (первый) — системный
        assert_eq!(servers[0].get("tag").unwrap(), "dns-local");
        let rules = dns.get("rules").unwrap().as_array().unwrap();
        assert!(rules.iter().any(|r| r.get("server") == Some(&json!("dns"))));
    }
}
