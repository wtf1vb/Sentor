// DNS-блокировщик рекламы «всегда» (локальный резолвер в стиле AdGuard Home):
// процесс sentor.exe --adsdns <toolsDir> слушает 127.0.0.1/[::1]:53, домены
// вшитого списка Hagezi (route_rules::route_ads_domains) + пользовательский
// «Блокировать всегда» отвечает 0.0.0.0/::/NXDOMAIN, остальное пересылает
// на 1.1.1.1 → 8.8.8.8. DNS адаптеров переключается на 127.0.0.1 (netsh)
// с бэкапом в ads_dns_backup.json. Защита от «интернет отвалится»:
// 1) включение — только после успешного тестового запроса к блокировщику;
// 2) restore трогает только адаптеры, где DNS всё ещё НАШ (127.0.0.1/::1);
// 3) страж (--proxy-guard <pid> <tools> dns) возвращает исходные DNS при
//    смерти блокировщика; 4) тумблер OFF восстанавливает DNS немедленно;
// 5) форвард идёт 1.1.1.1 → 8.8.8.8 → ИСХОДНЫЕ DNS адаптеров из бэкапа
//    (последний ответивший — первым): прямой UDP 53 наружу операторы часто
//    перекрывают — без фолбэка локальный резолвер мёртв, а с ним и весь инет.
use std::collections::HashSet;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::logging::log_add;
use crate::paths;

const PORT: u16 = 53;
const UPSTREAMS: &[&str] = &["1.1.1.1:53", "8.8.8.8:53"];
const STATE_TTL_SECS: u64 = 6; // heartbeat старше этого = блокировщик мёртв

// ---------- апстримы с фолбэком на исходные DNS ----------

// кеш динамических апстримов (исходные DNS из бэкапа) и последний ответивший
struct UpstreamCache {
    at: Instant,
    list: Vec<String>,
}
static UPSTREAMS_CACHE: Mutex<Option<UpstreamCache>> = Mutex::new(None);
static LAST_GOOD_UP: Mutex<Option<String>> = Mutex::new(None);

// backup_upstreams — исходные DNS адаптеров из ads_dns_backup.json
// (роутер/оператор). Бэкап появляется через ~2-5 с после старта блокировщика
// (пишется при первом переключении адаптеров) — читаем лениво, кеш на 10 с.
fn backup_upstreams(tools: &Path) -> Vec<String> {
    let Ok(data) = std::fs::read(paths::adsdns_backup_file(tools)) else {
        return Vec::new();
    };
    let Ok(list) = serde_json::from_slice::<Vec<AdapterDns>>(&data) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for a in list {
        for d in a.dns {
            if d.is_empty()
                || d == "127.0.0.1"
                || d == "::1"
                || d == "0.0.0.0"
                || d.starts_with("fe80")
                || d.starts_with("169.254")
            {
                continue;
            }
            let up = if d.contains(':') { format!("[{}]:53", d) } else { format!("{}:53", d) };
            if !out.contains(&up) {
                out.push(up);
            }
        }
    }
    out
}

// upstream_list — полный список апстримов: 1.1.1.1 → 8.8.8.8 → исходные DNS;
// последний ответивший поднимается в начало, чтобы на сетях с перекрытым
// UDP 53 не платить таймауты на каждом запросе
fn upstream_list(tools: &Path) -> Vec<String> {
    let mut out: Vec<String> = UPSTREAMS.iter().map(|s| s.to_string()).collect();
    let mut cache = UPSTREAMS_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    match &*cache {
        Some(c) if c.at.elapsed() < Duration::from_secs(10) => {
            out.extend(c.list.iter().cloned());
        }
        _ => {
            let list = backup_upstreams(tools);
            out.extend(list.iter().cloned());
            *cache = Some(UpstreamCache { at: Instant::now(), list });
        }
    }
    drop(cache);
    let good = LAST_GOOD_UP.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(g) = good {
        if let Some(i) = out.iter().position(|x| *x == g) {
            out.remove(i);
            out.insert(0, g);
        }
    }
    out
}


// ---------- state / heartbeat ----------

#[derive(Serialize, Deserialize, Clone)]
struct DnsState {
    pid: u32,
    at: u64,
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn read_state(tools: &Path) -> Option<DnsState> {
    let data = std::fs::read(paths::adsdns_state_file(tools)).ok()?;
    serde_json::from_slice(&data).ok()
}

pub fn adsdns_running(tools: &Path) -> bool {
    match read_state(tools) {
        Some(s) => now_unix().saturating_sub(s.at) <= STATE_TTL_SECS,
        None => false,
    }
}

fn heartbeat_loop(tools: PathBuf) {
    loop {
        let st = DnsState { pid: std::process::id(), at: now_unix() };
        let _ = crate::store::atomic_write_json(&paths::adsdns_state_file(&tools), &st);
        std::thread::sleep(Duration::from_secs(2));
    }
}

// ---------- DNS-сообщения (минимальный парсинг без crate) ----------

struct Question {
    domain: String,
    qend: usize, // конец секции Question в пакете (после QTYPE+QCLASS)
    qtype: u16,
}

// разбирает заголовок + первый вопрос; возвращает домен, qtype и смещение
// конца вопроса. Обрабатывает только запросы (QR=0) без сжатия в QNAME —
// у вопросов от Windows-резолвера его и не бывает.
fn parse_question(buf: &[u8]) -> Option<Question> {
    if buf.len() < 12 {
        return None;
    }
    let flags = ((buf[2] as u16) << 8) | buf[3] as u16;
    if flags & 0x8000 != 0 {
        return None; // QR=1 — это ответ, не запрос
    }
    let qd = ((buf[4] as u16) << 8) | buf[5] as u16;
    if qd == 0 {
        return None;
    }
    let mut i = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if i >= buf.len() || labels.len() > 12 {
            return None; // кривой пакет / петля
        }
        let len = buf[i] as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if i + 1 + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[i + 1..i + 1 + len]).to_lowercase());
        i += 1 + len;
    }
    if i + 4 > buf.len() {
        return None;
    }
    let qtype = ((buf[i] as u16) << 8) | buf[i + 1] as u16;
    // i..i+2 = QTYPE, i+2..i+4 = QCLASS
    let domain = labels.join(".");
    if domain.is_empty() {
        return None;
    }
    Some(Question { domain, qend: i + 4, qtype })
}

fn is_blocked(set: &HashSet<String>, host: &str) -> bool {
    // суффикс-матч: cdn.ads.example.com → ads.example.com → example.com
    let mut cur: &str = host;
    loop {
        if set.contains(cur) {
            return true;
        }
        match cur.find('.') {
            Some(i) if i + 1 < cur.len() => cur = &cur[i + 1..],
            _ => return false,
        }
    }
}

// ответ на заблокированный домен: A → 0.0.0.0, AAAA → ::, остальное NXDOMAIN
fn blocked_response(req: &[u8], q: &Question) -> Vec<u8> {
    let rd = req[2] & 0x01;
    let is_a = q.qtype == 1;
    let is_aaaa = q.qtype == 28;
    let mut out = Vec::with_capacity(q.qend + 28);
    out.extend_from_slice(&req[0..2]); // ID
    out.push(0x80 | rd); // QR=1, RD из запроса
    if is_a || is_aaaa {
        out.push(0x80); // RA=1, RCODE=0
    } else {
        out.push(0x80 | 3); // RA=1, RCODE=3 (NXDOMAIN)
    }
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0]); // QDCOUNT=1, AN/NS/AR=0
    out.extend_from_slice(&req[12..q.qend]); // вопрос целиком
    if is_a || is_aaaa {
        out[7] = 1; // ANCOUNT=1
        out.extend_from_slice(&[0xC0, 0x0C]); // указатель на имя из вопроса
        if is_a {
            out.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 0, 0, 0, 0]);
        } else {
            out.extend_from_slice(&[0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
            out.extend_from_slice(&[0u8; 16]);
        }
    }
    out
}

// сырой форвард запроса вверх (1.1.1.1 → 8.8.8.8 → исходные DNS адаптеров из
// бэкапа); ответ возвращается как есть. Успешный апстрим запоминается —
// следующий запрос идёт в него первым.
fn forward_upstream(req: &[u8], tools: &Path) -> Option<Vec<u8>> {
    for up in upstream_list(tools) {
        let sock = match UdpSocket::bind(("0.0.0.0", 0)) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if sock.set_read_timeout(Some(Duration::from_millis(700))).is_err() {
            continue;
        }
        if sock.send_to(req, &up).is_err() {
            continue;
        }
        let mut buf = vec![0u8; 4096];
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                // защита от подмены: ответ только от того апстрима, куда шли
                if peer.to_string() == up {
                    *LAST_GOOD_UP.lock().unwrap_or_else(|e| e.into_inner()) = Some(up.clone());
                    return Some(buf[..n].to_vec());
                }
            }
            Err(_) => continue,
        }
    }
    None
}

fn handle_query(req: &[u8], bl: &HashSet<String>, tools: &Path) -> Option<Vec<u8>> {
    let q = parse_question(req)?;
    if is_blocked(bl, &q.domain) {
        Some(blocked_response(req, &q))
    } else {
        forward_upstream(req, tools)
    }
}

// ---------- серверы ----------

fn serve_udp(sock: UdpSocket, bl: Arc<HashSet<String>>, tools: PathBuf) {
    let sock = Arc::new(sock);
    let mut buf = [0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) => continue,
        };
        // каждый запрос в своём потоке: медленный апстрим не задерживает
        // остальные запросы (форвард — до пары секунд на все апстримы)
        let req = buf[..n].to_vec();
        let bl = bl.clone();
        let sock = sock.clone();
        let tools = tools.clone();
        let peer = peer;
        std::thread::spawn(move || {
            if let Some(resp) = handle_query(&req, &bl, &tools) {
                let _ = sock.send_to(&resp, peer);
            }
        });
    }
}

// DNS over TCP (Windows-резолвер ретраит по TCP при TC-флаге: без этого
// «большие» ответы отваливались бы)
fn serve_tcp(listener: TcpListener, bl: Arc<HashSet<String>>, tools: PathBuf) {
    use std::io::{Read, Write};
    for stream in listener.incoming().flatten() {
        let bl = bl.clone();
        let tools = tools.clone();
        std::thread::spawn(move || {
            let mut s = stream;
            let _ = s.set_read_timeout(Some(Duration::from_secs(4)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(4)));
            let mut len2 = [0u8; 2];
            if s.read_exact(&mut len2).is_err() {
                return;
            }
            let n = ((len2[0] as usize) << 8) | len2[1] as usize;
            if n == 0 || n > 8192 {
                return;
            }
            let mut req = vec![0u8; n];
            if s.read_exact(&mut req).is_err() {
                return;
            }
            let Some(resp) = handle_query(&req, &bl, &tools) else {
                return;
            };
            if resp.len() > 0xFFFF {
                return;
            }
            let mut out = Vec::with_capacity(resp.len() + 2);
            out.push((resp.len() >> 8) as u8);
            out.push(resp.len() as u8);
            out.extend_from_slice(&resp);
            let _ = s.write_all(&out);
        });
    }
}

fn load_blocklist(tools: &Path) -> HashSet<String> {
    let mut set: HashSet<String> = HashSet::new();
    for d in crate::route_rules::route_ads_domains().iter() {
        set.insert(d.trim().to_lowercase());
    }
    // пользовательский список «Блокировать всегда» (routeBlockCustom)
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase", default)]
    struct SettingsLite {
        route_block_custom: Option<String>,
    }
    if let Ok(raw) = std::fs::read_to_string(paths::vpn_settings_path(tools)) {
        if let Ok(s) = serde_json::from_str::<SettingsLite>(&raw) {
            if let Some(list) = s.route_block_custom {
                for line in list.lines() {
                    let t = line.trim().to_lowercase();
                    if t.is_empty() || t.starts_with('#') || t.starts_with('!') || t.contains('/') {
                        continue; // комментарии и CIDR — не для DNS-блокировки
                    }
                    let dom = t.split_whitespace().next().unwrap_or("");
                    let dom = dom.trim_start_matches("*.").trim_start_matches("domain:").trim_end_matches('.');
                    if dom.contains('.') {
                        set.insert(dom.to_string());
                    }
                }
            }
        }
    }
    set
}

// тело sentor.exe --adsdns <toolsDir>
pub fn run_dns_process(tools_dir: &str) {
    let tools = Path::new(tools_dir);
    let bl = Arc::new(load_blocklist(tools));
    log_add("adsdns", &format!("DNS-блокировщик запущен: {} доменов в блок-листе", bl.len()));

    let mut udp = Vec::new();
    match UdpSocket::bind(("127.0.0.1", PORT)) {
        Ok(s) => udp.push(s),
        Err(e) => log_add("adsdns", &format!("127.0.0.1:53 не занять: {}", e)),
    }
    match UdpSocket::bind(("[::1]", PORT)) {
        Ok(s) => udp.push(s),
        Err(e) => log_add("adsdns", &format!("[::1]:53 не занять: {}", e)),
    }
    if udp.is_empty() {
        log_add("adsdns", "порт 53 занят другим процессом — блокировщик не поднялся");
        return;
    }
    for addr in ["127.0.0.1:53", "[::1]:53"] {
        match TcpListener::bind(addr) {
            Ok(l) => {
                let bl2 = bl.clone();
                let tools2 = tools.to_path_buf();
                std::thread::spawn(move || serve_tcp(l, bl2, tools2));
            }
            Err(e) => log_add("adsdns", &format!("TCP {}: {}", addr, e)),
        }
    }
    let hb = tools.to_path_buf();
    std::thread::spawn(move || heartbeat_loop(hb));
    for s in udp {
        let bl2 = bl.clone();
        let tools2 = tools.to_path_buf();
        std::thread::spawn(move || serve_udp(s, bl2, tools2));
    }
    // процесс живёт, пока его не убьют (тумблер OFF / страж после падения)
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

// тестовый запрос к себе: блокировщик реально отвечает, прежде чем мы
// посмеем переключать DNS адаптеров
fn dns_probe() -> bool {
    // QNAME: 6 "google" 3 "com" 0, QTYPE=A, QCLASS=IN
    let mut req = Vec::with_capacity(31);
    req.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    req.push(6);
    req.extend_from_slice(b"google");
    req.push(3);
    req.extend_from_slice(b"com");
    req.push(0);
    req.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
    let sock = match UdpSocket::bind(("127.0.0.1", 0)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // 4 с: на сетях с перекрытым UDP 53 первый запрос успевает попробовать
    // ВСЕ апстримы (1.1.1.1/8.8.8.8 молчат, исходный DNS из бэкапа отвечает) —
    // старых 1.5 с на это не хватало и включение ложно отклонялось
    if sock.set_read_timeout(Some(Duration::from_millis(4000))).is_err() {
        return false;
    }
    if sock.send_to(&req, ("127.0.0.1", PORT)).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => n >= 12 && buf[0] == 0x12 && buf[1] == 0x34,
        Err(_) => false,
    }
}

// ---------- адаптеры / netsh ----------

#[derive(Serialize, Deserialize, Clone, Default)]
struct AdapterDns {
    name: String,
    dns: Vec<String>,
}

fn list_adapters() -> Vec<AdapterDns> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH};
    let mut out = Vec::new();
    unsafe {
        let mut size: u32 = 0;
        let _ = GetAdaptersAddresses(0, 0, std::ptr::null_mut(), std::ptr::null_mut(), &mut size);
        if size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = GetAdaptersAddresses(
            0,
            0,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut size,
        );
        if rc != 0 {
            return out;
        }
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = &*cur;
            // OnlyUp; loopback (24) и туннели (131) не трогаем — у TUN свой DNS
            if a.OperStatus == 1 && a.IfType != 24 && a.IfType != 131 {
                let mut name = String::new();
                if !a.FriendlyName.is_null() {
                    let mut len = 0usize;
                    while *a.FriendlyName.add(len) != 0 {
                        len += 1;
                    }
                    name = String::from_utf16_lossy(std::slice::from_raw_parts(a.FriendlyName, len));
                }
                if !name.is_empty() {
                    let mut dns = Vec::new();
                    let mut d = a.FirstDnsServerAddress;
                    while !d.is_null() {
                        let da = &*d;
                        let sa = da.Address.lpSockaddr;
                        if !sa.is_null() && da.Address.iSockaddrLength >= 16 {
                            let family = *(sa as *const u16);
                            if family == 2 {
                                // AF_INET: IPv4 по смещению 4
                                let ip = std::slice::from_raw_parts((sa as *const u8).add(4), 4);
                                dns.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                            } else if family == 23 {
                                // AF_INET6: IPv6 по смещению 8 (16 байт)
                                let ip = std::slice::from_raw_parts((sa as *const u8).add(8), 16);
                                let seg: Vec<String> =
                                    (0..8).map(|k| format!("{:x}", ((ip[k * 2] as u16) << 8) | ip[k * 2 + 1] as u16)).collect();
                                dns.push(seg.join(":"));
                            }
                        }
                        d = da.Next;
                    }
                    out.push(AdapterDns { name, dns });
                }
            }
            cur = a.Next;
        }
    }
    out
}

fn netsh_set_static(name: &str, ip: &str, v6: bool) {
    let iface = format!("name=\"{}\"", name);
    let family = if v6 { "ipv6" } else { "ip" };
    let _ = crate::tools::run_hidden("netsh", &[family, "set", "dns", &iface, "static", ip, "primary"]);
}

fn netsh_add_dns(name: &str, ip: &str, v6: bool) {
    let iface = format!("name=\"{}\"", name);
    let family = if v6 { "ipv6" } else { "ip" };
    let _ = crate::tools::run_hidden("netsh", &[family, "add", "dns", &iface, ip, "index=2"]);
}

fn netsh_set_dhcp(name: &str, v6: bool) {
    let iface = format!("name=\"{}\"", name);
    let family = if v6 { "ipv6" } else { "ip" };
    let _ = crate::tools::run_hidden("netsh", &[family, "set", "dns", &iface, "source=dhcp"]);
}

fn set_adapter_dns(tools: &Path) -> Result<(), String> {
    let adapters = list_adapters();
    if adapters.is_empty() {
        return Err("активные сетевые адаптеры не найдены".into());
    }
    let backup_path = paths::adsdns_backup_file(tools);
    if !backup_path.exists() {
        // бэкап ДО первого переключения (исходные DNS пользователя)
        if let Err(e) = crate::store::atomic_write_json(&backup_path, &adapters) {
            return Err(format!("бэкап DNS не записан: {} — переключение отменено", e));
        }
    }
    let mut changed = 0;
    for a in &adapters {
        let ours_only = a.dns.len() == 1 && (a.dns[0] == "127.0.0.1" || a.dns[0] == "::1");
        if ours_only {
            continue; // уже наши — netsh не дёргаем
        }
        netsh_set_static(&a.name, "127.0.0.1", false);
        netsh_set_static(&a.name, "::1", true);
        changed += 1;
    }
    log_add("adsdns", &format!("DNS адаптеров переключён на 127.0.0.1 (адаптеров: {})", changed));
    Ok(())
}

// восстановление исходных DNS. Идемпотентно и безопасно: трогает только
// адаптеры, где DNS всё ещё НАШ (127.0.0.1/::1); чужие настройки не читает.
pub fn restore_dns(tools: &Path) {
    let backup_path = paths::adsdns_backup_file(tools);
    let backup: Vec<AdapterDns> = std::fs::read(&backup_path)
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default();
    let adapters = list_adapters();
    let mut restored = 0;
    for a in &adapters {
        let ours = !a.dns.is_empty() && a.dns.iter().all(|d| d == "127.0.0.1" || d == "::1");
        if !ours {
            continue;
        }
        let entry = backup.iter().find(|b| b.name == a.name);
        match entry {
            Some(b) => {
                let v4s: Vec<&String> = b.dns.iter().filter(|d| !d.contains(':')).collect();
                let v6s: Vec<&String> = b.dns.iter().filter(|d| d.contains(':')).collect();
                if !v4s.is_empty() {
                    netsh_set_static(&a.name, v4s[0], false);
                    for d in v4s.iter().skip(1) {
                        netsh_add_dns(&a.name, d, false);
                    }
                } else {
                    netsh_set_dhcp(&a.name, false);
                }
                if !v6s.is_empty() {
                    netsh_set_static(&a.name, v6s[0], true);
                    for d in v6s.iter().skip(1) {
                        netsh_add_dns(&a.name, d, true);
                    }
                } else {
                    netsh_set_dhcp(&a.name, true);
                }
            }
            // адаптера не было в бэкапе = мы его DNS не меняли — на всякий
            // случай возвращаем DHCP (адрес мог появиться уже с нашим DNS)
            None => {
                netsh_set_dhcp(&a.name, false);
                netsh_set_dhcp(&a.name, true);
            }
        }
        restored += 1;
    }
    if restored > 0 {
        log_add("adsdns", &format!("исходные DNS адаптеров восстановлены: {}", restored));
    }
    let _ = std::fs::remove_file(&backup_path);
    let _ = crate::tools::run_hidden("ipconfig", &["/flushdns"]);
}

// ---------- включение/выключение ----------

pub fn adsdns_start(tools: &Path) -> String {
    if adsdns_running(tools) {
        // уже работает (пережил закрытие окна) — вернуть DNS адаптеров, если слетели
        if let Err(e) = set_adapter_dns(tools) {
            return format!("⚠️ Блокировщик работает, но DNS не переключён: {}", e);
        }
        return "✅ DNS-блокировщик уже работает".into();
    }
    let _ = std::fs::remove_file(paths::adsdns_state_file(tools));
    let Ok(exe) = std::env::current_exe() else {
        return "❌ Не нашёл путь исполняемого файла".into();
    };
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(["--adsdns", &tools.display().to_string()]);
    use std::os::windows::process::CommandExt;
    // DETACHED: переживает закрытие окна приложения — блокировка «всегда»
    cmd.creation_flags(0x00000008);
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return format!("❌ Не смог запустить DNS-блокировщик: {}", e),
    };
    let pid = child.id();
    // ждём живого heartbeat (список 213k доменов грузится ~1 с)
    let mut alive = false;
    for _ in 0..24 {
        if let Some(s) = read_state(tools) {
            if s.pid == pid && now_unix().saturating_sub(s.at) <= STATE_TTL_SECS {
                alive = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    if !alive {
        let _ = std::fs::remove_file(paths::adsdns_state_file(tools));
        return "❌ DNS-блокировщик не запустился — смотри панель «Логи» (компонент adsdns)".into();
    }
    // тестовый запрос ДО переключения DNS: не сможем резолвить — не переключаем
    if !dns_probe() {
        kill_blocker_quiet(pid);
        let _ = std::fs::remove_file(paths::adsdns_state_file(tools));
        return "❌ Тестовый запрос к блокировщику не прошёл — DNS адаптеров НЕ переключены".into();
    }
    if let Err(e) = set_adapter_dns(tools) {
        kill_blocker_quiet(pid);
        let _ = std::fs::remove_file(paths::adsdns_state_file(tools));
        return format!("❌ {}: DNS адаптеров НЕ переключены", e);
    }
    // страж: смерть блокировщика (крах/taskkill) → восстановление DNS
    spawn_dns_guard(tools, pid);
    log_add("adsdns", "реклама блокируется во всей системе (в т.ч. без VPN)");
    "✅ Реклама блокируется во всей системе — даже без VPN (локальный DNS)".into()
}

fn kill_blocker_quiet(pid: u32) {
    // Проверяем имя образа перед taskkill /PID: heartbeat-файл мог остаться от
    // умершего блокировщика, а его PID переиспользован ОС — вслепую мы убили
    // бы посторонний процесс.
    if crate::tools::pid_image_is_self(pid) {
        let _ = crate::tools::run_hidden("taskkill", &["/PID", &pid.to_string(), "/F"]);
    } else {
        log_add("adsdns", &format!("PID {} больше не наш блокировщик — taskkill отменён", pid));
    }
    std::thread::sleep(Duration::from_millis(400));
}

fn spawn_dns_guard(tools: &Path, dns_pid: u32) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["--proxy-guard", &dns_pid.to_string(), &tools.display().to_string(), "dns"]);
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    let _ = cmd.spawn();
}

pub fn adsdns_stop(tools: &Path) -> String {
    if !adsdns_running(tools) {
        // хвост прошлого падения: backup есть, DNS могли остаться нашими
        restore_dns(tools);
        let _ = std::fs::remove_file(paths::adsdns_state_file(tools));
        return "DNS-блокировщик и так не запущен".into();
    }
    let pid = read_state(tools).map(|s| s.pid).unwrap_or(0);
    if pid > 0 {
        kill_blocker_quiet(pid);
    }
    let _ = std::fs::remove_file(paths::adsdns_state_file(tools));
    restore_dns(tools);
    log_add("adsdns", "остановлено");
    "✅ Блокировка рекламы выключена, DNS адаптеров восстановлены".into()
}

// при старте приложения: тумблер ON → поднять блокировщик (если умер) и
// вернуть наши DNS; тумблер OFF → убрать хвосты прошлого падения
// Осиротевшие NRPT-правила: убитый тасккилом WARP/туннель мог оставить
// catch-all правило "." с ПУСТЫМ списком серверов — тогда системный
// резолвер отправляет ВСЕ домены в пустоту (google из кэша работает,
// всё остальное — «хост неизвестен»). Такое правило по определению
// битое — чистим на старте приложения.
pub fn cleanup_orphan_nrpt() {
    let ps = "Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Namespace -eq '.' -and (-not $_.DnsServers -or $_.DnsServers.Count -eq 0) } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }";
    if let Ok(out) = crate::tools::run_hidden("powershell", &["-NoProfile", "-Command", ps]) {
        let t = out.trim();
        if !t.is_empty() {
            log_add("adsdns", &format!("NRPT-чистка: {}", t));
        }
    }
}

pub fn ensure_on_startup(tools: &Path) {
    cleanup_orphan_nrpt();
    let on = crate::store::load_vpn_settings(tools)
        .normalize()
        .ads_block
        .unwrap_or(false);
    if on {
        if adsdns_running(tools) {
            // блокировщик пережил закрытие окна — вернуть DNS, если слетели
            if let Err(e) = set_adapter_dns(tools) {
                log_add("adsdns", &format!("DNS не переключён: {}", e));
            }
            return;
        }
        log_add("adsdns", "блокировка рекламы включена — поднимаю DNS-блокировщик");
        let msg = adsdns_start(tools);
        log_add("adsdns", &msg);
    } else if paths::adsdns_backup_file(tools).exists() {
        log_add("adsdns", "хвост прошлого падения: тумблер OFF, а DNS наши — восстанавливаю");
        restore_dns(tools);
        let _ = std::fs::remove_file(paths::adsdns_state_file(tools));
    }
}
