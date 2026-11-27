// Порт Go dns.go: DNS-резолвер с фиксированными серверами Яндекса (77.88.8.8).
//
// В Go это делалось подменой net.DefaultResolver (PreferGo) с кастомным Dial:
// UDP:53 пробуется настоящим запросом при старте, при неудаче запросы идут
// по TCP. В Rust std не даёт подменить системный резолвер, поэтому здесь
// собственный минимальный DNS-клиент (UDP с фоллбеком на TCP) поверх
// std::net::UdpSocket/TcpStream — логика и таймауты один в один из Go.
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::logging::log_add;

// Go: yandexDNSServers
const YANDEX_DNS_SERVERS: [&str; 2] = ["77.88.8.8:53", "77.88.8.1:53"];

// Go: dialer Timeout: 3 * time.Second (KeepAlive 30s в Rust std не выставляется
// для исходящих TCP — API нет; для коротких DNS-запросов не критично)
const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

// Go: udp53Alive — дедлайн 1500 мс
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

// udp_ok — результат пробы UDP:53 при старте (Go: udpOK захвачен замыканием Dial).
static UDP_OK: AtomicBool = AtomicBool::new(false);

// random_query_id — случайный ID транзакции DNS (Go-резолвер генерировал
// случайные id). Последовательные id упрощали off-path подмену ответов,
// поэтому счётчик 0x534e заменён на CSPRNG; fastrand — фоллбек, если ГСЧ
// системы недоступен (id — защита от подмены, а не секрет).
fn random_query_id() -> u16 {
    let mut b = [0u8; 2];
    if getrandom::fill(&mut b).is_ok() {
        return u16::from_be_bytes(b);
    }
    fastrand::u16(..)
}

// setup_global_resolver — проба UDP:53 при старте (Go: setupGlobalResolver,
// вызывается один раз при запуске ядра).
// UDP-dial «успешен» всегда (connectionless не подтверждает доступность),
// и TCP-ветка dial'а была мертворожденной: в сети с тихой блокировкой
// UDP:53 каждый запрос уходил в мёртвый сокет и отваливался по таймауту
// резолвера. Пробуем НАСТОЯЩИЙ DNS-запрос по UDP: если ответа нет —
// UDP-запросы падают сразу с внятной ошибкой, не съедая таймауты.
pub fn setup_global_resolver() {
    let mut udp_ok = false;
    for dns in YANDEX_DNS_SERVERS {
        if udp53_alive(dns) {
            udp_ok = true;
            break;
        }
    }
    if !udp_ok {
        log_add(
            "wdtt",
            "[DNS] UDP:53 не отвечает (тихая блокировка?) — UDP-запросы будут падать сразу; проверь сеть/канал DNS",
        );
    }
    UDP_OK.store(udp_ok, Ordering::SeqCst);
}

// udp53_alive — живой ли DNS-сервер по UDP: реальный минимальный запрос
// (A example.com) с коротким дедлайном.
// Go: func udp53Alive(dialer *net.Dialer, server string) bool
fn udp53_alive(server: &str) -> bool {
    let addr: SocketAddr = match server.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let bind_addr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if sock.connect(addr).is_err() {
        return false;
    }
    let _ = sock.set_read_timeout(Some(PROBE_TIMEOUT));
    let _ = sock.set_write_timeout(Some(PROBE_TIMEOUT));
    let q: [u8; 29] = [
        0x53, 0x4e, // id
        0x01, 0x00, // flags: RD=1
        0, 1, 0, 0, 0, 0, 0, 0, // 1 вопрос
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // example.com
        0, 1, 0, 1, // тип A, класс IN
    ];
    if sock.send(&q).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    match sock.recv(&mut buf) {
        // наш пробный запрос имеет id 0x534e и флаг QR в ответе: сверяем,
        // иначе «живым» считался любой подслушанный/чужой пакет
        Ok(n) => n >= 12 && buf[0] == 0x53 && buf[1] == 0x4e && (buf[2] & 0x80) != 0,
        Err(_) => false,
    }
}

// is_yandex_dns_address — Go: func isYandexDNSAddress(address string) bool
#[allow(dead_code)] // Go-паритет (isYandexDNSAddress); путь не подключён
fn is_yandex_dns_address(address: &str) -> bool {
    // Go: net.SplitHostPort; при ошибке host = address
    let host = if let Some(rest) = address.strip_prefix('[') {
        match rest.find(']') {
            Some(i) => &rest[..i],
            None => address,
        }
    } else if let Some((h, p)) = address.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') {
            h
        } else {
            address
        }
    } else {
        address
    };
    // Go: strings.Trim(host, "[]")
    let host = host.trim_matches(|c| c == '[' || c == ']');
    host == "77.88.8.8" || host == "77.88.8.1"
}

// lookup_host — аналог Go net.LookupHost / net.DefaultResolver.LookupHost.
// Возвращает все найденные IP (IPv4/IPv6). IP-литерал разбирается без DNS.
pub fn lookup_host(host: &str) -> Result<Vec<IpAddr>, String> {
    // IP-литерал (в Go резолвер тоже не ходит в DNS для адресов)
    let literal = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let name = host.trim_end_matches('.');
    if name.is_empty() {
        return Err(format!("lookup {}: invalid domain name", host));
    }
    if !name.is_ascii() {
        return Err(format!("lookup {}: invalid domain name", name));
    }

    // Как в Go LookupHost: достаточно одного семейства; ошибка — если не
    // получилось ни по A, ни по AAAA.
    let mut ips = Vec::new();
    let mut last_err = String::new();

    match resolve_family(name, 1) {
        // тип A
        Ok(mut v) => ips.append(&mut v),
        Err(e) => last_err = e,
    }
    if ips.is_empty() {
        match resolve_family(name, 28) {
            // тип AAAA
            Ok(mut v) => ips.append(&mut v),
            Err(e) => last_err = e,
        }
    }

    if ips.is_empty() {
        if last_err.is_empty() {
            last_err = format!("lookup {}: no such host", name);
        }
        return Err(last_err);
    }
    Ok(ips)
}

// resolve_host — точка входа резолвера в реальный путь (Go: подменённый
// net.DefaultResolver). Порядок: SocketAddr/IP-литерал → собственный резолвер
// (Яндекс-DNS: UDP с TCP-фоллбеком — обход глушения/подмены DNS) → системный
// to_socket_addrs как последний фоллбек (IDN/нестандартные имена).
pub fn resolve_host(spec: &str) -> Vec<SocketAddr> {
    // литералы: "1.2.3.4:443", "[2001:db8::1]:443"
    if let Ok(a) = spec.parse::<SocketAddr>() {
        return vec![a];
    }
    let host = spec.trim_matches(|c| c == '[' || c == ']').trim().to_string();
    if host.is_empty() {
        return Vec::new();
    }
    // голый IP без порта
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![SocketAddr::new(ip, 0)];
    }
    let (host, port) = match spec.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.trim_matches(|c| c == '[' || c == ']'), p.parse::<u16>().unwrap_or(0))
        }
        _ => (spec.trim_matches(|c| c == '[' || c == ']'), 0),
    };
    if host.is_empty() {
        return Vec::new();
    }
    match lookup_host(host) {
        Ok(ips) if !ips.is_empty() => {
            return ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
        }
        Ok(_) => {}
        Err(e) => {
            log_add(
                "wdtt",
                &format!("[DNS] собственный резолвер не ответил для {} ({}): пробую системный", host, e),
            );
        }
    }
    use std::net::ToSocketAddrs;
    match (host, port).to_socket_addrs() {
        Ok(it) => it.collect(),
        Err(_) => Vec::new(),
    }
}

// resolve_family — все серверы по очереди: UDP (если проба прошла), затем TCP.
// Go: Dial-замыкание резолвера — резолвер просит ИМЕННО тот транспорт, что в
// network: при network == "tcp" (фоллбек на TCP после обрезанного UDP-ответа)
// звонить в udp нельзя — сервер молча отбрасывает TCP-фреймованный запрос.
// Раньше udp-dial «успешен всегда», и TCP-фоллбек не работал никогда.
fn resolve_family(name: &str, qtype: u16) -> Result<Vec<IpAddr>, String> {
    let mut last_err = String::new();

    if UDP_OK.load(Ordering::SeqCst) {
        for server in YANDEX_DNS_SERVERS {
            let id = random_query_id();
            let query = build_query(id, name, qtype)?;
            match dns_query_udp(server, &query) {
                Ok(resp) => {
                    // Обрезанный UDP-ответ (TC-бит) → фоллбек на TCP
                    if resp.len() >= 3 && (resp[2] & 0x02) != 0 {
                        break;
                    }
                    match parse_response(&resp, id, name, qtype) {
                        Ok(ips) if !ips.is_empty() => return Ok(ips),
                        Ok(_) => last_err = format!("lookup {}: пустой UDP-ответ от {}", name, server),
                        Err(e) => {
                            // подделка/чужой ответ не должен убивать попытку:
                            // пробуем следующий сервер/транспорт
                            last_err = e;
                        }
                    }
                }
                Err(e) => last_err = e,
            }
        }
    } else {
        last_err = "udp:53 недоступен (проба при старте не прошла)".to_string();
    }

    // TCP-фоллбек: после обрезанного UDP-ответа или неудачных UDP-дейлов
    for server in YANDEX_DNS_SERVERS {
        let id = random_query_id();
        let query = build_query(id, name, qtype)?;
        match dns_query_tcp(server, &query) {
            Ok(resp) => match parse_response(&resp, id, name, qtype) {
                Ok(ips) if !ips.is_empty() => return Ok(ips),
                Ok(_) => last_err = format!("lookup {}: пустой TCP-ответ от {}", name, server),
                Err(e) => last_err = e,
            },
            Err(e) => last_err = e,
        }
    }

    if last_err.is_empty() {
        last_err = format!("lookup {}: no suitable address record", name);
    }
    Err(last_err)
}

// build_query — минимальный DNS-запрос (RD=1, 1 вопрос, класс IN).
fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut m = Vec::with_capacity(512);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // 1 вопрос
    for label in name.split('.') {
        if label.is_empty() {
            continue; // завершающая точка / пустые лейблы
        }
        let b = label.as_bytes();
        // Лейбл длиннее 63 байт обрезался молча — запрос спрашивал ЧУЖОЕ имя.
        // Такое имя невалидно для DNS: ошибка вместо подмены смысла.
        if b.len() > 63 {
            return Err(format!("lookup {}: метка DNS длиннее 63 байт", name));
        }
        m.push(b.len() as u8);
        m.extend_from_slice(b);
    }
    // полное имя в проводном формате (с завершающим нулём) — до 255 байт
    if m.len() - 12 > 255 {
        return Err(format!("lookup {}: имя длиннее 255 байт", name));
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]); // класс IN
    Ok(m)
}

fn dns_query_udp(server: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    let addr: SocketAddr = server
        .parse()
        .map_err(|e| format!("dial {}: {}", server, e))?;
    let bind_addr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("dial {}: {}", server, e))?;
    sock.connect(addr)
        .map_err(|e| format!("dial {}: {}", server, e))?;
    let _ = sock.set_read_timeout(Some(DIAL_TIMEOUT));
    let _ = sock.set_write_timeout(Some(DIAL_TIMEOUT));
    sock.send(query)
        .map_err(|e| format!("отправка DNS-запроса {}: {}", server, e))?;
    let mut buf = [0u8; 512];
    let n = sock
        .recv(&mut buf)
        .map_err(|e| format!("чтение DNS-ответа {}: {}", server, e))?;
    Ok(buf[..n].to_vec())
}

fn dns_query_tcp(server: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    let addr: SocketAddr = server
        .parse()
        .map_err(|e| format!("dial {}: {}", server, e))?;
    let mut sock =
        TcpStream::connect_timeout(&addr, DIAL_TIMEOUT).map_err(|e| format!("dial {}: {}", server, e))?;
    let _ = sock.set_read_timeout(Some(DIAL_TIMEOUT));
    let _ = sock.set_write_timeout(Some(DIAL_TIMEOUT));
    // TCP-DNS: 2-байтовый префикс длины (как в Go resolver)
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    sock.write_all(&framed)
        .map_err(|e| format!("отправка DNS-запроса {}: {}", server, e))?;
    let mut len_buf = [0u8; 2];
    sock.read_exact(&mut len_buf)
        .map_err(|e| format!("чтение DNS-ответа {}: {}", server, e))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 {
        return Err(format!("чтение DNS-ответа {}: пустой ответ", server));
    }
    let mut resp = vec![0u8; resp_len];
    sock.read_exact(&mut resp)
        .map_err(|e| format!("чтение DNS-ответа {}: {}", server, e))?;
    Ok(resp)
}

// skip_name — пропустить имя в сообщении DNS (с compression pointer).
fn skip_name(msg: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let l = *msg.get(off)?;
        if l & 0xC0 == 0xC0 {
            return Some(off + 2); // указатель сжатия — 2 байта
        }
        if l == 0 {
            return Some(off + 1);
        }
        off += 1 + l as usize;
    }
}

// parse_response — разбор DNS-ответа: A (1) и AAAA (28) из секции ответов.
// Ошибки в стиле Go: NXDOMAIN → "lookup <name>: no such host".
// Ответ валиден только при совпадении ID транзакции, флаге QR и вопроса
// (имя+тип+класс) — без этого off-path подделка выдавала себя за ответ
// резолвера, и клиент подключался к подменённому IP.
fn parse_response(msg: &[u8], id: u16, name: &str, qtype: u16) -> Result<Vec<IpAddr>, String> {
    if msg.len() < 12 {
        return Err(format!("lookup {}: короткий DNS-ответ", name));
    }
    if msg[0..2] != id.to_be_bytes() {
        // чужой/подделанный пакет: отбрасываем (не окончательная ошибка)
        return Err(format!("lookup {}: несовпадение ID ответа (подмена?)", name));
    }
    if msg[2] & 0x80 == 0 {
        // пришёл не ответ, а запрос — тоже мусор
        return Err(format!("lookup {}: ответ без флага QR", name));
    }
    let rcode = msg[3] & 0x0F;
    match rcode {
        0 => {}
        3 => return Err(format!("lookup {}: no such host", name)),
        _ => return Err(format!("lookup {}: server misbehaving (rcode {})", name, rcode)),
    }
    // вопрос в ответе обязан совпадать с нашим: сверяем закодированное имя,
    // тип и класс (имя уже валидировано в build_query: метки ≤63, ASCII)
    let mut q = Vec::new();
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    let q_end = 12 + q.len() + 4;
    if msg.len() < q_end
        || msg[12..12 + q.len()] != q[..]
        || msg[12 + q.len()..12 + q.len() + 2] != qtype.to_be_bytes()
        || msg[12 + q.len() + 2..q_end] != [0, 1]
    {
        return Err(format!("lookup {}: ответ не на наш вопрос (подмена?)", name));
    }
    let qd_count = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an_count = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    let mut off = 12usize;
    for _ in 0..qd_count {
        off = skip_name(msg, off)
            .ok_or_else(|| format!("lookup {}: битый DNS-ответ", name))?;
        off += 4; // тип + класс
    }

    let mut out: Vec<IpAddr> = Vec::new();
    for _ in 0..an_count {
        off = skip_name(msg, off)
            .ok_or_else(|| format!("lookup {}: битый DNS-ответ", name))?;
        if off + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let rdlen = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        let rdata = off + 10;
        if rdata + rdlen > msg.len() {
            break;
        }
        match rtype {
            1 if rdlen == 4 => {
                let ip = IpAddr::V4(Ipv4Addr::new(
                    msg[rdata],
                    msg[rdata + 1],
                    msg[rdata + 2],
                    msg[rdata + 3],
                ));
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
            28 if rdlen == 16 => {
                let ip = IpAddr::V6(Ipv6Addr::new(
                    u16::from_be_bytes([msg[rdata], msg[rdata + 1]]),
                    u16::from_be_bytes([msg[rdata + 2], msg[rdata + 3]]),
                    u16::from_be_bytes([msg[rdata + 4], msg[rdata + 5]]),
                    u16::from_be_bytes([msg[rdata + 6], msg[rdata + 7]]),
                    u16::from_be_bytes([msg[rdata + 8], msg[rdata + 9]]),
                    u16::from_be_bytes([msg[rdata + 10], msg[rdata + 11]]),
                    u16::from_be_bytes([msg[rdata + 12], msg[rdata + 13]]),
                    u16::from_be_bytes([msg[rdata + 14], msg[rdata + 15]]),
                ));
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
            _ => {}
        }
        off = rdata + rdlen;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_bytes_match_probe_format() {
        let q = build_query(0x534e, "example.com", 1).expect("query");
        assert_eq!(&q[0..2], &[0x53, 0x4e]); // id
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD=1
        assert_eq!(&q[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            &q[12..],
            &[
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1
            ]
        );
        // с завершающей точкой — то же самое
        let q2 = build_query(0x534e, "example.com.", 1).expect("query2");
        assert_eq!(q, q2);
        // слишком длинная метка — ошибка, а не молчаливая обрезка
        let long = format!("{}.example.com", "a".repeat(64));
        assert!(build_query(1, &long, 1).is_err());
    }

    #[test]
    fn parse_response_a_record() {
        let mut m = vec![];
        m.extend_from_slice(&[0x53, 0x4e, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        m.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        // ответ: имя через compression pointer, A, IN, ttl 60, rdlen 4
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let ips = parse_response(&m, 0x534e, "example.com", 1).expect("parse");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn parse_response_rejects_spoofed() {
        let mut m = vec![];
        m.extend_from_slice(&[0x53, 0x4e, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        m.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        // чужой ID — ответ обязан быть отброшен
        assert!(parse_response(&m, 0x1111, "example.com", 1).is_err());
        // не ответ, а запрос (QR=0)
        let mut req = m.clone();
        req[2] = 0x01;
        assert!(parse_response(&req, 0x534e, "example.com", 1).is_err());
        // правильный ID, но вопрос про другое имя — подмена
        let fake = [1, b'x', 0, 0, 1, 0, 1];
        let tail: Vec<u8> = m[29..].to_vec();
        let mut patched: Vec<u8> = m[..12].to_vec();
        patched.extend_from_slice(&fake);
        patched.extend_from_slice(&tail);
        assert!(parse_response(&patched, 0x534e, "example.com", 1).is_err());
    }

    #[test]
    fn parse_response_nxdomain() {
        let m = [0x53, 0x4e, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_response(&m, 0x534e, "example.com", 1).unwrap_err(),
            "lookup example.com: no such host"
        );
    }

    #[test]
    fn yandex_address_detection() {
        assert!(is_yandex_dns_address("77.88.8.8:53"));
        assert!(is_yandex_dns_address("77.88.8.1:53"));
        assert!(is_yandex_dns_address("77.88.8.8"));
        assert!(is_yandex_dns_address("[77.88.8.8]:53"));
        assert!(!is_yandex_dns_address("8.8.8.8:53"));
        assert!(!is_yandex_dns_address("8.8.8.8"));
        assert!(!is_yandex_dns_address("[::1]:53"));
    }

    #[test]
    fn skip_name_with_pointer() {
        let msg = [3, b'w', b'w', b'w', 0, 0, 0xC0, 0x00];
        assert_eq!(skip_name(&msg, 0), Some(5));
        assert_eq!(skip_name(&msg, 6), Some(8));
    }
}
