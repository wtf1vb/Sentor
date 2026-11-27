// WARP/AmneziaWG via the embedded sing-box (wireguard endpoint) - port of
// Go warp_wg.go/warp_gen.go/warp_i1_mask.go.
// Отличие от Go: туннель поднимает sing-box (адаптер, маршруты и DNS — его
// работа), а не amneziawg-go в процессе. sing-box 1.12+ удалил endpoint
// amnezia-wg, а wireguard endpoint не имеет AWG-полей и строго парсит JSON
// (unknown field) — Jc/Jmin/Jmax/S1/S2/H1-H4/I1-I5 приманки встроенным ядром
// не применяются, туннель идёт как обычный WireGuard (честно логируем).
use base64::Engine;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use serde_json::json;

use crate::logging::log_add;

pub const WARP_IFACE: &str = "sentor-warp";
#[allow(dead_code)]
const WARP_REG_BASE: &str = "https://api.cloudflareclient.com/v0i1909051800";
#[allow(dead_code)]
const WARP_REG_UA: &str = "okhttp/3.12.1";
// DNS — RU-резолверы из warp-config-ru (geohide + comss, только v4). Внутри
// туннеля работал бы и 1.1.1.1 — DNS не влияет на handshake, выравниваем с
// рабочим генератором.
#[allow(dead_code)]
const WARP_GEN_DNS: &str = "45.155.204.190, 37.230.192.51, 83.220.169.155, 212.109.195.93";
// Авто-выбор endpoint'а генератора. Константа 162.159.195.1:500 (популярный
// обход 2024 года) на большинстве сетей умерла: UDP 500 — это IKEv2, ТСПУ
// режет его особенно жёстко, WG-handshake «притворяться IKE» там не проходит
// (проверено на живых конфигах: 162.159.192.1:1701 работает, 162.159.195.1:500
// молчит на той же сети). IP пробуем по TCP 443 (anycast Cloudflare отвечает,
// пока IP не заблокирован), порт — случайный из WARP_PORTS. «Альтернативный»
// список 854-8886 из warp-awg-gen устарел: Cloudflare на них не отвечает
// (живая сеть 2026-11: IP жив по TCP, handshake на 945 молчит, на 1701
// проходит), рабочий warp-config-ru использует только классику.
#[allow(dead_code)]
const WARP_KNOWN_IPS: &[&str] = &[
    "162.159.192.1", "162.159.192.11", "162.159.192.21", "162.159.192.31",
    "162.159.192.41", "162.159.192.51", "162.159.192.61", "162.159.192.71",
    "162.159.192.81", "162.159.192.91", "162.159.193.1", "162.159.195.1",
];
#[allow(dead_code)]
const WARP_PORTS: &[u16] = &[4500, 2408, 500, 1701];

// I1-маски AmneziaWG 1.5 — пара QUIC-масок из warp-config-ru (AppsGanin, MIT):
// на DPI-сетях выживают только junk-пакеты и I1-сигнатура, сама маска и есть
// то, что протаскивает WG-handshake мимо ТСПУ. Сгоревшие маски (старый набор
// 0xc7/SIP-текст) выпилены — на живой сети 2026-11 handshake с ними молчал.
// DPI со временем выучивает и эти — при массовом падении handshake обновить
// набор из репозитория генератора. Хелпер SentorWarp при переборе портов
// подставляет обе маски и фолбэк без приманок.
#[allow(dead_code)]
pub const WARP_I1_MASKS: [&str; 2] = [
    "I1 = <b 0xc10000000114367096bb0fb3f58f3a3fb8aaacd61d63a1c8a40e14f7374b8a62dccba6431716c3abf6f5afbcfb39bd008000047c32e268567c652e6f4db58bff759bc8c5aaca183b87cb4d22938fe7d8dca22a679a79e4d9ee62e4bbb3a380dd78d4e8e48f26b38a1d42d76b371a5a9a0444827a69d1ab5872a85749f65a4104e931740b4dc1e2dd77733fc7fac4f93011cd622f2bb47e85f71992e2d585f8dc765a7a12ddeb879746a267393ad023d267c4bd79f258703e27345155268bd3cc0506ebd72e2e3c6b5b0f005299cd94b67ddabe30389c4f9b5c2d512dcc298c14f14e9b7f931e1dc397926c31fbb7cebfc668349c218672501031ecce151d4cb03c4c660b6c6fe7754e75446cd7de09a8c81030c5f6fb377203f551864f3d83e27de7b86499736cbbb549b2f37f436db1cae0a4ea39930f0534aacdd1e3534bc87877e2afabe959ced261f228d6362e6fd277c88c312d966c8b9f67e4a92e757773db0b0862fb8108d1d8fa262a40a1b4171961f0704c8ba314da2482ac8ed9bd28d4b50f7432d89fd800c25a50c5e2f5c0710544fef5273401116aa0572366d8e49ad758fcb29e6a92912e644dbe227c247cb3417eabfab2db16796b2fba420de3b1dc94e8361f1f324a331ddaf1e626553138860757fd0bf687566108b77b70fb9f8f8962eca599c4a70ed373666961a8cb506b96756d9e28b94122b20f16b54f118c0e603ce0b831efea614ad836df6cf9affbdd09596412547496967da758cec9080295d853b0861670b71d9abde0d562b1a6de82782a5b0c14d297f27283a895abc889a5f6703f0e6eb95f67b2da45f150d0d8ab805612d570c2d5cb6997ac3a7756226c2f5c8982ffbd480c5004b0660a3c9468945efde90864019a2b519458724b55d766e16b0da25c0557c01f3c11ddeb024b62e303640e17fdd57dedb3aeb4a2c1b7c93059f9c1d7118d77caac1cd0f6556e46cbc991c1bb16970273dea833d01e5090d061a0c6d25af2415cd2878af97f6d0e7f1f936247b394ecb9bd484da6be936dee9b0b92dc90101a1b4295e97a9772f2263eb09431995aa173df4ca2abd687d87706f0f93eaa5e13cbe3b574fa3cfe94502ace25265778da6960d561381769c24e0cbd7aac73c16f95ae74ff7ec38124f7c722b9cb151d4b6841343f29be8f35145e1b27021056820fed77003df8554b4155716c8cf6049ef5e318481460a8ce3be7c7bfac695255be84dc491c19e9dedc449dd3471728cd2a3ee51324ccb3eef121e3e08f8e18f0006ea8957371d9f2f739f0b89e4db11e5c6430ada61572e589519fbad4498b460ce6e4407fc2d8f2dd4293a50a0cb8fcaaf35cd9a8cc097e3603fbfa08d9036f52b3e7fcce11b83ad28a4ac12dba0395a0cc871cefd1a2856fffb3f28d82ce35cf80579974778bab13d9b3578d8c75a2d196087a2cd439aff2bb33f2db24ac175fff4ed91d36a4cdbfaf3f83074f03894ea40f17034629890da3efdbb41141b38368ab532209b69f057ddc559c19bc8ae62bf3fd564c9a35d9a83d14a95834a92bae6d9a29ae5e8ece07910d16433e4c6230c9bd7d68b47de0de9843988af6dc88b5301820443bd4d0537778bf6b4c1dd067fcf14b81015f2a67c7f2a28f9cb7e0684d3cb4b1c24d9b343122a086611b489532f1c3a26779da1706c6759d96d8ab>",
    "I1 = <b 0xce000000010897a297ecc34cd6dd000044d0ec2e2e1ea2991f467ace4222129b5a098823784694b4897b9986ae0b7280135fa85e196d9ad980b150122129ce2a9379531b0fd3e871ca5fdb883c369832f730e272d7b8b74f393f9f0fa43f11e510ecb2219a52984410c204cf875585340c62238e14ad04dff382f2c200e0ee22fe743b9c6b8b043121c5710ec289f471c91ee414fca8b8be8419ae8ce7ffc53837f6ade262891895f3f4cecd31bc93ac5599e18e4f01b472362b8056c3172b513051f8322d1062997ef4a383b01706598d08d48c221d30e74c7ce000cdad36b706b1bf9b0607c32ec4b3203a4ee21ab64df336212b9758280803fcab14933b0e7ee1e04a7becce3e2633f4852585c567894a5f9efe9706a151b615856647e8b7dba69ab357b3982f554549bef9256111b2d67afde0b496f16962d4957ff654232aa9e845b61463908309cfd9de0a6abf5f425f577d7e5f6440652aa8da5f73588e82e9470f3b21b27b28c649506ae1a7f5f15b876f56abc4615f49911549b9bb39dd804fde182bd2dcec0c33bad9b138ca07d4a4a1650a2c2686acea05727e2a78962a840ae428f55627516e73c83dd8893b02358e81b524b4d99fda6df52b3a8d7a5291326e7ac9d773c5b43b8444554ef5aea104a738ed650aa979674bbed38da58ac29d87c29d387d80b526065baeb073ce65f075ccb56e47533aef357dceaa8293a523c5f6f790be90e4731123d3c6152a70576e90b4ab5bc5ead01576c68ab633ff7d36dcde2a0b2c68897e1acfc4d6483aaaeb635dd63c96b2b6a7a2bfe042f6aed82e5363aa850aace12ee3b1a93f30d8ab9537df483152a5527faca21efc9981b304f11fc95336f5b9637b174c5a0659e2b22e159a9fed4b8e93047371175b1d6d9cc8ab745f3b2281537d1c75fb9451871864efa5d184c38c185fd203de206751b92620f7c369e031d2041e152040920ac2c5ab5340bfc9d0561176abf10a147287ea90758575ac6a9f5ac9f390d0d5b23ee12af583383d994e22c0cf42383834bcd3ada1b3825a0664d8f3fb678261d57601ddf94a8a68a7c273a18c08aa99c7ad8c6c42eab67718843597ec9930457359dfdfbce024afc2dcf9348579a57d8d3490b2fa99f278f1c37d87dad9b221acd575192ffae1784f8e60ec7cee4068b6b988f0433d96d6a1b1865f4e155e9fe020279f434f3bf1bd117b717b92f6cd1cc9bea7d45978bcc3f24bda631a36910110a6ec06da35f8966c9279d130347594f13e9e07514fa370754d1424c0a1545c5070ef9fb2acd14233e8a50bfc5978b5bdf8bc1714731f798d21e2004117c61f2989dd44f0cf027b27d4019e81ed4b5c31db347c4a3a4d85048d7093cf16753d7b0d15e078f5c7a5205dc2f87e330a1f716738dce1c6180e9d02869b5546f1c4d2748f8c90d9693cba4e0079297d22fd61402dea32ff0eb69ebd65a5d0b687d87e3a8b2c42b648aa723c7c7daf37abcc4bb85caea2ee8f55bec20e913b3324ab8f5c3304f820d42ad1b9f2ffc1a3af9927136b4419e1e579ab4c2ae3c776d293d397d575df181e6cae0a4ada5d67ecea171cca3288d57c7bbdaee3befe745fb7d634f70386d873b90c4d6c6596bb65af68f9e5121e67ebf0d89d3c909ceedfb32ce9575a7758ff080724e1ab5d5f43074ecb53a479af21ed03d7b6899c36631c0166f9d47e5e1d4528a5d3d3f744029c4b1c190cbfbad06f5f83f7ad0429fa9a2719c56ffe3783460e166de2d8>",
];
#[allow(dead_code)]
pub fn warp_pick_i1() -> &'static str {
    WARP_I1_MASKS[fastrand::usize(0..WARP_I1_MASKS.len())]
}

// ---------- парсинг INI ----------

#[derive(Debug, Default, Clone)]
pub struct WarpConfig {
    pub private_key: String,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: i32,
    pub jc: i32,
    pub jmin: i32,
    pub jmax: i32,
    pub s1: i32,
    pub s2: i32,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
    pub has_amnezia: bool,
    pub awg_extras: Vec<String>,
    pub peer_public_key: String,
    pub peer_preshared_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub keepalive: i32,
}

fn parse_num(v: &str) -> i32 {
    v.trim().parse().unwrap_or(0)
}

fn parse_u32(v: &str) -> u32 {
    v.trim().parse().unwrap_or(0)
}

// parseWarpConfig — разбор INI ([Interface]/[Peer]) с wg-quick полями
// и амнезия-параметрами. Один [Peer], ключи нечувствительны к регистру.
pub fn parse_warp_config(conf: &str) -> Result<WarpConfig, String> {
    let mut c = WarpConfig {
        mtu: 1280,
        ..Default::default()
    };
    let mut section = String::new();
    let mut peer_sections = 0;
    for raw in conf.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            section = line.trim_matches(|c| c == '[' || c == ']').trim().to_lowercase();
            if section == "peer" {
                peer_sections += 1;
                if peer_sections > 1 {
                    return Err("конфиг с несколькими [Peer] не поддерживается — оставьте один пир (остальные молча терялись)".into());
                }
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_lowercase();
        let val = v.trim();
        if section == "interface" {
            match key.as_str() {
                "privatekey" => c.private_key = val.to_string(),
                "address" => {
                    for a in val.split(',') {
                        let a = a.trim();
                        if !a.is_empty() {
                            c.addresses.push(a.to_string());
                        }
                    }
                }
                "dns" => {
                    for d in val.split(',') {
                        let d = d.trim();
                        if !d.is_empty() {
                            c.dns.push(d.to_string());
                        }
                    }
                }
                "mtu" => c.mtu = parse_num(val),
                "jc" => {
                    c.jc = parse_num(val);
                    c.has_amnezia = true;
                }
                "jmin" => {
                    c.jmin = parse_num(val);
                    c.has_amnezia = true;
                }
                "jmax" => {
                    c.jmax = parse_num(val);
                    c.has_amnezia = true;
                }
                "s1" => {
                    c.s1 = parse_num(val);
                    c.has_amnezia = true;
                }
                "s2" => {
                    c.s2 = parse_num(val);
                    c.has_amnezia = true;
                }
                "h1" => {
                    c.h1 = parse_u32(val);
                    c.has_amnezia = true;
                }
                "h2" => {
                    c.h2 = parse_u32(val);
                    c.has_amnezia = true;
                }
                "h3" => {
                    c.h3 = parse_u32(val);
                    c.has_amnezia = true;
                }
                "h4" => {
                    c.h4 = parse_u32(val);
                    c.has_amnezia = true;
                }
                // спец-поля AmneziaWG 1.5 (I1–I5, J1–J3, ITime)
                "i1" | "i2" | "i3" | "i4" | "i5" | "j1" | "j2" | "j3" | "itime" => {
                    if !val.is_empty() {
                        c.awg_extras.push(format!("{} = {}", key, val));
                    }
                }
                _ => {}
            }
        } else if section == "peer" {
            match key.as_str() {
                "publickey" => c.peer_public_key = val.to_string(),
                "presharedkey" => c.peer_preshared_key = val.to_string(),
                "endpoint" => c.endpoint = val.to_string(),
                "allowedips" => {
                    for a in val.split(',') {
                        let a = a.trim();
                        if !a.is_empty() {
                            c.allowed_ips.push(a.to_string());
                        }
                    }
                }
                "persistentkeepalive" => c.keepalive = parse_num(val),
                _ => {}
            }
        }
    }
    if c.private_key.is_empty() {
        return Err("в конфиге нет PrivateKey".into());
    }
    if c.peer_public_key.is_empty() || c.endpoint.is_empty() {
        return Err("в конфиге нет PublicKey/Endpoint пира".into());
    }
    Ok(c)
}

impl WarpConfig {
    // hostPort — endpoint как (host, port)
    pub fn host_port(&self) -> (String, i32) {
        let ep = self.endpoint.trim();
        if let Some(rest) = ep.strip_prefix('[') {
            // [v6]:port
            if let Some(rb) = rest.find(']') {
                let host = rest[..rb].to_string();
                let port = rest[rb + 1..].trim_start_matches(':').parse().unwrap_or(0);
                return (host, port);
            }
        }
        match ep.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().unwrap_or(0)),
            // голый IPv6 без порта («2001:db8::1»): раньше резался rsplit'ом в
            // хост-мусор «2001:db8:» + порт «1», и peer отвергался ядром
            _ => (ep.to_string(), 0),
        }
    }
}

// warpDecodeConfFile — текст конфига из байтов файла: BOM + UTF-16.
pub fn warp_decode_conf_file(data: &[u8]) -> String {
    if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
        return String::from_utf8_lossy(&data[3..]).to_string();
    }
    let decode_utf16 = |be: bool| -> String {
        let mut units = Vec::with_capacity((data.len() - 2) / 2);
        let mut i = 2;
        while i + 1 < data.len() {
            let u = if be {
                u16::from_be_bytes([data[i], data[i + 1]])
            } else {
                u16::from_le_bytes([data[i], data[i + 1]])
            };
            units.push(u);
            i += 2;
        }
        String::from_utf16_lossy(&units)
    };
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE {
        return decode_utf16(false);
    }
    if data.len() >= 2 && data[0] == 0xFE && data[1] == 0xFF {
        return decode_utf16(true);
    }
    String::from_utf8_lossy(data).to_string()
}

// ---------- sing-box конфиг WARP ----------

// ---------- пробы (cloudflare trace) ----------

// warpProbeAndIP — транспорт + внешний IP одним запросом на 1.1.1.1/cdn-cgi/trace
// (IP-литерал, без DNS): таймаут = мёртвый транспорт, warp=on = реально через WARP.
#[allow(unused_assignments)] // last_err: инициал перезаписывается до чтения
pub fn warp_probe_and_ip(deadline: Instant) -> Result<(bool, String), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| e.to_string())?;
    let mut last_err = String::new();
    loop {
        match warp_probe_once(&client, deadline) {
            Ok(r) => return Ok(r),
            Err(e) => last_err = e,
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(1200));
    }
    if last_err.is_empty() {
        last_err = "таймаут".into();
    }
    Err(last_err)
}

fn warp_probe_once(client: &reqwest::blocking::Client, deadline: Instant) -> Result<(bool, String), String> {
    for url in ["https://1.1.1.1/cdn-cgi/trace", "https://www.cloudflare.com/cdn-cgi/trace"] {
        if Instant::now() >= deadline {
            return Err("таймаут пробы".into());
        }
        let Ok(resp) = client.get(url).send() else {
            continue;
        };
        let mut raw = Vec::new();
        if resp.take(1 << 16).read_to_end(&mut raw).is_err() {
            continue;
        }
        let mut kv = std::collections::HashMap::new();
        for ln in String::from_utf8_lossy(&raw).split('\n') {
            if let Some(i) = ln.find('=') {
                if i > 0 {
                    kv.insert(ln[..i].trim().to_string(), ln[i + 1..].trim().to_string());
                }
            }
        }
        let warp = kv.get("warp").cloned().unwrap_or_default();
        let ip = kv.get("ip").cloned().unwrap_or_default();
        if warp == "on" || warp == "plus" {
            return Ok((true, ip));
        }
        if warp.is_empty() {
            // ответ не trace (подмена/заглушка/ошибка CDN): пробуем второй URL —
            // раньше проба падала сразу, не попробовав запасной адрес
            continue;
        }
        return Err(format!("трафик идёт мимо туннеля (warp={})", warp));
    }
    Err("trace недоступен".into())
}

// warp_probe_once_client — одиночная проба с новым клиентом (ре-проб 30 с).
pub fn warp_probe_once_client(deadline: Instant) -> Result<(bool, String), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| e.to_string())?;
    warp_probe_once(&client, deadline)
}

// warp_probe_ip6 — внешний IPv6 туннеля. Endpoint только по v6-литералу:
// если у туннеля нет v6-маршрута (::/0 в конфиге или провайдер без v6),
// соединение просто не пройдёт — значит, v6 показывать нечего.
pub fn warp_probe_ip6(deadline: Instant) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|e| e.to_string())?;
    for url in [
        "https://[2606:4700:4700::1111]/cdn-cgi/trace",
        "https://[2606:4700:4700::1001]/cdn-cgi/trace",
    ] {
        if Instant::now() >= deadline {
            return Err("таймаут v6-пробы".into());
        }
        let Ok(resp) = client.get(url).send() else {
            continue;
        };
        let mut raw = Vec::new();
        if resp.take(1 << 16).read_to_end(&mut raw).is_err() {
            continue;
        }
        for ln in String::from_utf8_lossy(&raw).split('\n') {
            if let Some(i) = ln.find('=') {
                if ln[..i].trim() == "ip" {
                    let ip = ln[i + 1..].trim().to_string();
                    // trace мог ответить по v4-фолбэку — берём только честный v6
                    if ip.contains(':') {
                        return Ok(ip);
                    }
                }
            }
        }
    }
    Err("IPv6 недоступен".into())
}

// ---------- генератор: регистрация в Cloudflare ----------

// warp_endpoint_candidates — IP-кандидаты: резолв engage.cloudflareclient.com,
// адрес из ответа регистрации (если есть) и известные anycast-IP WARP.
#[allow(dead_code)]
fn warp_endpoint_candidates(api_ip: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |ip: String| {
        if !out.contains(&ip) {
            out.push(ip);
        }
    };
    if let Ok(addrs) = ("engage.cloudflareclient.com", 443u16).to_socket_addrs() {
        for a in addrs {
            if let IpAddr::V4(v) = a.ip() {
                push(v.to_string());
            }
        }
    }
    if let Some(ip) = api_ip {
        push(ip.to_string());
    }
    for ip in WARP_KNOWN_IPS {
        push((*ip).to_string());
    }
    out
}

// warp_probe_ip — достижимость IP по TCP 443 за 2 с. UDP-порт так не проверить
// (нужен полный WG-handshake), поэтому порт выбирается случайным из списка
// живых, а проба отсекает только заблокированные целиком IP.
#[allow(dead_code)]
fn warp_probe_ip(ip: &str) -> Option<Duration> {
    let addr: SocketAddr = format!("{}:443", ip).parse().ok()?;
    let start = Instant::now();
    TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    Some(start.elapsed())
}

// warp_pick_endpoint — авто-выбор endpoint'а генератора: самый быстрый живой
// IP + случайный порт из WARP_PORTS. api_endpoint — ip:port, выданный
// Cloudflare при регистрации: его IP участвует в пробе, а сам он становится
// запасным вариантом, если ни один кандидат не ответил.
#[allow(dead_code)]
pub fn warp_pick_endpoint(api_endpoint: &str) -> String {
    let port = WARP_PORTS[fastrand::usize(0..WARP_PORTS.len())];
    let api_ip = api_endpoint
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']'))
        .filter(|h| h.parse::<std::net::Ipv4Addr>().is_ok());
    let cands = warp_endpoint_candidates(api_ip);
    // проба параллельно, по потоку на IP; каждая ограничена таймаутом 2 с
    let (tx, rx) = std::sync::mpsc::channel();
    for ip in &cands {
        let ip = ip.clone();
        let tx = tx.clone();
        std::thread::spawn(move || {
            if let Some(rtt) = warp_probe_ip(&ip) {
                let _ = tx.send((ip, rtt));
            }
        });
    }
    drop(tx); // канал закроется, когда все пробы завершатся
    let mut results: Vec<(String, Duration)> = rx.iter().collect();
    results.sort_by_key(|(_, rtt)| *rtt);
    if let Some((ip, rtt)) = results.first() {
        log_add(
            "warp",
            &format!("endpoint {} живой (проба {} мс) — порт {}", ip, rtt.as_millis(), port),
        );
        return format!("{}:{}", ip, port);
    }
    let api = api_endpoint.trim();
    if !api.is_empty() {
        log_add("warp", &format!("живых IP не нашлось — берём выданный Cloudflare {}", api));
        return api.to_string();
    }
    log_add("warp", &format!("живых IP не нашлось — фолбэк 162.159.192.1:{}", port));
    format!("162.159.192.1:{}", port)
}

// warpGenKeypair — пара ключей WireGuard (с клампом, как wg genkey).
#[allow(dead_code)]
fn warp_gen_keypair() -> Result<(String, String), String> {
    let mut priv_raw = [0u8; 32];
    getrandom::fill(&mut priv_raw).map_err(|e| e.to_string())?;
    priv_raw[0] &= 248;
    priv_raw[31] &= 127;
    priv_raw[31] |= 64;
    let pub_raw = x25519_dalek::x25519(priv_raw, [9u8; 32]);
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    Ok((b64(&priv_raw), b64(&pub_raw)))
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CfResp {
    #[serde(default)]
    result: CfResult,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct CfResult {
    #[serde(default)]
    id: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    config: CfConfig,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct CfConfig {
    #[serde(default)]
    interface: CfInterface,
    #[serde(default)]
    peers: Vec<CfPeer>,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct CfInterface {
    #[serde(default)]
    addresses: CfAddresses,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct CfAddresses {
    #[serde(default)]
    v4: String,
    // v6 из ответа регистрации в конфиг больше не пишется (v4-only генерация,
    // как в warp-config-ru) — поле оставлено для полноты разбора ответа
    #[allow(dead_code)]
    #[serde(default)]
    v6: String,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct CfPeer {
    #[serde(default, rename = "public_key")]
    public_key: String,
    // endpoint, выданный Cloudflare при регистрации (обычно ip:2408) —
    // участвует в авто-выборе и служит запасным вариантом
    #[serde(default)]
    endpoint: CfEndpoint,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct CfEndpoint {
    #[serde(default)]
    v4: String,
    #[serde(default)]
    v6: String,
}

use serde::Deserialize;

#[allow(dead_code)]
fn cf_request(method: &str, url: &str, token: &str, body: Option<&str>) -> Result<CfResp, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = match method {
        "POST" => client.post(url),
        "PATCH" => client.patch(url),
        _ => client.get(url),
    }
    .header("User-Agent", WARP_REG_UA)
    .header("Content-Type", "application/json");
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", token));
    }
    if let Some(b) = body {
        req = req.body(b.to_string());
    }
    let resp = req.send().map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let mut raw = Vec::new();
    resp.take(1 << 20).read_to_end(&mut raw).map_err(|e| e.to_string())?;
    if status >= 300 {
        return Err(format!(
            "HTTP {}: {}",
            status,
            String::from_utf8_lossy(&raw).replace('\n', " ").trim().to_string()
        ));
    }
    serde_json::from_slice(&raw).map_err(|e| e.to_string())
}

// cf_no_retry — клиентская HTTP-ошибка (4xx, кроме 429): повторять
// бессмысленно, та же ошибка вернётся; раньше ретраились и 401/422.
#[allow(dead_code)]
fn cf_no_retry(err: &str) -> bool {
    let Some(rest) = err.strip_prefix("HTTP ") else {
        return false;
    };
    let code = rest.split(':').next().unwrap_or("").trim();
    matches!(
        code,
        "400" | "401" | "403" | "404" | "405" | "422"
    )
}

// warpCFRequestRetry — 3 попытки (бэкофф 1с/2с): регистрация идёт напрямую.
#[allow(unused_assignments)]
#[allow(dead_code)]
fn cf_request_retry(method: &str, url: &str, token: &str, body: Option<&str>) -> Result<CfResp, String> {
    let mut last_err = String::new();
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(1 << (attempt - 1)));
        }
        match cf_request(method, url, token, body) {
            Ok(r) => return Ok(r),
            Err(e) => {
                if cf_no_retry(&e) {
                    return Err(e);
                }
                last_err = e;
            }
        }
    }
    Err(last_err)
}

// ---------- генератор: через сторонний сервис ----------

// warp_force_endpoint — подменить строку Endpoint в готовом конфиге
fn warp_force_endpoint(conf: &str, endpoint: &str) -> String {
    let mut out = String::new();
    for ln in conf.lines() {
        let k = ln.trim().to_lowercase();
        if k.starts_with("endpoint") {
            out.push_str(&format!("Endpoint = {}\n", endpoint));
        } else {
            out.push_str(ln);
            out.push('\n');
        }
    }
    out
}

// VpnGenerateWarpConf — конфиг приходит ГОТОВЫЙ со стороннего генератора
// warp-config-ru (AppsGanin, MIT): он сам регистрирует устройство в
// Cloudflare С СВОЕГО бэкенда (Netlify), а не с IP пользователя. Прямой
// регистр с мобильных/заблокированных сетей регулярно не проходит, а конфиги
// этого генератора на таких сетях рабочие (проверено пользователем).
// endpoint пусто — «Авто» сайта (случайный IP из пула × случайный порт из
// классики); заданный вручную endpoint передаётся сайту и дописывается в
// готовый конфиг поверх его выбора (внепуловые хосты сайт молча заменит
// авто — поэтому и дублируем).
// vercel-зеркало непригодно для программных клиентов: Vercel Security
// Checkpoint требует браузерный JS-челлендж (curl/reqwest всегда получают
// 429 HTML, браузер сайта проходит). Берём зеркало netlify того же
// генератора — отвечает программным клиентам без челленджа (проверено).
const WARP_GEN_API: &str = "https://warp-ru.netlify.app/api/generate";

pub fn generate_warp_conf(endpoint: &str) -> Result<String, String> {
    let mut body = json!({ "format": "amneziawg", "host": "auto", "port": "auto" });
    let manual = endpoint.trim().to_string();
    if !manual.is_empty() {
        if let Some((h, p)) = manual.rsplit_once(':') {
            if let Ok(port) = p.trim().parse::<u16>() {
                let host = h.trim().trim_matches(|c| c == '[' || c == ']');
                body["host"] = json!(host);
                body["port"] = json!(port);
            }
        }
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(45))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(WARP_GEN_API)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("Генератор warp-ru недоступен: {}", e))?;
    let status = resp.status().as_u16();
    let mut raw = Vec::new();
    resp.take(1 << 20).read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| format!("Генератор вернул не JSON (HTTP {}): {}", status, e))?;
    if !v.get("success").and_then(|x| x.as_bool()).unwrap_or(false) {
        let err = v.get("error").and_then(|x| x.as_str()).unwrap_or("причина не указана");
        return Err(format!("Генератор warp-ru: {}", err));
    }
    let conf = v.pointer("/data/config").and_then(|x| x.as_str()).unwrap_or("");
    if conf.is_empty() {
        return Err("Генератор warp-ru вернул пустой конфиг".into());
    }
    if let Err(e) = parse_warp_config(conf) {
        return Err(format!("Генератор вернул сломанный конфиг: {}", e));
    }
    if let Some(ep) = v.pointer("/data/meta/endpoint").and_then(|x| x.as_str()) {
        log_add("warp", &format!("конфиг от warp-ru сгенерирован, endpoint {}", ep));
    }
    if manual.is_empty() {
        Ok(conf.to_string())
    } else {
        Ok(warp_force_endpoint(conf, &manual))
    }
}

// СТАРЫЙ прямой путь (регистрация с IP пользователя в
// api.cloudflareclient.com) отключён: регистрация с мобильных/заблокированных
// сетей регулярно отклоняется, а конфиги выходили нерабочими. Оставлен как
// референс — вернуть вызовом из generate_warp_conf, если понадобится.
#[allow(dead_code)]
fn generate_warp_conf_direct(endpoint: &str) -> Result<String, String> {
    let (priv_key, pub_key) = warp_gen_keypair().map_err(|e| format!("Генерация ключей: {}", e))?;
    let tos = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let body = json!({
        "install_id": "",
        "tos": tos.to_string(),
        "key": pub_key,
        "fcm_token": "",
        "type": "ios",
        "locale": "en_US"
    });
    let r1 = cf_request_retry(
        "POST",
        &format!("{}/reg", WARP_REG_BASE),
        "",
        Some(body.to_string().as_str()),
    )
    .map_err(|e| format!("Регистрация в Cloudflare: {}", e))?;
    if r1.result.id.is_empty() || r1.result.token.is_empty() {
        return Err("Cloudflare вернул пустой id/token".into());
    }
    let r2 = cf_request_retry(
        "PATCH",
        &format!("{}/reg/{}", WARP_REG_BASE, r1.result.id),
        &r1.result.token,
        Some(json!({"warp_enabled": true}).to_string().as_str()),
    )
    .map_err(|e| format!("Включение WARP: {}", e))?;
    let peer_empty = r2.result.config.peers.is_empty();
    if peer_empty || r2.result.config.peers[0].public_key.is_empty() || r2.result.config.interface.addresses.v4.is_empty() {
        return Err("Cloudflare вернул неполный конфиг".into());
    }
    let endpoint = {
        let t = endpoint.trim();
        if t.is_empty() {
            // авто: проба живых IP + случайный порт из списка живых; запасной
            // вариант — то, что Cloudflare выдал в ответе регистрации
            let peer = &r2.result.config.peers[0].endpoint;
            let api_ep = if peer.v4.trim().is_empty() { peer.v6.as_str() } else { peer.v4.as_str() };
            warp_pick_endpoint(api_ep)
        } else {
            t.to_string()
        }
    };
    let v4 = r2.result.config.interface.addresses.v4.split('/').next().unwrap_or("").to_string();
    let mut b = String::new();
    // v4-only, как в warp-config-ru: мёртвый v6-путь (мобильная сеть/роутер
    // без v6) даёт happy-eyeballs зависания; v6 при желании дописывают вручную
    b.push_str(&format!("[Interface]\nPrivateKey = {}\n", priv_key));
    b.push_str(&format!("Address = {}\nDNS = {}\nMTU = 1280\n", v4, WARP_GEN_DNS));
    b.push_str("Jc = 4\nJmin = 40\nJmax = 70\n");
    b.push_str("H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n");
    b.push_str(warp_pick_i1());
    b.push('\n');
    b.push_str(&format!("\n[Peer]\nPublicKey = {}\n", r2.result.config.peers[0].public_key));
    b.push_str("AllowedIPs = 0.0.0.0/0\n");
    b.push_str(&format!("Endpoint = {}\n", endpoint));
    // PersistentKeepalive — поле ПИРА: wg-quick игнорирует его в [Interface],
    // а наш парсер (parse_warp_config) читает только в секции [Peer]. Раньше
    // строка писалась в [Interface] и настройка молча терялась на круговороте
    // конфига (генератор → парсер → sing-box JSON).
    b.push_str("PersistentKeepalive = 25\n");
    Ok(b)
}

// ---------- CRUD конфигов ----------

// warpSafeFileName — имя файла без запрещённых символов, зарезервированных
// имён Windows (CON, NUL, COM1…) и хвостовых точек.
pub fn warp_safe_file_name(name: &str) -> String {
    let mut safe: String = name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect();
    let upper = safe.trim_end_matches('.').to_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL"
            | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
            | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
    ) {
        safe = format!("_{}", safe);
    }
    let safe = safe.trim_end_matches('.').to_string();
    if safe.is_empty() {
        "config".to_string()
    } else {
        safe
    }
}

use crate::models::VpnProxy;
use crate::store;
use crate::vpnlinks::new_id;

// VpnAddWarpConfig — добавить WARP/AmneziaWG-конфиг (INI) как сервер списка VPN.
pub fn add_warp_config(state: &crate::state::AppState, name: &str, conf: &str) -> String {
    let conf = conf.replace("\r\n", "\n").trim().to_string();
    if conf.is_empty() {
        return "⚠️ Вставь текст конфига".to_string();
    }
    let cfg = match parse_warp_config(&conf) {
        Ok(c) => c,
        Err(e) => return format!("❌ {}", e),
    };
    let tools = state.tools();
    let _guard = state.vpn_store.lock().unwrap_or_else(|e| e.into_inner());
    let mut list = store::load_vpn_proxies(&tools);
    if list.iter().any(|p| p.raw.trim() == conf) {
        return "⚠️ Такой конфиг уже добавлен".to_string();
    }
    let (host, port) = cfg.host_port();
    let name = if name.trim().is_empty() {
        format!("WARP · {}:{}", host, port)
    } else {
        name.trim().to_string()
    };
    list.push(VpnProxy {
        id: new_id(),
        proto: "warp".into(),
        name: name.clone(),
        host,
        port,
        raw: conf,
        sub_id: None,
        manual: None,
        extra: None,
    });
    if let Err(e) = store::save_vpn_proxies(&tools, &list) {
        return format!("❌ Не сохранилось: {}", e);
    }
    format!("✅ Конфиг добавлен: {}", name)
}

// VpnExportWarpConf — сохранить конфиг сервера в файл через диалог.
pub fn export_warp_conf(state: &crate::state::AppState, id: &str) -> String {
    let tools = state.tools();
    let list = store::load_vpn_proxies(&tools);
    let Some(p) = list.iter().find(|x| x.id == id) else {
        return "⚠️ Конфиг не найден".to_string();
    };
    if p.raw.trim().is_empty() {
        return "⚠️ У этого сервера нет текста конфига".to_string();
    }
    let default_name = format!("{}.conf", warp_safe_file_name(&p.name));
    let Some(path) = rfd::FileDialog::new()
        .set_title("Куда сохранить конфиг")
        .add_filter("Конфиги (*.conf)", &["conf"])
        .set_file_name(&default_name)
        .save_file()
    else {
        return String::new();
    };
    match std::fs::write(&path, p.raw.as_bytes()) {
        Ok(_) => format!("✅ Сохранено: {}", path.display()),
        Err(e) => format!("❌ Не смог записать: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // парсер хранит спец-поля как «ключ в нижнем регистре = значение»
    fn expected_extras(mask: &str) -> Vec<String> {
        mask.split('\n')
            .map(|l| {
                let (k, v) = l.split_once('=').expect("строка маски «ключ = значение»");
                format!("{} = {}", k.trim().to_lowercase(), v.trim())
            })
            .collect()
    }

    // Каждая вшитая маска (включая SIP-пару I1+I2) обязана проходить парсер
    // целиком, без усечений — иначе add_warp_config отвергнет сгенерированный
    // конфиг с этой маской или ядро получит обрезанное значение.
    #[test]
    fn all_i1_masks_parse() {
        for m in WARP_I1_MASKS {
            let conf = format!(
                "[Interface]\nPrivateKey = nucoX1UBje/swWOJJfLjQv16MiTDR2cjl16S5RdttAo=\nAddress = 172.16.0.2\nDNS = 1.1.1.1\nMTU = 1280\n{}\n\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 162.159.195.1:500\n",
                m
            );
            let cfg = parse_warp_config(&conf).expect("маска должна парситься");
            assert_eq!(cfg.awg_extras, expected_extras(m));
        }
    }

}
