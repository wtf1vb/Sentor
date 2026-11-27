// Geo location, service checks, country flags - port of Go vpn.go geo sections
// and vpn_geo_countries.go.
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::logging::log_add;
use crate::models::{ServerGeo, ServiceCheck, VpnGeoInfo, VpnServicesInfo};
use crate::state::AppState;

// ---------- центроиды стран (для точек выхода каскадов) ----------

const COUNTRY_CENTROIDS: &str = "ac:-7.9,-14.4;ad:42.5,1.6;ae:24.0,54.0;af:33.9,67.7;ag:17.1,-61.8;ai:18.2,-63.1;al:41.2,20.2;am:40.1,45.0;ao:-12.3,17.5;aq:-75.0,0.0;ar:-35.4,-65.2;as:-14.3,-170.7;at:47.6,14.1;au:-25.7,134.5;aw:12.5,-70.0;ax:60.2,19.9;az:40.3,47.7;ba:44.2,17.8;bb:13.2,-59.5;bd:23.8,90.3;be:50.6,4.6;bf:12.3,-1.7;bg:42.7,25.5;bh:26.0,50.6;bi:-3.4,29.9;bj:9.6,2.3;bl:18.2,-63.0;bm:32.3,-64.8;bn:4.5,114.7;bo:-16.7,-64.7;bq:12.2,-68.3;br:-11.9,-51.9;bs:24.7,-78.0;bt:27.4,90.4;bv:-54.4,3.4;bw:-22.2,23.8;by:53.7,28.0;bz:17.2,-88.7;ca:58.0,-102.6;cc:-12.2,96.8;cd:-3.4,23.6;cf:6.6,20.9;cg:-1.0,15.8;ch:46.8,8.2;ci:7.6,-5.5;ck:-19.6,-159.4;cl:-35.7,-71.3;cm:5.7,12.7;cn:36.6,103.9;co:3.9,-73.1;cr:9.9,-84.2;cu:21.6,-79.0;cv:16.0,-24.0;cw:12.2,-69.0;cx:-10.4,105.7;cy:35.1,33.4;cz:49.8,15.3;de:51.1,10.4;dg:-7.3,72.4;dj:11.7,42.6;dk:56.0,9.9;dm:15.4,-61.4;do:18.9,-70.5;dz:28.2,2.6;ea:35.9,-5.3;ec:-1.4,-78.4;ee:58.7,25.5;eg:26.6,29.8;eh:24.2,-12.9;er:15.2,39.8;es:40.2,-3.6;et:9.1,40.5;eu:50.1,9.4;fi:64.5,26.0;fj:-17.8,178.0;fk:-51.7,-59.5;fm:6.9,158.2;fo:62.0,-6.9;fr:46.6,2.4;ga:-0.6,11.8;gb:54.1,-2.9;gd:12.1,-61.7;ge:42.2,43.5;gf:4.0,-53.0;gg:49.4,-2.6;gh:7.9,-1.2;gi:36.1,-5.3;gl:71.7,-42.2;gm:13.4,-15.4;gn:10.4,-11.0;gp:16.2,-61.5;gq:1.6,10.5;gr:39.1,21.9;gs:-54.4,-36.6;gt:15.7,-90.2;gu:13.4,144.8;gw:12.0,-15.0;gy:4.8,-58.9;hk:22.4,114.1;hm:-53.1,73.5;hn:14.8,-86.6;hr:45.6,16.4;ht:19.0,-72.6;hu:47.2,19.4;ic:28.3,-16.6;id:-2.2,117.4;ie:53.2,-8.1;il:31.4,35.0;im:54.2,-4.6;in:22.4,79.6;io:-6.3,71.9;iq:33.0,43.8;ir:32.6,54.3;is:64.9,-18.6;it:42.8,12.8;je:49.2,-2.1;jm:18.1,-77.3;jo:31.3,36.8;jp:36.6,138.0;ke:0.6,37.8;kg:41.3,74.6;kh:12.7,104.9;ki:1.9,-157.4;km:-11.7,43.4;kn:17.3,-62.7;kp:40.2,127.2;kr:36.4,128.0;kw:29.3,47.6;ky:19.3,-81.3;kz:48.2,67.3;la:18.2,103.9;lb:33.9,35.9;lc:13.9,-61.0;li:47.2,9.5;lk:7.6,80.7;lr:6.4,-9.3;ls:-29.6,28.3;lt:55.3,23.9;lu:49.8,6.1;lv:56.9,24.9;ly:27.0,17.3;ma:31.9,-6.9;mc:43.7,7.4;md:47.2,28.5;me:42.8,19.2;mf:18.1,-63.0;mg:-19.4,46.7;mh:7.1,171.1;mk:41.6,21.7;ml:17.6,-4.0;mm:21.2,96.5;mn:46.9,103.5;mo:22.2,113.5;mp:15.1,145.7;mq:14.6,-61.0;mr:20.3,-10.3;ms:16.7,-62.2;mt:35.9,14.4;mu:-20.3,57.6;mv:3.2,73.2;mw:-13.3,34.3;mx:23.6,-102.5;my:4.2,102.0;mz:-18.7,35.5;na:-22.1,17.2;nc:-21.3,165.6;ne:17.4,9.4;nf:-29.0,167.9;ng:9.6,8.1;ni:12.9,-85.2;nl:52.2,5.6;no:64.6,11.5;np:28.3,84.0;nr:-0.5,166.9;nu:-19.0,-169.9;nz:-41.8,172.8;om:21.5,55.9;pa:8.5,-80.1;pe:-9.2,-75.0;pf:-17.7,-149.4;pg:-6.5,145.2;ph:12.9,121.8;pk:29.9,69.4;pl:52.1,19.4;pm:46.9,-56.3;pn:-24.4,-124.8;pr:18.2,-66.4;ps:31.9,35.2;pt:39.6,-8.2;pw:7.5,134.6;py:-23.3,-58.3;qa:25.3,51.2;re:-21.1,55.5;ro:45.8,25.0;rs:44.1,20.9;ru:61.5,99.0;rw:-2.0,29.9;sa:24.1,45.1;sb:-9.6,160.2;sc:-4.7,55.5;sd:15.8,30.2;se:62.8,16.7;sg:1.35,103.8;sh:-15.9,-5.7;si:46.1,14.8;sj:77.5,17.9;sk:48.7,19.7;sl:8.5,-11.8;sm:43.9,12.5;sn:14.4,-14.5;so:6.0,46.2;sr:4.0,-56.0;ss:7.3,30.3;st:0.2,6.6;sv:13.7,-88.9;sx:18.0,-63.0;sy:35.0,38.5;sz:-26.5,31.5;ta:-37.1,-12.3;tc:21.7,-71.8;td:15.4,18.7;tf:-49.3,69.5;tg:8.5,1.0;th:15.1,101.0;tj:38.9,71.3;tk:-9.0,-171.8;tl:-8.8,125.9;tm:39.1,59.4;tn:34.1,9.6;to:-21.2,-175.2;tr:39.0,35.2;tt:10.5,-61.3;tv:-7.1,177.6;tw:23.7,121.0;tz:-6.4,34.8;ua:49.0,31.4;ug:1.3,32.4;um:19.3,-166.6;un:40.7,-74.0;us:39.8,-98.6;uy:-32.8,-56.0;uz:41.4,64.6;va:41.9,12.45;vc:13.2,-61.2;ve:7.1,-66.2;vg:18.4,-64.6;vi:18.3,-64.9;vn:16.6,106.3;vu:-16.6,168.2;wf:-13.8,-177.9;ws:-13.7,-172.1;xk:42.6,20.9;ye:15.9,47.6;yt:-12.8,45.2;za:-29.0,25.1;zm:-13.5,27.8;zw:-19.0,29.9";

fn centroids() -> &'static HashMap<String, (f64, f64)> {
    static M: OnceLock<HashMap<String, (f64, f64)>> = OnceLock::new();
    M.get_or_init(|| {
        let mut m = HashMap::new();
        for part in COUNTRY_CENTROIDS.split(';') {
            let Some((cc, ll)) = part.split_once(':') else {
                continue;
            };
            let Some((a, b)) = ll.split_once(',') else {
                continue;
            };
            if let (Ok(a), Ok(b)) = (a.trim().parse::<f64>(), b.trim().parse::<f64>()) {
                m.insert(cc.to_string(), (a, b));
            }
        }
        m
    })
}

pub fn cc_centroid(cc: &str) -> Option<(f64, f64)> {
    centroids().get(&cc.trim().to_lowercase()).copied()
}

// Региональные индикаторы: '🇦' (U+1F1E6) .. '🇿' (U+1F1FF)
fn is_region_indicator(c: char) -> bool {
    ('\u{1F1E6}'..='\u{1F1FF}').contains(&c)
}

fn cc_from_pair(a: char, b: char) -> String {
    let off = '🇦' as u32;
    let x = char::from_u32('a' as u32 + (a as u32 - off)).unwrap_or('?');
    let y = char::from_u32('a' as u32 + (b as u32 - off)).unwrap_or('?');
    format!("{}{}", x, y)
}

// vpnCascadeExitCC — код страны ВЫХОДА каскадного конфига: последний флаг
// в имени («🇷🇺➜🇪🇸 GidroksiFree #14» → «es»).
pub fn cascade_exit_cc(name: &str) -> Option<String> {
    let runes: Vec<char> = name.chars().collect();
    let mut last = String::new();
    let mut count = 0;
    let mut i = 0;
    while i < runes.len() {
        let r = runes[i];
        if is_region_indicator(r) && i + 1 < runes.len() && is_region_indicator(runes[i + 1]) {
            last = cc_from_pair(r, runes[i + 1]);
            count += 1;
            i += 1;
        }
        i += 1;
    }
    if count >= 2 {
        // Два соседних флага без явного маркера («🇳🇱🇩🇪 Dual») — перечисление,
        // а не каскад: считать выходом последний флаг было неверно
        if name.contains('➜') || name.to_lowercase().contains("каскад") {
            return Some(last);
        }
        return None;
    }
    // один флаг или ни одного: каскад может быть отмечен словами —
    // тогда последний (единственный) флаг тоже выход («🇪🇸 Каскад»)
    if !last.is_empty() && (name.to_lowercase().contains("каскад") || name.contains('➜')) {
        return Some(last);
    }
    None
}

// ---------- геолокация внешнего IP ----------

// VPN-клиент через туннель: HTTP-прокси на локальный порт ядра.
fn tunnel_client(timeout: Duration, local_port: i32) -> Option<reqwest::blocking::Client> {
    let proxy = format!("http://127.0.0.1:{}", local_port);
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .proxy(reqwest::Proxy::all(&proxy).ok()?)
        .build()
        .ok()
}

// VpnCheckIp — внешний IP через туннель (api.ipify.org).
pub fn check_ip(state: &AppState) -> String {
    let conn = &state.conn;
    let (gen, connected) = {
        let inner = conn.inner.lock().unwrap_or_else(|e| e.into_inner());
        (inner.gen, inner.state.phase == "connected")
    };
    let warp = crate::conn::warp_active();
    if !connected || (!crate::conn::port_open(crate::conn::vpn_local()) && !warp) {
        return String::new();
    }
    // WARP — полный TUN без прокси-порта: обычный клиент, запросы и так через туннель
    let client = if warp {
        reqwest::blocking::Client::builder().timeout(Duration::from_secs(8)).build().ok()
    } else {
        tunnel_client(Duration::from_secs(8), crate::conn::vpn_local())
    };
    let Some(client) = client else {
        return String::new();
    };
    let Ok(resp) = client.get("https://api.ipify.org").send() else {
        return String::new();
    };
    if resp.status().as_u16() != 200 {
        return String::new();
    }
    let mut body = Vec::new();
    if resp.take(64).read_to_end(&mut body).is_err() {
        return String::new();
    }
    let ip = String::from_utf8_lossy(&body).trim().to_string();
    if ip.parse::<std::net::IpAddr>().is_err() {
        return String::new();
    }
    // Пока шёл запрос, соединение могли выключить/переключить — не приписываем
    // чужой IP новому подключению. Проверка и запись под мьютексом.
    let inner = conn.inner.lock().unwrap_or_else(|e| e.into_inner());
    if inner.gen == gen && inner.state.phase == "connected" && !ip.is_empty() {
        conn.set_vpn_ip(&ip);
        return ip;
    }
    String::new()
}

// VpnGeo — где находится текущий внешний IP. Кэш по IP; негативный кэш:
// оба гео-источника упали — не долбим их каждым опросом UI.
pub fn vpn_geo(state: &AppState) -> VpnGeoInfo {
    static GEO: OnceLock<Mutex<(VpnGeoInfo, Option<Instant>)>> = OnceLock::new();
    let cache = GEO.get_or_init(|| Mutex::new((VpnGeoInfo::default(), None)));
    let conn = &state.conn;
    let connected = conn.is_connected();
    let warp = crate::conn::warp_active();
    if !connected || (!crate::conn::port_open(crate::conn::vpn_local()) && !warp) {
        *cache.lock().unwrap_or_else(|e| e.into_inner()) = (VpnGeoInfo::default(), None);
        return VpnGeoInfo::default();
    }
    let ip = conn.get_vpn_ip();
    {
        let (cached, failed_at) = &*cache.lock().unwrap_or_else(|e| e.into_inner());
        let fail_recently = failed_at.map(|t| t.elapsed() < Duration::from_secs(120)).unwrap_or(false);
        if cached.ok && !ip.is_empty() && cached.ip == ip {
            return cached.clone();
        }
        if fail_recently {
            return VpnGeoInfo::default();
        }
    }
    if ip.is_empty() {
        // старую точку прошлой сессии показывать нельзя — глобус честно сбрасывается
        return VpnGeoInfo::default();
    }
    let mut geo = VpnGeoInfo {
        ip: ip.clone(),
        ..Default::default()
    };
    // WARP — полный TUN: обычный клиент, запросы и так через туннель
    let client = if warp {
        reqwest::blocking::Client::builder().timeout(Duration::from_secs(10)).build().ok()
    } else {
        tunnel_client(Duration::from_secs(10), crate::conn::vpn_local())
    };
    let Some(client) = client else {
        return VpnGeoInfo::default();
    };
    // Основной источник: ipwho.is (без ключа, https)
    if let Ok(resp) = client.get("https://ipwho.is/").send() {
        if let Ok(v) = resp.json::<serde_json::Value>() {
            let success = v.get("success").and_then(|x| x.as_bool()).unwrap_or(false);
            if success {
                geo = VpnGeoInfo {
                    ok: true,
                    ip: v.get("ip").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                    city: v.get("city").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                    country: v.get("country").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                    country_code: v.get("country_code").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                    isp: v
                        .get("connection")
                        .and_then(|c| c.get("isp"))
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    lat: v.get("latitude").and_then(|x| x.as_f64()).unwrap_or(0.0),
                    lon: v.get("longitude").and_then(|x| x.as_f64()).unwrap_or(0.0),
                };
            }
        }
    }
    // Фолбэк: ipapi.co
    if !geo.ok {
        if let Ok(resp) = client.get("https://ipapi.co/json/").send() {
            if let Ok(v) = resp.json::<serde_json::Value>() {
                let ipj = v.get("ip").and_then(|x| x.as_str()).unwrap_or_default().to_string();
                if !ipj.is_empty() {
                    geo = VpnGeoInfo {
                        ok: true,
                        ip: ipj,
                        city: v.get("city").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                        country: v.get("country_name").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                        country_code: v.get("country_code").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                        isp: v.get("org").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                        lat: v.get("latitude").and_then(|x| x.as_f64()).unwrap_or(0.0),
                        lon: v.get("longitude").and_then(|x| x.as_f64()).unwrap_or(0.0),
                    };
                }
            }
        }
    }
    if geo.ok && geo.ip.is_empty() {
        geo.ip = ip;
    }
    *cache.lock().unwrap_or_else(|e| e.into_inner()) = (
        geo.clone(),
        if geo.ok { None } else { Some(Instant::now()) },
    );
    geo
}

// ---------- координаты серверов (глобус) ----------

const SRV_GEO_TTL_OK: Duration = Duration::from_secs(24 * 3600);
const SRV_GEO_TTL_BAD: Duration = Duration::from_secs(600);

#[derive(Clone)]
struct SrvGeoEntry {
    g: ServerGeo,
    ok: bool,
    ts: Instant,
}

static SRV_GEO_CACHE: OnceLock<Mutex<HashMap<String, SrvGeoEntry>>> = OnceLock::new();
static SRV_GEO_LOG_LAST: Mutex<String> = Mutex::new(String::new());

fn srv_geo_cache() -> &'static Mutex<HashMap<String, SrvGeoEntry>> {
    SRV_GEO_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

// VpnServersGeo — координаты всех серверов списка (маркеры на глобусе).
// ip-api.com/batch понимает и IP, и домены: до 100 за запрос, ответ в том
// же порядке. Каскады получают точку страны ВЫХОДА по флагу из имени.
pub fn servers_geo(state: &AppState) -> HashMap<String, ServerGeo> {
    let tools = state.tools();
    let mut out: HashMap<String, ServerGeo> = HashMap::new();
    let list = crate::store::load_vpn_proxies(&tools);
    let mut hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut pending: Vec<String> = Vec::new();
    let mut cascade_done: std::collections::HashSet<String> = std::collections::HashSet::new();
    for p in &list {
        if p.proto == "warp" {
            continue;
        }
        // Каскад (🇷🇺➜🇪🇸, «🔗Каскад»): точка на глобусе = страна ВЫХОДА
        if let Some(cc) = cascade_exit_cc(&p.name) {
            if let Some((lat, lon)) = cc_centroid(&cc) {
                out.insert(
                    p.id.clone(),
                    ServerGeo {
                        lat,
                        lon,
                        country: cc.to_uppercase(),
                        city: String::new(),
                    },
                );
                cascade_done.insert(p.id.clone());
                continue;
            }
        }
        let h = p.host.trim().to_lowercase();
        if h.is_empty() {
            continue;
        }
        if hosts.insert(h.clone()) {
            pending.push(h);
        }
    }
    if pending.is_empty() {
        return out;
    }
    // что уже есть свежего в кэше, а что надо спрашивать у ip-api
    let fetch: Vec<String> = {
        let cache = srv_geo_cache().lock().unwrap_or_else(|e| e.into_inner());
        pending
            .iter()
            .filter(|h| match cache.get(*h) {
                Some(e) if e.ok && e.ts.elapsed() < SRV_GEO_TTL_OK => false,
                Some(e) if !e.ok && e.ts.elapsed() < SRV_GEO_TTL_BAD => false,
                _ => true,
            })
            .cloned()
            .collect()
    };
    // ip-api бесплатный только по http: список хостов — это почти вся
    // подписка, открытым текстом его отправлять нельзя. Когда туннель поднят,
    // запрос идёт через него (как check_ip/vpn_geo); без туннеля гео не
    // запрашиваем вовсе — из кэша отдаётся то, что уже есть.
    let client = if crate::conn::warp_active() {
        reqwest::blocking::Client::builder().timeout(Duration::from_secs(12)).build().ok()
    } else if state.conn.is_connected() && crate::conn::port_open(crate::conn::vpn_local()) {
        tunnel_client(Duration::from_secs(12), crate::conn::vpn_local())
    } else {
        log_add("geo", "гео серверов пропущено: туннель не поднят — список хостов не уходит по открытому http");
        None
    };
    let mut start = 0;
    while start < fetch.len() {
        // Бесплатный ip-api: 15 запросов/мин → пауза ≥4 с между чанками.
        // Пауза 1.2 с ловила 429-волны, и чанки помечались failed на 10 минут
        // («глобус с дырками»).
        if start > 0 {
            std::thread::sleep(Duration::from_millis(4200));
        }
        let end = (start + 100).min(fetch.len());
        let chunk = &fetch[start..end];
        start = end;
        let Some(client) = &client else {
            mark_failed(chunk);
            continue;
        };
        let resp = client
            .post("http://ip-api.com/batch?fields=status,country,city,lat,lon,query")
            .header("Content-Type", "application/json")
            .body(json!(chunk).to_string())
            .send();
        match resp {
            Err(e) => {
                log_add("geo", &format!("ip-api недоступен: {}", e));
                mark_failed(chunk);
            }
            Ok(r) => {
                if r.status().as_u16() >= 300 {
                    log_add("geo", &format!("ip-api HTTP {}", r.status().as_u16()));
                    mark_failed(chunk);
                    continue;
                }
                let Ok(arr) = r.json::<Vec<serde_json::Value>>() else {
                    mark_failed(chunk);
                    continue;
                };
                // ответ — в том же порядке, что и запрос: маппим по индексу
                let mut served: std::collections::HashSet<String> = std::collections::HashSet::new();
                let mut cache = srv_geo_cache().lock().unwrap_or_else(|e| e.into_inner());
                for (i, it) in arr.iter().enumerate() {
                    if i >= chunk.len() {
                        break;
                    }
                    let h = &chunk[i];
                    let status = it.get("status").and_then(|x| x.as_str()).unwrap_or_default();
                    let lat = it.get("lat").and_then(|x| x.as_f64()).unwrap_or(0.0);
                    let lon = it.get("lon").and_then(|x| x.as_f64()).unwrap_or(0.0);
                    if status == "success" && (lat != 0.0 || lon != 0.0) {
                        cache.insert(
                            h.clone(),
                            SrvGeoEntry {
                                g: ServerGeo {
                                    lat,
                                    lon,
                                    country: it.get("country").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                                    city: it.get("city").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                                },
                                ok: true,
                                ts: Instant::now(),
                            },
                        );
                        served.insert(h.clone());
                    }
                }
                drop(cache);
                let not_served: Vec<String> = chunk.iter().filter(|h| !served.contains(*h)).cloned().collect();
                mark_failed(&not_served);
            }
        }
    }
    // сборка ответа — из кэша, включая хосты, которые в этот раз не спрашивали
    let (mut got, mut fail) = (0usize, 0usize);
    {
        let cache = srv_geo_cache().lock().unwrap_or_else(|e| e.into_inner());
        for p in &list {
            if p.proto == "warp" || cascade_done.contains(&p.id) {
                continue;
            }
            let h = p.host.trim().to_lowercase();
            match cache.get(&h) {
                Some(e) if e.ok => {
                    out.insert(p.id.clone(), e.g.clone());
                    got += 1;
                }
                _ => fail += 1,
            }
        }
    }
    // антифлуд лога: пишем только при изменении сводки
    let line = format!("координаты: {}/{} серверов (без гео: {})", got, list.len(), fail);
    let mut last = SRV_GEO_LOG_LAST.lock().unwrap_or_else(|e| e.into_inner());
    if *last != line {
        *last = line.clone();
        drop(last);
        log_add("geo", &line);
    }
    out
}

// vpnSrvGeoMarkFailed — пометить хосты сбойными: повтор через TTL_BAD.
// Уже имеющийся в кэше свежий успех не трогаем.
fn mark_failed(hosts: &[String]) {
    let mut cache = srv_geo_cache().lock().unwrap_or_else(|e| e.into_inner());
    for h in hosts {
        if let Some(e) = cache.get(h) {
            if e.ok && e.ts.elapsed() < SRV_GEO_TTL_OK {
                continue;
            }
        }
        cache.insert(
            h.clone(),
            SrvGeoEntry {
                g: ServerGeo::default(),
                ok: false,
                ts: Instant::now(),
            },
        );
    }
}

// ---------- проверки доступности сервисов ----------

const SVC_TARGETS: [(&str, &str); 6] = [
    ("YouTube", "https://www.youtube.com/generate_204"),
    ("ChatGPT", "https://chat.openai.com/"),
    ("Gemini", "https://gemini.google.com/"),
    ("Discord", "https://discord.com/api/v9/gateway"),
    ("Steam", "https://store.steampowered.com/"),
    ("Telegram", "https://api.telegram.org/"),
];

struct SvcState {
    running: bool,
    info: Option<VpnServicesInfo>,
}

static SVC: Mutex<SvcState> = Mutex::new(SvcState {
    running: false,
    info: None,
});

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn names_only() -> Vec<ServiceCheck> {
    SVC_TARGETS
        .iter()
        .map(|(name, _)| ServiceCheck {
            name: name.to_string(),
            ok: false,
            ms: -1,
        })
        .collect()
}

pub fn start_service_checks(_state: &AppState) -> String {
    let mut svc = SVC.lock().unwrap_or_else(|e| e.into_inner());
    if svc.running {
        return "already".to_string();
    }
    svc.running = true;
    let mut info = svc.info.take().unwrap_or_default();
    info.checking = true;
    info.at = now_unix();
    // на время проверки показываем только имена
    if info.services.len() != SVC_TARGETS.len() {
        info.services = names_only();
    } else {
        for s in info.services.iter_mut() {
            s.ms = -1;
            s.ok = false;
        }
    }
    svc.info = Some(info);
    drop(svc);
    std::thread::spawn(move || run_service_checks());
    "ok".to_string()
}

fn run_service_checks() {
    let through = crate::conn::port_open(crate::conn::vpn_local()); // ядро запущено — через туннель
    {
        let mut svc = SVC.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(info) = svc.info.as_mut() {
            info.through = if through { "tun".to_string() } else { "direct".to_string() };
        }
    }
    let mut handles = Vec::new();
    for (name, url) in SVC_TARGETS {
        handles.push(std::thread::spawn(move || probe_service(name, url, through)));
    }
    let mut res: Vec<ServiceCheck> = Vec::new();
    for h in handles {
        if let Ok(r) = h.join() {
            res.push(r);
        }
    }
    // порядок — как в SVC_TARGETS
    let mut ordered = names_only();
    for r in res {
        if let Some(slot) = ordered.iter_mut().find(|s| s.name == r.name) {
            *slot = r;
        }
    }
    let mut svc = SVC.lock().unwrap_or_else(|e| e.into_inner());
    svc.running = false;
    if let Some(info) = svc.info.as_mut() {
        info.checking = false;
        info.at = now_unix();
        info.services = ordered;
    }
}

pub fn services_info() -> VpnServicesInfo {
    let mut svc = SVC.lock().unwrap_or_else(|e| e.into_inner());
    // до первой проверки показываем просто имена сервисов
    let info = svc.info.get_or_insert_with(VpnServicesInfo::default);
    if info.services.is_empty() {
        info.services = names_only();
    }
    info.clone()
}

// probeService — любой HTTP-ответ (даже 403/404) = сервис доступен;
// таймаут/сброс соединения = заблокирован.
fn probe_service(name: &str, url: &str, through: bool) -> ServiceCheck {
    let mut sc = ServiceCheck {
        name: name.to_string(),
        ok: false,
        ms: -1,
    };
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(4))
        .no_proxy();
    if through {
        // http://, а не socks5://: инбаунд xray — только HTTP
        if let Ok(p) = reqwest::Proxy::all(&format!("http://127.0.0.1:{}", crate::conn::vpn_local())) {
            builder = builder.proxy(p);
        }
    }
    let Ok(client) = builder.build() else {
        return sc;
    };
    let t0 = Instant::now();
    let Ok(resp) = client.get(url).send() else {
        return sc;
    };
    let resp = resp;
    let mut sink = Vec::new();
    let _ = resp.take(512).read_to_end(&mut sink);
    sc.ok = true;
    sc.ms = t0.elapsed().as_millis() as i64;
    sc
}

// ---------- флаги стран ----------

// VpnFlags — флаги как data-URI (SVG), ключ — код страны в нижнем регистре.
pub fn vpn_flags() -> HashMap<String, String> {
    static FLAGS: OnceLock<HashMap<String, String>> = OnceLock::new();
    FLAGS
        .get_or_init(|| {
            static DIR: include_dir::Dir = include_dir::include_dir!("$CARGO_MANIFEST_DIR/assets/flags");
            let mut m = HashMap::new();
            for f in DIR.files() {
                let name = f.path().file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                // только cc.svg: 6 символов имени («ru.svg» — 6 с точкой)
                if !name.ends_with(".svg") || name.len() != 6 {
                    continue;
                }
                let cc = name.trim_end_matches(".svg").to_lowercase();
                use base64::Engine;
                m.insert(cc, format!("data:image/svg+xml;base64,{}", base64::engine::general_purpose::STANDARD.encode(f.contents())));
            }
            m
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cascade_names() {
        // эмодзи в этом тесте были безвозвратно испорчены (литеральные '?') —
        // восстановлены: 🇷🇺➜🇪🇸 = U+1F1F7 U+1F1FA U+279C U+1F1EA U+1F1F8
        assert_eq!(cascade_exit_cc("🇷🇺➜🇪🇸 GidroksiFree #14").as_deref(), Some("es"));
        assert_eq!(cascade_exit_cc("🇪🇸 Каскад").as_deref(), Some("es"));
        assert_eq!(cascade_exit_cc("🇪🇸 solo #3"), None);
        assert_eq!(cascade_exit_cc("plain name"), None);
        // два соседних флага без маркера каскада — перечисление, не каскад
        assert_eq!(cascade_exit_cc("🇳🇱🇩🇪 Dual #7"), None);
    }

    #[test]
    fn centroids_lookup() {
        let (lat, _lon) = cc_centroid("ES").unwrap();
        assert!((lat - 40.2).abs() < 0.01);
        assert!(cc_centroid("xx").is_none());
    }

    #[test]
    fn flags_embedded() {
        let flags = vpn_flags();
        // 250+ флагов вшито
        assert!(flags.len() > 200, "flags={}", flags.len());
        assert!(flags.contains_key("ru"));
        assert!(flags["ru"].starts_with("data:image/svg+xml;base64,"));
    }
}
