// CSQTT — туннель через TURN/RTP (маскировка под VK-звонки), преемник WDTT.
// Драйвер переносит архитектуру официального desktop-клиента (danusha2345/csqtt-vpn,
// Go/Wails) на Rust: наш код создаёт Wintun-адаптер и UDP-мост сырых IP-пакетов
// на 127.0.0.1:19000, где живёт официальный Rust-транспорт csqtt-client.exe
// (вшит в assets, SHA256 бандла сверен с релизными SHA256SUMS).
//
// Жизненный цикл (паритет с Go core.go):
//   спавн csqtt-client (--peer ... --credentials-stdin ...) + env CSQTT_EVENTS=1
//   → stdin: CSQTT_CREDENTIALS|{"password":..,"vk":..}
//   → stdout: лог-строки + события __CSQTT_EVENT__|KIND|{json}
//   → CONFIG (TUNCONF ip:dns) → маршруты: bypass сервера/VK/TURN, split
//     0.0.0.0/1+128.0.0.0/1 через TUN, v6-guard ::/1+8000::/1, DNS адаптера, NRPT
//   → STOP по stdin, ожидание 10 с, kill; очистка маршрутов/NRPT при любом исходе.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;
use tauri::{Emitter, Manager};

use crate::logging::log_add;
use crate::models::{CqsttServer, CqsttStatusInfo};
use crate::paths;

const TUN_NAME: &str = "sentor_csqtt";
const TUN_MTU: usize = 1300;
const INNER_LISTEN: &str = "127.0.0.1:19000";
const CONFIG_WAIT_SECS: u64 = 90;
// ядро штатно выходит за ~2 с (закрытие 9 TURN-сессий); 5 с — запас, раньше
// 10 с блокировали поток вызывающего при зависшем ядре
const CLIENT_STOP_WAIT_MS: u64 = 5_000;
const LOG_LINES_MAX: usize = 400;
// VK и связанные сети — bypass через физический шлюз (bypassCIDRs из Go-драйвера)
const BYPASS_CIDRS: &[&str] = &[
    "87.240.0.0/16", "93.186.224.0/19", "95.142.192.0/20", "95.213.0.0/18",
    "94.100.176.0/20", "217.20.144.0/20", "217.69.128.0/20", "185.6.244.0/22",
];
const NRPT_DISPLAY: &str = "CSQTT DNS";
const NRPT_COMMENT: &str = "CSQTT_MANAGED";
const EVENT_PREFIX: &str = "__CSQTT_EVENT__|";

// ---------- глобальное состояние ----------

struct CqsttInner {
    running: bool,
    stop_requested: bool,
    session: u64,
    state: CqsttStatusInfo,
    log_lines: Vec<String>,
    log_file: Option<std::fs::File>,
}

static CQSTT: Mutex<CqsttInner> = Mutex::new(CqsttInner {
    running: false,
    stop_requested: false,
    session: 0,
    state: CqsttStatusInfo {
        running: false,
        phase: String::new(),
        name: String::new(),
        id: None,
        since: 0,
        active: 0,
        bytes_up: 0,
        bytes_down: 0,
        workers: 0,
        error: None,
        stage: 0,
    },
    log_lines: Vec::new(),
    log_file: None,
});

// дескрипторы живой сессии (child/bridge) — общий доступ для disconnect/watchdog
struct SessionHandles {
    child: Option<std::process::Child>,
    stdin: Option<std::process::ChildStdin>,
    bridge: Option<Bridge>,
    closing: Option<Arc<AtomicBool>>,
    // bypass-маршруты сессии (сервер /32, VK CIDR, TURN IP) — снимает
    // cleanup_routing при любом завершении: раньше они жили до ребута и после
    // смены сети отправляли трафик в мёртвый шлюз
    bypass: Vec<(String, String)>,
    // Job Object ядра: KILL_ON_JOB_CLOSE убивает осиротевший csqtt-client
    // (DETACHED-потомок после kill Sentor оставался жить и держал 19000 порт)
    job: Option<crate::conn::JobHandle>,
}

static HANDLES: Mutex<SessionHandles> = Mutex::new(SessionHandles {
    child: None,
    stdin: None,
    bridge: None,
    closing: None,
    bypass: Vec::new(),
    job: None,
});

static APP: OnceLock<tauri::AppHandle> = OnceLock::new();

pub fn set_app_handle(h: tauri::AppHandle) {
    let _ = APP.set(h);
}

fn app() -> Option<&'static tauri::AppHandle> {
    APP.get()
}

// ---------- события для фронтенда ----------

fn cqstt_emit_state() {
    let g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(a) = app() {
        let _ = a.emit("cqsttState", &g.state);
    }
}

// set_stage — этап подключения для живой схемы пути (ТЫ→CSQTT→VK TURN→ИНТЕРНЕТ):
// 1=старт, 2=ядро запущено, 3=VK TURN готовы, 4=адаптер+маршруты (активен).
// Только вперёд: поздняя строка предыдущего этапа не откатывает схему.
fn set_stage(n: i32, session_tag: u64) {
    let mut g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
    if g.session != session_tag || g.state.stage >= n {
        return;
    }
    g.state.stage = n;
    drop(g);
    cqstt_emit_state();
}

fn cqstt_log_add(level: &str, msg: &str) {
    let line = format!("{} [{}] {}", chrono::Local::now().format("%H:%M:%S"), level, msg);
    {
        let mut g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
        g.log_lines.push(line.clone());
        if g.log_lines.len() > LOG_LINES_MAX {
            let cut = g.log_lines.len() - LOG_LINES_MAX;
            g.log_lines.drain(0..cut);
        }
        if let Some(f) = g.log_file.as_mut() {
            let _ = writeln!(f, "{}", line);
        }
    }
    if let Some(a) = app() {
        let _ = a.emit("cqsttLog", (level.to_string(), msg.to_string()));
    }
}

pub fn log_text() -> String {
    let g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
    g.log_lines.join("\n")
}

pub fn status() -> CqsttStatusInfo {
    // байты считает мост (up/down в Bridge) — подтягиваем при каждом опросе
    let (up, down) = {
        let h = HANDLES.lock().unwrap_or_else(|e| e.into_inner());
        match &h.bridge {
            Some(b) => (b.up.load(Ordering::Relaxed), b.down.load(Ordering::Relaxed)),
            None => (0, 0),
        }
    };
    let mut g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
    if up > 0 || down > 0 {
        g.state.bytes_up = up;
        g.state.bytes_down = down;
    }
    g.state.clone()
}

pub fn running() -> bool {
    let g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
    g.running
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// ---------- утилиты ----------

fn run_hidden(exe: &str, args: &[&str]) -> Result<String, String> {
    crate::tools::run_hidden(exe, args)
}

// нормализация полей сервера (паритет с pwdtt_normalize_server)
fn normalize_server(s: &mut CqsttServer) {
    s.name = s.name.trim().to_string();
    s.peer = s.peer.trim().to_string();
    s.password = s.password.trim().to_string();
    if s.name.is_empty() {
        s.name = s.peer.clone();
    }
    if s.workers <= 0 {
        s.workers = 18;
    }
    s.workers = s.workers.clamp(1, 100);
    let obfs = s.obfs.clone().unwrap_or_else(|| "audio".into()).to_lowercase();
    s.obfs = Some(match obfs.as_str() {
        "video" => "video".into(),
        "unified" => "unified".into(),
        _ => "audio".into(),
    });
    let tr = s.transport.clone().unwrap_or_else(|| "udp".into()).to_lowercase();
    s.transport = Some(match tr.as_str() {
        "tcp_tls" | "tcp" => "tcp_tls".into(),
        _ => "udp".into(),
    });
    let fp = s.fingerprint.clone().unwrap_or_else(|| "chrome".into()).to_lowercase();
    s.fingerprint = Some(match fp.as_str() {
        "safari" | "firefox" | "edge" | "opera" | "android" => fp,
        _ => "chrome".into(),
    });
    // хеши: до 6 штук (лимит ядра MAX_VK_HASHES), дедуп
    let mut hashes: Vec<String> = Vec::new();
    for part in s.hashes.split([',', ';', '\n']) {
        let h = part.trim();
        if !h.is_empty() && !hashes.contains(&h.to_string()) {
            hashes.push(h.to_string());
        }
        if hashes.len() >= 6 {
            break;
        }
    }
    s.hashes = hashes.join(",");
    // device-id НЕ генерим здесь: стабильный идентификатор установки читается
    // из файла при каждом запуске ядра (см. stable_device_id) — сервер
    // привязывает пароль к идентификатору устройства, случайная смена id на
    // каждое подключение даёт молчаливый отказ воркеров
}

pub fn hash_list(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in s.split([',', ';', '\n']) {
        let h = part.trim();
        if !h.is_empty() && !out.contains(&h.to_string()) {
            out.push(h.to_string());
        }
    }
    out
}

// ---------- распаковка ядра ----------

fn ensure_core(tools: &Path) -> Result<PathBuf, String> {
    let dir = paths::cqstt_core_dir(tools);
    std::fs::create_dir_all(&dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
    let exe = dir.join("csqtt-client.exe");
    let Some(blob) = crate::tools::embedded("csqtt-client.exe") else {
        return Err("вшитый csqtt-client.exe не найден".into());
    };
    let have_check = |p: &Path, blob: &[u8]| -> bool {
        match std::fs::metadata(p) {
            Ok(st) => st.len() == blob.len() as u64 && crate::tools::blob_matches(p, blob),
            Err(_) => false,
        }
    };
    if !have_check(&exe, blob) {
        std::fs::write(&exe, blob).map_err(|e| format!("не записать ядро: {}", e))?;
    }
    // wintun.dll — из уже вшитого официального (подпись WireGuard)
    let dll = dir.join("wintun.dll");
    let Some(dll_blob) = crate::tools::embedded("wintun.dll") else {
        return Err("вшитый wintun.dll не найден".into());
    };
    if !have_check(&dll, dll_blob) {
        std::fs::write(&dll, dll_blob).map_err(|e| format!("не записать wintun.dll: {}", e))?;
    }
    Ok(dir)
}

// ---------- маршруты / NRPT ----------

// физический шлюз по умолчанию: таблица маршрутов, минимальная метрика среди
// /0-маршрутов с указанным NextHop (порт physDefault из Go)
fn phys_default() -> Result<(String, u32), String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    };
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let rc = GetIpForwardTable2(2 /* AF_INET */, &mut table);
        if rc != 0 {
            return Err(format!("GetIpForwardTable2: код {}", rc));
        }
        let t = &*table;
        // Table — [MIB_IPFORWARD_ROW2; 1] (фиктивный массив): индексировать
        // нельзя (паника при NumEntries > 1), идём указательной арифметикой
        let rows_ptr = &t.Table as *const MIB_IPFORWARD_ROW2;
        let mut best: Option<(String, u32, u32)> = None; // (nexthop, ifindex, metric)
        for i in 0..t.NumEntries as usize {
            let r = &*rows_ptr.add(i);
            if r.DestinationPrefix.PrefixLength != 0 {
                continue; // только дефолтные маршруты
            }
            // NextHop: SOCKADDR_INET — читаем family по смещению 0, IPv4 по 4..8
            let nh = std::ptr::addr_of!(r.NextHop).cast::<u8>();
            let family = std::slice::from_raw_parts(nh, 2)[0] as u16
                | ((std::slice::from_raw_parts(nh, 2)[1] as u16) << 8);
            if family != 2 {
                continue;
            }
            let oct = std::slice::from_raw_parts(nh.add(4), 4);
            if oct == [0, 0, 0, 0] {
                continue; // on-link без шлюза не подходит
            }
            let metric = r.Metric;
            if best.as_ref().map(|b| metric < b.2).unwrap_or(true) {
                let gw = format!("{}.{}.{}.{}", oct[0], oct[1], oct[2], oct[3]);
                best = Some((gw, r.InterfaceIndex, metric));
            }
        }
        let res = best
            .map(|(gw, idx, _)| (gw, idx))
            .ok_or_else(|| "нет активного IPv4-маршрута по умолчанию".into());
        FreeMibTable(table as *const _); // память API надо освобождать
        res
    }
}

fn route_add(network: &str, mask: &str, gw: &str, ifindex: u32) -> Result<(), String> {
    let ifarg = ifindex.to_string();
    run_hidden("route", &["add", network, "mask", mask, gw, "metric", "1", "if", &ifarg]).map(|_| ())
}

fn route_delete(network: &str, mask: &str) {
    let _ = run_hidden("route", &["delete", network, "mask", mask]);
}

// NRPT: все домены через DNS туннеля (порт installManagedNRPT из Go)

// запоминаем выданный сервером DNS: после force-kill правило может остаться
// с ПУСТЫМИ DisplayName/Comment (метаданные теряются) — если при этом DNS не
// 1.1.1.1, запасной критерий «'.' + 1.1.1.1» его не находил, и «все домены →
// недоступный DNS» висело вечно. Храним в nrpt_dns.txt и чистим и по нему.
fn nrpt_saved_dns() -> Option<String> {
    let p = paths::cqstt_dir(&tools_dir()).join("nrpt_dns.txt");
    std::fs::read_to_string(&p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// условие PS для опознания НАШИХ NRPT-правил (с метаданными или без)
fn nrpt_match_ps() -> String {
    let mut cond = format!(
        "$_.DisplayName -eq '{d}' -or $_.Comment -eq '{c}'",
        d = NRPT_DISPLAY,
        c = NRPT_COMMENT
    );
    cond.push_str(" -or ($_.Namespace -eq '.' -and $_.NameServers -contains '1.1.1.1')");
    if let Some(dns) = nrpt_saved_dns() {
        cond.push_str(&format!(" -or ($_.Namespace -eq '.' -and $_.NameServers -contains '{}')", dns));
    }
    cond
}

fn nrpt_install(dns: &str) -> Result<(), String> {
    let _ = std::fs::create_dir_all(paths::cqstt_dir(&tools_dir()));
    let _ = std::fs::write(paths::cqstt_dir(&tools_dir()).join("nrpt_dns.txt"), dns);
    let ps = format!(
        "$ErrorActionPreference = 'Stop'\n\
         $m = {{ {m} }}\n\
         Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object $m | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }}\n\
         $rule = Add-DnsClientNrptRule -Namespace '.' -NameServers '{dns}' -DisplayName '{d}' -Comment '{c}' -PassThru -ErrorAction Stop\n\
         if ($null -eq $rule -or $rule.NameServers -notcontains '{dns}') {{ throw 'NRPT verification failed' }}\n\
         Clear-DnsClientCache -ErrorAction SilentlyContinue\n",
        m = nrpt_match_ps(),
        d = NRPT_DISPLAY,
        c = NRPT_COMMENT,
        dns = dns
    );
    run_hidden("powershell", &["-NoProfile", "-NonInteractive", "-Command", &ps]).map(|_| ())
}

fn adapter_index(name: &str, timeout: Duration) -> Result<u32, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(idx) = adapter_index_once(name) {
            return Ok(idx);
        }
        if Instant::now() > deadline {
            return Err(format!("адаптер {} не появился за {:?}", name, timeout));
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn adapter_index_once(name: &str) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH};
    unsafe {
        let mut size: u32 = 0;
        let _ = GetAdaptersAddresses(0, 0, std::ptr::null_mut(), std::ptr::null_mut(), &mut size);
        if size == 0 {
            return None;
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
            return None;
        }
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = &*cur;
            if !a.FriendlyName.is_null() {
                let mut len = 0usize;
                while *a.FriendlyName.add(len) != 0 {
                    len += 1;
                }
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(a.FriendlyName, len));
                if s.eq_ignore_ascii_case(name) && a.OperStatus == 1 {
                    // IPv4-IfIndex: маршруты route add / bypass-хостов завязаны
                    // на него. Ipv6IfIndex у wintun обычно совпадает, но не
                    // обязан — маршрут мог уйти не на тот интерфейс.
                    // (внешний unsafe-блок функции уже покрывает union-доступ)
                    return Some(a.Anonymous1.Anonymous.IfIndex);
                }
            }
            cur = a.Next;
        }
        None
    }
}

// ---------- Wintun ↔ UDP мост ----------

struct Bridge {
    closing: Arc<AtomicBool>,
    up: Arc<AtomicI64>,
    down: Arc<AtomicI64>,
    session: Arc<wintun::Session>,
    // держит сокеты релея живыми до конца сессии (значение не читается —
    // мост-поток работает со своей копией Arc)
    #[allow(dead_code)]
    relay: Option<Arc<ServerRelay>>,
}

impl Bridge {
    fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        // shutdown будит receive_blocking в потоках моста
        let _ = self.session.shutdown();
    }
}

// ---------- UDP-релей серверного потока ----------

// bypass-маршрут для IP сервера НЕ ставится: весь прочий трафик на его адрес
// (панель конфигов, веб-морда и т.п.) идёт ЧЕРЕЗ туннель и проходит белые
// списки. Но собственный UDP-поток ядра к серверу обязан уходить с
// физического интерфейса — иначе петля (пакет вернётся из TUN в ядро как
// «туннельные данные»). Мост перехватывает эти пакеты прямо в TUN и
// рассылает с физического адреса; ответы сервера заворачиваются обратно в
// TUN от имени сервера. Для ядра всё прозрачно: оно «разговаривает» с
// server:port со своего локального порта, как и раньше.
struct UdpRelayParams {
    server_ip: Ipv4Addr,
    server_port: u16,
    phys_ip: IpAddr,
}

struct ServerRelay {
    server_ip: Ipv4Addr,
    server_port: u16,
    phys_ip: IpAddr,
    tun_ip: String,
    closing: Arc<AtomicBool>,
    session: Arc<wintun::Session>,
    // ключ — локальный порт ядра; сокет релея живёт на физическом IP
    sockets: Mutex<HashMap<u16, Arc<UdpSocket>>>,
}

impl ServerRelay {
    fn new(p: &UdpRelayParams, tun_ip: String, closing: Arc<AtomicBool>, session: Arc<wintun::Session>) -> Self {
        ServerRelay {
            server_ip: p.server_ip,
            server_port: p.server_port,
            phys_ip: p.phys_ip,
            tun_ip,
            closing,
            session,
            sockets: Mutex::new(HashMap::new()),
        }
    }

    // intercept — true: пакет ядра к серверу перехвачен и отправлен физически
    // (в 19000 НЕ возвращать — это его же пакет, петля); false: обычный трафик.
    fn intercept(&self, pkt: &[u8]) -> bool {
        let Some(f) = parse_ipv4_udp_flow(pkt) else { return false };
        if f.dst != self.server_ip || f.dst_port != self.server_port || f.src_port == 0 {
            return false;
        }
        match self.socket_for(f.src_port) {
            Some(s) => {
                if let Err(e) = s.send(&f.payload) {
                    // TURN-протокол устойчив к потерям: ядро повторит само
                    cqstt_log_add("WARN", &format!("релей к серверу: отправка не удалась: {}", e));
                }
                true
            }
            // сокет не создался — пакет в 19000 отдавать нельзя (петля),
            // дропаем: ядро повторит
            None => true,
        }
    }

    fn socket_for(&self, core_port: u16) -> Option<Arc<UdpSocket>> {
        {
            let m = self.sockets.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(s) = m.get(&core_port) {
                return Some(s.clone());
            }
        }
        let mut m = self.sockets.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = m.get(&core_port) {
            return Some(s.clone()); // двойная проверка под повторным локом
        }
        let phys = match self.phys_ip {
            IpAddr::V4(v) => v.to_string(),
            IpAddr::V6(v) => v.to_string(),
        };
        let bind_addr = format!("{}:0", phys);
        let sock = UdpSocket::bind(bind_addr.as_str())
            .and_then(|s| {
                s.connect((self.server_ip, self.server_port))?;
                Ok(s)
            })
            .map(Arc::new);
        match sock {
            Ok(s) => {
                std::thread::spawn({
                    let r = ServerRelayReader {
                        sock: s.clone(),
                        core_port,
                        server_ip: self.server_ip,
                        server_port: self.server_port,
                        tun_ip: self.tun_ip.clone(),
                        closing: self.closing.clone(),
                        session: self.session.clone(),
                    };
                    move || r.run()
                });
                cqstt_log_add(
                    "INFO",
                    &format!("релей к серверу: поток ядра :{} → физический {}", core_port, phys),
                );
                m.insert(core_port, s.clone());
                Some(s)
            }
            Err(e) => {
                cqstt_log_add("ERROR", &format!("релей к серверу: сокет на {} не создан: {}", phys, e));
                None
            }
        }
    }
}

// читатель релея: ответы сервера → IPv4/UDP-пакет в TUN (сервер → ядро)
struct ServerRelayReader {
    sock: Arc<UdpSocket>,
    core_port: u16,
    server_ip: Ipv4Addr,
    server_port: u16,
    tun_ip: String,
    closing: Arc<AtomicBool>,
    session: Arc<wintun::Session>,
}

impl ServerRelayReader {
    fn run(self) {
        let dst_ip = match self.tun_ip.parse::<Ipv4Addr>() {
            Ok(v) => v,
            Err(_) => return, // IPv6-туннель: релей не поддерживается
        };
        let mut buf = [0u8; 65536];
        loop {
            if self.closing.load(Ordering::SeqCst) {
                return;
            }
            let _ = self.sock.set_read_timeout(Some(Duration::from_millis(500)));
            match self.sock.recv(&mut buf) {
                Ok(n) if n > 0 => {
                    let pkt = build_ipv4_udp_packet(
                        self.server_ip,
                        dst_ip,
                        self.server_port,
                        self.core_port,
                        &buf[..n],
                    );
                    match self.session.allocate_send_packet(pkt.len() as u16) {
                        Ok(mut p) => {
                            p.bytes_mut().copy_from_slice(&pkt);
                            self.session.send_packet(p);
                        }
                        Err(_) => continue,
                    }
                }
                Ok(_) => {}
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => return, // сокет закрыт — поток ядра переподнимется
            }
        }
    }
}

// ---------- разбор/сборка IPv4+UDP (чистые функции, покрыты тестами) ----------

struct Ipv4UdpFlow {
    // читается тестами roundtrip и диагностикой
    #[allow(dead_code)]
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
}

fn checksum_add(sum: &mut u32, bytes: &[u8]) {
    let mut i = 0;
    while i + 1 < bytes.len() {
        *sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if bytes.len() % 2 == 1 {
        *sum += (bytes[bytes.len() - 1] as u32) << 8;
    }
}

fn fold_checksum(sum: u32) -> u16 {
    let mut s = sum;
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}

fn ipv4_header_checksum(hdr: &[u8]) -> u16 {
    let mut sum = 0u32;
    checksum_add(&mut sum, hdr);
    fold_checksum(sum)
}

fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    checksum_add(&mut sum, &src.octets());
    checksum_add(&mut sum, &dst.octets());
    sum += 17;
    sum += udp.len() as u32;
    checksum_add(&mut sum, udp);
    fold_checksum(sum)
}

fn build_ipv4_udp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut p = vec![0u8; total_len];
    p[0] = 0x45; // IPv4, IHL=5
    p[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    p[6] = 0x40; // DF
    p[8] = 64; // TTL
    p[9] = 17; // proto UDP
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&src_port.to_be_bytes());
    p[22..24].copy_from_slice(&dst_port.to_be_bytes());
    p[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    // checksum UDP считается при нулевом поле checksum (уже ноль в векторе)
    let ucs = udp_checksum(src, dst, &p[20..]);
    p[26..28].copy_from_slice(&ucs.to_be_bytes());
    let ics = ipv4_header_checksum(&p[..20]);
    p[10..12].copy_from_slice(&ics.to_be_bytes());
    p
}

fn parse_ipv4_udp_flow(pkt: &[u8]) -> Option<Ipv4UdpFlow> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x1FFF != 0 {
        return None; // не первый фрагмент — UDP-заголовка нет
    }
    if pkt[9] != 17 {
        return None; // не UDP
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let end = total_len.min(pkt.len());
    if end < ihl + 8 {
        return None;
    }
    Some(Ipv4UdpFlow {
        src: Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
        dst: Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
        src_port: u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]),
        dst_port: u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]),
        payload: pkt[ihl + 8..end].to_vec(),
    })
}

// сырой UDP-мост: TUN ↔ 127.0.0.1:19000 (bare IP-пакеты, протокол ядра)
fn start_bridge(
    wintun: &wintun::Wintun,
    core_dir: &Path,
    tun_ip: String,
    relay: Option<UdpRelayParams>,
    up: Arc<AtomicI64>,
    down: Arc<AtomicI64>,
    closing: Arc<AtomicBool>,
    on_fail: Arc<dyn Fn(String) + Send + Sync + 'static>,
) -> Result<Bridge, String> {
    let dll = core_dir.join("wintun.dll");
    // WintunStartSession падает и от «драйвер ещё добивает сессию прошлого
    // подключения», и от адаптера, отравленного force-kill'ом. Круг 1: до 3
    // попыток подряд. Круг 2: СНОСИМ адаптер (открытый — через
    // WintunDeleteAdapter: крейт умеет уничтожать только созданные в этом
    // процессе) и создаём заново, ещё до 3 попыток.
    let mut last_session_err = String::new();
    for round in 0..2u32 {
        // disconnect посреди подключения: новые круги и адаптеры не создаём —
        // иначе адаптер появился бы уже ПОСЛЕ уборки disconnect-потока
        if closing.load(Ordering::SeqCst) {
            return Err("подключение отменено".into());
        }
        if round > 0 {
            cqstt_log_add("WARN", "start_session не поднялся — сношу адаптер и создаю заново");
            let orphans = list_our_adapters(
                "($_.Name -eq 'sentor_csqtt') -or ($_.InterfaceDescription -in @('Sentor','Sentor Tunnel'))",
            );
            let (n, _) = wintun_delete_by_names(&dll, &orphans);
            cqstt_log_add("INFO", &format!("снесено старых адаптеров: {}", n));
            std::thread::sleep(Duration::from_millis(600));
        }
        // адаптер мог остаться от упавшей сессии — сначала открываем
        let (adapter, created_here) = match wintun::Adapter::open(wintun, TUN_NAME) {
            Ok(a) => (a, false),
            Err(_) => match wintun::Adapter::create(wintun, TUN_NAME, "Sentor", None) {
                Ok(a) => (a, true),
                Err(e) => {
                    last_session_err = format!("Wintun create {}: {}", TUN_NAME, e);
                    continue;
                }
            },
        };
        // раньше open-vs-create не различался — при «failed 3 из 3» было не
        // понять, падение на свежем адаптере или на остатке прошлой сессии
        cqstt_log_add(
            "INFO",
            &format!(
                "Wintun-адаптер {}: {}",
                TUN_NAME,
                if created_here { "создан заново" } else { "открыт существующий" }
            ),
        );
        let adapter = Arc::new(adapter);
        let mut session: Option<wintun::Session> = None;
        for attempt in 1..=3 {
            if closing.load(Ordering::SeqCst) {
                return Err("подключение отменено".into());
            }
            match adapter.start_session(0x400_000) {
                // 4 MiB ring
                Ok(s) => {
                    session = Some(s);
                    break;
                }
                Err(e) => {
                    last_session_err =
                        format!("Wintun session: {} (попытка {} из 3, круг {})", e, attempt, round + 1);
                    if attempt < 3 {
                        std::thread::sleep(Duration::from_millis(400));
                    }
                }
            }
        }
        if let Some(session) = session {
            return build_bridge(session, tun_ip, relay, up, down, closing, on_fail);
        }
        // не поднялся: созданный здесь умрёт с drop'ом (close уничтожает
        // созданные в процессе), открытый на новом круге удалит purge
        drop(adapter);
    }
    Err(format!(
        "{} — wintun-драйвер в клинче; если повторится, поможет перезагрузка ПК",
        last_session_err
    ))
}

// build_bridge — UDP-мост TUN ↔ ядро на уже поднятом ring (бывшее хвост
// start_bridge; session передан готовым и сам держит Arc<Adapter>)
fn build_bridge(
    session: wintun::Session,
    tun_ip: String,
    relay: Option<UdpRelayParams>,
    up: Arc<AtomicI64>,
    down: Arc<AtomicI64>,
    closing: Arc<AtomicBool>,
    on_fail: Arc<dyn Fn(String) + Send + Sync + 'static>,
) -> Result<Bridge, String> {
    let session = Arc::new(session);
    let relay = relay.map(|p| Arc::new(ServerRelay::new(&p, tun_ip.clone(), closing.clone(), session.clone())));
    let sock = UdpSocket::bind(("127.0.0.1", 0)).map_err(|e| format!("bind: {}", e))?;
    sock.connect(INNER_LISTEN).map_err(|e| format!("connect {}: {}", INNER_LISTEN, e))?;
    let sock = Arc::new(sock);
    // TUN → ядро
    {
        let session = session.clone();
        let sock = sock.clone();
        let relay = relay.clone();
        let up = up.clone();
        let closing = closing.clone();
        let on_fail = on_fail.clone();
        std::thread::spawn(move || loop {
            if closing.load(Ordering::SeqCst) {
                return;
            }
            match session.receive_blocking() {
                Ok(pkt) => {
                    let data: &[u8] = pkt.bytes();
                    let n = data.len();
                    // фильтр мусора из TUN (зеркально обратному направлению):
                    // полагаться только на netsh MTU нельзя — при его сбое
                    // oversized-пакеты раньше уходили ядру, ломая протокол
                    if n < 20 || n > TUN_MTU + 40 {
                        continue;
                    }
                    // UDP-поток ядра к серверу — перехват и физическая отправка
                    // (без bypass-маршрута сервисы на IP сервера доступны через
                    // туннель; перехваченный пакет в 19000 НЕ возвращается)
                    if let Some(r) = &relay {
                        if r.intercept(data) {
                            up.fetch_add(n as i64, Ordering::Relaxed);
                            continue;
                        }
                    }
                    if sock.send(data).is_err() {
                        // при штатном disconnect ядро умирает раньше моста —
                        // это не авария: без проверки closing on_fail плодит
                        // ложный ERROR и запускает параллельную disconnect_internal
                        if !closing.load(Ordering::SeqCst) {
                            on_fail("UDP-мост: ядро не принимает пакеты".into());
                        }
                        return;
                    }
                    up.fetch_add(n as i64, Ordering::Relaxed);
                }
                Err(_) => {
                    if !closing.load(Ordering::SeqCst) {
                        on_fail("Wintun read: кольцо остановлено".into());
                    }
                    return;
                }
            }
        });
    }
    // ядро → TUN
    {
        let session = session.clone();
        let down = down.clone();
        let closing = closing.clone();
        let on_fail = on_fail.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            loop {
                if closing.load(Ordering::SeqCst) {
                    return;
                }
                match sock.recv(&mut buf) {
                    Ok(n) => {
                        // фильтр битых пакетов от ядра (в Go — ERROR_INVALID_DATA/BAD_LENGTH)
                        if n < 20 || n > TUN_MTU + 40 {
                            continue;
                        }
                        match session.allocate_send_packet(n as u16) {
                            Ok(mut pkt) => {
                                pkt.bytes_mut().copy_from_slice(&buf[..n]);
                                session.send_packet(pkt);
                                down.fetch_add(n as i64, Ordering::Relaxed);
                            }
                            Err(_) => continue,
                        }
                    }
                    Err(_) => {
                        if !closing.load(Ordering::SeqCst) {
                            on_fail("UDP-мост: соединение с ядром разорвано".into());
                        }
                        return;
                    }
                }
            }
        });
    }
    Ok(Bridge { closing, up, down, session, relay })
}

// ---------- вспомогательные парсеры ----------

// TUNCONF-строка из события CONFIG. Семантика РОВНО как в Go (parseTunnelConfig):
// SplitN(":", 3) → [ip, dns-список, хвост]. Хвост (порт DNS-proxy и т.п., например
// "TUNCONF:10.70.0.3:1.1.1.1:19000") ОТБРАСЫВАЕТСЯ — если брать всё после первого
// ":", DNS-кандидатом станет "1.1.1.1:19000" и проверка IPv4 молча отбросит весь
// конфиг → «сервер не выдал TUNCONF» без единой ошибки в логе.
fn parse_tunconf(value: &str) -> Option<(String, String)> {
    let v = value.trim().strip_prefix("TUNCONF:")?.trim();
    let mut parts = v.splitn(3, ':');
    let ip = parts.next()?.trim();
    let dns_list = parts.next()?.trim();
    if !valid_ipv4(ip) {
        return None;
    }
    for candidate in dns_list.split(',') {
        let dns = candidate.trim();
        if valid_ipv4(dns) {
            return Some((ip.to_string(), dns.to_string()));
        }
    }
    None
}

// net.ParseIP(...).To4() != nil из Go: ровно 4 октета 0..=255
fn valid_ipv4(s: &str) -> bool {
    let mut it = s.split('.');
    it.clone().count() == 4 && it.all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
}

fn relay_ip_from_line(line: &str) -> Option<String> {
    // \brelay\s+(\d+\.\d+\.\d+\.\d+): — TURN-адреса из лога ядра
    let idx = line.find("relay ")?;
    let rest = line[idx + 6..].trim_start();
    let mut oct: Vec<String> = Vec::new();
    let mut cur = String::new();
    for c in rest.chars() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else if c == '.' {
            if cur.is_empty() || cur.len() > 3 {
                return None;
            }
            oct.push(std::mem::take(&mut cur));
            if oct.len() > 3 {
                return None;
            }
        } else {
            break;
        }
    }
    if oct.len() != 3 || cur.is_empty() || cur.len() > 3 {
        return None;
    }
    oct.push(cur);
    if oct.iter().any(|o| o.parse::<u8>().is_err()) {
        return None;
    }
    Some(oct.join("."))
}

fn split_cidr(cidr: &str) -> Option<(String, String)> {
    let (ip, plen) = cidr.split_once('/')?;
    let plen: u32 = plen.parse().ok()?;
    if plen > 32 {
        return None;
    }
    let parts: Vec<u32> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return None;
    }
    let addr = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    let maskv = if plen == 0 { 0 } else { u32::MAX << (32 - plen) };
    let net = addr & maskv;
    let mask = [(maskv >> 24) as u8, (maskv >> 16) as u8, (maskv >> 8) as u8, maskv as u8];
    Some((
        format!("{}.{}.{}.{}", (net >> 24) as u8, (net >> 16) as u8, (net >> 8) as u8, net as u8),
        format!("{}.{}.{}.{}", mask[0], mask[1], mask[2], mask[3]),
    ))
}

fn resolve_host(host: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    // голый IPv6 без порта в to_socket_addrs не парсится: оборачиваем в скобки,
    // иначе «не разрешён адрес сервера» на любом IPv6-пире
    let target = if h.contains(':') { format!("[{}]:443", h) } else { format!("{}:443", h) };
    target.to_socket_addrs().ok()?.next().map(|a| a.ip().to_string())
}

// ---------- маршрутизация (порт startSystemRouting) ----------

fn setup_routing(tun_ip: &str, tun_dns: &str) -> Result<(), String> {
    let idx = adapter_index(TUN_NAME, Duration::from_secs(12))?;
    cqstt_log_add("INFO", &format!("адаптер {} (if {})", TUN_NAME, idx));
    // MTU (без него Windows шлёт в TUN UDP-пакеты крупнее лимита целиком)
    if let Err(e) = run_hidden("netsh", &["interface", "ipv4", "set", "subinterface", TUN_NAME, &format!("mtu={}", TUN_MTU), "store=active"]) {
        // без MTU мост начнёт ронять пакеты фильтром размеров — сбой должен
        // быть виден в логе, а не глотаться молча
        cqstt_log_add("WARN", &format!("MTU {} для {} не применился: {}", TUN_MTU, TUN_NAME, e));
    }
    // IP адаптера
    run_hidden("netsh", &["interface", "ipv4", "set", "address", &format!("name={}", TUN_NAME), "static", tun_ip, "255.255.255.0"])
        .map_err(|e| format!("IP адаптера: {}", e))?;
    let _ = run_hidden("netsh", &["interface", "ipv4", "set", "interface", TUN_NAME, "metric=1"]);
    std::thread::sleep(Duration::from_millis(500));

    // split-default: половинки v4 через TUN (эквивалент New-NetRoute из Go)
    let ifarg = idx.to_string();
    for prefix in ["0.0.0.0", "128.0.0.0"] {
        run_hidden("route", &["add", prefix, "mask", "128.0.0.0", tun_ip, "metric", "1", "if", &ifarg])
            .map_err(|e| format!("split-маршрут {}: {}", prefix, e))?;
    }
    // v6-guard: ::/1 и 8000::/1 в TUN (иначе v6-трафик утечёт мимо туннеля)
    for prefix in ["::/1", "8000::/1"] {
        let _ = run_hidden("netsh", &["interface", "ipv6", "add", "route", prefix, TUN_NAME, "metric=1", "store=active"]);
    }
    cqstt_log_add("INFO", "split-маршруты и v6-guard установлены");

    // DNS: адаптер TUN + NRPT
    run_hidden("netsh", &["interface", "ipv4", "set", "dnsservers", &format!("name={}", TUN_NAME), "static", tun_dns, "primary"])
        .map_err(|e| format!("DNS адаптера: {}", e))?;
    if let Err(e) = nrpt_install(tun_dns) {
        log_add("cqstt", &format!("NRPT не встал (не критично): {}", e));
    }
    Ok(())
}

// очистка маршрутов/NRPT/DNS-кэша; безопасно вызывать многократно.
// ВСЁ в ОДНОМ проходе PowerShell: раньше было 4 запуска подряд (проверка
// чужого туннеля, снятие NRPT, nrpt_cleanup-дубль, маршруты) — на холодных
// стартах PS это давало ~8-12 с; теперь один процесс (~2-3 с). Плюс сам вызов
// теперь идёт из фонового потока (disconnect_in_background), а не из UI.
fn cleanup_routing() {
    // bypass-маршруты сессии (сервер/VK/TURN /32) — снимаются при ЛЮБОМ
    // завершении: раньше жили до ребута и после смены сети уводили трафик
    // в мёртвый шлюз
    clear_bypass_routes();
    let ps = format!(
        "$m = {{{m}}}\n\
         $foreign = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ $_.InterfaceDescription -eq 'CSQTT Tunnel' -and $_.Status -eq 'Up' }}).Count\n\
         if ($foreign -eq 0) {{\n\
         \x20 Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object $m | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }}\n\
         }} else {{ Write-Output 'NRPT_KEPT_FOREIGN' }}\n\
         $down = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ $_.InterfaceDescription -in @('Sentor','Sentor Tunnel','CSQTT Tunnel') -and $_.Status -ne 'Up' }} | Select-Object -ExpandProperty ifIndex\n\
         foreach ($prefix in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {{\n\
         \x20 Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue | Where-Object {{ $_.InterfaceAlias -eq '{a}' -or $down -contains $_.InterfaceIndex }} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n\
         }}\n\
         Clear-DnsClientCache -ErrorAction SilentlyContinue\n",
        m = nrpt_match_ps(),
        a = TUN_NAME
    );
    let out = run_hidden("powershell", &["-NoProfile", "-NonInteractive", "-Command", &ps]).unwrap_or_default();
    if out.contains("NRPT_KEPT_FOREIGN") {
        cqstt_log_add("INFO", "чужой CSQTT-туннель жив — NRPT не трогаю");
    }
    // v6-guard-маршруты чистим netsh (PowerShell мог не увидеть их в ActiveStore)
    for prefix in ["::/1", "8000::/1"] {
        let _ = run_hidden("netsh", &["interface", "ipv6", "delete", "route", prefix, TUN_NAME]);
    }
}

// снять все bypass-маршруты, накопленные этой сессией (сервер, VK CIDR,
// TURN-релеи)
fn clear_bypass_routes() {
    let routes: Vec<(String, String)> = {
        let mut h = HANDLES.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut h.bypass)
    };
    for (net, mask) in &routes {
        route_delete(net, mask);
    }
}

fn route_bypass_host(ip: &str, gw: &str, phys_if: u32) {
    if route_add(ip, "255.255.255.255", gw, phys_if).is_ok() {
        // трекинг для clear_bypass_routes: раньше TURN-хосты добавлялись
        // «в никуда» и оставались в таблице до ребута
        HANDLES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bypass
            .push((ip.to_string(), "255.255.255.255".into()));
    }
}

// Общий обработчик строк вывода ядра для stdout И stderr. В Go stderr сливается
// с stdout (cmd.Stderr = cmd.Stdout), поэтому события __CSQTT_EVENT__ могут
// прийти из любого потока — обрабатываем обе трубы одинаково.
struct CoreLineRouter {
    ev_cfg: Arc<Mutex<Option<(String, String)>>>,
    ev_notify: Arc<(Mutex<bool>, std::sync::Condvar)>,
    ev_turn: Arc<Mutex<Vec<String>>>,
    gw: String,
    phys: u32,
    session_tag: u64,
}

impl CoreLineRouter {
    fn process(&self, t: &str) {
        if t.starts_with(EVENT_PREFIX) {
            // РОВНО как в Go (core.go:347): SplitN по ПОЛНОЙ строке —
            // ["__CSQTT_EVENT__", KIND, JSON]. Раньше strip_prefix съедал первый
            // сегмент, оставалось 2 части, условие parts.len() == 3 никогда не
            // выполнялось и все события ядра (включая CONFIG) молча выбрасывались
            // → «сервер не выдал TUNCONF за 90 с» без единой ошибки в логе.
            let parts: Vec<&str> = t.splitn(3, '|').collect();
            if parts.len() == 3 {
                match parts[1] {
                    "CONFIG" => {
                        let cfgv: Option<String> = serde_json::from_str::<serde_json::Value>(parts[2])
                            .ok()
                            .and_then(|v| v.get("config").and_then(|c| c.as_str()).map(|x| x.to_string()));
                        match cfgv.as_deref().and_then(parse_tunconf) {
                            Some((ip, dns)) => {
                                *self.ev_cfg.lock().unwrap_or_else(|e| e.into_inner()) = Some((ip, dns));
                                let (lk, cv) = &*self.ev_notify;
                                *lk.lock().unwrap_or_else(|e| e.into_inner()) = true;
                                cv.notify_all();
                            }
                            None => {
                                // раньше молча игнорировали — теперь видно в логе
                                cqstt_log_add("WARN", &format!("CONFIG не распознан: {}", parts[2].trim()));
                            }
                        }
                    }
                    "READY" => cqstt_log_add("INFO", "ядро готово (READY)"),
                    "STATS" => {
                        // {"active":..} — байты считаем на мосту
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(parts[2]) {
                            let active = v.get("active").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
                            let mut g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
                            if g.session == self.session_tag {
                                g.state.active = active;
                            }
                        }
                    }
                    "ERROR" => cqstt_log_add("ERROR", &format!("ядро: {}", parts[2].trim())),
                    _ => cqstt_log_add("INFO", &format!("[event] {}", parts[1])),
                }
            } else {
                // событие с неожиданным числом сегментов больше не исчезает молча
                cqstt_log_add("WARN", &format!("событие ядра с неожиданным форматом: {}", t.trim()));
            }
            return;
        }
        if let Some(rest) = t.strip_prefix("CAPTCHA_SOLVE|") {
            let pp: Vec<&str> = rest.split('|').collect();
            if pp.len() >= 3 {
                cqstt_log_add("WARN", &format!("требуется капча ({}) — открываю панель", pp[0]));
                let payload = json!({ "mode": pp[0], "url": pp[1], "session": pp[2] });
                if let Some(a) = app() {
                    let _ = a.emit("cqsttCaptcha", payload.to_string());
                }
            }
            return;
        }
        if let Some(ip) = relay_ip_from_line(t) {
            let mut turn = self.ev_turn.lock().unwrap_or_else(|e| e.into_inner());
            if !turn.contains(&ip) {
                turn.push(ip.clone());
                drop(turn);
                route_bypass_host(&ip, &self.gw, self.phys);
                cqstt_log_add("INFO", &format!("  + bypass TURN {}", ip));
            }
            return;
        }
        // этап 3: VK-авторизация прошла / TURN-креды получены (живая схема пути)
        if t.contains("[VK Auth] Success") || (t.contains("[КРЕД #") && t.contains("OK, TURN")) {
            set_stage(3, self.session_tag);
        }
        cqstt_log_add("INFO", &format!("[client] {}", t));
    }
}

// ---------- жизненный цикл сессии ----------

// abort_if_closing — disconnect запросили, а воркер ещё подключался (гонка
// «быстрый disconnect во время connect»): раньше воркер продолжал поднимать
// адаптер/маршруты после того, как disconnect-поток уже отработал, и всё
// созданное после его уборки оставалось висеть — адаптер-сирота в трее и
// split-маршруты до ребута. Чистим сами (все шаги идемпотентны и конкурентны
// с уборкой disconnect-потока: take() под локом не даёт снести чужое).
// Возвращает true, если воркер должен завершиться (closing выставлен).
fn abort_if_closing(closing: &AtomicBool, session_tag: u64) -> bool {
    if !closing.load(Ordering::SeqCst) {
        return false;
    }
    {
        let g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
        if g.session != session_tag {
            return true; // сессия сменилась — мир новой сессии не трогаем
        }
    }
    stop_client_process();
    if let Some(b) = HANDLES.lock().unwrap_or_else(|e| e.into_inner()).bridge.take() {
        b.close();
    }
    cleanup_routing();
    finish_session("disconnected", None, session_tag);
    true
}

#[allow(clippy::too_many_arguments)]
fn session_worker(
    tools: PathBuf,
    session_tag: u64,
    closing: Arc<AtomicBool>,
    gw: String,
    phys_if: u32,
    relay: Option<UdpRelayParams>,
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
) {
    // конфиг туннеля придёт событием CONFIG
    let config: Arc<Mutex<Option<(String, String)>>> = Arc::new(Mutex::new(None));
    let notify = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let ev_turn: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(CoreLineRouter {
        ev_cfg: config.clone(),
        ev_notify: notify.clone(),
        ev_turn,
        gw,
        phys: phys_if,
        session_tag,
    });

    // чтение потока ядра (stdout или stderr) с разбором строк через router
    fn spawn_reader(
        r: Box<dyn std::io::Read + Send>,
        router: Arc<CoreLineRouter>,
        closing: Arc<AtomicBool>,
    ) {
        std::thread::spawn(move || {
            let mut r = r;
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                if closing.load(Ordering::SeqCst) {
                    return;
                }
                match r.read(&mut chunk) {
                    Ok(0) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => return,
                }
                while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=pos).collect();
                    let t = String::from_utf8_lossy(&line[..line.len() - 1]).trim_end_matches('\r').to_string();
                    let t = t.trim().to_string();
                    if t.is_empty() {
                        continue;
                    }
                    router.process(&t);
                }
            }
        });
    }
    if let Some(r) = stdout {
        spawn_reader(Box::new(r), router.clone(), closing.clone());
    }
    if let Some(r) = stderr {
        spawn_reader(Box::new(r), router, closing.clone());
    }

    // ждём CONFIG до CONFIG_WAIT_SECS
    {
        let (lk, cv) = &*notify;
        let deadline = Instant::now() + Duration::from_secs(CONFIG_WAIT_SECS);
        let mut guard = lk.lock().unwrap_or_else(|e| e.into_inner());
        while !*guard {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || closing.load(Ordering::SeqCst) {
                break;
            }
            let (g2, _) = cv.wait_timeout(guard, left.min(Duration::from_millis(500))).unwrap_or_else(|e| e.into_inner());
            guard = g2;
        }
    };
    let Some((tun_ip, tun_dns)) = config.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
        if closing.load(Ordering::SeqCst) {
            // Штатный disconnect в окне подключения: уборку выполняет
            // disconnect-поток. Раньше эта ветка пугала ложным ERROR
            // «сервер не выдал TUNCONF» при ручном отключении во время
            // ожидания конфига.
            finish_session("disconnected", None, session_tag);
            return;
        }
        cqstt_log_add("ERROR", "сервер не выдал TUNCONF за 90 с — подключение не удалось");
        stop_client_process();
        cleanup_routing();
        finish_session("disconnected", Some("сервер не выдал TUNCONF".into()), session_tag);
        return;
    };
    cqstt_log_add("INFO", &format!("TUNCONF: IP {} · DNS {}", tun_ip, tun_dns));
    // CONFIG мог прийти уже ПОСЛЕ запроса disconnect (флаг closing не прерывает
    // ожидание, если конфиг успел положить роутер): без этой проверки воркер
    // продолжил бы поднимать адаптер на мёртвой сессии
    if abort_if_closing(&closing, session_tag) {
        return;
    }

    // мост Wintun ↔ ядро
    let up = Arc::new(AtomicI64::new(0));
    let down = Arc::new(AtomicI64::new(0));
    let fail_flag = Arc::new(AtomicBool::new(false));
    let fail_flag2 = fail_flag.clone();
    let core_dir = paths::cqstt_core_dir(&tools);
    let wintun = match unsafe { wintun::load_from_path(core_dir.join("wintun.dll")) } {
        Ok(w) => w,
        Err(e) => {
            let m = format!("wintun.dll не загрузился: {}", e);
            cqstt_log_add("ERROR", &m);
            stop_client_process();
            cleanup_routing();
            finish_session("disconnected", Some(m), session_tag);
            return;
        }
    };
    let on_fail = move |cause: String| {
        // мост умер — гасим сессию в фоновом потоке. Обязательно с тегом своей
        // сессии: без него запоздалый disconnect убивал уже НОВУЮ сессию при
        // быстром переподключении («спонтанные отключения»)
        if !fail_flag2.swap(true, Ordering::SeqCst) {
            cqstt_log_add("ERROR", &format!("мост остановлен: {}", cause));
            std::thread::spawn(move || {
                let _ = disconnect_internal(Some(session_tag));
            });
        }
    };
    let bridge = match start_bridge(&wintun, &core_dir, tun_ip.clone(), relay, up.clone(), down.clone(), closing.clone(), Arc::new(on_fail)) {
        Ok(b) => b,
        Err(e) => {
            if closing.load(Ordering::SeqCst) {
                // отменили посреди подключения — тихо убираем созданное,
                // без ложной ошибки в состоянии
                abort_if_closing(&closing, session_tag);
                return;
            }
            let m = format!("Wintun-мост: {}", e);
            cqstt_log_add("ERROR", &m);
            stop_client_process();
            cleanup_routing();
            finish_session("disconnected", Some(m), session_tag);
            return;
        }
    };
    if let Some(old) = HANDLES.lock().unwrap_or_else(|e| e.into_inner()).bridge.replace(bridge) {
        old.close();
    }
    // адаптер/мост могли появиться уже после отработки disconnect-потока
    // (start_bridge с ретраями занимает секунды) — иначе он остался бы сиротой
    if abort_if_closing(&closing, session_tag) {
        return;
    }

    // маршрутизация
    match setup_routing(&tun_ip, &tun_dns) {
        Ok(()) => {
            // маршруты могли добавиться уже после уборки disconnect-потока —
            // снимаем их сами, иначе висят до ребута
            if abort_if_closing(&closing, session_tag) {
                return;
            }
            cqstt_log_add("INFO", "системные маршруты направлены в CSQTT");
            let mut g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
            if g.session == session_tag {
                g.state.phase = "connected".into();
                g.state.since = now_unix();
                g.state.stage = 4;
                g.state.error = None;
            }
            drop(g);
            cqstt_emit_state();
            cqstt_log_add("INFO", &format!("✅ CSQTT активен: IP {}, DNS {}", tun_ip, tun_dns));
        }
        Err(e) => {
            if closing.load(Ordering::SeqCst) {
                abort_if_closing(&closing, session_tag);
                return;
            }
            cqstt_log_add("ERROR", &format!("маршрутизация: {}", e));
            stop_client_process();
            if let Some(b) = HANDLES.lock().unwrap_or_else(|e| e.into_inner()).bridge.take() {
                b.close();
            }
            cleanup_routing();
            finish_session("disconnected", Some(e), session_tag);
            return;
        }
    }

    // watchdog: смерть ядра/моста → уборка и оповещение
    loop {
        if closing.load(Ordering::SeqCst) {
            // штатный disconnect: cleanup выполняет disconnect()
            return;
        }
        if fail_flag.load(Ordering::SeqCst) {
            break;
        }
        let died = {
            let mut h = HANDLES.lock().unwrap_or_else(|e| e.into_inner());
            match h.child.as_mut().map(|c| c.try_wait()) {
                Some(Ok(Some(_))) => true,
                Some(Ok(None)) | None => false,
                Some(Err(_)) => true,
            }
        };
        if died {
            cqstt_log_add("ERROR", "csqtt-client завершился раньше времени");
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if let Some(b) = HANDLES.lock().unwrap_or_else(|e| e.into_inner()).bridge.take() {
        b.close();
    }
    cleanup_routing();
    let err = fail_flag.load(Ordering::SeqCst).then(|| "мост/ядро остановились".to_string());
    finish_session("disconnected", err, session_tag);
}

fn stop_client_process() {
    let (child, stdin, job) = {
        let mut h = HANDLES.lock().unwrap_or_else(|e| e.into_inner());
        (h.child.take(), h.stdin.take(), h.job.take())
    };
    if let Some(mut stdin) = stdin {
        let _ = stdin.write_all(b"STOP\n");
        let _ = stdin.flush();
        drop(stdin);
    }
    if let Some(mut child) = child {
        let deadline = Instant::now() + Duration::from_millis(CLIENT_STOP_WAIT_MS);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if Instant::now() > deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(_) => break,
            }
        }
    }
    // child мёртв — дескриптор Job больше не нужен (drop закроет хендл;
    // раньше закрытия дропать нельзя: KILL_ON_JOB_CLOSE добил бы живое ядро)
    drop(job);
}

fn finish_session(phase: &str, error: Option<String>, session_tag: u64) {
    let mut g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
    if g.session != session_tag {
        return; // сессия сменилась — не затираем чужое состояние
    }
    g.running = false;
    g.stop_requested = false;
    g.state.phase = phase.into();
    g.state.running = false;
    g.state.since = 0;
    g.state.stage = 0;
    // счётчики сессии обнуляем: раньше после disconnect UI показывал байты
    // прошлой сессии до следующего подключения
    g.state.active = 0;
    g.state.bytes_up = 0;
    g.state.bytes_down = 0;
    g.state.error = error;
    // адаптер сессии убираем здесь же, под локом и после сверки тега: пока
    // running не снят, новая сессия стартовать не может. Покрывает фоновое
    // отключение и все самостоятельные завершения (смерть ядра/моста, ошибки
    // после подъёма TUN); при синхронном disconnect() то же делает его хвост
    delete_session_adapter();
    drop(g);
    cqstt_emit_state();
}

// ---------- публичные операции ----------

pub fn connect(server: &CqsttServer) -> Result<(), String> {
    let mut s = server.clone();
    normalize_server(&mut s);
    let tools = tools_dir();
    // guards: взаимное исключение TUN-ов
    {
        let mut g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
        if g.running {
            return Err("CSQTT уже подключён".into());
        }
        if crate::wdtt_session::running() {
            return Err("⚠️ Сначала отключи WDTT — два TUN-туннеля конфликтуют за маршруты".into());
        }
        if crate::conn::warp_active() {
            return Err("⚠️ Сначала отключи WARP — два TUN-туннеля конфликтуют за маршруты".into());
        }
        g.stop_requested = false;
        g.session += 1;
        g.running = true;
        g.state = CqsttStatusInfo {
            running: true,
            phase: "connecting".into(),
            name: s.name.clone(),
            id: Some(s.id.clone()),
            since: 0,
            active: 0,
            bytes_up: 0,
            bytes_down: 0,
            workers: s.workers,
            stage: 1,
            error: None,
        };
        // лог-файл + очистка кольца ДО старта ядра
        let _ = std::fs::create_dir_all(paths::cqstt_dir(&tools));
        g.log_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(paths::cqstt_log_path(&tools))
            .ok();
        g.log_lines.clear();
    }
    // новый флаг closing для этой сессии — кладём в HANDLES (worker и
    // disconnect() пользуются им совместно)
    let closing = Arc::new(AtomicBool::new(false));
    HANDLES.lock().unwrap_or_else(|e| e.into_inner()).closing = Some(closing.clone());
    cqstt_emit_state();

    // остановить основной VPN (TUN-маршруты общие), как делает WDTT
    if let Some(a) = app().cloned() {
        let had_vpn = {
            let st = a.state::<Arc<crate::state::AppState>>();
            let inner = st.conn.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.state.phase == "connected" || inner.state.phase == "starting"
        };
        if had_vpn {
            cqstt_log_add("INFO", "останавливаю основной VPN — маршруты общие");
            crate::commands::vpn_disconnect_cmd(&a);
        }
    }

    if let Err(e) = connect_inner(&tools, &s) {
        cleanup_routing();
        {
            let mut g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
            g.running = false;
            g.state.phase = "disconnected".into();
            g.state.running = false;
            g.state.stage = 0;
            g.state.error = Some(e.clone());
        }
        cqstt_emit_state();
        return Err(e);
    }
    Ok(())
}

// stable_device_id — порт loadOrCreateDeviceID из csqtt-vpn: 32 hex-символа,
// сгенерированные ОДИН РАЗ и сохранённые в cqstt\device-id. Сервер привязывает
// пароль к идентификатору устройства — новый id на каждое подключение даёт
// молчаливый отказ воркеров («Все воркеры завершены» без TUNCONF).
fn stable_device_id(tools: &Path) -> String {
    let p = paths::cqstt_dir(tools).join("device-id");
    if let Ok(s) = std::fs::read_to_string(&p) {
        let t = s.trim();
        if t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            return t.to_string();
        }
    }
    let mut bytes = [0u8; 16];
    for b in bytes.iter_mut() {
        *b = fastrand::u8(..);
    }
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let _ = std::fs::create_dir_all(paths::cqstt_dir(tools));
    let _ = std::fs::write(&p, &hex);
    hex
}

fn connect_inner(tools: &Path, s: &CqsttServer) -> Result<(), String> {
    // 1. распаковка ядра
    let core_dir = ensure_core(tools).map_err(|e| {
        cqstt_log_add("ERROR", &e);
        e
    })?;
    let exe = paths::cqstt_client_exe(tools);

    // 2. физический шлюз для bypass-маршрутов (до появления TUN)
    let (gw, phys_if) = phys_default().map_err(|e| {
        let m = format!("физический маршрут: {}", e);
        cqstt_log_add("ERROR", &m);
        m
    })?;
    cqstt_log_add("INFO", &format!("физический шлюз: {} (if {})", gw, phys_if));

    // 3. bypass: сервер + сети VK
    let server_host = s.peer.rsplit_once(':').map(|(h, _)| h).unwrap_or(s.peer.as_str()).trim().to_string();
    let server_ip = resolve_host(&server_host).ok_or_else(|| {
        let m = format!("не разрешён адрес сервера {}", server_host);
        cqstt_log_add("ERROR", &m);
        m
    })?;
    let mut route_guard: Vec<(String, String)> = Vec::new();
    // UDP-релей серверного потока: bypass для IP сервера не ставится — сервисы
    // на этом IP (панель конфигов и т.п.) доступны через туннель. Мост
    // перехватывает UDP ядра к серверу и отправляет с физического IP.
    let server_port: u16 = s.peer.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(46000);
    let relay_params: Option<UdpRelayParams> =
        if server_ip.parse::<Ipv4Addr>().is_ok() && s.transport.as_deref().unwrap_or("udp") == "udp" {
            match std::net::UdpSocket::bind(("0.0.0.0", 0)).and_then(|sk| {
                sk.connect((server_ip.as_str(), server_port))?;
                sk.local_addr()
            }) {
                Ok(local) => {
                    cqstt_log_add(
                        "INFO",
                        &format!(
                            "релей к серверу: ядро ↔ {}:{} через {} — bypass для IP сервера не ставится (панель/сервисы на нём пойдут через туннель)",
                            server_ip, server_port, local.ip()
                        ),
                    );
                    Some(UdpRelayParams {
                        server_ip: server_ip.parse().unwrap(),
                        server_port,
                        phys_ip: local.ip(),
                    })
                }
                Err(e) => {
                    cqstt_log_add(
                        "WARN",
                        &format!("релей к серверу не поднялся ({}): {} — серверу вернём bypass", server_ip, e),
                    );
                    None
                }
            }
        } else {
            None
        };
    if relay_params.is_none() {
        // старое поведение: bypass для IP сервера (tcp_tls-транспорт или IPv6-сервер)
        route_add(&server_ip, "255.255.255.255", &gw, phys_if)
            .map_err(|e| format!("bypass-маршрут сервера {}: {}", server_ip, e))?;
        route_guard.push((server_ip.clone(), "255.255.255.255".into()));
    }
    for cidr in BYPASS_CIDRS {
        if let Some((net, mask)) = split_cidr(cidr) {
            if route_add(&net, &mask, &gw, phys_if).is_ok() {
                route_guard.push((net, mask));
            }
        }
    }
    cqstt_log_add(
        "INFO",
        if relay_params.is_some() {
            "bypass: VK-сети и TURN; IP сервера — через туннельный релей"
        } else {
            "bypass-маршруты сервера и VK добавлены"
        },
    );
    // список в HANDLES СРАЗУ: всё, что упадёт ниже (спавн ядра, stdin и т.д.),
    // всё равно выйдет через cleanup_routing — он снимет и эти маршруты.
    // Раньше список регистрировался только в конце connect_inner и при сбое
    // по пути маршруты утекали до ребута
    {
        let mut h = HANDLES.lock().unwrap_or_else(|e| e.into_inner());
        h.bypass = route_guard;
    }

    // 4. спавн ядра
    let hashes = hash_list(&s.hashes).join(",");
    let device_id = stable_device_id(tools);
    let mut cmd = std::process::Command::new(&exe);
    cmd.args([
        "--peer",
        s.peer.trim(),
        "--credentials-stdin",
        "--workers",
        &s.workers.to_string(),
        "--device-id",
        device_id.as_str(),
        "--vk-hash-mode",
        "manual",
        "--vk-auth-mode",
        "vkcalls",
        "--captcha-mode",
        "auto",
        "--obfs",
        s.obfs.as_deref().unwrap_or("audio"),
        "--turn-transport",
        s.transport.as_deref().unwrap_or("udp"),
        "--listen",
        INNER_LISTEN,
    ]);
    cmd.current_dir(&core_dir);
    cmd.env("CSQTT_EVENTS", "1");
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdin(std::process::Stdio::piped());
    log_add("cqstt", &format!("запуск csqtt-client (peer {}, workers {})", s.peer, s.workers));
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let m = format!("старт csqtt-client: {}", e);
            cqstt_log_add("ERROR", &m);
            return Err(m);
        }
    };
    // Job Object с KILL_ON_JOB_CLOSE: csqtt-client — DETACHED-потомок, после
    // краха/kill Sentor оставался жить и держал 127.0.0.1:19000 до ручного
    // добивания. Дескриптор живёт в HANDLES до конца сессии — при смерти
    // приложения ОС закроет хендл и Job добьёт ядро сам.
    let job = crate::conn::new_kill_on_close_job();
    if let Some(job) = &job {
        job.attach(child.id());
    }
    // credentials через stdin (пароль и хеши не светятся в argv)
    let mut stdin = match child.stdin.take() {
        Some(x) => x,
        None => {
            let _ = child.kill();
            return Err("нет stdin у ядра".into());
        }
    };
    let creds = json!({ "password": s.password, "vk": hashes });
    let input = format!("CSQTT_CREDENTIALS|{}\n", creds);
    if stdin.write_all(input.as_bytes()).is_err() || stdin.flush().is_err() {
        let _ = child.kill();
        return Err("не передать credentials в csqtt-client".into());
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    // зарегистрировать дескрипторы сессии
    {
        let mut h = HANDLES.lock().unwrap_or_else(|e| e.into_inner());
        h.child = Some(child);
        h.stdin = Some(stdin);
        h.job = job;
    }

    // 5. воркер: чтение вывода, CONFIG-ожидание, мост, маршруты, watchdog
    let session_tag = CQSTT.lock().unwrap_or_else(|e| e.into_inner()).session;
    // этап 2: ядро запущено и приняло credentials (живая схема пути)
    set_stage(2, session_tag);
    let closing = HANDLES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .closing
        .clone()
        .ok_or("closing-флаг сессии не установлен")?;
    let tools_buf = tools.to_path_buf();
    let _ = std::thread::Builder::new().name("cqstt-session".into()).spawn(move || {
        session_worker(tools_buf, session_tag, closing, gw, phys_if, relay_params, stdout, stderr);
    });
    Ok(())
}

fn tools_dir() -> PathBuf {
    static CACHE: OnceLock<PathBuf> = OnceLock::new();
    CACHE.get_or_init(crate::paths::find_tools_dir).clone()
}

pub fn disconnect() -> String {
    disconnect_internal(None)
}

// мгновенная (НЕ блокирующая) остановка для UI-команды. Раньше disconnect()
// целиком исполнялся на главном потоке Tauri: до 10 с ожидания ядра + ~10 с
// уборки (4 запуска PowerShell подряд) — окно зависало на 10-25 с. Теперь
// команда мгновенно ставит фазу «disconnecting» и возвращает управление,
// а вся цепочка (STOP ядру → ожидание → закрытие моста → уборка) идёт в фоне.
pub fn disconnect_in_background() -> String {
    let tag;
    {
        let mut g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
        if !g.running {
            return "CSQTT и так не подключён".into();
        }
        if g.stop_requested {
            return "⌛ CSQTT уже останавливается…".into();
        }
        g.stop_requested = true;
        g.state.phase = "disconnecting".into();
        tag = g.session;
    }
    cqstt_emit_state();
    // будим воркер (worker-цикл проверяет closing)
    if let Some(c) = HANDLES.lock().unwrap_or_else(|e| e.into_inner()).closing.clone() {
        c.store(true, Ordering::SeqCst);
    }
    let spawned = std::thread::Builder::new()
        .name("cqstt-disconnect".into())
        .spawn(move || {
            stop_client_process();
            if let Some(b) = HANDLES.lock().unwrap_or_else(|e| e.into_inner()).bridge.take() {
                b.close();
            }
            cleanup_routing();
            // тег-защита как у finish_session: если пока шла остановка началась
            // новая сессия — её состояние не трогаем
            finish_session("disconnected", None, tag);
            log_add("cqstt", "остановлено");
        });
    if spawned.is_err() {
        // фон не взялся — отрабатываем синхронно как раньше (лучше подлагивание,
        // чем неубранные маршруты)
        let _ = disconnect_internal(None);
        return "✅ CSQTT отключён, маршруты восстановлены".into();
    }
    "⌛ Останавливаю CSQTT — закрытие ядра и чистка маршрутов в фоне…".into()
}

// allowed_tag = Some(t): гасить ТОЛЬКО сессию с тегом t (для on_fail — без
// тега запоздалый фоновой disconnect гасил уже НОВУЮ сессию при быстром
// переподключении). None: пользовательский disconnect — гасит текущую.
fn disconnect_internal(allowed_tag: Option<u64>) -> String {
    let stop_tag;
    {
        let mut g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
        if !g.running {
            return "CSQTT и так не подключён".into();
        }
        if let Some(tag) = allowed_tag {
            if g.session != tag {
                return String::new(); // сессия уже сменилась — не наша
            }
        }
        stop_tag = g.session;
        g.stop_requested = true;
    }
    // будим воркер (worker-цикл проверяет closing)
    if let Some(c) = HANDLES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .closing
        .clone()
    {
        c.store(true, Ordering::SeqCst);
    }
    stop_client_process();
    if let Some(b) = HANDLES.lock().unwrap_or_else(|e| e.into_inner()).bridge.take() {
        b.close();
    }
    cleanup_routing();
    let mut g = CQSTT.lock().unwrap_or_else(|e| e.into_inner());
    // адаптер — только пока сессия ещё наша. Проверка и удаление под одним
    // локом: новая сессия не стартует, пока не снят running, — при быстром
    // переподключении не снесём её адаптер
    if g.session == stop_tag {
        delete_session_adapter();
    }
    g.running = false;
    g.state.phase = "disconnected".into();
    g.state.running = false;
    g.state.since = 0;
    g.state.stage = 0;
    g.state.active = 0;
    g.state.bytes_up = 0;
    g.state.bytes_down = 0;
    drop(g);
    cqstt_emit_state();
    log_add("cqstt", "остановлено");
    "✅ CSQTT отключён, маршруты восстановлены".into()
}

pub fn send_captcha(token: &str) -> String {
    let mut h = HANDLES.lock().unwrap_or_else(|e| e.into_inner());
    match h.stdin.as_mut() {
        Some(stdin) => {
            if stdin.write_all(format!("CAPTCHA_RESULT|{}\n", token).as_bytes()).is_ok()
                && stdin.flush().is_ok()
            {
                "✅ Токен капчи передан ядру".into()
            } else {
                "❌ Ядро не принимает капчу — процесс умер?".into()
            }
        }
        None => "⚠️ Туннель не запущен".into(),
    }
}

// при выходе приложения: сессию CSQTT гасим (TUN-маршруты общие с VPN/WDTT)
pub fn shutdown() {
    if running() {
        let _ = disconnect();
    }
    cleanup_routing();
}

// хвост прошлой сессии: если остался живой csqtt-client.exe без нашей сессии —
// добить (после краха приложения DETACHED-потомков не оставляем намеренно)
pub fn startup_cleanup() {
    let _ = run_hidden("taskkill", &["/F", "/IM", "csqtt-client.exe"]);
    cleanup_routing();
    delete_orphan_adapters();
}

// ---------- прямое удаление wintun-адаптеров (крейт не умеет) ----------

// Крейт wintun 0.5.1: Adapter::delete() — это просто drop → WintunCloseAdapter,
// который уничтожает ТОЛЬКО адаптеры, созданные в этом процессе (adapter.rs:134,
// 382-386). Сироты от убитых прошлых инстансов им не удаляются вовсе — прежний
// «фикс» был ноопом. Поэтому собственные объявления Wintun* поверх той же
// wintun.dll: WintunDeleteAdapter работает с ЛЮБЫМ адаптером по хэндлу.
type WintunOpenAdapterFn = unsafe extern "system" fn(name: *const u16) -> isize;
type WintunDeleteAdapterFn =
    unsafe extern "system" fn(adapter: isize, force_close_sessions: i32, reboot_required: *mut i32) -> i32;
type WintunCloseAdapterFn = unsafe extern "system" fn(adapter: isize);

// имена наших wintun-адаптеров из PS; живые (Up) НЕ выдаются — чужой клиент в
// автономном режиме может легитимно держать адаптер и его сессию
fn list_our_adapters(where_clause: &str) -> Vec<String> {
    list_our_adapters_any_status(&format!("{w} -and $_.Status -ne 'Up'", w = where_clause))
}

// то же, но БЕЗ фильтра статуса: для сноса НАШЕЙ сессии — в момент остановки
// адаптер ещё может числиться Up (сессия гасится асинхронно потоками моста)
fn list_our_adapters_any_status(where_clause: &str) -> Vec<String> {
    // UTF-8: имена адаптеров бывают кириллическими («Подключение по локальной
    // сети»), без этого PS отвечает в cp866 и WintunOpenAdapter по мусорному
    // имени молча не находил адаптер
    let ps = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ {w} }} | Select-Object -ExpandProperty Name",
        w = where_clause
    );
    match crate::tools::run_hidden("powershell", &["-NoProfile", "-NonInteractive", "-Command", &ps]) {
        Ok(out) => out.lines().map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(),
        Err(_) => Vec::new(),
    }
}

// удалить наши wintun-адаптеры по именам через WintunDeleteAdapter;
// возвращает (число реально удалённых, код ошибки Windows при неудаче)
fn wintun_delete_by_names(dll: &Path, names: &[String]) -> (usize, Option<u32>) {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError};
    if names.is_empty() || !dll.exists() {
        return (0, None);
    }
    let mut dll_w: Vec<u16> = dll.as_os_str().to_string_lossy().encode_utf16().collect();
    dll_w.push(0);
    let module = unsafe { LoadLibraryW(dll_w.as_ptr()) };
    if module.is_null() {
        return (0, Some(126)); // ERROR_MOD_NOT_FOUND
    }
    let result;
    unsafe {
        let (Some(open), Some(del), Some(close)) = (
            GetProcAddress(module, b"WintunOpenAdapter\0".as_ptr()),
            GetProcAddress(module, b"WintunDeleteAdapter\0".as_ptr()),
            GetProcAddress(module, b"WintunCloseAdapter\0".as_ptr()),
        ) else {
            FreeLibrary(module);
            return (0, Some(127)); // ERROR_PROC_NOT_FOUND
        };
        let open: WintunOpenAdapterFn = std::mem::transmute(open);
        let del: WintunDeleteAdapterFn = std::mem::transmute(del);
        let close: WintunCloseAdapterFn = std::mem::transmute(close);
        let mut count = 0usize;
        let mut last_err: Option<u32> = None;
        for name in names {
            let mut w: Vec<u16> = name.encode_utf16().collect();
            w.push(0);
            let handle = open(w.as_ptr());
            if handle == 0 {
                continue; // исчез между list и open — не страшно
            }
            // force_close_sessions = 1: у сироты живых сессий быть не должно,
            // а если уцелела — она всё равно от мёртвого процесса
            if del(handle, 1, std::ptr::null_mut()) != 0 {
                count += 1;
            } else {
                // НЕ глотаем: иначе «адаптер остался» diagnose нечем
                last_err = Some(GetLastError());
            }
            close(handle);
        }
        result = (count, last_err);
    }
    let _ = unsafe { FreeLibrary(module) };
    result
}

// wintun_open_probe — жив ли адаптер с этим именем (нативно, без PS)
fn wintun_open_probe(dll: &Path, name: &str) -> bool {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows_sys::Win32::Foundation::FreeLibrary;
    if !dll.exists() {
        return false;
    }
    let mut dll_w: Vec<u16> = dll.as_os_str().to_string_lossy().encode_utf16().collect();
    dll_w.push(0);
    let module = unsafe { LoadLibraryW(dll_w.as_ptr()) };
    if module.is_null() {
        return false;
    }
    let alive;
    unsafe {
        let Some(open) = GetProcAddress(module, b"WintunOpenAdapter\0".as_ptr()) else {
            FreeLibrary(module);
            return false;
        };
        let open: WintunOpenAdapterFn = std::mem::transmute(open);
        let mut w: Vec<u16> = name.encode_utf16().collect();
        w.push(0);
        let handle = open(w.as_ptr());
        alive = handle != 0;
        if alive {
            let Some(close) = GetProcAddress(module, b"WintunCloseAdapter\0".as_ptr()) else {
                FreeLibrary(module);
                return alive;
            };
            let close: WintunCloseAdapterFn = std::mem::transmute(close);
            close(handle);
        }
    }
    let _ = unsafe { FreeLibrary(module) };
    alive
}

// После force-kill приложения Wintun-адаптер остаётся в системе: объект
// адаптера живёт в драйвере до WintunDeleteAdapter (или ребута) — в сетевом
// трее висит «Sentor Tunnel · Без доступа к Интернету» и пугает. Удаляем при
// старте приложения адаптеры-сироты наших подписей ('Sentor'/'Sentor Tunnel')
// И автономного движка ('CSQTT Tunnel') — официальный клиент после кривого
// закрытия тоже оставляет свой адаптер висеть до ребута, а Sentor раньше
// игнорировал его forever. Up-адаптеры не трогаем — под ними может жить
// чужая сессия (list_our_adapters их не отдаёт).
fn delete_orphan_adapters() {
    let tools = tools_dir();
    let dll = paths::cqstt_core_dir(&tools).join("wintun.dll");
    if !dll.exists() {
        return; // ни разу не подключались — адаптеров и быть не могло
    }
    let names = list_our_adapters(
        "$_.InterfaceDescription -in @('Sentor','Sentor Tunnel','CSQTT Tunnel')",
    );
    if names.is_empty() {
        return;
    }
    let (n, err) = wintun_delete_by_names(&dll, &names);
    if n > 0 {
        cqstt_log_add("INFO", &format!("убрано адаптеров-сирот: {}", n));
    } else if let Some(code) = err {
        cqstt_log_add("ERROR", &format!("⚠️ адаптеры-сироты не удалились: {:?} (ошибка {})", names, code));
    }
}

// delete_session_adapter — убрать wintun-адаптер сессии после остановки.
// Почему не одним вызовом: (1) крейтовский Session::shutdown — это только
// SetEvent, кольцо закрывается в Drop ПОСЛЕДНЕЙ Arc<Session>, а их держат
// потоки моста, выходящие асинхронно — WintunDeleteAdapter в первые моменты
// может отвалиться (ошибка раньше молча глоталась и адаптер оставался);
// (2) при конфликте имён wintun плодит «sentor_csqtt 2», а удаляли ровно одно
// имя; (3) Adapter::open от прошлой сессии при закрытии не удаляется вовсе.
// Поэтому: нативный верифицирующий ретрай-цикл (open-проба = жив/мёртв),
// расширенный поиск через PS при живом хвосте и ЧЕСТНЫЙ лог с кодом ошибки.
fn delete_session_adapter() {
    let tools = tools_dir();
    let dll = paths::cqstt_core_dir(&tools).join("wintun.dll");
    if !dll.exists() {
        return;
    }
    // 1) быстрый путь: точное имя, до ~2.5 с на отпускание хэндлов моста
    let mut names = vec![TUN_NAME.to_string()];
    let mut deleted = 0;
    let mut last_err: Option<u32> = None;
    for _ in 0..8 {
        let (n, err) = wintun_delete_by_names(&dll, &names);
        deleted += n;
        last_err = err;
        if !wintun_open_probe(&dll, TUN_NAME) {
            break; // снесено — нативная верификация
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    // 2) хвост жив → ищем ВСЕ наши адаптеры любого статуса: дубликаты имён
    // («sentor_csqtt 2»), сироты с описанием Sentor, имена с суффиксами
    if wintun_open_probe(&dll, TUN_NAME) {
        let extra = list_our_adapters_any_status(
            "($_.Name -like 'sentor_csqtt*') -or ($_.InterfaceDescription -in @('Sentor','Sentor Tunnel'))",
        );
        for name in extra {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        for _ in 0..4 {
            let (n, err) = wintun_delete_by_names(&dll, &names);
            deleted += n;
            last_err = err;
            let mut alive = false;
            for name in &names {
                if wintun_open_probe(&dll, name) {
                    alive = true;
                }
            }
            if !alive {
                break;
            }
            std::thread::sleep(Duration::from_millis(400));
        }
    }
    // 3) честный отчёт: если что-то пережило всё это — это видно в логе
    if deleted > 0 {
        cqstt_log_add("INFO", &format!("адаптер сессии удалён ({} шт.)", deleted));
    }
    if wintun_open_probe(&dll, TUN_NAME) {
        cqstt_log_add(
            "ERROR",
            &format!(
                "⚠️ адаптер сессии НЕ удалён — WintunDeleteAdapter ошибка {:?}; перезапусти Sentor (снос сирот при старте) или ребутни ПК",
                last_err
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Condvar, Mutex};

    fn router() -> CoreLineRouter {
        CoreLineRouter {
            ev_cfg: Arc::new(Mutex::new(None)),
            ev_notify: Arc::new((Mutex::new(false), Condvar::new())),
            ev_turn: Arc::new(Mutex::new(Vec::new())),
            gw: "192.168.0.1".into(),
            phys: 17,
            session_tag: 0,
        }
    }

    // Раньше все события ядра молча выбрасывались: strip_prefix съедал
    // "__CSQTT_EVENT__|", splitn оставлял 2 части, len==3 не выполнялся
    // → «сервер не выдал TUNCONF за 90 с» при живом и рабочем ядре.
    #[test]
    fn config_event_reaches_parser() {
        let r = router();
        r.process("__CSQTT_EVENT__|CONFIG|{\"config\":\"TUNCONF:10.70.0.3:1.1.1.1:19000\"}");
        let cfg = r.ev_cfg.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(cfg, Some(("10.70.0.3".to_string(), "1.1.1.1".to_string())));
        assert!(*r.ev_notify.0.lock().unwrap_or_else(|e| e.into_inner()));
    }

    #[test]
    fn malformed_event_does_not_panic_or_assign() {
        let r = router();
        r.process("__CSQTT_EVENT__|CONFIG");
        r.process("__CSQTT_EVENT__|");
        assert!(r.ev_cfg.lock().unwrap_or_else(|e| e.into_inner()).is_none());
    }

    #[test]
    fn ready_and_stats_events_are_consumed() {
        let r = router();
        r.process("__CSQTT_EVENT__|READY|{}");
        r.process("__CSQTT_EVENT__|STATS|{\"active\":7}");
        // события не должны задевать конфиг
        assert!(r.ev_cfg.lock().unwrap_or_else(|e| e.into_inner()).is_none());
    }

    // семантика РОВНО как в Go (parseTunnelConfig): хвост после третьего
    // ":" отбрасывается, иначе DNS-кандидат "1.1.1.1:19000" валит весь конфиг
    #[test]
    fn parse_tunconf_tail_is_dropped() {
        assert_eq!(
            parse_tunconf("TUNCONF:10.70.0.3:1.1.1.1:19000"),
            Some(("10.70.0.3".to_string(), "1.1.1.1".to_string()))
        );
        assert_eq!(parse_tunconf("10.70.0.3"), None);
        assert_eq!(parse_tunconf("TUNCONF:not-ip:1.1.1.1"), None);
    }

    // Релей: сборка IPv4/UDP → разбор — roundtrip с валидными checksum.
    #[test]
    fn relay_packet_roundtrip() {
        let payload = b"hello relay, this is a longer payload for the test";
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(10, 70, 0, 4),
            Ipv4Addr::new(150, 241, 89, 35),
            53000,
            46000,
            payload,
        );
        let f = parse_ipv4_udp_flow(&pkt).expect("parse");
        assert_eq!(f.src, Ipv4Addr::new(10, 70, 0, 4));
        assert_eq!(f.dst, Ipv4Addr::new(150, 241, 89, 35));
        assert_eq!(f.src_port, 53000);
        assert_eq!(f.dst_port, 46000);
        assert_eq!(f.payload, payload);
        // оба checksum валидны (сумма с уже вписанным checksum даёт ноль)
        assert_eq!(ipv4_header_checksum(&pkt[..20]), 0);
        assert_eq!(udp_checksum(f.src, f.dst, &pkt[20..]), 0);
    }

    #[test]
    fn relay_parse_rejects_non_udp_and_fragments() {
        // TCP-пакет — не перехват
        let mut tcp = build_ipv4_udp_packet(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            1,
            2,
            b"x",
        );
        tcp[9] = 6; // proto TCP
        assert!(parse_ipv4_udp_flow(&tcp).is_none());
        // не первый фрагмент (offset != 0) — UDP-заголовка нет
        let mut frag = build_ipv4_udp_packet(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            1,
            2,
            b"x",
        );
        frag[7] = 0x01; // fragment offset = 1
        assert!(parse_ipv4_udp_flow(&frag).is_none());
        // обрезанный пакет
        assert!(parse_ipv4_udp_flow(&pkt_short()).is_none());
    }

    fn pkt_short() -> Vec<u8> {
        let mut p = build_ipv4_udp_packet(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8), 1, 2, b"x");
        p.truncate(24); // меньше ihl + 8
        p
    }
}
