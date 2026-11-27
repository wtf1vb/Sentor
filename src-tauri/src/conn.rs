// VPN connection manager - port of Go vpnConnManager (vpn.go): ports,
// core spawn with Job Object, phase events, TUN wait, traffic probe, watchdog.
// Not ported yet: xray configs (user's core is sing-box), WARP (runWarp),
// route rules injection.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use tauri::{AppHandle, Emitter};

use crate::logging::log_add;
use crate::models::{VpnProxy, VpnSettings, VpnStatusInfo, VpnTrafficInfo};
use crate::paths;
use crate::store;
use crate::sysproxy;

// ---------- порты ----------

static VPN_LOCAL: AtomicI32 = AtomicI32::new(10808);
static VPN_API: AtomicI32 = AtomicI32::new(19093);

pub fn vpn_local() -> i32 {
    let p = VPN_LOCAL.load(Ordering::Relaxed);
    if p <= 0 || p > 65535 {
        10808
    } else {
        p
    }
}

pub fn vpn_api() -> i32 {
    let p = VPN_API.load(Ordering::Relaxed);
    if p <= 0 || p > 65535 {
        19093
    } else {
        p
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct VpnPortFile {
    local: i32,
    api: i32,
}

pub fn load_vpn_ports(tools: &Path) {
    let Ok(data) = std::fs::read(paths::vpn_ports_path(tools)) else {
        return;
    };
    let Ok(p) = serde_json::from_slice::<VpnPortFile>(&data) else {
        return;
    };
    if p.local > 0 && p.local < 65536 {
        VPN_LOCAL.store(p.local, Ordering::Relaxed);
    }
    if p.api > 0 && p.api < 65536 && p.api != p.local {
        VPN_API.store(p.api, Ordering::Relaxed);
    }
}

pub fn save_vpn_ports(tools: &Path, local: i32, api: i32) {
    if local <= 0 || local > 65535 || api <= 0 || api > 65535 || local == api {
        return;
    }
    let _ = std::fs::create_dir_all(paths::vpn_dir(tools));
    let _ = store::atomic_write_json(&paths::vpn_ports_path(tools), &json!({"local": local, "api": api}));
}

// pickFreePort: «занят/свободен» проверяется реальным bind.
pub fn pick_free_port(preferred: i32) -> i32 {
    if preferred > 0 && preferred < 65536 {
        if let Ok(ln) = std::net::TcpListener::bind(("127.0.0.1", preferred as u16)) {
            drop(ln);
            return preferred;
        }
    }
    std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|ln| ln.local_addr().ok().map(|a| a.port() as i32))
        .filter(|p| *p > 0)
        .unwrap_or(preferred)
}

pub fn choose_vpn_ports(tools: &Path) -> (i32, i32) {
    let local = pick_free_port(10808);
    let mut api = pick_free_port(19093);
    for _ in 0..10 {
        if api != local {
            break;
        }
        api = pick_free_port(0);
    }
    if api == local {
        // совсем маловероятно; не даём двум inbound'ам один порт
        api = if local < 65535 { local + 1 } else { local - 1 };
    }
    VPN_LOCAL.store(local, Ordering::Relaxed);
    VPN_API.store(api, Ordering::Relaxed);
    save_vpn_ports(tools, local, api);
    log_add("core", &format!("порты: mixed 127.0.0.1:{}, API 127.0.0.1:{}", local, api));
    (local, api)
}

pub fn port_open(port: i32) -> bool {
    // без unwrap: невалидный порт — просто «порт не открыт», а не паника потока
    let Ok(addr) = format!("127.0.0.1:{}", port).parse() else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}

// ---------- TUN-интерфейс ----------

// tunInterfaceUp — открыт ли TUN-адаптер с именем этой сессии (FriendlyName).
pub fn tun_interface_up(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH};
    unsafe {
        let mut size: u32 = 0;
        let flags = 0u32;
        let _ = GetAdaptersAddresses(0, flags, std::ptr::null_mut(), std::ptr::null_mut(), &mut size);
        if size == 0 {
            return false;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = GetAdaptersAddresses(
            0,
            flags,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut size,
        );
        if rc != 0 {
            return false;
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
                if s.eq_ignore_ascii_case(name) {
                    return true;
                }
            }
            cur = a.Next;
        }
        false
    }
}

// ---------- лог ядра ----------

// stripAnsi — убрать ANSI-раскраску из лога ядра
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '\u{1b}' {
            // пропускаем до 'm'
            for (_, c2) in chars.by_ref() {
                if c2 == 'm' {
                    break;
                }
            }
        } else {
            let _ = i;
            out.push(c);
        }
    }
    out
}

// lastCoreErrorLine — последняя строка ERROR/FATAL из core_log.txt
pub fn last_core_error_line(tools: &Path) -> String {
    last_error_line_in(&paths::vpn_dir(tools).join("core_log.txt"))
}

// last_error_line_in — последняя строка ERROR/FATAL из указанного лог-файла
// (у ядра TUN-цепочки свой файл: основной core_log.txt позже открывается
// с truncate и затёр бы его вывод).
fn last_error_line_in(path: &Path) -> String {
    let Ok(data) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let s = strip_ansi(&data);
    let mut best = String::new();
    for ln in s.split('\n') {
        let t = ln.trim();
        if t.contains("ERROR") || t.contains("FATAL") {
            best = t.to_string();
        }
    }
    // обрезаем по рунам: срез по байтам резал UTF-8 пополам
    let chars: Vec<char> = best.chars().collect();
    if chars.len() > 220 {
        best = chars[chars.len() - 220..].iter().collect();
    }
    best
}

// ---------- состояние подключения ----------

pub struct ConnInner {
    pub state: crate::models::VpnConnState,
    pub gen: u64,
    pub stop: Option<Arc<AtomicBool>>,
    pub child: Option<std::process::Child>,
    pub child2: Option<std::process::Child>, // второе ядро цепочки xray+TUN
    // stdin WARP-хелпера: закрытие = graceful teardown (маршруты/DNS/адаптер
    // снимаются самим хелпером); TerminateProcess остаётся аварийным путём
    pub child_stdin: Option<std::process::ChildStdin>,
    // дескрипторы Job Object'ов ядер: пока открыты, KILL_ON_JOB_CLOSE держит
    // защиту от сирот; забираются в stop_attempt (ReapedCore) и закрываются
    // Drop'ом после подтверждённого выхода ядер. Значения никогда не
    // читаются — важно только их ЖИВОЕ наличие в inner.
    #[allow(dead_code)]
    pub job: Option<JobHandle>,
    #[allow(dead_code)]
    pub job2: Option<JobHandle>,
    pub tun_name: String,
}

static CORE_PID: AtomicI64 = AtomicI64::new(0);

// поднят ли WARP-туннель (у него нет прокси-порта — живость по флагу)
static WARP_ACTIVE: AtomicBool = AtomicBool::new(false);

// внешний IP текущей сессии (WARP-пробы пишут из фоновых потоков)
static WARP_IP: Mutex<String> = Mutex::new(String::new());

// внешний IPv6 туннеля (пусто — v6-маршрута нет/не ответила проба)
static WARP_IP6: Mutex<String> = Mutex::new(String::new());

pub fn warp_active() -> bool {
    WARP_ACTIVE.load(Ordering::Relaxed)
}

// Вынутые при остановке дескрипторы ядер: владение передаётся из inner
// коротким локом, чтобы ожидания смерти шли без удержания мьютекса.
struct ReapedCore {
    child: Option<std::process::Child>,
    child2: Option<std::process::Child>,
    stdin: Option<std::process::ChildStdin>,
    // значения не читаются: важно, что дескрипторы открыты до конца reap_core
    // (Drop закрывает их после подтверждённого выхода ядер)
    #[allow(dead_code)]
    job: Option<JobHandle>,
    #[allow(dead_code)]
    job2: Option<JobHandle>,
    tun_name: String,
}

pub struct ConnManager {
    tools_dir: OnceLock<PathBuf>,
    pub inner: Mutex<ConnInner>,
}

impl ConnManager {
    pub fn new() -> Self {
        ConnManager {
            tools_dir: OnceLock::new(),
            inner: Mutex::new(ConnInner {
                state: Default::default(),
                gen: 0,
                stop: None,
                child: None,
                child2: None,
                child_stdin: None,
                job: None,
                job2: None,
                tun_name: String::new(),
            }),
        }
    }

    pub fn tools(&self) -> PathBuf {
        self.tools_dir.get_or_init(crate::paths::find_tools_dir).clone()
    }

    pub fn set_vpn_ip(&self, ip: &str) {
        *WARP_IP.lock().unwrap_or_else(|e| e.into_inner()) = ip.to_string();
        // сброс сессии чистит и v6 — все точки очистки v4 собраны тут
        if ip.is_empty() {
            *WARP_IP6.lock().unwrap_or_else(|e| e.into_inner()) = String::new();
        }
    }

    pub fn get_vpn_ip(&self) -> String {
        WARP_IP.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn get_vpn_ip6(&self) -> String {
        WARP_IP6.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn emit_state(app: &AppHandle, st: &crate::models::VpnConnState) {
        let _ = app.emit("vpnState", st);
    }

    // activeID — сервер текущей попытки или активного подключения
    pub fn active_id(&self) -> String {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.state.phase == "starting" || inner.state.phase == "connected" {
            inner.state.server_id.clone()
        } else {
            String::new()
        }
    }

    pub fn is_connected(&self) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).state.phase == "connected"
    }

    fn child_exited(child: &mut Option<std::process::Child>) -> bool {
        match child {
            None => true,
            Some(c) => match c.try_wait() {
                Ok(Some(_)) | Err(_) => true,
                Ok(None) => false,
            },
        }
    }

    // coreDied — умерло ли ядро (для цепочки xray+TUN — ХОТЬ одно из двух).
    // ВАЖНО: child == None означает «этого ядра в конфигурации нет» — это НЕ
    // смерть. Раньше None трактовался как «умерло», и при одиночном ядре
    // (child2 всегда None) core_exited() возвращал true при ЖИВОМ ядре —
    // первая же итерация ожидания порта давала «Ядро не поднялось» на ровном
    // месте, и свежезапущенное ядро гасилось собственным fail_for.
    fn core_exited(&self) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.child.is_none() && inner.child2.is_none() {
            return true; // ядер нет вообще — некому быть живым
        }
        let died = |c: &mut Option<std::process::Child>| match c {
            None => false, // этого ядра нет — не считается умершим
            Some(c) => match c.try_wait() {
                Ok(Some(_)) | Err(_) => true,
                Ok(None) => false,
            },
        };
        died(&mut inner.child) || died(&mut inner.child2)
    }

    // killCoreLocked — гасим ядра, ждём до 2 с фактического выхода, потом
    // исчезновения старого wintun-адаптера (до 8 с). reason — для лога: раньше
    // «остановлено» не говорило, КТО вызвал остановку.
    //
    // ОЖИДАНИЯ БЕЗ МЬЮТЕКСА: раньше вся эта цепочка (6 с graceful + 2 с kill +
    // 8 с TUN) шла под удерживаемым мьютексом ConnInner — Stop/новый Start
    // блокировали vpn_status_impl и ВСЕ команды до ~16 с (UI замирал).
    // Теперь дескрипторы ВЫНИМАЮТСЯ из inner коротким локом (stop_attempt),
    // а ожидания идут в reap_core на уже переданных владелец-хэндлах.
    fn reap_core(&self, mut r: ReapedCore, reason: &str) {
        if r.child.is_some() || r.child2.is_some() {
            // WARP-хелпер гасим ЗАКРЫТИЕМ STDIN: он успевает снять маршруты,
            // DNS и удалить wintun-адаптер (TerminateProcess оставил бы хвосты
            // до следующего запуска — их подчищает cleanupStale хелпера).
            // Не-хелперные ядра (stdin = None) идут старым путём.
            if let Some(sin) = r.stdin.take() {
                drop(sin);
                let gdeadline = Instant::now() + Duration::from_secs(6);
                while Instant::now() < gdeadline {
                    let e1 = Self::child_exited(&mut r.child);
                    let e2 = Self::child_exited(&mut r.child2);
                    if e1 && e2 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            if let Some(child) = r.child.as_mut() {
                let _ = child.kill();
            }
            if let Some(child) = r.child2.as_mut() {
                let _ = child.kill();
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                let e1 = Self::child_exited(&mut r.child);
                let e2 = Self::child_exited(&mut r.child2);
                if e1 && e2 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            log_add("core", &format!("остановлено ({})", reason));
            let tun_name = r.tun_name.clone();
            let iface_deadline = Instant::now() + Duration::from_secs(8);
            while Instant::now() < iface_deadline && tun_interface_up(&tun_name) {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        // Дескрипторы Job закрываются на выходе (Drop): пока соединение живо,
        // они держат KILL_ON_JOB_CLOSE-защиту от сирот; здесь ядра уже вышли,
        // поэтому закрытие не добьёт ничего живого.
    }

    // core_exit_code — код выхода умершего ядра (до kill/wait!): 0 = вышел сам,
    // 1 = TerminateProcess (кто-то убил), 0xC0000005 = нативный краш,
    // None = объект процесса потерян (гонка регистрации) или ещё жив.
    fn core_exit_code(&self) -> Option<i32> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let code = inner
            .child
            .as_mut()
            .and_then(|c| c.try_wait().ok())
            .and_then(|st| st.and_then(|s| s.code()));
        match code {
            Some(c) => Some(c),
            None => inner
                .child2
                .as_mut()
                .and_then(|c| c.try_wait().ok())
                .and_then(|st| st.and_then(|s| s.code())),
        }
    }

// stop_attempt — прерывание попытки + гашение ядер. Прежняя семантика, но
// мьютекс берётся КРАТКО (вынимаем дескрипторы и ставим stop-флаг), а все
// ожидания идут в reap_core БЕЗ лока — иначе stop() блокировал статус/команды.
fn stop_attempt(&self, reason: &str) {
    WARP_ACTIVE.store(false, Ordering::Relaxed);
    let (flag, r) = {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (
            inner.stop.take(),
            ReapedCore {
                child: inner.child.take(),
                child2: inner.child2.take(),
                stdin: inner.child_stdin.take(),
                job: inner.job.take(),
                job2: inner.job2.take(),
                tun_name: inner.tun_name.clone(),
            },
        )
    };
    if let Some(f) = &flag {
        f.store(true, Ordering::Relaxed);
    }
    // ядер больше нет — ссылка на PID больше не имеет смысла (иначе
    // переиспользованный ОС PID засчитывался бы живым чужим процессом)
    CORE_PID.store(0, Ordering::Relaxed);
    self.reap_core(r, reason);
}

// Stop — полное отключение: прерывает попытку, гасит ядро, снимает прокси.
// Генерация инкрементируется ДО ожиданий; после них состояние/прокси трогаем
// только если новая попытка не успела начаться (иначе заглушили бы её настройки).
pub fn stop(&self, app: &AppHandle) {
    let tools = self.tools();
    let my_gen;
    {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.gen += 1;
        my_gen = inner.gen;
    }
    self.stop_attempt("отключение (Stop)");
    let st;
    let still_ours;
    {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        still_ours = inner.gen == my_gen;
        if still_ours {
            inner.state = Default::default();
        }
        st = inner.state.clone();
        Self::emit_state(app, &st); // под мьютексом: события не приходят в обратном порядке
    }
    if still_ours {
        // Прокси и внешний IP снимаем только у СВОЕЙ сессии: если пока шли
        // ожидания успел начаться новый Start — его настройки не трогаем.
        sysproxy::clear_system_proxy(&tools);
        self.set_vpn_ip("");
    }
}

    // Start — асинхронный запуск подключения: возвращает управление сразу,
    // фазы прилетают событием «vpnState». Переключение сервера = рестарт.
    pub fn start(
        self: Arc<Self>,
        app: AppHandle,
        p: VpnProxy,
        core: String,
        st: VpnSettings,
        force: bool,
    ) -> (bool, String) {
        {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.state.phase == "starting" {
                return (false, "⏳ Уже идёт подключение — подожди".to_string());
            }
            // WDTT-туннель поднимает свой TUN с auto_route: маршруты у туннелей
            // общие, два TUN одновременно дерутся за дефолтный маршрут. Раньше
            // проверка была только в обратную сторону (pwdtt останавливает VPN
            // при старте), а старт VPN при живом WDTT молча ломал маршруты.
            if crate::wdtt_session::running() {
                return (
                    false,
                    "⚠️ Сначала отключи WDTT-туннель — маршруты у туннелей общие".to_string(),
                );
            }
            // CSQTT — ещё один TUN-туннель со своими split-маршрутами: та же
            // проблема драки за дефолтный маршрут
            if crate::cqstt_session::running() {
                return (
                    false,
                    "⚠️ Сначала отключи CSQTT-туннель — маршруты у туннелей общие".to_string(),
                );
            }
        }
        let (was_active, my_gen) = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            (
                inner.state.phase == "connected" || inner.state.phase == "starting",
                inner.gen + 1,
            )
        };
        // Гасим предыдущую попытку/подключение: ожидания смерти ядер идут БЕЗ
        // лока (см. stop_attempt), потом коротким локом регистрируем новую.
        self.stop_attempt("новое подключение (смена сервера/повтор)");
        let flag;
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.gen != my_gen - 1 {
                // Пока шли ожидания гашения, началась другая операция
                // (Stop / ещё один Start) — не перебиваем её.
                return (false, "⏳ Идёт другая операция — попробуй ещё раз".to_string());
            }
            inner.gen = my_gen;
            // При переключении сервера старый системный прокси указывает на
            // уже убитый порт — снимаем его до выбора новых портов.
            if was_active {
                let tools = self.tools();
                sysproxy::clear_system_proxy(&tools);
            }
            flag = Arc::new(AtomicBool::new(false));
            inner.stop = Some(flag.clone());
            inner.state = crate::models::VpnConnState {
                phase: "starting".into(),
                step: String::new(),
                error: String::new(),
                server_id: p.id.clone(),
                server_name: p.name.clone(),
                since: 0,
                ..Default::default()
            };
            self.set_vpn_ip("");
            let st2 = inner.state.clone();
            Self::emit_state(&app, &st2);
        }
        std::thread::spawn(move || {
            self.run(&app, p, core, st, flag, force);
        });
        (true, String::new())
    }

    fn interrupted(flag: &Arc<AtomicBool>) -> bool {
        flag.load(Ordering::Relaxed)
    }

    fn same_attempt(inner: &ConnInner, flag: &Arc<AtomicBool>) -> bool {
        inner.state.phase == "starting"
            && inner.stop.as_ref().map(|f| Arc::ptr_eq(f, flag)).unwrap_or(false)
    }

    fn set_step_for(&self, app: &AppHandle, flag: &Arc<AtomicBool>, step: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !Self::same_attempt(&inner, flag) {
            return; // попытку уже отменили или заменили новой
        }
        inner.state.step = step.to_string();
        let st = inner.state.clone();
        Self::emit_state(app, &st);
    }

    // failFor — попытка не удалась: гасим ядро, публикуем фазу failed.
    fn fail_for(&self, app: &AppHandle, flag: &Arc<AtomicBool>, msg: &str) {
        self.fail_for_opt(app, flag, msg, false);
    }

    // fail_for_opt — вариант с canForce: true для «Сервер недоступен» на пробе
    // трафика (сервер жив, но проверку не прошёл) — там UI даёт кнопку
    // «Всё равно подключиться»; остальные ошибки — фатальные, кнопки нет.
    fn fail_for_opt(&self, app: &AppHandle, flag: &Arc<AtomicBool>, msg: &str, can_force: bool) {
        let tools = self.tools();
        // Проверка «та же попытка» под коротким локом; сами ожидания гашения
        // (stop_attempt) идут без лока.
        let gen0 = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !Self::same_attempt(&inner, flag) {
                return;
            }
            inner.gen
        };
        self.stop_attempt("попытка не удалась");
        sysproxy::clear_system_proxy(&tools);
        self.set_vpn_ip("");
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.gen != gen0 {
            // Пока гасили ядра, началась новая попытка — её состояние не трогаем.
            return;
        }
        inner.state.phase = "failed".into();
        inner.state.step = format!("❌ {}", msg);
        inner.state.error = msg.to_string();
        inner.state.can_force = can_force;
        let st = inner.state.clone();
        Self::emit_state(app, &st);
    }

    // run — тело подключения: конфиг → запуск ядра → порт → TUN → проба трафика.
    // force=true — подключиться без пробы трафика (кнопка «Всё равно
    // подключиться» после «Сервер недоступен» на прошлой попытке).
    fn run(&self, app: &AppHandle, p: VpnProxy, core: String, st: VpnSettings, flag: Arc<AtomicBool>, force: bool) {
        let tools = self.tools();
        if p.proto == "warp" {
            self.run_warp(app, &p, &flag);
            return;
        }
        // Попытку могли отменить ещё до записи конфига (Stop сразу после Start).
        {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !Self::same_attempt(&inner, &flag) {
                return;
            }
        }
        // 10808/19093 — только предпочтение: занято — берём свободный.
        let (local_port, api_port) = choose_vpn_ports(&tools);
        // Свой конфиг на каждую попытку: старый run не должен перезаписать
        // конфиг нового.
        let base_cfg = paths::vpn_config_path_for(&tools, &core);
        let ext = base_cfg
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        let stem = base_cfg
            .with_extension("")
            .to_string_lossy()
            .to_string();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let cfg_path = PathBuf::from(format!("{}-{}{}", stem, nanos, ext));
        let _cfg_guard = CfgCleanup(cfg_path.clone());
        // уникальное имя TUN-адаптера на сессию: зомби-адаптер прошлой сессии
        // не помешает новому инстансу
        let tun_name = if st.tun {
            let n = format!("sentor{:x}", nanos % 0xffffffff);
            self.inner.lock().unwrap_or_else(|e| e.into_inner()).tun_name = n.clone();
            n
        } else {
            String::new()
        };
        let args: Vec<PathBuf>;
        let mut core_label = core.clone();
        let mut main_core = core.clone();
        if core == "xray" && st.tun {
            // Цепочка ради TUN: xray с SOCKS-инбаундом на свободном порту,
            // sing-box — TUN-фронтом, который забирает весь трафик и заворачивает
            // его в этот порт. Адрес сервера резолвим заранее и исключаем из
            // туннеля прямым правилом — иначе соединение xray к серверу
            // захватывалось бы TUN и уходило по кругу.
            self.set_step_for(app, &flag, "⏳ Резолвлю адрес сервера…");
            let server_ip = match resolve_server_ip(&p.host) {
                Some(ip) => ip,
                None => {
                    self.fail_for(app, &flag, &format!("TUN-цепочка: не удалось резолвить адрес сервера {}", p.host));
                    return;
                }
            };
            let x_port = pick_free_port(0);
            let x_cfg = PathBuf::from(format!("{}-xray-{}{}", stem, nanos, ext));
            let mut px = p.clone();
            px.host = server_ip.clone(); // xray ходит строго на IP — свой DNS не нужен
            // Подмена адреса не должна менять SNI/Host: у ключей без явного sni
            // они берутся из адреса сервера — голый IP сервер отвергает
            {
                let has_sni = px.extra.as_ref().and_then(|e| e.get("sni")).map(|s| !s.is_empty()).unwrap_or(false);
                let has_host = px.extra.as_ref().and_then(|e| e.get("host")).map(|s| !s.is_empty()).unwrap_or(false);
                if !has_sni && !has_host {
                    px.extra.get_or_insert_with(std::collections::HashMap::new).insert("sni".into(), p.host.clone());
                }
            }
            if let Err(e) = crate::vpnconfig::build_xray_chain_config(&tools, &px, x_port, &x_cfg) {
                self.fail_for(app, &flag, &e);
                return;
            }
            let _xcfg_guard = CfgCleanup(x_cfg.clone());
            self.set_step_for(app, &flag, "⏳ Запускаю ядро xray…");
            log_add("core", &format!("запуск xray · сервер {} (TUN-цепочка)", p.name));
            {
                let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if !Self::same_attempt(&inner, &flag) || Self::interrupted(&flag) {
                    return;
                }
            }
            let xray_exe = paths::vpn_core_exe_for(&tools, "xray");
            let mut xcmd = std::process::Command::new(&xray_exe);
            xcmd.args(["run", "-c"]).arg(&x_cfg).current_dir(paths::vpn_core_dir(&tools));
            use std::os::windows::process::CommandExt;
            xcmd.creation_flags(0x08000000);
            xcmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
            let mut xchild = match xcmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    self.fail_for(app, &flag, &format!("xray (TUN-цепочка) не запустился: {}", e));
                    return;
                }
            };
            // Лог ядра цепочки — в ОТДЕЛЬНЫЙ файл: основной core_log.txt
            // открывается позже (с truncate) под sing-box и затёр бы вывод
            // xray; без файла ошибки цепочки показывали чужую прошлую строку
            let xlog_path = paths::vpn_dir(&tools).join("core_log_xray.txt");
            let xlog_file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&xlog_path)
                .ok();
            let xlog = Arc::new(Mutex::new(xlog_file));
            if let Some(out) = xchild.stdout.take() {
                let lc = xlog.clone();
                std::thread::spawn(move || stream_core_output(out, lc));
            }
            if let Some(err) = xchild.stderr.take() {
                let lc = xlog.clone();
                std::thread::spawn(move || stream_core_output(err, lc));
            }
            let xjob = new_kill_on_close_job();
            if let Some(job) = &xjob {
                job.attach(xchild.id());
            }
            {
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if Self::same_attempt(&inner, &flag) {
                    inner.child2 = Some(xchild);
                    inner.job2 = xjob;
                } else {
                    // Stop/новый Start попал в окно между spawn и регистрацией:
                    // гасим свежий процесс сами, чтобы живой xray не утёк
                    // (Stop уже отработал и не видел этот child). Дескриптор Job
                    // закрывается вместе с локальной переменной — после kill+wait.
                    let mut xchild = xchild;
                    let _ = xchild.kill();
                    let _ = xchild.wait();
                }
            }
            self.set_step_for(app, &flag, "⏳ Жду порт xray…");
            let mut x_up = false;
            for _ in 0..20 {
                if Self::interrupted(&flag) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(300));
                if self.core_exited() {
                    self.fail_for(app, &flag, &format!("xray (TUN-цепочка) не поднялся: {}", last_error_line_in(&xlog_path)));
                    return;
                }
                if port_open(x_port) {
                    x_up = true;
                    break;
                }
            }
            if !x_up {
                if self.core_exited() {
                    self.fail_for(app, &flag, &format!("xray (TUN-цепочка) не поднялся: {}", last_error_line_in(&xlog_path)));
                } else {
                    self.fail_for(app, &flag, "xray (TUN-цепочка) запущен, но порт не отвечает — проверь параметры ключа");
                }
                return;
            }
            if let Err(e) = crate::vpnconfig::write_chain_tun_config(&tools, &server_ip, x_port, local_port, api_port, &cfg_path, &tun_name) {
                self.fail_for(app, &flag, &e);
                return;
            }
            args = vec![PathBuf::from("run"), PathBuf::from("-c"), cfg_path.clone()];
            core_label = "xray+TUN".into();
            main_core = "sing-box".into();
        } else {
            match core.as_str() {
                "sing-box" => {
                    if let Err(e) = crate::vpnconfig::write_vpn_config(&tools, &p, local_port, st.tun, st.tun, &cfg_path, api_port, &tun_name) {
                        self.fail_for(app, &flag, &e);
                        return;
                    }
                }
                "xray" => {
                    if let Err(e) = crate::vpnconfig::build_xray_config(&tools, &p, local_port, &cfg_path, true) {
                        self.fail_for(app, &flag, &e);
                        return;
                    }
                }
                _ => {}
            }
            args = vec![PathBuf::from("run"), PathBuf::from("-c"), cfg_path.clone()];
        }
        // конфиг записан ровно один раз, в формате выбранного ядра
        self.set_step_for(app, &flag, &format!("⏳ Запускаю ядро {}…", core_label));
        {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !Self::same_attempt(&inner, &flag) || Self::interrupted(&flag) {
                return; // попытку уже отменили — уборку сделает Stop
            }
        }
        log_add("core", &format!("запуск {} · сервер {}", core_label, p.name));
        let exe = paths::vpn_core_exe_for(&tools, &main_core);
        // лог ядра — в файл + строки в общий буфер логов
        let log_path = paths::vpn_dir(&tools).join("core_log.txt");
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&log_path)
            .ok();
        let log_file: Arc<Mutex<Option<std::fs::File>>> = Arc::new(Mutex::new(log_file));
        let mut cmd = std::process::Command::new(&exe);
        cmd.args(&args).current_dir(paths::vpn_core_dir(&tools));
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                *log_file.lock().unwrap_or_else(|e| e.into_inner()) = None;
                self.fail_for(app, &flag, &format!("Ядро не запустилось: {}", e));
                return;
            }
        };
        CORE_PID.store(child.id() as i64, Ordering::Relaxed);
        // stdout/stderr → файл + общий лог
        let log_clone = log_file.clone();
        if let Some(out) = child.stdout.take() {
            let lc = log_clone.clone();
            std::thread::spawn(move || stream_core_output(out, lc));
        }
        if let Some(err) = child.stderr.take() {
            let lc = log_clone.clone();
            std::thread::spawn(move || stream_core_output(err, lc));
        }
        // Job Object с KILL_ON_JOB_CLOSE: ядра-сироты умирают при крахе/kill
        // Sentor. Дескриптор хранится в inner рядом с child и закрывается в
        // kill_core после подтверждённого выхода ядра (закрытие раньше времени
        // добило бы живое ядро).
        let job = new_kill_on_close_job();
        if let Some(job) = &job {
            job.attach(child.id());
        }
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if Self::same_attempt(&inner, &flag) {
                inner.child = Some(child);
                inner.job = job;
            } else {
                // Stop/новый Start попал в окно между spawn и регистрацией:
                // гасим свежий процесс сами, чтобы живое ядро с TUN auto_route
                // не утекло (Stop уже отработал и не видел этот child).
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        // 1) ждём HTTP/SOCKS порт (mixed)
        self.set_step_for(app, &flag, "⏳ Жду порт ядра…");
        let mut port_up = false;
        for _ in 0..20 {
            if Self::interrupted(&flag) {
                return; // Stop / новый Start уже всё погасили
            }
            std::thread::sleep(Duration::from_millis(300));
            if self.core_exited() {
                let last = last_core_error_line(&tools);
                // код выхода ДО kill/wait: 0 = вышел сам, 1 = убили TerminateProcess,
                // 0xC0000005 = нативный краш, None = объект процесса потерян
                let code = self.core_exit_code();
                log_add("core", &format!("ядро умерло до подъёма порта: код выхода {:?}", code));
                if last.is_empty() {
                    // ядро завершилось без единой строки в логе (нативная смерть
                    // до/во время поднятия инбаундов) — сохраняем конфиг попытки:
                    // без него «молчаливая» смерть не разбирается вообще
                    let diag = paths::vpn_dir(&tools).join("config_failed_core.json");
                    let _ = std::fs::copy(&cfg_path, &diag);
                    log_add("core", "ядро завершилось без вывода — конфиг попытки сохранён в vpn/config_failed_core.json");
                }
                self.fail_for(app, &flag, &format!("Ядро не поднялось: {}", last));
                return;
            }
            if port_open(local_port) {
                port_up = true;
                break;
            }
        }
        if !port_up {
            if self.core_exited() {
                self.fail_for(app, &flag, &format!("Ядро не поднялось: {}", last_core_error_line(&tools)));
            } else {
                self.fail_for(
                    app,
                    &flag,
                    "Ядро запущено, но порт не отвечает — проверь параметры сервера (UUID/пароль/SNI)",
                );
            }
            return;
        }
        // 2) в TUN-режиме ждём реального открытия интерфейса до 15 с
        if st.tun {
            self.set_step_for(app, &flag, "⏳ Поднимаю TUN-интерфейс…");
            let mut iface_up = false;
            for _ in 0..100 {
                if Self::interrupted(&flag) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(150));
                if self.core_exited() {
                    break;
                }
                if tun_interface_up(&tun_name) {
                    iface_up = true;
                    break;
                }
            }
            if self.core_exited() {
                let last = last_core_error_line(&tools);
                let code = self.core_exit_code();
                log_add("core", &format!("ядро умерло при открытии TUN: код выхода {:?}", code));
                if last.is_empty() {
                    // смерть при открытии TUN без вывода — конфиг попытки в диагностику
                    let diag = paths::vpn_dir(&tools).join("config_failed_core.json");
                    let _ = std::fs::copy(&cfg_path, &diag);
                    log_add("core", "ядро упало при открытии TUN без вывода — конфиг попытки сохранён в vpn/config_failed_core.json");
                }
                self.fail_for(app, &flag, &format!("Ядро упало при открытии TUN: {}", last));
                return;
            }
            if !iface_up {
                self.fail_for(
                    app,
                    &flag,
                    "TUN-интерфейс не открылся за 15 секунд (wintun заклинило). Перезагрузи ПК или включи «Системный прокси» вместо TUN",
                );
                return;
            }
        }
        // 3) честная проверка трафика через прокси (force — без проверки:
        // пользователь уже увидел «Сервер недоступен» и нажал кнопку)
        let (_ok, probe_ms, _probe_reason) = if force {
            self.set_step_for(app, &flag, "⏳ Подключаюсь без проверки трафика…");
            (true, 0, String::new())
        } else {
            self.set_step_for(app, &flag, "⏳ Проверяю трафик через туннель…");
            let r = vpn_probe_through_proxy(local_port);
            if !r.0 {
                self.fail_for_opt(
                    app,
                    &flag,
                    &format!("Сервер недоступен: {} — прогони «Проверить» и выбери рабочий ключ", r.2),
                    true, // сервер поднялся, проверка не прошла — даём «Всё равно подключиться»
                );
                return;
            }
            r
        };
        if Self::interrupted(&flag) {
            return;
        }
        let mut msg = format!("✅ Подключено: {} [{}]", p.name, core_label);
        if force {
            msg += " · проверка трафика пропущена (принудительное подключение)";
        } else if probe_ms > 4000 {
            msg += &format!(" ⚠️ туннель очень медленный ({} мс) — сервер перегружен или душится, попробуй другой ключ", probe_ms);
        }
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !Self::same_attempt(&inner, &flag) {
                return; // отменено/заменено между пробой и фиксацией
            }
            // Настройки читаем под мьютексом: пользователь мог выключить тумблер
            let sys_proxy = store::load_vpn_settings(&tools).system_proxy;
            if sys_proxy {
                if !sysproxy::set_system_proxy(&tools, &format!("127.0.0.1:{}", local_port)) {
                    // false — запись в реестр не прошла (права/политики): без
                    // предупреждения UI показал бы «Подключено», а трафик
                    // программ шёл бы мимо туннеля
                    msg += " ⚠️ системный прокси включить не удалось (реестр/политики)";
                }
            } else if !st.tun {
                msg += &format!(
                    " — порт 127.0.0.1:{}; чтобы трафик программ шёл через VPN, включи «Системный прокси» или «TUN»",
                    local_port
                );
            }
            inner.state.phase = "connected".into();
            inner.state.step = msg;
            inner.state.error = String::new();
            inner.state.since = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let st2 = inner.state.clone();
            Self::emit_state(app, &st2);
        }
        // вотчдог: ядро умерло при живом соединении — сообщаем UI сразу
        loop {
            std::thread::sleep(Duration::from_secs(2));
            if Self::interrupted(&flag) {
                return;
            }
            if self.core_exited() {
                let tools = self.tools();
                // Снимок «наша сессия ещё активна» под коротким локом; сами
                // ожидания гашения идут без лока.
                let gen0 = {
                    let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    if !(inner.state.phase == "connected"
                        && inner.state.server_id == p.id
                        && inner.stop.as_ref().map(|f| Arc::ptr_eq(f, &flag)).unwrap_or(false))
                    {
                        return;
                    }
                    inner.gen
                };
                self.stop_attempt("вотчдог: ядро умерло при живом соединении");
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if inner.gen != gen0 {
                    return;
                }
                inner.state = crate::models::VpnConnState {
                    phase: "idle".into(),
                    step: String::new(),
                    error: String::new(),
                    server_id: p.id.clone(),
                    server_name: p.name.clone(),
                    since: 0,
                    ..Default::default()
                };
                sysproxy::clear_system_proxy(&tools);
                self.set_vpn_ip("");
                let st2 = inner.state.clone();
                Self::emit_state(app, &st2);
                drop(inner);
                let _ = app.emit("vpnDied", &p.id);
                return;
            }
        }
    }
}

// Резолв адреса сервера: предпочитаем IPv4, иначе первый (как ip4→ip6 в Go).
fn resolve_server_ip(host: &str) -> Option<String> {
    use std::net::{IpAddr, ToSocketAddrs};
    let h = host.trim();
    // IP-литералы (в т.ч. [v6] со скобками) — без DNS: раньше «v6:0»
    // («2001:db8::1:0») был невалиден, и TUN-цепочка для v6-хостов всегда
    // падала с «не удалось резолвить»
    let literal = h.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    let addrs: Vec<std::net::SocketAddr> = format!("{}:0", h).to_socket_addrs().ok()?.collect();
    if let Some(a) = addrs.iter().find(|a| a.is_ipv4()) {
        return Some(a.ip().to_string());
    }
    addrs.first().map(|a| a.ip().to_string())
}

// стримим stdout/stderr ядра: строки → файл + общий лог-буфер
fn stream_core_output<R: Read>(mut stream: R, log_file: Arc<Mutex<Option<std::fs::File>>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=pos).collect();
                    let line = String::from_utf8_lossy(&line[..line.len() - 1]);
                    let line = strip_ansi(line.trim_end_matches('\r'));
                    if line.trim().is_empty() {
                        continue;
                    }
                    log_add("core", &line);
                    if let Some(f) = log_file.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
                        let _ = writeln!(f, "{}", line);
                    }
                }
                // нет перевода строки, но буфер распух — сбросим
                if buf.len() > 8000 {
                    let line = String::from_utf8_lossy(&buf);
                    log_add("core", &strip_ansi(&line));
                    buf.clear();
                }
            }
            Err(_) => break,
        }
    }
    if !buf.is_empty() {
        let line = String::from_utf8_lossy(&buf);
        log_add("core", &strip_ansi(line.trim_end_matches('\r')));
        if let Some(f) = log_file.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            let _ = writeln!(f, "{}", String::from_utf8_lossy(&buf));
        }
    }
}

// файл конфига попытки удаляется при выходе (Go: defer os.Remove)
struct CfgCleanup(PathBuf);
impl Drop for CfgCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ---------- Job Object ----------

// JobHandle — HANDLE Job Object'а с KILL_ON_JOB_CLOSE. Сырой HANDLE не
// Send/Sync (а AppState обязан ими быть), поэтому заворачиваем. Drop закрывает
// дескриптор: пока дескриптор открыт, Job жив и ядро-сирота умрёт при крахе
// Sentor. Закрывать раньше смерти процесса нельзя — KILL_ON_JOB_CLOSE добил
// бы живое ядро, поэтому хендлы лежат в ConnInner/WgInner и снимаются только
// в kill_core/teardown после остановки.
pub struct JobHandle(windows_sys::Win32::Foundation::HANDLE);
// HANDLE — непрозрачный указатель ядра; CloseHandle/WaitForSingleObject
// потокобезопасны, передача между потоками допустима.
unsafe impl Send for JobHandle {}
unsafe impl Sync for JobHandle {}

impl JobHandle {
    pub fn attach(&self, pid: u32) {
        attach_to_job(self.0, pid);
    }
}

impl Drop for JobHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

pub fn new_kill_on_close_job() -> Option<JobHandle> {
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return None;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let rc = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if rc == 0 {
            let _ = windows_sys::Win32::Foundation::CloseHandle(job);
            return None;
        }
        Some(JobHandle(job))
    }
}

pub fn attach_to_job(job: windows_sys::Win32::Foundation::HANDLE, pid: u32) {
    use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
    };
    unsafe {
        let h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            log_add("core", "не удалось открыть процесс для Job Object");
            return;
        }
        if AssignProcessToJobObject(job, h) == 0 {
            log_add("core", "не удалось привязать ядро к Job Object");
        }
        windows_sys::Win32::Foundation::CloseHandle(h);
    }
}

// ---------- проба трафика ----------

// Как в Throne (URLTest холодного конфига дважды): первый запрос через
// непрогретое ядро часто падает — пробуем несколько раз. Возвращает задержку.
pub fn vpn_probe_through_proxy(local_port: i32) -> (bool, i64, String) {
    if !port_open(local_port) {
        return (false, 0, "локальный порт ядра не отвечает".into());
    }
    let proxy = format!("http://127.0.0.1:{}", local_port);
    let Ok(proxy_url) = reqwest::Proxy::all(&proxy) else {
        return (false, 0, "не удалось настроить прокси-клиент".into());
    };
    let client = match reqwest::blocking::Client::builder()
        .proxy(proxy_url)
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => return (false, 0, e.to_string()),
    };
    // HTTPS-проба отдельным клиентом: TLS-рукопожатие через непрогретый туннель
    // часто идёт дольше 5 с — на живом ключе получали ложное «Сервер
    // недоступен». Таймаут 10 с; ретраи ниже.
    let px_https = match reqwest::Proxy::all(&proxy) {
        Ok(px) => px,
        Err(e) => return (false, 0, e.to_string()),
    };
    let https_client = match reqwest::blocking::Client::builder()
        .proxy(px_https)
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => client.clone(), // не собрались — пробуем обычным 5-сек клиентом
    };
    let mut reason = String::new();
    for _ in 0..3 {
        let t0 = Instant::now();
        let resp = client.get("http://www.gstatic.com/generate_204").send();
        match resp {
            Ok(r) => {
                let ms = t0.elapsed().as_millis() as i64;
                let status = r.status().as_u16();
                // одиночный 204 проскакивает даже на умирающем канале —
                // проверяем HTTPS и нагрузкой
                // HTTPS с ретраями: одиночный провал на холодном туннеле —
                // не повод хоронить живой ключ. Заглушка/хайджек (HTTP >=400)
                // ретраями не лечится — падаем сразу.
                let mut https_err = String::new();
                let mut https_ok = false;
                for _ in 0..3 {
                    match https_client.get("https://www.google.com/generate_204").send() {
                        Ok(r2) => {
                            let st2 = r2.status().as_u16();
                            if st2 >= 400 {
                                return (
                                    false,
                                    0,
                                    format!("HTTPS через туннель вернул HTTP {} (заглушка/хайджек?)", st2),
                                );
                            }
                            https_ok = true;
                            break;
                        }
                        Err(e) => {
                            https_err = format!("HTTPS через туннель не прошёл: {}", e);
                            std::thread::sleep(Duration::from_millis(400));
                        }
                    }
                }
                if !https_ok {
                    return (false, 0, https_err);
                }
                let _ = status;
                let (n, secs) = throughput_stress(&client, 6, 256 * 1024, Duration::from_secs(8));
                if n < 512 * 1024 {
                    return (
                        false,
                        0,
                        format!("канал не тянет нагрузку: {} КБ за {:.1} с — ключ «отвечает, но не качает»", n / 1024, secs),
                    );
                }
                return (true, ms, String::new());
            }
            Err(e) => {
                reason = format!("туннель не отвечает: {}", e);
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    (false, 0, reason)
}

// throughputStress — стресс-проверка канала под нагрузкой: workers параллельных
// докачек через один и тот же прокси.
pub fn throughput_stress(client: &reqwest::blocking::Client, workers: usize, per_worker: u64, deadline: Duration) -> (u64, f64) {
    use std::sync::atomic::AtomicU64;
    let total = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..workers {
        let client = client.clone();
        let total = total.clone();
        handles.push(std::thread::spawn(move || {
            let deadline_t = Instant::now() + deadline;
            while Instant::now() < deadline_t {
                let resp = client.get("https://speed.cloudflare.com/__down?bytes=262144").send();
                match resp {
                    Ok(r) => {
                        let n = r
                            .bytes()
                            .map(|b| b.len().min(per_worker as usize) as u64)
                            .unwrap_or(0);
                        total.fetch_add(n, Ordering::Relaxed);
                        // качаем следующий чанк до дедлайна: раньше обе ветки
                        // match делали break — «цикл» жил ровно одну итерацию
                        if n == 0 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    (total.load(Ordering::Relaxed), start.elapsed().as_secs_f64())
}

// ---------- живость ядра и статус ----------

// vpnProcessAlive — WaitForSingleObject с нулевым таймаутом (нужен SYNCHRONIZE).
pub fn vpn_process_alive(pid: i64) -> bool {
    if pid <= 0 {
        return false;
    }
    use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid as u32);
        if h.is_null() {
            return false;
        }
        let ev = WaitForSingleObject(h, 0);
        windows_sys::Win32::Foundation::CloseHandle(h);
        ev == WAIT_TIMEOUT
    }
}

pub fn vpn_core_alive() -> bool {
    // WARP-режим: чистый TUN без локального прокси-порта — port_open() тут
    // всегда false, и страховка статуса убивала живое ядро через ~3 c после
    // «connected». Живость = жив процесс, запущенный нами (WARP_ACTIVE
    // ставится в run_warp и снимается в stop_attempt).
    if WARP_ACTIVE.load(Ordering::Relaxed) {
        let pid = CORE_PID.load(Ordering::Relaxed);
        return pid > 0 && vpn_process_alive(pid);
    }
    // проверяем живость ИМЕННО запущенного нами процесса: чужой слушатель на
    // нашем порту (v2rayN/clash любят тот же 10808) не считается «нашим ядром»
    let pid = CORE_PID.load(Ordering::Relaxed);
    if pid > 0 {
        if !vpn_process_alive(pid) {
            return false;
        }
        if port_open(vpn_local()) {
            return true;
        }
        // Транзиентный отказ connect (ядро под нагрузкой, таймаут 300 мс)
        // раньше гасил живую сессию «страховкой статуса»: вторая попытка
        // прежде чем объявлять ядро мёртвым.
        std::thread::sleep(Duration::from_millis(250));
        return port_open(vpn_local());
    }
    port_open(vpn_local())
}

// VpnStatus — со страховкой от падения вотчдога и защитой по поколению.
pub fn vpn_status_impl(mgr: &Arc<ConnManager>, app: &AppHandle) -> VpnStatusInfo {
    let tools = mgr.tools();
    let (ph, gen) = {
        let inner = mgr.inner.lock().unwrap_or_else(|e| e.into_inner());
        (inner.state.clone(), inner.gen)
    };
    let mut running = ph.phase == "connected" && vpn_core_alive();
    if ph.phase == "connected" && running {
        let inner = mgr.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.gen != gen {
            // Порт мог ответить от старого ядра, пока уже началась новая попытка
            drop(inner);
            let (ph2, gen2) = {
                let i = mgr.inner.lock().unwrap_or_else(|e| e.into_inner());
                (i.state.clone(), i.gen)
            };
            running = ph2.phase == "connected" && vpn_core_alive();
            return finish_status(mgr, &tools, app, ph2, gen2, running);
        }
    }
    finish_status(mgr, &tools, app, ph, gen, running)
}

fn finish_status(
    mgr: &Arc<ConnManager>,
    tools: &Path,
    app: &AppHandle,
    ph: crate::models::VpnConnState,
    gen: u64,
    mut running: bool,
) -> VpnStatusInfo {
    let mut ph = ph;
    if ph.phase == "connected" && !running {
        // страховка от падения вотчдога: фаза жива, а ядра нет — прибираемся
        let cleanup = {
            let inner = mgr.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.gen == gen && inner.state.phase == "connected" && inner.state.server_id == ph.server_id
        };
        if cleanup {
            // Ожидания гашения — без лока (см. stop_attempt): ядра уже мертвы,
            // так что это быстро, но даже их нельзя держать под мьютексом
            // статуса — опрос UI заблокировался бы.
            mgr.stop_attempt("страховка статуса: фаза жива, ядро мертво");
            let mut inner = mgr.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.gen == gen {
                inner.state = crate::models::VpnConnState {
                    phase: "idle".into(),
                    step: String::new(),
                    error: String::new(),
                    server_id: ph.server_id.clone(),
                    server_name: ph.server_name.clone(),
                    since: 0,
                    ..Default::default()
                };
                sysproxy::clear_system_proxy(tools);
                mgr.set_vpn_ip("");
            }
            ph = inner.state.clone();
            let st = ph.clone();
            ConnManager::emit_state(app, &st);
            drop(inner);
        } else {
            // Пока проверяли порт, началась другая попытка/подключение:
            // возвращаем актуальное состояние, ничего не трогая.
            let inner = mgr.inner.lock().unwrap_or_else(|e| e.into_inner());
            ph = inner.state.clone();
            drop(inner);
            running = ph.phase == "connected" && vpn_core_alive();
        }
    }
    VpnStatusInfo {
        running,
        active_id: ph.server_id.clone(),
        active_name: ph.server_name.clone(),
        port: vpn_local(),
        core_installed: paths::vpn_core_exe_for(tools, &store::load_vpn_settings(tools).core).exists(),
        system_proxy_on: sysproxy::system_proxy_enabled(),
        ip: if running { mgr.get_vpn_ip() } else { String::new() },
        ip6: if running { mgr.get_vpn_ip6() } else { String::new() },
        since: if running { ph.since } else { 0 },
        adsdns_running: crate::adsdns::adsdns_running(tools),
    }
}

// VpnTraffic — суммарные байты через ядро (GET /connections clash-API).
pub fn vpn_traffic_impl(connected: bool) -> VpnTrafficInfo {
    if !connected {
        return VpnTrafficInfo::default();
    }
    let url = format!("http://127.0.0.1:{}/connections", vpn_api());
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(_) => return VpnTrafficInfo::default(),
    };
    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(_) => return VpnTrafficInfo::default(),
    };
    if resp.status().as_u16() != 200 {
        // не-200 от чужой заглушки не должен давать фальшивые счётчики
        return VpnTrafficInfo::default();
    }
    let Ok(v) = resp.json::<serde_json::Value>() else {
        return VpnTrafficInfo::default();
    };
    VpnTrafficInfo {
        down: v.get("downloadTotal").and_then(|x| x.as_u64()).unwrap_or(0),
        up: v.get("uploadTotal").and_then(|x| x.as_u64()).unwrap_or(0),
    }
}

// runWarp — тело подключения WARP/AmneziaWG через хелпер SentorWarp.exe
// (amneziawg-go: полная AWG-обфускация, wintun + адрес/DNS/маршруты внутри
// хелпера), 1.5 с на handshake, затем фоновая
// проба (cloudflare trace) и периодический ре-проб каждые 30 с.
impl ConnManager {
    fn run_warp(&self, app: &AppHandle, p: &VpnProxy, flag: &Arc<AtomicBool>) {
        let tools = self.tools();
        {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !Self::same_attempt(&inner, flag) {
                return; // отменена до подъёма туннеля
            }
        }
        self.set_step_for(app, flag, "⏳ Поднимаю AmneziaWG-туннель…");
        let conf = {
            let raw = p.raw.trim();
            if !raw.is_empty() {
                raw.to_string()
            } else {
                crate::vpnconfig::vpn_extra(p, "conf", "")
            }
        };
        if conf.is_empty() {
            self.fail_for(app, flag, "AmneziaWG: в конфиге сервера нет текста");
            return;
        }
        // Ранняя валидация конфига (те же ошибки, что и раньше, — до запуска ядра)
        if let Err(e) = crate::warp::parse_warp_config(&conf) {
            self.fail_for(app, flag, &format!("AmneziaWG: {}", e));
            return;
        }
        let cfg_path = paths::vpn_dir(&tools).join("config_warp.conf");
        if let Err(e) = std::fs::write(&cfg_path, conf.as_bytes()) {
            self.fail_for(app, flag, &format!("AmneziaWG: запись конфига: {}", e));
            return;
        }
        // Конфиг содержит приватный ключ WARP: удаляется при выходе из run
        // (stop/fail/вотчдог) — раньше оставался на диске до следующего запуска
        let _cfg_guard = CfgCleanup(cfg_path.clone());
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !Self::same_attempt(&inner, flag) {
                return;
            }
            inner.tun_name = crate::warp::WARP_IFACE.to_string();
        }
        // Ядро WARP — SentorWarp.exe (amneziawg-go, вынесенный в
        // процесс): sing-box 1.14 выпилил AWG-обфускацию, а без неё DPI оператора
        // режет голый WG-handshake. Хелпер применяет конфиг как есть (Jc/S/H/I1),
        // сам поднимает wintun-адаптер, адрес, DNS и маршруты.
        if let Err(e) = crate::tools::ensure_warp_helper(&tools) {
            self.fail_for(app, flag, &format!("AmneziaWG: {}", e));
            return;
        }
        let exe = paths::vpn_core_dir(&tools).join(paths::WARP_HELPER_EXE);
        let log_path = paths::vpn_dir(&tools).join("core_log.txt");
        let log_file: Arc<Mutex<Option<std::fs::File>>> = Arc::new(Mutex::new(
            std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(&log_path).ok(),
        ));
        log_add("warp", &format!("запуск AWG-ядра (SentorWarp) · сервер {}", p.name));
        use std::os::windows::process::CommandExt;
        let mut cmd = std::process::Command::new(&exe);
        cmd.arg(&cfg_path)
            .current_dir(paths::vpn_core_dir(&tools))
            .creation_flags(0x08000000)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                self.fail_for(app, flag, &format!("Ядро не запустилось: {}", e));
                return;
            }
        };
        CORE_PID.store(child.id() as i64, Ordering::Relaxed);
        let child_stdin = child.stdin.take();
        if let Some(out) = child.stdout.take() {
            let lc = log_file.clone();
            std::thread::spawn(move || stream_core_output(out, lc));
        }
        if let Some(err) = child.stderr.take() {
            let lc = log_file.clone();
            std::thread::spawn(move || stream_core_output(err, lc));
        }
        let job = new_kill_on_close_job();
        if let Some(job) = &job {
            job.attach(child.id());
        }
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if Self::same_attempt(&inner, flag) {
                inner.child = Some(child);
                inner.child_stdin = child_stdin;
                inner.job = job;
                WARP_ACTIVE.store(true, Ordering::Relaxed);
            } else {
                // Stop/новый Start попал в окно между spawn и регистрацией:
                // гасим свежий процесс сами, чтобы живой TUN auto_route не утёк.
                drop(child_stdin); // закрыть stdin → хелпер сам сносит туннель
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
        self.set_step_for(app, flag, "⏳ Поднимаю TUN-интерфейс…");
        let mut iface_up = false;
        for _ in 0..100 {
            if Self::interrupted(flag) {
                return;
            }
            std::thread::sleep(Duration::from_millis(150));
            if self.core_exited() {
                break;
            }
            if tun_interface_up(crate::warp::WARP_IFACE) {
                iface_up = true;
                break;
            }
        }
        if self.core_exited() {
            self.fail_for(app, flag, &format!("Ядро упало при открытии TUN: {}", last_core_error_line(&tools)));
            return;
        }
        if !iface_up {
            self.fail_for(app, flag, "TUN-интерфейс не открылся за 15 секунд (wintun заклинило). Перезагрузи ПК");
            return;
        }
        // Туннель поднят — считаем подключённым сразу, без гейта на пробе:
        // DNS/блокировки не должны мешать статусу. Проба уходит в фон.
        std::thread::sleep(Duration::from_millis(1500)); // дать handshake дожать
        if Self::interrupted(flag) {
            return;
        }
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !Self::same_attempt(&inner, flag) {
                return;
            }
            inner.state.phase = "connected".into();
            inner.state.step = format!("✅ Подключено: {} [WARP]", p.name);
            inner.state.error = String::new();
            inner.state.since = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let st2 = inner.state.clone();
            Self::emit_state(app, &st2);
        }
        // фоновая проба: внешний IP для чипа/глобуса (20 с бюджета)
        let pf = flag.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            match crate::warp::warp_probe_and_ip(deadline) {
                Ok((true, ip)) => {
                    if !pf.load(Ordering::Relaxed) {
                        *WARP_IP.lock().unwrap_or_else(|e| e.into_inner()) = ip.clone();
                        log_add("warp", &format!("Проба через туннель: warp=on, IP {}", ip));
                    }
                }
                Ok((false, _)) => log_add("warp", "⚠️ Проба: warp!=on — маршруты не захватили трафик"),
                Err(e) => log_add(
                    "warp",
                    &format!("⚠️ Проба через туннель не прошла: {} — транспорт/DNS не отвечает, смотри handshake в логе", e),
                ),
            }
            // IPv6-проба: конфиги WARP обычно содержат ::/0, но маршрута v6
            // может не быть — пустой результат просто прячет строку IPv6 в UI
            if !pf.load(Ordering::Relaxed) {
                let deadline = Instant::now() + Duration::from_secs(15);
                match crate::warp::warp_probe_ip6(deadline) {
                    Ok(ip6) => {
                        *WARP_IP6.lock().unwrap_or_else(|e| e.into_inner()) = ip6.clone();
                        log_add("warp", &format!("IPv6 туннеля: {}", ip6));
                    }
                    Err(_) => {
                        *WARP_IP6.lock().unwrap_or_else(|e| e.into_inner()) = String::new();
                    }
                }
            }
        });
        // периодический ре-проб: транспортно умерший туннель не должен
        // висеть незамеченным — раз в 30 сек короткая проба
        let rf = flag.clone();
        std::thread::spawn(move || {
            let mut failures = 0;
            loop {
                std::thread::sleep(Duration::from_secs(30));
                if rf.load(Ordering::Relaxed) {
                    return;
                }
                let deadline = Instant::now() + Duration::from_secs(6);
                match crate::warp::warp_probe_once_client(deadline) {
                    Err(e) => {
                        failures += 1;
                        if failures == 3 {
                            log_add("warp", &format!("⚠️ Трафик через туннель пропал: {} — handshake-строки в логе покажут детали", e));
                        }
                    }
                    Ok((true, ip)) => {
                        failures = 0;
                        let mut cur = WARP_IP.lock().unwrap_or_else(|e| e.into_inner());
                        if *cur != ip {
                            *cur = ip.clone();
                            drop(cur);
                            log_add("warp", &format!("Внешний IP сменился: {}", ip));
                        }
                    }
                    Ok((false, _)) => {}
                }
            }
        });
        // вотчдог: ядро умерло — глушим сессию и сообщаем UI
        loop {
            std::thread::sleep(Duration::from_secs(2));
            if Self::interrupted(flag) {
                return;
            }
            if self.core_exited() {
                let tools = self.tools();
                // Снимок «наша сессия ещё активна» под коротким локом; сами
                // ожидания гашения идут без лока.
                let gen0 = {
                    let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    if !(inner.state.phase == "connected"
                        && inner.state.server_id == p.id
                        && inner.stop.as_ref().map(|f| Arc::ptr_eq(f, flag)).unwrap_or(false))
                    {
                        return;
                    }
                    inner.gen
                };
                self.stop_attempt("вотчдог: WARP-ядро умерло");
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if inner.gen != gen0 {
                    return;
                }
                inner.state = crate::models::VpnConnState {
                    phase: "idle".into(),
                    step: String::new(),
                    error: String::new(),
                    server_id: p.id.clone(),
                    server_name: p.name.clone(),
                    since: 0,
                    ..Default::default()
                };
                sysproxy::clear_system_proxy(&tools);
                self.set_vpn_ip("");
                let st2 = inner.state.clone();
                Self::emit_state(app, &st2);
                drop(inner);
                let _ = app.emit("vpnDied", &p.id);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_ranges() {
        assert_eq!(crate::vpnconfig::vpn_port_ranges("2000-4000,5000-6000"), vec!["2000:4000", "5000:6000"]);
        assert_eq!(crate::vpnconfig::vpn_port_ranges("5000"), vec!["5000:5000"]);
        assert_eq!(crate::vpnconfig::vpn_port_ranges(" 2000-4000 , 5000 "), vec!["2000:4000", "5000:5000"]);
    }

    #[test]
    fn strip_ansi_codes() {
        assert_eq!(strip_ansi("\u{1b}[31mERROR text\u{1b}[0m"), "ERROR text");
        assert_eq!(strip_ansi("plain"), "plain");
        assert_eq!(strip_ansi("\u{1b}[1;32mok\u{1b}[0m tail"), "ok tail");
    }

    #[test]
    fn ports_defaults_and_bounds() {
        assert!(vpn_local() > 0 && vpn_local() < 65536);
        assert!(vpn_api() > 0 && vpn_api() < 65536);
    }
}
