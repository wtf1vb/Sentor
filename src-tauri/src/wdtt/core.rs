// Фасад ядра WDTT — порт Go pwdttcore/main.go (Core: New/Start/Stop/Pause/
// Resume/SolveCaptcha), events.go (emitReady), wrap.go (deriveWrapKey) и
// logWriter (log.Printf → события с классификацией и фильтром).
//
// КОНТРАКТ СОСЕДНИХ МОДУЛЕЙ wdtt/ (порт Go, snake_case) — общий для пакета:
//   crate::wdtt::stats::Stats      — Go stats.go: struct Stats {
//         pub total_bytes_up: AtomicI64, pub total_bytes_down: AtomicI64,
//         pub active_connections: AtomicI32 } + Stats::new()
//   crate::wdtt::gate::AllocationGate — Go allocation_gate.go:
//         AllocationGate::new() -> Arc-совместимый gate, gate.wait() (интервал 100 мс)
//   crate::wdtt::dns::setup_global_resolver() — Go dns.go setupGlobalResolver
//   crate::wdtt::blacklist::{global_blacklist_is_banned, global_blacklist_ban,
//                            global_blacklist_clear} — Go GlobalBlacklist
//   crate::wdtt::dispatcher::Dispatcher — Go dispatcher.go (см. dispatcher.rs)
//   crate::wdtt::session::run_session — Go session.go (см. session.rs)
//   crate::wdtt::workers::{worker_group, normalize_workers, TurnParams, SpawnSignal,
//                          TurnIpsSlot, sleep_cancelable, WORKERS_PER_GROUP}
//   crate::wdtt::vk::get_creds — Go vk_auth.go GetCreds (используется в workers.rs)
//   crate::wdtt::protocol::{request_config, send_auth} (используется в session.rs)
//   crate::wdtt::obfs::{WRAP_KEY_LEN, ObfsConfig, ObfsState, obfs_wrap_packet,
//                       obfs_unwrap_packet, obfs_is_rtp_packet} — DTLS-путь (TODO(DTLS))
//
// Глобальный канал капчи (Go CaptchaResultChan) доступен vk.rs/captcha.rs через:
//   core::captcha_drain(), core::captcha_wait(timeout) -> Option<String>
//   (запись делает Core::solve_captcha / core::captcha_store)
use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::wdtt::{PwdttCoreConfig, WdttEvent};

use super::dispatcher::Dispatcher;
use super::gate::AllocationGate;
use super::stats::Stats;
use super::workers::{self, SpawnSignal, TurnIpsSlot, TurnParams, WORKERS_PER_GROUP};

const EVENTS_CAP: usize = 1024;
const SOCKET_BUF_SIZE: i32 = 625 * 1024;
const RESOLVE_ATTEMPTS: u32 = 15;

// ---------- шина событий (порт Go chan Event, cap 1024) ----------

pub struct EventBus {
    q: Mutex<VecDeque<WdttEvent>>,
    cv: Condvar,
    closed: AtomicBool,
}

impl EventBus {
    fn new() -> Arc<EventBus> {
        Arc::new(EventBus {
            q: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
            closed: AtomicBool::new(false),
        })
    }

    // push — порт Go Core.emit: переполненный буфер режем лог-строки
    // безболезненно, а State/wg_config — вытесняя самый старый элемент
    // (UI зависал бы в «connecting» без конфига).
    pub fn push(&self, ev: WdttEvent) {
        let mut g = self.q.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= EVENTS_CAP {
            if matches!(ev, WdttEvent::Log { .. }) {
                return;
            }
            g.pop_front();
        }
        g.push_back(ev);
        drop(g);
        self.cv.notify_all();
    }

    // recv — чтение события с таймаутом; None = очередь пуста.
    pub fn recv(&self, timeout: Duration) -> Option<WdttEvent> {
        let mut g = self.q.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ev) = g.pop_front() {
            return Some(ev);
        }
        if self.closed.load(Ordering::SeqCst) {
            return None;
        }
        // poison-safe: паника другого потока не должна ронять читателя событий
        let (mut g2, _) = self
            .cv
            .wait_timeout(g, timeout)
            .unwrap_or_else(|e| e.into_inner());
        g2.pop_front()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    // close — порт Go close(c.events): после drain очередь читатель выходит.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.cv.notify_all();
    }
}

// ---------- глобальный канал капчи (Go CaptchaResultChan) ----------

static CAPTCHA: Mutex<Option<String>> = Mutex::new(None);
static CAPTCHA_CV: Condvar = Condvar::new();

// captcha_store — запись токена (Go SolveCaptcha: drain + запись, ёмкость 1).
pub fn captcha_store(token: &str) {
    *CAPTCHA.lock().unwrap_or_else(|e| e.into_inner()) = Some(token.to_string());
    CAPTCHA_CV.notify_all();
}

// drainCaptchaResult — осушить канал перед новым ожиданием (для vk.rs).
pub fn captcha_drain() {
    *CAPTCHA.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

// captcha_wait — дождаться токена с таймаутом (Go <-CaptchaResultChan / timer).
pub fn captcha_wait(timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    let mut g = CAPTCHA.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if let Some(t) = g.take() {
            return Some(t);
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let (g2, _) = CAPTCHA_CV
            .wait_timeout(g, deadline - now)
            .unwrap_or_else(|e| e.into_inner());
        g = g2;
    }
}

// ---------- активное ядро (Go activeCore/activeCoreMu) ----------

static ACTIVE_CORE: Mutex<Option<Arc<WdttCore>>> = Mutex::new(None);

fn set_active_core(c: Arc<WdttCore>) {
    *ACTIVE_CORE.lock().unwrap_or_else(|e| e.into_inner()) = Some(c);
}

pub fn get_active_core() -> Option<Arc<WdttCore>> {
    ACTIVE_CORE.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

// ---------- логирование (порт log.Printf → logWriter) ----------

// Маркеры, которые показываются в UI (Go logWriter.Write).
const UI_SHOW_MARKERS: [&str; 10] = [
    "Ошибка кредов",
    "VK Auth] Failed",
    "КАПЧА] v2 попытка",
    "КАПЧА] Превышен лимит",
    "[READY]",
    "[WG]",
    "Туннель активен",
    "Туннель готов",
    "[STATS]",
    "[ЯДРО]",
];

// log — порт log.Printf: classifyLevel + фильтр + Log-событие.
// Непрошедшие фильтр строки уходят с уровнем "SKIP" (UI их не показывает).
pub fn log(msg: &str) {
    let msg = msg.trim_end_matches('\n');
    if msg.is_empty() {
        return;
    }
    let level = classify_level(msg);
    // ВСЕ ошибки — показываем
    if level == "ERROR" {
        emit_log(&level, msg);
        return;
    }
    // === ПОКАЗЫВАЕМ В UI ===
    if UI_SHOW_MARKERS.iter().any(|m| msg.contains(m)) {
        emit_log(&level, msg);
        return;
    }
    // === ПРОПУСКАЕМ ДЛЯ UI (Bridge пишет в файл) ===
    emit_log("SKIP", msg);
}

// emit_log — прямая отправка Log-события (порт c.emit(Event{Type: EventLog,...})).
pub fn emit_log(level: &str, msg: &str) {
    if let Some(ac) = get_active_core() {
        ac.bus
            .push(WdttEvent::Log { level: level.to_string(), message: msg.to_string() });
    }
}

// classifyLevel — порт Go classifyLevel.
fn classify_level(msg: &str) -> String {
    let low = msg.to_lowercase();
    if low.contains("fatal") || low.contains("ошибка") || low.contains("error") {
        return "ERROR".into();
    }
    if low.contains("warn")
        || low.contains("не удалось")
        || low.contains("retry")
        || low.contains("[failover]")
        || low.contains("[reconnect]")
    {
        return "WARN".into();
    }
    "INFO".into()
}

// emitReady — вызывается из session.rs (порт Go emitReady).
pub fn emit_ready() {
    if let Some(ac) = get_active_core() {
        ac.bus.push(WdttEvent::Event {
            name: "ready".into(),
            data: String::new(),
            turn_ips: Vec::new(),
        });
    }
}

// emitEventNamed — прямая отправка Event-события с произвольным именем
// (порт Go c.emit(Event{Type: EventEvent, Name: ..., Data: ...})).
// Используется "captcha_solve" из vk.rs: запрос ручного ввода токена капчи.
pub fn emit_event_named(name: &str, data: &str) {
    if let Some(ac) = get_active_core() {
        ac.bus.push(WdttEvent::Event {
            name: name.to_string(),
            data: data.to_string(),
            turn_ips: Vec::new(),
        });
    }
}

// getCaptchaMode — пакетный доступ из captcha.rs/vk.rs (Go getCaptchaMode).
pub fn get_captcha_mode() -> String {
    if let Some(ac) = get_active_core() {
        return ac.cfg.captcha_mode.clone();
    }
    "auto".into()
}

// getVKAuthMode — пакетный доступ из vk.rs (Go getVKAuthMode).
pub fn get_vk_auth_mode() -> String {
    "vkcalls".into()
}

// ---------- Core ----------

pub struct WdttCore {
    pub(crate) cfg: PwdttCoreConfig,
    cancel: Arc<AtomicBool>,
    pause_flag: Arc<AtomicBool>,
    bus: Arc<EventBus>,
    start_attempted: AtomicBool,
    start_err: Mutex<Option<String>>,
    finished: AtomicBool,
    stop_once: OnceLock<()>,
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl WdttCore {
    // New — создаёт ядро с конфигом (порт Go New).
    pub fn new(mut cfg: PwdttCoreConfig) -> Arc<WdttCore> {
        if cfg.device_id.is_empty() {
            cfg.device_id = "unknown".into();
        }
        // 18, а не 24: воркеры работают группами по 9, и «24» молча урезалось
        // до 18 — дефолт должен быть кратен девяти сразу
        if cfg.workers == 0 {
            cfg.workers = 18;
        }
        if cfg.obfs_mode.is_empty() {
            cfg.obfs_mode = "audio".into();
        }
        cfg.captcha_mode = normalize_captcha_mode(&cfg.captcha_mode);
        Arc::new(WdttCore {
            cfg,
            cancel: Arc::new(AtomicBool::new(false)),
            pause_flag: Arc::new(AtomicBool::new(false)),
            bus: EventBus::new(),
            start_attempted: AtomicBool::new(false),
            start_err: Mutex::new(None),
            finished: AtomicBool::new(false),
            stop_once: OnceLock::new(),
            threads: Mutex::new(Vec::new()),
        })
    }

    // Канал событий ядра (Go Start возвращает <-chan Event).
    pub fn events(&self) -> Arc<EventBus> {
        self.bus.clone()
    }

    // Start — запускает ядро (порт Go Start: startOnce + sticky-ошибка +
    // guard «уже завершено»).
    pub fn start(self: &Arc<Self>) -> Result<(), String> {
        if !self.start_attempted.swap(true, Ordering::SeqCst) {
            let r = self.start_inner();
            if let Err(e) = &r {
                *self.start_err.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.clone());
                return r;
            }
            return Ok(());
        }
        if let Some(e) = self.start_err.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Err(format!("core start previously failed: {}", e));
        }
        if self.finished.load(Ordering::SeqCst) {
            // первый запуск уже завершился: «успех» с мёртвым каналом вводил
            // бы звонящего в заблуждение
            return Err("core already stopped".into());
        }
        Ok(())
    }

    fn start_inner(self: &Arc<Self>) -> Result<(), String> {
        let cancel = self.cancel.clone();
        let canceled = || -> Result<(), String> { Err("остановлено".to_string()) };

        // Устанавливаем activeCore для доступа из session/vk_auth
        set_active_core(self.clone());

        // Отпечаток из конфига сервера (chrome/android/ios/safari/firefox):
        // раньше set_active_fingerprint не вызывался нигде и все запросы ходили
        // с chrome-профилями, какие бы значения ни были в UI
        let fp = self.cfg.fingerprint.trim().to_lowercase();
        if !fp.is_empty() {
            super::profiles::set_active_fingerprint(&fp);
        }

        super::dns::setup_global_resolver();

        // Валидация
        if self.cfg.peer_addr.is_empty() {
            cancel.store(true, Ordering::SeqCst);
            return Err("PeerAddr is required".into());
        }
        if self.cfg.hashes.is_empty() {
            cancel.store(true, Ordering::SeqCst);
            return Err("Hashes are required".into());
        }
        if self.cfg.password.is_empty() {
            cancel.store(true, Ordering::SeqCst);
            return Err("Password is required".into());
        }
        // Протокол AUTH/GETCONF использует '|' как разделитель полей без
        // экранирования: пароль с '|' делал AUTH неразборуемым на сервере
        if self.cfg.password.contains('|') {
            cancel.store(true, Ordering::SeqCst);
            return Err("Password must not contain '|' (protocol separator)".into());
        }

        // Резолв пира — с отменой: без неё Stop() не мог прервать Start()
        // минутами. Ошибки резолва логируем — раньше пауза была полностью немой.
        let clean_peer_addr = self.cfg.peer_addr.trim().to_string();
        let mut peer: Option<SocketAddr> = None;
        let mut last_err = String::new();
        for i in 0..RESOLVE_ATTEMPTS {
            if cancel.load(Ordering::Relaxed) {
                return canceled();
            }
            match resolve_udp(&clean_peer_addr) {
                Ok(a) => {
                    peer = Some(a);
                    break;
                }
                Err(e) => {
                    log(&format!(
                        "[ЯДРО] Резолв пира {:?} не удался ({}/{}): {}",
                        clean_peer_addr,
                        i + 1,
                        RESOLVE_ATTEMPTS,
                        e
                    ));
                    last_err = e;
                }
            }
            if !workers::sleep_cancelable(Duration::from_secs(1), &cancel) {
                return canceled();
            }
        }
        let Some(peer) = peer else {
            cancel.store(true, Ordering::SeqCst);
            return Err(format!("resolve peer: {}", last_err));
        };

        // WRAP ключ
        let wrap_key = match derive_wrap_key(&self.cfg.password) {
            Ok(k) => k,
            Err(e) => {
                cancel.store(true, Ordering::SeqCst);
                return Err(format!("derive wrap key: {}", e));
            }
        };

        // Нормализация воркеров
        let n = workers::normalize_workers(self.cfg.workers);

        // Go-Config имел TurnHost/TurnPort/TurnTCP; в Rust-контракте
        // PwdttCoreConfig их нет (sing-box-туннель обходится без них).
        let tp = Arc::new(TurnParams {
            host: String::new(),
            port: String::new(),
            hashes: self.cfg.hashes.clone(),
            wrap_key: wrap_key.to_vec(),
            obfs_mode: self.cfg.obfs_mode.clone(),
            tcp_transport: false,
            allocate_gate: Arc::new(AllocationGate::new(Duration::from_millis(100))),
        });

        // Локальный UDP-сокет
        let listen_port = if self.cfg.local_port == 0 { 9000u16 } else { self.cfg.local_port };
        let mut sock: Option<UdpSocket> = None;
        for i in 0..5u32 {
            match UdpSocket::bind(("127.0.0.1", listen_port)) {
                Ok(s) => {
                    sock = Some(s);
                    break;
                }
                Err(_) => {
                    log(&format!("[ЯДРО] Порт {} занят, жду... ({}/5)", listen_port, i + 1));
                }
            }
            if !workers::sleep_cancelable(Duration::from_secs(1), &cancel) {
                return canceled();
            }
        }
        let sock = match sock {
            Some(s) => s,
            None => {
                // Фолбэк на случайный порт: контракт cfg.Listen нарушается,
                // внешний код должен узнать об этом — хотя бы в лог
                log(&format!(
                    "[ЯДРО] Слушать 127.0.0.1:{} не удалось — перехожу на случайный порт 127.0.0.1:0",
                    listen_port
                ));
                match UdpSocket::bind("127.0.0.1:0") {
                    Ok(s) => s,
                    Err(e) => {
                        cancel.store(true, Ordering::SeqCst);
                        return Err(format!("listen: {}", e));
                    }
                }
            }
        };
        set_udp_bufsizes(&sock, SOCKET_BUF_SIZE);
        let local_port = sock
            .local_addr()
            .map(|a| a.port().to_string())
            .unwrap_or_else(|_| listen_port.to_string());
        let local_port = if local_port.is_empty() || local_port == "0" {
            "9000".to_string()
        } else {
            local_port
        };

        let num_groups = n / WORKERS_PER_GROUP;

        // Статистика
        let stats = Arc::new(Stats::new());
        {
            let stats = stats.clone();
            let cancel2 = cancel.clone();
            let bus = self.bus.clone();
            let h = std::thread::spawn(move || stats_loop(stats, cancel2, bus));
            self.threads.lock().unwrap_or_else(|e| e.into_inner()).push(h);
        }

        // Диспетчер
        let disp = Dispatcher::new(sock, stats.clone(), cancel.clone());

        // Конфиг WireGuard: первый получивший воркер доставляет событие
        let (config_tx, config_rx) = std::sync::mpsc::sync_channel::<String>(1);
        let turn_ips = TurnIpsSlot::new();
        {
            let bus = self.bus.clone();
            let cancel2 = cancel.clone();
            let turn_ips2 = turn_ips.clone();
            let h = std::thread::spawn(move || {
                // TURN-IPы резолвятся в фоне и могли приехать ПОЗЖЕ конфига:
                // ждём их ограниченное время (4 с), иначе exclude-маршруты
                // не строились
                loop {
                    if cancel2.load(Ordering::Relaxed) {
                        return;
                    }
                    match config_rx.recv_timeout(Duration::from_millis(250)) {
                        Ok(raw_conf) => {
                            let final_conf = patch_mtu(&raw_conf);
                            let ips = turn_ips2
                                .wait_take(Duration::from_secs(4))
                                .unwrap_or_default();
                            bus.push(WdttEvent::Event {
                                name: "wg_config".into(),
                                data: final_conf,
                                turn_ips: ips,
                            });
                            return;
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
            });
            self.threads.lock().unwrap_or_else(|e| e.into_inner()).push(h);
        }

        // Старт
        self.bus.push(WdttEvent::State { status: "connecting".into() });

        // success-горутина: группы воркеров + финальная уборка
        {
            let core = self.clone();
            let cancel2 = cancel.clone();
            let disp2 = disp.clone();
            let tp2 = tp.clone();
            let stats2 = stats.clone();
            let config_tx2 = config_tx.clone();
            let turn_ips2 = turn_ips.clone();
            let pause2 = self.pause_flag.clone();
            let device_id = self.cfg.device_id.clone();
            let password = self.cfg.password.clone();
            let lp = local_port.clone();
            let h = std::thread::spawn(move || {
                let mut prev_wait_creds: Option<std::sync::mpsc::Receiver<()>> = None;
                let mut prev_wait_spawn: Option<std::sync::mpsc::Receiver<()>> = None;
                let mut worker_id_counter: i32 = 1;
                let mut handles: Vec<std::thread::JoinHandle<()>> = Vec::new();

                for g in 0..num_groups {
                    let is_first = g == 0;
                    let my_wait_creds = if g > 0 { prev_wait_creds.take() } else { None };
                    let my_wait_spawn = if g > 0 { prev_wait_spawn.take() } else { None };
                    let (my_signal_creds, my_signal_spawn): (
                        Option<SpawnSignal>,
                        Option<SpawnSignal>,
                    ) = if g + 1 < num_groups {
                        let (tc, rc) = std::sync::mpsc::channel::<()>();
                        prev_wait_creds = Some(rc);
                        let (ts, rs) = std::sync::mpsc::channel::<()>();
                        prev_wait_spawn = Some(rs);
                        (Some(SpawnSignal::new(tc)), Some(SpawnSignal::new(ts)))
                    } else {
                        (None, None)
                    };

                    let ids: Vec<i32> = (0..WORKERS_PER_GROUP)
                        .map(|_| {
                            let id = worker_id_counter;
                            worker_id_counter += 1;
                            id
                        })
                        .collect();

                    let g_id = g + 1;
                    let cc = if is_first { Some(config_tx2.clone()) } else { None };

                    let cancel3 = cancel2.clone();
                    let disp3 = disp2.clone();
                    let tp3 = tp2.clone();
                    let stats3 = stats2.clone();
                    let pause3 = pause2.clone();
                    let turn_ips3 = turn_ips2.clone();
                    let dev = device_id.clone();
                    let pass = password.clone();
                    let lp3 = lp.clone();
                    handles.push(std::thread::spawn(move || {
                        workers::worker_group(
                            &cancel3,
                            g_id,
                            g, // startHashIndex
                            tp3,
                            peer,
                            disp3,
                            lp3,
                            is_first,
                            cc,
                            Some(turn_ips3),
                            ids,
                            pause3,
                            dev,
                            pass,
                            stats3,
                            my_wait_creds,
                            my_signal_creds,
                            my_wait_spawn,
                            my_signal_spawn,
                        );
                    }));
                }

                for h in handles {
                    // паника воркера не должна уходить молча
                    if let Err(p) = h.join() {
                        log(&format!("[ЯДРО] Воркер запаниковал: {}", super::panic_msg(&p)));
                    }
                }
                drop(config_tx2); // close(configCh)
                log("[ЯДРО] Все воркеры завершены");

                // Финальная уборка (порядок Go-defer'ов: cancel → Shutdown →
                // close(events) → finished)
                cancel2.store(true, Ordering::SeqCst);
                disp2.shutdown();
                core.bus.close();
                core.finished.store(true, Ordering::SeqCst);
            });
            self.threads.lock().unwrap_or_else(|e| e.into_inner()).push(h);
        }

        Ok(())
    }

    // Stop — останавливает ядро (guard от двойного Stop).
    pub fn stop(&self) {
        if self.stop_once.set(()).is_ok() {
            self.cancel.store(true, Ordering::SeqCst);
            // баны TURN-адресов не должны переживать сессию: WRAP_TIMEOUT
            // прошлой сессии иначе душил новую 5 минут
            super::blacklist::global_blacklist_clear();
        }
    }

    // Pause — приостанавливает воркеры.
    #[allow(dead_code)] // Go-паритет Pause/Resume; Tauri-команды пока нет
    pub fn pause(&self) {
        self.pause_flag.store(true, Ordering::SeqCst);
    }

    // Resume — возобновляет воркеры.
    #[allow(dead_code)]
    pub fn resume(&self) {
        self.pause_flag.store(false, Ordering::SeqCst);
    }

    // SolveCaptcha — передаёт токен капчи в ядро (атомарно: drain + запись).
    pub fn solve_captcha(&self, token: &str) {
        captcha_store(token);
    }
}

// ---------- служебные функции ----------

// resolve_udp — предпочитаем IPv4, иначе первый адрес (как ResolveUDPAddr).
// Резолв через собственный DNS-резолвер (Яндекс-DNS, UDP→TCP-фоллбек) —
// обход глушения/подмены системного DNS; системный — только как фоллбек
// внутри dns::resolve_host.
fn resolve_udp(addr: &str) -> Result<SocketAddr, String> {
    let addrs = super::dns::resolve_host(addr);
    if let Some(a) = addrs.iter().find(|a| a.is_ipv4()) {
        return Ok(*a);
    }
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| format!("резолв {}: нет адресов", addr))
}

// set_udp_bufsizes — Go SetReadBuffer/SetWriteBuffer (best effort).
#[cfg(windows)]
fn set_udp_bufsizes(s: &UdpSocket, size: i32) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, SO_RCVBUF, SO_SNDBUF, SOL_SOCKET};
    unsafe {
        let raw = s.as_raw_socket() as usize;
        let _ = setsockopt(
            raw,
            SOL_SOCKET,
            SO_RCVBUF,
            &size as *const i32 as *const u8,
            std::mem::size_of::<i32>() as i32,
        );
        let _ = setsockopt(
            raw,
            SOL_SOCKET,
            SO_SNDBUF,
            &size as *const i32 as *const u8,
            std::mem::size_of::<i32>() as i32,
        );
    }
}

#[cfg(not(windows))]
fn set_udp_bufsizes(_s: &UdpSocket, _size: i32) {}

// stats_loop — порт Go Stats.RunLoop: [STATS] каждые 3 секунды + Stats-событие.
fn stats_loop(stats: Arc<Stats>, cancel: Arc<AtomicBool>, bus: Arc<EventBus>) {
    let mut last = Instant::now();
    while !cancel.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(250));
        if last.elapsed() < Duration::from_secs(3) {
            continue;
        }
        last = Instant::now();
        let active = stats.active_connections.load(Ordering::Relaxed);
        let up = stats.total_bytes_up.load(Ordering::Relaxed);
        let down = stats.total_bytes_down.load(Ordering::Relaxed);
        let total_mb = (up + down) as f64 / (1024.0 * 1024.0);
        emit_log(
            "INFO",
            &format!("[STATS] Активных: {}, Трафик: {} МБ", active, format_mb(total_mb)),
        );
        bus.push(WdttEvent::Stats { active, bytes_up: up, bytes_down: down });
    }
}

// format_mb — порт Go ftoa (две цифры дробной части с обрезкой нулей).
fn format_mb(f: f64) -> String {
    let mut s = format!("{:.2}", f);
    while s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    if s.is_empty() {
        s = "0".into();
    }
    s
}

// patchMTU — MTU уже задан в ЛЮБОМ написании — не дублируем; иначе вставляем
// «MTU = 1280» сразу после [Interface].
fn patch_mtu(conf: &str) -> String {
    for line in conf.split('\n') {
        let trimmed = line.trim();
        let first3: String = trimmed.chars().take(3).collect();
        if first3.eq_ignore_ascii_case("mtu") {
            return conf.to_string();
        }
    }
    let mut out: Vec<String> = Vec::new();
    for line in conf.split('\n') {
        out.push(line.to_string());
        if line.trim() == "[Interface]" {
            out.push("MTU = 1280".into());
        }
    }
    out.join("\n")
}

// normalizeCaptchaMode — auto | rjs | wv.
pub fn normalize_captcha_mode(mode: &str) -> String {
    let m = mode.trim().to_lowercase();
    match m.as_str() {
        "auto" | "rjs" | "wv" => m,
        _ => "auto".into(),
    }
}

// normalizeVKAuthMode — legacy | vkcalls.
#[allow(dead_code)]
pub fn normalize_vk_auth_mode(mode: &str) -> String {
    match mode.trim().to_lowercase().as_str() {
        "legacy" => "legacy".into(),
        _ => "vkcalls".into(),
    }
}

// ---------- WRAP-ключ (порт Go wrap.go) ----------

// deriveWrapKey — HKDF-SHA256(password, salt="WDTT-WRAP-v1",
// info="rtp-obfs/chacha20poly1305", 32 байта). Крейта hkdf в Cargo.toml нет —
// HMAC-SHA256 и Extract/Expand реализованы вручную на sha2.
pub fn derive_wrap_key(password: &str) -> Result<[u8; 32], String> {
    if password.is_empty() {
        return Err("empty password".into());
    }
    Ok(hkdf_sha256(password.as_bytes(), b"WDTT-WRAP-v1", b"rtp-obfs/chacha20poly1305", 32))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    use sha2::Sha256;
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&ih);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

// hkdf_sha256 — RFC 5869 (нужен только len<=32 — один блок Expand).
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> [u8; 32] {
    let prk = if salt.is_empty() {
        hmac_sha256(&[0u8; 32], ikm)
    } else {
        hmac_sha256(salt, ikm)
    };
    let mut data = Vec::with_capacity(info.len() + 1);
    data.extend_from_slice(info);
    data.push(1u8);
    let t = hmac_sha256(&prk, &data);
    let mut okm = [0u8; 32];
    okm.copy_from_slice(&t[..len.min(32)]);
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_mtu_variants() {
        assert_eq!(patch_mtu("MTU = 1280\nx"), "MTU = 1280\nx");
        assert_eq!(patch_mtu("mtu=1200"), "mtu=1200");
        assert_eq!(patch_mtu("[Interface]\nPrivateKey = a"), "[Interface]\nMTU = 1280\nPrivateKey = a");
    }

    #[test]
    fn mb_format() {
        assert_eq!(format_mb(1.05), "1.05");
        assert_eq!(format_mb(0.29), "0.29");
        assert_eq!(format_mb(10.0), "10");
        assert_eq!(format_mb(0.0), "0");
    }

    #[test]
    fn wrap_key_derives() {
        let k = derive_wrap_key("secret").unwrap();
        assert_eq!(k.len(), 32);
        assert!(derive_wrap_key("").is_err());
        // детерминированность
        assert_eq!(derive_wrap_key("secret").unwrap(), k);
    }

    #[test]
    fn normalize_modes() {
        assert_eq!(normalize_captcha_mode(" RJS "), "rjs");
        assert_eq!(normalize_captcha_mode("bogus"), "auto");
        assert_eq!(normalize_vk_auth_mode("legacy"), "legacy");
        assert_eq!(normalize_vk_auth_mode("x"), "vkcalls");
    }
}
