// TURN/DTLS-сессия — порт Go pwdttcore/session.go.
//
// TODO(DTLS) — ОСОБЕННОСТЬ ТЕКУЩЕЙ ВЕРСИИ: транспорт — «чистый» TCP к адресу
// TURN-сервера (host:port), БЕЗ TURN-client (pion/turn) и БЕЗ DTLS (pion/dtls).
// Вся остальная логика Go (типизация ошибок failover, GETCONF/AUTH-протокол,
// слот диспетчера, keepalive, таймауты, семафор рукопожатий) портирована
// один в один; недостающее сетевое ядро изолировано в ЕДИНСТВЕННОЙ функции
// wrap_dtls() ниже — там же точное описание, что осталось доделать.
//
// Почему так: крейт webrtc (webrtc-rs) в актуальной версии 0.21 больше НЕ
// содержит модуля dtls (тонкая обёртка над rtc-*); старая ветка 0.14 с
// webrtc::dtls — полностью async и требует tokio, а TURN-клиент живёт в
// отдельном крейте `turn`. Все три зависимости запрещены правилами порта
// (Cargo.toml допускает только webrtc + rcgen). Когда ограничения снимут —
// добавить turn + tokio + (webrtc 0.14 | rtc-dtls) и реализовать wrap_dtls.
//
// КОНТРАКТ СОСЕДНИХ МОДУЛЕЙ wdtt/ (порт Go, snake_case):
//   crate::wdtt::core::log(msg)                 — log.Printf → события ядра
//   crate::wdtt::core::emit_ready()             — Go emitReady() (events.go)
//   crate::wdtt::stats::Stats                   — Go stats.go (см. dispatcher.rs)
//   crate::wdtt::protocol::request_config(conn: &dyn WdttTransport, local_port: &str,
//                                         device_id: &str, password: &str) -> Result<String, String>
//                                               — Go protocol.go RequestConfig
//   crate::wdtt::protocol::send_auth(conn: &dyn WdttTransport, device_id: &str,
//                                    password: &str) -> Result<(), String>
//                                               — Go protocol.go SendAuth
//   crate::wdtt::vk::handle_auth_error(stream_id: i32) -> bool — Go vk_auth.go
//   crate::wdtt::gate::AllocationGate::wait(&self)             — Go allocation_gate.go
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::core::log;
use super::dispatcher::{try_send_or_cancel, Dispatcher, WorkerSlot};
use super::stats::Stats;
use super::workers::TurnParams;

const WORKER_SEND_BUF: usize = 128;
const SESSION_READ_TIMEOUT: Duration = Duration::from_secs(30 * 60);
// Таймаут ЗАПИСИ пакетов: нормальная запись в TCP мгновенна (уходит в буфер
// ядра). 30-минутный SESSION_READ_TIMEOUT здесь означал: при забитом TCP
// writer висит до получаса, disconnect() выглядит мёртвым.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const READ_BUF_SIZE: usize = 1600;
const SOCKET_BUF_SIZE: i32 = 625 * 1024;
const KEEPALIVE_BYTE: u8 = 0xFF;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_LIMIT: u32 = 3;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

// ---------- ошибки сессии (порт SessionError/SessionErrorType) ----------

// SessionErrorType — тип ошибки сессии.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionErrorType {
    // ADDRESS_DEAD — этот конкретный TURN-адрес не работает (квота, unreachable, timeout)
    AddressDead,
    // WRAP_TIMEOUT — DTLS-рукопожатие не прошло, нужно сменить обфускацию
    #[allow(dead_code)] // ветка оживает с DTLS-адаптером
    WrapTimeout,
    // AUTH — TURN отклонил креды (401/протухшие); нужно обновить креды и повторить
    #[allow(dead_code)] // 401-ветка wrap_dtls (TODO(DTLS))
    Auth,
    // FATAL — невосстановимая ошибка (FATAL_AUTH, хеш мёртв и т.д.)
    Fatal,
}

impl SessionErrorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionErrorType::AddressDead => "ADDRESS_DEAD",
            SessionErrorType::WrapTimeout => "WRAP_TIMEOUT",
            SessionErrorType::Auth => "AUTH",
            SessionErrorType::Fatal => "FATAL",
        }
    }
}

// SessionError — структурированная ошибка сессии.
#[derive(Debug, Clone)]
pub struct SessionError {
    pub kind: SessionErrorType,
    // TURN-адрес, на котором произошла ошибка (если применимо)
    pub address: String,
    pub err: String,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} (addr={})",
            self.kind.as_str(),
            self.err,
            self.address
        )
    }
}

impl SessionError {
    fn new(kind: SessionErrorType, address: &str, err: String) -> SessionError {
        SessionError { kind, address: address.to_string(), err }
    }
}

// ---------- транспорт (шов для DTLS) ----------

// WdttTransport — потоковый шов, через который ходят и протокол
// (RequestConfig/SendAuth), и пакеты туннеля. В Go это net.Conn поверх DTLS
// поверх packet-pipe TURN-релея; здесь — TCP (fallback), позже — DTLS-адаптер.
pub trait WdttTransport: Send + Sync {
    // read — чтение с таймаутом: Err(kind=WouldBlock/TimedOut) = тишина.
    fn read(&self, buf: &mut [u8], timeout: Duration) -> std::io::Result<usize>;
    // write — запись (до таймаута; возвращает число записанных байт).
    fn write(&self, buf: &[u8], timeout: Duration) -> std::io::Result<usize>;
    fn shutdown(&self);
}

// TcpTransport — fallback-транспорт (в Go здесь dtlsConn поверх TURN-релея).
pub struct TcpTransport {
    s: TcpStream,
}

impl TcpTransport {
    pub fn new(s: TcpStream) -> TcpTransport {
        TcpTransport { s }
    }
}

impl WdttTransport for TcpTransport {
    fn read(&self, buf: &mut [u8], timeout: Duration) -> std::io::Result<usize> {
        self.s.set_read_timeout(Some(timeout))?;
        match (&self.s).read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                Err(std::io::Error::new(ErrorKind::WouldBlock, "read timeout"))
            }
            Err(e) => Err(e),
        }
    }

    fn write(&self, buf: &[u8], timeout: Duration) -> std::io::Result<usize> {
        self.s.set_write_timeout(Some(timeout))?;
        let mut off = 0;
        let start = Instant::now();
        while off < buf.len() {
            let n = (&self.s).write(&buf[off..])?;
            if n == 0 {
                return Err(std::io::Error::new(ErrorKind::WriteZero, "write zero"));
            }
            off += n;
            if start.elapsed() >= timeout {
                break;
            }
        }
        if off < buf.len() {
            // Частичная запись раньше возвращалась как Ok(off), а вызывающие
            // (request_config/send_auth/write_loop) длину не проверяли: пакет
            // уходил обрезанным, TCP-поток рассинхронизировался. Все вызывающие
            // обрабатывают Err — сигнализируем честно.
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                format!("write timeout: {} из {} байт", off, buf.len()),
            ));
        }
        Ok(off)
    }

    fn shutdown(&self) {
        let _ = self.s.shutdown(std::net::Shutdown::Both);
    }
}

// ---------- семафор рукопожатий (Go handshakeSem, ёмкость 3) ----------

static HANDSHAKE_SEM: Mutex<u32> = Mutex::new(HANDSHAKE_LIMIT);
static HANDSHAKE_CV: Condvar = Condvar::new();

fn handshake_acquire(cancel: &AtomicBool) -> bool {
    let mut g = HANDSHAKE_SEM.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if *g > 0 {
            *g -= 1;
            return true;
        }
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        // poison-safe: отравленный лок не должен паникой ронять воркера
        let (g2, _) = HANDSHAKE_CV
            .wait_timeout(g, Duration::from_millis(200))
            .unwrap_or_else(|e| e.into_inner());
        g = g2;
    }
}

struct SemGuard;
impl Drop for SemGuard {
    fn drop(&mut self) {
        let mut g = HANDSHAKE_SEM.lock().unwrap_or_else(|e| e.into_inner());
        *g += 1;
        HANDSHAKE_CV.notify_one();
    }
}

// ---------- DTLS (единственная точка интеграции) ----------

// wrap_dtls — TODO(DTLS): сейчас transport пропускается насквозь (identity).
//
// Что должно быть здесь при полной реализации (порт Go RunSession):
//   1. TURN (pion/turn → крейт `turn`):
//      - dialTURNConn: UDP (connected UDP-сокет, буферы 625 КБ) либо TCP
//        (turn.NewSTUNConn) к turnAddrResolved — TCP-диал в этой версии уже
//        сделан снаружи (в run_session);
//      - turn.NewClient(ClientConfig{STUNServerAddr/TURNServerAddr, Conn,
//        Username, Password, RequestedAddressFamily по peer}) + Listen();
//      - allocateGate.wait() (уже вызывается в run_session);
//      - Allocate(): ошибки "quota"/"486"/"unreachable"/"timeout"/
//        "connection refused"/"no route to host" → ADDRESS_DEAD;
//        401 → super::vk::handle_auth_error(cache_stream_id) + SessionError::Auth;
//        остальное → FATAL. После успеха — сброс счётчика ошибок стрима
//        (Go: getStreamCache(cacheStreamID).errorCount.Store(0)).
//      - CreatePermission(peer) → ADDRESS_DEAD при ошибке;
//      - SendBindingRequest каждые 10 с.
//   2. Релей-насосы над relay.PacketConn: два направления relay↔pipe
//      (Go connutil.AsyncPacketPipe), при useWrap (len(tp.wrap_key)==32) —
//      обфускация RTP-пакетов chacha20poly1305 (crate::wdtt::obfs:
//      ObfsConfig::new(mode), ObfsState::new(), obfs_wrap_packet /
//      obfs_unwrap_packet / obfs_is_rtp_packet); буфер чтения
//      READ_BUF_SIZE+96 (оверхед obfs до ~88 байт резал максимальный пакет).
//   3. DTLS-клиент (pion/dtls v3 → webrtc-rs dtls / rtc-dtls) поверх pipeB:
//      self-signed сертификат (rcgen::generate_simple_self_signed, ECDSA),
//      конфиг = { insecure_skip_verify: true, extended_master_secret: Require,
//      cipher_suites: [TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
//      connection_id_generator: OnlySendCIDGenerator } — connection-id «only
//      send» в webrtc-rs не реализован: либо допилить, либо работать без CID;
//      рукопожатие с дедлайном HANDSHAKE_TIMEOUT (20 с), семафор уже здесь.
//   4. Классификация таймаута рукопожатия (порт Go):
//      - deadline/timeout и ни одного пакета от peer (first_wire_read=false)
//        → ADDRESS_DEAD «TURN relay молчит: ни один пакет от peer не вернулся»;
//      - deadline/timeout и пакеты были, useWrap → WRAP_TIMEOUT «peer ответил,
//        но WRAP/DTLS не подтверждён»;
//      - прочие ошибки → ADDRESS_DEAD «DTLS хендшейк».
//   5. Асинхронный DTLS-конн мостится в синхронный WdttTransport парой
//      каналов (read/write половины) — сам trait менять не нужно.
//   Логи Go, появляющиеся на этом этапе:
//      «[СЕССИЯ #N] Relay: …; peer: …», «[СЕССИЯ #N] TURN permission OK …»,
//      «[ВОРКЕР #N] [DTLS] Рукопожатие (Handshake)...»,
//      «[ВОРКЕР #N] [DTLS] Соединение установлено ✓»,
//      «[СЕССИЯ #N] Первый пакет получен/отправлен через TURN …».
fn wrap_dtls(
    transport: Box<dyn WdttTransport>,
    _peer: SocketAddr,
    cancel: &AtomicBool,
) -> Result<Box<dyn WdttTransport>, SessionError> {
    if !handshake_acquire(cancel) {
        return Err(SessionError::new(
            SessionErrorType::Fatal,
            "",
            "остановлено в очереди рукопожатий".into(),
        ));
    }
    let _guard = SemGuard;
    // TODO(DTLS): здесь — TURN-релей + obfs-насосы + DTLS-рукопожатие
    // (см. список выше); HANDSHAKE_TIMEOUT — дедлайн рукопожатия.
    let _ = HANDSHAKE_TIMEOUT;
    Ok(transport)
}

// ---------- вспомогательное ----------

// split_host_port — порт Go net.SplitHostPort (v4/[v6]:port).
pub(crate) fn split_host_port(addr: &str) -> Result<(String, String), String> {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(rb) = rest.find(']') {
            let host = rest[..rb].to_string();
            let port = rest[rb + 1..].trim_start_matches(':').to_string();
            return Ok((host, port));
        }
        return Err("missing ']' in address".into());
    }
    match addr.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), p.to_string())),
        None => Err("missing port in address".into()),
    }
}

// join_host_port — порт Go net.JoinHostPort.
pub(crate) fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

// ActiveGuard — порт Go defer stats.ActiveConnections.Add(-1).
struct ActiveGuard<'a>(&'a Stats);
impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

// CancelGuard — порт Go `defer sessCancel()` в каждой прокси-горутине:
// выход любого насоса будит второй (его цикл проверяет флаг каждые 0.5 с).
struct CancelGuard(Arc<AtomicBool>);
impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

// ---------- RunSession ----------

// RunSession устанавливает сессию с указанным адресом (порт Go RunSession).
// Адрес передаётся явно, а не выбирается по индексу. Возвращает
// (config_delivered, ошибка): None — сессия завершилась штатно.
#[allow(clippy::too_many_arguments)]
pub fn run_session(
    cancel: &Arc<AtomicBool>,
    tp: &TurnParams,
    peer: SocketAddr,
    d: &Arc<Dispatcher>,
    local_port: &str,
    get_config: bool,
    config_ch: Option<&SyncSender<String>>,
    session_id: i32,
    turn_addr: &str,
    turn_user: &str,
    turn_pass: &str,
    obfs_mode: &str,
    cache_stream_id: i32,
    device_id: &str,
    password: &str,
    stats: &Arc<Stats>,
) -> (bool, Option<SessionError>) {
    let mut config_delivered = false;

    if turn_addr.is_empty() {
        return (
            false,
            Some(SessionError::new(
                SessionErrorType::Fatal,
                "",
                "пустой TURN-адрес".into(),
            )),
        );
    }

    let (mut urlhost, mut urlport) = match split_host_port(turn_addr) {
        Ok(v) => v,
        Err(e) => {
            return (
                false,
                Some(SessionError::new(
                    SessionErrorType::AddressDead,
                    turn_addr,
                    format!("разбор TURN-адреса: {}", e),
                )),
            )
        }
    };
    if !tp.host.is_empty() {
        urlhost = tp.host.clone();
    }
    if !tp.port.is_empty() {
        urlport = tp.port.clone();
    }
    let turn_addr_resolved = join_host_port(&urlhost, &urlport);

    // TODO(DTLS): Go dialTURNConn — UDP (connected UDP + буферы 625 КБ) или
    // TCP (turn.NewSTUNConn); в этой версии транспорт сессии — «чистый» TCP.
    // Резолв через собственный DNS-резолвер (Яндекс-DNS с UDP→TCP-фоллбеком —
    // обход глушения/подмены DNS), системный — только фоллбек внутри
    // dns::resolve_host
    let addr_list: Vec<SocketAddr> = {
        let l = super::dns::resolve_host(&turn_addr_resolved);
        if l.is_empty() {
            return (
                false,
                Some(SessionError::new(
                    SessionErrorType::AddressDead,
                    turn_addr,
                    "резолв TURN: нет адресов".to_string(),
                )),
            );
        }
        l
    };
    let addr = match addr_list.into_iter().next() {
        Some(a) => a,
        None => {
            return (
                false,
                Some(SessionError::new(
                    SessionErrorType::AddressDead,
                    turn_addr,
                    "резолв TURN: нет адресов".into(),
                )),
            )
        }
    };
    let stream = match TcpStream::connect_timeout(&addr, DIAL_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            return (
                false,
                Some(SessionError::new(
                    SessionErrorType::AddressDead,
                    turn_addr,
                    format!("подключение TURN TCP: {}", e),
                )),
            )
        }
    };
    let _ = stream.set_nodelay(true);
    log(&format!(
        "[СЕССИЯ #{}] TCP ({}) — TODO(DTLS): без TURN/DTLS, transport прямой",
        session_id, turn_addr
    ));

    // allocateGate — темп Allocate-попыток (интервал 100 мс).
    tp.allocate_gate.wait();
    if cancel.load(Ordering::Relaxed) {
        return (
            false,
            Some(SessionError::new(
                SessionErrorType::Fatal,
                turn_addr,
                "остановлено".into(),
            )),
        );
    }

    // TODO(DTLS): TURN Allocate/CreatePermission + обфускация (useWrap —
    // len(tp.wrap_key)==32, RTP chacha20poly1305 obfs-режим) + DTLS.
    // В fallback-транспорте obfs неприменим (он пакетный, RTP), креды
    // turn_user/turn_pass и cache_stream_id нужны только DTLS-пути.
    let _ = (turn_user, turn_pass, obfs_mode, cache_stream_id);
    let _ = (READ_BUF_SIZE, SOCKET_BUF_SIZE);

    let transport: Arc<dyn WdttTransport> = match wrap_dtls(
        Box::new(TcpTransport::new(stream)),
        peer,
        cancel,
    ) {
        Ok(t) => Arc::from(t),
        Err(e) => return (false, Some(e)),
    };

    stats.active_connections.fetch_add(1, Ordering::Relaxed);
    let _active_guard = ActiveGuard(stats);

    // Протокол: GETCONF (кто первый достал конфиг) либо AUTH.
    if get_config {
        if let Some(cc) = config_ch {
            match super::protocol::request_config(
                transport.as_ref(),
                local_port,
                device_id,
                password,
            ) {
                Err(conf_err) => {
                    if conf_err.contains("FATAL_AUTH") {
                        return (
                            false,
                            Some(SessionError::new(
                                SessionErrorType::Fatal,
                                turn_addr,
                                conf_err,
                            )),
                        );
                    }
                    log(&format!(
                        "[ВОРКЕР #{}] Ошибка конфига: {}",
                        session_id, conf_err
                    ));
                }
                Ok(conf) if !conf.is_empty() => {
                    // Go: select { case configCh <- conf: ... default: ... }
                    // в обоих случаях configDelivered = true, сессия живёт дальше.
                    match cc.try_send(conf) {
                        Ok(()) => {
                            config_delivered = true;
                            log(&format!("[ВОРКЕР #{}] Конфиг получен", session_id));
                        }
                        Err(_) => {
                            config_delivered = true;
                            log(&format!(
                                "[ВОРКЕР #{}] Конфиг уже был доставлен другим воркером",
                                session_id
                            ));
                        }
                    }
                }
                Ok(_) => {
                    log(&format!(
                        "[ВОРКЕР #{}] Сервер ещё не выдал WireGuard-конфиг, повторим позже",
                        session_id
                    ));
                }
            }
        }
    } else if let Err(auth_err) =
        super::protocol::send_auth(transport.as_ref(), device_id, password)
    {
        log(&format!(
            "[ВОРКЕР #{}] Ошибка авторизации: {}",
            session_id, auth_err
        ));
    }

    super::core::emit_ready();

    // Слот диспетчера + прокси-насосы. Пакеты И keepalive-пинги шлёт ОДИН
    // поток (у DTLS writeDeadline общий: второй писатель устраивал гонку).
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(WORKER_SEND_BUF);
    let slot = Arc::new(WorkerSlot { id: session_id, send_tx: tx });
    d.register(slot.clone());

    let sess_cancel = Arc::new(AtomicBool::new(false));

    let writer = {
        let tr = transport.clone();
        let sess_cancel = sess_cancel.clone();
        let wid = session_id;
        std::thread::spawn(move || {
            let _cancel_on_exit = CancelGuard(sess_cancel.clone());
            let mut since_ping = Instant::now();
            let ping = [KEEPALIVE_BYTE];
            loop {
                if sess_cancel.load(Ordering::Relaxed) {
                    return;
                }
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(pkt) => {
                        since_ping = Instant::now();
                        if let Err(e) = tr.write(&pkt, WRITE_TIMEOUT) {
                            log(&format!("[ВОРКЕР #{}] Ошибка Writer: {}", wid, e));
                            return;
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if since_ping.elapsed() >= KEEPALIVE_INTERVAL {
                            since_ping = Instant::now();
                            if tr.write(&ping, Duration::from_secs(5)).is_err() {
                                return;
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }
        })
    };

    let reader = {
        let tr = transport.clone();
        let sess_cancel = sess_cancel.clone();
        let cancel = cancel.clone();
        let return_tx = d.return_tx.clone();
        let wid = session_id;
        std::thread::spawn(move || {
            let _cancel_on_exit = CancelGuard(sess_cancel.clone());
            let mut buf = vec![0u8; READ_BUF_SIZE + 96];
            let mut silence = Duration::ZERO;
            loop {
                if sess_cancel.load(Ordering::Relaxed) || cancel.load(Ordering::Relaxed) {
                    return;
                }
                match tr.read(&mut buf, Duration::from_millis(500)) {
                    Ok(0) => {
                        log(&format!("[ВОРКЕР #{}] [RECONNECT] Reader завершён: EOF", wid));
                        return;
                    }
                    Ok(n) => {
                        silence = Duration::ZERO;
                        if n == 1 && buf[0] == KEEPALIVE_BYTE {
                            continue;
                        }
                        if !try_send_or_cancel(&return_tx, buf[..n].to_vec(), &sess_cancel) {
                            return;
                        }
                    }
                    Err(e)
                        if e.kind() == ErrorKind::WouldBlock
                            || e.kind() == ErrorKind::TimedOut =>
                    {
                        silence += Duration::from_millis(500);
                        if silence >= SESSION_READ_TIMEOUT {
                            // Тишина дольше sessionReadTimeout при работающих
                            // keepalive = пир мёртв («тихая» смерть: VPN-сервер
                            // исчез, TURN жив). Сессия пересоздастся.
                            log(&format!(
                                "[ВОРКЕР #{}] [RECONNECT] нет данных {:?} — сессия считается мёртвой, пересоздаю",
                                wid, SESSION_READ_TIMEOUT
                            ));
                            return;
                        }
                    }
                    Err(e) => {
                        log(&format!(
                            "[ВОРКЕР #{}] [RECONNECT] Reader завершён: {}",
                            wid, e
                        ));
                        return;
                    }
                }
            }
        })
    };

    // Читатель завершается по sess_cancel/cancel (≤0.5 с), писатель — по
    // sess_cancel (≤0.5 с) или по закрытию слота.
    let _ = reader.join();
    let _ = writer.join();
    d.unregister(&slot);
    drop(slot);
    transport.shutdown();
    log(&format!("[СЕССИЯ #{}] Завершена", session_id));
    (config_delivered, None)
}
