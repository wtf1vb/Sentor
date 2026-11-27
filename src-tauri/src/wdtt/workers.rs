// Пул воркеров — порт Go pwdttcore/worker_group.go.
//
// Группы по 9 воркеров с цепочкой сигналов между группами (креды/спавн):
// следующая группа стартует сразу после успешного GetCreds предыдущей
// (сигнал не зависит от DNS-резолва TURN — он нужен только для exclude-маршрутов).
// Каждый воркер: выбор TURN-адреса (round-robin с оффсетом, бан-лист),
// RunSession, failover по типу ошибки (ADDRESS_DEAD / WRAP_TIMEOUT / AUTH / FATAL).
//
// КОНТРАКТ СОСЕДНИХ МОДУЛЕЙ wdtt/ (порт Go, snake_case):
//   crate::wdtt::core::log(msg) — log.Printf → события ядра
//   crate::wdtt::session::run_session(...) — Go session.go RunSession
//   crate::wdtt::session::{SessionError, SessionErrorType}
//   crate::wdtt::dispatcher::Dispatcher — Go dispatcher.go
//   crate::wdtt::stats::Stats — Go stats.go
//   crate::wdtt::gate::AllocationGate::{new, wait} — Go allocation_gate.go
//   crate::wdtt::blacklist::{global_blacklist_is_banned(&str) -> bool,
//                            global_blacklist_ban(&str)} — Go blacklist.go GlobalBlacklist
//   crate::wdtt::vk::get_creds(cancel: &Arc<AtomicBool>, link: &str, stream_id: i32)
//       -> Result<(String /*user*/, String /*pass*/, Vec<String> /*turn urls*/), String>
//                                                — Go vk_auth.go GetCreds
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use super::core::log;
use super::dispatcher::Dispatcher;
use super::gate::AllocationGate;
use super::session::{run_session, SessionErrorType};
use super::stats::Stats;

pub const WORKERS_PER_GROUP: usize = 9;

// maxAttemptsPerAddress — сколько раз пробуем один адрес, прежде чем забанить
const MAX_ATTEMPTS_PER_ADDRESS: i32 = 3;
// sleepWhenAllBanned — сколько спим, если все адреса забанены
const SLEEP_WHEN_ALL_BANNED: Duration = Duration::from_secs(60);
// sleepAfterAddressDead — спим после того как адрес умер (перед переходом к следующему)
const SLEEP_AFTER_ADDRESS_DEAD: Duration = Duration::from_millis(500);
// workerStartDelay — задержка между запуском воркеров
const WORKER_START_DELAY: Duration = Duration::from_millis(200);
// workerBatchDelay — задержка между первой и второй волной воркеров (5 секунд)
const WORKER_BATCH_DELAY: Duration = Duration::from_secs(5);
// firstBatchSize — сколько воркеров запускаем в первой волне
const FIRST_BATCH_SIZE: usize = 5;
// configRacerLimit bounds concurrent initial config requests. The first
// racers are assigned different TURN URLs whenever enough URLs exist.
const CONFIG_RACER_LIMIT: usize = 3;

// TurnParams — параметры туннеля для всех воркеров ядра.
#[allow(dead_code)] // wrap_key/tcp_transport нужны только DTLS-пути (TODO(DTLS))
pub struct TurnParams {
    pub host: String,
    pub port: String,
    pub hashes: Vec<String>,
    pub wrap_key: Vec<u8>,
    pub obfs_mode: String,
    pub tcp_transport: bool,
    pub allocate_gate: Arc<AllocationGate>,
}

// SpawnSignal — порт Go `close(ch)`-сигнала между группами: ровно один
// close() на любом пути выхода. Clone нужен, чтобы close() мог уйти в
// фоновый поток (сигнал creds через 2 с).
#[derive(Clone)]
pub struct SpawnSignal {
    inner: Arc<SpawnInner>,
}
struct SpawnInner {
    fired: AtomicBool,
    tx: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}
impl SpawnSignal {
    pub fn new(tx: std::sync::mpsc::Sender<()>) -> SpawnSignal {
        SpawnSignal {
            inner: Arc::new(SpawnInner { fired: AtomicBool::new(false), tx: Mutex::new(Some(tx)) }),
        }
    }
    // signal_once — закрыть канал (получатель увидит Disconnected).
    pub fn signal_once(&self) {
        if !self.inner.fired.swap(true, Ordering::SeqCst) {
            *self.inner.tx.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }
}

// TurnIpsSlot — порт Go turnIPsCh (chan []string, cap 1): первая группа кладёт
// резолвы TURN-хостов, ядро ждёт их до 4 с после прихода конфига.
#[derive(Clone)]
pub struct TurnIpsSlot {
    inner: Arc<(Mutex<Option<Vec<String>>>, std::sync::Condvar)>,
}
impl TurnIpsSlot {
    pub fn new() -> TurnIpsSlot {
        TurnIpsSlot { inner: Arc::new((Mutex::new(None), std::sync::Condvar::new())) }
    }
    pub fn set(&self, ips: Vec<String>) {
        let (m, cv) = &*self.inner;
        *m.lock().unwrap_or_else(|e| e.into_inner()) = Some(ips);
        cv.notify_all();
    }
    pub fn wait_take(&self, timeout: Duration) -> Option<Vec<String>> {
        let (m, cv) = &*self.inner;
        let deadline = Instant::now() + timeout;
        let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(v) = g.take() {
                return Some(v);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            // poison-safe: паника другого потока не должна ронять ожидающего
            let (g2, _) = cv.wait_timeout(g, deadline - now).unwrap_or_else(|e| e.into_inner());
            g = g2;
        }
    }
}
impl Default for TurnIpsSlot {
    fn default() -> Self {
        TurnIpsSlot::new()
    }
}

// wait_signal — порт Go select { <-waitCh; <-ctx.Done() }:
// true = канал закрыт (сигнал получен), false = отмена.
pub fn wait_signal(w: &Receiver<()>, cancel: &Arc<AtomicBool>) -> bool {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        match w.try_recv() {
            Ok(_) | Err(TryRecvError::Disconnected) => return true,
            Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

// sleep_cancelable — порт Go select { <-time.After(d); <-ctx.Done() }:
// true = доспали полностью, false = отмена.
pub fn sleep_cancelable(d: Duration, cancel: &Arc<AtomicBool>) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !cancel.load(Ordering::Relaxed)
}

struct Creds {
    user: String,
    pass: String,
    urls: Vec<String>,
}

// fetch_creds_into — порт Go fetchCreds-замыкания группы.
fn fetch_creds_into(
    cancel: &Arc<AtomicBool>,
    hash: &str,
    stream_id: i32,
    creds: &RwLock<Creds>,
) -> Result<(), String> {
    let (u, p, urls) = super::vk::get_creds(cancel, hash, stream_id)?;
    *creds.write().unwrap() = Creds { user: u, pass: p, urls };
    Ok(())
}

// WorkerGroup — порт Go WorkerGroup.
#[allow(clippy::too_many_arguments)]
pub fn worker_group(
    cancel: &Arc<AtomicBool>,
    group_id: usize,
    hash_index: usize,
    tp: Arc<TurnParams>,
    peer: SocketAddr,
    d: Arc<Dispatcher>,
    local_port: String,
    get_config: bool,
    config_ch: Option<SyncSender<String>>,
    turn_ips_ch: Option<TurnIpsSlot>,
    worker_ids: Vec<i32>,
    pause_flag: Arc<AtomicBool>,
    device_id: String,
    password: String,
    stats: Arc<Stats>,
    wait_creds: Option<Receiver<()>>,
    signal_creds: Option<SpawnSignal>,
    wait_spawn: Option<Receiver<()>>,
    signal_spawn: Option<SpawnSignal>,
) {
    // signal_spawn_once гарантирует ровно один close(signal_spawn) на любом пути выхода
    let signal_spawn_once = |s: &Option<SpawnSignal>| {
        if let Some(x) = s {
            x.signal_once();
        }
    };

    if let Some(w) = &wait_creds {
        if !wait_signal(w, cancel) {
            signal_spawn_once(&signal_spawn);
            return;
        }
    }

    // Сигнал следующей группе не должен зависеть от успешности GetCreds ниже:
    // иначе один transient-фейл VK API навсегда блокирует все последующие группы
    if let Some(sc) = &signal_creds {
        let sc = sc.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(2));
            sc.signal_once();
        });
    }

    let config_sent = Arc::new(AtomicI32::new(if get_config { 0 } else { 1 }));

    while pause_flag.load(Ordering::Relaxed) {
        if cancel.load(Ordering::Relaxed) {
            signal_spawn_once(&signal_spawn);
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    if let Some(w) = &wait_spawn {
        if !wait_signal(w, cancel) {
            signal_spawn_once(&signal_spawn);
            return;
        }
    }

    if tp.hashes.is_empty() {
        // start() валидирует список, но WorkerGroup — пакетная точка входа:
        // будущий вызов с пустым списком паниковал бы на hashIndex%0
        log(&format!("[ГРУППА #{}] нет хешей VK-звонков — группа не запущена", group_id));
        signal_spawn_once(&signal_spawn);
        return;
    }
    let n_hashes = tp.hashes.len();
    let mut hash = tp.hashes[hash_index % n_hashes].clone();
    let short_hash = |h: &str| -> String { h.chars().take(8).collect() };
    log(&format!(
        "[ГРУППА #{}] Запрос кредов (хеш: {}..., {}/{})",
        group_id,
        short_hash(&hash),
        hash_index % n_hashes + 1,
        n_hashes
    ));

    let cred_stream_id = (group_id * 100) as i32;

    let creds = Arc::new(RwLock::new(Creds { user: String::new(), pass: String::new(), urls: Vec::new() }));
    let refresh_mu = Arc::new(Mutex::new(()));
    let cred_gen = Arc::new(AtomicU64::new(0));

    // Первичное получение кредов — с ретраями, а не один фейл навсегда.
    // Ротация хеша при неудаче: 954/951 = звонок по этому хешу неактивен
    // (ссылка устарела/звонок завершён) — у другого хеша звонок может быть
    // жив. С одним хешем ротация сводится к повтору того же.
    let mut attempt: u32 = 1;
    loop {
        match fetch_creds_into(cancel, &hash, cred_stream_id, &creds) {
            Ok(()) => break,
            Err(e) => {
                log(&format!("[ГРУППА #{}] Ошибка кредов (попытка {}): {}", group_id, attempt, e));
                if n_hashes > 1 {
                    let next = (hash_index as usize + attempt as usize) % n_hashes;
                    hash = tp.hashes[next].clone();
                    log(&format!(
                        "[ГРУППА #{}] Хеш {} из {} не дал кредов — пробую следующий: {}...",
                        group_id,
                        (hash_index as usize + attempt as usize - 1) % n_hashes + 1,
                        n_hashes,
                        short_hash(&hash)
                    ));
                }
            }
        }
        attempt += 1;
        if !sleep_cancelable(Duration::from_secs(5), cancel) {
            signal_spawn_once(&signal_spawn);
            return;
        }
    }

    {
        let c = creds.read().unwrap();
        log(&format!(
            "[ГРУППА #{}] Креды OK, TURN: {:?}, {} воркеров",
            group_id,
            c.urls,
            worker_ids.len()
        ));
    }

    // Спавним следующую группу СРАЗУ после успешного получения кредов: раньше
    // сигнал уходил только после DNS-резолва TURN-хостов, и медленный DNS
    // задерживал старт всех последующих групп. Резолв — только для
    // exclude-routes, критическим путём не является.
    signal_spawn_once(&signal_spawn);

    // Отправляем TURN IP для exclude routes (только первая группа) — в фоне
    if group_id == 1 {
        if let Some(slot) = &turn_ips_ch {
            let urls = creds.read().unwrap().urls.clone();
            if !urls.is_empty() {
                let tp2 = tp.clone();
                let cancel2 = cancel.clone();
                let slot2 = slot.clone();
                std::thread::spawn(move || {
                    let mut turn_ips: Vec<String> = Vec::new();
                    for url in urls {
                        if cancel2.load(Ordering::Relaxed) {
                            return;
                        }
                        let mut host = match url.rsplit_once(':') {
                            Some((h, _)) => h.trim_start_matches('[').trim_end_matches(']').to_string(),
                            None => url.clone(),
                        };
                        if !tp2.host.is_empty() {
                            host = tp2.host.clone();
                        }
                        // S21: резолв через собственный DNS-резолвер; пустой
                        // результат — оставляем голый хост (как раньше при
                        // ошибке системного резолва)
                        let ips = super::dns::resolve_host(&host);
                        if ips.is_empty() {
                            turn_ips.push(host.clone());
                        } else {
                            for a in ips {
                                turn_ips.push(a.ip().to_string());
                            }
                        }
                    }
                    // Дедупликация
                    let mut seen: HashSet<String> = HashSet::new();
                    let unique: Vec<String> =
                        turn_ips.into_iter().filter(|ip| seen.insert(ip.clone())).collect();
                    slot2.set(unique);
                });
            }
        }
    }

    // Запускаем воркеры с поэтапной задержкой
    let mut handles = Vec::new();
    for (idx, wid) in worker_ids.iter().enumerate() {
        let wid = *wid;
        // Определяем задержку перед запуском этого воркера
        let start_delay = if idx < FIRST_BATCH_SIZE {
            // Первая волна: 5 воркеров с задержкой 200ms
            WORKER_START_DELAY * idx as u32
        } else {
            // Вторая волна: первая волна + 5 секунд + (индекс во второй волне) * 200ms
            WORKER_START_DELAY * FIRST_BATCH_SIZE as u32
                + WORKER_BATCH_DELAY
                + WORKER_START_DELAY * (idx - FIRST_BATCH_SIZE) as u32
        };

        let tp2 = tp.clone();
        let d2 = d.clone();
        let cancel2 = cancel.clone();
        let pause2 = pause_flag.clone();
        let creds2 = creds.clone();
        let refresh2 = refresh_mu.clone();
        let gen2 = cred_gen.clone();
        let stats2 = stats.clone();
        let sent2 = config_sent.clone();
        let cc = config_ch.clone();
        let dev = device_id.clone();
        let pass = password.clone();
        let lp = local_port.clone();
        let hash2 = hash.clone();

        handles.push(std::thread::spawn(move || {
            // Ждём свою задержку перед стартом
            if !sleep_cancelable(start_delay, &cancel2) {
                return;
            }
            worker_loop(
                &cancel2,
                wid,
                idx,
                &tp2,
                peer,
                &d2,
                &lp,
                get_config,
                cc.as_ref(),
                &sent2,
                &pause2,
                &creds2,
                &refresh2,
                &gen2,
                cred_stream_id,
                &hash2,
                &dev,
                &pass,
                &stats2,
            );
        }));
    }

    signal_spawn_once(&signal_spawn);

    for h in handles {
        // паника воркера не должна уходить молча
        if let Err(p) = h.join() {
            log(&format!("[ГРУППА #{}] Воркер запаниковал: {}", group_id, super::panic_msg(&p)));
        }
    }
    log(&format!("[ГРУППА #{}] Все воркеры группы завершились.", group_id));
}

// worker_loop — тело одного воркера (порт Go go func(wid, workerIndex...)).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::fn_params_excessive_bools)]
fn worker_loop(
    cancel: &Arc<AtomicBool>,
    wid: i32,
    worker_index: usize,
    tp: &Arc<TurnParams>,
    peer: SocketAddr,
    d: &Arc<Dispatcher>,
    local_port: &str,
    should_get_config: bool,
    config_ch: Option<&SyncSender<String>>,
    config_sent: &AtomicI32,
    pause_flag: &Arc<AtomicBool>,
    creds: &Arc<RwLock<Creds>>,
    refresh_mu: &Arc<Mutex<()>>,
    cred_gen: &Arc<AtomicU64>,
    cred_stream_id: i32,
    hash: &str,
    device_id: &str,
    password: &str,
    stats: &Arc<Stats>,
) {
    // Retry state is local to this worker, avoiding synchronized storms.
    let mut address_attempts: i32 = 0;
    let mut relay_offset: usize = 0;
    let mut last_turn_addr = String::new();
    let mut auth_refresh_fails: i32 = 0; // подряд неудачных обновлений кредов (для бэкоффа)
    // Храним текущий ObfsMode для этого воркера (может меняться при WRAP_TIMEOUT)
    let mut worker_obfs_mode = tp.obfs_mode.clone();

    loop {
        if cancel.load(Ordering::Relaxed) {
            return;
        }

        // Проверяем паузу
        while pause_flag.load(Ordering::Relaxed) {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        // Берём свежие креды (могут быть обновлены после AUTH-ошибки)
        let (urls, w_user, w_pass, gen) = {
            let c = creds.read().unwrap();
            (c.urls.clone(), c.user.clone(), c.pass.clone(), cred_gen.load(Ordering::SeqCst))
        };

        if urls.is_empty() {
            log(&format!("[ВОРКЕР #{}] Нет TURN-адресов в кредах", wid));
            if !sleep_cancelable(Duration::from_secs(5), cancel) {
                return;
            }
            continue;
        }

        // Spread workers deterministically over relays and advance after a
        // failed relay instead of converging on urls[0].
        let turn_addr = match select_turn_url(&urls, wid, relay_offset, &|a: &str| {
            super::blacklist::global_blacklist_is_banned(a)
        }) {
            Some(u) => u,
            None => {
                log(&format!(
                    "[ВОРКЕР #{}] Все TURN-адреса забанены (всего {}), спим {:?}",
                    wid,
                    urls.len(),
                    SLEEP_WHEN_ALL_BANNED
                ));
                if !sleep_cancelable(SLEEP_WHEN_ALL_BANNED, cancel) {
                    return;
                }
                continue;
            }
        };

        if turn_addr != last_turn_addr {
            address_attempts = 0;
            last_turn_addr = turn_addr.clone();
        }

        // A few workers race for config on round-robin-selected relays. This
        // prevents one silent relay from blocking startup without starting a
        // config request from every worker.
        let get_conf =
            should_race_for_config(should_get_config, worker_index, config_sent.load(Ordering::SeqCst));
        let cc = if get_conf { config_ch } else { None };

        // Передаём в RunSession конкретный адрес и креды
        let (config_delivered, sess_err) = run_session(
            cancel, tp, peer, d, local_port, get_conf, cc, wid, &turn_addr, &w_user, &w_pass,
            &worker_obfs_mode, cred_stream_id, device_id, password, stats,
        );

        if get_conf && config_delivered {
            config_sent.store(1, Ordering::SeqCst);
        }

        // Обработка ошибок
        if let Some(err) = sess_err {
            if cancel.load(Ordering::Relaxed) {
                return;
            }

            log(&format!(
                "[ВОРКЕР #{}] [FAILOVER] Сбой сессии: {} (адрес={}, тип={})",
                wid,
                err.err,
                err.address,
                err.kind.as_str()
            ));

            match err.kind {
                SessionErrorType::AddressDead => {
                    // Адрес мёртв — баним и пробуем следующий
                    if !err.address.is_empty() {
                        super::blacklist::global_blacklist_ban(&err.address);
                        log(&format!(
                            "[ВОРКЕР #{}] TURN-адрес {} забанен на 5 минут",
                            wid, err.address
                        ));
                    }
                    relay_offset += 1;
                    address_attempts = 0;
                    // Небольшая пауза перед переходом к следующему адресу
                    if !sleep_cancelable(SLEEP_AFTER_ADDRESS_DEAD, cancel) {
                        return;
                    }
                    // Продолжаем цикл — возьмём следующий доступный адрес
                    continue;
                }

                SessionErrorType::WrapTimeout => {
                    // DTLS-таймаут — пробуем сменить обфускацию.
                    // Режим пер-воркерский: глобальная перезапись tp.ObfsMode
                    // была гонкой и меняла режим у всех живых сессий
                    log(&format!(
                        "[ВОРКЕР #{}] WRAP_TIMEOUT на адресе {}, пробуем сменить обфускацию",
                        wid, err.address
                    ));

                    // Меняем режим обфускации
                    worker_obfs_mode = if worker_obfs_mode == "audio" {
                        "video".into()
                    } else {
                        "audio".into()
                    };
                    log(&format!(
                        "[ВОРКЕР #{}] Режим обфускации изменён на {}",
                        wid, worker_obfs_mode
                    ));

                    // Увеличиваем счётчик попыток на этом адресе
                    address_attempts += 1;

                    // Если слишком много попыток на одном адресе — баним его
                    if address_attempts >= MAX_ATTEMPTS_PER_ADDRESS {
                        if !err.address.is_empty() {
                            super::blacklist::global_blacklist_ban(&err.address);
                            log(&format!(
                                "[ВОРКЕР #{}] TURN-адрес {} забанен после {} попыток",
                                wid, err.address, address_attempts
                            ));
                        }
                        address_attempts = 0;
                        relay_offset += 1;
                        // Продолжаем цикл — возьмём следующий адрес
                        continue;
                    }

                    // Пробуем тот же адрес с новой обфускацией
                    continue;
                }

                SessionErrorType::Auth => {
                    // Креды протухли (401) — обновляем и продолжаем.
                    // handle_auth_error (Go handleAuthError) ведёт счёт ошибок
                    // кэша: после 3 ошибок за 10 с кэш инвалидируется. Без него
                    // refetch ниже возвращал те же битые кэшированные креды
                    // до конца TTL (9 минут) — ревокация кредов ломала все
                    // стримы кэша.
                    if super::vk::handle_auth_error(cred_stream_id) {
                        log(&format!(
                            "[ВОРКЕР #{}] Кэш кредов инвалидирован после серии auth-ошибок",
                            wid
                        ));
                    }
                    // Обновляет только один воркер: остальные увидят новый credGen
                    log(&format!(
                        "[ВОРКЕР #{}] Ошибка авторизации TURN, обновляю креды",
                        wid
                    ));
                    // ctx-aware захват: fetch висит (сеть/капча-лок) — другие
                    // воркеры группы не должны стоять на мьютексе неопределённо
                    let guard = loop {
                        if let Ok(g) = refresh_mu.try_lock() {
                            break g;
                        }
                        if cancel.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    };
                    let current_gen = cred_gen.load(Ordering::SeqCst);
                    if current_gen == gen {
                        match fetch_creds_into(cancel, hash, cred_stream_id, creds) {
                            Ok(()) => {
                                cred_gen.fetch_add(1, Ordering::SeqCst);
                                log(&format!("[ВОРКЕР #{}] Креды обновлены", wid));
                                auth_refresh_fails = 0;
                            }
                            Err(e) => {
                                log(&format!(
                                    "[ВОРКЕР #{}] Не удалось обновить креды: {}",
                                    wid, e
                                ));
                                auth_refresh_fails += 1;
                            }
                        }
                    }
                    drop(guard);
                    // Нарастающий backoff: при устойчиво невалидном хеше каждый
                    // воркер группы каждые ~2 с гонял полную цепочку VK API,
                    // штампуя запросы и CAPTCHA-локи. 4→64 с при серии фейлов.
                    let mut backoff = Duration::from_secs(2);
                    if auth_refresh_fails > 1 {
                        let shift = (auth_refresh_fails - 1).min(5);
                        backoff = Duration::from_secs(2u64 << shift);
                    }
                    if !sleep_cancelable(backoff, cancel) {
                        return;
                    }
                    continue;
                }

                SessionErrorType::Fatal => {
                    // Фатальная ошибка — выходим
                    log(&format!("[ВОРКЕР #{}] Фатальная ошибка: {}", wid, err.err));
                    return;
                }
            }
        }

        // Успех — сбрасываем счётчики
        address_attempts = 0;

        // После успешной сессии — небольшая пауза перед следующим циклом
        if !sleep_cancelable(Duration::from_millis(100), cancel) {
            return;
        }
    }
}

// shouldRaceForConfig — первые CONFIG_RACER_LIMIT воркеров группы гонят конфиг.
pub fn should_race_for_config(enabled: bool, worker_index: usize, config_sent: i32) -> bool {
    enabled && config_sent == 0 && worker_index < CONFIG_RACER_LIMIT
}

// normalizeWorkers — кратность девяти, границы 9..=108.
pub fn normalize_workers(n: usize) -> usize {
    let mut n = n;
    if n > 108 {
        n = 108;
    }
    if n < WORKERS_PER_GROUP {
        n = WORKERS_PER_GROUP;
    }
    (n / WORKERS_PER_GROUP) * WORKERS_PER_GROUP
}

// selectTurnURL assigns workers round-robin and skips currently banned relays.
pub fn select_turn_url(
    urls: &[String],
    worker_id: i32,
    offset: usize,
    is_banned: &dyn Fn(&str) -> bool,
) -> Option<String> {
    if urls.is_empty() {
        return None;
    }
    let len = urls.len();
    let start = ((worker_id as i64 - 1 + offset as i64).rem_euclid(len as i64)) as usize;
    for i in 0..len {
        let u = &urls[(start + i) % len];
        if !is_banned(u) {
            return Some(u.clone());
        }
    }
    None
}

// ParseHashes — хеши из «сырого» текста (запятые/переводы строк/пробелы),
// с нормализацией и дедупликацией.
#[allow(dead_code)] // дубль pwdtt_hash_list + normalize; используется тестами
pub fn parse_hashes(raw: &str) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for h in raw.split(|r: char| r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' ')
    {
        let h = normalize_vk_join_hash(h);
        if !h.is_empty() && seen.insert(h.clone()) {
            result.push(h);
        }
    }
    result
}

// normalizeVKJoinHash — вытащить чистый хеш из ссылки/строки.
//
// РЕГИСТР СОХРАНЯЕТСЯ: хеш VK-звонка регистрозависим — VK API отвечает
// error 954 «call is unavailable» на хеш, приведённый к нижнему регистру
// (в CSQTT хеш шлётся как есть и работает на том же ключе). В lowercase
// опускается только копия для поиска префикса ссылки; сами префиксы ASCII,
// поэтому индексы в оригинале и копии совпадают.
pub fn normalize_vk_join_hash(input: &str) -> String {
    let s = input.trim().trim_matches(|c| c == '<' || c == '>' || c == '"' || c == '\'');
    if s.is_empty() {
        return String::new();
    }
    let low = s.to_lowercase();
    let s = if let Some(idx) = low.find("/call/join/") {
        &s[idx + "/call/join/".len()..]
    } else if low.starts_with("http://") || low.starts_with("https://") {
        // ссылка без /call/join/ — не хеш VK-звонка
        return String::new();
    } else {
        s
    };
    let s = match s.find(|c: char| c == '?' || c == '#' || c == '/') {
        Some(idx) => &s[..idx],
        None => s,
    };
    s.trim().trim_matches('/').to_string()
}
