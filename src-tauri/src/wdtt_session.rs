// WDTT-менеджер сессии — драйв ВНЕШНЕГО ядра wdtt-core.exe.
//
// Собственный Rust-клиент (модуль wdtt/) остался в репо как референс, но
// транспорт (TURN Allocate + DTLS через pion) в нём не реализован — GETCONF
// уходил голым текстом в TCP-порт релея и всегда давал read timeout, из-за
// чего wg_config не приходил и wintun-адаптер не поднимался. Теперь сессию
// ведёт вшитое ядро wdtt-core.exe (client/core из ildarmaga/pwdtt-client,
// GPL-3, + головная обёртка cmd/wdtt-core: JSON-строки в stdout, команды в
// stdin). Ядро само делает VK-авторизацию, TURN-аллокацию, DTLS-рукопожатие
// и GETCONF; wg_config (INI) прилетает событием и превращается в sing-box
// конфиг (tun + wireguard endpoint → 127.0.0.1:19001, где слушает ядро) —
// мост TUN↔ядро делает сам sing-box своим WG-outbound, отдельный UDP-релей
// в Rust не нужен.
//
// Состояние публикуется событием «pwdttState» (снимок PwdttStatusInfo), строки
// лога — «pwdttLog» (кортеж (level, message)); кольцевой буфер 400 строк
// + файл toolsDir\wdtt\session.log. Капча решается авто-режимами ядра
// (auto/rjs/wv); ручной ввод — send_captcha (stdin {"cmd":"captcha"}).
//
// При Stop — stdin {"cmd":"stop"} + kill через 6 с (Job Object с
// KILL_ON_JOB_CLOSE убирает сирот при падении Sentor).
//
// ИНТЕГРАЦИЯ: при старте приложения нужно один раз вызвать
// wdtt_session::set_app_handle(app.app_handle().clone()), иначе события
// «pwdttState»/«pwdttLog» не уйдут во фронтенд, а stop основного VPN будет
// недоступен. Экспортируемые функции для commands.rs: connect / disconnect /
// status / log_text / import_link_impl / send_captcha / shutdown /
// startup_cleanup.
use std::io::{BufRead, BufReader, Read};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager};

use crate::logging::log_add;
use crate::models::{PwdttServer, PwdttStatusInfo};
use crate::paths;
use crate::store;

pub const PWDTT_IFACE: &str = "pwdtt-wg";
const LOG_LINES_MAX: usize = 400;

// ---------- ссылка на приложение ----------

static APP: OnceLock<AppHandle> = OnceLock::new();

// set_app_handle — вызвать один раз в setup() приложения.
pub fn set_app_handle(app: AppHandle) {
    let _ = APP.set(app);
}

fn app() -> Option<&'static AppHandle> {
    APP.get()
}

// ---------- состояние менеджера (Go pwdttMu + глобальные переменные) ----------

struct WdttInner {
    running: bool,
    // «Отключить»/выход попали в окно старта connect (running=true, ядро ещё
    // не в g.core): connect проверяет флаг после запуска ядра и гасит его.
    stop_requested: bool,
    session: u64,
    state: PwdttStatusInfo,
    log_lines: Vec<String>,
    log_file: Option<std::fs::File>,
    core: Option<Arc<CoreProc>>,
}

static WDTT: Mutex<WdttInner> = Mutex::new(WdttInner {
    running: false,
    stop_requested: false,
    session: 0,
    state: PwdttStatusInfo {
        running: false,
        phase: String::new(),
        name: String::new(),
        id: None,
        since: 0,
        active: 0,
        bytes_up: 0,
        bytes_down: 0,
        error: None,
    },
    log_lines: Vec::new(),
    log_file: None,
    core: None,
});

// pwdttEmitState — снапшот состояния во фронтенд.
fn pwdtt_emit_state() {
    let st = {
        let g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
        let mut st = g.state.clone();
        st.running = g.running;
        st
    };
    if let Some(a) = app() {
        let _ = a.emit("pwdttState", &st);
    }
}

// ---------- внешний процесс ядра wdtt-core.exe ----------

// Локальный UDP-порт ядра: sing-box шлёт WG-пакеты на этот endpoint
// (wg_config приходит с Endpoint = этот адрес), отдельный мост в Rust не нужен.
const PWDTT_CORE_LISTEN: &str = "127.0.0.1:19001";

// CoreProc — живой процесс wdtt-core.exe. stdin для команд (капча/tun_ready/
// stop), stdout читает поток событий, stderr — WARN-лог. Child под Mutex:
// kill из потоков (disconnect-watchdog, finalize) без гонок.
struct CoreProc {
    child: Mutex<std::process::Child>,
    stdin: Mutex<Option<std::process::ChildStdin>>,
    // Job Object с KILL_ON_JOB_CLOSE: держим открытым — сирота умирает при
    // крахе Sentor; дескриптор не читается, закрывается в Drop.
    #[allow(dead_code)]
    job: Option<crate::conn::JobHandle>,
}

impl CoreProc {
    // command — JSON-строка команды в stdin ядра ({"cmd":"captcha"|"tun_ready"|"stop"}).
    fn command(&self, line: &str) {
        if let Ok(mut g) = self.stdin.lock() {
            if let Some(w) = g.as_mut() {
                use std::io::Write;
                let _ = writeln!(w, "{}", line);
                let _ = w.flush();
            }
        }
    }

    fn kill_force(&self) {
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn alive(&self) -> bool {
        match self.child.lock() {
            Ok(mut c) => c.try_wait().map(|x| x.is_none()).unwrap_or(false),
            Err(_) => false,
        }
    }
}

// ensure_wdtt_core — распаковка вшитого ядра рядом с конфигом (как ensure_core
// у CSQTT). Содержимое сверяем по размеру + байтам, чтобы частично скопированный
// файл прошлого запуска не подменил рабочее ядро.
fn ensure_wdtt_core(tools: &Path) -> Result<PathBuf, String> {
    let dir = paths::pwdtt_dir(tools);
    std::fs::create_dir_all(&dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
    let exe = dir.join("wdtt-core.exe");
    let Some(blob) = crate::tools::embedded("wdtt-core.exe") else {
        return Err("вшитый wdtt-core.exe не найден".into());
    };
    let ok = std::fs::metadata(&exe)
        .map(|st| st.len() == blob.len() as u64)
        .unwrap_or(false)
        && crate::tools::blob_matches(&exe, blob);
    if !ok {
        std::fs::write(&exe, blob).map_err(|e| format!("не записать ядро: {}", e))?;
    }
    Ok(exe)
}

// ensure_wdtt_wg — распаковка хелпера wdtt-wg.exe + wintun.dll рядом
// (wireguard-go грузит wintun.dll из каталога процесса, см. win_wg.go:68).
fn ensure_wdtt_wg(dir: &Path) -> Result<PathBuf, String> {
    let exe = dir.join("wdtt-wg.exe");
    let Some(blob) = crate::tools::embedded("wdtt-wg.exe") else {
        return Err("вшитый wdtt-wg.exe не найден".into());
    };
    let ok = std::fs::metadata(&exe)
        .map(|st| st.len() == blob.len() as u64)
        .unwrap_or(false)
        && crate::tools::blob_matches(&exe, blob);
    if !ok {
        std::fs::write(&exe, blob).map_err(|e| format!("не записать хелпер: {}", e))?;
    }
    let dll = dir.join("wintun.dll");
    let Some(dll_blob) = crate::tools::embedded("wintun.dll") else {
        return Err("вшитый wintun.dll не найден".into());
    };
    let ok = std::fs::metadata(&dll)
        .map(|st| st.len() == dll_blob.len() as u64)
        .unwrap_or(false)
        && crate::tools::blob_matches(&dll, dll_blob);
    if !ok {
        std::fs::write(&dll, dll_blob).map_err(|e| format!("не записать wintun.dll: {}", e))?;
    }
    Ok(exe)
}

// ---------- память о TURN-релеях между сессиями ----------
//
// Ядро учит здоровье релеев только внутри своего процесса (relay_health.go:
// карта пуста на старте → непроверенный релей получает дефолтный score, а
// проверенный — штраф за медленный RTT; вся волна воркеров бьёт в один релей,
// даже если в прошлой сессии он был мёртв — 28 с DTLS-таймаутов на каждого).
// Ядро поддерживает приоритет через env WDTT_PREFERRED_RELAYS
// (relay_health.go: relayPreferenceBonus, +10000 к score) — выученное пишем
// в relays.json и передаём при запуске ядра.

const RELAY_DEAD_TTL_SECS: u64 = 30 * 60; // через полчаса релею дают шанс ре-теста

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct RelayMemory {
    /// Релей-хосты, выданные VK в прошлых сессиях (кандидаты).
    #[serde(default)]
    candidates: Vec<String>,
    /// Хост → unix-секунды последней зафиксированной смерти.
    #[serde(default)]
    dead: std::collections::HashMap<String, u64>,
}

fn relay_memory_path() -> PathBuf {
    paths::pwdtt_dir(&paths::find_tools_dir()).join("relays.json")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// relay_memory_update — load → правка → save под одним локом (события turn_ips
// и RELAY-строки могут прийти почти одновременно из одного потока stdout).
fn relay_memory_update(f: impl FnOnce(&mut RelayMemory)) {
    static LOCK: Mutex<()> = Mutex::new(());
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = relay_memory_path();
    let mut mem = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<RelayMemory>(&b).ok())
        .unwrap_or_default();
    f(&mut mem);
    if let Ok(json) = serde_json::to_vec_pretty(&mem) {
        let _ = std::fs::write(&path, json);
    }
}

// relay_memory_note_candidates — событие turn_ips: запоминаем кандидатов VK
// (порядок как пришёл — он же порядок приоритета в env).
fn relay_memory_note_candidates(list: &[String]) {
    relay_memory_update(|mem| {
        for ip in list {
            if !mem.candidates.iter().any(|c| c == ip) {
                mem.candidates.push(ip.clone());
            }
        }
        // умершие кандидаты, которых VK больше не выдаёт, — выносим из списка
        mem.candidates.retain(|c| list.contains(c) || !mem.dead.contains_key(c));
    });
}

// relay_log_death — смерть релея из строки лога ядра (core/session.go:244):
// «[RELAY] воркер #N host=IP ... err=...» и «... (не дошёл до READY)» — смерть
// релея; «... завершён» — нормальное завершение, здоровье не трогаем.
// «context canceled» — отмена нашей же остановкой (disconnect/stop): хендшейк
// воркера прерван, релей жив. Без фильтра каждый такой Stop помечал релей
// мёртвым на 30 минут и Preference-список следующего коннекта пустел.
fn relay_log_death(msg: &str) -> Option<String> {
    if !msg.contains("RELAY") {
        return None;
    }
    if msg.contains("context canceled") {
        return None;
    }
    if !(msg.contains("err=") || msg.contains("не дошёл")) {
        return None;
    }
    first_ipv4(msg)
}

fn relay_memory_note_log(msg: &str) {
    if let Some(ip) = relay_log_death(msg) {
        relay_memory_update(|mem| {
            mem.dead.insert(ip, unix_now());
            mem.dead.retain(|_, t| unix_now().saturating_sub(*t) < 24 * 3600);
        });
    }
}

// relay_memory_preferred — приоритетные релеи для env ядра: кандидаты минус
// недавно умершие (свежесняет RELAY_DEAD_TTL_SECS; умерший вернётся в список
// через полчаса и 9-й воркер (cap 8 живых аллокаций на хост) пере-проверит его).
fn relay_memory_preferred() -> Vec<String> {
    static LOCK: Mutex<()> = Mutex::new(());
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mem = std::fs::read(relay_memory_path())
        .ok()
        .and_then(|b| serde_json::from_slice::<RelayMemory>(&b).ok())
        .unwrap_or_default();
    let now = unix_now();
    mem.candidates
        .into_iter()
        .filter(|ip| {
            mem.dead
                .get(ip)
                .map(|t| now.saturating_sub(*t) > RELAY_DEAD_TTL_SECS)
                .unwrap_or(true)
        })
        .collect()
}

// first_ipv4 — первый IPv4-адрес в строке лога («чost=» в paste пользователя —
// артефакт терминала, поэтому ищем сам адрес, а не ключ «host=»).
fn first_ipv4(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let mut j = i;
            let mut dots = 0;
            while j < b.len() && (b[j].is_ascii_digit() || b[j] == b'.') {
                if b[j] == b'.' {
                    dots += 1;
                }
                j += 1;
            }
            let cand = &s[i..j];
            let octets: Vec<&str> = cand.split('.').collect();
            if dots == 3
                && octets.len() == 4
                && octets
                    .iter()
                    .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
            {
                return Some(cand.to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

// pwdttLogAdd — строка в буфер + файл + событие «pwdttLog».
fn pwdtt_log_add(level: &str, msg: &str) {
    let msg = msg.trim();
    if msg.is_empty() {
        return;
    }
    let line = format!("{} [{}] {}", chrono::Local::now().format("%H:%M:%S"), level, msg);
    {
        let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
        g.log_lines.push(line.clone());
        if g.log_lines.len() > LOG_LINES_MAX {
            let cut = g.log_lines.len() - LOG_LINES_MAX;
            g.log_lines.drain(0..cut);
        }
        if let Some(f) = g.log_file.as_mut() {
            use std::io::Write;
            let _ = writeln!(f, "{}", line);
        }
    }
    if let Some(a) = app() {
        // Go: runtime.EventsEmit(ctx, "pwdttLog", level, msg)
        let _ = a.emit("pwdttLog", (level.to_string(), msg.to_string()));
    }
}

// PwdttLog — весь буфер текущей сессии одной строкой.
pub fn log_text() -> String {
    let g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
    g.log_lines.join("\n")
}

// PwdttStatus — снимок состояния (фронтенд опрашивает раз в полторы секунды).
pub fn status() -> PwdttStatusInfo {
    let g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
    let mut st = g.state.clone();
    st.running = g.running;
    st
}

// ---------- утилиты ----------

// pwdttHashList — хеши приходят построчно или через запятую. Каждый хеш
// прогоняем через normalize_vk_join_hash: полный URL (https://vk.com/call/join/…),
// кавычки и мусор раньше уезжали в «vk.com/call/join/https://vk.com/…» —
// VK API отвергал, GetCreds падал бесконечно.
pub fn pwdtt_hash_list(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for part in s.split(|r: char| r == ',' || r == '\n' || r == '\r' || r == ';') {
        let p = crate::wdtt::workers::normalize_vk_join_hash(part);
        if !p.is_empty() && seen.insert(p.clone()) {
            out.push(p);
        }
    }
    out
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

// net.SplitHostPort (v4/[v6]:port) — Go-паритет: «[v6]»/«[v6]:»/«host:» и
// голый IPv6 без скобок — ошибки, а не мусорный host/порт.
fn split_host_port(addr: &str) -> Result<(String, String), String> {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(rb) = rest.find(']') {
            return match rest[rb + 1..].strip_prefix(':') {
                Some(p) if !p.is_empty() => Ok((rest[..rb].to_string(), p.to_string())),
                _ => Err("missing port in address".into()),
            };
        }
        return Err("missing ']' in address".into());
    }
    match addr.rsplit_once(':') {
        // «2001:db8::1» без скобок раньше парсился как host «2001:db8:» +
        // порт «1», и резолв падал с враньём в диагностике
        Some((h, p)) if !h.contains(':') && !p.is_empty() => Ok((h.to_string(), p.to_string())),
        _ => Err("missing port in address".into()),
    }
}

// pwdttNormalizeServer — нормализация полей сервера.
pub fn pwdtt_normalize_server(s: &mut PwdttServer) {
    s.name = s.name.trim().to_string();
    s.peer = s.peer.trim().to_string();
    s.password = s.password.trim().to_string();
    if s.name.is_empty() {
        s.name = match split_host_port(&s.peer) {
            Ok((h, _)) => h,
            Err(_) => s.peer.clone(),
        };
    }
    if s.workers <= 0 {
        s.workers = 18;
    }
    if s.workers < 9 {
        s.workers = 9;
    }
    // верхняя граница: workers приходит из недоверенной ссылки qwdtt://,
    // «workers=999999» просил бы ~111 тыс. групп воркеров (исчерпание памяти)
    if s.workers > 72 {
        s.workers = 72;
    }
    s.workers -= s.workers % 9; // воркеры работают группами по девять
    let cm = s.captcha_mode.clone().unwrap_or_default();
    let cml = cm.trim().to_lowercase();
    s.captcha_mode = Some(match cml.as_str() {
        "rjs" | "wv" => cml,
        _ => "auto".into(),
    });
    let om = s.obfs_mode.clone().unwrap_or_default();
    s.obfs_mode = Some(if om == "video" { "video".into() } else { "audio".into() });
    let fp = s.fingerprint.clone().unwrap_or_default();
    let fpl = fp.trim().to_lowercase();
    s.fingerprint = Some(match fpl.as_str() {
        "android" | "ios" | "safari" | "firefox" => fpl,
        _ => "chrome".into(),
    });
    // DeviceID оставляем пустым по умолчанию: ядро шлёт "unknown", и именно
    // к нему wdtt-server привязывает пароль при первом подключении.
}

// pwdttParseLink — разбор wdtt://host:dtls:wg:proxy:pass[:hashes][#имя] и
// qwdtt://config?name=&peer=&pass=&hashes=&workers= (форматы PWDTT).
pub fn pwdtt_parse_link(link: &str) -> Result<PwdttServer, String> {
    let mut s = PwdttServer::default();
    let trimmed = link.trim();
    let low = trimmed.to_lowercase();
    if trimmed.is_empty() {
        return Err("ссылка пуста".into());
    }
    if low.starts_with("qwdtt://config?") {
        // url.ParseQuery: повторный ключ игнорируем, берём первый (Go Values.Get)
        let mut values: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for (k, v) in parse_query(&trimmed["qwdtt://config?".len()..]) {
            values.entry(k).or_insert(v);
        }
        s.name = values.get("name").map(|v| v.trim().to_string()).unwrap_or_default();
        s.peer = values.get("peer").map(|v| v.trim().to_string()).unwrap_or_default();
        s.password = values.get("pass").map(|v| v.trim().to_string()).unwrap_or_default();
        s.hashes = values
            .get("hashes")
            .map(|v| pwdtt_hash_list(v).join("\n"))
            .unwrap_or_default();
        if let Some(w) = values.get("workers") {
            if let Ok(n) = w.trim().parse::<i32>() {
                s.workers = n;
            }
        }
    } else if low.starts_with("wdtt://") {
        let mut rest = &trimmed["wdtt://".len()..];
        if let Some(i) = rest.rfind('#') {
            if let Ok(un) = percent_encoding::percent_decode_str(&rest[i + 1..]).decode_utf8() {
                s.name = un.trim().to_string();
            }
            rest = &rest[..i];
        }
        let fields: Vec<&str> = rest.split(':').collect();
        if fields.len() < 5 {
            return Err("формат wdtt://host:dtlsPort:wgPort:proxyPort:password[:hashes][#имя]".into());
        }
        let host = fields[0].trim();
        if host.is_empty() {
            return Err("в ссылке нет адреса сервера".into());
        }
        s.peer = join_host_port(host, fields[1].trim());
        s.password = fields[4].trim().to_string();
        s.hashes = pwdtt_hash_list(&fields[5..].join(":")).join("\n");
    } else {
        return Err("это не ссылка wdtt:// или qwdtt://config".into());
    }
    if s.peer.is_empty() || s.password.is_empty() {
        return Err("в ссылке нет адреса или пароля".into());
    }
    match split_host_port(&s.peer) {
        Ok((h, _)) if !h.is_empty() => {}
        _ => return Err("в ссылке неверный адрес сервера".into()),
    }
    Ok(s)
}

// parse_query — порт Go url.ParseQuery ('+' → пробел, %xx-декодирование).
fn parse_query(q: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let unescape = |x: &str| -> String {
            percent_encoding::percent_decode_str(&x.replace('+', " "))
                .decode_utf8()
                .map(|c| c.to_string())
                .unwrap_or_else(|_| x.to_string())
        };
        out.push((unescape(k), unescape(v)));
    }
    out
}

// PwdttImportLink — сервер из ссылки wdtt:// или qwdtt://config.
// Возвращает (имя, peer) добавленного сервера — сообщение формирует callers
// («✅ Добавлено из ссылки: {name} ({peer})»).
pub fn import_link_impl(link: &str) -> Result<(String, String), String> {
    let a = app().ok_or_else(|| "AppHandle не установлен".to_string())?;
    let state = a.state::<Arc<crate::state::AppState>>();
    let tools = state.tools();
    let mut s = pwdtt_parse_link(link)?;
    pwdtt_normalize_server(&mut s);
    let _guard = state.pwdtt_store.lock().unwrap_or_else(|e| e.into_inner());
    let list = store::load_pwdtt_servers(&tools);
    for x in &list {
        if x.peer == s.peer && x.password == s.password && x.hashes == s.hashes {
            return Err(format!("⚠️ Такой сервер уже есть: {}", x.name));
        }
    }
    s.id = uuid::Uuid::new_v4().to_string();
    let (name, peer) = (s.name.clone(), s.peer.clone());
    let mut list = list;
    list.push(s);
    store::save_pwdtt_servers(&tools, &list)
        .map_err(|e| format!("❌ Не удалось сохранить сервер: {}", e))?;
    Ok((name, peer))
}

// ---------- подключение ----------

// PwdttConnect — запуск туннеля к сохранённому серверу. Сервер загружен
// вызывающей стороной (CRUD в commands.rs). Успех = Ok(()) → вызывающий
// показывает «⏳ Подключаюсь: {server.name}».
pub fn connect(server: &PwdttServer) -> Result<(), String> {
    let sess = {
        let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
        if g.running {
            return Err("⚠️ WDTT уже запущен — сначала отключи".into());
        }
        // WARP — отдельный in-process туннель: два TUN одновременно подерутся за маршруты
        if crate::conn::warp_active() {
            return Err("⚠️ Сначала отключи WARP — два туннеля одновременно подерутся за маршруты".into());
        }
        // CSQTT — тоже TUN-туннель со split-маршрутами
        if crate::cqstt_session::running() {
            return Err("⚠️ Сначала отключи CSQTT — два туннеля одновременно подерутся за маршруты".into());
        }
        g.running = true;
        g.session += 1;
        g.session
    };
    let fail = |msg: String| -> String {
        {
            let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
            g.running = false;
            g.state = PwdttStatusInfo {
                running: false,
                phase: "disconnected".into(),
                name: String::new(),
                id: None,
                since: 0,
                active: 0,
                bytes_up: 0,
                bytes_down: 0,
                error: Some(msg.clone()),
            };
        }
        pwdtt_emit_state();
        msg
    };

    // Валидация сервера
    let hashes = pwdtt_hash_list(&server.hashes);
    if hashes.is_empty() {
        return Err(fail("⚠️ В сервере нет хешей VK — добавь хотя бы один".into()));
    }
    // Хеш VK-звонка регистрозависим: старый импорт приводил его к нижнему
    // регистру, и испорченное значение оставалось в pwdtt.json — VK отвечал
    // 954 «Invalid join link» на каждом подключении, хотя код уже правильный.
    // Печатаем хеши в консоль WDTT, чтобы регистр был виден сразу, и
    // предупреждаем, если хеш выглядит стёртым (ни одной заглавной буквы).
    for (i, h) in hashes.iter().enumerate() {
        pwdtt_log_add(
            "INFO",
            &format!("[APP] Хеш {}/{} ({} симв.): {}", i + 1, hashes.len(), h.len(), h),
        );
        if h.len() >= 32 && !h.chars().any(|c: char| c.is_ascii_uppercase()) {
            pwdtt_log_add(
                "WARN",
                &format!(
                    "[APP] Хеш {}/{} целиком в нижнем регистре — похоже, регистр стёрла старая версия при импорте. Удали сервер в списке и добавь заново из буфера (или вставь хеш в поле вручную с правильным регистром)",
                    i + 1,
                    hashes.len()
                ),
            );
        }
    }

    let Some(a) = app() else {
        return Err(fail("❌ AppHandle не установлен (wdtt_session::set_app_handle)".into()));
    };
    let state = a.state::<Arc<crate::state::AppState>>();
    let tools = state.tools();

    {
        let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
        g.state = PwdttStatusInfo {
            running: true,
            phase: "connecting".into(),
            name: server.name.clone(),
            id: Some(server.id.clone()),
            since: 0,
            active: 0,
            bytes_up: 0,
            bytes_down: 0,
            error: None,
        };
    }
    pwdtt_emit_state();

    // TUN и маршруты у туннелей общие — основной VPN гасим. ПОСЛЕ валидации
    // сервера: раньше остановка шла первой, и при «Сервер не найден»/«нет
    // хешей» пользователь оставался без VPN-туннеля ни с чем.
    // id активного сервера запоминаем ДО остановки: при провале старта WDTT
    // вернём VPN (stop() сбрасывает состояние, active_id после него пуст).
    let prev_vpn_id = state.conn.active_id();
    if state.conn.is_connected() || !prev_vpn_id.is_empty() {
        state.conn.stop(a);
        log_add("pwdtt", "основной VPN остановлен — маршруты у туннелей общие");
    }

    let device_id = server
        .device_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".into());
    let workers_s = server.workers.max(0).to_string();
    let captcha_mode = server.captcha_mode.clone().unwrap_or_else(|| "auto".into());
    let obfs = server.obfs_mode.clone().unwrap_or_else(|| "audio".into());
    // канал клиент↔TURN: Go-ядро WDTT исторически работает по TCP-аллокациям
    // (default tcp), udp — выбор в UI. fingerprint ядро не принимает — он
    // относится к VK-HTTP клиента ядра, там свой профиль.
    let turn_transport = if server.turn_tcp.unwrap_or(false) { "tcp" } else { "udp" };
    let hashes_arg = hashes.join(",");

    // Лог сессии открываем ДО старта ядра: чистая вкладка логов даже при
    // провальном connect (раньше clear шёл только после успешного старта,
    // и в логе висел хвост прошлой сессии)
    let _ = std::fs::create_dir_all(paths::pwdtt_dir(&tools));
    let log_res = std::fs::File::create(paths::pwdtt_log_path(&tools));
    if let Err(e) = &log_res {
        log_add(
            "pwdtt",
            &format!("session.log не открылся — лог сессии будет только в UI: {}", e),
        );
    }
    {
        let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
        g.log_lines.clear();
        g.log_file = log_res.ok();
    }

    // Ядро: вшитый wdtt-core.exe (client/core из ildarmaga/pwdtt-client,
    // GPL-3) — TURN-аллокация + DTLS + GETCONF внутри ядра.
    let core_exe = match ensure_wdtt_core(&tools) {
        Ok(p) => p,
        Err(e) => {
            if !prev_vpn_id.is_empty() {
                let msg = crate::commands::vpn_connect_impl(&state, a.clone(), prev_vpn_id, false);
                log_add("pwdtt", &format!("возврат основного VPN: {}", msg));
            }
            return Err(fail(format!("❌ {}", e)));
        }
    };

    let mut cmd = std::process::Command::new(&core_exe);
    cmd.args([
        "-peer",
        server.peer.as_str(),
        "-password",
        server.password.as_str(),
        "-vk",
        hashes_arg.as_str(),
        "-listen",
        PWDTT_CORE_LISTEN,
        "-device-id",
        device_id.as_str(),
        "-workers",
        workers_s.as_str(),
        "-captcha-mode",
        captcha_mode.as_str(),
        "-obfs",
        obfs.as_str(),
        "-tunnel",
        "wg",
        "-turn-transport",
        turn_transport,
    ])
    .current_dir(paths::pwdtt_dir(&tools))
    .creation_flags(0x08000000) // CREATE_NO_WINDOW
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());

    // Приоритетные релеи из прошлых сессий: без этого вся волна воркеров
    // стартует с пустой картой здоровья ядра и бьёт в (возможно мёртвый)
    // первый релей из списка VK — 28 с DTLS-таймаута у каждого.
    let preferred = relay_memory_preferred();
    if !preferred.is_empty() {
        cmd.env("WDTT_PREFERRED_RELAYS", preferred.join(","));
        log_add(
            "pwdtt",
            &format!("[APP] Приоритетные TURN-релеи (из прошлых сессий): {}", preferred.join(", ")),
        );
    }

    let spawned = cmd.spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            // Основной VPN мы остановили ради общих маршрутов — при провале
            // WDTT возвращаем его, иначе пользователь остался без интернета
            if !prev_vpn_id.is_empty() {
                let msg = crate::commands::vpn_connect_impl(&state, a.clone(), prev_vpn_id, false);
                log_add("pwdtt", &format!("возврат основного VPN: {}", msg));
            }
            return Err(fail(format!("❌ wdtt-core не запустился: {}", e)));
        }
    };
    let job = crate::conn::new_kill_on_close_job();
    if let Some(job) = &job {
        job.attach(child.id());
    }
    let core_stdin = child.stdin.take();
    let core_stdout = child.stdout.take().expect("stdout ядра не пайпнут");
    let core_stderr = child.stderr.take();
    let proc = Arc::new(CoreProc {
        child: Mutex::new(child),
        stdin: Mutex::new(core_stdin),
        job,
    });

    {
        let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
        if g.stop_requested {
            // disconnect/shutdown попали в окно старта (running=true, core ещё
            // не зарегистрирован — раньше disconnect() в этом окне был no-op
            // и туннель всё равно поднимался). Гасим свежезапущенное ядро и
            // возвращаем основной VPN.
            g.stop_requested = false;
            drop(g);
            proc.kill_force();
            pwdtt_wg_teardown();
            if !prev_vpn_id.is_empty() {
                let msg = crate::commands::vpn_connect_impl(&state, a.clone(), prev_vpn_id, false);
                log_add("pwdtt", &format!("возврат основного VPN: {}", msg));
            }
            return Err(fail("⏹ Запуск отменён: нажали «Отключить» во время подключения".into()));
        }
        g.core = Some(proc.clone());
        g.stop_requested = false;
    }

    // stdout → события (wg_config/captcha/stats/логи); stderr → WARN-лог.
    let turn_ips: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    std::thread::spawn(move || core_session_worker(proc, core_stdout, sess, turn_ips));
    if let Some(err_stream) = core_stderr {
        std::thread::spawn(move || stream_core_output(err_stream));
    }
    log_add("pwdtt", &format!("подключение: {} ({})", server.name, server.peer));
    Ok(())
}

// core_session_worker — stdout wdtt-core.exe (JSON-строки) → состояние + логи.
// sess — поколение сессии: события устаревшей сессии только осушаются,
// без побочных эффектов.
fn core_session_worker(
    proc: Arc<CoreProc>,
    stdout: std::process::ChildStdout,
    sess: u64,
    turn_ips: Arc<Mutex<Vec<String>>>,
) {
    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let line = line.trim().trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        let stale = WDTT.lock().unwrap_or_else(|e| e.into_inner()).session != sess;
        if stale {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            // не-JSON хвост (старое ядро?) — в лог как есть
            pwdtt_log_add("INFO", &format!("[CORE] {}", line));
            continue;
        };
        match v.get("type").and_then(|t| t.as_str()).unwrap_or("") {
            "log" => {
                let level = v.get("level").and_then(|x| x.as_str()).unwrap_or("INFO");
                let msg = v.get("message").and_then(|x| x.as_str()).unwrap_or("");
                if !msg.is_empty() && level != "SKIP" {
                    pwdtt_log_add(level, msg);
                    relay_memory_note_log(msg);
                }
            }
            "state" => {
                let status = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
                if status == "connecting" {
                    let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
                    if g.session == sess {
                        g.state.phase = "connecting".into();
                    }
                    drop(g);
                    pwdtt_emit_state();
                }
            }
            "stats" => {
                let rx = v.get("rx").and_then(|x| x.as_i64()).unwrap_or(0);
                let tx = v.get("tx").and_then(|x| x.as_i64()).unwrap_or(0);
                let active = v.get("workers").and_then(|x| x.as_i64()).unwrap_or(0);
                let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
                if g.session == sess {
                    g.state.active = active as i32;
                    g.state.bytes_up = tx;
                    g.state.bytes_down = rx;
                }
            }
            "error" => {
                let msg = v.get("message").and_then(|x| x.as_str()).unwrap_or("").to_string();
                pwdtt_log_add("ERROR", &msg);
                let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
                if g.session == sess {
                    g.state.error = Some(msg);
                }
            }
            "event" => {
                let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let data = v.get("data").and_then(|x| x.as_str()).unwrap_or("").to_string();
                handle_core_event(&proc, sess, &name, &data, &turn_ips);
            }
            _ => {}
        }
    }

    // stdout закрылся — ядро завершается (Stop, все воркеры кончились или крах).
    // Страховка: если процесс не вышел за 1.5 с (завис в VK-запросе) — добиваем.
    if proc.alive() {
        std::thread::sleep(Duration::from_millis(1500));
        if proc.alive() {
            proc.kill_force();
        }
    }
    pwdtt_wg_teardown();
    let current = {
        let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
        let current = g.session == sess;
        if current {
            g.running = false;
            g.core = None;
            g.state.phase = "disconnected".into();
            g.state.since = 0;
            g.state.active = 0;
            g.log_file = None; // Close()
        }
        current
    };
    if !current {
        return;
    }
    pwdtt_emit_state();
    log_add("pwdtt", "туннель остановлен");
}

// handle_core_event — событие {"type":"event","name":...} от ядра.
fn handle_core_event(
    proc: &Arc<CoreProc>,
    sess: u64,
    name: &str,
    data: &str,
    turn_ips: &Arc<Mutex<Vec<String>>>,
) {
    match name {
        "turn_ips" => {
            // TURN-релеи ядра → exclude-маршруты sing-box (приходят ДО wg_config)
            let list: Vec<String> = data
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if list.is_empty() {
                return;
            }
            pwdtt_log_add(
                "INFO",
                &format!("[APP] TURN-релеи для exclude-маршрутов: {}", list.join(", ")),
            );
            if let Ok(mut g) = turn_ips.lock() {
                *g = list.clone();
            }
            // запоминаем кандидатов VK для приоритета в следующей сессии
            relay_memory_note_candidates(&list);
        }
        "wg_config" => {
            // Сессия могла быть остановлена (disconnect/shutdown), пока конфиг
            // шёл в очереди stdout: поднимать sing-box для мёртвой сессии
            // нельзя — иначе процесс жил бы до завершения ожидания интерфейса
            // в apply (до 15 с) и дольше.
            let active = {
                let g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
                g.running && !g.stop_requested && g.session == sess
            };
            if !active {
                return;
            }
            let ips = turn_ips.lock().map(|g| g.clone()).unwrap_or_default();
            pwdtt_log_add("INFO", "[WG] Применение конфига...");
            match pwdtt_wg_apply(data, &ips) {
                Err(e) => {
                    pwdtt_log_add("ERROR", &format!("[WG] Ошибка: {}", e));
                    // ошибка не глушит ядро: фаза «disconnected», ядро ретраит
                    // конфиг — при успехе фаза вернётся в «connected».
                    {
                        let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
                        if g.session == sess {
                            g.state.phase = "disconnected".into();
                            g.state.error = Some(format!("WDTT-туннель не поднялся: {}", e));
                        }
                    }
                    pwdtt_emit_state();
                }
                Ok(()) => {
                    pwdtt_log_add("INFO", "[WG] Конфиг применён, туннель активен");
                    // Воркеры ядра ждут уведомления о готовом TUN (wg_config
                    // применён → адаптер поднят) — снимаем остальные группы.
                    proc.command("{\"cmd\":\"tun_ready\"}");
                    {
                        let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
                        if g.session == sess {
                            g.state.phase = "connected".into();
                            if g.state.since == 0 {
                                g.state.since = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs() as i64)
                                    .unwrap_or(0);
                            }
                            g.state.error = None;
                        }
                    }
                    pwdtt_emit_state();
                }
            }
        }
        "captcha_required" => {
            // Формат ядра: mode|redirectURI|sessionToken. Панель UI ждёт JSON
            // {streamId, mode, url} — упаковываем строкой, как раньше.
            let mut parts = data.splitn(3, '|');
            let mode = parts.next().unwrap_or("").trim().to_string();
            let url = parts.next().unwrap_or("").trim().to_string();
            // окно ожидания зависит от mode ядра: auto=10 с (рассчитано на их
            // авто-WebView), manual=60 с, selected(wv)=120 с — успей вставить токен
            let hint = match mode.as_str() {
                "manual" => "окно ~60 с",
                "selected" => "окно ~120 с",
                _ => "окно ~10 с (появится окно подольше — это финальная попытка)",
            };
            pwdtt_log_add(
                "WARN",
                &format!(
                    "[КАПЧА] Ядро не решило капчу само ({}) — открой URL из панели, реши и вставь токен/ссылку, {}",
                    mode, hint
                ),
            );
            if let Some(a) = app() {
                let payload =
                    serde_json::json!({"streamId": 0, "mode": mode, "url": url}).to_string();
                let _ = a.emit("pwdttCaptcha", &payload);
            }
        }
        _ => {
            pwdtt_log_add("INFO", &format!("[CORE] событие {}: {}", name, data));
        }
    }
}

// stderr wdtt-core.exe → WARN-лог сессии (паники ядра, голый вывод Go).
fn stream_core_output<R: Read + Send + 'static>(mut stream: R) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=pos).collect();
                    let line = String::from_utf8_lossy(&line[..line.len() - 1]);
                    let line = line.trim_end_matches('\r').trim();
                    if line.is_empty() {
                        continue;
                    }
                    pwdtt_log_add("WARN", &format!("[CORE-ERR] {}", line));
                }
                if buf.len() > 8000 {
                    let line = String::from_utf8_lossy(&buf).to_string();
                    pwdtt_log_add("WARN", &format!("[CORE-ERR] {}", line.trim()));
                    buf.clear();
                }
            }
            Err(_) => break,
        }
    }
    let line = String::from_utf8_lossy(&buf).to_string();
    let line = line.trim();
    if !line.is_empty() {
        pwdtt_log_add("WARN", &format!("[CORE-ERR] {}", line));
    }
}

// running — жива ли WDTT-сессия. conn.rs проверяет это при старте VPN/WARP:
// TUN-маршруты у туннелей общие, одновременно их держать нельзя.
pub fn running() -> bool {
    WDTT.lock().unwrap_or_else(|e| e.into_inner()).running
}

// PwdttDisconnect — снять интерфейс и погасить ядро.
pub fn disconnect() -> String {
    let (running, proc) = {
        let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
        // Флаг на окно старта: если connect ещё не дошёл до регистрации ядра,
        // сам он увидит stop_requested и погасит свежезапущенное ядро.
        g.stop_requested = true;
        (g.running, g.core.clone())
    };
    if !running {
        return "WDTT и так не запущен".into();
    }
    pwdtt_wg_teardown();
    if let Some(p) = &proc {
        // stdin {"cmd":"stop"} — ядро глушит воркеры и закрывает stdout,
        // finalize в reader-потоке довершает остановку. Зависшее ядро добиваем.
        p.command("{\"cmd\":\"stop\"}");
        let p2 = p.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(6));
            if p2.alive() {
                p2.kill_force();
            }
        });
    }
    "⏹ Останавливаю WDTT…".into()
}

// extract_captcha_token — юзер мог вставить всю ссылку из адресной строки
// (после решения VK редиректит на RedirectURI с success_token=…) — вытаскиваем
// чистый токен; голый токен проходит как есть. В ядре токен уходит в VK как
// QueryEscape(successToken) — URL целиком VK отверг бы.
fn extract_captcha_token(input: &str) -> String {
    let s = input.trim();
    if s.is_empty() {
        return String::new();
    }
    let extract = |key: &str| -> Option<String> {
        let low = s.to_lowercase();
        let pat = format!("{}=", key.to_lowercase());
        let idx = low.find(&pat)?;
        let rest = &s[idx + pat.len()..];
        let end = rest.find(|c| c == '&' || c == '#').unwrap_or(rest.len());
        let v = &rest[..end];
        let decoded = percent_encoding::percent_decode_str(v)
            .decode_utf8()
            .map(|c| c.to_string())
            .unwrap_or_else(|_| v.to_string());
        let decoded = decoded.trim().to_string();
        if decoded.is_empty() {
            None
        } else {
            Some(decoded)
        }
    };
    extract("success_token")
        .or_else(|| extract("token"))
        .unwrap_or_else(|| s.to_string())
}

// PwdttSendCaptcha — ручной ввод токена капчи (если авто-режимы не справились).
pub fn send_captcha(token: &str) -> String {
    let (running, proc) = {
        let g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
        (g.running, g.core.clone())
    };
    match (running, proc) {
        (true, Some(p)) => {
            let cleaned = extract_captcha_token(token);
            if cleaned.is_empty() {
                return "⚠️ Токен пустой — вставь итоговый токен или ссылку из адресной строки".into();
            }
            let line = serde_json::json!({"cmd": "captcha", "token": cleaned}).to_string();
            p.command(&line);
            "✅ Токен капчи передан ядру".into()
        }
        _ => "⚠️ Туннель не запущен".into(),
    }
}

// pwdttShutdown — уборка при закрытии окна/выходе: снять интерфейс
// и остановить ядро, не дожидаясь reader-потока.
pub fn shutdown() {
    pwdtt_wg_teardown();
    let proc = {
        let mut g = WDTT.lock().unwrap_or_else(|e| e.into_inner());
        // на случай окна старта connect (см. disconnect)
        g.stop_requested = true;
        g.core.clone()
    };
    if let Some(p) = &proc {
        p.command("{\"cmd\":\"stop\"}");
        // при выходе приложения ждём долго: kill_force через 3 с — KILL_ON_JOB
        // дожмёт всё равно при закрытии дескриптора Job
        let p2 = p.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            if p2.alive() {
                p2.kill_force();
            }
        });
    }
}

// pwdttStartupCleanup — хвост прошлого падения: битый адаптер pwdtt-wg держит
// маршруты в никуда. Сносим ТОЛЬКО устройства в проблемном состоянии:
// здоровый адаптер переиспользуется sing-box'ом, а снос здорового гонкой с
// CreateTUN ронял весь процесс (нативный краш wintun.dll).
pub fn startup_cleanup() {
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(2500)); // дать стартовать туннелям без гонки
        // Конфиг wg с приватным ключом живёт только внутри сессии (teardown
        // удаляет) — после краха процесса убираем остаток. При живой сессии
        // не трогаем: пользователь мог подключиться в первые секунды.
        if !running() {
            let tools = paths::find_tools_dir();
            let _ = std::fs::remove_file(paths::pwdtt_dir(&tools).join("wg.conf"));
        }
        // Сначала получаем InstanceId битых устройств, потом удаляем каждый
        // отдельным pnputil с проверкой кода выхода.
        let out = match crate::tools::run_hidden(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -eq 'pwdtt-wg' -and $_.Status -ne 'OK' } | ForEach-Object { $_.InstanceId }",
            ],
        ) {
            Ok(o) => o,
            Err(_) => return,
        };
        let mut removed = 0;
        let mut failed = 0;
        for id in out.split_whitespace() {
            if crate::tools::run_hidden("pnputil", &["/remove-device", id]).is_err() {
                failed += 1;
                log_add("pwdtt", &format!("pnputil /remove-device {}: не удалось", id));
                continue;
            }
            removed += 1;
        }
        if removed > 0 {
            log_add(
                "pwdtt",
                &format!("убрано битых адаптеров прошлой сессии (pwdtt-wg): {}", removed),
            );
        }
        if failed > 0 {
            log_add(
                "pwdtt",
                &format!("не удалось убрать битых адаптеров: {} — нужны права администратора", failed),
            );
        }
    });
}

// ---------- туннель: wdtt-wg.exe (порт PWDTT backend/win_wg.go) ----------

// pwdttExcludeCIDRs — исключающие маршруты: VK (включая TURN-релеи), DNS —
// мимо туннеля (в sing-box это route-правило в direct-outbound).
const PWDTT_EXCLUDE_CIDRS: [&str; 15] = [
    "87.240.128.0/18",
    "87.240.192.0/19",
    "90.156.0.0/16",
    "93.186.224.0/21",
    "95.142.192.0/21",
    "95.163.0.0/16",
    "95.213.0.0/18",
    "155.212.192.0/20",
    "185.16.28.0/22",
    "194.67.64.0/18",
    "195.82.146.0/23",
    "213.180.193.0/24",
    "77.88.0.0/18",
    "8.8.8.0/24",
    "1.1.1.0/24",
];

struct WgInner {
    child: Option<std::process::Child>,
    // stdin wdtt-wg: "stop" → вежливый teardown (маршруты снимает сам хелпер)
    stdin: Option<std::process::ChildStdin>,
    conf_path: Option<PathBuf>,
    // Дескриптор Job Object ядра туннеля: пока открыт, KILL_ON_JOB_CLOSE
    // защищает от сирот при крахе Sentor; закрывается в teardown (Drop).
    job: Option<crate::conn::JobHandle>,
}

static PWDTT_WG: Mutex<WgInner> = Mutex::new(WgInner {
    child: None,
    stdin: None,
    conf_path: None,
    job: None,
});

// wg_log — строка лога туннеля с [WG]-префиксом (Go: logf в forwarder'е).
fn wg_log(msg: &str) {
    pwdtt_log_add("INFO", &format!("[WG] {}", msg));
}

// pwdtt_wg_apply — поднять туннель: подход PWDTT-десктопа (backend/win_wg.go)
// 1-в-1: вшитый wdtt-wg.exe поднимает userspace WireGuard + wintun В СВОЁМ
// процессе, маршруты/netsh руками, endpoint 127.0.0.1:19001 (локальный релей
// wdtt-core). БЕЗ sing-box: его route.auto_detect_interface привязывал udp6-бинд
// wireguard к физическому адаптеру (ms_tcpip6 выключен) — бинд умирал, handshake
// не уходил. У wireguard-go bind без привязки — udp6-сокет создаётся всегда.
fn pwdtt_wg_apply(conf: &str, turn_ips: &[String]) -> Result<(), String> {
    {
        let mut g = PWDTT_WG.lock().unwrap_or_else(|e| e.into_inner());
        pwdtt_wg_teardown_locked(&mut g);
    }

    // Sanity-check конфига (Address обязателен; сам INI уходит в хелпер как есть).
    let cfg = crate::warp::parse_warp_config(conf)?;
    if cfg.addresses.is_empty() {
        return Err("в конфиге нет Address".into());
    }
    if cfg.has_amnezia || !cfg.awg_extras.is_empty() {
        wg_log("AWG-параметры конфига не применяются — туннель пойдёт как обычный WireGuard");
    }

    let tools = paths::find_tools_dir();
    let dir = paths::pwdtt_dir(&tools);
    let _ = std::fs::create_dir_all(&dir);
    let exe = ensure_wdtt_wg(&dir)?;

    let conf_path = dir.join("wg.conf");
    std::fs::write(&conf_path, conf.as_bytes())
        .map_err(|e| format!("запись wg.conf: {}", e))?;

    // Exclude-маршруты напрямую через физический шлюз (route add в хелпере):
    // TURN-релеи (/32) + VK/DNS CIDRs. IPv6 excludes не даём — route add в
    // хелпере v4-only, релеи VK здесь всегда IPv4.
    let mut excludes: Vec<String> = Vec::new();
    for ip in turn_ips {
        let ip = ip.trim();
        if !ip.is_empty() && !ip.contains(':') {
            excludes.push(format!("{}/32", ip));
        }
    }
    excludes.extend(PWDTT_EXCLUDE_CIDRS.iter().map(|s| s.to_string()));
    let excludes_arg = excludes.join(",");

    wg_log(&format!(
        "Создание TUN интерфейса {:?} через wdtt-wg (wireguard-go, userspace)",
        PWDTT_IFACE
    ));
    let mut cmd = std::process::Command::new(&exe);
    cmd.args([
        "-iface",
        PWDTT_IFACE,
        "-conf",
        conf_path.to_str().unwrap_or_default(),
        "-excludes",
        excludes_arg.as_str(),
    ])
    .current_dir(&dir)
    .creation_flags(0x08000000) // CREATE_NO_WINDOW
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("wdtt-wg не запустился: {}", e))?;
    let wg_stdin = child.stdin.take();
    if let Some(out) = child.stdout.take() {
        std::thread::spawn(move || stream_wg_output(out));
    }
    if let Some(err) = child.stderr.take() {
        std::thread::spawn(move || stream_wg_output(err));
    }
    // Job Object с KILL_ON_JOB_CLOSE: wdtt-wg-сирота умирает при крахе Sentor.
    let job = crate::conn::new_kill_on_close_job();
    if let Some(job) = &job {
        job.attach(child.id());
    }
    {
        let mut g = PWDTT_WG.lock().unwrap_or_else(|e| e.into_inner());
        g.child = Some(child);
        g.stdin = wg_stdin;
        g.conf_path = Some(conf_path);
        g.job = job;
    }

    // Ждём TUN-адаптер (до 15 с) и следим, что sing-box не упал на старте
    let mut iface_up = false;
    for _ in 0..100 {
        // disconnect/shutdown в окне ожидания TUN: глушим свежий sing-box сразу,
        // а не через 15 с по истечении ожидания интерфейса
        if { let g = WDTT.lock().unwrap_or_else(|e| e.into_inner()); g.stop_requested } {
            pwdtt_wg_teardown();
            return Err("остановлено во время подключения (disconnect)".into());
        }
        // проверка под коротким локом; teardown — уже ПОСЛЕ его снятия
        // (pwdtt_wg_teardown сам берёт PWDTT_WG — повторный lock повесил бы поток)
        enum StartupFail {
            Died,
            Lost,
        }
        let fail: Option<StartupFail> = {
            let mut g = PWDTT_WG.lock().unwrap_or_else(|e| e.into_inner());
            match &mut g.child {
                Some(c) => {
                    if c.try_wait().map(|x| x.is_some()).unwrap_or(false) {
                        Some(StartupFail::Died)
                    } else {
                        None
                    }
                }
                None => Some(StartupFail::Lost),
            }
        };
        match fail {
            Some(StartupFail::Died) => {
                pwdtt_wg_teardown();
                return Err("wdtt-wg упал при открытии TUN — смотри лог сессии".into());
            }
            Some(StartupFail::Lost) => {
                return Err("wdtt-wg процесс потерян".into());
            }
            None => {}
        }
        std::thread::sleep(Duration::from_millis(150));
        if crate::conn::tun_interface_up(PWDTT_IFACE) {
            iface_up = true;
            break;
        }
    }
    if !iface_up {
        pwdtt_wg_teardown();
        return Err("TUN-интерфейс не открылся за 15 секунд (wintun заклинило). Перезагрузи ПК".into());
    }
    // дать wireguard handshake дожать (как runWarp в conn.rs)
    std::thread::sleep(Duration::from_millis(1500));
    wg_log(&format!("Туннель {} поднят (wdtt-wg userspace wireguard)", PWDTT_IFACE));
    Ok(())
}

// pwdtt_wg_teardown — снять туннель (stdin "stop" хелперу + kill при зависании).
fn pwdtt_wg_teardown() {
    let mut g = PWDTT_WG.lock().unwrap_or_else(|e| e.into_inner());
    pwdtt_wg_teardown_locked(&mut g);
}

fn pwdtt_wg_teardown_locked(g: &mut WgInner) {
    if g.child.is_none() && g.conf_path.is_none() {
        return;
    }
    // Вежливый стоп: wdtt-wg сам снимает split-default и exclude-маршруты
    // (teardownWG внутри хелпера), закрываем stdin как дубль-сигнал (EOF).
    if let Some(mut w) = g.stdin.take() {
        use std::io::Write;
        let _ = writeln!(w, "stop");
        let _ = w.flush();
    }
    if let Some(mut c) = g.child.take() {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            match c.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        // Не вышел — жёстко (хвосты маршрутов досмотрит cleanup при след. коннекте).
        let _ = c.kill();
        let _ = c.wait();
    }
    // Дескриптор Job закрываем после kill+wait: при ещё живом хелпере
    // KILL_ON_JOB_CLOSE сам его добьёт — на teardown это и есть цель.
    g.job = None;
    if let Some(p) = g.conf_path.take() {
        let _ = std::fs::remove_file(&p);
    }
}

// stdout/stderr wdtt-wg → строки в лог сессии
fn stream_wg_output<R: Read + Send + 'static>(mut stream: R) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=pos).collect();
                    let line = String::from_utf8_lossy(&line[..line.len() - 1]);
                    let line = line.trim_end_matches('\r').trim();
                    if line.is_empty() {
                        continue;
                    }
                    wg_log(line);
                }
                if buf.len() > 8000 {
                    let line = String::from_utf8_lossy(&buf).to_string();
                    wg_log(line.trim());
                    buf.clear();
                }
            }
            Err(_) => break,
        }
    }
    if !buf.is_empty() {
        let line = String::from_utf8_lossy(&buf).to_string();
        wg_log(line.trim_end_matches('\r').trim());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_list_splits() {
        assert_eq!(
            pwdtt_hash_list("abc\ndef , ghi ;\r\njkl"),
            vec!["abc", "def", "ghi", "jkl"]
        );
        assert!(pwdtt_hash_list("  ,,, ; ").is_empty());
    }

    #[test]
    fn hash_list_normalizes_urls() {
        // полный URL ссылки звонка → чистый хеш; кавычки/скобки обрезаются.
        // РЕГИСТР СОХРАНЯЕТСЯ: хеш VK-звонка регистрозависим (lowercase давал
        // 954 «call unavailable» на хешах с заглавными)
        assert_eq!(
            pwdtt_hash_list("https://vk.com/call/join/AbCd,  \"join2\""),
            vec!["AbCd", "join2"]
        );
        // разные регистры одного хеша — разные хеши после фикса (VK их
        // различает); дубликат считается только при точном совпадении
        assert_eq!(
            pwdtt_hash_list("AbCd\nabcD"),
            vec!["AbCd", "abcD"]
        );
    }

    #[test]
    fn captcha_token_extraction() {
        // голый токен — как есть
        assert_eq!(extract_captcha_token("vka1b2c3"), "vka1b2c3");
        // вся ссылка из адресной строки после решения — токен вытащен
        assert_eq!(
            extract_captcha_token("https://vk.ru/call/join/AbCd?session_token=abc&success_token=T0kEn9%2Bx&captcha_ts=1"),
            "T0kEn9+x"
        );
        // параметр token= без success_token=
        assert_eq!(
            extract_captcha_token("https://example.ru/redirect?token=abc_def"),
            "abc_def"
        );
        // не URL и не токен-строка — как есть
        assert_eq!(extract_captcha_token("просто строка"), "просто строка");
        assert_eq!(extract_captcha_token("   "), "");
    }

    #[test]
    fn parse_qwdtt_link() {
        let s = pwdtt_parse_link(
            "qwdtt://config?name=My%20srv&peer=1.2.3.4:443&pass=secret&hashes=aaa%2Cbbb&workers=27",
        )
        .unwrap();
        assert_eq!(s.name, "My srv");
        assert_eq!(s.peer, "1.2.3.4:443");
        assert_eq!(s.password, "secret");
        assert_eq!(s.hashes, "aaa\nbbb");
        assert_eq!(s.workers, 27);
    }

    #[test]
    fn parse_wdtt_link() {
        let s = pwdtt_parse_link("wdtt://1.2.3.4:5555:6666:7777:pw:hash1:hash2#My%20name").unwrap();
        assert_eq!(s.peer, "1.2.3.4:5555");
        assert_eq!(s.password, "pw");
        // Go: pwdttHashList НЕ режет ':' — остаток после пароля это ОДИН хеш
        // (несколько хешей в ссылке разделяются запятыми)
        assert_eq!(s.hashes, "hash1:hash2");
        assert_eq!(s.name, "My name");
        assert!(pwdtt_parse_link("wdtt://1.2.3.4:5555").is_err());
        assert!(pwdtt_parse_link("vless://x").is_err());
    }

    #[test]
    fn parse_wdtt_link_multi_hashes() {
        let s =
            pwdtt_parse_link("wdtt://1.2.3.4:5555:6666:7777:pw:hash1,hash2").unwrap();
        assert_eq!(s.hashes, "hash1\nhash2");
    }

    #[test]
    fn normalize_server_bounds() {
        let mut s = PwdttServer {
            name: String::new(),
            peer: "host.example:1234".into(),
            password: " p ".into(),
            hashes: "a".into(),
            workers: 999999,
            ..Default::default()
        };
        pwdtt_normalize_server(&mut s);
        assert_eq!(s.name, "host.example");
        assert_eq!(s.password, "p");
        assert_eq!(s.workers, 72 - 72 % 9);
        assert_eq!(s.captcha_mode.as_deref(), Some("auto"));
        assert_eq!(s.obfs_mode.as_deref(), Some("audio"));
        assert_eq!(s.fingerprint.as_deref(), Some("chrome"));
    }

    #[test]
    fn normalize_video_kept() {
        let mut s = PwdttServer::default();
        s.obfs_mode = Some("video".into());
        s.fingerprint = Some("FIREFOX ".into());
        pwdtt_normalize_server(&mut s);
        assert_eq!(s.obfs_mode.as_deref(), Some("video"));
        assert_eq!(s.fingerprint.as_deref(), Some("firefox"));
    }

    #[test]
    fn first_ipv4_in_relay_lines() {
        // реальные строки ядра (в paste юзера «х» иногда мнётся в «ч» —
        // парсим адрес, а не ключ host=)
        assert_eq!(
            first_ipv4("[RELAY] воркер #7 host=193.203.43.35 life=28.1s err=WRAP_AUTH_TIMEOUT: DTLS timeout"),
            Some("193.203.43.35".into())
        );
        assert_eq!(
            first_ipv4("[RELAY] воркер #3 чost=193.203.43.35 life=28.2s (не дошёл до READY)"),
            Some("193.203.43.35".into())
        );
        assert_eq!(
            first_ipv4("[СЕССИЯ #7] TURN UDP (90.156.234.255:19302)"),
            Some("90.156.234.255".into())
        );
        // ложных срабатываний быть не должно
        assert_eq!(first_ipv4("life=28.1s err=DTLS timeout"), None);
        assert_eq!(first_ipv4("[CORE] wdtt-core/1.0.0 запущен"), None);
        assert_eq!(first_ipv4("Трафик: 3.20 МБ"), None);
        // порт за адресом не съедается
        assert_eq!(first_ipv4("СЕССИЯ #1 (10.0.0.1:19302)"), Some("10.0.0.1".into()));
    }

    #[test]
    fn relay_log_death_classifies_lines() {
        // настоящая смерть релея (28с DTLS-таймаут) — учим
        assert_eq!(
            relay_log_death(
                "[RELAY] воркер #7 host=193.203.43.35 life=28.1s err=WRAP_AUTH_TIMEOUT: DTLS timeout (мёртвый TURN relay, повтор с новым allocation)"
            ),
            Some("193.203.43.35".into())
        );
        // «не дошёл до READY» — тоже смерть
        assert_eq!(
            relay_log_death("[RELAY] воркер #3 чost=10.0.0.1 life=5.0s (не дошёл до READY)"),
            Some("10.0.0.1".into())
        );
        // остановка сессии отменила хендшейк — релей жив, НЕ учим
        // (реальная строка из session.log 03:35:01)
        assert_eq!(
            relay_log_death(
                "[RELAY] воркер #5 host=193.203.43.35 life=19.0s err=DTLS хендшейк: handshake error: context canceled"
            ),
            None
        );
        assert_eq!(
            relay_log_death("[RELAY] воркер #2 host=90.156.234.255 life=371.4s err=TURN Allocate: context canceled"),
            None
        );
        // нормальное завершение и прочие строки — не смерть
        assert_eq!(
            relay_log_death("[RELAY] воркер #1 host=90.156.234.255 life=405.1s завершён"),
            None
        );
        assert_eq!(relay_log_death("[СТАТ] Активных: 8 | Трафик: 8.06 МБ (↓ 7.10 | ↑ 0.96)"), None);
        assert_eq!(relay_log_death("[ВОРКЕР #1] [DTLS] Соединение установлено ✓"), None);
    }

    #[test]
    fn relay_memory_json_roundtrip() {
        let mem = RelayMemory {
            candidates: vec!["90.156.234.255".into(), "193.203.43.35".into()],
            dead: [("193.203.43.35".to_string(), 1700000000u64)].into_iter().collect(),
        };
        let json = serde_json::to_vec(&mem).unwrap();
        let back: RelayMemory = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.candidates, mem.candidates);
        assert_eq!(back.dead.get("193.203.43.35"), Some(&1700000000));
        // пустой/старый файл без поля dead тоже читается
        let old: RelayMemory = serde_json::from_str(r#"{"candidates":["1.2.3.4"]}"#).unwrap();
        assert_eq!(old.candidates, vec!["1.2.3.4"]);
        assert!(old.dead.is_empty());
    }
}
