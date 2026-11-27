// Tools management - port of Go app.go installers/update/strategy/tgproxy
// functions and relay helpers from relay.go. Everything heavy (cores, zapret,
// tgproxy exe) is embedded in the exe (assets/), like the Go build.
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use tauri::{AppHandle, Emitter};

use crate::logging::log_add;
use crate::models::{RelayStats, ToolSources, UpdateInfo};
use crate::paths;
use crate::sysinfo;

pub const GITHUB_ZAPRET_RELEASE: &str =
    "https://api.github.com/repos/Flowseal/zapret-discord-youtube/releases/latest";
pub const GITHUB_TG_LATEST: &str = "https://api.github.com/repos/Flowseal/tg-ws-proxy/releases/latest";
pub const GITHUB_ZAPRET_REPO: &str = "https://github.com/Flowseal/zapret-discord-youtube";
pub const GITHUB_TG_REPO: &str = "https://github.com/Flowseal/tg-ws-proxy";
pub const ZAPRET_EMBEDDED_VERSION: &str = "1.10.3";

// вшитые бинарники (go:embed → include_bytes!); pub — cqstt_session распаковывает
// csqtt-client.exe/wintun.dll через этот реестр
pub fn embedded(name: &str) -> Option<&'static [u8]> {
    match name {
        "zapret.zip" => Some(include_bytes!("../assets/zapret.zip")),
        "TgWsProxy_windows.exe" => Some(include_bytes!("../assets/TgWsProxy_windows.exe")),
        "sing-box.exe" => Some(include_bytes!("../assets/vpn/sing-box.exe")),
        "xray.exe" => Some(include_bytes!("../assets/vpn/xray.exe")),
        "wintun.dll" => Some(include_bytes!("../assets/vpn/wintun.dll")),
        "SentorWarp.exe" => Some(include_bytes!("../assets/vpn/SentorWarp.exe")),
        // CSQTT: Rust-транспорт из danusha2345/csqtt-vpn v2.1.19 (ядро amurcanov 2.1.15);
        // SHA256 бандла сверен с официальными SHA256SUMS релиза; wintun.dll берём из vpn/
        "csqtt-client.exe" => Some(include_bytes!("../assets/cqstt/csqtt-client.exe")),
        // WDTT: ядро из ildarmaga/pwdtt-client client/core (GPL-3) с головной
        // обёрткой cmd/wdtt-core (JSON-события в stdout, команды в stdin) —
        // сессию ведёт внешний процесс, см. wdtt_session.rs
        "wdtt-core.exe" => Some(include_bytes!("../assets/wdtt/wdtt-core.exe")),
        // TUN+WireGuard хелпер (порт подхода PWDTT backend/win_wg.go):
        // userspace wireguard-go + wintun в его процессе, маршруты руками
        "wdtt-wg.exe" => Some(include_bytes!("../assets/wdtt/wdtt-wg.exe")),
        _ => None,
    }
}

// ---------- запуск процессов ----------

// Читатель пайпа в фоновом потоке (run_hidden): при «болтливом» ребёнке буфер
// пайпа заполняется, ребёнок блокируется на write, try_wait никогда не вернёт
// Some — раньше это давало 30-секундное зависание и убитый процесс с потерей
// вывода. Читаем байты: вывод cmd-утилит не UTF-8 (cp866) — lossy.
fn spawn_pipe_reader<R: std::io::Read + Send + 'static>(
    s: R,
    tx: std::sync::mpsc::Sender<String>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut s = s;
        let _ = s.read_to_end(&mut buf);
        let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
    })
}

// runHidden: таймаут 30 с — sc/taskkill в теории могут зависнуть.
pub fn run_hidden(exe: &str, args: &[&str]) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    use std::sync::mpsc;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let (tx, rx) = mpsc::channel::<String>();
    let mut readers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    if let Some(s) = child.stdout.take() {
        readers.push(spawn_pipe_reader(s, tx.clone()));
    }
    if let Some(s) = child.stderr.take() {
        readers.push(spawn_pipe_reader(s, tx.clone()));
    }
    drop(tx);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    for r in readers {
                        let _ = r.join();
                    }
                    let mut out = String::new();
                    while let Ok(s) = rx.try_recv() {
                        out.push_str(&s);
                    }
                    let tail = out.trim();
                    if tail.is_empty() {
                        return Err(format!("{} не дождались (таймаут)", exe));
                    }
                    return Err(format!("{} не дождались (таймаут): {}", exe, tail));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    for r in readers {
        let _ = r.join();
    }
    let mut out = String::new();
    while let Ok(s) = rx.try_recv() {
        out.push_str(&s);
    }
    Ok(out)
}

// unloadWinDivert выгружает драйвер: после принудительной остановки winws
// служба может остаться загруженной и держать WinDivert64.sys.
pub fn unload_win_divert() {
    for svc in ["WinDivert2.2", "WinDivert2.3", "WinDivert1.4", "WinDivert"] {
        let _ = run_hidden("sc", &["stop", svc]);
    }
    std::thread::sleep(Duration::from_millis(500));
}

// ---------- GitHub releases / скачивание ----------

#[derive(Debug, Deserialize, Default, Clone)]
pub struct GhAsset {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "browser_download_url", default)]
    pub url: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub digest: String, // sha256:<hex> — GitHub считает при загрузке ассета
}

pub fn github_release(api_url: &str) -> Result<(String, Vec<GhAsset>), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(api_url)
        .header("User-Agent", "net-center-gui")
        .header("Accept", "application/vnd.github+json")
        .send()
        .map_err(|e| e.to_string())?;
    if resp.status().as_u16() != 200 {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    let rel: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    let tag = rel
        .get("tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let assets: Vec<GhAsset> = rel
        .get("assets")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| serde_json::from_value(x.clone()).ok()).collect())
        .unwrap_or_default();
    Ok((tag, assets))
}

// download: sha256 из метаданных GitHub, лимит размера, живой прогресс (dlProgress).
pub fn download_with_progress(
    app: Option<&AppHandle>,
    kind: &str,
    url: &str,
    dest: &Path,
    asset: &GhAsset,
) -> Result<(), String> {
    let expected = asset.digest.trim().to_lowercase();
    let expected = expected.strip_prefix("sha256:").unwrap_or(&expected).to_string();
    if expected.is_empty() {
        return Err("в релизе нет SHA-256 ассета — скачивание отменено".into());
    }
    if expected.len() != 64 {
        return Err("некорректный SHA-256 в метаданных релиза".into());
    }
    if asset.size <= 0 || asset.size > 512 << 20 {
        return Err("некорректный размер ассета в метаданных релиза".into());
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15 * 60))
        .build()
        .map_err(|e| e.to_string())?;
    let mut resp = client
        .get(url)
        .header("User-Agent", "net-center-gui")
        .send()
        .map_err(|e| e.to_string())?;
    if resp.status().as_u16() != 200 {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    let mut out = std::fs::File::create(dest).map_err(|e| e.to_string())?;
    let mut hasher = sha2::Sha256::new();
    let total = if resp.content_length().unwrap_or(0) > 0 {
        resp.content_length().unwrap()
    } else {
        asset.size as u64
    };
    let mut got: u64 = 0;
    let mut last = Instant::now();
    let mut buf = vec![0u8; 65536];
    let mut n_total: u64 = 0;
    loop {
        let n = match resp.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                let _ = std::fs::remove_file(dest);
                return Err(e.to_string());
            }
        };
        hasher.update(&buf[..n]);
        if let Err(e) = out.write_all(&buf[..n]) {
            let _ = std::fs::remove_file(dest);
            return Err(e.to_string());
        }
        got += n as u64;
        n_total += n as u64;
        if last.elapsed() > Duration::from_millis(250) {
            last = Instant::now();
            if let Some(a) = app {
                let _ = a.emit("dlProgress", json!({"kind": kind, "got": got, "total": total}));
            }
        }
    }
    if let Some(a) = app {
        let _ = a.emit("dlProgress", json!({"kind": kind, "got": n_total, "total": asset.size}));
    }
    drop(out);
    if n_total != asset.size as u64 {
        let _ = std::fs::remove_file(dest);
        return Err(format!("размер не совпал: получено {}, ожидалось {}", n_total, asset.size));
    }
    use sha2::Digest as _;
    let got_hash = hex_lower(&hasher.finalize());
    if got_hash != expected {
        let _ = std::fs::remove_file(dest);
        return Err(format!("SHA-256 не совпал: получено {}, ожидалось {}", got_hash, expected));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ---------- zip ----------

fn unzip_bytes(data: &[u8], dest: &Path) -> Result<(), String> {
    let reader = std::io::Cursor::new(data);
    let mut arch = zip::ZipArchive::new(reader).map_err(|e| e.to_string())?;
    for i in 0..arch.len() {
        let mut entry = arch.by_index(i).map_err(|e| e.to_string())?;
        let name = entry.name().replace('\\', "/");
        // Zip Slip: запись архива не должна выходить за пределы dest —
        // абсолютные пути, буквы дисков и ".." запрещены целиком.
        if name.is_empty()
            || name.starts_with('/')
            || name.contains(':')
            || name.split('/').any(|part| part == "..")
        {
            return Err(format!("архив содержит подозрительный путь: {}", name));
        }
        let out_path = dest.join(&name);
        if name.ends_with('/') {
            std::fs::create_dir_all(&out_path).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut out = std::fs::File::create(&out_path).map_err(|e| e.to_string())?;
        std::io::copy(&mut entry, &mut out).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// unzipFlatten: если всё содержимое лежит в одной корневой папке архива —
// поднимаем её содержимое на уровень dest.
fn unzip_flatten(data: &[u8], dest: &Path) -> Result<(), String> {
    unzip_bytes(data, dest)?;
    // единый корень?
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dest)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    if entries.len() == 1 && entries[0].is_dir() {
        let root = entries.remove(0);
        for item in std::fs::read_dir(&root).map_err(|e| e.to_string())?.flatten() {
            let target = dest.join(item.file_name());
            std::fs::rename(item.path(), target).map_err(|e| e.to_string())?;
        }
        let _ = std::fs::remove_dir(&root);
    }
    Ok(())
}

// ---------- zapret ----------

pub fn install_zapret(tools: &Path) -> String {
    if sysinfo::process_running(paths::WINWS_NAME) {
        return "❌ Сначала останови Zapret (winws запущен)".into();
    }
    let Some(blob) = embedded("zapret.zip") else {
        return "❌ Вшитый zapret.zip не найден".into();
    };
    let dest = tools.join("zapret");
    unload_win_divert();
    let _ = std::fs::remove_dir_all(&dest);
    if let Err(e) = unzip_bytes(blob, &dest) {
        // драйвер мог выгружаться не мгновенно — даём время и пробуем снова
        std::thread::sleep(Duration::from_secs(2));
        let _ = std::fs::remove_dir_all(&dest);
        if let Err(e2) = unzip_bytes(blob, &dest) {
            return format!("❌ Ошибка распаковки: {} — закрой все окна приложения (включая «Проверку») и попробуй снова", e2);
        }
        let _ = e;
    }
    write_version(tools, "zapret", ZAPRET_EMBEDDED_VERSION);
    format!("✅ Zapret {} установлен в {}", ZAPRET_EMBEDDED_VERSION, dest.display())
}

pub fn update_zapret(app: Option<&AppHandle>, tools: &Path) -> String {
    if sysinfo::process_running(paths::WINWS_NAME) {
        return "❌ Сначала останови Zapret (winws запущен)".into();
    }
    let (tag, assets) = match github_release(GITHUB_ZAPRET_RELEASE) {
        Ok(x) => x,
        Err(e) => return format!("❌ Не получил список релизов: {}", e),
    };
    let Some(asset) = assets.iter().find(|a| a.name.to_lowercase().ends_with(".zip")) else {
        return "❌ В релизе нет .zip архива".into();
    };
    let tmp = std::env::temp_dir().join(format!("zapret_download_{}.zip", std::process::id()));
    let _ = std::fs::remove_file(&tmp); // tmp с pid: общий путь затирался бы параллельными обновлениями
    if let Err(e) = download_with_progress(app, "zapret", &asset.url, &tmp, asset) {
        return format!("❌ Ошибка скачивания: {}", e);
    }
    let Ok(blob) = std::fs::read(&tmp) else {
        return "❌ Не смог прочитать скачанный архив".into();
    };
    let dest = tools.join("zapret");
    let stage = PathBuf::from(format!("{}_update", dest.display()));
    let _ = std::fs::remove_dir_all(&stage);
    if let Err(e) = unzip_flatten(&blob, &stage) {
        std::thread::sleep(Duration::from_secs(2));
        let _ = std::fs::remove_dir_all(&stage);
        if let Err(e2) = unzip_flatten(&blob, &stage) {
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_dir_all(&stage);
            return format!("❌ Ошибка распаковки: {}", e2);
        }
        let _ = e;
    }
    if paths::find_file(&stage, paths::WINWS_NAME, 4).as_os_str().is_empty() {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_dir_all(&stage);
        return format!("❌ В архиве нет {} — обновление отменено, старая версия сохранена", paths::WINWS_NAME);
    }
    unload_win_divert();
    let old = PathBuf::from(format!("{}.old", dest.display()));
    let _ = std::fs::remove_dir_all(&old);
    if let Err(e) = std::fs::rename(&dest, &old) {
        if e.kind() != std::io::ErrorKind::NotFound {
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_dir_all(&stage);
            return format!("❌ Не удалось заменить старую папку: {}", e);
        }
    }
    if let Err(e) = std::fs::rename(&stage, &dest) {
        if std::fs::rename(&old, &dest).is_err() {
            log_add("update", &format!("ОТКАТ ОБНОВЛЕНИЯ УПАЛ: старая версия осталась в {}: {:?}", old.display(), e));
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_dir_all(&stage);
            return format!("❌ Не удалось сохранить новую версию, и откат не прошёл — старая версия сохранена в {}: {}", old.display(), e);
        }
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_dir_all(&stage);
        return format!("❌ Не удалось сохранить новую версию (старая на месте): {}", e);
    }
    let _ = std::fs::remove_dir_all(&old);
    let _ = std::fs::remove_file(&tmp);
    write_version(tools, "zapret", &tag);
    format!("✅ Zapret обновлён до {}: {}", tag, dest.display())
}

// ---------- tgproxy ----------

pub fn install_tg_proxy(tools: &Path) -> String {
    if sysinfo::process_running(paths::TG_EXE_NAME) {
        return "❌ Сначала останови TG-прокси".into();
    }
    let Some(blob) = embedded(paths::TG_EXE_NAME) else {
        return "❌ Вшитый TgWsProxy_windows.exe не найден".into();
    };
    let dir = tools.join("tgproxy");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return format!("❌ Ошибка создания папки {}: {}", dir.display(), e);
    }
    let dest = dir.join(paths::TG_EXE_NAME);
    if let Err(e) = std::fs::write(&dest, blob) {
        return format!("❌ Ошибка записи: {}", e);
    }
    let _ = std::fs::remove_file(paths::version_file(tools, "tgproxy")); // версия встроенного exe неизвестна
    format!("✅ TG WS Proxy установлен в {}", dir.display())
}

pub fn update_tg_proxy(app: Option<&AppHandle>, tools: &Path) -> String {
    if sysinfo::process_running(paths::TG_EXE_NAME) {
        return "❌ Сначала останови TG-прокси".into();
    }
    let (tag, assets) = match github_release(GITHUB_TG_LATEST) {
        Ok(x) => x,
        Err(e) => return format!("❌ Не получил список релизов: {}", e),
    };
    let Some(asset) = assets.iter().find(|a| a.name.eq_ignore_ascii_case(paths::TG_EXE_NAME)) else {
        return format!("❌ В релизе нет {}", paths::TG_EXE_NAME);
    };
    let dir = tools.join("tgproxy");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return format!("❌ Ошибка создания папки {}: {}", dir.display(), e);
    }
    let dest = dir.join(paths::TG_EXE_NAME);
    let tmp = PathBuf::from(format!("{}.download", dest.display()));
    let _ = std::fs::remove_file(&tmp);
    if let Err(e) = download_with_progress(app, "tg", &asset.url, &tmp, asset) {
        let _ = std::fs::remove_file(&tmp);
        return format!("❌ Ошибка скачивания: {}", e);
    }
    let (_, pe) = is_pe(&tmp);
    if !pe {
        let _ = std::fs::remove_file(&tmp);
        return "❌ Скачанный файл не является Windows-исполняемым — обновление отменено".into();
    }
    let old = PathBuf::from(format!("{}.old", dest.display()));
    let _ = std::fs::remove_file(&old);
    if let Err(e) = std::fs::rename(&dest, &old) {
        if e.kind() != std::io::ErrorKind::NotFound {
            let _ = std::fs::remove_file(&tmp);
            return format!("❌ Не удалось заменить старый файл: {}", e);
        }
    }
    if let Err(e) = std::fs::rename(&tmp, &dest) {
        if std::fs::rename(&old, &dest).is_err() {
            log_add("update", &format!("ОТКАТ ОБНОВЛЕНИЯ TG УПАЛ: старый файл остался в {}: {}", old.display(), e));
        }
        let _ = std::fs::remove_file(&tmp);
        return format!("❌ Не удалось сохранить новый файл: {}", e);
    }
    let _ = std::fs::remove_file(&old);
    write_version(tools, "tgproxy", &tag);
    format!("✅ TG WS Proxy обновлён до {}", tag)
}

// isPE: размер + «MZ»-заголовок; нужен обновлению TG (PE-проверка скачанного exe)
fn is_pe(path: &Path) -> (i64, bool) {
    let Ok(mut f) = std::fs::File::open(path) else {
        return (0, false);
    };
    let size = f.metadata().map(|m| m.len() as i64).unwrap_or(0);
    let mut hdr = [0u8; 2];
    if f.read_exact(&mut hdr).is_err() {
        return (size, false);
    }
    (size, hdr[0] == b'M' && hdr[1] == b'Z')
}

// urlDecode для парсинга csqtt://-ссылок (password в legacy-формате url-encoded)
pub fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

// ---------- стратегии zapret ----------

pub fn start_strategy(state: &crate::state::AppState, name: &str) -> String {
    let tools = state.tools();
    let (dir, ok) = paths::zapret_dir(&tools);
    if !ok {
        return "❌ Zapret не установлен".into();
    }
    // имя с фронтенда — без валидации `cmd /c` запускал произвольный .bat
    if !paths::valid_strategy_name(&dir, name) {
        return "❌ Недопустимое имя стратегии".into();
    }
    let bat = dir.join(name);
    if !bat.exists() {
        return "❌ Стратегия не найдена".into();
    }
    if paths::find_file(&dir, paths::WINWS_NAME, 2).as_os_str().is_empty() {
        return format!(
            "❌ winws.exe не найден в {} — похоже, антивирус удалил его. Добавь папку в исключения антивируса и снова нажми «Установить»",
            dir.display()
        );
    }
    // Переключение стратегии = перезапуск: иначе processRunning увидит старый
    // winws и отрапортует успех, не запустив новый профиль.
    if sysinfo::process_running(paths::WINWS_NAME) {
        let _ = run_hidden("taskkill", &["/F", "/IM", paths::WINWS_NAME]);
        std::thread::sleep(Duration::from_millis(400));
    }
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new("cmd");
    cmd.args(["/c", &bat.display().to_string()]).current_dir(&dir).creation_flags(0x08000000);
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    log_add("zapret", &format!("запуск стратегии: {}", name));
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return format!("❌ Ошибка запуска: {}", e),
    };
    if let Some(out) = child.stdout.take() {
        std::thread::spawn(move || stream_to_log(out, "zapret"));
    }
    if let Some(err) = child.stderr.take() {
        std::thread::spawn(move || stream_to_log(err, "zapret"));
    }
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    for _ in 0..16 {
        std::thread::sleep(Duration::from_millis(500));
        if sysinfo::process_running(paths::WINWS_NAME) {
            save_selected_strategy(&tools, name);
            return format!("✅ Запущено: {}", name);
        }
    }
    let _ = run_hidden("taskkill", &["/F", "/IM", paths::WINWS_NAME]);
    "⚠️ winws не запустился за 8 секунд — смотри панель «Логи» (если драйвер завис после переустановки, помогает перезагрузка ПК)".into()
}

pub fn stop_zapret() -> String {
    if !sysinfo::process_running(paths::WINWS_NAME) {
        return "winws.exe и так не запущен".into();
    }
    if let Err(e) = run_hidden("taskkill", &["/F", "/IM", paths::WINWS_NAME]) {
        return format!("❌ Не удалось остановить: {}", e);
    }
    log_add("zapret", "остановлено");
    "✅ Остановлено".into()
}

// pub: поток вывода spawned-процесса в лог (zapret, tgproxy, warp)
pub fn stream_to_log<R: Read>(mut stream: R, comp: &str) {
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
                    let line = line.trim_end_matches('\r');
                    if !line.trim().is_empty() {
                        log_add(comp, line);
                    }
                }
                if buf.len() > 8000 {
                    let line = String::from_utf8_lossy(&buf);
                    log_add(comp, line.trim_end_matches('\r'));
                    buf.clear();
                }
            }
            Err(_) => break,
        }
    }
    if !buf.is_empty() {
        let line = String::from_utf8_lossy(&buf);
        log_add(comp, line.trim_end_matches('\r'));
    }
}

pub fn save_selected_strategy_pub(tools: &Path, name: &str) {
    save_selected_strategy(tools, name);
}

fn save_selected_strategy(tools: &Path, name: &str) {
    if let Err(e) = std::fs::write(paths::selected_strategy_file(tools), name.as_bytes()) {
        log_add("zapret", &format!("не удалось сохранить выбранную стратегию: {}", e));
    }
}

// ---------- tgproxy запуск/остановка + релей ----------

// processAlivePid — существует ли процесс с таким pid
pub fn process_alive_pid(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
        if h.is_null() {
            return false;
        }
        windows_sys::Win32::Foundation::CloseHandle(h);
        true
    }
}

fn process_image_path(pid: u32) -> String {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return String::new();
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let rc = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        windows_sys::Win32::Foundation::CloseHandle(h);
        if rc == 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..len as usize])
    }
}

// pid_image_is_self — имя образа процесса совпадает с нашим exe: защита от
// переиспользованного PID (taskkill /PID по устаревшему pid убил бы
// посторонний процесс). Не смогли прочитать образ — считаем «не наш».
pub(crate) fn pid_image_is_self(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let image = process_image_path(pid);
    if image.is_empty() {
        return false;
    }
    let Ok(self_exe) = std::env::current_exe() else {
        return false;
    };
    let base = Path::new(&image)
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let self_base = self_exe
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    !self_base.is_empty() && base == self_base
}

// blob_matches — байтовое сравнение файла с вшитым блобом: размерного
// сравнения недостаточно — битый/подменённый файл того же размера никогда
// не перезаписывался (ядро/wintun молча оставались повреждёнными).
pub(crate) fn blob_matches(path: &Path, blob: &[u8]) -> bool {
    match std::fs::read(path) {
        Ok(data) => data == blob,
        Err(_) => false,
    }
}

// relayProcessAlive дополнительно проверяет имя образа: stats-файл мог
// остаться от старого релея, а его pid — достаться другому процессу.
pub fn relay_process_alive(pid: i32) -> bool {
    if !process_alive_pid(pid) {
        return false;
    }
    let Ok(self_exe) = std::env::current_exe() else {
        return true;
    };
    let image = process_image_path(pid as u32);
    if image.is_empty() {
        return true; // не смогли прочитать образ — доверяем pid
    }
    let base = Path::new(&image)
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let self_base = self_exe
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if base == self_base {
        return true;
    }
    base == "sentor.exe" || base == "sentor_new.exe" || base == "sentor_relay.exe"
}

// prepareRelayExe — релей из копии: работающий релей не держит основной exe.
pub fn prepare_relay_exe(tools: &Path) -> Result<PathBuf, String> {
    let src = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = tools.join("relay");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // mingw-сборка статически импортирует WebView2Loader.dll: Windows ищет её
    // в папке ПРОЦЕССА ещё до main(), поэтому любая копия exe без рядом
    // лежащей DLL вообще не стартует (диалог «система не обнаружила
    // WebView2Loader.dll»). Раньше релей работал по случайности: он наследовал
    // CWD папки запуска Sentor, где DLL оказывалась в путях поиска. Копируем
    // её рядом с релеем явно — до раннего выхода «копия уже актуальна».
    let dll_dst = dir.join("WebView2Loader.dll");
    if !dll_dst.exists() {
        if let Some(src_dir) = src.parent() {
            let dll_src = src_dir.join("WebView2Loader.dll");
            if dll_src.exists() {
                if let Err(e) = std::fs::copy(&dll_src, &dll_dst) {
                    log_add("tgproxy", &format!("не удалось скопировать WebView2Loader.dll к релею: {}", e));
                }
            } else {
                log_add("tgproxy", "рядом с exe нет WebView2Loader.dll — релей может не запуститься");
            }
        }
    }
    let dst = dir.join("Sentor_relay.exe");
    if src.to_string_lossy().to_lowercase() == dst.to_string_lossy().to_lowercase() {
        return Ok(src);
    }
    let src_info = std::fs::metadata(&src).map_err(|e| e.to_string())?;
    if let Ok(dst_info) = std::fs::metadata(&dst) {
        if dst_info.len() == src_info.len() && dst_info.modified().ok() >= src_info.modified().ok() {
            return Ok(dst);
        }
    }
    let tmp = PathBuf::from(format!("{}.new", dst.display()));
    let _ = std::fs::remove_file(&tmp);
    std::fs::copy(&src, &tmp).map_err(|e| e.to_string())?;
    if let Err(e) = std::fs::remove_file(&dst) {
        if e.kind() != std::io::ErrorKind::NotFound {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.to_string());
        }
    }
    std::fs::rename(&tmp, &dst).map_err(|e| e.to_string())?;
    Ok(dst)
}

// Жизненный цикл релея сериализуем мьютексом: без него ensure_relay (setup
// при старте) и start_tg_proxy (команда UI) оба проходили stats_ok=false и
// поднимали два экземпляра — второй становился осиротевшим процессом со
// случайным портом (listen "0"), stats перезаписывал последний писатель.
static RELAY_MU: Mutex<()> = Mutex::new(());

fn start_relay(state: &crate::state::AppState, listen: &str) -> Result<(), String> {
    let tools = state.tools();
    let path = paths::relay_stats_path(&tools);
    let _ = std::fs::remove_file(&path);
    let exe = match prepare_relay_exe(&tools) {
        Ok(e) => e,
        Err(e) => {
            // Копия не создалась — запускаем из основного exe.
            log_add("tgproxy", &format!("не удалось подготовить копию релея: {}", e));
            std::env::current_exe().map_err(|e| e.to_string())?
        }
    };
    let backend = {
        let m = crate::relay::find_tg_config(&tools);
        crate::relay::cfg_port(m.as_ref())
    };
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(["--relay", listen, &backend, &path.display().to_string()])
        .creation_flags(0x08000000); // CREATE_NO_WINDOW
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(data) = std::fs::read(&path) {
            if let Ok(s) = serde_json::from_slice::<RelayStats>(&data) {
                if s.pid == pid as i32 && crate::conn::port_open(s.port) {
                    std::thread::spawn(move || {
                        let _ = child.wait();
                    });
                    return Ok(());
                }
            }
        }
        match child.try_wait() {
            Ok(Some(_)) => return Err("релей не запустился: процесс завершился".into()),
            Err(e) => return Err(e.to_string()),
            Ok(None) => {}
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            // без wait дескриптор процесса бросается: wait подбирает код выхода
            let _ = child.wait();
            return Err("релей не записал stats за 3 секунды".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ensureRelay — релей должен быть запущен (если жив старый — используем его).
pub fn ensure_relay(state: &crate::state::AppState) -> Result<(), String> {
    let _g = RELAY_MU.lock().unwrap_or_else(|e| e.into_inner());
    let tools = state.tools();
    let path = paths::relay_stats_path(&tools);
    let stats_ok = |path: &Path| -> bool {
        if let Ok(data) = std::fs::read(path) {
            if let Ok(s) = serde_json::from_slice::<RelayStats>(&data) {
                if relay_process_alive(s.pid) && crate::conn::port_open(s.port) {
                    return true;
                }
            }
        }
        false
    };
    if stats_ok(&path) {
        return Ok(()); // уже работает
    }
    // На привычном порту кто-то жив: мог быть старый релей с потерянным stats —
    // даём ему восстановиться, иначе подняли бы второй экземпляр.
    if crate::conn::port_open(14430) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if stats_ok(&path) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        return Err("порт 14430 занят другим процессом, а живого релея в stats нет — подключи Telegram напрямую к его порту или перезагрузи ПК".into());
    }
    let _ = std::fs::remove_file(&path);
    let mut last_err = String::new();
    for listen in ["14430", "0"] {
        match start_relay(state, listen) {
            Ok(_) => return Ok(()),
            Err(e) => last_err = e,
        }
    }
    Err(format!("счётный релей не поднялся: {}", last_err))
}

pub fn kill_relay(tools: &Path) {
    let _g = RELAY_MU.lock().unwrap_or_else(|e| e.into_inner());
    let path = paths::relay_stats_path(tools);
    if let Ok(data) = std::fs::read(&path) {
        if let Ok(s) = serde_json::from_slice::<RelayStats>(&data) {
            if relay_process_alive(s.pid) {
                let _ = run_hidden("taskkill", &["/F", "/PID", &s.pid.to_string()]);
            }
        }
    }
    let _ = std::fs::remove_file(&path);
}

// relayPortNow — фактический порт живого релея (или порт прокси напрямую)
pub fn relay_port_now(tools: &Path) -> String {
    if let Ok(data) = std::fs::read(paths::relay_stats_path(tools)) {
        if let Ok(s) = serde_json::from_slice::<RelayStats>(&data) {
            if relay_process_alive(s.pid) {
                return s.port.to_string();
            }
        }
    }
    let m = crate::relay::find_tg_config(tools);
    crate::relay::cfg_port(m.as_ref())
}

pub fn relay_running(tools: &Path) -> bool {
    if let Ok(data) = std::fs::read(paths::relay_stats_path(tools)) {
        if let Ok(s) = serde_json::from_slice::<RelayStats>(&data) {
            return relay_process_alive(s.pid) && crate::conn::port_open(s.port);
        }
    }
    false
}

pub fn start_tg_proxy(state: &crate::state::AppState) -> String {
    let tools = state.tools();
    let exe = tools.join("tgproxy").join(paths::TG_EXE_NAME);
    if !exe.exists() {
        return "❌ TG-прокси не установлен".into();
    }
    if sysinfo::process_running(paths::TG_EXE_NAME) {
        // прокси уже работает (например, остался с прошлой сессии) —
        // релей всё равно должен быть поднят
        return match ensure_relay(state) {
            Ok(_) => "Уже запущен".into(),
            Err(e) => format!("Уже запущен, но счётчик трафика не поднялся: {}", e),
        };
    }
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new(&exe);
    cmd.current_dir(exe.parent().unwrap_or(Path::new("."))).creation_flags(0x00000008); // DETACHED_PROCESS
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    log_add("tgproxy", "запуск TG WS Proxy");
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return format!("❌ Ошибка запуска: {}", e),
    };
    // кэш статуса мог помнить «не запущен» — сбрасываем, чтобы первый же
    // опрос UI увидел живой процесс
    sysinfo::invalidate_process_cache(paths::TG_EXE_NAME);
    if let Some(out) = child.stdout.take() {
        std::thread::spawn(move || stream_to_log(out, "tgproxy"));
    }
    if let Some(err) = child.stderr.take() {
        std::thread::spawn(move || stream_to_log(err, "tgproxy"));
    }
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    // (скрытие окон tg-ws-proxy через EnumWindows опущено: DETACHED_PROCESS
    // уже не даёт консольного окна)
    // Даём tg-ws-proxy время создать config.json и открыть порт: релей должен
    // узнать фактический backend-порт, а не стартовать с дефолтным 1443.
    let mut backend_ready = false;
    for _ in 0..20 {
        if !sysinfo::process_running(paths::TG_EXE_NAME) {
            return "❌ TG-прокси завершился сразу после запуска — смотри панель «Логи»".into();
        }
        let m = crate::relay::find_tg_config(&tools);
        let backend = crate::relay::cfg_port(m.as_ref());
        if let Ok(n) = backend.parse::<i32>() {
            if crate::conn::port_open(n) {
                backend_ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    // Счётный релей — отдельный процесс, живёт даже при закрытом окне
    if let Err(e) = ensure_relay(state) {
        return format!("✅ TG-прокси запущен, но счётчик трафика не поднялся: {}", e);
    }
    if !backend_ready {
        return format!(
            "⚠️ TG-прокси запущен, но его порт пока не отвечает. Релей слушает 127.0.0.1:{} — проверь логи tg-ws-proxy",
            relay_port_now(&tools)
        );
    }
    format!(
        "✅ TG-прокси запущен. В Telegram используй прокси 127.0.0.1:{} (добавится кнопкой «Добавить в Telegram»)",
        relay_port_now(&tools)
    )
}

pub fn stop_tg_proxy(tools: &Path) -> String {
    if !sysinfo::process_running(paths::TG_EXE_NAME) {
        kill_relay(tools);
        sysinfo::invalidate_process_cache(paths::TG_EXE_NAME);
        return "TG-прокси и так не запущен".into();
    }
    // порядок обратный запуску: релей убивается ПОСЛЕ tg — иначе прокси
    // оставался жить, стучась в мёртвый порт релея
    if let Err(e) = run_hidden("taskkill", &["/F", "/IM", paths::TG_EXE_NAME]) {
        kill_relay(tools);
        sysinfo::invalidate_process_cache(paths::TG_EXE_NAME);
        return format!("❌ Не удалось остановить: {}", e);
    }
    // taskkill возвращается раньше, чем процесс исчезает из снимка системы:
    // UI после первого клика ещё пару секунд считал прокси живым и требовал
    // повторного нажатия. Ждём фактической смерти (до 4 с).
    let mut gone = false;
    for _ in 0..16 {
        if !sysinfo::process_running(paths::TG_EXE_NAME) {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    kill_relay(tools);
    sysinfo::invalidate_process_cache(paths::TG_EXE_NAME);
    log_add("tgproxy", "остановлено");
    if gone {
        "✅ Остановлено".into()
    } else {
        "⚠️ Команда остановки отправлена — процесс завершается".into()
    }
}

// add_to_telegram — открыть tg:// ссылку прокси в Telegram.
// direct=false: порт СЧЁТНОГО релея (учёт трафика на карточке Telegram);
// «ещё не запущен» = предпочтительный 14430: ссылка оживает сразу.
// direct=true: порт tg-ws-proxy НАПРЯМУЮ, мимо релея — трафик через
// такой прокси в счётчике не отображается.
pub fn add_to_telegram(tools: &Path, direct: bool) -> String {
    if !sysinfo::process_running(paths::TG_EXE_NAME) {
        return "❌ Сначала запусти TG-прокси".into();
    }
    let m = crate::relay::find_tg_config(tools);
    let cfg_str = |m: Option<&serde_json::Map<String, serde_json::Value>>, key: &str| -> String {
        m.and_then(|mm| mm.get(key))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    let mut secret = cfg_str(m.as_ref(), "secret");
    if secret.is_empty() {
        return "❌ Не нашёл секрет в конфиге tg-ws-proxy — возьми ссылку в его трее («Скопировать ссылку»)".into();
    }
    secret = secret.replace([':', ' '], "");
    let mut host = cfg_str(m.as_ref(), "host");
    if host.is_empty() || host == "0.0.0.0" || host == "::" {
        host = "127.0.0.1".into();
    }
    let (port, how) = if direct {
        let p = crate::relay::cfg_port(m.as_ref());
        let p = if p == "0" || p.is_empty() { "1443".to_string() } else { p };
        (p, "напрямую (без счётчика трафика)")
    } else if relay_running(tools) {
        (relay_port_now(tools), "через релей")
    } else {
        ("14430".to_string(), "через релей")
    };
    let link = format!(
        "tg://proxy?server={}&port={}&secret={}",
        query_escape(&host),
        query_escape(&port),
        query_escape(&secret)
    );
    use std::os::windows::process::CommandExt;
    let rc = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", &link])
        .creation_flags(0x08000000)
        .spawn();
    if let Err(e) = rc {
        return format!("❌ Не удалось открыть ссылку: {}", e);
    }
    format!("✅ Telegram открыт ({}), порт {} — подтверди добавление прокси", how, port)
}

fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ---------- версии и обновления ----------

pub fn write_version(tools: &Path, name: &str, v: &str) {
    if let Err(e) = std::fs::write(paths::version_file(tools, name), v.as_bytes()) {
        // без версии CheckUpdates посчитает установленное «неизвестным»
        log_add("update", &format!("не удалось записать версию {}: {}", name, e));
    }
}

pub fn norm_ver(v: &str) -> String {
    v.trim().to_lowercase().strip_prefix('v').unwrap_or(v.trim()).to_string()
}

// CheckUpdates сравнивает установленные версии с последними релизами GitHub.
pub fn check_updates(tools: &Path) -> UpdateInfo {
    let mut info = UpdateInfo {
        zapret_installed: paths::read_version(tools, "zapret"),
        tg_installed: paths::read_version(tools, "tgproxy"),
        ..Default::default()
    };
    let (_, z_ok) = paths::zapret_dir(tools);
    info.zapret_has = z_ok;
    info.tg_has = tools.join("tgproxy").join(paths::TG_EXE_NAME).exists();
    let mut errs: Vec<String> = Vec::new();
    match github_release(GITHUB_ZAPRET_RELEASE) {
        Err(e) => errs.push(format!("Zapret: {}", e)),
        Ok((tag, _)) => {
            info.zapret_latest = tag.clone();
            info.zapret_update = info.zapret_has && norm_ver(&tag) != norm_ver(&info.zapret_installed);
        }
    }
    match github_release(GITHUB_TG_LATEST) {
        Err(e) => errs.push(format!("TG Proxy: {}", e)),
        Ok((tag, _)) => {
            info.tg_latest = tag.clone();
            info.tg_update = info.tg_has && norm_ver(&tag) != norm_ver(&info.tg_installed);
        }
    }
    info.error = errs.join("; ");
    info
}

// tool_sources — откуда берутся утилиты: свежая установка идёт из вшитого в
// приложение пакета, обновления качаются с GitHub Releases (по API релизов).
// Список отдаём командой, чтобы фронтенд не дублировал адреса.
pub fn tool_sources() -> ToolSources {
    ToolSources {
        zapret_repo: GITHUB_ZAPRET_REPO.to_string(),
        zapret_releases: format!("{}/releases", GITHUB_ZAPRET_REPO),
        zapret_api: GITHUB_ZAPRET_RELEASE.to_string(),
        zapret_asset: "ZIP-архив из последнего релиза".to_string(),
        tg_repo: GITHUB_TG_REPO.to_string(),
        tg_releases: format!("{}/releases", GITHUB_TG_REPO),
        tg_api: GITHUB_TG_LATEST.to_string(),
        tg_asset: format!("{} (exe из релиза)", paths::TG_EXE_NAME),
    }
}

// ---------- ядра ----------

static VPN_CORE_MU: Mutex<()> = Mutex::new(());

// ensure_warp_helper — распаковать SentorWarp.exe (amneziawg-go ядро WARP)
// в vpn\core перед подключением WARP. Идемпотентно: файл нужного размера не
// перезаписывается. Вызывается из run_warp при каждом подключении — тогда
// хелпер появляется даже у тех, кто не жмёт «Установить ядро».
pub fn ensure_warp_helper(tools: &Path) -> Result<(), String> {
    let _guard = VPN_CORE_MU.lock().unwrap_or_else(|e| e.into_inner());
    let Some(blob) = embedded(paths::WARP_HELPER_EXE) else {
        return Err("вшитый SentorWarp.exe не найден".into());
    };
    let core_dir = paths::vpn_core_dir(tools);
    let _ = std::fs::create_dir_all(&core_dir);
    let exe_path = core_dir.join(paths::WARP_HELPER_EXE);
    let need_write = match std::fs::metadata(&exe_path) {
        Ok(st) => st.len() != blob.len() as u64 || !blob_matches(&exe_path, blob),
        Err(_) => true,
    };
    if need_write {
        std::fs::write(&exe_path, blob).map_err(|e| format!("запись {}: {}", exe_path.display(), e))?;
    }
    Ok(())
}

// VpnInstallCore распаковывает вшитое ядро (sing-box|xray) в vpn\core.
// Идемпотентно: файл нужного размера не перезаписывается.
pub fn vpn_install_core(tools: &Path, core: &str) -> String {
    let _guard = VPN_CORE_MU.lock().unwrap_or_else(|e| e.into_inner());
    let (blob, exe_name) = match core {
        "sing-box" => (embedded("sing-box.exe"), "sing-box.exe"),
        "xray" => (embedded("xray.exe"), "xray.exe"),
        _ => return format!("❌ Неизвестное ядро: {}", core),
    };
    let Some(blob) = blob else {
        return "❌ Вшитое ядро не найдено".into();
    };
    let core_dir = paths::vpn_core_dir(tools);
    let _ = std::fs::create_dir_all(&core_dir);
    let exe_path = core_dir.join(exe_name);
    let need_write = match std::fs::metadata(&exe_path) {
        Ok(st) => st.len() != blob.len() as u64 || !blob_matches(&exe_path, blob),
        Err(_) => true,
    };
    if need_write {
        if let Err(e) = std::fs::write(&exe_path, blob) {
            return format!("❌ {}", e);
        }
    }
    if core == "sing-box" {
        let dll = core_dir.join("wintun.dll");
        let dll_blob = embedded("wintun.dll").unwrap_or(&[]);
        if dll_blob.is_empty() {
            // пустой блоб нельзя писать на диск: получится битая dll вместо
            // честной ошибки установки
            return "❌ вшитый wintun.dll не найден".into();
        }
        let need_dll = match std::fs::metadata(&dll) {
            Ok(st) => st.len() != dll_blob.len() as u64 || !blob_matches(&dll, dll_blob),
            Err(_) => true,
        };
        if need_dll {
            if let Err(e) = std::fs::write(&dll, dll_blob) {
                return format!("❌ wintun.dll: {}", e);
            }
        }
    }
    write_version(tools, &format!("vpncore_{}", core), "embedded");
    format!("✅ Ядро {} установлено ({} МБ)", core, blob.len() / 1024 / 1024)
}
