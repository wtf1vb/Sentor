// System proxy via Windows registry - port of Go writeSystemProxy/readSystemProxySettings,
// proxyBackup and the stale-cleanup logic (vpn.go).
use std::path::Path;

use serde::{Deserialize, Serialize};

use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ,
};

use crate::logging::log_add;

const INET_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxyBackup {
    pub enabled: bool,
    pub server: String,
    // прежний AutoConfigURL (свой PAC пользователя, если был) — возвращаем
    // при отключении системного прокси
    #[serde(default)]
    pub autoconfig: String,
}

pub fn read_system_proxy() -> (bool, String) {
    unsafe {
        let mut hk: HKEY = std::mem::zeroed();
        if RegOpenKeyExW(HKEY_CURRENT_USER, to_wide(INET_KEY).as_ptr(), 0, KEY_QUERY_VALUE, &mut hk) != 0 {
            return (false, String::new());
        }
        let mut enabled = false;
        let mut v: u32 = 0;
        let mut sz: u32 = 4;
        let mut ty: u32 = 0;
        if RegQueryValueExW(hk, to_wide("ProxyEnable").as_ptr(), std::ptr::null(), &mut ty, (&mut v as *mut u32).cast(), &mut sz) == 0
            && ty == REG_DWORD
        {
            enabled = v == 1;
        }
        let mut server = String::new();
        let mut buf = [0u16; 512];
        let mut bsz = (buf.len() * 2) as u32;
        ty = 0;
        if RegQueryValueExW(hk, to_wide("ProxyServer").as_ptr(), std::ptr::null(), &mut ty, buf.as_mut_ptr().cast(), &mut bsz) == 0
            && ty == REG_SZ
        {
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            server = String::from_utf16_lossy(&buf[..end]);
        }
        RegCloseKey(hk);
        (enabled, server)
    }
}

pub fn write_system_proxy(enabled: bool, server: &str) -> Result<(), String> {
    unsafe {
        let mut hk: HKEY = std::mem::zeroed();
        if RegOpenKeyExW(HKEY_CURRENT_USER, to_wide(INET_KEY).as_ptr(), 0, KEY_SET_VALUE, &mut hk) != 0 {
            let msg = "реестр не открылся на запись".to_string();
            log_add("proxy", &msg);
            return Err(msg);
        }
        let en: u32 = if enabled { 1 } else { 0 };
        // LSTATUS больше не теряется: без проверки UI показывал «прокси
        // включён», а запись могла не пройти (права/политики)
        let mut err: Option<String> = None;
        let r1 = RegSetValueExW(hk, to_wide("ProxyEnable").as_ptr(), 0, REG_DWORD, (&en as *const u32).cast(), 4);
        if r1 != 0 {
            err = Some(format!("ProxyEnable: код {}", r1));
        }
        // Восстанавливаем и пустое значение: иначе после выключения в реестре
        // остаётся наш мёртвый 127.0.0.1:10808. Код 2 (нет значения) при
        // удалении — успех: удалить отсутствующее = оно отсутствует.
        let r2 = if server.is_empty() {
            RegDeleteValueW(hk, to_wide("ProxyServer").as_ptr())
        } else {
            let s = to_wide(server);
            RegSetValueExW(hk, to_wide("ProxyServer").as_ptr(), 0, REG_SZ, s.as_ptr().cast(), (s.len() * 2) as u32)
        };
        if r2 != 0 && r2 != 2 {
            err = Some(format!("ProxyServer: код {}", r2));
        }
        RegCloseKey(hk);
        if let Some(e) = err {
            log_add("proxy", &format!("запись реестра не удалась: {}", e));
            return Err(e);
        }
    }
    refresh_wininet();
    Ok(())
}

pub fn refresh_wininet() {
    use windows_sys::Win32::Networking::WinInet::InternetSetOptionW;
    unsafe {
        InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0); // INTERNET_OPTION_SETTINGS_CHANGED
        InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0); // INTERNET_OPTION_REFRESH
    }
}

// ---------- AutoConfigURL (свой PAC пользователя) ----------

// byedpi (YouTube-прокси «только youtube/googlevideo») полностью вырезан из
// приложения: его PAC-сервер на 10809 больше никогда не поднимается, поэтому
// наш старый URL в реестре — всегда мёртвый хвост. Константа и проверка
// file:// нужны только для уборки таких хвостов при старте; свой PAC
// приложение больше не ставит.
const LEGACY_BYEDPI_PAC_URL: &str = "http://127.0.0.1:10809/proxy.pac";

// легаси file:// URL первых сборок byedpi — опознаём и снимаем так же
fn legacy_byedpi_pac_url(tools: &Path, url: &str) -> bool {
    url.eq_ignore_ascii_case(LEGACY_BYEDPI_PAC_URL)
        || url.eq_ignore_ascii_case(&format!(
            "file:///{}/byedpi/proxy.pac",
            tools.display().to_string().replace('\\', "/")
        ))
}

// Чтение AutoConfigURL из того же ключа Internet Settings (REG_SZ; пусто — нет).
pub fn read_autoconfig() -> String {
    unsafe {
        let mut hk: HKEY = std::mem::zeroed();
        if RegOpenKeyExW(HKEY_CURRENT_USER, to_wide(INET_KEY).as_ptr(), 0, KEY_QUERY_VALUE, &mut hk) != 0 {
            return String::new();
        }
        let mut buf = [0u16; 1024];
        let mut bsz = (buf.len() * 2) as u32;
        let mut ty: u32 = 0;
        let mut url = String::new();
        if RegQueryValueExW(hk, to_wide("AutoConfigURL").as_ptr(), std::ptr::null(), &mut ty, buf.as_mut_ptr().cast(), &mut bsz) == 0
            && ty == REG_SZ
        {
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            url = String::from_utf16_lossy(&buf[..end]);
        }
        RegCloseKey(hk);
        url
    }
}

// Запись AutoConfigURL; пустая строка = удалить значение (код 2 = и так нет).
pub fn write_autoconfig(url: &str) -> Result<(), String> {
    unsafe {
        let mut hk: HKEY = std::mem::zeroed();
        if RegOpenKeyExW(HKEY_CURRENT_USER, to_wide(INET_KEY).as_ptr(), 0, KEY_SET_VALUE, &mut hk) != 0 {
            let msg = "реестр не открылся на запись (AutoConfigURL)".to_string();
            log_add("proxy", &msg);
            return Err(msg);
        }
        let r = if url.is_empty() {
            RegDeleteValueW(hk, to_wide("AutoConfigURL").as_ptr())
        } else {
            let s = to_wide(url);
            RegSetValueExW(hk, to_wide("AutoConfigURL").as_ptr(), 0, REG_SZ, s.as_ptr().cast(), (s.len() * 2) as u32)
        };
        RegCloseKey(hk);
        if r != 0 && r != 2 {
            let msg = format!("AutoConfigURL: код {}", r);
            log_add("proxy", &format!("запись реестра не удалась: {}", msg));
            return Err(msg);
        }
    }
    refresh_wininet();
    Ok(())
}

pub fn proxy_backup_path(tools: &Path) -> std::path::PathBuf {
    tools.join("system_proxy_backup.json")
}

// Целостность бэкапа: битый файл (усечённая запись, сбой диска) при
// восстановлении разбираться не будет — настройки пользователя вернутся
// «глушением» вместо возврата. Проверяем перед каждым включением прокси/PAC;
// битый пересоздаём из актуального реестра, но ТОЛЬКО если там сейчас нет
// наших значений (иначе в бэкап попали бы они и восстановить было бы нечего —
// тогда отказываемся включать: fail-safe вместо потери пользовательских настроек).
fn ensure_backup_integrity(tools: &Path) -> bool {
    let path = proxy_backup_path(tools);
    let Ok(data) = std::fs::read(&path) else {
        return true; // файла нет — не битый, создаст вызывающий
    };
    if serde_json::from_slice::<ProxyBackup>(&data).is_ok() {
        return true;
    }
    let _ = std::fs::remove_file(&path);
    let (enabled, server) = read_system_proxy();
    let ac = read_autoconfig();
    let low = server.to_lowercase();
    let ours_manual = enabled && (low.starts_with("127.0.0.1:") || low.starts_with("localhost:"));
    // наш легаси byedpi-PAC в реестре бэкапу не нужен: он мёртв навсегда,
    // восстановить его нельзя — хвост снимет cleanup_stale_system_proxy
    let ac = if legacy_byedpi_pac_url(tools, &ac) { String::new() } else { ac };
    if ours_manual {
        log_add("proxy", "бэкап прокси повреждён, в реестре наши значения — включение отменено");
        return false;
    }
    match crate::store::atomic_write_json(&path, &ProxyBackup { enabled, server, autoconfig: ac }) {
        Ok(()) => {
            log_add("proxy", "бэкап прокси повреждён — пересоздан из текущих настроек");
            true
        }
        Err(e) => {
            log_add(
                "proxy",
                &format!("бэкап прокси пересоздать не удалось ({}), включение отменено", e),
            );
            false
        }
    }
}

// setSystemProxy запоминает прежние настройки пользователя один раз, чтобы
// clearSystemProxy вернул именно их, а не просто выключил прокси.
// Возвращает false, если прокси включить не удалось (для логов вызывающего).
pub fn set_system_proxy(tools: &Path, addr: &str) -> bool {
    // битый бэкап чиним/отказываемся ДО включения — без валидного бэкапа
    // восстановить настройки пользователя после отключения было бы нечем
    if !ensure_backup_integrity(tools) {
        return false;
    }
    let path = proxy_backup_path(tools);
    match std::fs::metadata(&path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let (enabled, server) = read_system_proxy();
            // Бэкап обязателен: без него ставить прокси нельзя — исходные
            // настройки пользователя перезаписались бы без шанса на возврат.
            // AutoConfigURL тоже запоминаем: у пользователя может быть свой
            // PAC (корпоративный), его нужно вернуть при отключении.
            if let Err(e) = crate::store::atomic_write_json(
                &path,
                &ProxyBackup { enabled, server, autoconfig: read_autoconfig() },
            ) {
                log_add(
                    "proxy",
                    &format!("бэкап системного прокси не записан ({}), прокси НЕ включён", e),
                );
                return false;
            }
        }
        Err(e) => {
            // Stat упал не из-за отсутствия файла (права/диск) — бэкап
            // создать не удалось, значит включать прокси НЕЛЬЗЯ: исходные
            // настройки пользователя перезаписались бы без шанса на возврат
            log_add(
                "proxy",
                &format!("не удалось проверить бэкап системного прокси ({}), прокси НЕ включён", e),
            );
            return false;
        }
    }
    let ok = write_system_proxy(true, addr).is_ok();
    if ok {
        // прокси реально включён — ставим стража: убьют процесс (диспетчер,
        // крах, антивирус) — он восстановит настройки пользователя из бэкапа
        spawn_proxy_guard(tools);
    }
    ok
}

// ---------- страж системного прокси (переживает force-kill родителя) ----------

// Если Sentor убивают (диспетчер задач/крах/антивирус) при включённом системном
// прокси, graceful-очистка не успевает: в реестре остаётся ProxyEnable=1 на
// мёртвый 127.0.0.1:<порт> — у пользователя «интернет отвалится» до следующего
// запуска Sentor (а если он не запустится вовсе — навсегда). Страж — отдельный
// процесс sentor.exe --proxy-guard: ждёт смерти родителя и восстанавливает
// настройки из бэкапа. Один на жизнь процесса, Job Object'у НЕ назначается —
// обязан пережить родителя.
static PROXY_GUARD_SPAWNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn spawn_proxy_guard(tools: &Path) {
    use std::sync::atomic::Ordering;
    if PROXY_GUARD_SPAWNED.swap(true, Ordering::SeqCst) {
        return; // страж уже ждёт смерти этого же процесса — порты ему не важны
    }
    let Ok(exe) = std::env::current_exe() else {
        // спавн не состоялся — возвращаем флаг, чтобы попытка повторилась
        PROXY_GUARD_SPAWNED.store(false, Ordering::SeqCst);
        return;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args([
        "--proxy-guard",
        &std::process::id().to_string(),
        &tools.display().to_string(),
    ]);
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    if cmd.spawn().is_err() {
        // раньше флаг сгорал даже при неудачном спавне — страж больше не
        // поднимался до конца жизни процесса (антивирус зарезал первый запуск
        // → при падении приложения мёртвый прокси оставался навсегда)
        PROXY_GUARD_SPAWNED.store(false, Ordering::SeqCst);
    }
}

// run_proxy_guard — тело стража (sentor.exe --proxy-guard <pid> <toolsDir> [dns]).
// Режимы:
//  - обычный (VPN): ждёт смерти родителя и возвращает ручной ProxyEnable;
//  - dns: ждёт смерти DNS-блокировщика рекламы; умер нештатно (тумблер OFF
//    восстанавливает DNS сам и стражу всё равно) → вернуть DNS адаптеров.
pub fn run_proxy_guard(parent_pid: u32, tools_dir: &str, mode: &str) {
    let tools = Path::new(tools_dir);
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject, INFINITE};
    unsafe {
        let h = OpenProcess(SYNCHRONIZE, 0, parent_pid);
        if !h.is_null() {
            // держим хендл: wait безопасен относительно переиспользования PID
            WaitForSingleObject(h, INFINITE);
            windows_sys::Win32::Foundation::CloseHandle(h);
        }
        // OpenProcess не удался → процесс уже мёртв, чистим немедленно
    }
    if mode == "dns" {
        // DNS-блокировщик умер (крах/taskkill): вернуть исходные DNS адаптеров.
        // После штатного OFF restore уже отработал и здесь просто no-op —
        // restore трогает только адаптеры с НАШИМ 127.0.0.1/::1.
        std::thread::sleep(std::time::Duration::from_millis(500));
        crate::adsdns::restore_dns(tools);
        return;
    }
    // Дать graceful-очистке родителя (если выход был штатным) добежать:
    // прокси уже снят → cleanup увидит «не наш» и выйдет без изменений
    std::thread::sleep(std::time::Duration::from_millis(800));
    cleanup_stale_vpn_proxy(tools);
}

// cleanup_stale_vpn_proxy — уборка стража: вернуть ручной
// ProxyEnable/ProxyServer, если там наш мёртвый 127.0.0.1:vpn_local.
pub fn cleanup_stale_vpn_proxy(tools: &Path) {
    let path = proxy_backup_path(tools);
    let ours = format!("127.0.0.1:{}", crate::conn::vpn_local());
    let legacy_ours = format!("localhost:{}", crate::conn::vpn_local());
    let (enabled, server) = read_system_proxy();
    let low = server.to_lowercase();
    // локальный адрес — наш ТОЛЬКО если порт мёртв: живой локальный прокси
    // может быть чужим (Clash/v2rayN на 127.0.0.1:7890), а также это мог быть
    // УЖЕ ПОДНЯТЫЙ прокси нового инстанса — глушить/перезаписывать нельзя
    let our_local = (low.starts_with("127.0.0.1:") || low.starts_with("localhost:"))
        && match server_port(&server) {
            Some(p) => !port_alive(p as i32),
            None => true, // не распарсили — считаем нашим (как раньше)
        };
    let proxy_ours = enabled
        && (server.eq_ignore_ascii_case(&ours) || server.eq_ignore_ascii_case(&legacy_ours) || our_local);
    if !proxy_ours {
        // ручного нашего прокси нет — бэкап больше не актуален
        let _ = std::fs::remove_file(&path);
        return;
    }
    let Ok(data) = std::fs::read(&path) else {
        // бэкапа нет (старая версия/крах): глушим мёртвый прокси
        let _ = write_system_proxy(false, "");
        refresh_wininet();
        return;
    };
    let Ok(b) = serde_json::from_slice::<ProxyBackup>(&data) else {
        let _ = write_system_proxy(false, "");
        refresh_wininet();
        return;
    };
    let result = if b.enabled {
        write_system_proxy(true, &b.server)
    } else {
        write_system_proxy(false, &b.server)
    };
    if result.is_ok() {
        let _ = std::fs::remove_file(&path);
    }
    refresh_wininet();
}

pub fn clear_system_proxy_for(tools: &Path, ours: &str, legacy_ours: &str) {
    let path = proxy_backup_path(tools);
    if let Ok(data) = std::fs::read(&path) {
        match serde_json::from_slice::<ProxyBackup>(&data) {
            Ok(b) => {
                let (enabled, server) = read_system_proxy();
                // Не затираем то, что пользователь поменял вручную: восстанавливаем
                // бэкап только если в реестре всё ещё НАШ адрес.
                let ours_match = server.eq_ignore_ascii_case(ours) || server.eq_ignore_ascii_case(legacy_ours);
                // Бэкап удаляем только если восстановление реально прошло:
                // при сбое записи (права/политики) файл оставляем — попытку
                // вернуть настройки пользователя можно повторить
                let mut restored = false;
                if ours_match {
                    let result = if enabled {
                        write_system_proxy(b.enabled, &b.server)
                    } else {
                        // Пользователь сам выключил наш прокси: включать его прежний
                        // прокси за него нельзя, но и терять сохранённый ProxyServer
                        // тоже нечестно — возвращаем его строку с ProxyEnable=0
                        write_system_proxy(false, &b.server)
                    };
                    restored = result.is_ok();
                    // возвращаем и прежний AutoConfigURL (свой PAC пользователя),
                    // если он был и сейчас не стоит; легаси byedpi-PAC из старого
                    // бэкапа восстанавливать нельзя — он мёртв навсегда
                    if restored && !b.autoconfig.is_empty() && !legacy_byedpi_pac_url(tools, &b.autoconfig) {
                        let _ = write_autoconfig(&b.autoconfig);
                    }
                }
                if restored {
                    let _ = std::fs::remove_file(&path);
                }
            }
            // Бэкап не разбирается (битый) — восстанавливать из него нечего
            Err(_) => {
                let _ = std::fs::remove_file(&path);
            }
        }
        refresh_wininet();
        return;
    }
    // Бэкапа нет (старая версия/крах): выключаем только если в реестре
    // действительно наш мёртвый 127.0.0.1:10808.
    let (enabled, server) = read_system_proxy();
    let ours_match = server.eq_ignore_ascii_case(ours) || server.eq_ignore_ascii_case(legacy_ours);
    if enabled && ours_match {
        let _ = write_system_proxy(false, "");
    }
}

pub fn clear_system_proxy(tools: &Path) {
    let legacy = format!("localhost:{}", crate::conn::vpn_local());
    clear_system_proxy_for(tools, &format!("127.0.0.1:{}", crate::conn::vpn_local()), &legacy);
}

// cleanupStaleSystemProxy вызывается при старте: если прошлый процесс упал
// с включённым системным прокси — возвращаем настройки пользователя. Заодно
// снимаем хвост удалённого byedpi: старые сборки ставили его PAC в реестр,
// PAC-сервера (10809) больше не существует, и мёртвый AutoConfigURL ломал бы
// youtube-домены.
pub fn cleanup_stale_system_proxy(tools: &Path) {
    let path = proxy_backup_path(tools);
    let ours = format!("127.0.0.1:{}", crate::conn::vpn_local());
    let legacy_ours = format!("localhost:{}", crate::conn::vpn_local());
    let (enabled, server) = read_system_proxy();
    let ac = read_autoconfig();
    // Локальный адрес в реестре — наш ТОЛЬКО если порт мёртв: «любой
    // 127.0.0.1:* — наш» глушил чужой работающий прокси (Clash/v2rayN на
    // 127.0.0.1:7890) и уже поднятый прокси нового инстанса. Мёртвый порт =
    // хвост прошлого падения — глушим как раньше.
    let low = server.to_lowercase();
    let our_local = (low.starts_with("127.0.0.1:") || low.starts_with("localhost:"))
        && match server_port(&server) {
            Some(p) => !port_alive(p as i32),
            None => true, // не распарсили — считаем нашим (как раньше)
        };
    let proxy_ours = enabled
        && (server.eq_ignore_ascii_case(&ours) || server.eq_ignore_ascii_case(&legacy_ours) || our_local);
    // PAC удалённого byedpi (http://…10809/proxy.pac и легаси file://):
    // раздача не поднимется ни при каком раскладе — снимаем всегда
    let pac_ours = legacy_byedpi_pac_url(tools, &ac);
    if !proxy_ours && !pac_ours {
        // в реестре ничего нашего — бэкап больше не актуален
        let _ = std::fs::remove_file(&path);
        refresh_wininet();
        return;
    }
    let Ok(data) = std::fs::read(&path) else {
        // бэкапа нет (старая версия/крах): глушим только то, что реально наше
        if proxy_ours {
            let _ = write_system_proxy(false, "");
        }
        if pac_ours {
            let _ = write_autoconfig("");
        }
        refresh_wininet();
        return;
    };
    let Ok(b) = serde_json::from_slice::<ProxyBackup>(&data) else {
        let _ = std::fs::remove_file(&path);
        if proxy_ours {
            let _ = write_system_proxy(false, "");
        }
        if pac_ours {
            let _ = write_autoconfig("");
        }
        refresh_wininet();
        return;
    };
    // Бэкап удаляем только если восстановление реально прошло: при сбое
    // записи (права/политики) файл оставляем — следующий старт повторит
    let mut restored = true;
    if proxy_ours {
        let result = if b.enabled {
            write_system_proxy(true, &b.server)
        } else {
            // Пользователь сам выключил наш прокси: включать его прежний
            // прокси за него нельзя, но и терять сохранённый ProxyServer
            // тоже нечестно — возвращаем его строку с ProxyEnable=0
            write_system_proxy(false, &b.server)
        };
        restored &= result.is_ok();
    }
    if pac_ours {
        // вместо мёртвого byedpi-PAC возвращаем прежний PAC пользователя,
        // если он был сохранён в бэкапе (и это не наш же мёртвый URL)
        let new_ac = if !b.autoconfig.is_empty() && !legacy_byedpi_pac_url(tools, &b.autoconfig) {
            b.autoconfig.clone()
        } else {
            String::new()
        };
        restored &= write_autoconfig(&new_ac).is_ok();
    }
    if restored {
        let _ = std::fs::remove_file(&path);
    }
    refresh_wininet();
}

pub fn system_proxy_enabled() -> bool {
    let local = crate::conn::vpn_local();
    let (enabled, server) = read_system_proxy();
    enabled
        && (server.eq_ignore_ascii_case(&format!("127.0.0.1:{}", local))
            || server.eq_ignore_ascii_case(&format!("localhost:{}", local)))
}

// ---------- помощники распознавания «наших» значений в реестре ----------

fn port_alive(port: i32) -> bool {
    let p = port.clamp(1, 65535) as u16;
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], p));
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500)).is_ok()
}

// Порт из ProxyServer («127.0.0.1:10808», «localhost:10808», «h=1.2.3.4:80;...»)
fn server_port(server: &str) -> Option<u16> {
    server.split(';').next()?.rsplit(':').next()?.trim().parse().ok()
}