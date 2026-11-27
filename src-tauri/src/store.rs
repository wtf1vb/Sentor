// JSON store helpers - port of Go atomicWriteJSON/renameBad and the
// load/save functions for proxies, settings, subs, traffic, pwdtt servers.
use std::collections::HashMap;
use std::path::Path;

use serde::{de::DeserializeOwned, Serialize};

use crate::logging::log_add;
use crate::models::{CqsttServer, PwdttServer, TrafficFileState, VpnProxy, VpnSettings, VpnSubscription};

// atomicWriteJSON — запись через tmp + rename: читатель никогда не видит
// полузаписанный файл. Уникальный суффикс tmp защищает от двух параллельных
// писателей одного файла (общий ".tmp" давал rename-ошибку и потерю апдейта),
// sync_all перед rename — данные реально на диске при обрыве питания.
pub fn atomic_write_json<T: Serialize>(path: &Path, v: &T) -> Result<(), String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let data = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = format!("{}.{}.{}.tmp", path_buf_display(path), std::process::id(), seq);
    let tmp = Path::new(&tmp);
    let write_res = (|| -> Result<(), String> {
        let mut f = std::fs::File::create(tmp)
            .map_err(|e| format!("create {}: {}", tmp.display(), e))?;
        use std::io::Write;
        f.write_all(data.as_bytes()).map_err(|e| format!("write {}: {}", tmp.display(), e))?;
        f.sync_all().map_err(|e| format!("sync {}: {}", tmp.display(), e))
    })();
    if let Err(e) = write_res {
        log_add("vpn", &format!("не удалось записать {}: {}", tmp.display(), e));
        let _ = std::fs::remove_file(tmp);
        return Err(e);
    }
    std::fs::rename(tmp, path).map_err(|e| {
        log_add("vpn", &format!("не удалось заменить {}: {}", path.display(), e));
        let _ = std::fs::remove_file(tmp);
        e.to_string()
    })
}

fn path_buf_display(p: &Path) -> String {
    p.display().to_string()
}

// renameBad — убрать повреждённый json с дороги (.bad-копия).
pub fn rename_bad(path: &Path) {
    let bad = path_buf_display(path) + ".bad";
    let _ = std::fs::remove_file(&bad);
    let _ = std::fs::rename(path, &bad);
}

fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    serde_json::from_slice(&data).map_err(|e| e.to_string())
}

// ---------- vpn ----------

pub fn load_vpn_proxies(tools: &Path) -> Vec<VpnProxy> {
    let path = crate::paths::vpn_proxies_path(tools);
    match load_json::<Vec<VpnProxy>>(&path) {
        Ok(list) => list,
        Err(e) => {
            // отсутствующий файл — это пустой список, а не ошибка
            if std::fs::metadata(&path).is_ok() {
                log_add("vpn", &format!("proxies.json повреждён ({}) — сохраняю копию .bad", e));
                rename_bad(&path);
            }
            Vec::new()
        }
    }
}

pub fn save_vpn_proxies(tools: &Path, list: &[VpnProxy]) -> Result<(), String> {
    let _ = std::fs::create_dir_all(crate::paths::vpn_dir(tools));
    atomic_write_json(&crate::paths::vpn_proxies_path(tools), &list.to_vec())
}

pub fn load_vpn_settings(tools: &Path) -> VpnSettings {
    let path = crate::paths::vpn_settings_path(tools);
    let mut s: VpnSettings = match load_json(&path) {
        Ok(s) => s,
        Err(e) => {
            if std::fs::metadata(&path).is_ok() {
                log_add("vpn", &format!("settings.json повреждён ({}) — сохраняю копию .bad", e));
                rename_bad(&path);
            }
            VpnSettings::default()
        }
    };
    s = s.normalize();
    s
}

pub fn save_vpn_settings(tools: &Path, s: &VpnSettings) -> Result<(), String> {
    let _ = std::fs::create_dir_all(crate::paths::vpn_dir(tools));
    atomic_write_json(&crate::paths::vpn_settings_path(tools), s)
}

pub fn load_vpn_subs(tools: &Path) -> Vec<VpnSubscription> {
    let path = crate::paths::vpn_subs_path(tools);
    match load_json::<Vec<VpnSubscription>>(&path) {
        Ok(list) => list,
        Err(e) => {
            if std::fs::metadata(&path).is_ok() {
                log_add("vpn", &format!("subscriptions.json повреждён ({}) — сохраняю копию .bad", e));
                rename_bad(&path);
            }
            Vec::new()
        }
    }
}

pub fn save_vpn_subs(tools: &Path, list: &[VpnSubscription]) -> Result<(), String> {
    let _ = std::fs::create_dir_all(crate::paths::vpn_dir(tools));
    atomic_write_json(&crate::paths::vpn_subs_path(tools), &list.to_vec())
}

// ---------- traffic ----------

// loadTrafficTotals: новый формат TrafficFileState, старый — map[string]uint64.
// Возвращает (totals, relay_pid, relay_prev); relay_pid = -1 для старого формата.
pub fn load_traffic_totals(tools: &Path) -> (HashMap<String, u64>, i32, u64) {
    let mut totals: HashMap<String, u64> = HashMap::new();
    totals.insert("telegram".into(), 0);
    let path = crate::paths::traffic_file(tools);
    let Ok(data) = std::fs::read(&path) else {
        return (totals, 0, 0);
    };
    match serde_json::from_slice::<TrafficFileState>(&data) {
        Ok(st) => {
            let mut relay_pid = st.relay_pid.unwrap_or(0);
            let relay_prev = st.relay_bytes.unwrap_or(0);
            totals.insert("telegram".into(), st.telegram);
            // Файл старого формата: relayPid/relayBytes ещё не сохранялись.
            if st.telegram > 0 && (st.version.unwrap_or(0) == 0 || st.relay_pid.unwrap_or(0) == 0) {
                relay_pid = -1;
            }
            (totals, relay_pid, relay_prev)
        }
        Err(_) => {
            // Совсем старый формат — просто map[string]uint64.
            if let Ok(old) = serde_json::from_slice::<HashMap<String, u64>>(&data) {
                let telegram = old.get("telegram").copied().unwrap_or(0);
                totals.extend(old);
                let mut relay_pid = 0;
                if telegram > 0 {
                    relay_pid = -1;
                }
                return (totals, relay_pid, 0);
            }
            (totals, 0, 0)
        }
    }
}

pub fn save_traffic_totals(tools: &Path, telegram: u64, relay_pid: i32, relay_prev: u64) {
    let st = TrafficFileState {
        telegram,
        relay_pid: if relay_pid == 0 { None } else { Some(relay_pid) },
        relay_bytes: if relay_prev == 0 { None } else { Some(relay_prev) },
        version: Some(1),
    };
    // Ошибку не глотаем совсем: при переполнении диска/блокировке файла
    // счётчик молча переставал сохраняться — в лог это не попадало никогда
    if let Err(e) = atomic_write_json(&crate::paths::traffic_file(tools), &st) {
        log_add("traffic", &format!("traffic.json не сохранился: {}", e));
    }
}

// ---------- pwdtt ----------

pub fn load_pwdtt_servers(tools: &Path) -> Vec<PwdttServer> {
    let path = crate::paths::pwdtt_servers_path(tools);
    match load_json::<Vec<PwdttServer>>(&path) {
        Ok(list) => list,
        Err(e) => {
            if std::fs::metadata(&path).is_ok() {
                log_add("pwdtt", &format!("pwdtt.json повреждён ({}) — сохраняю копию .bad", e));
                rename_bad(&path);
            }
            Vec::new()
        }
    }
}

pub fn save_pwdtt_servers(tools: &Path, list: &[PwdttServer]) -> Result<(), String> {
    let _ = std::fs::create_dir_all(crate::paths::pwdtt_dir(tools));
    atomic_write_json(&crate::paths::pwdtt_servers_path(tools), &list.to_vec())
}

// ---------- cqstt ----------

pub fn load_cqstt_servers(tools: &Path) -> Vec<CqsttServer> {
    let path = crate::paths::cqstt_servers_path(tools);
    match load_json::<Vec<CqsttServer>>(&path) {
        Ok(list) => list,
        Err(e) => {
            if std::fs::metadata(&path).is_ok() {
                log_add("cqstt", &format!("cqstt.json повреждён ({}) — сохраняю копию .bad", e));
                rename_bad(&path);
            }
            Vec::new()
        }
    }
}

pub fn save_cqstt_servers(tools: &Path, list: &[CqsttServer]) -> Result<(), String> {
    let _ = std::fs::create_dir_all(crate::paths::cqstt_dir(tools));
    atomic_write_json(&crate::paths::cqstt_servers_path(tools), &list.to_vec())
}

#[cfg(test)]
mod diag_tests {
    use super::*;

    // READ-ONLY: парсим реальные файлы пользователя, ничего не пишем.
    // Игнорируется по умолчанию: тест привязан к личному D:\NetTools этой
    // машины и падает на любой другой. Запуск вручную: cargo test -- --ignored
    #[test]
    #[ignore]
    fn real_files_parse() {
        let tools = std::path::Path::new("D:\\NetTools");
        let subs = load_vpn_subs(tools);
        println!("subs parsed: {}", subs.len());
        for s in &subs {
            println!("  - {} / {} / count={}", s.id, s.name, s.count);
        }
        let px = load_vpn_proxies(tools);
        println!("proxies parsed: {}", px.len());
        let st = load_vpn_settings(tools);
        println!("core: {}", st.core);
        assert!(subs.len() >= 5, "subs = {}", subs.len());
    }
}
