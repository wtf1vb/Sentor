// Decryption of client subscription links - port of Go happcrypt.go.
// happ://crypt..crypt5 — RSA (crypt1-4: склейка блоков с перебором паддингов;
// crypt5: маркер → RSA-4096 → AEAD-тело). incy://crypt1 — AES-256-GCM на
// деривированном из keymat ключе (контрольный отпечаток проверяется).
// v2raytun://crypt — RSA-блоки PKCS#1v15, три ключа. happ://add и
// v2raytun://import — обёртки вокруг обычной ссылки.
use aead::generic_array::GenericArray;
use aead::{Aead, KeyInit};
use base64::Engine;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::Digest;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::vpnlinks::b64_decode as vpn_b64;

// ---------- вшитый ключевой материал (шифрованный AES-256-GCM) ----------

// Материалы лежат в assets/happcrypt/*.enc (формат: «SKM1» + nonce 12 б + ct+tag,
// AAD = имя файла). Сам ключ шифрования в бинарнике в открытом виде не хранится:
// он собирается из «россыпи» слов (часть ^ маска) и прогоняется через SHA-256.
// Это защита от поиска по строкам в exe, но НЕ от целенаправленного реверса —
// полностью спрятать секрет внутри дистрибутива невозможно в принципе.
// После правки исходных ключей перегенерируйте .enc: cargo run --bin encrypt-keymat
const KM_PARTS: [u64; 4] = [0x6d8e0516500f9685, 0x7441d06a8de96c40, 0x216643511a0632b8, 0xaf8edd92ab851c54];
const KM_MASKS: [u64; 4] = [0x0eb1eb35f2e70375, 0x3766ad8bc0d91087, 0xbe56d6f9c96b522f, 0x852a52782517708b];

fn keymat_aes_key() -> [u8; 32] {
    let mut preimage = [0u8; 32];
    for i in 0..4 {
        preimage[i * 8..i * 8 + 8].copy_from_slice(&(KM_PARTS[i] ^ KM_MASKS[i]).to_le_bytes());
    }
    sha2::Sha256::digest(preimage).into()
}

fn keymat_decrypt(name: &str, blob: &'static [u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 4 + 12 + 16 || &blob[..4] != b"SKM1" {
        return Err("keymat: неверный формат блоба".into());
    }
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&keymat_aes_key()).map_err(|e| e.to_string())?;
    let (nonce, ct) = blob[4..].split_at(12);
    cipher
        .decrypt(
            GenericArray::from_slice(nonce),
            aead::Payload { msg: ct, aad: name.as_bytes() },
        )
        .map_err(|_| format!("keymat: {} не расшифровывается — перегенерируйте .enc (cargo run --bin encrypt-keymat)", name))
}

fn embedded(name: &str) -> Option<Vec<u8>> {
    let blob: &'static [u8] = match name {
        "happcrypt.json" => include_bytes!("../assets/happcrypt/happcrypt.json.enc"),
        "happcrypt5.json" => include_bytes!("../assets/happcrypt/happcrypt5.json.enc"),
        "v2keys.json" => include_bytes!("../assets/happcrypt/v2keys.json.enc"),
        "incy_keymat_a.b64" => include_bytes!("../assets/happcrypt/incy_keymat_a.b64.enc"),
        "incy_keymat_b.b64" => include_bytes!("../assets/happcrypt/incy_keymat_b.b64.enc"),
        _ => return None,
    };
    keymat_decrypt(name, blob).ok()
}

fn embedded_res(name: &str) -> Result<Vec<u8>, String> {
    embedded(name).ok_or_else(|| format!("asset {} не найден", name))
}

// ---------- AEAD-хелперы ----------

fn chacha_open(key: &[u8], nonce: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let a = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).ok()?;
    a.decrypt(GenericArray::from_slice(nonce), ct).ok()
}

fn aes_gcm_open(key: &[u8], nonce: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let a = aes_gcm::Aes256Gcm::new_from_slice(key).ok()?;
    a.decrypt(GenericArray::from_slice(nonce), ct).ok()
}

// ---------- базовые операции (один в один из crypto.py) ----------

// happB64Decode — base64 обычный и URL-safe; пробелы и паддинг игнорируются
fn happ_b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut s: String = s.split_whitespace().collect();
    s = s.replace('-', "+").replace('_', "/");
    let trimmed = s.trim_end_matches('=');
    let pad = (4 - trimmed.len() % 4) % 4;
    let padded = format!("{}{}", trimmed, "=".repeat(pad));
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .map_err(|e| e.to_string())
}

// happSwapPairs — обмен соседних байтов парами: 0<->1, 2<->3, ...
fn happ_swap_pairs(b: &[u8]) -> Vec<u8> {
    let mut t = b.to_vec();
    let mut i = 0;
    while i + 1 < t.len() {
        t.swap(i, i + 1);
        i += 2;
    }
    t
}

// happBlockSwap — перестановка блоков по 4 байта: ABCD -> CDAB (инволюция)
fn happ_block_swap(b: &[u8]) -> Vec<u8> {
    let mut t = b.to_vec();
    let n = t.len() - t.len() % 4;
    let mut i = 0;
    while i < n {
        t.swap(i, i + 2);
        t.swap(i + 1, i + 3);
        i += 4;
    }
    t
}

// happPEM — PEM-блок из base64-тела, переносы по 64 символа.
// Режем по СИМВОЛАМ: байтовый срез паниковал бы на не-ASCII теле (граница
// символа UTF-8), сейчас все входы — ASCII base64, но функция общая.
fn happ_pem(kind: &str, body: &str) -> String {
    let mut b = String::new();
    b.push_str(&format!("-----BEGIN {}-----\n", kind));
    let chars: Vec<char> = body.chars().collect();
    for chunk in chars.chunks(64) {
        b.extend(chunk.iter());
        b.push('\n');
    }
    b.push_str(&format!("-----END {}-----", kind));
    b
}

fn parse_priv_pem(p: &str) -> Result<RsaPrivateKey, String> {
    use rsa::pkcs1::DecodeRsaPrivateKey as _;
    if let Ok(k) = RsaPrivateKey::from_pkcs1_pem(p) {
        return Ok(k);
    }
    use rsa::pkcs8::DecodePrivateKey as _;
    if let Ok(k) = RsaPrivateKey::from_pkcs8_pem(p) {
        return Ok(k);
    }
    Err("не удалось разобрать приватный ключ".into())
}

// ---------- загрузка ключей (единожды) ----------

struct HappKeys {
    pkcs1: Vec<RsaPrivateKey>,       // crypt..crypt4, по порядку
    crypt5: HashMap<String, RsaPrivateKey>, // маркер → ключ
    v2: Vec<RsaPrivateKey>,          // crypt3, crypt4, key3
}

fn load_happ_keys() -> Result<&'static HappKeys, String> {
    static KEYS: OnceLock<Result<HappKeys, String>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let f14: serde_json::Value =
            serde_json::from_slice(&embedded_res("happcrypt.json")?).map_err(|e| e.to_string())?;
        let mut pkcs1 = Vec::new();
        if let Some(arr) = f14.get("keys").and_then(|k| k.as_array()) {
            for e in arr {
                let key_b64 = e.get("key").and_then(|k| k.as_str()).unwrap_or_default();
                let name = e.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                let k = parse_priv_pem(&happ_pem("RSA PRIVATE KEY", key_b64))
                    .map_err(|err| format!("happcrypt {}: {}", name, err))?;
                pkcs1.push(k);
            }
        }
        let m5: HashMap<String, String> =
            serde_json::from_slice(&embedded_res("happcrypt5.json")?).map_err(|e| e.to_string())?;
        let mut crypt5 = HashMap::new();
        for (marker, kb64) in &m5 {
            let k = parse_priv_pem(&happ_pem("PRIVATE KEY", kb64))
                .map_err(|e| format!("crypt5 {}: {}", marker, e))?;
            crypt5.insert(marker.clone(), k);
        }
        let mv2: HashMap<String, String> =
            serde_json::from_slice(&embedded_res("v2keys.json")?).map_err(|e| e.to_string())?;
        let mut v2 = Vec::new();
        for name in ["crypt3", "crypt4", "key3"] {
            if let Some(kb64) = mv2.get(name) {
                let k = parse_priv_pem(&happ_pem("PRIVATE KEY", kb64))
                    .map_err(|e| format!("v2 {}: {}", name, e))?;
                v2.push(k);
            }
        }
        Ok(HappKeys { pkcs1, crypt5, v2 })
    })
    .as_ref()
    .map_err(|e| e.clone())
}

// happRSADecryptBest — RSA-расшифровка перебором схем: PKCS1v15, OAEP-SHA1, OAEP-SHA256
fn rsa_decrypt_best(k: &RsaPrivateKey, blob: &[u8]) -> Result<Vec<u8>, String> {
    use rsa::Oaep;
    if let Ok(out) = k.decrypt(rsa::Pkcs1v15Encrypt, blob) {
        return Ok(out);
    }
    if let Ok(out) = k.decrypt(Oaep::new::<sha1::Sha1>(), blob) {
        return Ok(out);
    }
    k.decrypt(Oaep::new::<sha2::Sha256>(), blob)
        .map_err(|e| e.to_string())
}

// ---------- happ://crypt..crypt4 ----------

// happDecryptCrypt1to4 — payload: склейка RSA-блоков, расшифровываем по очереди
fn decrypt_crypt1to4(keys: &HappKeys, ordinal: usize, payload: &str) -> Result<String, String> {
    let Some(key) = keys.pkcs1.get(ordinal) else {
        return Err(format!("нет ключа для crypt{}", ordinal + 1));
    };
    let key_size = key.size();
    let cipher_bytes = happ_b64_decode(payload)?;
    if cipher_bytes.is_empty() || cipher_bytes.len() % key_size != 0 {
        return Err("длина payload не кратна размеру RSA-блока".into());
    }
    let mut out = Vec::new();
    for chunk in cipher_bytes.chunks(key_size) {
        out.extend_from_slice(&rsa_decrypt_best(key, chunk)?);
    }
    // строгий UTF-8: мусор от неверного ключа/паддинга раньше молча уходил
    // дальше как «URL подписки», и ошибка диагностировалась где-то внизу
    String::from_utf8(out).map_err(|_| "расшифрованный payload не является валидным UTF-8".to_string())
}

// ---------- happ://crypt5 ----------

// happCrypt5Body — тело crypt5: [nonce 12][2+8 соль, если salted][длина-сегмента][URL][ключ AEAD]
fn crypt5_body(body: &[u8], key: &RsaPrivateKey, salted: bool) -> Result<String, String> {
    if body.len() < 13 {
        return Err("crypt5 body слишком короткий".into());
    }
    let nonce = &body[..12];
    let mut salt: Option<&[u8]> = None;
    let mut pos = 12;
    if salted {
        if body.len() < 22 {
            return Err("crypt5 salted header слишком короткий".into());
        }
        salt = Some(&body[14..22]);
        pos = 22;
    }
    let start = pos;
    while pos < body.len() && (48..=57).contains(&body[pos]) {
        pos += 1;
    }
    if pos == start {
        return Err("crypt5: нет поля длины сегмента".into());
    }
    let mut seg_len: usize = 0;
    for &c in &body[start..pos] {
        let d = (c - b'0') as usize;
        // Never let a crafted length field overflow or exceed the body.
        if seg_len > (body.len() - d) / 10 {
            return Err("crypt5: слишком большая длина сегмента".into());
        }
        seg_len = seg_len * 10 + d;
    }
    let packed = &body[pos..];
    if packed.is_empty() || seg_len > packed.len() - 1 {
        return Err("crypt5 сегмент обрезан".into());
    }
    let url_b64 = &packed[1..seg_len + 1];
    let enc_b64 = &packed[seg_len + 1..];

    let enc = happ_b64_decode(std::str::from_utf8(enc_b64).map_err(|e| e.to_string())?)?;
    let rsa_plain = rsa_decrypt_best(key, &enc)?;
    // XOR с солью ниже — key_material мутируется; клон исходного значения не нужен
    let mut key_material = happ_b64_decode(std::str::from_utf8(&happ_swap_pairs(&rsa_plain)).map_err(|e| e.to_string())?)?;
    if key_material.len() != 32 {
        return Err(format!("crypt5: длина ключа {} != 32", key_material.len()));
    }
    if let Some(salt) = salt {
        for i in 0..32 {
            key_material[i] ^= salt[i % salt.len()];
        }
    }
    let ct = happ_b64_decode(std::str::from_utf8(url_b64).map_err(|e| e.to_string())?)?;
    // сначала ChaCha20-Poly1305, затем AES-256-GCM — аутентификация
    // исключает ложные срабатывания
    let text = chacha_open(&key_material, nonce, &ct).or_else(|| aes_gcm_open(&key_material, nonce, &ct));
    let Some(text) = text else {
        return Err("crypt5: AEAD-аутентификация не прошла".into());
    };
    let inner = happ_b64_decode(std::str::from_utf8(&happ_swap_pairs(&text)).map_err(|e| e.to_string())?)?;
    String::from_utf8(inner).map_err(|_| "crypt5: расшифрованный payload не является валидным UTF-8".to_string())
}

// happDecryptCrypt5Once — маркер (первые+последние 4 байта после свапа), ключ, тело.
// Пробуем оба режима соли — AEAD-аутентификация исключает ложные срабатывания.
fn decrypt_crypt5_once(keys: &HappKeys, payload: &str) -> Result<String, String> {
    let n = happ_block_swap(payload.as_bytes());
    if n.len() < 8 {
        return Err("crypt5 payload слишком короткий".into());
    }
    let marker = String::from_utf8_lossy(&n[..4]).to_string()
        + &String::from_utf8_lossy(&n[n.len() - 4..]);
    let key = keys
        .crypt5
        .get(&marker)
        .ok_or_else(|| format!("нет ключа для маркера {:?}", marker))?;
    let body = &n[4..n.len() - 4];
    let salted_auto = body.len() > 12 && !(48..=57).contains(&body[12]);
    let mut last_err = String::new();
    for salted in [salted_auto, !salted_auto] {
        match crypt5_body(body, key, salted) {
            Ok(text) => return Ok(text),
            Err(e) => last_err = e,
        }
    }
    if last_err.is_empty() {
        last_err = "crypt5: не расшифровано".into();
    }
    Err(last_err)
}

// happDecryptCrypt5 — полная и укороченная (без 2 последних символов) формы
fn decrypt_crypt5(keys: &HappKeys, payload: &str) -> Result<String, String> {
    let payload = payload.trim();
    let mut candidates = vec![payload];
    // укороченная форма — минус 2 СИМВОЛА, не байта: байтовый срез рвал
    // UTF-8 на мультибайтном хвосте (CJK/эмодзи) и паниковал в потоке команды
    if payload.chars().count() > 10 {
        if let Some((idx, _)) = payload.char_indices().rev().nth(1) {
            candidates.push(&payload[..idx]);
        }
    }
    let mut last_err = String::new();
    for cand in candidates {
        if let Ok(text) = decrypt_crypt5_once(keys, cand) {
            return Ok(text);
        }
        last_err = "crypt5: не расшифровано".into();
    }
    if last_err.is_empty() {
        last_err = "crypt5: не расшифровано".into();
    }
    Err(last_err)
}

// happDecryptLocal — локальная расшифровка happ://crypt../crypt5 ключами hpwnr.
// Сеть не использует. errNotClientLink — это вообще не happ-crypt ссылка.
fn happ_decrypt_local(happ_url: &str) -> Result<String, String> {
    let keys = load_happ_keys()?;
    let path = if happ_url.to_lowercase().starts_with("happ://") {
        &happ_url[7..]
    } else {
        happ_url
    };
    let low = path.to_lowercase();
    // обрезаем по границе символов безопасно: префиксы ASCII
    let cut = |skip: usize| -> Result<String, String> {
        path.get(skip..).map(|s| s.to_string()).ok_or_else(|| "не клиентская ссылка".into())
    };
    if low.starts_with("crypt5/") {
        return decrypt_crypt5(keys, &cut(7)?);
    }
    if low.starts_with("crypt4/") {
        return decrypt_crypt1to4(keys, 3, &cut(7)?);
    }
    if low.starts_with("crypt3/") {
        return decrypt_crypt1to4(keys, 2, &cut(7)?);
    }
    if low.starts_with("crypt2/") {
        return decrypt_crypt1to4(keys, 1, &cut(7)?);
    }
    if low.starts_with("crypt/") {
        return decrypt_crypt1to4(keys, 0, &cut(6)?);
    }
    Err("не клиентская ссылка".into())
}

// ---------- обёртки: happ://add, v2raytun://import ----------

fn query_get(query: &str, key: &str) -> Option<String> {
    // Пара без «=» (или хвостовой «&») — не повод бросить весь поиск:
    // «?foo&url=https://…» раньше возвращал None, и ссылка «не разворачивалась»
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let Some(k) = percent_decode(k) else {
            continue;
        };
        if k == key {
            return percent_decode(v);
        }
    }
    None
}

fn percent_decode(s: &str) -> Option<String> {
    percent_encoding::percent_decode_str(s).decode_utf8().ok().map(|c| c.to_string())
}

// unwrapHappAdd — happ://add/<url> или happ://add/sub?url=… → внутренняя ссылка
fn unwrap_happ_add(link: &str) -> String {
    let low = link.to_lowercase();
    if low.starts_with("happ://add?") {
        let i = link.find('?');
        if let Some(i) = i {
            if let Some(inner) = query_get(&link[i + 1..], "url") {
                if !inner.is_empty() {
                    return inner;
                }
            }
        }
        return link.to_string();
    }
    if !low.starts_with("happ://add/") {
        return link.to_string();
    }
    let rest = &link["happ://add/".len()..];
    if rest.to_lowercase().starts_with("sub?") {
        if let Some(i) = rest.find('?') {
            if let Some(inner) = query_get(&rest[i + 1..], "url") {
                if !inner.is_empty() {
                    return inner;
                }
            }
        }
        return link.to_string();
    }
    let rl = rest.to_lowercase();
    if rl.starts_with("http://") || rl.starts_with("https://") || rl.starts_with("happ://") {
        return rest.to_string();
    }
    link.to_string()
}

// unwrapV2raytunImport — v2raytun://import/<payload> → внутренняя ссылка.
fn unwrap_v2raytun_import(link: &str) -> String {
    if !link.to_lowercase().starts_with("v2raytun://import/") {
        return link.to_string();
    }
    let mut rest = link["v2raytun://import/".len()..].trim().to_string();
    let rl = rest.to_lowercase();
    if rl.starts_with("http://") || rl.starts_with("https://") || rl.starts_with("happ://") {
        return rest;
    }
    // PathUnescape, а не QueryUnescape: «+» в payload — штатный символ base64
    if let Some(cand) = percent_decode(&rest) {
        rest = cand;
    }
    // Telegram вклеивает невидимые символы — вычищаем всё не-base64
    let cand: String = rest
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
        .collect();
    if cand.len() < 8 {
        return link.to_string();
    }
    if let Ok(inner) = vpn_b64(&cand) {
        let inner = inner.trim().to_string();
        let il = inner.to_lowercase();
        if il.starts_with("v2raytun://import/") {
            return unwrap_v2raytun_import(&inner); // вложенная обёртка
        }
        if il.starts_with("http://") || il.starts_with("https://") || il.starts_with("happ://") {
            return inner;
        }
    }
    link.to_string()
}

// ---------- incy://crypt1 ----------

const INCY_FINGERPRINT: &str = "b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c";

// incyDeriveKey — SHA-256("incy"+"deep"+"crypt1"+"v2026.06" + keymatA[1024:1056] + keymatB[2048:2080])
fn incy_derive_key() -> Result<Vec<u8>, String> {
    static KEY: OnceLock<Result<Vec<u8>, String>> = OnceLock::new();
    KEY.get_or_init(|| {
        let a_raw = base64::engine::general_purpose::STANDARD
            .decode(embedded_res("incy_keymat_a.b64")?)
            .map_err(|e| e.to_string())?;
        let b_raw = base64::engine::general_purpose::STANDARD
            .decode(embedded_res("incy_keymat_b.b64")?)
            .map_err(|e| e.to_string())?;
        if a_raw.len() < 1024 + 32 || b_raw.len() < 2048 + 32 {
            return Err("incy: keymat меньше ожидаемого".into());
        }
        let mut seed = b"incydeepcrypt1v2026.06".to_vec();
        seed.extend_from_slice(&a_raw[1024..1056]);
        seed.extend_from_slice(&b_raw[2048..2080]);
        let k = sha2::Sha256::digest(&seed);
        // отпечаток публикуется от КЛЮЧА, а не от seed: fp = sha256(sha256(seed))
        let fp = sha2::Sha256::digest(k);
        let fp_hex: String = fp.iter().map(|b| format!("{:02x}", b)).collect();
        if fp_hex != INCY_FINGERPRINT {
            return Err(format!("incy: отпечаток {} не совпал с {} — keymat не тот", fp_hex, INCY_FINGERPRINT));
        }
        Ok(k.to_vec())
    })
    .as_ref()
    .map_err(|e| e.clone())
    .map(|k| k.clone())
}

// incyDecryptLink — incy://crypt1/<payload> → (url, name)
fn incy_decrypt_link(link: &str) -> Result<(String, String), String> {
    const PREFIX: &str = "incy://crypt1/";
    if !link.to_lowercase().starts_with(PREFIX) {
        return Err("не incy://crypt1 ссылка".into());
    }
    let payload = &link[PREFIX.len()..];
    if payload.is_empty() {
        return Err("incy: пустой payload".into());
    }
    let r = incy_decrypt_payload(payload);
    match r {
        Ok(x) => Ok(x),
        Err(e) => {
            if payload.ends_with('/') {
                // «/» — штатный символ std-base64: срезаем хвостовые «/» только
                // при неудаче (разделители схемы)
                incy_decrypt_payload(payload.trim_end_matches('/'))
            } else {
                Err(e)
            }
        }
    }
}

fn incy_decrypt_payload(payload: &str) -> Result<(String, String), String> {
    let mut s: String = payload
        .chars()
        .filter_map(|r| match r {
            '-' => Some('+'),
            '_' => Some('/'),
            '=' => None,
            _ => Some(r),
        })
        .collect();
    s += &"=".repeat((4 - s.len() % 4) % 4);
    let wire = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| e.to_string())?;
    if wire.len() < 12 + 16 + 1 {
        return Err("incy: payload слишком короткий".into());
    }
    let (iv, ct) = wire.split_at(12);
    let key = incy_derive_key()?;
    let pt = aes_gcm_open(&key, iv, ct)
        .ok_or("incy: AEAD-аутентификация не прошла")?;
    let parsed: serde_json::Value = serde_json::from_slice(&pt).map_err(|_| "incy: внутри не JSON".to_string())?;
    let url = parsed.get("url").and_then(|x| x.as_str()).unwrap_or_default().to_string();
    let name = parsed.get("n").and_then(|x| x.as_str()).unwrap_or_default().to_string();
    if url.is_empty() {
        return Err("incy: нет поля url".into());
    }
    Ok((url, name))
}

// ---------- v2raytun://crypt ----------

fn looks_like_scheme_link(s: &str) -> bool {
    let Some(i) = s.find("://") else {
        return false;
    };
    if i == 0 {
        return false;
    }
    s[..i].chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

// v2raytunDecryptPayload — payload после "v2raytun://crypt/" → scheme://-ссылка.
// Пробуем каждый ключ (crypt3, crypt4, key3): блоки PKCS#1v15, результат —
// только строгая UTF-8 scheme-ссылка.
fn v2raytun_decrypt_payload(keys: &HappKeys, payload: &str) -> Result<String, String> {
    let ct = happ_b64_decode(payload)?;
    if ct.is_empty() {
        return Err("v2raytun: пустой шифртекст".into());
    }
    let mut last_err = "v2raytun: ни один ключ не подошёл".to_string();
    for key in &keys.v2 {
        let ks = key.size();
        if ct.len() % ks != 0 {
            last_err = "v2raytun: длина не кратна размеру блока".into();
            continue;
        }
        let mut out: Vec<u8> = Vec::new();
        let mut ok_all = true;
        for blk in ct.chunks(ks) {
            match key.decrypt(rsa::Pkcs1v15Encrypt, blk) {
                Ok(part) => out.extend_from_slice(&part),
                Err(e) => {
                    ok_all = false;
                    last_err = e.to_string();
                    break;
                }
            }
        }
        if !ok_all {
            continue;
        }
        let text = String::from_utf8_lossy(&out).trim().to_string();
        if looks_like_scheme_link(&text) {
            return Ok(text);
        }
    }
    Err(last_err)
}

// ---------- интеграция в Sentor ----------

const NOT_CLIENT_LINK: &str = "не клиентская ссылка";

// vpnExpandClientLink — один шаг: happ/incy/v2raytun → либо URL, либо готовое тело.
// innerURL непустой → это ссылка для скачивания; body непустой → готовые конфиги.
// is_bare_http_url — одна строка-адрес без переносов: расшифрованный
// payload-URL подписки, а не готовое тело (тела многострочные).
fn is_bare_http_url(s: &str) -> bool {
    let low = s.to_lowercase();
    (low.starts_with("http://") || low.starts_with("https://"))
        && !s.contains('\n')
        && !s.contains('\r')
}

pub fn vpn_expand_client_link(link: &str) -> Result<(String, String, String), String> {
    let low = link.to_lowercase();
    if low.starts_with("happ://add/") || low.starts_with("happ://add?") {
        let inner = unwrap_happ_add(link);
        if inner == link {
            return Err("happ://add без внутренней ссылки".into());
        }
        return Ok((inner, String::new(), String::new()));
    }
    if low.starts_with("v2raytun://import/") {
        let inner = unwrap_v2raytun_import(link);
        if inner == link {
            return Err("v2raytun://import без внутренней ссылки".into());
        }
        return Ok((inner, String::new(), String::new()));
    }
    if low.starts_with("incy://crypt1/") {
        let (u, n) = incy_decrypt_link(link)?;
        return Ok((u, String::new(), n));
    }
    if low.starts_with("happ://crypt") {
        match happ_decrypt_local(link) {
            Ok(text) => {
                // Payload бывает двух видов: готовое тело подписки (пачка
                // ссылок) или «голый» http(s)-адрес подписки (частый случай
                // crypt5). Адрес отдаём в inner_url — вызывающий код
                // (добавление/обновление подписки) сам скачает содержимое:
                // строку-URL парсер подписок не разбирает и вернул бы
                // «пустой или нераспознанный ответ».
                let t = text.trim();
                if is_bare_http_url(t) {
                    return Ok((t.to_string(), String::new(), String::new()));
                }
                return Ok((String::new(), text, String::new()));
            }
            Err(e) => return Err(e),
        }
    }
    if low.starts_with("v2raytun://crypt/") {
        let keys = load_happ_keys()?;
        let text = v2raytun_decrypt_payload(keys, &link["v2raytun://crypt/".len()..])?;
        return Ok((text, String::new(), String::new()));
    }
    if low.starts_with("happ://") || low.starts_with("incy://") || low.starts_with("v2raytun://") {
        // распознанная схема, но неизвестный вариант — не «не клиентская»
        return Err("ссылка не расшифрована: неизвестный вариант схемы".into());
    }
    Err(NOT_CLIENT_LINK.to_string())
}

// vpnResolveLink — рекурсивный разворот (внутренние ссылки тоже клиентские).
// Go-сигнатура: (innerURL, body, name, err), depth > 3 — слишком глубоко.
pub fn vpn_resolve_link(link: &str, depth: i32) -> Result<(String, String, String), String> {
    if depth > 3 {
        return Err("слишком глубокая вложенность ссылок".into());
    }
    let (inner_url, body, name) = vpn_expand_client_link(link.trim())?;
    if !inner_url.is_empty() {
        let low = inner_url.to_lowercase();
        if low.starts_with("happ://") || low.starts_with("incy://") || low.starts_with("v2raytun://") {
            return vpn_resolve_link(&inner_url, depth + 1);
        }
    }
    Ok((inner_url, body, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_variants() {
        assert_eq!(happ_b64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(happ_b64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(happ_b64_decode("aGV-sb8_ ").unwrap().len(), 6); // urlsafe + пробел: 8 символов → 6 байт
    }

    #[test]
    fn swaps() {
        assert_eq!(happ_swap_pairs(&[1, 2, 3, 4, 5]), vec![2, 1, 4, 3, 5]);
        assert_eq!(happ_block_swap(&[1, 2, 3, 4]), vec![3, 4, 1, 2]);
        // инволюция
        let x = happ_block_swap(&happ_block_swap(&[9, 8, 7, 6, 5, 4]));
        assert_eq!(x, vec![9, 8, 7, 6, 5, 4]);
    }

    #[test]
    fn happ_add_unwrap() {
        assert_eq!(unwrap_happ_add("happ://add/https://sub.example/x"), "https://sub.example/x");
        assert_eq!(unwrap_happ_add("happ://add/sub?url=https%3A%2F%2Fy.z"), "https://y.z");
        assert_eq!(unwrap_happ_add("happ://add/happ://crypt5/xyz"), "happ://crypt5/xyz");
        assert_eq!(unwrap_happ_add("happ://add/nothing"), "happ://add/nothing");
    }

    // Регрессия: crypt5-payload с «голым» URL подписки должен попасть
    // в inner_url (скачивание), а не в body («пустой или нераспознанный ответ»).
    #[test]
    fn crypt5_url_payload_goes_to_inner_url() {
        let link = "happ://crypt5/hfqapEAvdlY8Y6bmt7969VRAAUSRkFglo1vwrtfuScqvdhsbPef3LWhmdeLgNrSss6e9Xp7WNJvaRpIudvnI6VYhnVBpR9TrwL/47yjndT425Aw18Nvq2r0tdaw8Gj/IhelUlMwAoCwr9FuxVi6A6DVZMchYtEbJ7yoAqxUqh7tj7o6CYWq0/fDwXztIcBu3BsSta2Y591HS5ktsb0pHKKkq62MoUNZQ7F7lwiUjGOfp5bx1Jb/xN0yGUkROkea4mYGna1Ce+gu9/Tlmnj29vj6zW+sv3mc05jSJZL/8ATNpkFzaau9r6PGOx/xopLdea2yQzuZb/oFwgpKd3wysZnQUrXkyk30s36nZipRwyGem+NwDAPUgJTKdERRX2h+0SzHOdkLRi8yoAkcHOTVFK+4qi6WU0v1ybX8pumDyZT5va8bbOojVXVDMVJ0t+mt+XB5lPX1SpeLZ0NU45p+wSFWu4ZgWJ6kAkBoW3fIr/OT0Xz6nkNsVzWmrxPKj0QTUjFwz13Xsr5svHP3CmVDqaAtyXToOA/xBQKQgdO7wat1vCoM1fURbIzfCgEAa8rnzC/7NyxrCl//N7eAa2yY3OkpoG0SzOpE6dJs+TNnqz+nAVGWuF2cN+7FAJA1n6OJKJBLA5EsgUWQ+JeC2e9b8SYZ/ve798SAkVZ+9gRgqXnsRbVGOJWMihMlAMR+ERcRpJS5GMxQKhxS0PKVvVGQPO6xu+1wJspnFfsYHd7ErEoJzYLLxVlYNxhYNgJKpD+tZGRTp4OWNJgIg9BEnx3diZShkyz1s=thwrxc";
        let (url, body, name) = vpn_resolve_link(link, 0).expect("crypt5 должен расшифроваться");
        assert!(url.starts_with("https://"), "URL должен быть в inner_url: {}", url);
        assert!(body.is_empty(), "body должен быть пуст (иначе URL попадёт в парсер)");
        assert!(name.is_empty());
    }

    #[test]
    fn is_bare_http_url_cases() {
        assert!(is_bare_http_url("https://sub.example/x"));
        assert!(is_bare_http_url("http://x.y "));
        assert!(!is_bare_http_url("vmess://abc"));
        assert!(!is_bare_http_url("https://a\nvmess://b")); // многострочное тело
    }

    #[test]
    fn v2_import_unwrap() {
        let inner = "https://panel.example/sub";
        let payload = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        assert_eq!(unwrap_v2raytun_import(&format!("v2raytun://import/{}", payload)), inner);
        assert_eq!(unwrap_v2raytun_import("v2raytun://import/https://direct.example"), "https://direct.example");
    }

    #[test]
    fn keys_load_and_resolve_chain() {
        // ключи вшитые: PKCS1 (crypt1-4) + crypt5 + v2
        let keys = load_happ_keys().expect("keys must load");
        assert!(keys.pkcs1.len() >= 4, "pkcs1={}", keys.pkcs1.len());
        assert!(!keys.crypt5.is_empty(), "crypt5 keys missing");
        assert!(keys.v2.len() >= 2, "v2 keys={}", keys.v2.len());
        // happ://add → resolve (не крипто-ветка)
        let (u, b, n) = vpn_resolve_link("happ://add/https://x.example/s", 0).unwrap();
        assert_eq!(u, "https://x.example/s");
        assert!(b.is_empty() && n.is_empty());
    }

    #[test]
    fn incy_key_fingerprint() {
        // производный ключ обязан совпасть с опубликованным отпечатком
        assert!(incy_derive_key().is_ok());
        assert_eq!(incy_derive_key().unwrap().len(), 32);
    }
}
