// Порт Go obfs.go: RTP-обфускация соединения (chacha20poly1305).
// МОДУЛЬ ПОКА НЕ ПОДКЛЮЧЁН: точка интеграции — session.rs::wrap_dtls
// (TODO(DTLS)); включится вместе с DTLS-адаптером. Код корректен
// (roundtrip покрыт тестами), поэтому не удаляем, а глушим dead_code.
#![allow(dead_code)]
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

// Go: wrapKeyLen (wrap.go) = 32
pub const WRAP_KEY_LEN: usize = 32;

// Go: chacha20poly1305.Overhead — 16 байт тега Poly1305
const CHACHA20POLY1305_OVERHEAD: usize = 16;

// Кэш AEAD по ключу (Go: aeadCache sync.Map) — не пересоздаём шифр на каждый пакет.
static AEAD_CACHE: OnceLock<Mutex<HashMap<Vec<u8>, ChaCha20Poly1305>>> = OnceLock::new();

// with_aead — берёт (или создаёт и кэширует) шифр под ключ и передаёт его в f.
// В Go getAEAD возвращает cipher.AEAD; здесь отдаём по ссылке, чтобы не клонировать.
fn with_aead<T>(key: &[u8], f: impl FnOnce(&ChaCha20Poly1305) -> Result<T, String>) -> Result<T, String> {
    if key.len() != WRAP_KEY_LEN {
        return Err(format!("obfs: key must be {} bytes", WRAP_KEY_LEN));
    }
    let cache = AEAD_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if !cache.contains_key(key) {
        let aead = ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("{}", e))?;
        cache.insert(key.to_vec(), aead);
    }
    let aead = cache.get(key).expect("aead just inserted");
    f(aead)
}

// ObfsConfig — параметры обфускации (Go ObfsConfig).
#[derive(Debug, Clone)]
pub struct ObfsConfig {
    pub ssrc: u32,
    pub payload_type: u8,
    pub padding_max: usize,
}

// random_bytes — getrandom с фоллбеком от времени: ошибки ГСЧ раньше
// проглатывались (`let _ =`), и ssrc мог стать 0/повторным у двух сессий.
// Фоллбек не криптостойкий, но для обфускации RTP этого достаточно.
fn random_bytes(buf: &mut [u8]) {
    if getrandom::fill(buf).is_ok() {
        return;
    }
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut seed = t ^ (buf.as_ptr() as u64);
    for b in buf.iter_mut() {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (seed >> 33) as u8;
    }
}

// new_obfs_config создаёт конфиг по режиму (audio/video).
// Go: func NewObfsConfig(mode string) *ObfsConfig
pub fn new_obfs_config(mode: &str) -> ObfsConfig {
    let mut buf = [0u8; 4];
    random_bytes(&mut buf);

    let (pt, pad): (u8, usize) = if mode == "video" {
        (96, 60)
    } else {
        (111, 24)
    };

    ObfsConfig {
        ssrc: u32::from_be_bytes(buf),
        payload_type: pt,
        padding_max: pad,
    }
}

// ObfsState — состояние обфускации (Go ObfsState): начальные seq/ts и счётчик
// пакетов. В Go счётчик защищён мьютексом; в Rust он атомарный, состояние
// можно держать за &ObfsState (Send+Sync) и шарить между потоками.
#[derive(Debug)]
pub struct ObfsState {
    init_seq: u16,
    init_ts: u32,
    count: AtomicU64,
}

impl ObfsState {
    // new_obfs_state инициализирует случайные стартовые seq/ts.
    // Go: func NewObfsState() *ObfsState
    pub fn new() -> Self {
        let mut buf = [0u8; 6];
        random_bytes(&mut buf);
        ObfsState {
            init_seq: u16::from_be_bytes([buf[0], buf[1]]),
            init_ts: u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]),
            count: AtomicU64::new(0),
        }
    }
}

impl Default for ObfsState {
    fn default() -> Self {
        Self::new()
    }
}

fn obfs_build_nonce(ssrc: u32, seq: u16, ts: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&ssrc.to_be_bytes());
    n[4..6].copy_from_slice(&seq.to_be_bytes());
    // n[6..8] остаются нулями — так же, как в Go (PutUint16(n[4:6], seq), ts в n[8:12])
    n[8..12].copy_from_slice(&ts.to_be_bytes());
    n
}

// obfs_wrap_packet упаковывает payload в RTP-пакет с обфускацией.
// Go: func obfsWrapPacket(key, payload []byte, cfg *ObfsConfig, state *ObfsState) ([]byte, error)
pub fn obfs_wrap_packet(
    key: &[u8],
    payload: &[u8],
    cfg: &ObfsConfig,
    state: &ObfsState,
) -> Result<Vec<u8>, String> {
    if key.len() != WRAP_KEY_LEN {
        return Err(format!(
            "obfs: key must be {} bytes (got {})",
            WRAP_KEY_LEN,
            key.len()
        ));
    }
    if payload.is_empty() {
        return Err("obfs: empty payload".to_string());
    }

    // Go: state.mu.Lock(); c := state.count; state.count++; state.mu.Unlock()
    let c = state.count.fetch_add(1, Ordering::SeqCst);

    let seq = state.init_seq.wrapping_add(c as u16);
    let ts = state
        .init_ts
        .wrapping_add((c as u32).wrapping_mul(960))
        .wrapping_add((c >> 16) as u32);

    let nonce = obfs_build_nonce(cfg.ssrc, seq, ts);

    let mut pad_rand: usize = 0;
    if cfg.padding_max > 0 {
        let mut rnd_buf = [0u8; 1];
        random_bytes(&mut rnd_buf);
        pad_rand = (rnd_buf[0] as usize) % cfg.padding_max;
    }
    let pad_total = pad_rand + 1;

    let out_len = 12 + payload.len() + CHACHA20POLY1305_OVERHEAD + pad_total;
    let mut out = vec![0u8; out_len];

    out[0] = 0x80 | 0x20;
    out[1] = cfg.payload_type & 0x7F;
    out[2..4].copy_from_slice(&seq.to_be_bytes());
    out[4..8].copy_from_slice(&ts.to_be_bytes());
    out[8..12].copy_from_slice(&cfg.ssrc.to_be_bytes());

    with_aead(key, |aead| {
        // Go: sealed := aead.Seal(out[12:12], nonce, payload, out[:12]) —
        // шифруем payload с AAD = RTP-заголовок (первые 12 байт);
        // encrypt возвращает ciphertext||tag, кладём после заголовка.
        let sealed = aead
            .encrypt(
                aead::Nonce::<ChaCha20Poly1305>::from_slice(&nonce),
                Payload {
                    msg: payload,
                    aad: &out[..12],
                },
            )
            .map_err(|_| "obfs: cipher seal failed".to_string())?;
        out[12..12 + sealed.len()].copy_from_slice(&sealed);

        let pad_start = 12 + sealed.len();
        if pad_rand > 0 {
            random_bytes(&mut out[pad_start..pad_start + pad_rand]);
        }

        out[out_len - 1] = pad_total as u8;
        Ok(())
    })?;

    Ok(out)
}

// obfs_unwrap_packet распаковывает обфусцированный RTP-пакет в dst,
// возвращает длину открытого payload.
// Go: func obfsUnwrapPacket(key, wire, dst []byte) (int, error)
pub fn obfs_unwrap_packet(key: &[u8], wire: &[u8], dst: &mut [u8]) -> Result<usize, String> {
    if key.len() != WRAP_KEY_LEN {
        return Err(format!(
            "obfs: key must be {} bytes (got {})",
            WRAP_KEY_LEN,
            key.len()
        ));
    }
    if wire.len() < 13 {
        return Err("obfs: packet too short".to_string());
    }

    if (wire[0] >> 6) != 2 {
        return Err("obfs: not RTP v2".to_string());
    }

    let seq = u16::from_be_bytes([wire[2], wire[3]]);
    let ts = u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]);
    let ssrc = u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]);

    let mut payload_end = wire.len();
    if wire[0] & 0x20 != 0 {
        let pad_len = wire[wire.len() - 1] as usize;
        if pad_len == 0 || pad_len > payload_end - 12 {
            return Err(format!("obfs: invalid padding length {}", pad_len));
        }
        payload_end -= pad_len;
    }

    let ciphertext_len = payload_end - 12;
    if ciphertext_len <= CHACHA20POLY1305_OVERHEAD {
        return Err("obfs: no payload after stripping header/padding".to_string());
    }
    if ciphertext_len - CHACHA20POLY1305_OVERHEAD > dst.len() {
        return Err("obfs: dst buffer too small".to_string());
    }

    let nonce = obfs_build_nonce(ssrc, seq, ts);

    with_aead(key, |aead| {
        // Go: plain, err := aead.Open(dst[:0], nonce, wire[12:payloadEnd], wire[:12])
        // Ошибка Open в Go: "chacha20poly1305: message authentication failed".
        let plain = aead
            .decrypt(
                aead::Nonce::<ChaCha20Poly1305>::from_slice(&nonce),
                Payload {
                    msg: &wire[12..payload_end],
                    aad: &wire[..12],
                },
            )
            .map_err(|_| "obfs: auth: chacha20poly1305: message authentication failed".to_string())?;
        let n = plain.len();
        dst[..n].copy_from_slice(&plain);
        Ok(n)
    })
}

// obfs_is_rtp_packet — похоже ли на обфусцированный RTP-пакет.
// Go: func obfsIsRTPPacket(wire []byte) bool
pub fn obfs_is_rtp_packet(wire: &[u8]) -> bool {
    if wire.len() < 13 {
        return false;
    }

    if (wire[0] >> 6) != 2 {
        return false;
    }

    let pt = wire[1] & 0x7F;
    pt == 111 || pt == 96
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let key = [7u8; WRAP_KEY_LEN];
        let cfg = new_obfs_config("audio");
        let state = ObfsState::new();
        let payload = b"hello wdtt";

        let wire = obfs_wrap_packet(&key, payload, &cfg, &state).expect("wrap");
        assert!(obfs_is_rtp_packet(&wire));
        assert_eq!(wire[0], 0x80 | 0x20);
        assert_eq!(wire[1] & 0x7F, 111);
        // pad_total случайный — проверяем только минимальный размер
        assert!(wire.len() >= 12 + payload.len() + 16 + 1);

        let mut dst = [0u8; 64];
        let n = obfs_unwrap_packet(&key, &wire, &mut dst).expect("unwrap");
        assert_eq!(&dst[..n], payload);
    }

    #[test]
    fn video_mode_uses_pt96_and_larger_padding() {
        let cfg = new_obfs_config("video");
        assert_eq!(cfg.payload_type, 96);
        assert_eq!(cfg.padding_max, 60);
        let cfg = new_obfs_config("audio");
        assert_eq!(cfg.payload_type, 111);
        assert_eq!(cfg.padding_max, 24);
    }

    #[test]
    fn key_length_is_enforced() {
        let err = obfs_wrap_packet(&[0u8; 31], b"x", &new_obfs_config("audio"), &ObfsState::new())
            .unwrap_err();
        assert_eq!(
            err,
            format!("obfs: key must be {} bytes (got 31)", WRAP_KEY_LEN)
        );

        let mut dst = [0u8; 64];
        let err = obfs_unwrap_packet(&[0u8; 16], &[0u8; 40], &mut dst).unwrap_err();
        assert_eq!(
            err,
            format!("obfs: key must be {} bytes (got 16)", WRAP_KEY_LEN)
        );
    }

    #[test]
    fn empty_payload_and_short_packet() {
        let key = [1u8; WRAP_KEY_LEN];
        let err = obfs_wrap_packet(&key, b"", &new_obfs_config("audio"), &ObfsState::new()).unwrap_err();
        assert_eq!(err, "obfs: empty payload");

        let mut dst = [0u8; 64];
        assert_eq!(obfs_unwrap_packet(&key, &[0u8; 12], &mut dst).unwrap_err(), "obfs: packet too short");
        assert_eq!(obfs_unwrap_packet(&key, &[0u8; 40], &mut dst).unwrap_err(), "obfs: not RTP v2");
    }

    #[test]
    fn dst_too_small() {
        let key = [1u8; WRAP_KEY_LEN];
        let cfg = new_obfs_config("audio");
        let wire = obfs_wrap_packet(&key, b"long payload here", &cfg, &ObfsState::new()).expect("wrap");
        let mut dst = [0u8; 2];
        assert_eq!(
            obfs_unwrap_packet(&key, &wire, &mut dst).unwrap_err(),
            "obfs: dst buffer too small"
        );
    }
}
