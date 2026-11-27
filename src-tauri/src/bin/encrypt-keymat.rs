//! Инструмент сборки: шифрует ключевые материалы happcrypt
//! (assets/happcrypt/*.json, *.b64) в *.enc для вшивания в exe.
//!
//! Запуск из src-tauri:  cargo run --bin encrypt-keymat
//! После любого изменения исходных ключей запускать заново, иначе exe
//! останется собран со старыми .enc (компилятор этого не отследит).

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

const FILES: [&str; 5] = [
    "happcrypt.json",
    "happcrypt5.json",
    "v2keys.json",
    "incy_keymat_a.b64",
    "incy_keymat_b.b64",
];

// Должны в точности совпадать с KM_PARTS/KM_MASKS в src/happcrypt.rs.
const KM_PARTS: [u64; 4] =
    [0x6d8e0516500f9685, 0x7441d06a8de96c40, 0x216643511a0632b8, 0xaf8edd92ab851c54];
const KM_MASKS: [u64; 4] =
    [0x0eb1eb35f2e70375, 0x3766ad8bc0d91087, 0xbe56d6f9c96b522f, 0x852a52782517708b];

fn keymat_aes_key() -> [u8; 32] {
    let mut preimage = [0u8; 32];
    for i in 0..4 {
        preimage[i * 8..i * 8 + 8].copy_from_slice(&(KM_PARTS[i] ^ KM_MASKS[i]).to_le_bytes());
    }
    Sha256::digest(preimage).into()
}

fn main() {
    let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/happcrypt"));
    let key = keymat_aes_key();
    let cipher = Aes256Gcm::new_from_slice(&key).expect("ключ AES");
    for name in FILES {
        let src = dir.join(name);
        let plain = fs::read(&src).unwrap_or_else(|e| panic!("не читается {}: {e}", src.display()));

        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).expect("nonce из ОС");
        let ct = cipher
            .encrypt(
                GenericArray::from_slice(&nonce),
                Payload { msg: &plain, aad: name.as_bytes() },
            )
            .expect("шифрование");

        let mut blob = Vec::with_capacity(4 + 12 + ct.len());
        blob.extend_from_slice(b"SKM1");
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);

        // контрольный круг: расшифровка обязана вернуть исходник
        let back = cipher
            .decrypt(
                GenericArray::from_slice(&blob[4..16]),
                Payload { msg: &blob[16..], aad: name.as_bytes() },
            )
            .expect("контрольная расшифровка");
        assert_eq!(back, plain, "roundtrip {name} не сошёлся");

        let dst = dir.join(format!("{name}.enc"));
        fs::write(&dst, &blob).unwrap_or_else(|e| panic!("не пишется {}: {e}", dst.display()));
        println!("{name}: {} -> {} байт, roundtrip OK", plain.len(), blob.len());
    }
    println!("Готово: *.enc обновлены. Пересобери релиз, чтобы они попали в exe.");
}
