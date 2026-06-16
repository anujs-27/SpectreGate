use bincode;
use rand::RngExt;
use serde::{Deserialize, Serialize};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, ChaChaPoly1305, Key, Nonce,
};

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub timestamp: u64,
    pub port: u16,
    pub padding: Vec<u8>,
}

pub const TARGET_PAYLOAD_SIZE: usize = 64;

fn pad_payload(payload: &mut Payload) -> Result<Vec<u8>, String> {
    payload.padding = Vec::new();
    let current_size = bincode::serialized_size(&payload)
        .map_err(|e| format!("Size calculation failed: {}", e))? as usize;

    if current_size < TARGET_PAYLOAD_SIZE {
        let header_overhead = 8;
        if TARGET_PAYLOAD_SIZE > (current_size + header_overhead) {
            let padding_needed = TARGET_PAYLOAD_SIZE - current_size - header_overhead;
            let mut random_bytes = vec![0u8; padding_needed];
            rand::rng().fill(&mut random_bytes[..]);
            payload.padding = random_bytes;
        }
    }
    bincode::serialize(&payload).map_err(|e| format!("Serialization failed: {}", e))
}

pub fn encrypt_payload(payload: &mut Payload, key_bytes: &[u8; 32]) -> Result<Vec<u8>, String> {
    let padded_payload = pad_payload(payload)?;

    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill(&mut nonce_bytes); //Make NONCE bytes
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key_bytes.into());

    let ciphertext = cipher
        .encrypt(nonce, padded_payload.as_slice())
        .map_err(|err| format!("Encryption failure: {:?}", err))?;

    let mut final_packet = nonce_bytes.to_vec();
    final_packet.extend(ciphertext);

    Ok(final_packet)
}

pub fn decrypt_payload(packet_bytes: &[u8], key_bytes: &[u8; 32]) -> Result<Payload, String> {
    if packet_bytes.len() < 28 {
        return Err(String::from(
            "Packet length falls short of minimum cryptographic criteria",
        ));
    }

    let (nonce_slice, ciphertext_slice) = packet_bytes.split_at(12);

    let nonce = Nonce::from_slice(nonce_slice);
    let cipher = ChaCha20Poly1305::new(key_bytes.into());

    let decrypted_bytes = cipher
        .decrypt(nonce, ciphertext_slice)
        .map_err(|err| format!("Cryptographic validation failed: {:?}", err))?;

    let payload: Payload = bincode::deserialize(&decrypted_bytes)
        .map_err(|err| format!("Payload deserialization failure: {:?}", err))?;

    Ok(payload)
}
