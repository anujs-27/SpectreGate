use bincode::{self, Options};
use rand::RngExt;
use serde::{Deserialize, Serialize};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub timestamp: u64,
    pub port: u16,
    pub padding: Vec<u8>,
}

pub const TARGET_PAYLOAD_SIZE: usize = 64;

fn pad_payload(payload: &Payload) -> Result<Vec<u8>, String> {
    let base_payload = Payload {
        timestamp: payload.timestamp,
        port: payload.port,
        padding: Vec::new(),
    };

    let mut serialized_bytes = bincode::serialize(&base_payload)
        .map_err(|error| format!("Serialization error: {}", error))?;

    if serialized_bytes.len() < TARGET_PAYLOAD_SIZE {
        let padding = TARGET_PAYLOAD_SIZE - serialized_bytes.len();
        let mut random_bytes = vec![0u8; padding];
        rand::rng().fill(&mut random_bytes[..]);
        serialized_bytes.extend_from_slice(&random_bytes);
    }

    Ok(serialized_bytes)
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
    // 12 bytes for nonce + 16 bytes minimum ChaCha20Poly1305 authentication tag
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

    let payload: Payload = bincode::options()
        .allow_trailing_bytes()
        .deserialize(&decrypted_bytes)
        .map_err(|err| format!("Error while deserialisation: {}", err))?;

    Ok(payload)
}
