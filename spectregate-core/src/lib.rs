use bincode;
use rand::{self, RngExt};
use serde::{Deserialize, Serialize};

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
            rand::rng().fill(&mut random_bytes);
            payload.padding = random_bytes;
        }
    }
    bincode::serialize(&payload).map_err(|e| format!("Serialization failed: {}", e))
}
