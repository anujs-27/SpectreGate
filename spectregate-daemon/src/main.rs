use std::{
    collections::HashSet,
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
};

use clap::Parser;
use pcap;
use spectregate_core::decrypt_payload;
use tokio;

#[derive(Parser, Debug)]
#[command(version, about = "Daemon service for spectregate.")]
struct Args {
    #[arg(long, short)]
    interface: String,

    #[arg(long, short)]
    port: u16,

    #[arg(long, short)]
    key: String,
}

struct NonceCache {
    seen_nonces: Arc<Mutex<HashSet<[u8; 12]>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Args = Args::parse();
    let key_path = Path::new(&args.key);

    println!(
        "Initialising spectregate daemon for interface {}",
        &args.interface
    );

    let file_buffer = std::fs::read(&key_path)
        .map_err(|e| format!("Critical Error: Failed to open key file: {}", e))?;

    if file_buffer.len() != 32 {
        return Err("Invalid key file, size of key file should be 32!!".into());
    }

    let key_bytes: [u8; 32] = file_buffer
        .try_into()
        .map_err(|_| "Couldn't convert key to array!!")?;

    let mut cap = pcap::Capture::from_device(args.interface.as_str())?
        .promisc(false)
        .immediate_mode(true)
        .open()?
        .setnonblock()?;

    let filter_string = format!("udp and dst port {}", args.port);
    cap.filter(&filter_string, true)?;

    println!(
        "Stealth sniffer actively running. Filtering for: '{}'",
        filter_string
    );

    Ok(())
}

fn validate_and_trigger(
    raw_payload: &[u8],
    src_ip: IpAddr,
    key: &[u8; 32],
    cache: &NonceCache,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&raw_payload[..12]);

    {
        let mut guard = cache
            .seen_nonces
            .lock()
            .map_err(|_| "Mutex lock poisoned")?;
        if !guard.insert(nonce) {
            return Err("Replay attack caught: Nonce token reuse detected!".into());
        }
    }

    let decrypted_payload = decrypt_payload(raw_payload, key)
        .map_err(|e| format!("Cryptographic processing failed: {}", e))?;

    let server_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    let delta = (server_now - decrypted_payload.timestamp as i64).abs();

    if delta > 15 {
        return Err(format!(
            "Replay guard rejection: Packet expired by {} seconds",
            delta
        )
        .into());
    }

    //TODO: trigger firewall

    Ok(())
}

//TODO: trigger_firewall_gate function
