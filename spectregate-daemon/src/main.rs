use std::{
    collections::HashSet,
    error::Error,
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
};

use futures::StreamExt;

use clap::Parser;
use etherparse;
use pcap::{self, PacketCodec};
use spectregate_core::decrypt_payload;
use tokio::{self, process::Command};

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

pub struct SimpleCodec;

impl PacketCodec for SimpleCodec {
    type Item = Vec<u8>;

    fn decode(&mut self, packet: pcap::Packet<'_>) -> Self::Item {
        packet.data.to_vec()
    }
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

    let mut packet_stream = cap.stream(SimpleCodec)?;

    let cache = NonceCache {
        seen_nonces: Arc::new(Mutex::new(HashSet::new())),
    };

    while let Some(packet_result) = packet_stream.next().await {
        match packet_result {
            Ok(raw_packet_bytes) => {
                match etherparse::SlicedPacket::from_ethernet(&raw_packet_bytes) {
                    Ok(packet) => {
                        let src_ip = match packet.net {
                            Some(etherparse::InternetSlice::Ipv4(ipv4_header)) => {
                                IpAddr::V4(ipv4_header.header().source_addr())
                            }
                            _ => {
                                continue;
                            }
                        };

                        if let Some(etherparse::TransportSlice::Udp(udp_slice)) = packet.transport {
                            let payload_slice = udp_slice.payload();
                            if payload_slice.len() < 84 {
                                continue;
                            }

                            if let Err(e) =
                                validate_and_trigger(payload_slice, src_ip, &key_bytes, &cache)
                                    .await
                            {
                                eprintln!("Discarded invalid knock sequence: {}", e);
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
            Err(e) => eprintln!("Error capturing packet: {}", e),
        }
    }

    Ok(())
}

async fn validate_and_trigger(
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

    trigger_firewall_gate(src_ip, decrypted_payload.port).await?;

    Ok(())
}

async fn trigger_firewall_gate(client_ip: IpAddr, target_port: u16) -> Result<(), Box<dyn Error>> {
    let element_binding = format!("{{ {} . {} timeout 10s }}", client_ip, target_port);

    let status = Command::new("nft")
        .args([
            "add",
            "element",
            "inet",
            "filter",
            "approved_knocks",
            &element_binding,
        ])
        .status()
        .await?;

    if status.success() {
        println!(
            "Gate opened successfully. Target port {} is available for 10 seconds.",
            target_port
        );
    } else {
        eprintln!("Firewall Error: nftables rejected the element insertion.");
    }

    Ok(())
}
