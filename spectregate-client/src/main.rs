use clap::Parser;
use spectregate_core::{Payload, encrypt_payload};
use std::{net::IpAddr, path::Path};
use tokio;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short, long)]
    server: IpAddr,
    #[arg(short, long)]
    port: u16, // Daemon UDP port
    #[arg(short, long)]
    open_port: u16,
    #[arg(short, long)]
    key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let key_path = Path::new(&args.key);

    let os_time = chrono::Utc::now().timestamp() as u64;

    let file_buffer = match std::fs::read(&key_path) {
        Ok(buffer) => buffer,
        Err(e) => {
            eprintln!("Failed to read key file: {}", e);
            return Ok(());
        }
    };

    if file_buffer.len() != 32 {
        eprintln!("Key file must be 32 bytes long.");
        return Ok(());
    }

    let key_bytes: [u8; 32] = file_buffer
        .try_into()
        .map_err(|_| "Failed to convert key to 32-byte array!!")?;

    let mut payload: Payload = Payload {
        timestamp: os_time,
        port: args.open_port,
        padding: Vec::new(),
    };

    let encr_payload = encrypt_payload(&mut payload, &key_bytes)
        .map_err(|err| format!("Encryption error {err}"))?;

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket
        .send_to(&encr_payload, (args.server, args.port))
        .await?;

    Ok(())
}
