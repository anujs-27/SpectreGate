# SpectreGate

SpectreGate is a Rust-based tool that hides sensitive services behind a lightweight authentication layer.

Instead of exposing ports such as SSH or web administration interfaces to the internet, SpectreGate keeps them blocked by default. A client must first send an encrypted authorization packet before access is temporarily allowed.

## How It Works

1. SpectreGate runs in the background without opening any network sockets.
2. It uses `libpcap` and a BPF filter to watch for specially crafted UDP packets.
3. When an authorization packet is received, the daemon:

   * Decrypts and verifies the payload using ChaCha20-Poly1305.
   * Checks the timestamp to ensure the packet is recent.
   * Verifies that the nonce has not been used before.
4. If validation succeeds, SpectreGate creates a temporary `nftables` rule allowing the client's IP address to access the protected service.
5. The client connects normally (for example, via SSH).
6. After a short timeout, the temporary firewall rule is removed. Existing established connections remain active through Linux connection tracking.

## Features

* No listening sockets
* Packet inspection using `libpcap` and BPF
* ChaCha20-Poly1305 authenticated encryption
* Replay attack protection using timestamps and nonces
* Dynamic firewall management with `nftables`
* Temporary per-client access rules

## Requirements

### Rust

* Stable Rust toolchain
* Cargo
* rustc

### System Dependencies

* `libpcap` development headers

### Linux Capabilities

SpectreGate requires:

* `CAP_NET_RAW`
* `CAP_NET_ADMIN`

or root privileges.

## Status

SpectreGate is currently under development and APIs, configuration formats, and internal behavior may change between releases.
