# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

MoshWin is a native Windows Mosh (Mobile Shell) client written in Rust. It implements the Mosh SSP (State Synchronization Protocol) over encrypted UDP, bootstrapped via SSH, with local echo prediction and a VT terminal emulator — all targeting the Windows console.

## Build & Development Commands

```bash
cargo build                          # Debug build
cargo build --release                # Release build
cargo test                           # Run all 44 unit tests
cargo test <module>::tests::<name>   # Run a single test, e.g. cargo test crypto::tests::encrypt_decrypt_roundtrip
cargo fmt                            # Format code
cargo fmt -- --check                 # Check formatting without modifying
cargo clippy -- -D warnings          # Lint (3 dead-code warnings are intentional for future use)
cargo check                          # Type-check without building
```

Run the client: `cargo run -- [user@]host` (requires a mosh-server on the remote).

## Architecture

### Connection flow

1. **SSH bootstrap** (`ssh.rs`): connects via russh, authenticates (key file → SSH agent → password), runs `mosh-server` on remote, extracts `MOSH_KEY` and UDP port.
2. **Transport** (`transport.rs`): opens a UDP socket and manages bidirectional SSP state synchronization with RTT-based retransmission.
3. **Main event loop** (`main.rs`): polls keyboard input (crossterm), feeds keystrokes through transport, receives remote terminal state, applies prediction overlay, renders to console.

### Module map

| Module | Responsibility |
|---|---|
| `main.rs` | CLI (clap), SSH-or-direct connection routing, async event loop |
| `transport.rs` | SSP protocol engine — state queues, frame numbering, RTT estimation, send/receive scheduling |
| `terminal.rs` | VT terminal emulator — `Framebuffer` (cells, rows, cursor), `vte`-based parser, scroll, color/attribute state |
| `prediction.rs` | Local echo prediction engine — overlays keystrokes onto framebuffer before server confirms, adaptive enable/disable |
| `ssh.rs` | SSH bootstrap — known-hosts verification, multi-method auth, `MOSH_CONNECT` output parsing |
| `network.rs` | UDP framing — packet serialization (timestamp + payload), MTU-based fragmentation and reassembly |
| `crypto.rs` | AES-128-OCB authenticated encryption — nonce encoding, encrypt/decrypt with 16-byte tag |
| `renderer.rs` | Differential Windows console renderer — compares old/new framebuffer, emits minimal crossterm commands |
| `userstream.rs` | User input state — keystroke queue, resize events, diff/apply/subtract for SSP synchronization |

### Key dependency flow

`main` → `ssh` (bootstrap) → `transport` (session) → `crypto` + `network` + `terminal` + `userstream`

`prediction` reads/writes `terminal::Framebuffer`. `renderer` reads `Framebuffer` to diff and draw.

### Protocol details

- **Wire format:** AES-128-OCB encrypted UDP, 8-byte nonce + 16-byte OCB tag (24 bytes overhead)
- **Serialization:** Protobuf via `prost` with inline message definitions (no `.proto` files / no protoc needed)
- **Fragmentation:** MTU 1280 bytes; large states split into numbered fragments and reassembled
- **Compression:** Optional zlib (flate2) for state diffs
- **Mosh protocol version:** 2 (upstream compatible)

### Timing constants (in transport.rs)

- Send interval: 20–250ms (adaptive based on RTT)
- ACK interval: 3000ms, ACK delay: 100ms
- RTT bounds: 50–1000ms

### Platform

Windows-only: uses `windows-sys` for Console/UI APIs, `crossterm` for terminal I/O. The command key is Ctrl-^ (0x1E).
