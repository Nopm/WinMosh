# MoshWin

A native Windows [Mosh](https://mosh.org) (Mobile Shell) client written in Rust.

MoshWin implements the Mosh State Synchronization Protocol (SSP) over encrypted UDP, bootstrapped via SSH, with local echo prediction and a VT terminal emulator — all targeting the Windows console. It is protocol-compatible with upstream `mosh-server` (version 2).

## Features

- SSH bootstrap with key file, SSH agent, and password authentication
- AES-128-OCB authenticated encryption (upstream-compatible wire format)
- Predictive local echo (always, adaptive, or never)
- Differential terminal rendering for minimal flicker
- Single static binary, no DLLs or runtime dependencies

## Installation

Download `mosh-client.exe` from Releases, or build from source:

```
cargo build --release
```

The binary is at `target\release\mosh-client.exe`.

## Usage

```
mosh-client [OPTIONS] [user@]host
```

Requires a `mosh-server` running (or installable) on the remote host.

### Options

| Flag | Description |
|---|---|
| `-p`, `--ssh-port <PORT>` | SSH port (default: 22) |
| `-i`, `--identity <FILE>` | SSH private key file |
| `--password <PASS>` | SSH password (prefer key-based auth) |
| `--server <PATH>` | Path to mosh-server on remote (default: `mosh-server`) |
| `--predict <MODE>` | Prediction mode: `always`, `adaptive`, `never` (default: `adaptive`) |
| `--direct <IP:PORT>` | Skip SSH, connect directly (requires `MOSH_KEY` env var) |
| `-v`, `--verbose` | Enable debug logging |

### In-session commands

Press `Ctrl-^` (the command key), then:

| Key | Action |
|---|---|
| `.` | Quit |
| `Ctrl-Z` | Suspend (not supported on Windows) |
| `^` | Send literal `Ctrl-^` |

## Requirements

- Windows 10 or later
- A remote host running `mosh-server` (typically installed via `mosh` package on Linux/macOS)

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
