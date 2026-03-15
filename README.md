# Proton Drive Client for Linux Mint

A native GUI desktop application and CLI for Linux Mint that provides seamless two-way synchronization with [Proton Drive](https://proton.me/drive). Built with Rust.

> **Status:** Concept / Planning — not yet functional. Contributions and feedback welcome.

---

## Overview

Proton Drive is an end-to-end encrypted cloud storage service. While Proton offers official clients for Windows, macOS, iOS, and Android, Linux users are currently left without a native desktop client. This project aims to fill that gap by providing a polished, first-class Proton Drive experience on Linux Mint.

---

## Architecture

The system is composed of three binaries that communicate over a **Unix socket**:

```
┌───────────────┐     ┌───────────────┐
│  GUI Desktop  │     │   CLI client  │
│     App       │     │ proton-drive  │
└───────┬───────┘     └───────┬───────┘
        │   Unix socket IPC   │
        └──────────┬──────────┘
                   │
         ┌─────────▼─────────┐
         │   protond (daemon) │  ← single source of truth
         │                   │
         │  ┌─────────────┐  │
         │  │  Auth       │  │  OAuth → browser → token
         │  ├─────────────┤  │
         │  │  Remote FS  │  │  Proton Drive API
         │  ├─────────────┤  │
         │  │  Local FS   │  │  inotify / walkdir
         │  ├─────────────┤  │
         │  │  Diff Engine│  │  Delta computation
         │  ├─────────────┤  │
         │  │  Sync Queue │  │  Prioritized job queue
         │  ├─────────────┤  │
         │  │  Transfer   │  │  Rate limiting + scheduling
         │  │  Manager    │  │
         │  └─────────────┘  │
         └───────────────────┘
```

### Components

#### `protond` — Sync Daemon

The core background service. All business logic lives here. Starts on login via systemd user unit.

**Sync pipeline (in order):**

| Step | Description |
|------|-------------|
| 1. **Authenticate** | OAuth flow — opens system browser to `proton.me`, captures redirect token. Stores session token in system keyring via `libsecret`. |
| 2. **Connect** | Establishes an authenticated session with the Proton Drive API. Refreshes tokens automatically. |
| 3. **Enumerate remote** | Walks the remote drive tree via Proton API, decrypts file metadata (names, sizes, modified times) using the user's private key. |
| 4. **Enumerate local** | Walks the configured local sync folder. Reads file metadata and computes hashes for changed files. |
| 5. **Diff** | Compares remote and local snapshots against the last-known sync state stored in a local SQLite database. Classifies each file as: `unchanged`, `local_new`, `remote_new`, `local_modified`, `remote_modified`, `conflict`. |
| 6. **Conflict resolution** | Files classified as `conflict` are paused. The user is notified via the GUI/CLI to resolve each conflict manually before sync resumes. |
| 7. **Build queue** | Creates a prioritized job queue (small files first, then large). Jobs are persisted to SQLite so they survive restarts. |
| 8. **Transfer** | Executes upload/download jobs with configurable rate limiting (separate upload/download caps in KB/s or MB/s) and optional time-window scheduling (e.g., sync only between 22:00–06:00). |

#### `proton-drive` — CLI Client

Thin client that sends commands to the daemon over the Unix socket and prints responses. Useful for scripting and headless servers.

```bash
proton-drive auth login          # trigger OAuth flow
proton-drive status              # show sync status
proton-drive sync                # force an immediate sync cycle
proton-drive conflicts list      # list unresolved conflicts
proton-drive conflicts resolve <id> --keep [local|remote]
proton-drive config set upload-limit 500   # KB/s
proton-drive config set sync-window 22:00-06:00
```

#### GUI Desktop App

A system-tray-first application that connects to the daemon socket. Provides:
- Tray icon with sync status indicator
- Conflict resolution dialogs
- Settings panel (bandwidth limits, sync schedule, folder selection)
- Live sync activity feed

### IPC Protocol

CLI and GUI communicate with the daemon via a **Unix domain socket** at `$XDG_RUNTIME_DIR/protond.sock`. Messages are length-prefixed JSON frames. The protocol is internal and versioned.

### Storage Layout

```
~/.config/proton-drive/
    config.toml          # user preferences (sync folder, bandwidth, schedule)

~/.local/share/proton-drive/
    state.db             # SQLite: file snapshots, sync queue, conflict log

$XDG_RUNTIME_DIR/
    protond.sock         # Unix socket (runtime only)
    protond.pid          # PID file
```

Credentials (OAuth tokens) are stored exclusively in the **system keyring** (`libsecret` / GNOME Keyring / KWallet) and never written to disk in plaintext.

---

## Planned Features

- **Two-way sync** — Automatic bidirectional sync between a local folder and Proton Drive
- **End-to-end encryption** — Full support for Proton's E2EE protocol
- **Conflict resolution** — User-driven resolution with manual accept/reject per file
- **Bandwidth management** — Per-direction rate caps and time-window scheduling
- **System tray integration** — Background operation with live status
- **Selective sync** — Choose which remote folders to mirror locally
- **Resumable transfers** — Interrupted uploads/downloads resume from where they left off

---

## Requirements

- Linux Mint 21+ (Ubuntu 22.04 base or later)
- A Proton account (Free or paid)
- GNOME Keyring or compatible `libsecret` provider

---

## Installation

> Installation instructions will be added once the first release is available.

---

## Building from Source

### Prerequisites

- [Rust](https://rustup.rs/) 1.75 or later
- `libsecret` development headers: `sudo apt install libsecret-1-dev`

```bash
# Clone the repository
git clone https://github.com/your-username/proton-drive-client.git
cd proton-drive-client

# Build all binaries
cargo build --release

# Binaries will be at:
#   ./target/release/protond
#   ./target/release/proton-drive
#   ./target/release/proton-drive-app
```

---

## Roadmap

- [ ] OAuth authentication with Proton (browser flow + libsecret storage)
- [ ] Proton Drive API client (auth, file listing, upload, download)
- [ ] Local filesystem walker + hash cache
- [ ] SQLite state store (snapshots, queue, conflicts)
- [ ] Diff engine
- [ ] Sync queue with job persistence
- [ ] Transfer manager with rate limiting and scheduling
- [ ] Unix socket IPC protocol
- [ ] CLI client (`proton-drive`)
- [ ] System tray GUI app
- [ ] Conflict resolution UI
- [ ] systemd user unit for auto-start
- [ ] Packaging (`.deb`, AppImage, Flatpak)

---

## Contributing

This project is in early planning. If you are interested in contributing, please open an issue to discuss ideas before submitting a pull request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes
4. Open a pull request

---

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

This is an unofficial, community-developed client. It is not affiliated with or endorsed by Proton AG. Use at your own risk.
