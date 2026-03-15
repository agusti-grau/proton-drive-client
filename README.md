# Proton Drive Client for Linux Mint

A native CLI and background daemon for Linux Mint that provides two-way synchronisation with [Proton Drive](https://proton.me/drive). Built in Rust.

> **Status: Early development — authentication and remote file listing are working. Sync engine not yet implemented.**

---

## What works today

| Feature | Status |
|---------|--------|
| SRP-6a authentication (login, 2FA, logout, token refresh) | ✅ Working |
| Session storage in system keyring (libsecret) | ✅ Working |
| Remote volume / share enumeration | ✅ Working |
| Remote file tree listing (depth-first walk) | ✅ Working |
| PGP name decryption (full key-chain: address → share → node) | ✅ Working |
| Local filesystem scanner | 🔲 Not started |
| SQLite state DB (snapshots, sync queue) | 🔲 Not started |
| Diff engine | 🔲 Not started |
| File upload / download | 🔲 Not started |
| `protond` IPC socket | 🔲 Not started |
| GUI desktop app | 🔲 Not started |

---

## Architecture

Three binaries sharing a Unix socket:

```
┌───────────────┐     ┌───────────────┐
│  GUI Desktop  │     │   CLI client  │
│  App (future) │     │ proton-drive  │
└───────┬───────┘     └───────┬───────┘
        │   Unix socket IPC   │
        └──────────┬──────────┘
                   │
         ┌─────────▼─────────┐
         │   protond (daemon) │
         │                   │
         │  Auth · Sync · Queue · Transfer
         └───────────────────┘
```

### Crate layout

```
Cargo.toml                     workspace root
crates/
  proton-core/                 library — all business logic
    src/
      api/
        client.rs              ApiClient (HTTP, auth + drive endpoints)
        types.rs               Auth API types
        drive_types.rs         Drive API types (Volume, Share, Link, …)
      auth/
        mod.rs                 login(), complete_2fa(), refresh_session(), logout()
        password.rs            bcrypt key derivation (SRP + key-password)
        srp.rs                 SRP-6a math (expand_hash, proofs)
      crypto/
        mod.rs                 pgp_decrypt() — rpgp 0.14 wrapper
      drive/
        mod.rs                 DriveClient, DriveNode, walk_decrypted()
        keyring.rs             DriveKeyring — key-chain management
      keyring.rs               System keyring (libsecret) session storage
      error.rs                 Error enum
  protond/                     Daemon (skeleton — IPC not yet implemented)
  proton-drive/                CLI client
```

### Sync pipeline (planned)

| Step | Description | Status |
|------|-------------|--------|
| 1 | Authenticate via SRP-6a → store session in libsecret | ✅ |
| 2 | Enumerate remote tree, decrypt file names with PGP key chain | ✅ |
| 3 | Enumerate local sync folder (walk + hash) | 🔲 |
| 4 | Diff remote vs local vs last-known state (SQLite) | 🔲 |
| 5 | Resolve conflicts — pause and notify user | 🔲 |
| 6 | Build prioritised job queue (persisted to SQLite) | 🔲 |
| 7 | Transfer with rate limiting + time-window scheduling | 🔲 |

---

## Authentication

Proton does **not** use OAuth.  Authentication uses a custom **SRP-6a** variant:

```
POST /auth/v4/info  →  server ephemeral B, PGP-signed modulus N, bcrypt salt
bcrypt(password, salt + "proton", cost=10)  →  60-byte bcrypt string
expand_hash = SHA-512(data‖0) ‖ SHA-512(data‖1) ‖ SHA-512(data‖2) ‖ SHA-512(data‖3)
x  = expand_hash(bcrypt_output ‖ modulus_bytes)
K  = expand_hash(S_padded)
M1 = expand_hash(A ‖ B ‖ K)          ← client proof
POST /auth/v4  →  verify server proof M2, get uid + tokens
```

Session tokens are stored in the system keyring and never written to disk.

## PGP key-decryption chain

Proton Drive encrypts file names and node keys with a layered PGP key chain:

```
user password
    │  hash_password(password, key_salt)   ← GET /core/v4/keys/salts
    ▼
key password  ──unlocks──►  address private key   (GET /core/v4/addresses)
                                   │  decrypt share.passphrase
                                   ▼
                          share key passphrase
                          ──unlocks──►  share private key   (share.key)
                                             │  decrypt root_link.node_passphrase
                                             ▼
                                    root node key passphrase
                                    ──unlocks──►  root node key
                                                       │  decrypt child names / passphrases
                                                       ▼
                                                  plaintext filename
                                                  (recurse for sub-folders)
```

---

## CLI usage

```bash
# Authentication
proton-drive auth login           # interactive SRP login (prompts for username + password)
proton-drive auth logout          # revoke session on server and remove from keyring
proton-drive auth status          # print currently logged-in account

# Remote file listing
proton-drive ls                   # list root folder (encrypted names)
proton-drive ls --decrypt         # list root folder with real names (prompts for password)
proton-drive ls -r                # recursive walk, encrypted names
proton-drive ls -r --decrypt      # recursive walk with real names
```

---

## Building from source

### Prerequisites

- [Rust](https://rustup.rs/) 1.75 or later (tested on 1.94.0)
- `libsecret` development headers:

```bash
sudo apt install libsecret-1-dev pkg-config
```

### Build

```bash
git clone https://github.com/your-username/proton-drive-client.git
cd proton-drive-client

cargo build --release

# Binaries:
#   ./target/release/proton-drive   (CLI)
#   ./target/release/protond        (daemon)
```

### Run tests

```bash
cargo test

# Live login test (requires a real Proton account):
PROTON_USER=you@proton.me PROTON_PASS=yourpassword \
    cargo test --test auth_integration -- --ignored
```

---

## Storage layout

```
~/.config/proton-drive/
    config.toml              user preferences (future)

~/.local/share/proton-drive/
    state.db                 SQLite: file snapshots, sync queue, conflicts (future)

$XDG_RUNTIME_DIR/
    protond.sock             Unix socket (future)
    protond.pid              PID file (future)
```

Credentials are stored exclusively in the **system keyring** (libsecret / GNOME Keyring / KWallet) and never written to disk in plaintext.

---

## Roadmap

- [x] SRP-6a authentication (login, 2FA, logout, token refresh)
- [x] Session storage in system keyring
- [x] Proton Drive API client (volumes, shares, links, pagination)
- [x] Remote file tree listing (depth-first walk, auto-paginated)
- [x] PGP name decryption (full address → share → node key chain)
- [ ] Verify PGP signature on SRP modulus
- [ ] Local filesystem walker + hash cache
- [ ] SQLite state store (snapshots, queue, conflicts)
- [ ] Diff engine
- [ ] Sync queue with job persistence
- [ ] File upload / download (Proton block-based transfer protocol)
- [ ] `protond` IPC socket (daemon ↔ CLI/GUI protocol)
- [ ] Transfer manager with rate limiting and time-window scheduling
- [ ] Conflict resolution
- [ ] System tray GUI app
- [ ] systemd user unit for auto-start
- [ ] Packaging (`.deb`, AppImage, Flatpak)

---

## Key dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `reqwest` | 0.12 | HTTP client (rustls, no OpenSSL) |
| `pgp` (rpgp) | 0.14 | OpenPGP key decryption |
| `sha2` | 0.10 | SHA-512 for SRP `expand_hash` |
| `bcrypt` | 0.15 | Password stretching (SRP + key-password) |
| `num-bigint` | 0.4 | Arbitrary-precision integers for SRP |
| `keyring` | 3 | libsecret / GNOME Keyring / KWallet |
| `clap` | 4 | CLI argument parsing |
| `serde` / `serde_json` | 1 | JSON serialisation |
| `tokio` | 1 | Async runtime |
| `thiserror` | 2 | Error type derivation |

---

## Contributing

The project is in active early development. If you are interested in contributing, please open an issue to discuss before submitting a pull request.

---

## Disclaimer

This is an unofficial, community-developed client. It is not affiliated with or endorsed by Proton AG. Use at your own risk.

## License

MIT — see [LICENSE](LICENSE).
