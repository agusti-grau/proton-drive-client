# Programming Diary — Proton Drive Client for Linux Mint

---

## Session 1 — 2026-03-14

### Overview

First session. Went from blank repository to a working scaffolding with a full authentication pipeline.

---

### 1. Project definition

Decided to build an unofficial Proton Drive client for Linux Mint.

**Key decisions made:**

| Topic | Decision |
|-------|----------|
| Platform | Linux Mint 21+ (Ubuntu 22.04 base) |
| Language | Rust |
| Client type | GUI desktop app + CLI + background daemon |
| IPC | Unix domain socket (`$XDG_RUNTIME_DIR/protond.sock`) |
| Authentication | SRP-6a (Proton's protocol — see note below) |
| Conflict resolution | Ask the user (manual per-file resolution) |
| Bandwidth control | Rate cap (KB/s) + time-window scheduling |

> **OAuth note:** The original plan mentioned browser-based OAuth, but research confirmed that Proton's API uses a custom SRP-6a protocol for all third-party clients. There is no public OAuth 2.0 endpoint. Authentication is done entirely via the SRP exchange.

---

### 2. Architecture design

Three binaries communicating over a Unix socket:

```
┌───────────────┐     ┌───────────────┐
│  GUI Desktop  │     │   CLI client  │
│     App       │     │ proton-drive  │
└───────┬───────┘     └───────┬───────┘
        │   Unix socket IPC   │
        └──────────┬──────────┘
                   │
         ┌─────────▼─────────┐
         │   protond (daemon) │
         │  Auth · Sync · Queue · Transfer  │
         └───────────────────┘
```

**Sync pipeline order:**
1. Authenticate (SRP → tokens → keyring)
2. Connect to Proton Drive API
3. Enumerate remote files (decrypt metadata)
4. Enumerate local files (walk + hash)
5. Diff against last-known state (SQLite)
6. Pause conflicts → notify user
7. Build prioritised job queue (persist to SQLite)
8. Transfer with rate limiting + time-window scheduling

**Storage layout decided:**
```
~/.config/proton-drive/config.toml
~/.local/share/proton-drive/state.db   (SQLite)
$XDG_RUNTIME_DIR/protond.sock
$XDG_RUNTIME_DIR/protond.pid
```
Credentials stored exclusively in the system keyring (libsecret).

---

### 3. README written

Created `README.md` with:
- Project description and status badge
- Full architecture diagram (ASCII)
- Sync pipeline table
- IPC protocol description
- Storage layout
- Build from source instructions
- Roadmap checklist

---

### 4. Authentication module implemented

#### Research findings

- Proton uses **SRP-6a** (RFC 5054 variant) for all account authentication.
- The API endpoint is `POST /auth/v4/info` → `POST /auth/v4`.
- All big-integer SRP values are transmitted as **little-endian** base64 bytes (non-standard).
- The 2048-bit prime modulus N is served **PGP-signed** from the API.
- Password is stretched with **bcrypt** (cost 10) before entering SRP.
- Reference implementations studied: `go-srp`, `proton-python-client`, `proton-api-rs` (archived).

#### Files created

```
Cargo.toml                              workspace (resolver = "2")
crates/
  proton-core/
    Cargo.toml
    src/
      lib.rs
      error.rs                          Error enum
      api/
        mod.rs
        types.rs                        AuthInfoResponse, AuthRequest, AuthResponse,
                                        TwoFactorInfo, TwoFactorRequest,
                                        RefreshRequest, Session
        client.rs                       ApiClient — HTTP wrapper around Proton API
      auth/
        mod.rs                          login(), complete_2fa(), refresh_session(), logout()
        password.rs                     bcrypt key derivation
        srp.rs                          SRP-6a math
      keyring.rs                        libsecret save/load/delete session
  protond/
    Cargo.toml
    src/main.rs                         daemon skeleton
  proton-drive/
    Cargo.toml
    src/main.rs                         CLI: auth login / logout / status
```

#### Authentication flow implemented

```
proton-drive auth login
        │
        ├─ prompt username + password (rpassword — hidden input)
        │
        ├─ GET /auth/v4/info
        │       └─ returns: modulus (PGP-signed N), server_ephemeral (B),
        │                   salt, srp_session, version
        │
        ├─ bcrypt(password, salt, cost=10) → strip 29-char prefix → key_password
        │
        ├─ SRP-6a computation
        │       k  = H(N_le ‖ g_le)
        │       a  = random 256-bit secret
        │       A  = g^a mod N
        │       u  = H(A_le ‖ B_le)
        │       x  = H(salt ‖ H(username:key_password))
        │       S  = (B − k·g^x)^(a + u·x) mod N
        │       K  = H(S_le)
        │       M1 = H(H(N)⊕H(g) ‖ H(username) ‖ salt ‖ A_le ‖ B_le ‖ K)
        │       M2_expected = H(A_le ‖ M1 ‖ K)
        │
        ├─ POST /auth/v4 → { ClientEphemeral: A, ClientProof: M1, SRPSession }
        │       └─ returns: uid, access_token, refresh_token, server_proof (M2)
        │
        ├─ verify server_proof == M2_expected   ← mutual authentication
        │
        ├─ if 2FA enabled → prompt TOTP → POST /auth/v4/2fa
        │
        └─ save Session { uid, access_token, refresh_token, username }
               to system keyring via libsecret
```

#### Key dependencies

| Crate | Purpose |
|-------|---------|
| `reqwest` 0.12 | HTTP client (rustls, no OpenSSL) |
| `sha2` 0.10 | SHA-512 for SRP hashing |
| `bcrypt` 0.15 | Password stretching |
| `num-bigint` 0.4 | Arbitrary-precision integers for SRP |
| `rand` 0.8 | Random client ephemeral |
| `base64` 0.22 | Encode/decode SRP wire values |
| `keyring` 3 | libsecret / GNOME Keyring / KWallet |
| `clap` 4 | CLI argument parsing |
| `rpassword` 7 | Hidden password prompt |
| `thiserror` 2 | Error type derivation |

---

### 5. Known limitations / TODOs

- [ ] PGP signature on the modulus is parsed but **not verified** against Proton's public key — must be added before production use.
- [ ] Auth version < 4 is rejected; older accounts using legacy password schemes are not supported yet.
- [ ] Token refresh on expiry is implemented but not wired into an automatic retry loop.
- [ ] `protond` daemon is a skeleton only — no IPC socket, no sync engine yet.
- [ ] No unit tests yet for SRP math or bcrypt derivation.
- [ ] Rust is not yet installed on the development machine — build not verified.

---

---

## Session 2 — 2026-03-14

### Goal: unit tests for `srp.rs` using go-srp test vectors

### Research findings (go-srp source)

Studying `ProtonMail/go-srp` revealed that my Session 1 implementation had several errors.

| Component | Session 1 (wrong) | Session 2 (corrected) |
|-----------|-------------------|----------------------|
| Hash function | SHA-512 (64 bytes) | `expand_hash` = 4× SHA-512 (256 bytes) |
| Endianness | Little-endian | **Big-endian** |
| x (password key) | `H(salt ‖ H(user:pass))` | `expand_hash(bcrypt_output ‖ modulus_bytes)` |
| Session key K | `SHA-512(S)` | `expand_hash(S_padded)` — 256 bytes |
| M1 (client proof) | RFC 2945 formula | `expand_hash(A ‖ B ‖ K)` |
| M2 (server proof) | `H(A ‖ M1 ‖ K)` | `expand_hash(A ‖ M1 ‖ K)` |
| password.rs return | Stripped 31-char hash | Full 60-byte bcrypt string |

#### `expand_hash` — the core hash primitive

```
expand_hash(data) = SHA512(data‖0x00) ‖ SHA512(data‖0x01) ‖ SHA512(data‖0x02) ‖ SHA512(data‖0x03)
                  = 256 bytes total
```

#### Note on bcrypt "proton" salt suffix

go-srp appends `"proton"` to the salt before bcrypt-base64 encoding it.
Analysis shows this is mathematically a no-op: bcrypt internally *decodes* the
base64 salt string back to 16 bytes, and the extra bits from `"proton"` fall below
the precision boundary of the 22-character encoding.  The hash produced by
`hash_with_salt(password, 10, salt_bytes)` is identical.

### Files changed

| File | Change |
|------|--------|
| `src/auth/srp.rs` | Full rewrite: `expand_hash`, big-endian, corrected M1/M2/x/k formulas |
| `src/auth/password.rs` | Returns full 60-byte bcrypt string bytes (not stripped hash) |
| `src/auth/mod.rs` | Updated call: passes `bcrypt_output` + `modulus_bytes` to `srp::generate_srp_proof`; removed `username` and `salt` from SRP call |

### Tests written

#### Inline unit tests in `srp.rs`

| Test | What it verifies |
|------|-----------------|
| `expand_hash_output_is_256_bytes` | Output length |
| `expand_hash_first_64_bytes_match_sha512_with_suffix_0` | Correct SHA-512 with suffix 0 |
| `expand_hash_last_64_bytes_match_sha512_with_suffix_3` | Correct SHA-512 with suffix 3 |
| `expand_hash_is_deterministic` | Same input → same output |
| `expand_hash_differs_for_different_inputs` | Collision resistance |
| `be_padded_pads_short_value` | Left zero-padding |
| `be_padded_exact_length_unchanged` | No change when already correct size |
| `srp_client_and_server_share_same_secret_p23` | S_client == S_server (safe prime 23) |
| `srp_client_and_server_share_same_secret_p47` | S_client == S_server (safe prime 47) |
| `decode_modulus_strips_pgp_wrapper` | PGP envelope parsing |
| `decode_modulus_plain_base64` | Plain base64 fallback |
| `generate_srp_proof_returns_valid_structure` | M1/M2 are 256-byte, non-empty |

#### Inline unit tests in `password.rs`

| Test | What it verifies |
|------|-----------------|
| `hash_password_returns_60_bytes` | Output length |
| `hash_password_starts_with_bcrypt_prefix` | `$2b$10$` or `$2y$10$` prefix |
| `hash_password_is_deterministic` | Reproducible |
| `hash_password_differs_for_different_passwords` | Password sensitivity |
| `hash_password_differs_for_different_salts` | Salt sensitivity |
| `hash_password_rejects_wrong_salt_length` | 8-byte salt rejected |
| `hash_password_rejects_invalid_base64` | Bad base64 rejected |

#### Integration tests in `tests/auth_integration.rs`

| Test | What it verifies |
|------|-----------------|
| `expand_hash_matches_go_srp_definition` | Cross-check against go-srp's formula |
| `hash_password_shape_for_gostrp_credentials` | Shape with actual go-srp test credentials |
| `srp_proof_structure_with_gostrp_inputs` | M1/M2 sizes with go-srp B value |
| `live_login_succeeds` *(#[ignore])* | Real API login (needs PROTON_USER/PROTON_PASS) |

### Known limitation

The go-srp test vectors include expected M1/M2 values (`Qb+1+jEq…`, `SLCSICli…`)
but the **modulus N** used in that test run is not hardcoded in go-srp — it was
fetched live from Proton's API. Without the exact modulus we cannot reproduce the
exact M1/M2 values.  The M1/M2 constants are kept as comments in
`tests/auth_integration.rs` pending discovery of the test modulus.

---

---

## Session 3 — 2026-03-15

### Goal: install Rust, compile, run tests

### Step 1 — Install Rust

Rust was not installed. Ran the official installer:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

Installed: **rustc 1.94.0** (stable, 2026-03-02).

### Step 2 — First compile attempt

`cargo check` failed with:

```
package `proton-core` depends on `keyring` with feature
`linux-secret-service-rt-tokio-crypto-rust` but `keyring` does not have that feature.
```

**Fix:** Updated `keyring` feature flags in `crates/proton-core/Cargo.toml`:

```toml
# Before
keyring = { version = "3", features = ["linux-secret-service-rt-tokio-crypto-rust"] }
# After
keyring = { version = "3", features = ["async-secret-service", "tokio", "crypto-rust"] }
```

`cargo check` then passed cleanly.

### Step 3 — First test run

21 unit tests passed. 2 integration tests failed:

```
Auth("Expected 16-byte salt, got 10 bytes")
```

### Root cause analysis

The go-srp test salt `yKlc5/CvObfoiw==` decodes to **10 bytes**, not 16.
This revealed two additional errors in `password.rs`:

| Issue | Wrong | Correct |
|-------|-------|---------|
| Salt length assumption | Always 16 bytes | Variable; API typically sends 10 bytes |
| `"proton"` suffix | Dismissed as no-op | Pads 10-byte salt to exactly 16 bytes: `10 + 6 = 16` |
| Output prefix | `$2b$10$` (Rust crate default) | `$2y$10$` (Proton convention) — prefix is part of `x` input |

**The "proton" suffix is not cosmetic.** For a 10-byte server salt, appending `"proton"` (6 bytes) produces exactly the 16 bytes bcrypt needs. My earlier analysis assumed a 16-byte salt where the suffix happened to be a no-op — that assumption was wrong.

**The `$2b$` → `$2y$` normalisation matters** because the full 60-byte bcrypt string is passed as input to `expand_hash` for `x` derivation. Different prefix → different `x` → wrong session key.

### Fixes applied to `password.rs`

1. Decode server salt (any length ≥ 10 bytes).
2. Append `b"proton"`.
3. Take first 16 bytes as the bcrypt salt.
4. After hashing, replace `$2b$` prefix with `$2y$`.

### Final result

```
running 21 tests  →  21 passed; 0 failed   (unit tests, proton-core)
running  4 tests  →   3 passed; 0 failed; 1 ignored   (integration tests)
```

Total: **24 tests, 0 failures, 0 warnings.**
The 1 ignored test (`live_login_succeeds`) requires real Proton credentials.

### Next steps

1. Obtain the Proton test modulus to enable exact M1/M2 vector verification.
2. Verify PGP signature of the modulus (fingerprint `248097092b458509c508dac0350585c4e9518f26`).
3. Begin remote filesystem enumeration (Proton Drive file listing API).

---

*Last updated: 2026-03-14*
