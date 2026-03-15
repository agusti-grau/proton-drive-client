//! `protond` — Proton Drive sync daemon.
//!
//! This binary will own the sync engine, auth state, transfer queue, and
//! expose a Unix-socket IPC interface for the CLI and GUI to connect to.
//!
//! Current status: skeleton only — auth integration is the first milestone.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    eprintln!("protond starting…");

    // TODO: parse config from ~/.config/proton-drive/config.toml
    // TODO: open Unix socket at $XDG_RUNTIME_DIR/protond.sock
    // TODO: load stored session from keyring and restore auth state
    // TODO: start sync engine loop
    // TODO: accept IPC connections from CLI / GUI

    eprintln!("protond: not yet implemented");
    Ok(())
}
