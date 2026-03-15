//! `proton-drive` — CLI client for the Proton Drive sync daemon.
//!
//! Communicates with `protond` over a Unix socket (TODO).
//! For now, auth commands call `proton-core` directly.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use proton_core::api::ApiClient;
use proton_core::auth::{self, LoginResult};
use proton_core::drive::DriveClient;
use proton_core::keyring;

// ── CLI definition ─────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "proton-drive",
    about = "Proton Drive client for Linux",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authentication commands.
    Auth {
        #[command(subcommand)]
        action: AuthCommands,
    },
    /// List files and folders in the remote drive.
    Ls {
        /// Folder path to list (not yet implemented — lists root for now).
        #[arg(default_value = "/")]
        path: String,
        /// Recursively list all files and folders.
        #[arg(short, long)]
        recursive: bool,
        /// Decrypt file names (prompts for password).
        #[arg(short, long)]
        decrypt: bool,
    },
    /// Show sync status (requires protond to be running).
    Status,
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Log in to your Proton account.
    Login,
    /// Log out and revoke the current session.
    Logout,
    /// Print the currently logged-in account.
    Status,
}

// ── Entry point ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Auth { action } => handle_auth(action).await,
        Commands::Ls { recursive, decrypt, .. } => cmd_ls(recursive, decrypt).await,
        Commands::Status => {
            // TODO: connect to protond Unix socket and request status.
            println!("protond IPC not yet implemented.");
            Ok(())
        }
    }
}

// ── Drive handlers ─────────────────────────────────────────────────────────

async fn cmd_ls(recursive: bool, decrypt: bool) -> Result<()> {
    let session = keyring::load_session()
        .context("Failed to read keyring")?
        .ok_or_else(|| anyhow::anyhow!("Not logged in — run `proton-drive auth login` first"))?;

    let api = ApiClient::new()
        .context("Failed to build API client")?
        .with_session(session);
    let drive = DriveClient::new(api);

    if decrypt {
        let password = rpassword::prompt_password("Password (for key decryption): ")
            .context("Failed to read password")?;

        if recursive {
            println!("Fetching and decrypting full drive tree…");
            let items = drive
                .walk_all_decrypted(&password)
                .await
                .context("Failed to walk drive")?;
            for (node, name) in &items {
                let kind = if node.is_folder() { "DIR " } else { "FILE" };
                println!("{kind}  {name}");
            }
            println!("\n{} item(s) total", items.len());
        } else {
            println!("Fetching and decrypting root folder…");
            let items = drive
                .list_root_decrypted(&password)
                .await
                .context("Failed to list drive root")?;
            for (node, name) in &items {
                let kind = if node.is_folder() { "DIR " } else { "FILE" };
                let size = if node.is_file() {
                    format!("  {:>12} B", node.size)
                } else {
                    String::new()
                };
                println!("{kind}{size}  {name}");
            }
            println!("\n{} item(s)", items.len());
        }
    } else if recursive {
        println!("Fetching full drive tree…");
        let nodes = drive.walk_all().await.context("Failed to list drive")?;
        for node in &nodes {
            let kind = if node.is_folder() { "DIR " } else { "FILE" };
            println!("{kind}  {}", node.display_name());
        }
        println!("\n{} item(s) total — use --decrypt to show real names", nodes.len());
    } else {
        println!("Fetching root folder…");
        let nodes = drive.list_root().await.context("Failed to list drive root")?;
        for node in &nodes {
            let kind = if node.is_folder() { "DIR " } else { "FILE" };
            let size = if node.is_file() {
                format!("  {:>12} B", node.size)
            } else {
                String::new()
            };
            println!("{kind}{size}  {}", node.display_name());
        }
        println!("\n{} item(s) — use --decrypt to show real names", nodes.len());
    }

    Ok(())
}

// ── Auth handlers ──────────────────────────────────────────────────────────

async fn handle_auth(action: AuthCommands) -> Result<()> {
    match action {
        AuthCommands::Login  => cmd_login().await,
        AuthCommands::Logout => cmd_logout().await,
        AuthCommands::Status => cmd_auth_status(),
    }
}

async fn cmd_login() -> Result<()> {
    // Prompt for credentials interactively.
    let username = prompt("Proton account (email or username): ")?;
    let password = rpassword::prompt_password("Password: ")
        .context("Failed to read password")?;

    println!("Authenticating…");

    let result = auth::login(username.trim(), &password)
        .await
        .context("Login failed")?;

    match result {
        LoginResult::Success(session) => {
            keyring::save_session(&session).context("Failed to save session to keyring")?;
            println!("Logged in as {}.", session.username);
        }
        LoginResult::TwoFactorRequired(client) => {
            let code = prompt("2FA code (TOTP): ")?;
            let session = auth::complete_2fa(&client, code.trim())
                .await
                .context("2FA failed")?;
            keyring::save_session(&session).context("Failed to save session to keyring")?;
            println!("Logged in as {} (2FA verified).", session.username);
        }
    }

    Ok(())
}

async fn cmd_logout() -> Result<()> {
    match keyring::load_session().context("Failed to read keyring")? {
        None => {
            println!("Not logged in.");
        }
        Some(session) => {
            let username = session.username.clone();
            auth::logout(&session).await.context("Logout failed")?;
            println!("Logged out from {}.", username);
        }
    }
    Ok(())
}

fn cmd_auth_status() -> Result<()> {
    match keyring::load_session().context("Failed to read keyring")? {
        None    => println!("Not logged in."),
        Some(s) => println!("Logged in as {}.", s.username),
    }
    Ok(())
}

// ── Utilities ──────────────────────────────────────────────────────────────

fn prompt(label: &str) -> Result<String> {
    use std::io::{self, Write};
    print!("{label}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input)
}
