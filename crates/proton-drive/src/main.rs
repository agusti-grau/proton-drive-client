//! `proton-drive` — CLI client for the Proton Drive sync daemon.
//!
//! Communicates with `protond` over a Unix socket (TODO).
//! For now, auth commands call `proton-core` directly.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use proton_core::auth::{self, LoginResult};
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
        Commands::Status => {
            // TODO: connect to protond Unix socket and request status.
            println!("protond IPC not yet implemented.");
            Ok(())
        }
    }
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
