//! Secure credential storage via the system keyring (libsecret / GNOME Keyring / KWallet).

use keyring::Entry;

use crate::api::Session;
use crate::{Error, Result};

const SERVICE: &str = "proton-drive";
const ACCOUNT: &str = "session";

/// Persist a session to the system keyring as JSON.
pub fn save_session(session: &Session) -> Result<()> {
    let json = serde_json::to_string(session)?;
    entry()?.set_password(&json).map_err(keyring_err)?;
    Ok(())
}

/// Load the stored session from the system keyring, or `None` if not found.
pub fn load_session() -> Result<Option<Session>> {
    match entry()?.get_password() {
        Ok(json) => {
            let session: Session = serde_json::from_str(&json)?;
            Ok(Some(session))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(keyring_err(e)),
    }
}

/// Remove the stored session from the system keyring.
pub fn delete_session() -> Result<()> {
    match entry()?.delete_credential() {
        Ok(()) => Ok(()),
        // Deleting a non-existent entry is harmless.
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(keyring_err(e)),
    }
}

fn entry() -> Result<Entry> {
    Entry::new(SERVICE, ACCOUNT).map_err(keyring_err)
}

fn keyring_err(e: keyring::Error) -> Error {
    Error::Keyring(e.to_string())
}
