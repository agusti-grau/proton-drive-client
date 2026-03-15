//! PGP cryptographic helpers for Proton Drive.
//!
//! Proton Drive uses OpenPGP (via rpgp) for:
//! - Encrypting the share-key passphrase with the address key.
//! - Encrypting each node-key passphrase with the parent node key.
//! - Encrypting file/folder names with the parent node key.
//!
//! The decryption primitive is always the same: an armored PGP message
//! encrypted to a given key, where that key is itself locked with a passphrase.

use std::io::Cursor;

use pgp::{Deserializable, Message, SignedSecretKey};

use crate::{Error, Result};

/// Decrypt a PGP-armored message using the supplied key.
///
/// # Arguments
/// - `armored_msg`  — PGP-armored ciphertext (the message to decrypt).
/// - `armored_key`  — PGP-armored secret key that the message is encrypted to.
/// - `key_passphrase` — Passphrase that unlocks `armored_key`.
///                      Pass an empty slice if the key has no passphrase.
///
/// # Returns
/// The raw plaintext bytes of the decrypted message.
pub fn pgp_decrypt(
    armored_msg: &str,
    armored_key: &str,
    key_passphrase: &[u8],
) -> Result<Vec<u8>> {
    let (key, _) = SignedSecretKey::from_armor_single(Cursor::new(armored_key.as_bytes()))
        .map_err(|e| Error::Crypto(format!("key parse: {e}")))?;

    let (msg, _) = Message::from_armor_single(Cursor::new(armored_msg.as_bytes()))
        .map_err(|e| Error::Crypto(format!("message parse: {e}")))?;

    let pw = String::from_utf8_lossy(key_passphrase).into_owned();
    let (decrypted, _) = msg
        .decrypt(|| pw.clone(), &[&key])
        .map_err(|e| Error::Crypto(format!("decrypt: {e}")))?;

    decrypted
        .get_content()
        .map_err(|e| Error::Crypto(format!("get content: {e}")))?
        .ok_or_else(|| Error::Crypto("decrypted message has no literal content".into()))
}
