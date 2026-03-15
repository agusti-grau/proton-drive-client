//! Proton Drive API response and request types.
//!
//! Field names use `PascalCase` to match the Proton API's JSON convention.
//! Integer enums (State, Type, Flags) use `#[serde(from = "i32")]` so unknown
//! values are safely preserved instead of causing a parse error.

use serde::{Deserialize, Serialize};

// ── Volume ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Volume {
    pub volume_id: String,
    pub state: VolumeState,
    /// The default share / root of this volume.
    pub share: VolumeShare,
    pub max_space: Option<i64>,
    pub used_space: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumeShare {
    pub share_id: String,
    /// LinkID of the root folder.
    pub link_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeState {
    Active,
    Locked,
    Other(i32),
}

impl From<i32> for VolumeState {
    fn from(n: i32) -> Self {
        match n {
            1 => Self::Active,
            3 => Self::Locked,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for VolumeState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

// ── Share ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ShareMetadata {
    pub share_id: String,
    /// LinkID of the share's root folder.
    pub link_id: String,
    pub volume_id: String,
    #[serde(rename = "Type")]
    pub share_type: ShareType,
    pub state: ShareState,
    pub flags: ShareFlags,
    pub creator: String,
    pub locked: bool,
}

/// Full share including the encrypted share key and passphrase.
/// Used to derive the keyring for decrypting link names.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Share {
    #[serde(flatten)]
    pub metadata: ShareMetadata,

    pub address_id: String,
    pub address_key_id: String,

    /// PGP-armored encrypted share private key.
    pub key: String,
    /// PGP-armored passphrase (encrypted with the address key).
    pub passphrase: String,
    /// PGP-armored signature of the passphrase.
    pub passphrase_signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareType {
    Main,
    Standard,
    Device,
    Other(i32),
}

impl From<i32> for ShareType {
    fn from(n: i32) -> Self {
        match n {
            1 => Self::Main,
            2 => Self::Standard,
            3 => Self::Device,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for ShareType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareState {
    Active,
    Deleted,
    Other(i32),
}

impl From<i32> for ShareState {
    fn from(n: i32) -> Self {
        match n {
            1 => Self::Active,
            2 => Self::Deleted,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for ShareState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareFlags {
    None,
    Primary,
    Other(i32),
}

impl From<i32> for ShareFlags {
    fn from(n: i32) -> Self {
        match n {
            0 => Self::None,
            1 => Self::Primary,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for ShareFlags {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

// ── Link (file / folder node) ──────────────────────────────────────────────

/// A node in the Proton Drive tree.  Represents both files and folders.
///
/// File and folder names are PGP-encrypted; use the drive crypto module to
/// decrypt them with the parent folder's node keyring.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Link {
    pub link_id: String,
    /// `None` only for the root link of a share.
    pub parent_link_id: Option<String>,

    #[serde(rename = "Type")]
    pub link_type: LinkType,

    /// PGP-armored encrypted file/folder name.
    /// Decrypt with the *parent* folder's node keyring.
    pub name: String,

    /// HMAC of the name (for collision detection).
    pub hash: String,

    /// File size in bytes.  0 for folders.
    pub size: i64,
    pub state: LinkState,
    pub mime_type: String,

    pub create_time: i64,
    pub modify_time: i64,

    /// PGP-armored encrypted private node key.
    pub node_key: String,
    /// PGP-armored passphrase for the node key (encrypted with parent's node key).
    pub node_passphrase: String,
    /// PGP-armored signature of the node passphrase.
    pub node_passphrase_signature: String,

    pub file_properties: Option<FileProperties>,
    pub folder_properties: Option<FolderProperties>,
}

impl Link {
    pub fn is_folder(&self) -> bool {
        self.link_type == LinkType::Folder
    }

    pub fn is_file(&self) -> bool {
        self.link_type == LinkType::File
    }

    pub fn is_active(&self) -> bool {
        self.link_type == LinkType::Folder && self.state == LinkState::Active
            || self.link_type == LinkType::File && self.state == LinkState::Active
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FileProperties {
    /// Base64-encoded key packet (encrypted with the node key).
    pub content_key_packet: String,
    /// PGP-armored signature of the content key packet.
    pub content_key_packet_signature: String,
    pub active_revision: RevisionMetadata,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FolderProperties {
    /// PGP-armored HMAC key used to hash child names.
    pub node_hash_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RevisionMetadata {
    #[serde(rename = "ID")]
    pub id: String,
    pub create_time: i64,
    pub size: i64,
    pub state: RevisionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Folder,
    File,
    Other(i32),
}

impl From<i32> for LinkType {
    fn from(n: i32) -> Self {
        match n {
            1 => Self::Folder,
            2 => Self::File,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for LinkType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Draft,
    Active,
    Trashed,
    Deleted,
    Restoring,
    Other(i32),
}

impl From<i32> for LinkState {
    fn from(n: i32) -> Self {
        match n {
            0 => Self::Draft,
            1 => Self::Active,
            2 => Self::Trashed,
            3 => Self::Deleted,
            4 => Self::Restoring,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for LinkState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionState {
    Draft,
    Active,
    Obsolete,
    Deleted,
    Other(i32),
}

impl From<i32> for RevisionState {
    fn from(n: i32) -> Self {
        match n {
            0 => Self::Draft,
            1 => Self::Active,
            2 => Self::Obsolete,
            3 => Self::Deleted,
            other => Self::Other(other),
        }
    }
}

impl<'de> Deserialize<'de> for RevisionState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(i32::deserialize(d)?))
    }
}

// ── Folder-create request ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateFolderReq {
    pub parent_link_id: String,
    pub name: String,
    pub hash: String,
    pub node_key: String,
    pub node_hash_key: String,
    pub node_passphrase: String,
    pub node_passphrase_signature: String,
    pub signature_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateFolderRes {
    #[serde(rename = "ID")]
    pub id: String,
}
