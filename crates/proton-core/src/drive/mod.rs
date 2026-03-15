//! High-level Proton Drive client: tree enumeration.
//!
//! Wraps [`ApiClient`] to provide ergonomic methods for listing and
//! walking the remote drive hierarchy (volumes → shares → links).
//!
//! ## Usage
//!
//! ```no_run
//! use proton_core::drive::DriveClient;
//! use proton_core::api::ApiClient;
//! use proton_core::api::types::Session;
//!
//! # async fn example(session: Session) -> proton_core::Result<()> {
//! let api = ApiClient::new()?.with_session(session);
//! let drive = DriveClient::new(api);
//! let nodes = drive.list_root().await?;
//! for node in &nodes {
//!     println!("{}", node.display_name());
//! }
//! # Ok(())
//! # }
//! ```

use crate::api::ApiClient;
use crate::api::drive_types::{Link, LinkState, LinkType, VolumeState};
use crate::Result;

/// Page size for folder-children requests.
const PAGE_SIZE: u32 = 150;

// ── DriveNode ──────────────────────────────────────────────────────────────

/// A node in the remote drive tree.
#[derive(Debug, Clone)]
pub struct DriveNode {
    pub share_id: String,
    pub link_id: String,
    pub parent_link_id: Option<String>,
    pub link_type: LinkType,
    /// PGP-encrypted name as returned by the API.
    /// Use `display_name()` for a printable representation.
    pub encrypted_name: String,
    pub size: i64,
    pub state: LinkState,
    pub mime_type: String,
    pub create_time: i64,
    pub modify_time: i64,
}

impl DriveNode {
    fn from_link(share_id: &str, link: Link) -> Self {
        Self {
            share_id: share_id.to_string(),
            link_id: link.link_id,
            parent_link_id: link.parent_link_id,
            link_type: link.link_type,
            encrypted_name: link.name,
            size: link.size,
            state: link.state,
            mime_type: link.mime_type,
            create_time: link.create_time,
            modify_time: link.modify_time,
        }
    }

    pub fn is_folder(&self) -> bool {
        self.link_type == LinkType::Folder
    }

    pub fn is_file(&self) -> bool {
        self.link_type == LinkType::File
    }

    pub fn is_active(&self) -> bool {
        self.state == LinkState::Active
    }

    /// Returns the encrypted name until PGP decryption is implemented.
    /// The name is a PGP-armored string; once decryption is wired in this
    /// method will return the plaintext filename.
    pub fn display_name(&self) -> &str {
        &self.encrypted_name
    }
}

// ── DriveClient ────────────────────────────────────────────────────────────

/// High-level client for enumerating the Proton Drive tree.
pub struct DriveClient {
    api: ApiClient,
}

impl DriveClient {
    pub fn new(api: ApiClient) -> Self {
        Self { api }
    }

    /// Find the main (primary) share of the user's default volume.
    ///
    /// Returns `(share_id, root_link_id)`.
    pub async fn find_main_share(&self) -> Result<(String, String)> {
        // Strategy: list volumes and pick the active one, then use its share.
        let volumes = self.api.list_volumes().await?;
        let volume = volumes
            .into_iter()
            .find(|v| v.state == VolumeState::Active)
            .ok_or_else(|| crate::Error::Api {
                code: 0,
                message: "No active volume found".into(),
            })?;

        Ok((volume.share.share_id, volume.share.link_id))
    }

    /// List the immediate children of a folder.
    ///
    /// Fetches all pages automatically.
    pub async fn list_children(
        &self,
        share_id: &str,
        folder_link_id: &str,
    ) -> Result<Vec<DriveNode>> {
        let mut nodes = Vec::new();
        let mut page = 0u32;

        loop {
            let links = self
                .api
                .list_children(share_id, folder_link_id, page, PAGE_SIZE)
                .await?;
            let count = links.len();
            for link in links {
                nodes.push(DriveNode::from_link(share_id, link));
            }
            if count < PAGE_SIZE as usize {
                break;
            }
            page += 1;
        }

        Ok(nodes)
    }

    /// List the root of the user's main share.
    pub async fn list_root(&self) -> Result<Vec<DriveNode>> {
        let (share_id, root_link_id) = self.find_main_share().await?;
        self.list_children(&share_id, &root_link_id).await
    }

    /// Recursively walk the drive tree starting from `folder_link_id`.
    ///
    /// Calls `visitor` for every node encountered (files and folders).
    /// Traversal is depth-first.
    pub async fn walk<F>(
        &self,
        share_id: &str,
        folder_link_id: &str,
        visitor: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&DriveNode),
    {
        let children = self.list_children(share_id, folder_link_id).await?;
        for node in &children {
            visitor(node);
            if node.is_folder() && node.is_active() {
                // SAFETY: recursion depth is bounded by the drive tree depth,
                // which in practice is well under stack limits.
                Box::pin(self.walk(share_id, &node.link_id, visitor)).await?;
            }
        }
        Ok(())
    }

    /// Walk the entire main share and return all nodes.
    pub async fn walk_all(&self) -> Result<Vec<DriveNode>> {
        let (share_id, root_link_id) = self.find_main_share().await?;
        let mut nodes = Vec::new();
        self.walk(&share_id, &root_link_id, &mut |n| nodes.push(n.clone()))
            .await?;
        Ok(nodes)
    }
}
