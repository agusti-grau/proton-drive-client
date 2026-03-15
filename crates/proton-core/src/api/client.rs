use reqwest::{Client, header};

use crate::{Error, Result};
use crate::api::types::*;
use crate::api::drive_types::*;

/// Proton API base URL.
const BASE_URL: &str = "https://mail.proton.me/api";

/// Value sent in the `x-pm-appversion` header.
/// Must match a version Proton's server accepts; use a known-good value.
const APP_VERSION: &str = "Other/0.1.0";

pub struct ApiClient {
    client: Client,
    session: Option<Session>,
}

impl ApiClient {
    /// Build a new client with default Proton headers.
    pub fn new() -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "x-pm-appversion",
            header::HeaderValue::from_static(APP_VERSION),
        );
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/vnd.protonmail.v1+json"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .https_only(true)
            .build()?;

        Ok(Self { client, session: None })
    }

    /// Attach an existing session (used after login or token refresh).
    pub fn with_session(mut self, session: Session) -> Self {
        self.session = Some(session);
        self
    }

    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    // ── Auth endpoints ─────────────────────────────────────────────────────

    /// `POST /auth/v4/info` — fetch SRP parameters for the given username.
    pub async fn get_auth_info(&self, username: &str) -> Result<AuthInfoResponse> {
        let body = serde_json::json!({ "Username": username });
        let text = self
            .client
            .post(format!("{BASE_URL}/auth/v4/info"))
            .json(&body)
            .send()
            .await?
            .text()
            .await?;

        let parsed: AuthInfoResponse = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed)
    }

    /// `POST /auth/v4` — submit SRP proof and receive session tokens.
    pub async fn authenticate(&self, req: &AuthRequest) -> Result<AuthResponse> {
        let text = self
            .client
            .post(format!("{BASE_URL}/auth/v4"))
            .json(req)
            .send()
            .await?
            .text()
            .await?;

        let parsed: AuthResponse = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed)
    }

    /// `POST /auth/v4/2fa` — submit a TOTP code after the main auth step.
    pub async fn submit_2fa(&self, code: &str) -> Result<()> {
        let session = self.require_session()?;
        let req = TwoFactorRequest { code: code.to_string() };

        let text = self
            .client
            .post(format!("{BASE_URL}/auth/v4/2fa"))
            .header(header::AUTHORIZATION, format!("Bearer {}", session.access_token))
            .header("x-pm-uid", &session.uid)
            .json(&req)
            .send()
            .await?
            .text()
            .await?;

        let v: serde_json::Value = serde_json::from_str(&text)?;
        let api_code = v["Code"].as_i64().unwrap_or(0) as i32;
        if api_code != 1000 {
            return Err(Error::Api { code: api_code, message: text });
        }
        Ok(())
    }

    /// `POST /auth/v4/refresh` — exchange a refresh token for a new access token.
    pub async fn refresh_token(&self) -> Result<AuthResponse> {
        let session = self.require_session()?;
        let req = RefreshRequest {
            uid: session.uid.clone(),
            refresh_token: session.refresh_token.clone(),
            grant_type: "refresh_token".to_string(),
            redirect_uri: "https://proton.me".to_string(),
            response_type: "token".to_string(),
        };

        let text = self
            .client
            .post(format!("{BASE_URL}/auth/v4/refresh"))
            .header("x-pm-uid", &session.uid)
            .json(&req)
            .send()
            .await?
            .text()
            .await?;

        let parsed: AuthResponse = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed)
    }

    /// `DELETE /auth/v4` — revoke the current session on the server.
    pub async fn logout(&self) -> Result<()> {
        let session = self.require_session()?;
        self.client
            .delete(format!("{BASE_URL}/auth/v4"))
            .header(header::AUTHORIZATION, format!("Bearer {}", session.access_token))
            .header("x-pm-uid", &session.uid)
            .send()
            .await?;
        Ok(())
    }

    // ── Drive endpoints ────────────────────────────────────────────────────

    /// `GET /drive/volumes` — list all volumes for the authenticated user.
    pub async fn list_volumes(&self) -> Result<Vec<Volume>> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, volumes: Vec<Volume> }

        let text = self.authed_get("/drive/volumes").await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.volumes)
    }

    /// `GET /drive/shares` — list all shares visible to the user.
    pub async fn list_shares(&self) -> Result<Vec<ShareMetadata>> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, shares: Vec<ShareMetadata> }

        let text = self.authed_get("/drive/shares?ShowAll=1").await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.shares)
    }

    /// `GET /drive/shares/{id}` — fetch full share details (including keys).
    pub async fn get_share(&self, share_id: &str) -> Result<Share> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, share: Share }

        let text = self.authed_get(&format!("/drive/shares/{share_id}")).await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.share)
    }

    /// `GET /drive/shares/{shareID}/links/{linkID}` — fetch a single link.
    pub async fn get_link(&self, share_id: &str, link_id: &str) -> Result<Link> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, link: Link }

        let text = self
            .authed_get(&format!("/drive/shares/{share_id}/links/{link_id}"))
            .await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.link)
    }

    /// `GET /drive/shares/{shareID}/folders/{linkID}/children` — list folder children.
    ///
    /// Returns one page (up to `page_size` links).  Call repeatedly with
    /// increasing `page` (0-indexed) until fewer than `page_size` links are
    /// returned.
    pub async fn list_children(
        &self,
        share_id: &str,
        folder_link_id: &str,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<Link>> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Resp { code: i32, links: Vec<Link> }

        let url = format!(
            "/drive/shares/{share_id}/folders/{folder_link_id}/children\
             ?Page={page}&PageSize={page_size}&ShowAll=1"
        );
        let text = self.authed_get(&url).await?;
        let parsed: Resp = serde_json::from_str(&text)?;
        if parsed.code != 1000 {
            return Err(Error::Api { code: parsed.code, message: text });
        }
        Ok(parsed.links)
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    /// Perform an authenticated GET to a path under `BASE_URL`.
    async fn authed_get(&self, path: &str) -> Result<String> {
        let session = self.require_session()?;
        let text = self
            .client
            .get(format!("{BASE_URL}{path}"))
            .header(header::AUTHORIZATION, format!("Bearer {}", session.access_token))
            .header("x-pm-uid", &session.uid)
            .send()
            .await?
            .text()
            .await?;
        Ok(text)
    }

    fn require_session(&self) -> Result<&Session> {
        self.session
            .as_ref()
            .ok_or_else(|| Error::Auth("No active session — login first".into()))
    }
}
