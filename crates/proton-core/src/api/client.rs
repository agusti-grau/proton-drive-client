use reqwest::{Client, header};

use crate::{Error, Result};
use crate::api::types::*;

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

    // ── Helpers ────────────────────────────────────────────────────────────

    fn require_session(&self) -> Result<&Session> {
        self.session
            .as_ref()
            .ok_or_else(|| Error::Auth("No active session — login first".into()))
    }
}
