//! Credentials bootstrap over vsock — with auto-refresh.
//!
//! AWS instance-role STS credentials live on the parent EC2 at IMDS
//! (169.254.169.254). The enclave has no network and no IMDS access.
//! The parent runs a small `imds-bridge` daemon (see
//! `deploy/cloud-init/parent-bootstrap.sh`) that:
//!
//! 1. Reads the instance role STS creds from IMDS.
//! 2. Listens on `vsock://3:9100`.
//! 3. On each `accept` (one per refresh), writes one JSON object
//!    followed by `SHUT_WR`:
//!    ```json
//!    {"access_key_id":"…","secret_access_key":"…",
//!     "session_token":"…","expires_at":"2026-05-19T08:50:54Z",
//!     "admin_token":"…"}
//!    ```
//!
//! ## Refresh model
//!
//! Earlier versions of this module fetched once at boot and treated
//! creds as static — the enclave would crash with `ExpiredToken` ~6h
//! later and systemd restart-on-failure would re-bootstrap. That works
//! but is clumsy and produces a noisy alert window.
//!
//! Now we ship a real `ProvideCredentials` impl (`VsockCredsProvider`)
//! that re-fetches over vsock on demand. The SDK's identity cache,
//! configured with a 1h `buffer_time`, calls us back when cached
//! creds are within 1h of expiry. We round-trip the parent vsock
//! channel, get fresh STS, return them; the SDK swaps them in
//! transparently for any in-flight call.
//!
//! The admin token is also vended by the same JSON blob — we cache
//! the first observed value in a `Mutex<Option<…>>` so the server's
//! boot path can pick it up without doing a second vsock round-trip.

use crate::vsock_transport::{PARENT_CID, PORT_CREDS};
use crate::StorageError;
use aws_credential_types::provider::error::CredentialsError;
use aws_credential_types::provider::future::ProvideCredentials as ProvideCredsFut;
use aws_credential_types::provider::ProvideCredentials;
use aws_credential_types::Credentials;
use aws_smithy_types::date_time::{DateTime, Format};
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::io::AsyncReadExt;
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct CredsJson {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    /// Informational; we don't act on it client-side beyond logging.
    expires_at: Option<String>,
    /// Bearer token the trading lambda uses to auth against the TEE.
    /// Vended together with AWS STS creds so the enclave never needs
    /// the EIGEN_TEE_ADMIN_TOKEN env var (would mean baking the secret
    /// into the EIF, which is PCR-measured and externally inspectable).
    admin_token: Option<String>,
}

pub struct Bootstrap {
    pub credentials: Credentials,
    pub admin_token: Option<String>,
}

/// Connect to the parent's `imds-bridge` on `vsock://3:PORT_CREDS`,
/// read one JSON blob, and return SDK credentials plus the admin
/// bearer token. Both come from the same parent-side daemon so we
/// avoid round-tripping vsock twice at boot.
pub async fn fetch_bootstrap() -> Result<Bootstrap, StorageError> {
    let addr = VsockAddr::new(PARENT_CID, PORT_CREDS);
    let mut stream = VsockStream::connect(addr).await.map_err(|e| {
        StorageError::Aws(format!(
            "vsock connect to creds bridge {PARENT_CID}:{PORT_CREDS}: {e}"
        ))
    })?;

    let mut buf = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| StorageError::Aws(format!("creds vsock read: {e}")))?;

    let creds: CredsJson = serde_json::from_slice(&buf)
        .map_err(|e| StorageError::Aws(format!("creds JSON parse: {e}")))?;

    info!(
        access_key_prefix = &creds.access_key_id[..creds.access_key_id.len().min(8)],
        expires_at = creds.expires_at.as_deref(),
        has_admin_token = creds.admin_token.is_some(),
        "fetched STS creds + admin token from parent vsock"
    );

    // Parse the RFC3339 `expires_at` into a SystemTime so the SDK's
    // identity cache can schedule refreshes. If parsing fails we log
    // and fall back to None (cache treats as static; the enclave will
    // still bootstrap, just without auto-refresh).
    let expires_after = match creds.expires_at.as_deref() {
        Some(s) => match DateTime::from_str(s, Format::DateTime) {
            Ok(dt) => SystemTime::try_from(dt).ok(),
            Err(e) => {
                warn!(?e, "couldn't parse expires_at; SDK refresh disabled");
                None
            }
        },
        None => None,
    };

    Ok(Bootstrap {
        credentials: Credentials::new(
            creds.access_key_id,
            creds.secret_access_key,
            creds.session_token,
            expires_after,
            "polylayer-vsock-bridge",
        ),
        admin_token: creds.admin_token,
    })
}

/// Back-compat: callers that only want creds.
pub async fn fetch_static_credentials() -> Result<Credentials, StorageError> {
    Ok(fetch_bootstrap().await?.credentials)
}

// ─── ProvideCredentials adapter ─────────────────────────────────────

/// State shared between the SDK-driven `ProvideCredentials` callbacks
/// and the boot path that needs the admin bearer token. The admin
/// token only travels alongside creds (same JSON blob), so the boot
/// path watches this cell after kicking off the first refresh.
#[derive(Default)]
pub struct VsockCredsState {
    pub admin_token: Mutex<Option<String>>,
}

/// AWS SDK creds provider that does a vsock round-trip per call.
///
/// The SDK invokes `provide_credentials()` once at first use and then
/// again every time the identity cache's `buffer_time` deadline
/// arrives before the previous creds' `expires_after`. With our 1h
/// buffer that's roughly every 5h for instance-role STS (which live
/// ~6h). Each call hits the parent's imds-bridge fresh.
#[derive(Debug, Clone)]
pub struct VsockCredsProvider {
    state: Arc<VsockCredsState>,
}

impl VsockCredsProvider {
    pub fn new() -> Self {
        Self {
            state: Arc::new(VsockCredsState::default()),
        }
    }

    /// Shared state handle — read `admin_token` after kicking off
    /// the first credentials fetch.
    pub fn state(&self) -> Arc<VsockCredsState> {
        self.state.clone()
    }
}

impl Default for VsockCredsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvideCredentials for VsockCredsProvider {
    fn provide_credentials<'a>(&'a self) -> ProvideCredsFut<'a>
    where
        Self: 'a,
    {
        let state = self.state.clone();
        ProvideCredsFut::new(async move {
            let bootstrap = fetch_bootstrap()
                .await
                .map_err(|e| CredentialsError::provider_error(e.to_string()))?;
            if let Some(t) = bootstrap.admin_token {
                let mut slot = state.admin_token.lock().expect("admin_token mutex");
                if slot.is_none() {
                    *slot = Some(t);
                }
            }
            Ok(bootstrap.credentials)
        })
    }
}
impl std::fmt::Debug for VsockCredsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VsockCredsState")
            .field("admin_token", &"<redacted>")
            .finish()
    }
}
