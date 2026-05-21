//! Polylayer TEE — HTTP server entry point.
//!
//! Mirrors the eigen-tee surface route-for-route, with the actual
//! signing logic delegated to `polylayer-tee-core`. The master mnemonic
//! is loaded via `storage::bootstrap` (KMS-sealed S3 blob, decrypted
//! with attestation) when running inside a Nitro enclave. For local
//! dev, set `MNEMONIC` directly and unset the `POLYLAYER_TEE_*` storage
//! env vars — the bootstrap then falls back to the env value.

use anyhow::{Context, Result};
use axum::routing::{get, post};
use axum::Router;
use polylayer_tee_core::derive::Master;
use polylayer_tee_core::solana_attestor::{derive_solana_attestor_keypair, SolanaAttestorKeypair};
use polylayer_tee_storage::{SessionStore, Storage};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};
use zeroize::Zeroize;

mod auth;
mod error;
mod routes;

/// Shared app state — the master, the Solana attestor, and runtime config.
pub struct AppState {
    pub master: Arc<Master>,
    pub solana_attestor: Arc<SolanaAttestorKeypair>,
    /// Bearer token gating every non-public route. Loaded from
    /// `EIGEN_TEE_ADMIN_TOKEN` at boot.
    pub admin_token: Arc<String>,
    /// Encrypted per-user session store (DynamoDB-backed). `None` on
    /// the local-dev path, which has no storage backend — session
    /// routes return 503 there.
    pub sessions: Option<Arc<SessionStore>>,
}

impl AppState {
    /// Borrow the session store, or a clean 503 if it isn't
    /// configured (local-dev runs without a DynamoDB backend).
    pub fn sessions(&self) -> Result<&SessionStore, error::ApiError> {
        self.sessions.as_deref().ok_or_else(|| {
            error::ApiError::unavailable(
                "sessions_unavailable",
                "session store not configured — production enclave only",
            )
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,polylayer_tee_server=debug".into()),
        )
        .with_target(false)
        .json()
        .init();

    // Nitro enclaves boot with no init system, so the loopback
    // interface (`lo`) starts DOWN — TCP connects to 127.0.0.1
    // return ENETUNREACH. We need it UP before our localhost-to-vsock
    // bridges can be reached. `ip` is from the `iproute2` package
    // installed in Dockerfile.enclave.
    if std::env::var("POLYLAYER_TEE_USE_VSOCK").is_ok() {
        match std::process::Command::new("ip")
            .args(["link", "set", "dev", "lo", "up"])
            .status()
        {
            Ok(s) if s.success() => info!("brought up lo interface"),
            Ok(s) => warn!(?s, "ip link set lo up exited non-zero"),
            Err(e) => warn!(?e, "could not run ip link set lo up"),
        }
    }

    // Bake-in /etc/hosts at startup. Docker zeroes this file in the
    // image layer at build time (it's a "magic" path it manages via
    // bind-mount at `docker run`), so a COPY in the Dockerfile produces
    // a 0-byte file. Inside a Nitro enclave there's no Docker runtime
    // — the rootfs is plain initrd — so we can just write it ourselves
    // before glibc's resolver sees its first hostname lookup.
    if std::env::var("POLYLAYER_TEE_USE_VSOCK").is_ok() {
        let hosts = "127.0.0.1\tlocalhost\n\
                     127.0.0.1\tkms.eu-central-1.amazonaws.com\n\
                     127.0.0.1\ts3.eu-central-1.amazonaws.com\n\
                     127.0.0.1\tdynamodb.eu-central-1.amazonaws.com\n\
                     ::1\tlocalhost\n";
        if let Err(e) = std::fs::write("/etc/hosts", hosts) {
            warn!(?e, "could not write /etc/hosts — AWS hostname resolution may fail");
        } else {
            info!("wrote /etc/hosts with enclave AWS endpoint mappings");
        }
    }

    let (mut mnemonic, bootstrap_admin_token, storage_opt) = load_master_secrets().await?;
    let master = Arc::new(Master::from_mnemonic(mnemonic.trim()).context("master mnemonic")?);
    mnemonic.zeroize();
    let solana_attestor =
        Arc::new(derive_solana_attestor_keypair(&master).context("solana attestor")?);

    // Build the encrypted session store from the surviving storage
    // stack. The session DEK is HKDF-derived from the master seed, so
    // it's stable across enclave restarts. `None` on the local-dev
    // path (no DynamoDB) — session routes 503 there.
    let sessions = storage_opt.map(|storage| {
        Arc::new(SessionStore::new(storage.ddb, master.session_dek()))
    });

    // Admin token precedence: parent-vended (production enclave) →
    // EIGEN_TEE_ADMIN_TOKEN env (local dev / legacy).
    let admin_token = Arc::new(
        bootstrap_admin_token
            .or_else(|| std::env::var("EIGEN_TEE_ADMIN_TOKEN").ok())
            .context(
                "admin bearer token is required — vend via the parent's imds-bridge \
                 in production, or set EIGEN_TEE_ADMIN_TOKEN for local dev",
            )?,
    );

    let state = Arc::new(AppState {
        master,
        solana_attestor,
        admin_token,
        sessions,
    });

    let app = build_router(state.clone());

    // Listener selection: `POLYLAYER_TEE_LISTEN=vsock` (the production
    // enclave path) listens on vsock CID_ANY:8080 so the parent's
    // socat bridge can forward TCP requests in. Anything else falls
    // back to TCP, which is what local-dev `cargo run` wants.
    match std::env::var("POLYLAYER_TEE_LISTEN").as_deref() {
        Ok("vsock") => serve_vsock(app).await,
        _ => serve_tcp(app).await,
    }
}

async fn serve_tcp(app: Router) -> Result<()> {
    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()
        .context("BIND_ADDR")?;
    info!(%addr, "polylayer-tee-server starting (tcp)");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_vsock(app: Router) -> Result<()> {
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
    let port: u32 = std::env::var("POLYLAYER_TEE_VSOCK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let addr = VsockAddr::new(VMADDR_CID_ANY, port);
    info!(?addr, "polylayer-tee-server starting (vsock)");
    let listener = VsockListener::bind(addr).context("vsock bind")?;

    // axum::serve only accepts a TcpListener. For vsock we drive
    // hyper-util directly, converting the axum Router into a hyper
    // service per connection. The Router itself is `Clone + Send +
    // Sync` and implements `Service<Request<Body>, Error = Infallible>`.
    loop {
        let (stream, peer) = listener.accept().await.context("vsock accept")?;
        let app = app.clone();
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = hyper_util::service::TowerToHyperService::new(app);
            let builder = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            );
            if let Err(e) = builder.serve_connection(io, service).await {
                tracing::debug!(?e, ?peer, "vsock connection closed");
            }
        });
    }
}

/// Source the master BIP-39 mnemonic AND the admin token. Both come
/// from the same boot path so we only init AWS clients / open the
/// vsock channel once:
///
/// 1. If `POLYLAYER_TEE_MNEMONIC_BUCKET` is set we're running inside
///    (or impersonating) a Nitro enclave with a real storage stack —
///    `Storage::from_env()` opens the vsock-tunneled SDK, fetches
///    creds + admin token from the parent's imds-bridge, then we
///    fetch the sealed mnemonic via KMS+S3. First-ever boot
///    generates a fresh mnemonic and seals it (one-time bootstrap).
/// 2. Otherwise (`MNEMONIC` is set, no storage vars) it's a local
///    dev run — use the env value directly and leave admin_token =
///    None so the caller falls back to EIGEN_TEE_ADMIN_TOKEN env.
async fn load_master_secrets() -> Result<(String, Option<String>, Option<Storage>)> {
    if std::env::var("POLYLAYER_TEE_MNEMONIC_BUCKET").is_ok() {
        info!("storage backend configured → loading sealed mnemonic from KMS+S3");
        let storage = Storage::from_env()
            .await
            .context("storage bootstrap: failed to init AWS clients")?;
        let admin_token = storage.admin_token.clone();
        let secrets = storage
            .load_or_create_mnemonic()
            .await
            .context("storage bootstrap: load_or_create_mnemonic")?;
        // Keep `storage` alive past bootstrap — its `ddb` client backs
        // the per-user session store.
        return Ok((secrets.mnemonic, admin_token, Some(storage)));
    }

    warn!(
        "POLYLAYER_TEE_MNEMONIC_BUCKET not set → using MNEMONIC env. \
         This is the local-dev path; production must run inside a Nitro \
         enclave with the storage stack configured."
    );
    let mnemonic = std::env::var("MNEMONIC").context(
        "MNEMONIC env var is required for local-dev runs. \
         In production set POLYLAYER_TEE_MNEMONIC_BUCKET (+ KMS_KEY_ID, etc.) \
         to use the sealed S3 blob path.",
    )?;
    Ok((mnemonic, None, None))
}

fn build_router(state: Arc<AppState>) -> Router {
    // Single router with both authenticated and unauthenticated routes.
    // `healthz` is the only public route — the auth layer is scoped to
    // the inner authenticated sub-router via `merge`.
    let authed = Router::new()
        .route("/v1/attestation", get(routes::health::attestation))
        .route("/v1/derive", get(routes::derive::derive))
        .route("/v1/sign/link-message", post(routes::sign_link_message::handler))
        .route(
            "/v1/sign/polymarket-order",
            post(routes::sign_polymarket_order::handler),
        )
        .route(
            "/v1/sign/clob-l2-headers",
            post(routes::sign_clob_l2_headers::handler),
        )
        .route(
            "/v1/sign/hl-bridge-permit",
            post(routes::sign_hl_bridge_permit::handler),
        )
        .route(
            "/v1/sign/hyperliquid-order",
            post(routes::sign_hyperliquid_order::handler),
        )
        .route(
            "/v1/sign/solana-resolution",
            post(routes::sign_solana_resolution::handler),
        )
        .route(
            "/v1/sign/solana-liquidation",
            post(routes::sign_solana_liquidation::handler),
        )
        .route(
            "/v1/sign/solana-price-twap",
            post(routes::sign_solana_price_twap::handler),
        )
        // Routes pending core port — return 501 with a tracked-task message:
        .route(
            "/v1/sign/jupiter-tx",
            post(routes::sign_jupiter_tx::handler),
        )
        .route(
            "/v1/jupiter/delegate",
            get(routes::jupiter_session::delegate),
        )
        .route(
            "/v1/jupiter/session/get",
            post(routes::jupiter_session::session_get),
        )
        .route(
            "/v1/jupiter/session/upsert",
            post(routes::jupiter_session::session_upsert),
        )
        .route(
            "/v1/jupiter/session/revoke",
            post(routes::jupiter_session::session_revoke),
        )
        .route(
            "/v1/hl-session/create",
            post(routes::hl_session::create),
        )
        .route(
            "/v1/hl-session/revoke",
            post(routes::hl_session::revoke),
        )
        .route("/v1/hl-session/get", get(routes::hl_session::get))
        .route("/v1/hl-session/list", get(routes::hl_session::list))
        .route(
            "/v1/polyleverage/delegate",
            get(routes::polyleverage_session::delegate),
        )
        .route(
            "/v1/polyleverage/session/get",
            post(routes::polyleverage_session::session_get),
        )
        .route(
            "/v1/polyleverage/session/upsert",
            post(routes::polyleverage_session::session_upsert),
        )
        .route(
            "/v1/polyleverage/session/revoke",
            post(routes::polyleverage_session::session_revoke),
        )
        .route(
            "/v1/session/create",
            post(routes::generic_session::create),
        )
        .route(
            "/v1/session/revoke",
            post(routes::generic_session::revoke),
        )
        .route("/v1/session/list", get(routes::generic_session::list))
        .route(
            "/v1/sign/evm-tx",
            post(routes::sign_evm_tx::handler),
        )
        .route(
            "/v1/sign/polymarket-wallet-batch",
            post(routes::sign_polymarket_wallet_batch::handler),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin,
        ));

    Router::new()
        .route("/healthz", get(routes::health::healthz))
        .merge(authed)
        .with_state(state)
}
