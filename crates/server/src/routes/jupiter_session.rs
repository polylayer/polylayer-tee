//! Jupiter perps session + delegate endpoints.
//!
//!   GET  /v1/jupiter/delegate        — derive + return the delegate pubkey
//!   POST /v1/jupiter/session/upsert  — register / replace the session
//!   POST /v1/jupiter/session/get     — read the session row
//!   POST /v1/jupiter/session/revoke  — mark the session revoked
//!
//! The session blob is AES-GCM sealed in DynamoDB via `SessionStore`.
//! One session per user; the DDB key is `jup-v1#<solana_pubkey_bs58>`.
//!
//! `/v1/jupiter/drain` is intentionally NOT here — see the tracker
//! (`docs/internal/TEE_SESSION_PORT.md`, task 2.7): building a drain
//! tx needs a recent blockhash, which needs Solana RPC, which the
//! enclave's vsock-proxy allowlist doesn't currently include.

use axum::extract::{Query, State};
use axum::Json;
use polylayer_tee_core::solana::decode_pubkey;
use polylayer_tee_core::solana_attestor::derive_jupiter_delegate;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{ApiError, ApiResult};
use crate::AppState;

/// Composite DDB key for a user's Jupiter session.
pub fn jup_session_key(solana_pubkey_bs58: &str) -> String {
    format!("jup-v1#{solana_pubkey_bs58}")
}

/// Stored Jupiter session blob. Field names match the lambda's
/// `JupiterSessionRowResponse` so the row deserializes directly on
/// the consumer side; `surface` is extra (TS ignores unknown keys).
#[derive(Serialize, Deserialize, Clone)]
pub struct JupiterSession {
    pub solana_pubkey: String,
    pub delegate_pubkey_b58: String,
    pub per_intent_max_size_usdc_atoms: String,
    pub cumulative_size_usdc_cap: String,
    pub cumulative_size_usdc_used: String,
    pub allowed_assets: Vec<String>,
    pub expires_at_unix_ts: u64,
    pub created_at_unix_ts: u64,
    pub revoked: bool,
    #[serde(default)]
    pub surface: String,
}

fn now_unix() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| ApiError::internal(format!("clock: {e}")))
}

/// Which session bound a trade violated. Returned by
/// `check_session_bounds`; the sign handler maps each to an `ApiError`.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionBoundError {
    Revoked,
    Expired,
    AssetNotAllowed,
    PerIntentExceeded,
    CumulativeExceeded,
    /// A numeric session field failed to parse — names the field.
    Parse(&'static str),
}

/// Pure session-bound check for a Jupiter trade.
///
/// `trade_size_usd` and the session's `*_usdc_atoms` fields are both
/// 6-decimal USD (verified against the Jupiter IDL: `sizeUsdDelta`
/// `10_000_000` == $10; USDC is also 6-decimal). Apples-to-apples.
///
/// On success returns the NEW cumulative-used value — the caller
/// persists it back to the session. Extracted out of the sign handler
/// so the bound logic is unit-testable without DDB or axum.
pub fn check_session_bounds(
    session: &JupiterSession,
    asset_label: &str,
    trade_size_usd: u64,
    now_unix_secs: u64,
) -> Result<u128, SessionBoundError> {
    if session.revoked {
        return Err(SessionBoundError::Revoked);
    }
    if session.expires_at_unix_ts < now_unix_secs {
        return Err(SessionBoundError::Expired);
    }
    if !session
        .allowed_assets
        .iter()
        .any(|a| a.as_str() == asset_label)
    {
        return Err(SessionBoundError::AssetNotAllowed);
    }
    let per_intent_max: u128 = session
        .per_intent_max_size_usdc_atoms
        .parse()
        .map_err(|_| SessionBoundError::Parse("per_intent_max_size_usdc_atoms"))?;
    if u128::from(trade_size_usd) > per_intent_max {
        return Err(SessionBoundError::PerIntentExceeded);
    }
    let cap: u128 = session
        .cumulative_size_usdc_cap
        .parse()
        .map_err(|_| SessionBoundError::Parse("cumulative_size_usdc_cap"))?;
    let used: u128 = session
        .cumulative_size_usdc_used
        .parse()
        .map_err(|_| SessionBoundError::Parse("cumulative_size_usdc_used"))?;
    let new_used = used + u128::from(trade_size_usd);
    if new_used > cap {
        return Err(SessionBoundError::CumulativeExceeded);
    }
    Ok(new_used)
}

// ─── GET /v1/jupiter/delegate ────────────────────────────────────────

#[derive(Deserialize)]
pub struct DelegateQuery {
    pub solana: String,
}

pub async fn delegate(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DelegateQuery>,
) -> ApiResult<Json<Value>> {
    let pk = decode_pubkey(&q.solana)
        .map_err(|e| ApiError::bad_request("invalid_solana_pubkey", e.to_string()))?;
    let delegate = derive_jupiter_delegate(&state.master, &pk)
        .map_err(|e| ApiError::internal(format!("delegate_derive: {e}")))?;
    Ok(Json(json!({
        "solana_pubkey": q.solana,
        "delegate_pubkey_b58": delegate.public_key_bs58(),
        "derivation_version": "jupiter-delegate-v1",
    })))
}

// ─── POST /v1/jupiter/session/get ────────────────────────────────────

#[derive(Deserialize)]
pub struct PubkeyBody {
    pub solana_pubkey: String,
}

pub async fn session_get(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PubkeyBody>,
) -> ApiResult<Json<Value>> {
    let store = state.sessions()?;
    let row: Option<JupiterSession> = store
        .get(&jup_session_key(&req.solana_pubkey))
        .await
        .map_err(|e| ApiError::internal(format!("session get: {e}")))?;
    Ok(Json(json!({ "row": row })))
}

// ─── POST /v1/jupiter/session/upsert ─────────────────────────────────

#[derive(Deserialize)]
pub struct UpsertBody {
    pub solana_pubkey: String,
    pub per_intent_max_size_usdc_atoms: String,
    pub cumulative_size_usdc_cap: String,
    pub allowed_assets: Vec<String>,
    pub expires_at_unix_ts: u64,
    #[serde(default)]
    pub surface: Option<String>,
}

pub async fn session_upsert(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpsertBody>,
) -> ApiResult<Json<Value>> {
    let store = state.sessions()?;
    let pk = decode_pubkey(&req.solana_pubkey)
        .map_err(|e| ApiError::bad_request("invalid_solana_pubkey", e.to_string()))?;
    let delegate = derive_jupiter_delegate(&state.master, &pk)
        .map_err(|e| ApiError::internal(format!("delegate_derive: {e}")))?;
    let now = now_unix()?;
    let key = jup_session_key(&req.solana_pubkey);

    // Preserve the cumulative-used counter + created_at across an
    // upsert — re-registering a session must not reset the spend.
    let prior: Option<JupiterSession> = store
        .get(&key)
        .await
        .map_err(|e| ApiError::internal(format!("session get: {e}")))?;
    let cumulative_used = prior
        .as_ref()
        .map(|p| p.cumulative_size_usdc_used.clone())
        .unwrap_or_else(|| "0".to_string());
    let created_at = prior.as_ref().map(|p| p.created_at_unix_ts).unwrap_or(now);

    let session = JupiterSession {
        solana_pubkey: req.solana_pubkey.clone(),
        delegate_pubkey_b58: delegate.public_key_bs58(),
        per_intent_max_size_usdc_atoms: req.per_intent_max_size_usdc_atoms,
        cumulative_size_usdc_cap: req.cumulative_size_usdc_cap,
        cumulative_size_usdc_used: cumulative_used,
        allowed_assets: req.allowed_assets,
        expires_at_unix_ts: req.expires_at_unix_ts,
        created_at_unix_ts: created_at,
        revoked: false,
        surface: req.surface.unwrap_or_else(|| "browser".to_string()),
    };
    store
        .put(&key, &session, Some(req.expires_at_unix_ts))
        .await
        .map_err(|e| ApiError::internal(format!("session put: {e}")))?;
    Ok(Json(
        serde_json::to_value(&session).expect("JupiterSession serializes"),
    ))
}

// ─── POST /v1/jupiter/session/revoke ─────────────────────────────────

pub async fn session_revoke(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PubkeyBody>,
) -> ApiResult<Json<Value>> {
    let store = state.sessions()?;
    let key = jup_session_key(&req.solana_pubkey);
    let row: Option<JupiterSession> = store
        .get(&key)
        .await
        .map_err(|e| ApiError::internal(format!("session get: {e}")))?;
    match row {
        Some(mut s) => {
            s.revoked = true;
            store
                .put(&key, &s, Some(s.expires_at_unix_ts))
                .await
                .map_err(|e| ApiError::internal(format!("session put: {e}")))?;
            Ok(Json(json!({ "row": s })))
        }
        None => Ok(Json(json!({ "row": null }))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Base session: $10 per-intent max, $100 cumulative cap, SOL+BTC
    /// allowed, expires far in the future. All amounts 6-decimal USD.
    fn base_session() -> JupiterSession {
        JupiterSession {
            solana_pubkey: "Hpubkey".into(),
            delegate_pubkey_b58: "Dpubkey".into(),
            per_intent_max_size_usdc_atoms: "10000000".into(),
            cumulative_size_usdc_cap: "100000000".into(),
            cumulative_size_usdc_used: "0".into(),
            allowed_assets: vec!["SOL".into(), "BTC".into()],
            expires_at_unix_ts: 2_000_000_000,
            created_at_unix_ts: 1_000_000_000,
            revoked: false,
            surface: "browser".into(),
        }
    }

    const NOW: u64 = 1_500_000_000; // between created_at and expires_at

    #[test]
    fn within_bounds_returns_new_cumulative() {
        // $5 trade: under the $10 per-intent and the $100 cap.
        let r = check_session_bounds(&base_session(), "SOL", 5_000_000, NOW);
        assert_eq!(r, Ok(5_000_000));
    }

    #[test]
    fn per_intent_cap_rejects() {
        // $15 > $10 per-intent max.
        let r = check_session_bounds(&base_session(), "SOL", 15_000_000, NOW);
        assert_eq!(r, Err(SessionBoundError::PerIntentExceeded));
    }

    #[test]
    fn cumulative_cap_rejects() {
        let mut s = base_session();
        s.cumulative_size_usdc_used = "98000000".into(); // $98 already used
        // $5 more would be $103 > $100 cap.
        let r = check_session_bounds(&s, "SOL", 5_000_000, NOW);
        assert_eq!(r, Err(SessionBoundError::CumulativeExceeded));
    }

    #[test]
    fn cumulative_exact_cap_is_allowed() {
        let mut s = base_session();
        s.cumulative_size_usdc_used = "95000000".into(); // $95 used
        // $5 → exactly $100. Only strictly-over rejects.
        let r = check_session_bounds(&s, "BTC", 5_000_000, NOW);
        assert_eq!(r, Ok(100_000_000));
    }

    #[test]
    fn expired_session_rejects() {
        // now is one second past expiry.
        let r = check_session_bounds(&base_session(), "SOL", 1_000_000, 2_000_000_001);
        assert_eq!(r, Err(SessionBoundError::Expired));
    }

    #[test]
    fn revoked_session_rejects() {
        let mut s = base_session();
        s.revoked = true;
        let r = check_session_bounds(&s, "SOL", 1_000_000, NOW);
        assert_eq!(r, Err(SessionBoundError::Revoked));
    }

    #[test]
    fn disallowed_asset_rejects() {
        // ETH is not in allowed_assets.
        let r = check_session_bounds(&base_session(), "ETH", 1_000_000, NOW);
        assert_eq!(r, Err(SessionBoundError::AssetNotAllowed));
    }

    #[test]
    fn revoked_takes_precedence_over_size() {
        // A revoked session rejects even an in-bounds trade.
        let mut s = base_session();
        s.revoked = true;
        let r = check_session_bounds(&s, "SOL", 1_000_000, NOW);
        assert_eq!(r, Err(SessionBoundError::Revoked));
    }
}
