//! Polyleverage zero-click session + delegate endpoints.
//!
//!   GET  /v1/polyleverage/delegate        — derive + return delegate pubkey
//!   POST /v1/polyleverage/session/get     — read the session row
//!   POST /v1/polyleverage/session/upsert  — mirror an on-chain session
//!   POST /v1/polyleverage/session/revoke  — mark the session revoked
//!
//! The delegate is TEE-derived (HKDF, `polylayer-session-delegate-v1`
//! salt) — same model as Jupiter, unlike HL. One session per user;
//! the DDB key is `plv-v1#<solana_pubkey_bs58>`.
//!
//! `upsert` mirrors an already-confirmed on-chain `CreateSession`: the
//! lambda passes the bounds it read from chain, the TEE stores them
//! and re-checks against this row before signing polyleverage
//! actions. The TEE re-derives the delegate itself rather than
//! trusting the caller-supplied pubkey.

use axum::extract::{Query, State};
use axum::Json;
use polylayer_tee_core::solana::decode_pubkey;
use polylayer_tee_core::solana_attestor::derive_session_delegate;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{ApiError, ApiResult};
use crate::AppState;

/// Composite DDB key for a user's polyleverage session.
pub fn plv_session_key(solana_pubkey_bs58: &str) -> String {
    format!("plv-v1#{solana_pubkey_bs58}")
}

/// Stored polyleverage session blob. Field names match the lambda's
/// `PolyleverageSessionRowResponse`.
#[derive(Serialize, Deserialize, Clone)]
pub struct PolyleverageSession {
    pub solana_pubkey: String,
    pub delegate_pubkey_b58: String,
    pub expires_at_slot: String,
    pub per_intent_max_collateral_atoms: String,
    pub cumulative_collateral_used: String,
    pub cumulative_collateral_cap: String,
    pub allowed_instruments: Vec<String>,
    pub created_at_unix_ts: u64,
    pub revoked: bool,
    pub on_chain_version_seen: String,
}

fn now_unix() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| ApiError::internal(format!("clock: {e}")))
}

// ─── GET /v1/polyleverage/delegate ───────────────────────────────────

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
    let delegate = derive_session_delegate(&state.master, &pk)
        .map_err(|e| ApiError::internal(format!("delegate_derive: {e}")))?;
    Ok(Json(json!({
        "solana_pubkey": q.solana,
        "delegate_pubkey_b58": delegate.public_key_bs58(),
        "derivation_version": "polylayer-session-delegate-v1",
    })))
}

// ─── POST /v1/polyleverage/session/get ───────────────────────────────

#[derive(Deserialize)]
pub struct PubkeyBody {
    pub solana_pubkey: String,
}

pub async fn session_get(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PubkeyBody>,
) -> ApiResult<Json<Value>> {
    let store = state.sessions()?;
    let row: Option<PolyleverageSession> = store
        .get(&plv_session_key(&req.solana_pubkey))
        .await
        .map_err(|e| ApiError::internal(format!("session get: {e}")))?;
    Ok(Json(json!({ "row": row })))
}

// ─── POST /v1/polyleverage/session/upsert ────────────────────────────

#[derive(Deserialize)]
pub struct UpsertBody {
    pub solana_pubkey: String,
    pub expires_at_slot: String,
    pub per_intent_max_collateral_atoms: String,
    pub cumulative_collateral_cap: String,
    pub allowed_instruments: Vec<String>,
    #[serde(default)]
    pub cumulative_collateral_used: Option<String>,
    #[serde(default)]
    pub revoked: Option<bool>,
    #[serde(default)]
    pub on_chain_version_seen: Option<String>,
}

pub async fn session_upsert(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpsertBody>,
) -> ApiResult<Json<Value>> {
    let store = state.sessions()?;
    let pk = decode_pubkey(&req.solana_pubkey)
        .map_err(|e| ApiError::bad_request("invalid_solana_pubkey", e.to_string()))?;
    // Re-derive the delegate ourselves — never trust a caller-supplied
    // delegate pubkey for the stored row.
    let delegate = derive_session_delegate(&state.master, &pk)
        .map_err(|e| ApiError::internal(format!("delegate_derive: {e}")))?;
    let now = now_unix()?;
    let key = plv_session_key(&req.solana_pubkey);

    // Preserve cumulative-used + created_at across an upsert unless the
    // caller explicitly passes a new cumulative value (the lambda may
    // do so when re-mirroring on-chain state).
    let prior: Option<PolyleverageSession> = store
        .get(&key)
        .await
        .map_err(|e| ApiError::internal(format!("session get: {e}")))?;
    let cumulative_used = req
        .cumulative_collateral_used
        .or_else(|| prior.as_ref().map(|p| p.cumulative_collateral_used.clone()))
        .unwrap_or_else(|| "0".to_string());
    let created_at = prior.as_ref().map(|p| p.created_at_unix_ts).unwrap_or(now);

    let session = PolyleverageSession {
        solana_pubkey: req.solana_pubkey.clone(),
        delegate_pubkey_b58: delegate.public_key_bs58(),
        expires_at_slot: req.expires_at_slot,
        per_intent_max_collateral_atoms: req.per_intent_max_collateral_atoms,
        cumulative_collateral_used: cumulative_used,
        cumulative_collateral_cap: req.cumulative_collateral_cap,
        allowed_instruments: req.allowed_instruments,
        created_at_unix_ts: created_at,
        revoked: req.revoked.unwrap_or(false),
        on_chain_version_seen: req.on_chain_version_seen.unwrap_or_default(),
    };
    // Slot-based expiry — no DDB TTL (TTL is unix-seconds, not slots).
    store
        .put(&key, &session, None)
        .await
        .map_err(|e| ApiError::internal(format!("session put: {e}")))?;
    Ok(Json(
        serde_json::to_value(&session).expect("PolyleverageSession serializes"),
    ))
}

// ─── POST /v1/polyleverage/session/revoke ────────────────────────────

pub async fn session_revoke(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PubkeyBody>,
) -> ApiResult<Json<Value>> {
    let store = state.sessions()?;
    let key = plv_session_key(&req.solana_pubkey);
    let row: Option<PolyleverageSession> = store
        .get(&key)
        .await
        .map_err(|e| ApiError::internal(format!("session get: {e}")))?;
    match row {
        Some(mut s) => {
            s.revoked = true;
            store
                .put(&key, &s, None)
                .await
                .map_err(|e| ApiError::internal(format!("session put: {e}")))?;
            Ok(Json(json!({ "row": s })))
        }
        None => Ok(Json(json!({ "row": null }))),
    }
}
