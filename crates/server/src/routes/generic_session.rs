//! Generic (Polymarket CLOB) zero-click session endpoints.
//!
//!   POST /v1/session/create  — store an intent-signed session
//!   POST /v1/session/revoke  — mark a session revoked
//!   GET  /v1/session/list    — list a user's sessions
//!
//! Same multi-session-per-user shape as HL: session rows keyed
//! `gen-v1#<session_id>`, a per-user index `gen-idx-v1#<bs58>`. The
//! delegate keypair is browser-generated; the TEE only stores the
//! intent-signed config.
//!
//! NOTE: `api_key` minting for surface ∈ {api, both} is NOT done here
//! — it's the `/v1/clob-creds-private` feature (tracker Phase 5.7+).
//! `create` returns `{ session_id, status }` with no `api_key`, and
//! `has_api_key` is always false. Browser-surface sessions are fully
//! functional; the programmatic bearer-token surface waits on the
//! CLOB-creds work.

use axum::extract::{Query, State};
use axum::Json;
use polylayer_tee_core::intents::{verify_intent_signature, IntentVerifyArgs};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{ApiError, ApiResult};
use crate::AppState;

fn session_key(session_id: &str) -> String {
    format!("gen-v1#{session_id}")
}

fn index_key(solana_pubkey_bs58: &str) -> String {
    format!("gen-idx-v1#{solana_pubkey_bs58}")
}

/// Stored Polymarket session blob.
#[derive(Serialize, Deserialize, Clone)]
pub struct GenericSession {
    pub session_id: String,
    pub solana_pubkey: String,
    pub surface: String,
    pub whitelist_mode: String,
    pub whitelist_ids: Vec<String>,
    pub max_total_usdc: String,
    pub max_order_size_usdc: String,
    pub max_price: String,
    pub min_price: String,
    pub delegate_pubkey: Option<String>,
    pub expiry: u64,
    pub total_usdc_filled: String,
    pub created_at: u64,
    pub revoked: bool,
}

#[derive(Serialize, Deserialize, Default)]
struct GenericSessionIndex {
    session_ids: Vec<String>,
}

fn now_unix() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| ApiError::internal(format!("clock: {e}")))
}

fn req_str(intent: &Value, field: &'static str) -> Result<String, ApiError> {
    intent
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ApiError::bad_request("intent_missing", field))
}

/// The `SessionListRow` shape the lambda expects. Built explicitly
/// (rather than serializing `GenericSession`) so `has_api_key` is
/// surfaced and no internal field leaks.
fn list_row(s: &GenericSession) -> Value {
    json!({
        "session_id": s.session_id,
        "surface": s.surface,
        "whitelist_mode": s.whitelist_mode,
        "whitelist_ids": s.whitelist_ids,
        "max_total_usdc": s.max_total_usdc,
        "max_order_size_usdc": s.max_order_size_usdc,
        "max_price": s.max_price,
        "min_price": s.min_price,
        "delegate_pubkey": s.delegate_pubkey,
        "expiry": s.expiry,
        "total_usdc_filled": s.total_usdc_filled,
        "created_at": s.created_at,
        "revoked": s.revoked,
        "has_api_key": false,
    })
}

// ─── POST /v1/session/create ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct IntentBody {
    pub intent: Value,
    pub intent_sig: String,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IntentBody>,
) -> ApiResult<Json<Value>> {
    let store = state.sessions()?;
    let now = now_unix()?;

    verify_intent_signature(IntentVerifyArgs {
        intent: &req.intent,
        signature_bs58: &req.intent_sig,
        expected_pubkey_bs58: None,
        enforce_expiry: false,
        now_unix_secs: now,
    })
    .map_err(|e| ApiError::bad_request("intent_verify", e.to_string()))?;

    let solana_pubkey = req_str(&req.intent, "solana_pubkey")?;
    let session_id = req_str(&req.intent, "session_id")?;
    let whitelist_ids: Vec<String> = req
        .intent
        .get("whitelist_ids")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let session = GenericSession {
        session_id: session_id.clone(),
        solana_pubkey: solana_pubkey.clone(),
        surface: req_str(&req.intent, "surface")?,
        whitelist_mode: req_str(&req.intent, "whitelist_mode")?,
        whitelist_ids,
        max_total_usdc: req_str(&req.intent, "max_total_usdc")?,
        max_order_size_usdc: req_str(&req.intent, "max_order_size_usdc")?,
        max_price: req_str(&req.intent, "max_price")?,
        min_price: req
            .intent
            .get("min_price")
            .and_then(Value::as_str)
            .unwrap_or("0")
            .to_string(),
        delegate_pubkey: req
            .intent
            .get("delegate_pubkey")
            .and_then(Value::as_str)
            .map(str::to_string),
        expiry: req
            .intent
            .get("expiry")
            .and_then(Value::as_u64)
            .ok_or_else(|| ApiError::bad_request("intent_missing", "expiry"))?,
        total_usdc_filled: "0".to_string(),
        created_at: now,
        revoked: false,
    };

    // expiry == 0 means "never"; only pass a DDB TTL for real expiries.
    let ttl = if session.expiry > 0 {
        Some(session.expiry)
    } else {
        None
    };
    store
        .put(&session_key(&session_id), &session, ttl)
        .await
        .map_err(|e| ApiError::internal(format!("session put: {e}")))?;

    let ikey = index_key(&solana_pubkey);
    let mut index: GenericSessionIndex = store
        .get(&ikey)
        .await
        .map_err(|e| ApiError::internal(format!("index get: {e}")))?
        .unwrap_or_default();
    if !index.session_ids.contains(&session_id) {
        index.session_ids.push(session_id.clone());
        store
            .put(&ikey, &index, None)
            .await
            .map_err(|e| ApiError::internal(format!("index put: {e}")))?;
    }

    Ok(Json(json!({ "session_id": session_id, "status": "active" })))
}

// ─── POST /v1/session/revoke ─────────────────────────────────────────

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IntentBody>,
) -> ApiResult<Json<Value>> {
    let store = state.sessions()?;
    let now = now_unix()?;

    verify_intent_signature(IntentVerifyArgs {
        intent: &req.intent,
        signature_bs58: &req.intent_sig,
        expected_pubkey_bs58: None,
        enforce_expiry: false,
        now_unix_secs: now,
    })
    .map_err(|e| ApiError::bad_request("intent_verify", e.to_string()))?;

    let solana_pubkey = req_str(&req.intent, "solana_pubkey")?;
    let session_id = req_str(&req.intent, "session_id")?;
    let key = session_key(&session_id);

    let row: Option<GenericSession> = store
        .get(&key)
        .await
        .map_err(|e| ApiError::internal(format!("session get: {e}")))?;
    if let Some(mut s) = row {
        if s.solana_pubkey == solana_pubkey {
            s.revoked = true;
            let ttl = if s.expiry > 0 { Some(s.expiry) } else { None };
            store
                .put(&key, &s, ttl)
                .await
                .map_err(|e| ApiError::internal(format!("session put: {e}")))?;
        }
    }
    Ok(Json(json!({ "status": "revoked" })))
}

// ─── GET /v1/session/list ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ListQuery {
    pub solana_pubkey: String,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let store = state.sessions()?;
    let index: GenericSessionIndex = store
        .get(&index_key(&q.solana_pubkey))
        .await
        .map_err(|e| ApiError::internal(format!("index get: {e}")))?
        .unwrap_or_default();

    let mut sessions: Vec<Value> = Vec::with_capacity(index.session_ids.len());
    for id in &index.session_ids {
        if let Some(s) = store
            .get::<GenericSession>(&session_key(id))
            .await
            .map_err(|e| ApiError::internal(format!("session get: {e}")))?
        {
            if s.solana_pubkey == q.solana_pubkey {
                sessions.push(list_row(&s));
            }
        }
    }
    Ok(Json(json!({ "sessions": sessions })))
}
