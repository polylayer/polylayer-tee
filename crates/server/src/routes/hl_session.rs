//! Hyperliquid zero-click session endpoints.
//!
//!   POST /v1/hl-session/create  — store an intent-signed session
//!   POST /v1/hl-session/revoke  — mark a session revoked
//!   GET  /v1/hl-session/list    — list a user's sessions
//!   GET  /v1/hl-session/get     — read one session
//!
//! Unlike Jupiter, the HL delegate keypair is generated browser-side
//! (the browser keeps the secret; the intent carries only the
//! pubkey) — so the TEE never derives anything here, it only stores
//! the session config the user signed.
//!
//! HL is genuinely multi-session-per-user. The DDB table has a single
//! partition key, so per-user listing uses an index blob:
//!   - session row:  `hl-sess-v1#<session_id>`
//!   - user index:   `hl-idx-v1#<solana_pubkey_bs58>`  -> [session_id]

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
    format!("hl-sess-v1#{session_id}")
}

fn index_key(solana_pubkey_bs58: &str) -> String {
    format!("hl-idx-v1#{solana_pubkey_bs58}")
}

/// Stored HL session blob. Field names match the lambda's
/// `HlSessionListRow`; `solana_pubkey` is extra (ownership check).
#[derive(Serialize, Deserialize, Clone)]
pub struct HlSession {
    pub session_id: String,
    pub solana_pubkey: String,
    pub surface: String,
    pub allowed_coins: Vec<String>,
    pub max_total_usd: String,
    pub max_order_size_usd: String,
    pub max_leverage: u64,
    pub delegate_pubkey: Option<String>,
    pub expiry: u64,
    pub total_usd_filled: String,
    pub revoked: bool,
}

/// Per-user index of HL session ids.
#[derive(Serialize, Deserialize, Default)]
struct HlSessionIndex {
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

fn req_u64(intent: &Value, field: &'static str) -> Result<u64, ApiError> {
    intent
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| ApiError::bad_request("intent_missing", field))
}

// ─── POST /v1/hl-session/create ──────────────────────────────────────

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

    // The HL session intent has no `expires_at` field of its own (it
    // carries `expiry`, the session lifetime, plus a fresh `salt`),
    // so intent-expiry enforcement is off.
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
    let allowed_coins: Vec<String> = req
        .intent
        .get("allowed_coins")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .ok_or_else(|| ApiError::bad_request("intent_missing", "allowed_coins"))?;

    let session = HlSession {
        session_id: session_id.clone(),
        solana_pubkey: solana_pubkey.clone(),
        surface: req_str(&req.intent, "surface")?,
        allowed_coins,
        max_total_usd: req_str(&req.intent, "max_total_usd")?,
        max_order_size_usd: req_str(&req.intent, "max_order_size_usd")?,
        max_leverage: req_u64(&req.intent, "max_leverage")?,
        delegate_pubkey: req
            .intent
            .get("delegate_pubkey")
            .and_then(Value::as_str)
            .map(str::to_string),
        expiry: req_u64(&req.intent, "expiry")?,
        total_usd_filled: "0".to_string(),
        revoked: false,
    };

    store
        .put(&session_key(&session_id), &session, Some(session.expiry))
        .await
        .map_err(|e| ApiError::internal(format!("session put: {e}")))?;

    // Append the id to the user's index (idempotent).
    let ikey = index_key(&solana_pubkey);
    let mut index: HlSessionIndex = store
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

    Ok(Json(
        serde_json::to_value(&session).expect("HlSession serializes"),
    ))
}

// ─── POST /v1/hl-session/revoke ──────────────────────────────────────

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

    let row: Option<HlSession> = store
        .get(&key)
        .await
        .map_err(|e| ApiError::internal(format!("session get: {e}")))?;
    match row {
        Some(mut s) if s.solana_pubkey == solana_pubkey => {
            s.revoked = true;
            store
                .put(&key, &s, Some(s.expiry))
                .await
                .map_err(|e| ApiError::internal(format!("session put: {e}")))?;
            Ok(Json(json!({ "revoked": true })))
        }
        // Not found, or owned by a different pubkey — don't leak which.
        _ => Ok(Json(json!({ "revoked": false }))),
    }
}

// ─── GET /v1/hl-session/get ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct GetQuery {
    pub solana_pubkey: String,
    pub session_id: String,
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Query(q): Query<GetQuery>,
) -> ApiResult<Json<Value>> {
    let store = state.sessions()?;
    let row: Option<HlSession> = store
        .get(&session_key(&q.session_id))
        .await
        .map_err(|e| ApiError::internal(format!("session get: {e}")))?;
    // Only return the row if it belongs to the asking pubkey.
    match row {
        Some(s) if s.solana_pubkey == q.solana_pubkey => {
            Ok(Json(serde_json::to_value(&s).expect("HlSession serializes")))
        }
        _ => Err(ApiError::not_found("session_not_found", "no such hl session")),
    }
}

// ─── GET /v1/hl-session/list ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct ListQuery {
    pub solana_pubkey: String,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let store = state.sessions()?;
    let index: HlSessionIndex = store
        .get(&index_key(&q.solana_pubkey))
        .await
        .map_err(|e| ApiError::internal(format!("index get: {e}")))?
        .unwrap_or_default();

    let mut sessions: Vec<HlSession> = Vec::with_capacity(index.session_ids.len());
    for id in &index.session_ids {
        if let Some(s) = store
            .get::<HlSession>(&session_key(id))
            .await
            .map_err(|e| ApiError::internal(format!("session get: {e}")))?
        {
            // Defensive: only surface rows that match the asker.
            if s.solana_pubkey == q.solana_pubkey {
                sessions.push(s);
            }
        }
    }
    Ok(Json(json!({ "sessions": sessions })))
}
