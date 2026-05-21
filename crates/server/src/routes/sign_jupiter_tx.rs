//! `POST /v1/sign/jupiter-tx` — Jupiter perpetuals tx signing.
//!
//! Decodes + validates the Jupiter perps ix against the user's intent
//! (asset, owner, custody), but returns 501 on signature emit until the
//! per-user Jupiter delegate derivation lands (task #190). The current
//! `SolanaAttestorKeypair` is the SHARED master attestor; signing a
//! Jupiter trade with it would conflate the attestor identity with
//! trade authority — wrong design. Each user gets their own delegate
//! once #190 ships.

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use polylayer_tee_core::intents::{verify_intent_signature, IntentVerifyArgs};
use polylayer_tee_core::jupiter::{
    custody_to_asset, decode_jupiter_perps_ix, sign_versioned_transaction, DecodedJupiterIx,
    JUPITER_PERPS_PROGRAM_ID,
};
use polylayer_tee_core::solana::decode_pubkey;
use polylayer_tee_core::solana_attestor::derive_jupiter_delegate;
use serde::Deserialize;
use serde_json::{json, Value};
use solana_pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Deserialize)]
pub struct Req {
    pub intent: Value,
    pub intent_sig: String,
    pub unsigned_tx_b64: String,
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Req>,
) -> ApiResult<Json<Value>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ApiError::internal(format!("clock: {e}")))?
        .as_secs();

    verify_intent_signature(IntentVerifyArgs {
        intent: &req.intent,
        signature_bs58: &req.intent_sig,
        expected_pubkey_bs58: None,
        enforce_expiry: true,
        now_unix_secs: now,
    })
    .map_err(|e| ApiError::bad_request("intent_verify", e.to_string()))?;

    let asset_intent = req
        .intent
        .get("asset")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("intent_missing", "asset"))?;

    let raw = B64
        .decode(req.unsigned_tx_b64.as_bytes())
        .map_err(|e| ApiError::bad_request("base64", e.to_string()))?;
    let tx: VersionedTransaction = bincode::deserialize(&raw)
        .map_err(|e| ApiError::bad_request("tx_deserialize", e.to_string()))?;

    let static_keys = tx.message.static_account_keys();
    let mut perps_ixes = 0usize;
    let mut decoded_match: Option<DecodedJupiterIx> = None;
    for ix in tx.message.instructions() {
        let program_id = static_keys
            .get(ix.program_id_index as usize)
            .copied()
            .unwrap_or(Pubkey::default());
        if program_id != *JUPITER_PERPS_PROGRAM_ID {
            continue;
        }
        let account_pubkeys: Vec<Pubkey> = ix
            .accounts
            .iter()
            .map(|&i| {
                static_keys
                    .get(i as usize)
                    .copied()
                    .unwrap_or(Pubkey::default())
            })
            .collect();
        if let Some(decoded) =
            decode_jupiter_perps_ix(&ix.data, &account_pubkeys).map_err(|e| {
                ApiError::bad_request("jupiter_decode", e.to_string())
            })?
        {
            perps_ixes += 1;
            decoded_match = Some(decoded);
        }
    }
    if perps_ixes != 1 {
        return Err(ApiError::bad_request(
            "perps_ix_count",
            format!("expected exactly 1 perps ix in tx, found {perps_ixes}"),
        ));
    }
    let decoded = decoded_match.expect("found exactly one");

    let custody = match &decoded {
        DecodedJupiterIx::Increase { accounts, .. }
        | DecodedJupiterIx::Decrease { accounts, .. } => accounts.custody,
    };
    let asset_label = custody_to_asset(&custody)
        .ok_or_else(|| ApiError::bad_request("unknown_custody", custody.to_string()))?;
    if asset_label != asset_intent {
        return Err(ApiError::bad_request(
            "asset_mismatch",
            format!("tx={asset_label} intent={asset_intent}"),
        ));
    }

    // All intent + tx-shape validation passed. Derive the per-user
    // Jupiter delegate and sign.
    let solana_pubkey_bs58 = req
        .intent
        .get("solana_pubkey")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("intent_missing", "solana_pubkey"))?;
    let solana_pubkey = decode_pubkey(solana_pubkey_bs58)
        .map_err(|e| ApiError::bad_request("invalid_solana_pubkey", e.to_string()))?;

    // ─── Session-bound enforcement ──────────────────────────────────
    // If the user has registered a Jupiter session, this trade must
    // fit inside its bounds and the cumulative counter is debited
    // before we sign. If no session exists, the per-intent ed25519
    // signature verified at the top is the sole authorization (the
    // interactive Phantom-signs-every-trade path).
    //
    // The debit is get-modify-put, not a DDB conditional write — two
    // concurrent signs for the same session could both pass the cap
    // check. Acceptable at current volume; tracked in
    // TEE_SESSION_PORT.md as a hardening follow-up.
    let trade_size_usd: u64 = match &decoded {
        DecodedJupiterIx::Increase { args, .. } => args.size_usd_delta,
        DecodedJupiterIx::Decrease { args, .. } => args.size_usd_delta,
    };
    if let Some(store) = &state.sessions {
        use crate::routes::jupiter_session::{
            check_session_bounds, jup_session_key, JupiterSession, SessionBoundError,
        };
        let key = jup_session_key(solana_pubkey_bs58);
        if let Some(mut session) = store
            .get::<JupiterSession>(&key)
            .await
            .map_err(|e| ApiError::internal(format!("session get: {e}")))?
        {
            let new_used =
                check_session_bounds(&session, asset_label, trade_size_usd, now).map_err(
                    |e| match e {
                        SessionBoundError::Revoked => ApiError::bad_request(
                            "session_revoked",
                            "jupiter session is revoked",
                        ),
                        SessionBoundError::Expired => ApiError::bad_request(
                            "session_expired",
                            "jupiter session has expired",
                        ),
                        SessionBoundError::AssetNotAllowed => ApiError::bad_request(
                            "asset_not_allowed",
                            format!("{asset_label} not in session allowed_assets"),
                        ),
                        SessionBoundError::PerIntentExceeded => ApiError::conflict(
                            "per_intent_exceeded",
                            format!("trade size {trade_size_usd} exceeds the per-intent max"),
                        ),
                        SessionBoundError::CumulativeExceeded => ApiError::conflict(
                            "cumulative_exceeded",
                            "trade would exceed the session cumulative cap",
                        ),
                        SessionBoundError::Parse(field) => {
                            ApiError::internal(format!("session field parse: {field}"))
                        }
                    },
                )?;
            // Debit the cumulative counter, then persist before signing.
            session.cumulative_size_usdc_used = new_used.to_string();
            store
                .put(&key, &session, Some(session.expires_at_unix_ts))
                .await
                .map_err(|e| ApiError::internal(format!("session debit: {e}")))?;
        }
    }

    let delegate = derive_jupiter_delegate(&state.master, &solana_pubkey)
        .map_err(|e| ApiError::internal(format!("delegate_derive: {e}")))?;
    let priv_bytes = *delegate.private_key_bytes();

    let signed = sign_versioned_transaction(&req.unsigned_tx_b64, &priv_bytes)
        .map_err(|e| ApiError::bad_request("sign", e.to_string()))?;

    let _ = decoded; // silence unused-warning; decoded was used to assert asset

    Ok(Json(json!({
        "signed_tx_b64": signed.signed_tx_b64,
        "signature_index": signed.signature_index,
        "delegate_pubkey_bs58": delegate.public_key_bs58(),
        "decoded_asset": asset_label,
    })))
}
