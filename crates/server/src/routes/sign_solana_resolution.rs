//! `POST /v1/sign/solana-resolution` — Ed25519 attestation that a
//! Polymarket market resolved to a specific outcome.

use axum::extract::State;
use axum::Json;
use polylayer_tee_core::solana_attestor::{build_resolution, AttestationCommon, ResolutionPayload};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Deserialize)]
pub struct Req {
    /// 0x-hex 32-byte market id.
    pub market_id: String,
    pub signed_unix_ts: u64,
    pub nonce: u64,
    pub final_outcome_bps: u16,
    pub resolved_at_ts: u64,
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Req>,
) -> ApiResult<Json<Value>> {
    let market_id = parse_market_id(&req.market_id)?;
    let common = AttestationCommon {
        market_id,
        signed_unix_ts: req.signed_unix_ts,
        nonce: req.nonce,
    };
    let payload = ResolutionPayload {
        final_outcome_bps: req.final_outcome_bps,
        resolved_at_ts: req.resolved_at_ts,
    };
    let bytes = build_resolution(&common, &payload);
    let sig = state.solana_attestor.sign(&bytes);
    Ok(Json(json!({
        "attestation_hex": format!("0x{}", hex::encode(bytes)),
        "signature_hex": format!("0x{}", hex::encode(sig)),
        "signature_bs58": bs58::encode(sig).into_string(),
        "attestor_pubkey_bs58": state.solana_attestor.public_key_bs58(),
    })))
}

pub(super) fn parse_market_id(s: &str) -> Result<[u8; 32], ApiError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped)
        .map_err(|e| ApiError::bad_request("invalid_market_id", e.to_string()))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request(
            "invalid_market_id",
            format!("expected 32 bytes, got {}", bytes.len()),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
