//! `POST /v1/sign/solana-liquidation` — historical-breach attestation for polyleverage.

use axum::extract::State;
use axum::Json;
use polylayer_tee_core::solana_attestor::{
    build_historical_liquidation, AttestationCommon, HistoricalLiquidationPayload,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::error::{ApiError, ApiResult};
use crate::routes::sign_solana_resolution::parse_market_id;
use crate::AppState;

#[derive(Deserialize)]
pub struct Req {
    pub market_id: String,
    pub signed_unix_ts: u64,
    pub nonce: u64,
    /// 0x-hex 32-byte polyleverage market-leverage-contract pubkey.
    pub pmlc_pubkey: String,
    /// u64 FP18 — TWAP at breach.
    pub breach_mark_fp: u64,
    /// Unix seconds of breach (must be >= 0).
    pub breach_unix_ts: i64,
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Req>,
) -> ApiResult<Json<Value>> {
    let market_id = parse_market_id(&req.market_id)?;
    let pmlc_pubkey = parse_market_id(&req.pmlc_pubkey)?;
    let common = AttestationCommon {
        market_id,
        signed_unix_ts: req.signed_unix_ts,
        nonce: req.nonce,
    };
    let payload = HistoricalLiquidationPayload {
        pmlc_pubkey,
        breach_mark_fp: req.breach_mark_fp,
        breach_unix_ts: req.breach_unix_ts,
    };
    let bytes = build_historical_liquidation(&common, &payload)
        .map_err(|e| ApiError::bad_request("attestation", e.to_string()))?;
    let sig = state.solana_attestor.sign(&bytes);
    Ok(Json(json!({
        "attestation_hex": format!("0x{}", hex::encode(bytes)),
        "signature_hex": format!("0x{}", hex::encode(sig)),
        "signature_bs58": bs58::encode(sig).into_string(),
        "attestor_pubkey_bs58": state.solana_attestor.public_key_bs58(),
    })))
}
