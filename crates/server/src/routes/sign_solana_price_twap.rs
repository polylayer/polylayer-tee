//! `POST /v1/sign/solana-price-twap` — TWAP mark attestation for polyleverage CloseMutual.

use axum::extract::State;
use axum::Json;
use polylayer_tee_core::solana_attestor::{
    build_price_twap, AttestationCommon, PriceTwapPayload,
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
    pub price_fp: u64,
    pub twap_window_slots: u64,
    pub observation_start_ts: u64,
    pub observation_end_ts: u64,
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
    let payload = PriceTwapPayload {
        price_fp: req.price_fp,
        twap_window_slots: req.twap_window_slots,
        observation_start_ts: req.observation_start_ts,
        observation_end_ts: req.observation_end_ts,
    };
    let bytes = build_price_twap(&common, &payload)
        .map_err(|e| ApiError::bad_request("attestation", e.to_string()))?;
    let sig = state.solana_attestor.sign(&bytes);
    Ok(Json(json!({
        "attestation_hex": format!("0x{}", hex::encode(bytes)),
        "signature_hex": format!("0x{}", hex::encode(sig)),
        "signature_bs58": bs58::encode(sig).into_string(),
        "attestor_pubkey_bs58": state.solana_attestor.public_key_bs58(),
    })))
}
