//! `POST /v1/sign/hl-bridge-permit` — USDC EIP-2612 permit for HL Bridge2.

use alloy_primitives::U256;
use axum::extract::State;
use axum::Json;
use polylayer_tee_core::evm::permits::{
    sign_usdc_permit_arbitrum, HL_BRIDGE2_ARBITRUM_ADDRESS,
};
use polylayer_tee_core::solana::decode_pubkey;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Deserialize)]
pub struct Req {
    pub solana_pubkey: String,
    /// USDC base units (6 decimals) as a decimal string.
    pub value: String,
    /// USDC contract's EIP-2612 nonce for the owner.
    pub nonce: String,
    /// Unix seconds deadline.
    pub deadline: String,
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Req>,
) -> ApiResult<Json<Value>> {
    let pubkey = decode_pubkey(&req.solana_pubkey)
        .map_err(|e| ApiError::bad_request("invalid_solana_pubkey", e.to_string()))?;
    let derived = state
        .master
        .derive_user_evm_account(&pubkey)
        .map_err(|e| ApiError::internal(format!("derive: {e}")))?;

    let value = U256::from_str_radix(&req.value, 10)
        .map_err(|e| ApiError::bad_request("invalid_value", e.to_string()))?;
    let nonce = U256::from_str_radix(&req.nonce, 10)
        .map_err(|e| ApiError::bad_request("invalid_nonce", e.to_string()))?;
    let deadline = U256::from_str_radix(&req.deadline, 10)
        .map_err(|e| ApiError::bad_request("invalid_deadline", e.to_string()))?;

    let sig = sign_usdc_permit_arbitrum(
        &derived.private_key.0,
        derived.address,
        HL_BRIDGE2_ARBITRUM_ADDRESS,
        value,
        nonce,
        deadline,
    )
    .map_err(|e| ApiError::bad_request("permit_sign", e.to_string()))?;

    Ok(Json(json!({
        "r": format!("0x{}", hex::encode(sig.r)),
        "s": format!("0x{}", hex::encode(sig.s)),
        "v": sig.v,
        "signature": format!("0x{}", hex::encode(sig.signature)),
        "evm_address": format!("{:#x}", derived.address),
        "spender": format!("{:#x}", HL_BRIDGE2_ARBITRUM_ADDRESS),
    })))
}
