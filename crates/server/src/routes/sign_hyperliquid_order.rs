//! `POST /v1/sign/hyperliquid-order` — L1 Agent EIP-712 signing.
//!
//! The lambda has already computed the 32-byte `connection_id` from the
//! msgpack-encoded action (the TEE does not carry msgpack). We just
//! sign the Agent EIP-712 wrapper against either mainnet or testnet.

use alloy_primitives::B256;
use axum::extract::State;
use axum::Json;
use polylayer_tee_core::hyperliquid::{sign_l1_action, HyperliquidNetwork};
use polylayer_tee_core::solana::decode_pubkey;
use serde::Deserialize;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;

use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Deserialize)]
pub struct Req {
    pub solana_pubkey: String,
    /// "mainnet" or "testnet".
    pub network: String,
    /// 32-byte `connection_id` as 0x-prefixed hex.
    pub connection_id: String,
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

    let network = match req.network.as_str() {
        "mainnet" => HyperliquidNetwork::Mainnet,
        "testnet" => HyperliquidNetwork::Testnet,
        other => {
            return Err(ApiError::bad_request(
                "invalid_network",
                format!("expected mainnet|testnet, got {other}"),
            ));
        }
    };
    let connection_id = B256::from_str(&req.connection_id)
        .map_err(|e| ApiError::bad_request("invalid_connection_id", e.to_string()))?;

    let sig = sign_l1_action(&derived.private_key.0, network, &connection_id)
        .map_err(|e| ApiError::bad_request("hl_sign", e.to_string()))?;

    Ok(Json(json!({
        "r": format!("0x{}", hex::encode(sig.r)),
        "s": format!("0x{}", hex::encode(sig.s)),
        "v": sig.v,
        "signature": format!("0x{}", hex::encode(sig.signature)),
        "evm_address": format!("{:#x}", sig.evm_address),
    })))
}
