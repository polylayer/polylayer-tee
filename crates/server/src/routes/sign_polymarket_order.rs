//! `POST /v1/sign/polymarket-order` — POLY_1271 EIP-712 V2 order.

use alloy_primitives::{Address, B256, U256};
use axum::extract::State;
use axum::Json;
use polylayer_tee_core::polymarket::{sign_v2_order, SignV2OrderArgs, V2Order};
use polylayer_tee_core::solana::decode_pubkey;
use serde::Deserialize;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;

use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Deserialize)]
pub struct OrderInput {
    pub salt: String,
    pub maker: String,
    pub signer: String,
    #[serde(rename = "tokenId")]
    pub token_id: String,
    #[serde(rename = "makerAmount")]
    pub maker_amount: String,
    #[serde(rename = "takerAmount")]
    pub taker_amount: String,
    pub side: u8,
    #[serde(rename = "signatureType")]
    pub signature_type: u8,
    pub timestamp: String,
    pub metadata: String,
    pub builder: String,
}

#[derive(Deserialize)]
pub struct Req {
    pub solana_pubkey: String,
    pub order: OrderInput,
    #[serde(default)]
    pub neg_risk: bool,
}

fn parse_addr(s: &str, field: &str) -> Result<Address, ApiError> {
    Address::from_str(s).map_err(|e| ApiError::bad_request("invalid_address", format!("{field}: {e}")))
}

fn parse_u256(s: &str, field: &str) -> Result<U256, ApiError> {
    U256::from_str_radix(s, 10)
        .map_err(|e| ApiError::bad_request("invalid_u256", format!("{field}: {e}")))
}

fn parse_b256(s: &str, field: &str) -> Result<B256, ApiError> {
    B256::from_str(s).map_err(|e| ApiError::bad_request("invalid_b256", format!("{field}: {e}")))
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

    let order = V2Order {
        salt: parse_u256(&req.order.salt, "salt")?,
        maker: parse_addr(&req.order.maker, "maker")?,
        signer: parse_addr(&req.order.signer, "signer")?,
        token_id: parse_u256(&req.order.token_id, "tokenId")?,
        maker_amount: parse_u256(&req.order.maker_amount, "makerAmount")?,
        taker_amount: parse_u256(&req.order.taker_amount, "takerAmount")?,
        side: req.order.side,
        signature_type: req.order.signature_type,
        timestamp: parse_u256(&req.order.timestamp, "timestamp")?,
        metadata: parse_b256(&req.order.metadata, "metadata")?,
        builder: parse_b256(&req.order.builder, "builder")?,
    };

    let sig = sign_v2_order(SignV2OrderArgs {
        priv_key: &derived.private_key.0,
        order,
        neg_risk: req.neg_risk,
    })
    .map_err(|e| ApiError::bad_request("polymarket_sign", e.to_string()))?;

    Ok(Json(json!({
        "signature": format!("0x{}", hex::encode(&sig.signature)),
        "evm_address": format!("{:#x}", sig.evm_address),
        "deposit_wallet_address": format!("{:#x}", sig.deposit_wallet_address),
        "neg_risk": sig.neg_risk,
    })))
}
