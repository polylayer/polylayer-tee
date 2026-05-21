//! `POST /v1/sign/link-message` — sign the registry link receipt.

use axum::extract::State;
use axum::Json;
use polylayer_tee_core::solana::decode_pubkey;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Deserialize)]
pub struct Req {
    pub solana_pubkey: String,
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Req>,
) -> ApiResult<Json<Value>> {
    let pubkey = decode_pubkey(&req.solana_pubkey)
        .map_err(|e| ApiError::bad_request("invalid_solana_pubkey", e.to_string()))?;
    let sig = state
        .master
        .sign_link_message(&pubkey)
        .map_err(|e| ApiError::internal(format!("sign: {e}")))?;
    Ok(Json(json!({
        "evm_address": format!("{:#x}", sig.evm_address),
        "message_hex": format!("0x{}", hex::encode(&sig.message)),
        "message_hash": format!("0x{}", hex::encode(sig.message_hash)),
        "signature": format!("0x{}", hex::encode(sig.signature)),
        "recovery_id": sig.recovery_id,
    })))
}
