//! `GET /v1/derive?solana=<bs58>` — derive the user's EVM address.

use axum::extract::{Query, State};
use axum::Json;
use polylayer_tee_core::solana::decode_pubkey;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Deserialize)]
pub struct DeriveQuery {
    pub solana: String,
}

pub async fn derive(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DeriveQuery>,
) -> ApiResult<Json<Value>> {
    let pubkey = decode_pubkey(&q.solana)
        .map_err(|e| ApiError::bad_request("invalid_solana_pubkey", e.to_string()))?;
    let account = state
        .master
        .derive_user_evm_account(&pubkey)
        .map_err(|e| ApiError::internal(format!("derive: {e}")))?;
    Ok(Json(json!({
        "solana_pubkey": q.solana,
        "evm_address": format!("{:#x}", account.address),
        "derivation_version": account.derivation_version,
    })))
}
