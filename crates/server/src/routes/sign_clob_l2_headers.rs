//! `POST /v1/sign/clob-l2-headers` — Polymarket CLOB HMAC auth.

use axum::extract::State;
use axum::Json;
use polylayer_tee_core::clob::{build_l2_headers, BuildL2HeadersArgs};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Deserialize)]
pub struct Req {
    pub address: String,
    pub api_key: String,
    pub secret: String,
    pub passphrase: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: String,
}

pub async fn handler(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<Req>,
) -> ApiResult<Json<Value>> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ApiError::internal(format!("clock: {e}")))?
        .as_secs();
    let headers = build_l2_headers(BuildL2HeadersArgs {
        address: &req.address,
        api_key: &req.api_key,
        secret: &req.secret,
        passphrase: &req.passphrase,
        method: &req.method,
        path: &req.path,
        body: &req.body,
        timestamp_secs: ts,
    })
    .map_err(|e| ApiError::bad_request("clob_headers", e.to_string()))?;

    Ok(Json(json!({
        "POLY_ADDRESS": headers.poly_address,
        "POLY_API_KEY": headers.poly_api_key,
        "POLY_PASSPHRASE": headers.poly_passphrase,
        "POLY_TIMESTAMP": headers.poly_timestamp,
        "POLY_SIGNATURE": headers.poly_signature,
    })))
}
