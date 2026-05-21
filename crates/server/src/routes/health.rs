//! `/healthz` and `/v1/attestation` routes.
//!
//! `healthz` is public and unauthenticated — used by load balancers.
//! `attestation` returns the runtime identity (Solana attestor pubkey
//! + the EVM master address) so the lambda can verify which TEE image
//! it's talking to. Full Nitro attestation document generation lands
//! with task #177.

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::AppState;

pub async fn healthz(State(state): State<Arc<AppState>>) -> Json<Value> {
    let master = state.master.derive_master_evm_account().ok();
    let attestor_pubkey = state.solana_attestor.public_key_bs58();
    Json(json!({
        "status": "ok",
        "master_evm_address": master.as_ref().map(|m| format!("{:#x}", m.address)),
        "solana_attestor_pubkey": attestor_pubkey,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn attestation(State(state): State<Arc<AppState>>) -> Json<Value> {
    // TODO(#177): include a real Nitro attestation document signed by
    // the NSM. For now this mirrors the legacy /v1/attestation shape
    // with just the public identity pieces.
    let master = state.master.derive_master_evm_account().ok();
    Json(json!({
        "master_evm_address": master.as_ref().map(|m| format!("{:#x}", m.address)),
        "solana_attestor_pubkey": state.solana_attestor.public_key_bs58(),
        "nitro_attestation_doc": null,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
