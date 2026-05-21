//! `POST /v1/sign/polymarket-wallet-batch` — DepositWallet.Batch signing.
//!
//! Only the `bootstrap_approvals` purpose is signable. That batch is
//! fully canonical (pUSD `approve` + CTF `setApprovalForAll`, at max,
//! for every V2 exchange spender), so the enclave reconstructs it from
//! its own constants and never trusts caller-supplied calldata — there
//! is nothing variable to validate against a user intent.
//!
//! Variable batches (pUSD wrap, Polymarket split/merge) carry
//! user-specific calldata and return 501 until the per-call assertion
//! layer (task #189) lands.

use alloy_primitives::{Address, U256};
use axum::extract::State;
use axum::Json;
use polylayer_tee_core::polymarket::{
    bootstrap_approval_calls, derive_deposit_wallet_address, sign_deposit_wallet_batch,
    DepositWalletCall, SignBatchArgs,
};
use polylayer_tee_core::solana::decode_pubkey;
use serde::Deserialize;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;

use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Deserialize)]
pub struct CallInput {
    pub target: String,
    pub value: String,
    pub data: String,
}

#[derive(Deserialize)]
pub struct Req {
    #[serde(default)]
    pub solana_pubkey: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    pub deposit_wallet: String,
    pub nonce: String,
    pub deadline: String,
    /// Optional echo of the calls the caller built — cross-checked
    /// against the canonical batch, never used as the signing input.
    #[serde(default)]
    pub calls: Vec<CallInput>,
}

fn parse_u256(s: &str, field: &str) -> Result<U256, ApiError> {
    U256::from_str_radix(s, 10)
        .map_err(|e| ApiError::bad_request("invalid_u256", format!("{field}: {e}")))
}

fn parse_supplied_calls(inputs: &[CallInput]) -> Result<Vec<DepositWalletCall>, ApiError> {
    inputs
        .iter()
        .map(|c| {
            let target = Address::from_str(&c.target)
                .map_err(|e| ApiError::bad_request("invalid_call_target", e.to_string()))?;
            let value = parse_u256(&c.value, "call.value")?;
            let data = hex::decode(c.data.trim_start_matches("0x"))
                .map_err(|e| ApiError::bad_request("invalid_call_data", e.to_string()))?;
            Ok(DepositWalletCall { target, value, data })
        })
        .collect()
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Req>,
) -> ApiResult<Json<Value>> {
    if req.purpose.as_deref() != Some("bootstrap_approvals") {
        return Err(ApiError::not_implemented(
            "wallet_batch_purpose",
            "only purpose=bootstrap_approvals is signable; variable batches pending task #189",
        ));
    }

    let solana_pubkey = req.solana_pubkey.as_deref().ok_or_else(|| {
        ApiError::bad_request(
            "missing_solana_pubkey",
            "solana_pubkey is required for bootstrap_approvals",
        )
    })?;
    let pubkey = decode_pubkey(solana_pubkey)
        .map_err(|e| ApiError::bad_request("invalid_solana_pubkey", e.to_string()))?;
    let derived = state
        .master
        .derive_user_evm_account(&pubkey)
        .map_err(|e| ApiError::internal(format!("derive: {e}")))?;

    // The batch is bound, via the EIP-712 domain's verifyingContract, to
    // a deposit wallet. Sign only for the caller's own wallet — never
    // one a caller-supplied address points at.
    let deposit_wallet = Address::from_str(&req.deposit_wallet)
        .map_err(|e| ApiError::bad_request("invalid_deposit_wallet", e.to_string()))?;
    let expected = derive_deposit_wallet_address(derived.address);
    if deposit_wallet != expected {
        return Err(ApiError::bad_request(
            "deposit_wallet_mismatch",
            format!("deposit_wallet {deposit_wallet:#x} is not the caller's ({expected:#x})"),
        ));
    }

    let nonce = parse_u256(&req.nonce, "nonce")?;
    let deadline = parse_u256(&req.deadline, "deadline")?;

    // Reconstruct the canonical batch in-enclave.
    let calls = bootstrap_approval_calls();

    // Defense in depth: if the caller echoed calls, they must match the
    // canonical set exactly — a mismatch means client drift or tampering.
    if !req.calls.is_empty() {
        let supplied = parse_supplied_calls(&req.calls)?;
        if supplied != calls {
            return Err(ApiError::bad_request(
                "non_canonical_bootstrap_batch",
                "supplied calls do not match the canonical bootstrap-approval batch",
            ));
        }
    }

    let sig = sign_deposit_wallet_batch(SignBatchArgs {
        priv_key: &derived.private_key.0,
        wallet_address: deposit_wallet,
        nonce,
        deadline,
        calls: &calls,
    })
    .map_err(|e| ApiError::bad_request("batch_sign", e.to_string()))?;

    let calls_json: Vec<Value> = calls
        .iter()
        .map(|c| {
            json!({
                "target": format!("{:#x}", c.target),
                "value": c.value.to_string(),
                "data": format!("0x{}", hex::encode(&c.data)),
            })
        })
        .collect();

    Ok(Json(json!({
        "signature": format!("0x{}", hex::encode(sig.signature)),
        "evm_address": format!("{:#x}", sig.evm_address),
        "deposit_wallet_address": format!("{:#x}", sig.wallet_address),
        "nonce": req.nonce,
        "deadline": req.deadline,
        "calls": calls_json,
        "domain": {
            "name": "DepositWallet",
            "version": "1",
            "chainId": 137,
            "verifyingContract": format!("{:#x}", deposit_wallet),
        },
    })))
}
