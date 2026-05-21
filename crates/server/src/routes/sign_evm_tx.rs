//! `POST /v1/sign/evm-tx` — generic EVM tx signing with intent validation.
//!
//! Dispatches on `intent.action`. Each branch decodes the calldata via
//! a `core::evm` validator that asserts the bytes match a user-supplied
//! intent (selector, target, recipient, amount bounds…). Only after
//! validation passes do we sign — so a caller can't smuggle a different
//! tx past the intent the user signed off-chain.
//!
//! CCTP-burn variants share the same calldata shape; we just accept
//! three intent.action strings as aliases so each upstream poller can
//! tag its rows distinctly without changing the on-chain semantics:
//!
//! - `withdraw` — `WithdrawTab.tsx` direct Polygon/Arbitrum → Solana
//! - `polymarket_to_solana_withdraw` — `polymarketUnwrapPoll.ts` pUSD-
//!   unwrap-then-CCTP-burn cron
//! - `hyperliquid_to_solana_withdraw` — `hlToSolanaPoll.ts` HL-Bridge2-
//!   then-CCTP-burn cron
//!
//! Polymarket-flow actions don't have production callers today but the
//! validators exist; wiring them now keeps the EIF stable as new
//! callers come online.

use alloy_primitives::{Address, B256, U256};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use polylayer_tee_core::evm::polymarket_flows::{
    validate_ctf_redeem, validate_erc20_transfer, validate_neg_risk_redeem,
    validate_pusd_wrap, CtfRedeemIntent, Erc20TransferIntent, NegRiskRedeemIntent,
    PusdWrapIntent,
};
use polylayer_tee_core::evm::{
    decode_deposit_for_burn, sign_eip1559, validate_against_intent, CctpIntentBounds,
    Eip1559Tx, TOKEN_MESSENGER_V2_ADDRESS,
};
use polylayer_tee_core::intents::{verify_intent_signature, IntentVerifyArgs};
use polylayer_tee_core::solana::decode_pubkey;
use serde::Deserialize;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{ApiError, ApiResult};
use crate::AppState;

#[derive(Deserialize)]
pub struct UnsignedTxInput {
    pub chain_id: u64,
    pub to: String,
    pub data: String,
    pub value: String,
    pub nonce: String,
    pub gas_limit: String,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
}

#[derive(Deserialize)]
pub struct Req {
    pub intent: Value,
    pub intent_sig: String,
    pub unsigned_tx: UnsignedTxInput,
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Req>,
) -> ApiResult<Json<Value>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ApiError::internal(format!("clock: {e}")))?
        .as_secs();

    verify_intent_signature(IntentVerifyArgs {
        intent: &req.intent,
        signature_bs58: &req.intent_sig,
        expected_pubkey_bs58: None,
        enforce_expiry: true,
        now_unix_secs: now,
    })
    .map_err(|e| ApiError::bad_request("intent_verify", e.to_string()))?;

    let action = req
        .intent
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("intent_missing", "action"))?;

    let solana_pubkey_bs58 = req
        .intent
        .get("solana_pubkey")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("intent_missing", "solana_pubkey"))?;
    let solana_pubkey = decode_pubkey(solana_pubkey_bs58)
        .map_err(|e| ApiError::bad_request("invalid_solana_pubkey", e.to_string()))?;
    let derived = state
        .master
        .derive_user_evm_account(&solana_pubkey)
        .map_err(|e| ApiError::internal(format!("derive: {e}")))?;

    let tx = parse_tx(&req.unsigned_tx)?;

    match action {
        "withdraw" | "polymarket_to_solana_withdraw" | "hyperliquid_to_solana_withdraw" => {
            validate_cctp_withdraw(&req.intent, &tx)?
        }
        "pusd_wrap" => validate_pusd_wrap_action(&req.intent, &tx)?,
        "ctf_redeem" => validate_ctf_redeem_action(&req.intent, &tx)?,
        "neg_risk_redeem" => validate_neg_risk_redeem_action(&req.intent, &tx)?,
        "erc20_transfer" => validate_erc20_transfer_action(&req.intent, &tx)?,
        other => {
            return Err(ApiError {
                status: StatusCode::NOT_IMPLEMENTED,
                code: "unsupported_action",
                message: format!("evm-tx action {other} is not supported"),
            });
        }
    };

    let signed = sign_eip1559(&derived.private_key.0, &tx)
        .map_err(|e| ApiError::bad_request("sign", e.to_string()))?;

    Ok(Json(json!({
        "signed_tx_hex": signed.raw_hex,
        "tx_hash": format!("{:#x}", signed.tx_hash),
        "evm_address": format!("{:#x}", signed.from),
    })))
}

// ─── Shared parsers ─────────────────────────────────────────────────

fn parse_tx(input: &UnsignedTxInput) -> Result<Eip1559Tx, ApiError> {
    let to = Address::from_str(&input.to)
        .map_err(|e| ApiError::bad_request("invalid_to", e.to_string()))?;
    let data = hex::decode(input.data.strip_prefix("0x").unwrap_or(&input.data))
        .map_err(|e| ApiError::bad_request("invalid_data", e.to_string()))?;
    let value = U256::from_str_radix(&input.value, 10)
        .map_err(|e| ApiError::bad_request("invalid_value", e.to_string()))?;
    let nonce = input
        .nonce
        .parse::<u64>()
        .map_err(|e| ApiError::bad_request("invalid_nonce", e.to_string()))?;
    let gas_limit = input
        .gas_limit
        .parse::<u64>()
        .map_err(|e| ApiError::bad_request("invalid_gas_limit", e.to_string()))?;
    let max_fee = U256::from_str_radix(&input.max_fee_per_gas, 10)
        .map_err(|e| ApiError::bad_request("invalid_max_fee", e.to_string()))?;
    let max_priority = U256::from_str_radix(&input.max_priority_fee_per_gas, 10)
        .map_err(|e| ApiError::bad_request("invalid_max_priority_fee", e.to_string()))?;
    Ok(Eip1559Tx {
        chain_id: input.chain_id,
        nonce,
        max_priority_fee_per_gas: max_priority,
        max_fee_per_gas: max_fee,
        gas_limit,
        to,
        value,
        data,
        access_list: vec![],
    })
}

fn intent_str<'a>(intent: &'a Value, field: &'static str) -> Result<&'a str, ApiError> {
    intent
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("intent_missing", field))
}

fn intent_address(intent: &Value, field: &'static str) -> Result<Address, ApiError> {
    let s = intent_str(intent, field)?;
    Address::from_str(s).map_err(|e| {
        ApiError::bad_request(
            "intent_invalid",
            format!("{field}: {e}"),
        )
    })
}

fn intent_b256(intent: &Value, field: &'static str) -> Result<B256, ApiError> {
    let s = intent_str(intent, field)?;
    B256::from_str(s).map_err(|e| {
        ApiError::bad_request(
            "intent_invalid",
            format!("{field}: {e}"),
        )
    })
}

fn intent_u256_decimal(intent: &Value, field: &'static str) -> Result<U256, ApiError> {
    let s = intent_str(intent, field)?;
    U256::from_str_radix(s, 10).map_err(|e| {
        ApiError::bad_request("intent_invalid", format!("{field}: {e}"))
    })
}

fn intent_u8(intent: &Value, field: &'static str) -> Result<u8, ApiError> {
    let n = intent
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| ApiError::bad_request("intent_missing", field))?;
    u8::try_from(n).map_err(|_| {
        ApiError::bad_request("intent_invalid", format!("{field}: {n} doesn't fit u8"))
    })
}

// ─── CCTP withdraw (3 aliased actions) ──────────────────────────────

/// Whichever of {`destination`, `solana_destination`} the intent uses,
/// return it as a bs58 Solana pubkey string. WithdrawTab.tsx uses
/// `destination`; the cron pollers use `solana_destination`.
fn cctp_destination(intent: &Value) -> Result<String, ApiError> {
    if let Some(s) = intent.get("destination").and_then(Value::as_str) {
        return Ok(s.to_string());
    }
    if let Some(s) = intent.get("solana_destination").and_then(Value::as_str) {
        return Ok(s.to_string());
    }
    Err(ApiError::bad_request(
        "intent_missing",
        "destination or solana_destination",
    ))
}

/// Whichever of {`amount_wei`, `amount`} the intent uses, return as
/// USDC base units (6 decimals). `amount_wei` is already base units;
/// `amount` (cron-poller flows) is a decimal string in USDC units.
fn cctp_amount_max(intent: &Value) -> Result<U256, ApiError> {
    if let Some(s) = intent.get("amount_wei").and_then(Value::as_str) {
        return U256::from_str_radix(s, 10)
            .map_err(|e| ApiError::bad_request("intent_invalid", format!("amount_wei: {e}")));
    }
    if let Some(s) = intent.get("amount").and_then(Value::as_str) {
        return decimal_usdc_to_base_units(s);
    }
    Err(ApiError::bad_request(
        "intent_missing",
        "amount_wei or amount",
    ))
}

/// `"10.5"` → `10_500_000` (USDC has 6 decimals).
fn decimal_usdc_to_base_units(s: &str) -> Result<U256, ApiError> {
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if frac_part.len() > 6 {
        return Err(ApiError::bad_request(
            "intent_invalid",
            format!("amount has {} fractional digits; max 6", frac_part.len()),
        ));
    }
    let mut buf = String::with_capacity(int_part.len() + 6);
    buf.push_str(int_part);
    buf.push_str(frac_part);
    for _ in frac_part.len()..6 {
        buf.push('0');
    }
    U256::from_str_radix(&buf, 10)
        .map_err(|e| ApiError::bad_request("intent_invalid", format!("amount: {e}")))
}

fn validate_cctp_withdraw(intent: &Value, tx: &Eip1559Tx) -> Result<(), ApiError> {
    if tx.to != TOKEN_MESSENGER_V2_ADDRESS {
        return Err(ApiError::bad_request(
            "withdraw_wrong_target",
            format!(
                "withdraw must target TokenMessengerV2 {:#x}, got {:#x}",
                TOKEN_MESSENGER_V2_ADDRESS, tx.to
            ),
        ));
    }
    let args = decode_deposit_for_burn(&tx.data)
        .map_err(|e| ApiError::bad_request("cctp_decode", e.to_string()))?;

    validate_against_intent(
        &args,
        &CctpIntentBounds {
            source_chain_id: tx.chain_id,
            destination_owner_bs58: cctp_destination(intent)?,
            intent_amount_max: cctp_amount_max(intent)?,
        },
    )
    .map_err(|e| ApiError::bad_request("cctp_validate", e.to_string()))?;

    Ok(())
}

// ─── pUSD wrap ──────────────────────────────────────────────────────

fn validate_pusd_wrap_action(intent: &Value, tx: &Eip1559Tx) -> Result<(), ApiError> {
    let source_token = intent_address(intent, "source_token")?;
    let deposit_wallet = intent_address(intent, "deposit_wallet")?;
    let max_amount = intent_u256_decimal(intent, "max_amount")?;
    validate_pusd_wrap(
        tx.to,
        &tx.data,
        &PusdWrapIntent {
            source_token,
            deposit_wallet,
            max_amount,
        },
    )
    .map_err(|e| ApiError::bad_request("pusd_wrap_validate", e.to_string()))?;
    Ok(())
}

// ─── CTF redeem (regular) ───────────────────────────────────────────

fn validate_ctf_redeem_action(intent: &Value, tx: &Eip1559Tx) -> Result<(), ApiError> {
    let condition_id = intent_b256(intent, "condition_id")?;
    let outcome_index = intent_u8(intent, "outcome_index")?;
    validate_ctf_redeem(
        tx.to,
        &tx.data,
        &CtfRedeemIntent {
            condition_id,
            outcome_index,
        },
    )
    .map_err(|e| ApiError::bad_request("ctf_redeem_validate", e.to_string()))?;
    Ok(())
}

// ─── NegRisk redeem ─────────────────────────────────────────────────

fn validate_neg_risk_redeem_action(intent: &Value, tx: &Eip1559Tx) -> Result<(), ApiError> {
    let condition_id = intent_b256(intent, "condition_id")?;
    let outcome_index = intent_u8(intent, "outcome_index")?;
    let max_amount = intent_u256_decimal(intent, "max_amount")?;
    validate_neg_risk_redeem(
        tx.to,
        &tx.data,
        &NegRiskRedeemIntent {
            condition_id,
            outcome_index,
            max_amount,
        },
    )
    .map_err(|e| ApiError::bad_request("neg_risk_redeem_validate", e.to_string()))?;
    Ok(())
}

// ─── ERC20 transfer ─────────────────────────────────────────────────

fn validate_erc20_transfer_action(intent: &Value, tx: &Eip1559Tx) -> Result<(), ApiError> {
    let token = intent_address(intent, "token")?;
    let recipient = intent_address(intent, "recipient")?;
    let amount = intent_u256_decimal(intent, "amount")?;
    validate_erc20_transfer(
        tx.to,
        &tx.data,
        &Erc20TransferIntent {
            token,
            recipient,
            amount,
        },
    )
    .map_err(|e| ApiError::bad_request("erc20_transfer_validate", e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::decimal_usdc_to_base_units;
    use alloy_primitives::U256;

    #[test]
    fn decimal_usdc_zero_fraction() {
        assert_eq!(
            decimal_usdc_to_base_units("10").unwrap(),
            U256::from(10_000_000u64)
        );
    }

    #[test]
    fn decimal_usdc_full_precision() {
        assert_eq!(
            decimal_usdc_to_base_units("10.500000").unwrap(),
            U256::from(10_500_000u64)
        );
    }

    #[test]
    fn decimal_usdc_partial_fraction_right_pads() {
        assert_eq!(
            decimal_usdc_to_base_units("0.5").unwrap(),
            U256::from(500_000u64)
        );
    }

    #[test]
    fn decimal_usdc_rejects_too_many_fractional_digits() {
        decimal_usdc_to_base_units("1.1234567").unwrap_err();
    }
}
