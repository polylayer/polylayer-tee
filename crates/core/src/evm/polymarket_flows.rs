//! Polymarket-flavored EVM calldata validators.
//!
//! Mirrors the assertion helpers in
//! `eigen-tee/src/lib/polymarketDepositWallet.ts` + the calldata
//! branches in `sign-evm-tx.ts`. Each `validate_*` function decodes
//! calldata via the minimal ABI helpers in `super::abi` and asserts
//! it matches a user-supplied intent.
//!
//! The patterns:
//!
//! - **pUSD wrap** = USDC.approve(Onramp, amount) → Onramp.wrap(USDC, dst, amount)
//! - **pUSD unwrap** = pUSD.approve(Offramp, amount) → Offramp.unwrap(...) → USDC.transfer(...)
//! - **CTF redeem (regular)** = CTF.redeemPositions(pUSD, 0x0, conditionId, indexSets[])
//! - **CTF redeem (neg-risk)** = NegRiskAdapter.redeemPositions(conditionId, amounts[])
//! - **CTF split** = pUSD.approve(CTF, amount) → CTF.splitPosition(...)
//! - **CTF merge** = CTF.mergePositions(pUSD, 0x0, conditionId, partition[], amount)
//! - **ERC20 transfer** = ERC20.transfer(recipient, amount)
//!
//! Note: the deposit-wallet "batch" route in eigen-tee feeds in arrays
//! of these calls. This module validates ONE call at a time; the route
//! layer composes them.

use alloy_primitives::{address, Address, B256, U256};
use once_cell::sync::Lazy;
use thiserror::Error;

use super::abi::{
    self, dynamic_u256_array, require_selector, selector_of, word_address, word_bool,
    word_bytes32, word_u256, AbiError,
};

// ─── Verified mainnet addresses ─────────────────────────────────────

pub const PUSD: Address = address!("C011a7E12a19f7B1f670d46F03B03f3342E82DFB");
pub const USDC_E: Address = address!("2791Bca1f2de4661ED88A30C99A7a9449Aa84174");
pub const USDC_NATIVE: Address = address!("3c499c542cEF5E3811e1192ce70d8cC03d5c3359");
pub const CTF: Address = address!("4D97DCd97eC945f40cF65F87097ACe5EA0476045");
pub const NEG_RISK_ADAPTER: Address = address!("d91E80cF2E7be2e162c6513ceD06f1dD0dA35296");
pub const COLLATERAL_ONRAMP: Address = address!("93070a847efEf7F70739046A929D47a521F5B8ee");
pub const COLLATERAL_OFFRAMP: Address = address!("2957922Eb93258b93368531d39fAcCA3B4dC5854");

// ─── Selectors (computed once at module load) ───────────────────────

pub static ERC20_APPROVE: Lazy<[u8; 4]> = Lazy::new(|| selector_of("approve(address,uint256)"));
pub static ERC20_TRANSFER: Lazy<[u8; 4]> =
    Lazy::new(|| selector_of("transfer(address,uint256)"));
pub static ONRAMP_WRAP: Lazy<[u8; 4]> = Lazy::new(|| selector_of("wrap(address,address,uint256)"));
pub static OFFRAMP_UNWRAP: Lazy<[u8; 4]> =
    Lazy::new(|| selector_of("unwrap(address,address,uint256)"));
pub static CTF_REDEEM: Lazy<[u8; 4]> = Lazy::new(|| {
    selector_of("redeemPositions(address,bytes32,bytes32,uint256[])")
});
pub static NEG_RISK_REDEEM: Lazy<[u8; 4]> =
    Lazy::new(|| selector_of("redeemPositions(bytes32,uint256[])"));
pub static CTF_SPLIT: Lazy<[u8; 4]> = Lazy::new(|| {
    selector_of("splitPosition(address,bytes32,bytes32,uint256[],uint256)")
});
pub static CTF_MERGE: Lazy<[u8; 4]> = Lazy::new(|| {
    selector_of("mergePositions(address,bytes32,bytes32,uint256[],uint256)")
});

#[derive(Debug, Error)]
pub enum FlowError {
    #[error("abi decode: {0}")]
    Abi(#[from] AbiError),

    #[error("expected target {expected}, got {actual}")]
    WrongTarget { expected: Address, actual: Address },

    #[error("spender {actual} not in allowed set")]
    SpenderNotAllowed { actual: Address },

    #[error("approve amount {amount} exceeds max {max}")]
    ApproveAmountExceedsMax { amount: U256, max: U256 },

    #[error("amount {amount} exceeds intent max {max}")]
    AmountExceedsIntent { amount: U256, max: U256 },

    #[error("recipient {actual} != intent {expected}")]
    WrongRecipient { actual: Address, expected: Address },

    #[error("condition id mismatch")]
    WrongConditionId,

    #[error("collateral {actual} != pUSD")]
    WrongCollateral { actual: Address },

    #[error("parentCollectionId must be zero, got non-zero")]
    NonZeroParentCollection,

    #[error("partition mismatch (intent len {intent_len} vs decoded len {decoded_len})")]
    PartitionLengthMismatch { intent_len: usize, decoded_len: usize },

    #[error("partition value mismatch at index {index}")]
    PartitionValueMismatch { index: usize },

    #[error("redeem amounts include unauthorized non-zero outcome at index {0}")]
    UnauthorizedAmount(usize),

    #[error("redeem outcome_index {0} out of bounds (len {1})")]
    OutcomeIndexOob(usize, usize),

    #[error("redeem indexSets do not match intent.outcome_index")]
    IndexSetsMismatch,
}

// ─── ERC20 transfer ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Erc20TransferIntent {
    /// The ERC20 token contract that calldata must `to`.
    pub token: Address,
    pub recipient: Address,
    pub amount: U256,
}

/// `transfer(address recipient, uint256 amount)`.
pub fn validate_erc20_transfer(
    call_target: Address,
    calldata: &[u8],
    intent: &Erc20TransferIntent,
) -> Result<(), FlowError> {
    if call_target != intent.token {
        return Err(FlowError::WrongTarget {
            expected: intent.token,
            actual: call_target,
        });
    }
    let args = require_selector(calldata, *ERC20_TRANSFER)?;
    let recipient = word_address(args, 0)?;
    let amount = word_u256(args, 1)?;
    if recipient != intent.recipient {
        return Err(FlowError::WrongRecipient {
            actual: recipient,
            expected: intent.recipient,
        });
    }
    if amount != intent.amount {
        return Err(FlowError::AmountExceedsIntent {
            amount,
            max: intent.amount,
        });
    }
    Ok(())
}

// ─── ERC20 approve (used inside pUSD wrap/unwrap composites) ────────

#[derive(Debug, Clone)]
pub struct Erc20ApproveIntent {
    pub token: Address,
    pub spender: Address,
    pub max_amount: U256,
}

pub fn validate_erc20_approve(
    call_target: Address,
    calldata: &[u8],
    intent: &Erc20ApproveIntent,
) -> Result<U256, FlowError> {
    if call_target != intent.token {
        return Err(FlowError::WrongTarget {
            expected: intent.token,
            actual: call_target,
        });
    }
    let args = require_selector(calldata, *ERC20_APPROVE)?;
    let spender = word_address(args, 0)?;
    let amount = word_u256(args, 1)?;
    if spender != intent.spender {
        return Err(FlowError::SpenderNotAllowed { actual: spender });
    }
    if amount > intent.max_amount {
        return Err(FlowError::ApproveAmountExceedsMax {
            amount,
            max: intent.max_amount,
        });
    }
    Ok(amount)
}

// ─── pUSD wrap (Onramp.wrap) ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PusdWrapIntent {
    /// The USDC variant being wrapped (native or USDC.e).
    pub source_token: Address,
    pub deposit_wallet: Address,
    pub max_amount: U256,
}

/// `wrap(address asset, address to, uint256 amount)` on CollateralOnramp.
pub fn validate_pusd_wrap(
    call_target: Address,
    calldata: &[u8],
    intent: &PusdWrapIntent,
) -> Result<U256, FlowError> {
    if call_target != COLLATERAL_ONRAMP {
        return Err(FlowError::WrongTarget {
            expected: COLLATERAL_ONRAMP,
            actual: call_target,
        });
    }
    let args = require_selector(calldata, *ONRAMP_WRAP)?;
    let asset = word_address(args, 0)?;
    let to = word_address(args, 1)?;
    let amount = word_u256(args, 2)?;
    if asset != intent.source_token {
        return Err(FlowError::WrongTarget {
            expected: intent.source_token,
            actual: asset,
        });
    }
    if to != intent.deposit_wallet {
        return Err(FlowError::WrongRecipient {
            expected: intent.deposit_wallet,
            actual: to,
        });
    }
    if amount > intent.max_amount {
        return Err(FlowError::AmountExceedsIntent {
            amount,
            max: intent.max_amount,
        });
    }
    Ok(amount)
}

// ─── CTF redeem (regular markets) ───────────────────────────────────

#[derive(Debug, Clone)]
pub struct CtfRedeemIntent {
    pub condition_id: B256,
    /// User's chosen outcome index (0..31).
    pub outcome_index: u8,
}

/// `redeemPositions(address collateral, bytes32 parentCollectionId, bytes32 conditionId, uint256[] indexSets)`.
pub fn validate_ctf_redeem(
    call_target: Address,
    calldata: &[u8],
    intent: &CtfRedeemIntent,
) -> Result<(), FlowError> {
    if call_target != CTF {
        return Err(FlowError::WrongTarget {
            expected: CTF,
            actual: call_target,
        });
    }
    let args = require_selector(calldata, *CTF_REDEEM)?;
    let collateral = word_address(args, 0)?;
    let parent_collection = word_bytes32(args, 1)?;
    let condition_id = word_bytes32(args, 2)?;
    let index_sets = dynamic_u256_array(args, 4, 3)?;

    if collateral != PUSD {
        return Err(FlowError::WrongCollateral { actual: collateral });
    }
    if parent_collection != B256::ZERO {
        return Err(FlowError::NonZeroParentCollection);
    }
    if condition_id != intent.condition_id {
        return Err(FlowError::WrongConditionId);
    }
    // The union of indexSets must equal exactly (1 << outcome_index).
    let expected = U256::from(1u64) << (intent.outcome_index as usize);
    let mut union = U256::ZERO;
    for s in &index_sets {
        union |= *s;
    }
    if union != expected {
        return Err(FlowError::IndexSetsMismatch);
    }
    Ok(())
}

// ─── NegRisk redeem ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NegRiskRedeemIntent {
    pub condition_id: B256,
    pub outcome_index: u8,
    /// Max amount the user authorized for this outcome.
    pub max_amount: U256,
}

/// `redeemPositions(bytes32 conditionId, uint256[] amounts)` on NegRiskAdapter.
pub fn validate_neg_risk_redeem(
    call_target: Address,
    calldata: &[u8],
    intent: &NegRiskRedeemIntent,
) -> Result<(), FlowError> {
    if call_target != NEG_RISK_ADAPTER {
        return Err(FlowError::WrongTarget {
            expected: NEG_RISK_ADAPTER,
            actual: call_target,
        });
    }
    let args = require_selector(calldata, *NEG_RISK_REDEEM)?;
    let condition_id = word_bytes32(args, 0)?;
    let amounts = dynamic_u256_array(args, 2, 1)?;

    if condition_id != intent.condition_id {
        return Err(FlowError::WrongConditionId);
    }
    let oi = intent.outcome_index as usize;
    if oi >= amounts.len() {
        return Err(FlowError::OutcomeIndexOob(oi, amounts.len()));
    }
    for (i, a) in amounts.iter().enumerate() {
        if i != oi && *a != U256::ZERO {
            return Err(FlowError::UnauthorizedAmount(i));
        }
    }
    if amounts[oi] > intent.max_amount {
        return Err(FlowError::AmountExceedsIntent {
            amount: amounts[oi],
            max: intent.max_amount,
        });
    }
    Ok(())
}

// Suppress unused-import warnings for helpers exercised in different
// branches by future flows.
#[allow(dead_code)]
fn _abi_anchor(_: &dyn Fn() -> Result<(), abi::AbiError>) {}
#[allow(dead_code)]
fn _word_bool_anchor(_: &[u8]) -> Result<bool, abi::AbiError> {
    word_bool(&[0u8; 32], 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_transfer_calldata(recipient: Address, amount: U256) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 64);
        out.extend_from_slice(&*ERC20_TRANSFER);
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(recipient.as_slice());
        out.extend_from_slice(&w);
        out.extend_from_slice(&amount.to_be_bytes::<32>());
        out
    }

    #[test]
    fn erc20_transfer_happy_path() {
        let recipient = Address::from_slice(&[0xab; 20]);
        let amount = U256::from(1_000_000u64);
        let calldata = build_transfer_calldata(recipient, amount);
        validate_erc20_transfer(
            PUSD,
            &calldata,
            &Erc20TransferIntent {
                token: PUSD,
                recipient,
                amount,
            },
        )
        .unwrap();
    }

    #[test]
    fn erc20_transfer_rejects_recipient_mismatch() {
        let calldata = build_transfer_calldata(Address::ZERO, U256::from(1u64));
        let err = validate_erc20_transfer(
            PUSD,
            &calldata,
            &Erc20TransferIntent {
                token: PUSD,
                recipient: Address::from_slice(&[0x42; 20]),
                amount: U256::from(1u64),
            },
        )
        .unwrap_err();
        assert!(matches!(err, FlowError::WrongRecipient { .. }));
    }

    #[test]
    fn approve_amount_capped() {
        let spender = Address::from_slice(&[0xee; 20]);
        let calldata = {
            let mut out = Vec::with_capacity(4 + 64);
            out.extend_from_slice(&*ERC20_APPROVE);
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(spender.as_slice());
            out.extend_from_slice(&w);
            out.extend_from_slice(&U256::from(500u64).to_be_bytes::<32>());
            out
        };
        // amount=500 ≤ max=1000 → ok
        let amount = validate_erc20_approve(
            PUSD,
            &calldata,
            &Erc20ApproveIntent {
                token: PUSD,
                spender,
                max_amount: U256::from(1000u64),
            },
        )
        .unwrap();
        assert_eq!(amount, U256::from(500u64));
        // amount=500 > max=100 → reject
        let err = validate_erc20_approve(
            PUSD,
            &calldata,
            &Erc20ApproveIntent {
                token: PUSD,
                spender,
                max_amount: U256::from(100u64),
            },
        )
        .unwrap_err();
        assert!(matches!(err, FlowError::ApproveAmountExceedsMax { .. }));
    }
}
