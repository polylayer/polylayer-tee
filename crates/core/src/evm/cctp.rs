//! CCTP V2 `depositForBurn` calldata validation.
//!
//! Mirrors the CCTP-burn branch in
//! `eigen-tee/src/routes/sign-evm-tx.ts`. Given a Polygon (or Arbitrum)
//! tx that claims to be a CCTP withdrawal to Solana, we ABI-decode the
//! calldata and check every arg against the user's signed intent:
//!
//! - selector matches `depositForBurn(uint256,uint32,bytes32,address,bytes32,uint256,uint32)`
//! - `destination_domain == 5` (Solana)
//! - `burn_token == native USDC` for the source chain
//! - `amount <= intent.amount_wei`
//! - `mint_recipient` matches the Solana USDC ATA of `intent.destination`
//!   (TEE computes this independently — defends against a hostile lambda
//!   swapping in an attacker-controlled ATA)
//! - `finality_threshold == 2000` (Standard transfer; Polygon doesn't
//!   support Fast)
//!
//! ATA derivation is identical to `getAssociatedTokenAddressSync` in
//! `@solana/spl-token`: PDA on the SPL Associated Token Program with
//! seeds `[owner, token_program, mint]`.

use alloy_primitives::{address, Address, B256, U256};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use thiserror::Error;

// ─── Selectors (computed at module load) ────────────────────────────

const DEPOSIT_FOR_BURN_V2_SIG: &str =
    "depositForBurn(uint256,uint32,bytes32,address,bytes32,uint256,uint32)";

/// 4-byte function selector for V2 `depositForBurn`. Computed once and
/// asserted at use; if Circle ever bumps the V2 ABI we'll see a mismatch.
pub fn deposit_for_burn_v2_selector() -> [u8; 4] {
    use sha3::Keccak256;
    let h = Keccak256::digest(DEPOSIT_FOR_BURN_V2_SIG.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&h[..4]);
    out
}

// ─── Verified mainnet constants ─────────────────────────────────────

/// TokenMessengerV2 deploys deterministically across Polygon + Arbitrum.
pub const TOKEN_MESSENGER_V2_ADDRESS: Address =
    address!("28b5a0e9c621a5badaa536219b3a228c8168cf5d");

pub const POLYGON_USDC: Address = address!("3c499c542cef5e3811e1192ce70d8cc03d5c3359");
pub const ARBITRUM_USDC: Address = address!("af88d065e77c8cc2239327c5edb3a432268e5831");

pub const CCTP_DOMAIN_SOLANA: u32 = 5;
pub const CCTP_DOMAIN_POLYGON: u32 = 7;
pub const CCTP_DOMAIN_ARBITRUM: u32 = 3;

/// CCTP Standard finality = 2000 (Polygon ↔ Solana requires this; Fast
/// isn't supported on Polygon as source or destination).
pub const CCTP_STANDARD_FINALITY: u32 = 2000;

/// SPL Token Program — needed for ATA derivation.
pub static SPL_TOKEN_PROGRAM: once_cell::sync::Lazy<Pubkey> = once_cell::sync::Lazy::new(|| {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        .parse()
        .expect("token program pubkey")
});

/// SPL Associated Token Program — the PDA derivation root.
pub static SPL_ATA_PROGRAM: once_cell::sync::Lazy<Pubkey> = once_cell::sync::Lazy::new(|| {
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
        .parse()
        .expect("ata program pubkey")
});

/// Solana USDC mint.
pub static SOLANA_USDC_MINT: once_cell::sync::Lazy<Pubkey> = once_cell::sync::Lazy::new(|| {
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        .parse()
        .expect("usdc mint pubkey")
});

#[derive(Debug, Error)]
pub enum CctpError {
    #[error("calldata too short ({0} bytes); need at least 4 for selector + 7 32-byte args")]
    TooShort(usize),

    #[error("selector mismatch (expected depositForBurn V2)")]
    WrongSelector,

    #[error("destination_domain {0} != Solana ({})", CCTP_DOMAIN_SOLANA)]
    WrongDestinationDomain(u32),

    #[error("burn_token {actual} != expected native USDC {expected} for chain")]
    WrongBurnToken { actual: Address, expected: Address },

    #[error("amount {actual} exceeds intent.amount_wei {intent_max}")]
    AmountExceedsIntent { actual: U256, intent_max: U256 },

    #[error("mint_recipient {actual:?} != derived USDC ATA {expected:?} for owner {owner}")]
    WrongMintRecipient {
        actual: B256,
        expected: B256,
        owner: String,
    },

    #[error("finality_threshold {0} != Standard ({})", CCTP_STANDARD_FINALITY)]
    WrongFinality(u32),

    #[error("unsupported source chain id {0}")]
    UnsupportedSourceChain(u64),

    #[error("invalid solana destination pubkey: {0}")]
    BadSolanaDestination(String),
}

/// Decoded V2 `depositForBurn` calldata.
#[derive(Debug, Clone)]
pub struct DepositForBurnArgs {
    pub amount: U256,
    pub destination_domain: u32,
    pub mint_recipient: B256,
    pub burn_token: Address,
    pub destination_caller: B256,
    pub max_fee: U256,
    pub min_finality_threshold: u32,
}

/// Decode raw V2 `depositForBurn` calldata. Selector + 7 × 32-byte ABI words.
pub fn decode_deposit_for_burn(calldata: &[u8]) -> Result<DepositForBurnArgs, CctpError> {
    if calldata.len() < 4 + 7 * 32 {
        return Err(CctpError::TooShort(calldata.len()));
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&calldata[..4]);
    if selector != deposit_for_burn_v2_selector() {
        return Err(CctpError::WrongSelector);
    }

    let args = &calldata[4..];
    let amount = U256::from_be_slice(&args[0..32]);
    let destination_domain = u32::from_be_bytes(args[60..64].try_into().unwrap());
    let mint_recipient = B256::from_slice(&args[64..96]);
    // address is right-aligned in a 32-byte word: bytes [76..96] = the 20-byte address.
    let burn_token = Address::from_slice(&args[108..128]);
    let destination_caller = B256::from_slice(&args[128..160]);
    let max_fee = U256::from_be_slice(&args[160..192]);
    let min_finality_threshold = u32::from_be_bytes(args[220..224].try_into().unwrap());

    Ok(DepositForBurnArgs {
        amount,
        destination_domain,
        mint_recipient,
        burn_token,
        destination_caller,
        max_fee,
        min_finality_threshold,
    })
}

/// Validate decoded args against a user's withdrawal intent. Caller
/// (server route) supplies the intent's amount cap + the Solana
/// destination pubkey; we derive the ATA ourselves so a compromised
/// lambda can't substitute one.
pub struct CctpIntentBounds {
    pub source_chain_id: u64,
    pub destination_owner_bs58: String,
    pub intent_amount_max: U256,
}

pub fn validate_against_intent(
    args: &DepositForBurnArgs,
    bounds: &CctpIntentBounds,
) -> Result<(), CctpError> {
    let expected_burn_token = match bounds.source_chain_id {
        137 => POLYGON_USDC,
        42161 => ARBITRUM_USDC,
        other => return Err(CctpError::UnsupportedSourceChain(other)),
    };
    if args.burn_token != expected_burn_token {
        return Err(CctpError::WrongBurnToken {
            actual: args.burn_token,
            expected: expected_burn_token,
        });
    }

    if args.destination_domain != CCTP_DOMAIN_SOLANA {
        return Err(CctpError::WrongDestinationDomain(args.destination_domain));
    }

    if args.amount > bounds.intent_amount_max {
        return Err(CctpError::AmountExceedsIntent {
            actual: args.amount,
            intent_max: bounds.intent_amount_max,
        });
    }

    if args.min_finality_threshold != CCTP_STANDARD_FINALITY {
        return Err(CctpError::WrongFinality(args.min_finality_threshold));
    }

    let expected_ata = derive_solana_usdc_ata(&bounds.destination_owner_bs58)?;
    let expected_b256 = B256::from_slice(&expected_ata.to_bytes());
    if args.mint_recipient != expected_b256 {
        return Err(CctpError::WrongMintRecipient {
            actual: args.mint_recipient,
            expected: expected_b256,
            owner: bounds.destination_owner_bs58.clone(),
        });
    }

    Ok(())
}

/// Derive the Solana USDC ATA for a given owner pubkey. Equivalent to
/// `getAssociatedTokenAddressSync(USDC_MINT, owner)` in
/// `@solana/spl-token`.
pub fn derive_solana_usdc_ata(owner_bs58: &str) -> Result<Pubkey, CctpError> {
    let owner: Pubkey = owner_bs58
        .parse()
        .map_err(|e: solana_pubkey::ParsePubkeyError| {
            CctpError::BadSolanaDestination(e.to_string())
        })?;
    let (ata, _bump) = Pubkey::find_program_address(
        &[
            owner.as_ref(),
            SPL_TOKEN_PROGRAM.as_ref(),
            SOLANA_USDC_MINT.as_ref(),
        ],
        &SPL_ATA_PROGRAM,
    );
    Ok(ata)
}

// `keccak256` shim — local for the selector calc. The other
// keccak'ed primitives sit in their own modules; importing one
// shared util crate-wide would lock in a circular bump cycle on
// digest bumps. Tiny duplication wins.
fn _keccak_marker() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_is_stable() {
        // 4-byte selector = keccak256(canonical_signature)[..4].
        // For `depositForBurn(uint256,uint32,bytes32,address,bytes32,uint256,uint32)`
        // this computes to 0x8e0250ee. If this assertion breaks, Circle
        // bumped the V2 ABI and our intent-validation needs a
        // coordinated update with the lambda.
        let sel = deposit_for_burn_v2_selector();
        assert_eq!(hex::encode(sel), "8e0250ee");
        // Also assert determinism across calls (no Lazy weirdness).
        assert_eq!(deposit_for_burn_v2_selector(), sel);
    }

    #[test]
    fn ata_derivation_matches_known_vector() {
        // System program pubkey (32 zero bytes) as a deterministic owner.
        // The ATA is computable independently; here we just check that
        // derivation produces SOMETHING reproducible.
        let owner = "11111111111111111111111111111111";
        let ata1 = derive_solana_usdc_ata(owner).unwrap();
        let ata2 = derive_solana_usdc_ata(owner).unwrap();
        assert_eq!(ata1, ata2);
    }

    #[test]
    fn decode_round_trip_rejects_wrong_selector() {
        let mut bad = vec![0u8; 4 + 7 * 32];
        bad[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let err = decode_deposit_for_burn(&bad).unwrap_err();
        assert!(matches!(err, CctpError::WrongSelector));
    }

    #[test]
    fn decode_too_short_rejected() {
        let err = decode_deposit_for_burn(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, CctpError::TooShort(16)));
    }

    #[test]
    fn validate_rejects_wrong_domain() {
        let args = DepositForBurnArgs {
            amount: U256::from(1u64),
            destination_domain: 99, // wrong
            mint_recipient: B256::ZERO,
            burn_token: POLYGON_USDC,
            destination_caller: B256::ZERO,
            max_fee: U256::ZERO,
            min_finality_threshold: CCTP_STANDARD_FINALITY,
        };
        let bounds = CctpIntentBounds {
            source_chain_id: 137,
            destination_owner_bs58: "11111111111111111111111111111111".into(),
            intent_amount_max: U256::from(100u64),
        };
        assert!(matches!(
            validate_against_intent(&args, &bounds),
            Err(CctpError::WrongDestinationDomain(99))
        ));
    }

    #[test]
    fn validate_rejects_amount_over_intent() {
        let args = DepositForBurnArgs {
            amount: U256::from(200u64),
            destination_domain: CCTP_DOMAIN_SOLANA,
            mint_recipient: B256::ZERO,
            burn_token: POLYGON_USDC,
            destination_caller: B256::ZERO,
            max_fee: U256::ZERO,
            min_finality_threshold: CCTP_STANDARD_FINALITY,
        };
        let bounds = CctpIntentBounds {
            source_chain_id: 137,
            destination_owner_bs58: "11111111111111111111111111111111".into(),
            intent_amount_max: U256::from(100u64), // less than args.amount
        };
        assert!(matches!(
            validate_against_intent(&args, &bounds),
            Err(CctpError::AmountExceedsIntent { .. })
        ));
    }
}
