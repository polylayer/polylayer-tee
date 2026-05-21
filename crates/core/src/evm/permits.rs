//! EIP-2612 USDC permit signer (Arbitrum).
//!
//! Mirrors `eigen-tee/src/lib/usdcPermit.ts`. Used by
//! `/v1/sign/hl-bridge-permit` to authorize the Hyperliquid Bridge2
//! contract to pull USDC from the user's TEE-derived EVM address.
//!
//! Domain on Arbitrum (per Circle's FiatTokenV2_2 bytecode):
//! ```text
//!   name              = "USD Coin"
//!   version           = "2"
//!   chainId           = 42161
//!   verifyingContract = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831
//! ```
//!
//! Permit struct (EIP-2612):
//! ```text
//!   Permit(address owner, address spender, uint256 value,
//!          uint256 nonce, uint256 deadline)
//! ```

use alloy_primitives::{address, Address, B256, U256};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use once_cell::sync::Lazy;
use sha3::{Digest, Keccak256};
use thiserror::Error;

use crate::derive::evm_address_from_verifying_key;

/// USDC on Arbitrum (Circle's native, post canonical-bridge migration).
pub const USDC_ARBITRUM_ADDRESS: Address = address!("af88d065e77c8cC2239327C5EDb3A432268e5831");

/// Hyperliquid Bridge2 on Arbitrum mainnet — spender + recipient for
/// `batchedDepositWithPermit`.
pub const HL_BRIDGE2_ARBITRUM_ADDRESS: Address =
    address!("2df1c51e09aecf9cacb7bc98cb1742757f163df7");

pub const ARBITRUM_CHAIN_ID: u64 = 42161;

const EIP712_DOMAIN_TYPE_STRING: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const PERMIT_TYPE_STRING: &str =
    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";

static EIP712_DOMAIN_TYPE_HASH: Lazy<B256> =
    Lazy::new(|| keccak256_to_b256(EIP712_DOMAIN_TYPE_STRING.as_bytes()));
static PERMIT_TYPE_HASH: Lazy<B256> = Lazy::new(|| keccak256_to_b256(PERMIT_TYPE_STRING.as_bytes()));
static USDC_NAME_HASH: Lazy<B256> = Lazy::new(|| keccak256_to_b256(b"USD Coin"));
static USDC_VERSION_HASH: Lazy<B256> = Lazy::new(|| keccak256_to_b256(b"2"));

#[derive(Debug, Error)]
pub enum PermitError {
    #[error("owner {owner} != derived EOA {derived}")]
    OwnerMismatch { owner: Address, derived: Address },

    #[error("malformed private key: {0}")]
    BadKey(String),

    #[error("signing failed: {0}")]
    Sign(String),
}

#[derive(Debug, Clone)]
pub struct Erc2612PermitSplitSig {
    pub r: B256,
    pub s: B256,
    /// Always 27 or 28.
    pub v: u8,
    /// Full 65-byte signature for callers that prefer that form.
    pub signature: [u8; 65],
}

pub fn sign_usdc_permit_arbitrum(
    priv_key: &[u8; 32],
    owner: Address,
    spender: Address,
    value: U256,
    nonce: U256,
    deadline: U256,
) -> Result<Erc2612PermitSplitSig, PermitError> {
    let signing_key =
        SigningKey::from_bytes(priv_key.into()).map_err(|e| PermitError::BadKey(e.to_string()))?;
    let derived = evm_address_from_verifying_key(signing_key.verifying_key());
    if derived != owner {
        return Err(PermitError::OwnerMismatch { owner, derived });
    }

    // Domain separator: name="USD Coin", version="2", chainId=42161,
    // verifyingContract=USDC_ARBITRUM_ADDRESS.
    let mut domain_buf = [0u8; 32 * 5];
    domain_buf[0..32].copy_from_slice(EIP712_DOMAIN_TYPE_HASH.as_slice());
    domain_buf[32..64].copy_from_slice(USDC_NAME_HASH.as_slice());
    domain_buf[64..96].copy_from_slice(USDC_VERSION_HASH.as_slice());
    domain_buf[96..128].copy_from_slice(&U256::from(ARBITRUM_CHAIN_ID).to_be_bytes::<32>());
    domain_buf[128 + 12..160].copy_from_slice(USDC_ARBITRUM_ADDRESS.as_slice());
    let domain_sep = keccak256_to_b256(&domain_buf);

    // Permit struct hash.
    let mut struct_buf = [0u8; 32 * 6];
    struct_buf[0..32].copy_from_slice(PERMIT_TYPE_HASH.as_slice());
    struct_buf[32 + 12..64].copy_from_slice(owner.as_slice());
    struct_buf[64 + 12..96].copy_from_slice(spender.as_slice());
    struct_buf[96..128].copy_from_slice(&value.to_be_bytes::<32>());
    struct_buf[128..160].copy_from_slice(&nonce.to_be_bytes::<32>());
    struct_buf[160..192].copy_from_slice(&deadline.to_be_bytes::<32>());
    let struct_hash = keccak256_to_b256(&struct_buf);

    // EIP-712 digest.
    let mut digest_buf = [0u8; 2 + 32 + 32];
    digest_buf[0] = 0x19;
    digest_buf[1] = 0x01;
    digest_buf[2..34].copy_from_slice(domain_sep.as_slice());
    digest_buf[34..66].copy_from_slice(struct_hash.as_slice());
    let digest: [u8; 32] = Keccak256::digest(digest_buf).into();

    let (sig, recovery_id): (Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(&digest)
        .map_err(|e| PermitError::Sign(e.to_string()))?;
    let r_s: [u8; 64] = sig.to_bytes().into();
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&r_s);
    let v = 27 + recovery_id.to_byte();
    signature[64] = v;

    Ok(Erc2612PermitSplitSig {
        r: B256::from_slice(&r_s[..32]),
        s: B256::from_slice(&r_s[32..]),
        v,
        signature,
    })
}

fn keccak256_to_b256(input: &[u8]) -> B256 {
    B256::from_slice(Keccak256::digest(input).as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::Master;

    const HARDHAT: &str = "test test test test test test test test test test test junk";

    #[test]
    fn rejects_wrong_owner() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let err = sign_usdc_permit_arbitrum(
            &acct.private_key.0,
            Address::ZERO, // wrong owner
            HL_BRIDGE2_ARBITRUM_ADDRESS,
            U256::from(1_000_000u64),
            U256::ZERO,
            U256::from(2_000_000_000u64),
        )
        .unwrap_err();
        assert!(matches!(err, PermitError::OwnerMismatch { .. }));
    }

    #[test]
    fn sign_produces_valid_split_sig() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let sig = sign_usdc_permit_arbitrum(
            &acct.private_key.0,
            acct.address,
            HL_BRIDGE2_ARBITRUM_ADDRESS,
            U256::from(1_000_000u64),
            U256::ZERO,
            U256::from(2_000_000_000u64),
        )
        .unwrap();
        assert_eq!(sig.signature.len(), 65);
        assert!(sig.v == 27 || sig.v == 28);
        // r||s split echoes the bytes.
        assert_eq!(&sig.signature[..32], sig.r.as_slice());
        assert_eq!(&sig.signature[32..64], sig.s.as_slice());
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let a = sign_usdc_permit_arbitrum(
            &acct.private_key.0,
            acct.address,
            HL_BRIDGE2_ARBITRUM_ADDRESS,
            U256::from(7u64),
            U256::from(3u64),
            U256::from(2_000_000_000u64),
        )
        .unwrap();
        let b = sign_usdc_permit_arbitrum(
            &acct.private_key.0,
            acct.address,
            HL_BRIDGE2_ARBITRUM_ADDRESS,
            U256::from(7u64),
            U256::from(3u64),
            U256::from(2_000_000_000u64),
        )
        .unwrap();
        assert_eq!(a.signature, b.signature);
    }

    #[test]
    fn value_change_changes_sig() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let a = sign_usdc_permit_arbitrum(
            &acct.private_key.0,
            acct.address,
            HL_BRIDGE2_ARBITRUM_ADDRESS,
            U256::from(1u64),
            U256::ZERO,
            U256::from(2_000_000_000u64),
        )
        .unwrap();
        let b = sign_usdc_permit_arbitrum(
            &acct.private_key.0,
            acct.address,
            HL_BRIDGE2_ARBITRUM_ADDRESS,
            U256::from(2u64),
            U256::ZERO,
            U256::from(2_000_000_000u64),
        )
        .unwrap();
        assert_ne!(a.signature, b.signature);
    }
}
