//! DepositWallet.Batch signing for atomic multi-call flows.
//!
//! Mirrors `signDepositWalletBatch` from
//! `eigen-tee/src/lib/polymarketDepositWallet.ts`. The batch validation
//! helpers (assert_pusd_wrap_batch, assert_polymarket_split_batch, etc.)
//! are security-critical — they verify the lambda-supplied calldata
//! matches the user's signed intent. Those live in a separate task
//! (#189) blocked by parity-fixture generation (#170) because writing
//! ~500 LOC of ABI-decoding validation without ground-truth test vectors
//! invites silent malicious-calldata vulnerabilities.

use alloy_primitives::{Address, B256, U256};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use once_cell::sync::Lazy;
use sha3::{Digest, Keccak256};
use thiserror::Error;

use super::constants::{
    DEPOSIT_WALLET_DOMAIN_NAME_HASH, DEPOSIT_WALLET_DOMAIN_VERSION_HASH, EIP712_DOMAIN_TYPE_HASH,
    POLYGON_CHAIN_ID,
};
use crate::derive::evm_address_from_verifying_key;

#[derive(Debug, Error)]
pub enum BatchError {
    #[error("malformed private key: {0}")]
    BadKey(String),

    #[error("signing failed: {0}")]
    Sign(String),

    #[error("batch must be non-empty")]
    EmptyBatch,

    #[error("batch length {0} exceeds max 24")]
    BatchTooLong(usize),
}

/// A single call within a DepositWallet.Batch.
#[derive(Debug, Clone)]
pub struct DepositWalletCall {
    pub target: Address,
    pub value: U256,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DepositWalletBatchSignature {
    /// 65-byte EIP-712 signature (r || s || v=27|28).
    pub signature: [u8; 65],
    pub evm_address: Address,
    pub wallet_address: Address,
}

pub struct SignBatchArgs<'a> {
    pub priv_key: &'a [u8; 32],
    pub wallet_address: Address,
    pub nonce: U256,
    pub deadline: U256,
    pub calls: &'a [DepositWalletCall],
}

// ─── EIP-712 type strings ────────────────────────────────────────────

pub const CALL_TYPE_STRING: &str = "Call(address target,uint256 value,bytes data)";
pub const BATCH_TYPE_STRING: &str =
    "Batch(address wallet,uint256 nonce,uint256 deadline,Call[] calls)Call(address target,uint256 value,bytes data)";

static CALL_TYPE_HASH: Lazy<B256> = Lazy::new(|| keccak256_to_b256(CALL_TYPE_STRING.as_bytes()));
static BATCH_TYPE_HASH: Lazy<B256> = Lazy::new(|| keccak256_to_b256(BATCH_TYPE_STRING.as_bytes()));

pub fn sign_deposit_wallet_batch(
    args: SignBatchArgs<'_>,
) -> Result<DepositWalletBatchSignature, BatchError> {
    if args.calls.is_empty() {
        return Err(BatchError::EmptyBatch);
    }
    if args.calls.len() > 24 {
        return Err(BatchError::BatchTooLong(args.calls.len()));
    }

    let signing_key =
        SigningKey::from_bytes(args.priv_key.into()).map_err(|e| BatchError::BadKey(e.to_string()))?;
    let evm_address = evm_address_from_verifying_key(signing_key.verifying_key());

    // Domain separator: DepositWallet domain, verifying = wallet itself.
    let domain_sep = batch_domain_separator(args.wallet_address);
    let batch_hash = hash_struct_batch(
        args.wallet_address,
        args.nonce,
        args.deadline,
        args.calls,
    );
    let digest = eip712_digest(domain_sep, batch_hash);

    let (sig, recovery_id): (Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(&digest)
        .map_err(|e| BatchError::Sign(e.to_string()))?;
    let signature = pack_eth_signature(sig, recovery_id);

    Ok(DepositWalletBatchSignature {
        signature,
        evm_address,
        wallet_address: args.wallet_address,
    })
}

fn batch_domain_separator(wallet_address: Address) -> B256 {
    let mut buf = [0u8; 32 * 5];
    buf[0..32].copy_from_slice(EIP712_DOMAIN_TYPE_HASH.as_slice());
    buf[32..64].copy_from_slice(DEPOSIT_WALLET_DOMAIN_NAME_HASH.as_slice());
    buf[64..96].copy_from_slice(DEPOSIT_WALLET_DOMAIN_VERSION_HASH.as_slice());
    buf[96..128].copy_from_slice(&U256::from(POLYGON_CHAIN_ID).to_be_bytes::<32>());
    buf[128 + 12..160].copy_from_slice(wallet_address.as_slice());
    keccak256_to_b256(&buf)
}

fn hash_struct_batch(
    wallet: Address,
    nonce: U256,
    deadline: U256,
    calls: &[DepositWalletCall],
) -> B256 {
    // Per EIP-712 dynamic array encoding: enc(Call[]) = keccak256(
    //   concat(hashStruct(call_i) for each call_i)
    // )
    let mut calls_concat = Vec::with_capacity(calls.len() * 32);
    for call in calls {
        let h = hash_struct_call(call);
        calls_concat.extend_from_slice(h.as_slice());
    }
    let calls_hash = keccak256_to_b256(&calls_concat);

    let mut buf = [0u8; 32 * 5];
    buf[0..32].copy_from_slice(BATCH_TYPE_HASH.as_slice());
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(wallet.as_slice());
    buf[32..64].copy_from_slice(&w);
    buf[64..96].copy_from_slice(&nonce.to_be_bytes::<32>());
    buf[96..128].copy_from_slice(&deadline.to_be_bytes::<32>());
    buf[128..160].copy_from_slice(calls_hash.as_slice());
    keccak256_to_b256(&buf)
}

fn hash_struct_call(call: &DepositWalletCall) -> B256 {
    let mut buf = [0u8; 32 * 4];
    buf[0..32].copy_from_slice(CALL_TYPE_HASH.as_slice());
    let mut t = [0u8; 32];
    t[12..].copy_from_slice(call.target.as_slice());
    buf[32..64].copy_from_slice(&t);
    buf[64..96].copy_from_slice(&call.value.to_be_bytes::<32>());
    // bytes type encoding: keccak256(bytes).
    let data_hash = keccak256_to_b256(&call.data);
    buf[96..128].copy_from_slice(data_hash.as_slice());
    keccak256_to_b256(&buf)
}

fn eip712_digest(domain_separator: B256, struct_hash: B256) -> [u8; 32] {
    let mut buf = [0u8; 2 + 32 + 32];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain_separator.as_slice());
    buf[34..66].copy_from_slice(struct_hash.as_slice());
    Keccak256::digest(buf).into()
}

fn pack_eth_signature(sig: Signature, recovery_id: RecoveryId) -> [u8; 65] {
    let mut out = [0u8; 65];
    let r_s: [u8; 64] = sig.to_bytes().into();
    out[..64].copy_from_slice(&r_s);
    out[64] = 27 + recovery_id.to_byte();
    out
}

fn keccak256_to_b256(input: &[u8]) -> B256 {
    B256::from_slice(Keccak256::digest(input).as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::Master;

    const HARDHAT: &str = "test test test test test test test test test test test junk";

    fn build_call() -> DepositWalletCall {
        DepositWalletCall {
            target: Address::from_slice(&[0x42; 20]),
            value: U256::ZERO,
            data: vec![0xa9, 0x05, 0x9c, 0xbb], // ERC20 transfer selector
        }
    }

    #[test]
    fn sign_batch_rejects_empty() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let err = sign_deposit_wallet_batch(SignBatchArgs {
            priv_key: &acct.private_key.0,
            wallet_address: acct.address,
            nonce: U256::ZERO,
            deadline: U256::MAX,
            calls: &[],
        })
        .unwrap_err();
        assert!(matches!(err, BatchError::EmptyBatch));
    }

    #[test]
    fn sign_batch_rejects_too_many_calls() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let calls: Vec<_> = (0..25).map(|_| build_call()).collect();
        let err = sign_deposit_wallet_batch(SignBatchArgs {
            priv_key: &acct.private_key.0,
            wallet_address: acct.address,
            nonce: U256::ZERO,
            deadline: U256::MAX,
            calls: &calls,
        })
        .unwrap_err();
        assert!(matches!(err, BatchError::BatchTooLong(25)));
    }

    #[test]
    fn sign_batch_produces_65_byte_sig() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let calls = vec![build_call()];
        let sig = sign_deposit_wallet_batch(SignBatchArgs {
            priv_key: &acct.private_key.0,
            wallet_address: acct.address,
            nonce: U256::from(1u64),
            deadline: U256::from(2_000_000_000u64),
            calls: &calls,
        })
        .unwrap();
        assert_eq!(sig.signature.len(), 65);
        assert!(sig.signature[64] == 27 || sig.signature[64] == 28);
        assert_eq!(sig.evm_address, acct.address);
    }

    #[test]
    fn sign_batch_is_deterministic() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let calls = vec![build_call()];
        let a = sign_deposit_wallet_batch(SignBatchArgs {
            priv_key: &acct.private_key.0,
            wallet_address: acct.address,
            nonce: U256::from(7u64),
            deadline: U256::from(2_000_000_000u64),
            calls: &calls,
        })
        .unwrap();
        let b = sign_deposit_wallet_batch(SignBatchArgs {
            priv_key: &acct.private_key.0,
            wallet_address: acct.address,
            nonce: U256::from(7u64),
            deadline: U256::from(2_000_000_000u64),
            calls: &calls,
        })
        .unwrap();
        assert_eq!(a.signature, b.signature);
    }

    #[test]
    fn sign_batch_changes_with_nonce() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let calls = vec![build_call()];
        let a = sign_deposit_wallet_batch(SignBatchArgs {
            priv_key: &acct.private_key.0,
            wallet_address: acct.address,
            nonce: U256::from(1u64),
            deadline: U256::from(2_000_000_000u64),
            calls: &calls,
        })
        .unwrap();
        let b = sign_deposit_wallet_batch(SignBatchArgs {
            priv_key: &acct.private_key.0,
            wallet_address: acct.address,
            nonce: U256::from(2u64),
            deadline: U256::from(2_000_000_000u64),
            calls: &calls,
        })
        .unwrap();
        assert_ne!(a.signature, b.signature);
    }
}
