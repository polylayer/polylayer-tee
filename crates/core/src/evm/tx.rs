//! Generic EIP-1559 transaction signing.
//!
//! Mirrors the signing primitive used by `eigen-tee/src/routes/sign-evm-tx.ts`.
//! Builds the type-2 (EIP-1559) RLP-encoded transaction, signs it
//! with the per-user secp256k1 key, returns the broadcast-ready hex.
//!
//! Wire format for EIP-1559 (per [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559)):
//!
//! ```text
//!   tx_payload = 0x02 || rlp([
//!     chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
//!     gas_limit, to, value, data, access_list
//!   ])
//!   digest = keccak256(tx_payload)
//!   (r, s, y_parity) = secp256k1_sign(digest, priv_key)
//!   signed_tx = 0x02 || rlp([
//!     chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
//!     gas_limit, to, value, data, access_list, y_parity, r, s
//!   ])
//!   tx_hash = keccak256(signed_tx)
//! ```
//!
//! Per the EIP, integer fields use minimal-length big-endian encoding —
//! leading zero bytes are stripped before RLP.

use alloy_primitives::{Address, B256, U256};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use rlp::RlpStream;
use sha3::{Digest, Keccak256};
use thiserror::Error;

use crate::derive::evm_address_from_verifying_key;

#[derive(Debug, Error)]
pub enum EvmTxError {
    #[error("malformed private key: {0}")]
    BadKey(String),

    #[error("signing failed: {0}")]
    Sign(String),

    #[error("expected unsigned tx for owner {expected}, derived {derived}")]
    OwnerMismatch { expected: Address, derived: Address },
}

/// EIP-1559 transaction fields. All amounts are pre-parsed by the caller
/// from on-wire decimal strings into `U256`. The `to` field is required
/// (we don't support contract-creation through this path — there's no
/// known intent shape that requires it).
#[derive(Debug, Clone)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub to: Address,
    pub value: U256,
    pub data: Vec<u8>,
    /// EIP-2930 access list. Almost always empty for our flows.
    pub access_list: Vec<AccessListItem>,
}

#[derive(Debug, Clone)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<B256>,
}

#[derive(Debug, Clone)]
pub struct SignedEip1559Tx {
    /// `0x`-prefixed raw signed transaction. Broadcast as-is via
    /// `eth_sendRawTransaction`.
    pub raw_hex: String,
    /// keccak256(signed_tx) — the tx hash that will appear on-chain.
    pub tx_hash: B256,
    /// The EOA that signed (derived from the private key).
    pub from: Address,
}

/// Sign an EIP-1559 transaction. The caller (route) is responsible for
/// validating that `tx.data` and `tx.to` match a known-good intent
/// (CCTP burn, pUSD wrap, CTF redeem, etc.) BEFORE calling this.
pub fn sign_eip1559(
    priv_key: &[u8; 32],
    tx: &Eip1559Tx,
) -> Result<SignedEip1559Tx, EvmTxError> {
    let signing_key = SigningKey::from_bytes(priv_key.into())
        .map_err(|e| EvmTxError::BadKey(e.to_string()))?;
    let from = evm_address_from_verifying_key(signing_key.verifying_key());

    // 1. RLP-encode unsigned payload + prefix 0x02.
    let unsigned = encode_unsigned(tx);
    let digest: [u8; 32] = Keccak256::digest(&unsigned).into();

    // 2. Sign the digest. k256 returns canonical (low-S) signatures.
    let (sig, recovery_id): (Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(&digest)
        .map_err(|e| EvmTxError::Sign(e.to_string()))?;
    let r_s: [u8; 64] = sig.to_bytes().into();
    let y_parity = recovery_id.to_byte();
    debug_assert!(y_parity == 0 || y_parity == 1, "recovery id must be 0|1");

    // 3. RLP-encode signed payload (12 fields = unsigned 9 + y_parity, r, s)
    //    + prefix 0x02.
    let signed = encode_signed(tx, y_parity, &r_s[..32], &r_s[32..]);
    let tx_hash = B256::from_slice(Keccak256::digest(&signed).as_slice());

    Ok(SignedEip1559Tx {
        raw_hex: format!("0x{}", hex::encode(signed)),
        tx_hash,
        from,
    })
}

fn encode_unsigned(tx: &Eip1559Tx) -> Vec<u8> {
    let mut s = RlpStream::new();
    s.begin_list(9);
    append_uint(&mut s, U256::from(tx.chain_id));
    append_uint(&mut s, U256::from(tx.nonce));
    append_uint(&mut s, tx.max_priority_fee_per_gas);
    append_uint(&mut s, tx.max_fee_per_gas);
    append_uint(&mut s, U256::from(tx.gas_limit));
    s.append(&tx.to.as_slice());
    append_uint(&mut s, tx.value);
    s.append(&tx.data.as_slice());
    append_access_list(&mut s, &tx.access_list);

    let mut out = Vec::with_capacity(1 + s.as_raw().len());
    out.push(0x02);
    out.extend_from_slice(s.as_raw());
    out
}

fn encode_signed(tx: &Eip1559Tx, y_parity: u8, r: &[u8], sig_s: &[u8]) -> Vec<u8> {
    let mut s = RlpStream::new();
    s.begin_list(12);
    append_uint(&mut s, U256::from(tx.chain_id));
    append_uint(&mut s, U256::from(tx.nonce));
    append_uint(&mut s, tx.max_priority_fee_per_gas);
    append_uint(&mut s, tx.max_fee_per_gas);
    append_uint(&mut s, U256::from(tx.gas_limit));
    s.append(&tx.to.as_slice());
    append_uint(&mut s, tx.value);
    s.append(&tx.data.as_slice());
    append_access_list(&mut s, &tx.access_list);
    append_uint_from_bytes(&mut s, &[y_parity]);
    append_uint_from_bytes(&mut s, r);
    append_uint_from_bytes(&mut s, sig_s);

    let mut out = Vec::with_capacity(1 + s.as_raw().len());
    out.push(0x02);
    out.extend_from_slice(s.as_raw());
    out
}

/// RLP-encode a U256 with leading-zero bytes stripped (EIP-1559 spec).
fn append_uint(s: &mut RlpStream, n: U256) {
    let bytes: [u8; 32] = n.to_be_bytes();
    append_uint_from_bytes(s, &bytes);
}

/// Strip leading-zero bytes then append. RLP treats `0` as empty bytes.
fn append_uint_from_bytes(s: &mut RlpStream, bytes: &[u8]) {
    let mut start = 0;
    while start < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    s.append(&&bytes[start..]);
}

fn append_access_list(s: &mut RlpStream, list: &[AccessListItem]) {
    s.begin_list(list.len());
    for item in list {
        s.begin_list(2);
        s.append(&item.address.as_slice());
        s.begin_list(item.storage_keys.len());
        for key in &item.storage_keys {
            s.append(&key.as_slice());
        }
    }
}

/// Validate that the unsigned tx's implied signer matches the expected
/// owner address. Cheap pre-flight check — if they don't match, refuse
/// to sign rather than emitting a sig from the wrong key.
pub fn assert_owner(
    priv_key: &[u8; 32],
    expected_owner: Address,
) -> Result<(), EvmTxError> {
    let signing_key = SigningKey::from_bytes(priv_key.into())
        .map_err(|e| EvmTxError::BadKey(e.to_string()))?;
    let derived = evm_address_from_verifying_key(signing_key.verifying_key());
    if derived != expected_owner {
        return Err(EvmTxError::OwnerMismatch {
            expected: expected_owner,
            derived,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::Master;

    const HARDHAT: &str = "test test test test test test test test test test test junk";

    fn sample_tx() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: 137,
            nonce: 42,
            max_priority_fee_per_gas: U256::from(2_000_000_000u64),
            max_fee_per_gas: U256::from(30_000_000_000u64),
            gas_limit: 100_000,
            to: "0x1234567890abcdef1234567890abcdef12345678"
                .parse()
                .unwrap(),
            value: U256::ZERO,
            data: vec![0xa9, 0x05, 0x9c, 0xbb], // ERC20 transfer selector
            access_list: vec![],
        }
    }

    #[test]
    fn sign_produces_well_formed_raw_hex() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let signed = sign_eip1559(&acct.private_key.0, &sample_tx()).unwrap();

        // EIP-1559 raw txs start with 0x02 type byte.
        assert!(signed.raw_hex.starts_with("0x02"));
        // tx_hash is 32 bytes.
        assert_eq!(signed.tx_hash.as_slice().len(), 32);
        // from matches the derived address.
        assert_eq!(signed.from, acct.address);
    }

    #[test]
    fn sign_is_deterministic() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let a = sign_eip1559(&acct.private_key.0, &sample_tx()).unwrap();
        let b = sign_eip1559(&acct.private_key.0, &sample_tx()).unwrap();
        assert_eq!(a.raw_hex, b.raw_hex);
        assert_eq!(a.tx_hash, b.tx_hash);
    }

    #[test]
    fn changing_nonce_changes_hash() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let mut t1 = sample_tx();
        t1.nonce = 1;
        let mut t2 = sample_tx();
        t2.nonce = 2;
        let a = sign_eip1559(&acct.private_key.0, &t1).unwrap();
        let b = sign_eip1559(&acct.private_key.0, &t2).unwrap();
        assert_ne!(a.tx_hash, b.tx_hash);
    }

    #[test]
    fn assert_owner_matches() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        assert_owner(&acct.private_key.0, acct.address).unwrap();
    }

    #[test]
    fn assert_owner_rejects_mismatch() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let err = assert_owner(&acct.private_key.0, Address::ZERO).unwrap_err();
        assert!(matches!(err, EvmTxError::OwnerMismatch { .. }));
    }
}
