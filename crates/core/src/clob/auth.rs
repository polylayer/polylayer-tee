//! Polymarket V2 CLOB L1 ClobAuth EIP-712 sign + L1 header construction.
//!
//! Mirrors the `buildL1Headers` helper in
//! `eigen-tee/src/lib/clobClient.ts`. Pure — no fetch. The HTTP call
//! that derives/creates API creds lives outside `core`.
//!
//! Domain: `{ name: "ClobAuthDomain", version: "1", chainId: 137 }`.
//! Message: `address`, `timestamp` (string), `nonce` (uint256), and a
//! fixed attestation message `"This message attests that I control the
//! given wallet"`.

use alloy_primitives::{Address, B256, U256};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use once_cell::sync::Lazy;
use sha3::{Digest, Keccak256};
use thiserror::Error;

use crate::derive::evm_address_from_verifying_key;

#[derive(Debug, Error)]
pub enum ClobAuthError {
    #[error("malformed private key: {0}")]
    BadKey(String),

    #[error("signing failed: {0}")]
    Sign(String),
}

#[derive(Debug, Clone)]
pub struct L1Headers {
    pub poly_address: String,
    pub poly_signature: String,
    pub poly_timestamp: String,
    pub poly_nonce: String,
}

pub const CLOB_AUTH_MESSAGE: &str = "This message attests that I control the given wallet";

const CLOB_AUTH_DOMAIN_TYPE_STRING: &str =
    "EIP712Domain(string name,string version,uint256 chainId)";
const CLOB_AUTH_TYPE_STRING: &str =
    "ClobAuth(address address,string timestamp,uint256 nonce,string message)";

static CLOB_AUTH_DOMAIN_TYPE_HASH: Lazy<B256> =
    Lazy::new(|| keccak256_to_b256(CLOB_AUTH_DOMAIN_TYPE_STRING.as_bytes()));
static CLOB_AUTH_TYPE_HASH: Lazy<B256> =
    Lazy::new(|| keccak256_to_b256(CLOB_AUTH_TYPE_STRING.as_bytes()));
static CLOB_AUTH_DOMAIN_NAME_HASH: Lazy<B256> =
    Lazy::new(|| keccak256_to_b256(b"ClobAuthDomain"));
static CLOB_AUTH_DOMAIN_VERSION_HASH: Lazy<B256> = Lazy::new(|| keccak256_to_b256(b"1"));
static CLOB_AUTH_MESSAGE_HASH: Lazy<B256> =
    Lazy::new(|| keccak256_to_b256(CLOB_AUTH_MESSAGE.as_bytes()));

pub fn build_l1_headers(
    priv_key: &[u8; 32],
    address: Address,
    nonce: u64,
    timestamp_secs: u64,
) -> Result<L1Headers, ClobAuthError> {
    let signing_key =
        SigningKey::from_bytes(priv_key.into()).map_err(|e| ClobAuthError::BadKey(e.to_string()))?;
    let recovered_addr = evm_address_from_verifying_key(signing_key.verifying_key());
    debug_assert_eq!(recovered_addr, address, "address must match private key");

    // Domain separator: ClobAuth has only name/version/chainId — no
    // verifyingContract — so its EIP712Domain type hash differs from
    // the standard 4-field one.
    let mut domain_buf = [0u8; 32 * 4];
    domain_buf[0..32].copy_from_slice(CLOB_AUTH_DOMAIN_TYPE_HASH.as_slice());
    domain_buf[32..64].copy_from_slice(CLOB_AUTH_DOMAIN_NAME_HASH.as_slice());
    domain_buf[64..96].copy_from_slice(CLOB_AUTH_DOMAIN_VERSION_HASH.as_slice());
    domain_buf[96..128].copy_from_slice(&U256::from(137u64).to_be_bytes::<32>());
    let domain_sep = keccak256_to_b256(&domain_buf);

    // Struct hash: ClobAuth(address, timestamp:string, nonce:uint256, message:string).
    // Strings hash to keccak(bytes).
    let ts_str = timestamp_secs.to_string();
    let ts_hash = keccak256_to_b256(ts_str.as_bytes());

    let mut struct_buf = [0u8; 32 * 5];
    struct_buf[0..32].copy_from_slice(CLOB_AUTH_TYPE_HASH.as_slice());
    // address word: 12 zero bytes + 20 address bytes.
    struct_buf[32 + 12..64].copy_from_slice(address.as_slice());
    struct_buf[64..96].copy_from_slice(ts_hash.as_slice());
    struct_buf[96..128].copy_from_slice(&U256::from(nonce).to_be_bytes::<32>());
    struct_buf[128..160].copy_from_slice(CLOB_AUTH_MESSAGE_HASH.as_slice());
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
        .map_err(|e| ClobAuthError::Sign(e.to_string()))?;
    let mut sig_bytes = [0u8; 65];
    let r_s: [u8; 64] = sig.to_bytes().into();
    sig_bytes[..64].copy_from_slice(&r_s);
    sig_bytes[64] = 27 + recovery_id.to_byte();

    Ok(L1Headers {
        poly_address: format!("{:#x}", address),
        poly_signature: format!("0x{}", hex::encode(sig_bytes)),
        poly_timestamp: ts_str,
        poly_nonce: nonce.to_string(),
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
    fn l1_headers_deterministic() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let a = build_l1_headers(&acct.private_key.0, acct.address, 0, 1_700_000_000).unwrap();
        let b = build_l1_headers(&acct.private_key.0, acct.address, 0, 1_700_000_000).unwrap();
        assert_eq!(a.poly_signature, b.poly_signature);
        assert_eq!(a.poly_address, format!("{:#x}", acct.address));
        assert_eq!(a.poly_timestamp, "1700000000");
        assert_eq!(a.poly_nonce, "0");
    }

    #[test]
    fn l1_headers_signature_starts_with_0x() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let h = build_l1_headers(&acct.private_key.0, acct.address, 0, 1_700_000_000).unwrap();
        assert!(h.poly_signature.starts_with("0x"));
        assert_eq!(h.poly_signature.len(), 2 + 130); // 0x + 65 bytes hex
    }

    #[test]
    fn l1_headers_change_with_nonce() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let a = build_l1_headers(&acct.private_key.0, acct.address, 0, 1_700_000_000).unwrap();
        let b = build_l1_headers(&acct.private_key.0, acct.address, 1, 1_700_000_000).unwrap();
        assert_ne!(a.poly_signature, b.poly_signature);
    }
}
