//! Hyperliquid action signing.
//!
//! Mirrors `eigen-tee/src/lib/hyperliquid-domain.ts` + the signing logic
//! in `sign-hyperliquid-order.ts`. Two patterns:
//!
//! ## L1 actions (orders, cancels, modifies)
//!
//! The lambda computes `connection_id = keccak256(msgpack(action) ||
//! nonce_be8 || vault_marker [|| expires_be8])`. The TEE receives
//! `(source, connection_id)` and signs the EIP-712 Agent payload:
//!
//! ```text
//!   domain: Exchange, v1, chainId=1337, verifyingContract=0x0
//!   types:  Agent { source: string, connectionId: bytes32 }
//! ```
//!
//! `source = "a"` for mainnet, `"b"` for testnet — distinguishes the two
//! networks since the domain is shared.
//!
//! ## User-signed actions (transfers, withdrawals)
//!
//! Domain `{ name: "HyperliquidSignTransaction", version: "1",
//! chainId: <signatureChainId>, verifyingContract: 0x0 }`. Types vary
//! per action. The TEE accepts a generic typed-data payload from the
//! lambda — see `sign_generic_typed_data` for that path.

use alloy_primitives::{address, Address, B256, U256};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use once_cell::sync::Lazy;
use sha3::{Digest, Keccak256};
use thiserror::Error;

use crate::derive::evm_address_from_verifying_key;

const HL_VERIFYING_CONTRACT: Address = address!("0000000000000000000000000000000000000000");
const HL_L1_CHAIN_ID: u64 = 1337;
const HL_L1_DOMAIN_NAME: &str = "Exchange";
const HL_L1_DOMAIN_VERSION: &str = "1";
const HL_USER_DOMAIN_NAME: &str = "HyperliquidSignTransaction";
const HL_USER_DOMAIN_VERSION: &str = "1";

const EIP712_DOMAIN_TYPE_STRING: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const AGENT_TYPE_STRING: &str = "Agent(string source,bytes32 connectionId)";

static EIP712_DOMAIN_TYPE_HASH: Lazy<B256> =
    Lazy::new(|| keccak256_to_b256(EIP712_DOMAIN_TYPE_STRING.as_bytes()));
static AGENT_TYPE_HASH: Lazy<B256> = Lazy::new(|| keccak256_to_b256(AGENT_TYPE_STRING.as_bytes()));
static HL_L1_DOMAIN_NAME_HASH: Lazy<B256> =
    Lazy::new(|| keccak256_to_b256(HL_L1_DOMAIN_NAME.as_bytes()));
static HL_L1_DOMAIN_VERSION_HASH: Lazy<B256> =
    Lazy::new(|| keccak256_to_b256(HL_L1_DOMAIN_VERSION.as_bytes()));
static HL_USER_DOMAIN_NAME_HASH: Lazy<B256> =
    Lazy::new(|| keccak256_to_b256(HL_USER_DOMAIN_NAME.as_bytes()));
static HL_USER_DOMAIN_VERSION_HASH: Lazy<B256> =
    Lazy::new(|| keccak256_to_b256(HL_USER_DOMAIN_VERSION.as_bytes()));

#[derive(Debug, Error)]
pub enum HyperliquidError {
    #[error("malformed private key: {0}")]
    BadKey(String),

    #[error("signing failed: {0}")]
    Sign(String),

    #[error("invalid network tag {0:?} (expected mainnet/testnet)")]
    BadNetwork(String),
}

#[derive(Debug, Clone, Copy)]
pub enum HyperliquidNetwork {
    Mainnet,
    Testnet,
}

impl HyperliquidNetwork {
    pub fn source_tag(self) -> &'static str {
        match self {
            Self::Mainnet => "a",
            Self::Testnet => "b",
        }
    }
}

/// The 65-byte Ethereum signature that Hyperliquid splits into r/s/v
/// on submission. The Python SDK's `sign_l1_action` returns the same.
#[derive(Debug, Clone)]
pub struct HyperliquidSignature {
    pub signature: [u8; 65],
    pub evm_address: Address,
    /// Convenience split: `r`, `s` (32 bytes each, big-endian) and `v`
    /// (27 or 28). Lambda forwards these in the HL POST body.
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

/// Sign a Hyperliquid L1 action. The caller (lambda) has already
/// computed the 32-byte connection_id from the msgpack-encoded action.
pub fn sign_l1_action(
    priv_key: &[u8; 32],
    network: HyperliquidNetwork,
    connection_id: &B256,
) -> Result<HyperliquidSignature, HyperliquidError> {
    let signing_key = SigningKey::from_bytes(priv_key.into())
        .map_err(|e| HyperliquidError::BadKey(e.to_string()))?;
    let evm_address = evm_address_from_verifying_key(signing_key.verifying_key());

    let domain_sep = l1_domain_separator();
    let struct_hash = hash_agent_struct(network.source_tag(), connection_id);
    let digest = eip712_digest(&domain_sep, &struct_hash);

    sign_digest(signing_key, evm_address, &digest)
}

/// Sign a Hyperliquid user-signed action. Caller provides the chain id
/// (from `action.signatureChainId`) and the pre-computed struct hash —
/// see `compute_user_struct_hash` for help when the route knows the
/// concrete typed data.
pub fn sign_user_action(
    priv_key: &[u8; 32],
    signature_chain_id: u64,
    struct_hash: &B256,
) -> Result<HyperliquidSignature, HyperliquidError> {
    let signing_key = SigningKey::from_bytes(priv_key.into())
        .map_err(|e| HyperliquidError::BadKey(e.to_string()))?;
    let evm_address = evm_address_from_verifying_key(signing_key.verifying_key());

    let domain_sep = user_domain_separator(signature_chain_id);
    let digest = eip712_digest(&domain_sep, struct_hash);

    sign_digest(signing_key, evm_address, &digest)
}

fn sign_digest(
    signing_key: SigningKey,
    evm_address: Address,
    digest: &[u8; 32],
) -> Result<HyperliquidSignature, HyperliquidError> {
    let (sig, recovery_id): (Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(digest)
        .map_err(|e| HyperliquidError::Sign(e.to_string()))?;
    let r_s: [u8; 64] = sig.to_bytes().into();
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&r_s);
    let v = 27 + recovery_id.to_byte();
    signature[64] = v;

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&r_s[0..32]);
    s.copy_from_slice(&r_s[32..64]);

    Ok(HyperliquidSignature {
        signature,
        evm_address,
        r,
        s,
        v,
    })
}

fn l1_domain_separator() -> B256 {
    let mut buf = [0u8; 32 * 5];
    buf[0..32].copy_from_slice(EIP712_DOMAIN_TYPE_HASH.as_slice());
    buf[32..64].copy_from_slice(HL_L1_DOMAIN_NAME_HASH.as_slice());
    buf[64..96].copy_from_slice(HL_L1_DOMAIN_VERSION_HASH.as_slice());
    buf[96..128].copy_from_slice(&U256::from(HL_L1_CHAIN_ID).to_be_bytes::<32>());
    buf[128 + 12..160].copy_from_slice(HL_VERIFYING_CONTRACT.as_slice());
    keccak256_to_b256(&buf)
}

fn user_domain_separator(chain_id: u64) -> B256 {
    let mut buf = [0u8; 32 * 5];
    buf[0..32].copy_from_slice(EIP712_DOMAIN_TYPE_HASH.as_slice());
    buf[32..64].copy_from_slice(HL_USER_DOMAIN_NAME_HASH.as_slice());
    buf[64..96].copy_from_slice(HL_USER_DOMAIN_VERSION_HASH.as_slice());
    buf[96..128].copy_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    buf[128 + 12..160].copy_from_slice(HL_VERIFYING_CONTRACT.as_slice());
    keccak256_to_b256(&buf)
}

fn hash_agent_struct(source: &str, connection_id: &B256) -> B256 {
    let mut buf = [0u8; 32 * 3];
    buf[0..32].copy_from_slice(AGENT_TYPE_HASH.as_slice());
    buf[32..64].copy_from_slice(keccak256_to_b256(source.as_bytes()).as_slice());
    buf[64..96].copy_from_slice(connection_id.as_slice());
    keccak256_to_b256(&buf)
}

fn eip712_digest(domain_separator: &B256, struct_hash: &B256) -> [u8; 32] {
    let mut buf = [0u8; 2 + 32 + 32];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain_separator.as_slice());
    buf[34..66].copy_from_slice(struct_hash.as_slice());
    Keccak256::digest(buf).into()
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
    fn l1_action_sign_produces_65_byte_sig() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let connection_id = B256::from([0xab; 32]);
        let sig = sign_l1_action(&acct.private_key.0, HyperliquidNetwork::Mainnet, &connection_id)
            .unwrap();
        assert_eq!(sig.signature.len(), 65);
        assert!(sig.v == 27 || sig.v == 28);
        // r||s splits match the full signature.
        assert_eq!(&sig.signature[0..32], &sig.r[..]);
        assert_eq!(&sig.signature[32..64], &sig.s[..]);
    }

    #[test]
    fn l1_action_sign_deterministic() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let connection_id = B256::from([0xab; 32]);
        let a = sign_l1_action(&acct.private_key.0, HyperliquidNetwork::Mainnet, &connection_id)
            .unwrap();
        let b = sign_l1_action(&acct.private_key.0, HyperliquidNetwork::Mainnet, &connection_id)
            .unwrap();
        assert_eq!(a.signature, b.signature);
    }

    #[test]
    fn l1_action_mainnet_vs_testnet_diverge() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let connection_id = B256::from([0xab; 32]);
        let mainnet =
            sign_l1_action(&acct.private_key.0, HyperliquidNetwork::Mainnet, &connection_id)
                .unwrap();
        let testnet =
            sign_l1_action(&acct.private_key.0, HyperliquidNetwork::Testnet, &connection_id)
                .unwrap();
        // Different source tag → different struct hash → different sig.
        assert_ne!(mainnet.signature, testnet.signature);
    }

    #[test]
    fn user_action_sign_deterministic() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let struct_hash = B256::from([0xcd; 32]);
        let a = sign_user_action(&acct.private_key.0, 42161, &struct_hash).unwrap();
        let b = sign_user_action(&acct.private_key.0, 42161, &struct_hash).unwrap();
        assert_eq!(a.signature, b.signature);
    }

    #[test]
    fn user_action_chain_id_affects_sig() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let struct_hash = B256::from([0xcd; 32]);
        let a = sign_user_action(&acct.private_key.0, 42161, &struct_hash).unwrap();
        let b = sign_user_action(&acct.private_key.0, 1, &struct_hash).unwrap();
        assert_ne!(a.signature, b.signature);
    }
}
