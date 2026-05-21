//! Polymarket V2 deposit-wallet order signing (POLY_1271 / ERC-7739).
//!
//! Mirrors `signPolymarketV2Order` from
//! `eigen-tee/src/lib/polymarketSign.ts`. The TEE-derived EOA signs an
//! ERC-7739-wrapped EIP-712 typed-data sign whose `contents` is a V2
//! Order struct. The output blob carries the inner sig plus the
//! metadata Polymarket's DepositWallet contract needs to verify
//! `isValidSignature` against the wallet owner's EOA.
//!
//! Wire format of the returned signature (variable-length bytes):
//!
//! ```text
//!     innerSig                 (65 bytes: r || s || v)
//!  ‖ appDomainSeparator        (32 bytes: keccak256 of the CTF Exchange domain)
//!  ‖ contentsHash              (32 bytes: keccak256 of the Order struct)
//!  ‖ contentsTypeString        (variable bytes: UTF-8 of POLYMARKET_V2_ORDER_TYPE_STRING)
//!  ‖ contentsTypeLength        (2 bytes, big-endian)
//! ```

use alloy_primitives::{Address, B256, U256};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use once_cell::sync::Lazy;
use sha3::{Digest, Keccak256};
use thiserror::Error;
use zeroize::Zeroize;

use super::constants::{
    CTF_EXCHANGE_NAME_HASH, CTF_EXCHANGE_V2_ADDRESS, CTF_EXCHANGE_VERSION_HASH,
    DEPOSIT_WALLET_DOMAIN_NAME_HASH, DEPOSIT_WALLET_DOMAIN_VERSION_HASH, EIP712_DOMAIN_TYPE_HASH,
    NEG_RISK_CTF_EXCHANGE_V2_ADDRESS, POLYGON_CHAIN_ID, POLYMARKET_V2_ORDER_TYPE_HASH,
    POLYMARKET_V2_ORDER_TYPE_STRING, SIG_TYPE_POLY_1271, ZERO_BYTES32,
};
use super::deposit_wallet::derive_deposit_wallet_address;
use crate::derive::evm_address_from_verifying_key;

#[derive(Debug, Error)]
pub enum PolymarketError {
    #[error("order.signatureType {0} != POLY_1271 (3)")]
    WrongSigType(u8),

    #[error("order.maker {actual} != derived DepositWallet {expected}")]
    MakerMismatch { actual: Address, expected: Address },

    #[error("order.signer {actual} != order.maker {expected}")]
    SignerMismatch { actual: Address, expected: Address },

    #[error("malformed private key: {0}")]
    BadKey(String),

    #[error("signing failed: {0}")]
    Sign(String),
}

/// Plain-data V2 Order. All numeric fields arrive as `U256` so the
/// caller (HTTP route) is responsible for parsing the on-wire decimal
/// strings — keeps this module dependency-free.
#[derive(Debug, Clone)]
pub struct V2Order {
    pub salt: U256,
    pub maker: Address,
    pub signer: Address,
    pub token_id: U256,
    pub maker_amount: U256,
    pub taker_amount: U256,
    /// 0 = BUY, 1 = SELL.
    pub side: u8,
    /// Must be 3 (POLY_1271).
    pub signature_type: u8,
    /// Milliseconds since epoch.
    pub timestamp: U256,
    pub metadata: B256,
    pub builder: B256,
}

pub struct SignV2OrderArgs<'a> {
    pub priv_key: &'a [u8; 32],
    pub order: V2Order,
    pub neg_risk: bool,
}

#[derive(Debug, Clone)]
pub struct V2OrderSignature {
    /// POLY_1271 / ERC-7739 wrapped signature. Variable length.
    pub signature: Vec<u8>,
    /// EOA that signed the inner typed-data sign.
    pub evm_address: Address,
    /// Deterministic DepositWallet — equals `order.maker` and `order.signer`.
    pub deposit_wallet_address: Address,
    pub neg_risk: bool,
}

/// TypedDataSign type-string per ERC-7739. The Order type definition
/// must be appended; EIP-712 requires referenced struct types in the
/// final type-hash input.
static TYPED_DATA_SIGN_TYPE_STRING: Lazy<String> = Lazy::new(|| {
    format!(
        "TypedDataSign(Order contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt){}",
        POLYMARKET_V2_ORDER_TYPE_STRING
    )
});

static TYPED_DATA_SIGN_TYPE_HASH: Lazy<B256> =
    Lazy::new(|| keccak256(TYPED_DATA_SIGN_TYPE_STRING.as_bytes()));

pub fn sign_v2_order(args: SignV2OrderArgs<'_>) -> Result<V2OrderSignature, PolymarketError> {
    // SigningKey::from_bytes validates the scalar (< n).
    let signing_key = SigningKey::from_bytes(args.priv_key.into())
        .map_err(|e| PolymarketError::BadKey(e.to_string()))?;
    let signer_address = evm_address_from_verifying_key(signing_key.verifying_key());
    let expected_deposit_wallet = derive_deposit_wallet_address(signer_address);

    if args.order.signature_type != SIG_TYPE_POLY_1271 {
        return Err(PolymarketError::WrongSigType(args.order.signature_type));
    }
    if args.order.maker != expected_deposit_wallet {
        return Err(PolymarketError::MakerMismatch {
            actual: args.order.maker,
            expected: expected_deposit_wallet,
        });
    }
    if args.order.signer != expected_deposit_wallet {
        return Err(PolymarketError::SignerMismatch {
            actual: args.order.signer,
            expected: expected_deposit_wallet,
        });
    }

    // hashStruct(Order) — used both inside the TypedDataSign wrapper
    // AND echoed in the POLY_1271 trailer as `contentsHash`.
    let contents_hash = hash_struct_order(&args.order);

    // Exchange domain separator — appears in the EIP-712 digest below
    // AND in the POLY_1271 trailer as `appDomainSeparator`.
    let exchange_domain_sep = exchange_domain_separator(args.neg_risk);

    // hashStruct(TypedDataSign) wrapping the order with the deposit
    // wallet's domain claim.
    let typed_data_sign_hash =
        hash_struct_typed_data_sign(contents_hash, expected_deposit_wallet);

    // EIP-712 message digest: keccak256(0x1901 || domain_sep || hashStruct).
    // Use the EXCHANGE's domain separator here — ERC-7739 pattern.
    let message_hash = eip712_digest(exchange_domain_sep, typed_data_sign_hash);

    let (sig, recovery_id): (Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(&message_hash)
        .map_err(|e| PolymarketError::Sign(e.to_string()))?;
    let inner_sig = pack_eth_signature(sig, recovery_id);

    let type_str_bytes = POLYMARKET_V2_ORDER_TYPE_STRING.as_bytes();
    let type_len = u16::try_from(type_str_bytes.len())
        .expect("POLYMARKET_V2_ORDER_TYPE_STRING length fits in u16");

    let mut blob =
        Vec::with_capacity(65 + 32 + 32 + type_str_bytes.len() + 2);
    blob.extend_from_slice(&inner_sig);
    blob.extend_from_slice(exchange_domain_sep.as_slice());
    blob.extend_from_slice(contents_hash.as_slice());
    blob.extend_from_slice(type_str_bytes);
    blob.extend_from_slice(&type_len.to_be_bytes());

    Ok(V2OrderSignature {
        signature: blob,
        evm_address: signer_address,
        deposit_wallet_address: expected_deposit_wallet,
        neg_risk: args.neg_risk,
    })
}

/// `keccak256(EIP712Domain_typehash || keccak(name) || keccak(version) || chainId || verifyingContract)`
fn exchange_domain_separator(neg_risk: bool) -> B256 {
    let verifying_contract = if neg_risk {
        NEG_RISK_CTF_EXCHANGE_V2_ADDRESS
    } else {
        CTF_EXCHANGE_V2_ADDRESS
    };
    let mut buf = [0u8; 32 * 5];
    buf[0..32].copy_from_slice(EIP712_DOMAIN_TYPE_HASH.as_slice());
    buf[32..64].copy_from_slice(CTF_EXCHANGE_NAME_HASH.as_slice());
    buf[64..96].copy_from_slice(CTF_EXCHANGE_VERSION_HASH.as_slice());
    buf[96..128].copy_from_slice(&U256::from(POLYGON_CHAIN_ID).to_be_bytes::<32>());
    // Address: 12 zero bytes + 20-byte address.
    buf[128 + 12..160].copy_from_slice(verifying_contract.as_slice());
    keccak256(&buf)
}

/// `hashStruct(Order) = keccak256(typeHash || abi.encode(fields...))`.
fn hash_struct_order(order: &V2Order) -> B256 {
    let mut buf = [0u8; 32 * 12];
    let mut o = 0usize;
    let put32 = |buf: &mut [u8; 384], offset: &mut usize, bytes: [u8; 32]| {
        buf[*offset..*offset + 32].copy_from_slice(&bytes);
        *offset += 32;
    };

    put32(&mut buf, &mut o, POLYMARKET_V2_ORDER_TYPE_HASH.0);
    put32(&mut buf, &mut o, order.salt.to_be_bytes::<32>());
    put32(&mut buf, &mut o, addr_word(order.maker));
    put32(&mut buf, &mut o, addr_word(order.signer));
    put32(&mut buf, &mut o, order.token_id.to_be_bytes::<32>());
    put32(&mut buf, &mut o, order.maker_amount.to_be_bytes::<32>());
    put32(&mut buf, &mut o, order.taker_amount.to_be_bytes::<32>());
    put32(&mut buf, &mut o, u8_word(order.side));
    put32(&mut buf, &mut o, u8_word(order.signature_type));
    put32(&mut buf, &mut o, order.timestamp.to_be_bytes::<32>());
    put32(&mut buf, &mut o, order.metadata.0);
    put32(&mut buf, &mut o, order.builder.0);
    debug_assert_eq!(o, 384);

    keccak256(&buf)
}

fn hash_struct_typed_data_sign(contents_hash: B256, verifying_contract: Address) -> B256 {
    let mut buf = [0u8; 32 * 7];
    buf[0..32].copy_from_slice(TYPED_DATA_SIGN_TYPE_HASH.as_slice());
    buf[32..64].copy_from_slice(contents_hash.as_slice());
    buf[64..96].copy_from_slice(DEPOSIT_WALLET_DOMAIN_NAME_HASH.as_slice());
    buf[96..128].copy_from_slice(DEPOSIT_WALLET_DOMAIN_VERSION_HASH.as_slice());
    buf[128..160].copy_from_slice(&U256::from(POLYGON_CHAIN_ID).to_be_bytes::<32>());
    buf[160..192].copy_from_slice(&addr_word(verifying_contract));
    buf[192..224].copy_from_slice(ZERO_BYTES32.as_slice());
    keccak256(&buf)
}

fn eip712_digest(domain_separator: B256, struct_hash: B256) -> [u8; 32] {
    let mut buf = [0u8; 2 + 32 + 32];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain_separator.as_slice());
    buf[34..66].copy_from_slice(struct_hash.as_slice());
    Keccak256::digest(buf).into()
}

/// Address → 32-byte ABI word (12 zero bytes + 20 address bytes).
fn addr_word(addr: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr.as_slice());
    out
}

/// u8 → 32-byte ABI word (31 zero bytes + 1 byte).
fn u8_word(v: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = v;
    out
}

/// Pack a k256 signature + recovery id into Ethereum's 65-byte
/// `r || s || v` form, with `v = 27 + recovery_id` (viem's convention).
fn pack_eth_signature(sig: Signature, recovery_id: RecoveryId) -> [u8; 65] {
    let mut out = [0u8; 65];
    let r_s: [u8; 64] = sig.to_bytes().into();
    out[..64].copy_from_slice(&r_s);
    out[64] = 27 + recovery_id.to_byte();
    out
}

fn keccak256(input: &[u8]) -> B256 {
    B256::from_slice(Keccak256::digest(input).as_slice())
}

// Suppress dead-code lint on Zeroize that's pulled in transitively; the
// SigningKey already implements Zeroize and clears on drop.
#[allow(dead_code)]
fn _zeroize_anchor<T: Zeroize>(_: &T) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::Master;

    /// Hardhat default mnemonic — same well-known fixture used in
    /// derive.rs. Account 0's address is 0xf39F...2266; deposit wallet
    /// for it is 0xdf8b…Ba76 (verified in deposit_wallet.rs tests).
    const HARDHAT: &str = "test test test test test test test test test test test junk";

    fn build_test_order(maker: Address) -> V2Order {
        V2Order {
            salt: U256::from(123456u64),
            maker,
            signer: maker,
            token_id: U256::from_str_radix("12345", 10).unwrap(),
            maker_amount: U256::from(500_000u64),
            taker_amount: U256::from(1_000_000u64),
            side: 0, // BUY
            signature_type: SIG_TYPE_POLY_1271,
            timestamp: U256::from(1_700_000_000_000u64),
            metadata: B256::ZERO,
            builder: B256::ZERO,
        }
    }

    #[test]
    fn sign_v2_order_rejects_wrong_sig_type() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let dw = derive_deposit_wallet_address(acct.address);
        let mut order = build_test_order(dw);
        order.signature_type = 0; // not POLY_1271
        let err = sign_v2_order(SignV2OrderArgs {
            priv_key: &acct.private_key.0,
            order,
            neg_risk: false,
        })
        .unwrap_err();
        assert!(matches!(err, PolymarketError::WrongSigType(0)));
    }

    #[test]
    fn sign_v2_order_rejects_maker_mismatch() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        // Wrong maker — not the derived DepositWallet.
        let order = build_test_order(Address::ZERO);
        let err = sign_v2_order(SignV2OrderArgs {
            priv_key: &acct.private_key.0,
            order,
            neg_risk: false,
        })
        .unwrap_err();
        assert!(matches!(err, PolymarketError::MakerMismatch { .. }));
    }

    #[test]
    fn sign_v2_order_produces_well_formed_blob() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let dw = derive_deposit_wallet_address(acct.address);
        let order = build_test_order(dw);
        let sig = sign_v2_order(SignV2OrderArgs {
            priv_key: &acct.private_key.0,
            order,
            neg_risk: false,
        })
        .unwrap();

        // Blob layout: 65 inner sig + 32 domain sep + 32 contents hash +
        // type-string + 2 length bytes.
        let expected_min = 65 + 32 + 32 + POLYMARKET_V2_ORDER_TYPE_STRING.len() + 2;
        assert_eq!(sig.signature.len(), expected_min);

        // v byte (last byte of inner sig) is 27 or 28.
        let v = sig.signature[64];
        assert!(v == 27 || v == 28, "v should be 27|28, got {v}");

        // The trailing 2 bytes are big-endian length of the type string.
        let type_len_bytes = &sig.signature[sig.signature.len() - 2..];
        let decoded_len = u16::from_be_bytes([type_len_bytes[0], type_len_bytes[1]]);
        assert_eq!(
            decoded_len as usize,
            POLYMARKET_V2_ORDER_TYPE_STRING.len()
        );

        // The bytes just before the length should be the type string.
        let ts_end = sig.signature.len() - 2;
        let ts_start = ts_end - POLYMARKET_V2_ORDER_TYPE_STRING.len();
        assert_eq!(
            &sig.signature[ts_start..ts_end],
            POLYMARKET_V2_ORDER_TYPE_STRING.as_bytes()
        );

        // evm_address should match the master EVM (since we used master
        // mnemonic + the master's address as owner).
        assert_eq!(sig.evm_address, acct.address);
        assert_eq!(sig.deposit_wallet_address, dw);
    }

    #[test]
    fn sign_v2_order_is_deterministic_for_same_inputs() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let dw = derive_deposit_wallet_address(acct.address);
        let order_a = build_test_order(dw);
        let order_b = build_test_order(dw);
        let sig_a = sign_v2_order(SignV2OrderArgs {
            priv_key: &acct.private_key.0,
            order: order_a,
            neg_risk: false,
        })
        .unwrap();
        let sig_b = sign_v2_order(SignV2OrderArgs {
            priv_key: &acct.private_key.0,
            order: order_b,
            neg_risk: false,
        })
        .unwrap();
        // secp256k1 ECDSA is deterministic via RFC-6979 in k256.
        assert_eq!(sig_a.signature, sig_b.signature);
    }

    #[test]
    fn sign_v2_order_neg_risk_differs_from_regular() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let dw = derive_deposit_wallet_address(acct.address);
        let order = build_test_order(dw);
        let sig_reg = sign_v2_order(SignV2OrderArgs {
            priv_key: &acct.private_key.0,
            order: order.clone(),
            neg_risk: false,
        })
        .unwrap();
        let sig_nr = sign_v2_order(SignV2OrderArgs {
            priv_key: &acct.private_key.0,
            order,
            neg_risk: true,
        })
        .unwrap();
        // Different verifyingContract in the exchange domain → different
        // domain separator → different inner sig.
        assert_ne!(&sig_reg.signature[..65], &sig_nr.signature[..65]);
        assert_ne!(
            &sig_reg.signature[65..97],
            &sig_nr.signature[65..97],
            "appDomainSeparator must differ between regular and neg-risk"
        );
    }
}
