//! Minimal ABI decoders for the calldata shapes our intent validators
//! need to inspect. We hand-roll instead of pulling alloy-sol-types to
//! keep the EIF lean — the decoded shapes are all static (no dynamic
//! arrays beyond `uint256[]`), so 200 LOC covers everything.
//!
//! All multi-byte ints are big-endian. Addresses are right-aligned in
//! 32-byte words; bytes32 is verbatim.

use alloy_primitives::{Address, B256, U256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AbiError {
    #[error("calldata too short ({0} bytes); need {1}")]
    TooShort(usize, usize),

    #[error("invalid uint256[] offset {0} (must be == 32 × num_static_args)")]
    BadDynamicOffset(u64),

    #[error("uint256[] length {0} exceeds sanity cap {1}")]
    ArrayTooLong(u64, usize),

    #[error("selector mismatch — expected {expected}, got {actual}")]
    WrongSelector { expected: String, actual: String },
}

/// Extract the 4-byte function selector + the args region.
pub fn split_selector(calldata: &[u8]) -> Result<([u8; 4], &[u8]), AbiError> {
    if calldata.len() < 4 {
        return Err(AbiError::TooShort(calldata.len(), 4));
    }
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&calldata[..4]);
    Ok((sel, &calldata[4..]))
}

/// Assert the leading selector matches an expected 4-byte value.
pub fn require_selector(calldata: &[u8], expected: [u8; 4]) -> Result<&[u8], AbiError> {
    let (sel, rest) = split_selector(calldata)?;
    if sel != expected {
        return Err(AbiError::WrongSelector {
            expected: hex::encode(expected),
            actual: hex::encode(sel),
        });
    }
    Ok(rest)
}

/// Read a 32-byte uint256 at offset `i*32` of the args region.
pub fn word_u256(args: &[u8], i: usize) -> Result<U256, AbiError> {
    let off = i * 32;
    if args.len() < off + 32 {
        return Err(AbiError::TooShort(args.len(), off + 32));
    }
    Ok(U256::from_be_slice(&args[off..off + 32]))
}

/// Read an address at word offset i. Addresses are right-aligned in
/// 32-byte words: bytes [i*32+12 .. i*32+32].
pub fn word_address(args: &[u8], i: usize) -> Result<Address, AbiError> {
    let off = i * 32;
    if args.len() < off + 32 {
        return Err(AbiError::TooShort(args.len(), off + 32));
    }
    Ok(Address::from_slice(&args[off + 12..off + 32]))
}

/// Read a bytes32 at word offset i.
pub fn word_bytes32(args: &[u8], i: usize) -> Result<B256, AbiError> {
    let off = i * 32;
    if args.len() < off + 32 {
        return Err(AbiError::TooShort(args.len(), off + 32));
    }
    Ok(B256::from_slice(&args[off..off + 32]))
}

/// Read a bool at word offset i. The low byte of the word is 0 or 1.
pub fn word_bool(args: &[u8], i: usize) -> Result<bool, AbiError> {
    let off = i * 32;
    if args.len() < off + 32 {
        return Err(AbiError::TooShort(args.len(), off + 32));
    }
    Ok(args[off + 31] != 0)
}

/// Sanity cap on dynamic-array lengths — defends against a hostile
/// calldata claiming length=2^64 to make us allocate forever.
const ARRAY_CAP: usize = 256;

/// Decode a `uint256[]` referenced from word offset `i` (which holds
/// an offset-into-args pointer per Solidity ABI). Returns the values.
pub fn dynamic_u256_array(
    args: &[u8],
    static_word_count: usize,
    i: usize,
) -> Result<Vec<U256>, AbiError> {
    let offset = word_u256(args, i)?;
    let off_u64: u64 = offset
        .try_into()
        .map_err(|_| AbiError::BadDynamicOffset(u64::MAX))?;
    // Solidity puts dynamic-arg data after all static args. The offset
    // is measured from the start of the args region, so it MUST equal
    // 32 × static_word_count (or later if multiple dynamic args).
    if off_u64 < (static_word_count * 32) as u64 {
        return Err(AbiError::BadDynamicOffset(off_u64));
    }
    let off = off_u64 as usize;
    if args.len() < off + 32 {
        return Err(AbiError::TooShort(args.len(), off + 32));
    }
    let len = U256::from_be_slice(&args[off..off + 32]);
    let len_u64: u64 = len.try_into().map_err(|_| AbiError::ArrayTooLong(u64::MAX, ARRAY_CAP))?;
    if len_u64 as usize > ARRAY_CAP {
        return Err(AbiError::ArrayTooLong(len_u64, ARRAY_CAP));
    }
    let count = len_u64 as usize;
    let data_start = off + 32;
    if args.len() < data_start + count * 32 {
        return Err(AbiError::TooShort(args.len(), data_start + count * 32));
    }
    let mut out = Vec::with_capacity(count);
    for k in 0..count {
        let s = data_start + k * 32;
        out.push(U256::from_be_slice(&args[s..s + 32]));
    }
    Ok(out)
}

/// Compute the 4-byte selector of a canonical function signature.
pub fn selector_of(canonical_sig: &str) -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    let h = Keccak256::digest(canonical_sig.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&h[..4]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_of_known() {
        // ERC20.transfer(address,uint256) → 0xa9059cbb
        assert_eq!(hex::encode(selector_of("transfer(address,uint256)")), "a9059cbb");
        // ERC20.approve(address,uint256) → 0x095ea7b3
        assert_eq!(hex::encode(selector_of("approve(address,uint256)")), "095ea7b3");
    }

    #[test]
    fn word_u256_roundtrip() {
        let mut args = vec![0u8; 64];
        args[31] = 1; // word[0] = 1
        let bytes_42 = U256::from(42u64).to_be_bytes::<32>();
        args[32..64].copy_from_slice(&bytes_42);
        assert_eq!(word_u256(&args, 0).unwrap(), U256::from(1u64));
        assert_eq!(word_u256(&args, 1).unwrap(), U256::from(42u64));
    }

    #[test]
    fn word_address_right_aligned() {
        let mut args = vec![0u8; 32];
        let addr = Address::from_slice(&[0xab; 20]);
        args[12..32].copy_from_slice(addr.as_slice());
        assert_eq!(word_address(&args, 0).unwrap(), addr);
    }
}
