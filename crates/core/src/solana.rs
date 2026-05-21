//! Solana pubkey + Ed25519 signature helpers.
//!
//! Mirrors `eigen-tee/src/lib/solana.ts`. We accept signatures in either
//! base58 (Phantom default) or hex (developer-friendly) form because
//! frontend libraries differ.
//!
//! Strict by default — malformed inputs raise rather than silently
//! returning `false`. The boolean variant is `verify_signature`; the
//! decoder fns return `Result`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

pub const PUBKEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum SolanaError {
    #[error("invalid bs58 pubkey: {0}")]
    Bs58Pubkey(String),

    #[error("pubkey wrong length: expected {expected} bytes, got {got}")]
    PubkeyLength { expected: usize, got: usize },

    #[error("empty signature")]
    EmptySignature,

    #[error("hex signature wrong length: expected {expected} chars, got {got}")]
    HexSignatureLength { expected: usize, got: usize },

    #[error("signature not bs58 or hex: {0}")]
    SignatureDecode(String),

    #[error("bs58 signature wrong length: expected {expected} bytes, got {got}")]
    Bs58SignatureLength { expected: usize, got: usize },

    #[error("malformed ed25519 verifying key")]
    InvalidVerifyingKey,
}

/// Decode a base58 Solana pubkey to its raw 32 bytes.
pub fn decode_pubkey(bs58_pubkey: &str) -> Result<[u8; PUBKEY_LEN], SolanaError> {
    let raw = bs58::decode(bs58_pubkey)
        .into_vec()
        .map_err(|e| SolanaError::Bs58Pubkey(e.to_string()))?;
    if raw.len() != PUBKEY_LEN {
        return Err(SolanaError::PubkeyLength { expected: PUBKEY_LEN, got: raw.len() });
    }
    let mut out = [0u8; PUBKEY_LEN];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Decode a Solana signature. Accepts base58 OR hex (with optional `0x`
/// prefix). Mirrors the TS `decodeSolanaSignature` regex-based dispatch.
pub fn decode_signature(input: &str) -> Result<[u8; SIG_LEN], SolanaError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SolanaError::EmptySignature);
    }

    // Hex if it looks like hex. Note: hex is a strict subset of bs58's
    // alphabet, so prefer hex when the input matches.
    let looks_hex = {
        let bytes = trimmed.strip_prefix("0x").unwrap_or(trimmed).as_bytes();
        !bytes.is_empty() && bytes.iter().all(|b| b.is_ascii_hexdigit())
    };

    if looks_hex {
        let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        if hex_str.len() != SIG_LEN * 2 {
            return Err(SolanaError::HexSignatureLength {
                expected: SIG_LEN * 2,
                got: hex_str.len(),
            });
        }
        let decoded = hex::decode(hex_str)
            .map_err(|e| SolanaError::SignatureDecode(e.to_string()))?;
        let mut out = [0u8; SIG_LEN];
        out.copy_from_slice(&decoded);
        return Ok(out);
    }

    // Fall through to bs58.
    let raw = bs58::decode(trimmed)
        .into_vec()
        .map_err(|e| SolanaError::SignatureDecode(e.to_string()))?;
    if raw.len() != SIG_LEN {
        return Err(SolanaError::Bs58SignatureLength { expected: SIG_LEN, got: raw.len() });
    }
    let mut out = [0u8; SIG_LEN];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Verify an Ed25519 signature over raw bytes. Returns `false` on bad
/// sig; returns `Err` on malformed key/sig structure.
pub fn verify_signature(
    message: &[u8],
    signature_bytes: &[u8; SIG_LEN],
    pubkey_bytes: &[u8; PUBKEY_LEN],
) -> Result<bool, SolanaError> {
    let vk = VerifyingKey::from_bytes(pubkey_bytes).map_err(|_| SolanaError::InvalidVerifyingKey)?;
    let sig = Signature::from_bytes(signature_bytes);
    Ok(vk.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_pubkey_round_trip() {
        // 32 zero bytes → known bs58 string `11111111111111111111111111111111`
        // (Solana's SystemProgram address). Verify both directions.
        let zeros = [0u8; 32];
        let s = bs58::encode(zeros).into_string();
        let back = decode_pubkey(&s).unwrap();
        assert_eq!(back, zeros);
    }

    #[test]
    fn decode_pubkey_wrong_length() {
        let short = bs58::encode([0u8; 16]).into_string();
        assert!(matches!(decode_pubkey(&short), Err(SolanaError::PubkeyLength { .. })));
    }

    #[test]
    fn decode_signature_hex_with_prefix() {
        let bytes = [0xabu8; 64];
        let hex_str = format!("0x{}", hex::encode(bytes));
        let decoded = decode_signature(&hex_str).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_hex_without_prefix() {
        let bytes = [0xcdu8; 64];
        let hex_str = hex::encode(bytes);
        let decoded = decode_signature(&hex_str).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_bs58() {
        // 64 random bytes that aren't valid hex.
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(123);
        }
        // bs58-encode and decode — confirm round-trip.
        let s = bs58::encode(bytes).into_string();
        // Skip if it happens to be all hex chars (very unlikely with this seed).
        let is_all_hex = s.bytes().all(|b| b.is_ascii_hexdigit());
        if !is_all_hex {
            let decoded = decode_signature(&s).unwrap();
            assert_eq!(decoded, bytes);
        }
    }

    #[test]
    fn decode_signature_empty() {
        assert!(matches!(decode_signature(""), Err(SolanaError::EmptySignature)));
        assert!(matches!(decode_signature("   "), Err(SolanaError::EmptySignature)));
    }
}
