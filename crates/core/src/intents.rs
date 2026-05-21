//! Lambda-side intents → TEE verification.
//!
//! Mirror of `eigen-tee/src/lib/intents.ts`. Every signed-intent route
//! funnels through `verify_intent_signature` — it:
//!
//! 1. Reads `intent.solana_pubkey` (or uses the override).
//! 2. Checks `intent.expiry` against the supplied wall clock.
//! 3. Canonicalizes the intent bytes (`canonical::canonicalize`).
//! 4. Verifies the Ed25519 signature matches the user's pubkey.
//!
//! ## Why the canonicalization here is different from `canonical.rs`
//!
//! The TS code has TWO canonicalize functions: `lib/canonical.ts` (the
//! strict one that rejects non-finite numbers) and `lib/intents.ts`'s
//! own copy (a lenient JSON.stringify-based one matching the Next.js
//! lambda's intents schema). For verified intents, the LAMBDA-side
//! canonicalization is what matters — both client and server must agree
//! on the bytes that were signed.
//!
//! For our use case the two functions produce **byte-identical** output
//! on every valid signed-intent payload (intents never contain
//! non-finite numbers). We reuse the strict `canonical::canonicalize`
//! here for that reason — fewer maintained code paths, and the parity
//! fixtures in task #170 will cross-check both.

use alloy_primitives::U256;
use serde_json::Value;
use thiserror::Error;

use crate::canonical::{canonical_bytes, CanonicalError};
use crate::solana::{self, decode_pubkey, decode_signature, verify_signature, SolanaError};

#[derive(Debug, Error)]
pub enum IntentError {
    #[error("intent has no solana_pubkey")]
    MissingPubkey,

    #[error("intent expired (expiry={expiry}, now={now})")]
    Expired { expiry: u64, now: u64 },

    #[error("bad bs58 input: {0}")]
    BadBs58(String),

    #[error("pubkey wrong length: {0}")]
    PubkeyLength(usize),

    #[error("signature wrong length: {0}")]
    SignatureLength(usize),

    #[error("signature invalid")]
    InvalidSignature,

    #[error("canonical encode failed: {0}")]
    CanonicalEncode(#[from] CanonicalError),

    #[error("solana primitive error: {0}")]
    Solana(#[from] SolanaError),

    #[error("not a non-negative integer string: {0}")]
    InvalidIntegerString(String),

    #[error("not a non-negative decimal string: {0}")]
    InvalidDecimalString(String),

    #[error("decimal scaling overflowed U256: {0}")]
    Overflow(String),
}

/// Arguments to `verify_intent_signature`. Struct-y to keep the call
/// sites readable when the optional fields vary.
pub struct IntentVerifyArgs<'a> {
    /// The parsed-but-untrusted intent JSON. We extract `solana_pubkey`
    /// and `expiry` from here, then canonicalize the whole thing for
    /// the signature check.
    pub intent: &'a Value,

    /// Base58 Ed25519 signature from the frontend (Phantom).
    pub signature_bs58: &'a str,

    /// Optional override of which pubkey to verify against. Defaults
    /// to `intent.solana_pubkey`.
    pub expected_pubkey_bs58: Option<&'a str>,

    /// If true (default), reject intents whose `expiry` field (unix
    /// seconds) is in the past.
    pub enforce_expiry: bool,

    /// Current wall-clock time in unix seconds. Caller supplies this
    /// so verification stays a pure function — easier to test, no
    /// hidden global clock dependency.
    pub now_unix_secs: u64,
}

/// Verify an Ed25519 signature over the canonical intent bytes. Returns
/// `Ok(())` on success; `Err(IntentError)` with a structured reason on
/// any failure path.
pub fn verify_intent_signature(args: IntentVerifyArgs<'_>) -> Result<(), IntentError> {
    let expected_pubkey = match args.expected_pubkey_bs58 {
        Some(s) if !s.is_empty() => s,
        _ => match args.intent.get("solana_pubkey").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => s,
            _ => return Err(IntentError::MissingPubkey),
        },
    };

    if args.enforce_expiry {
        if let Some(exp) = args.intent.get("expiry").and_then(Value::as_u64) {
            if exp < args.now_unix_secs {
                return Err(IntentError::Expired {
                    expiry: exp,
                    now: args.now_unix_secs,
                });
            }
        }
    }

    let pubkey_bytes = decode_pubkey(expected_pubkey).map_err(|e| match e {
        SolanaError::Bs58Pubkey(msg) => IntentError::BadBs58(msg),
        SolanaError::PubkeyLength { got, .. } => IntentError::PubkeyLength(got),
        other => IntentError::Solana(other),
    })?;
    let sig_bytes = decode_signature(args.signature_bs58).map_err(|e| match e {
        SolanaError::SignatureDecode(msg) => IntentError::BadBs58(msg),
        SolanaError::Bs58SignatureLength { got, .. }
        | SolanaError::HexSignatureLength { got, .. } => IntentError::SignatureLength(got),
        other => IntentError::Solana(other),
    })?;

    let message = canonical_bytes(args.intent)?;

    let ok = verify_signature(&message, &sig_bytes, &pubkey_bytes)?;
    if ok {
        Ok(())
    } else {
        Err(IntentError::InvalidSignature)
    }
}

/// Parse a decimal string as a non-negative U256. Matches the TS
/// regex `/^[0-9]+$/` — empty string rejected, leading-zero strings
/// permitted (the parser doesn't care about canonicalness of input).
pub fn parse_integer_string(value: &str) -> Result<U256, IntentError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(IntentError::InvalidIntegerString(value.to_string()));
    }
    U256::from_str_radix(value, 10)
        .map_err(|e| IntentError::Overflow(format!("integer string {value}: {e}")))
}

/// Convert a decimal-with-fraction string ("0.55", "1.23456") into the
/// integer value scaled by 10^decimals. Mirrors the TS
/// `parseDecimalToScaled` byte-for-byte.
pub fn parse_decimal_to_scaled(value: &str, decimals: u32) -> Result<U256, IntentError> {
    // Validate against /^[0-9]+(\.[0-9]+)?$/.
    let parts: Vec<&str> = value.split('.').collect();
    if parts.is_empty() || parts.len() > 2 {
        return Err(IntentError::InvalidDecimalString(value.to_string()));
    }
    let int_part = parts[0];
    let frac_part = parts.get(1).copied().unwrap_or("");
    if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(IntentError::InvalidDecimalString(value.to_string()));
    }
    if parts.len() == 2 && (frac_part.is_empty() || !frac_part.bytes().all(|b| b.is_ascii_digit())) {
        return Err(IntentError::InvalidDecimalString(value.to_string()));
    }

    // TS impl: (fracPart + "0".repeat(decimals)).slice(0, decimals).
    // Pad-right with zeros to at least `decimals` chars, then truncate
    // to exactly `decimals` chars. Excess fractional digits are
    // silently dropped — matches TS.
    let mut frac_padded = String::with_capacity(decimals as usize);
    frac_padded.push_str(frac_part);
    while frac_padded.len() < decimals as usize {
        frac_padded.push('0');
    }
    frac_padded.truncate(decimals as usize);

    let int_u = U256::from_str_radix(int_part, 10)
        .map_err(|e| IntentError::Overflow(format!("int part {int_part}: {e}")))?;
    let frac_u = if frac_padded.is_empty() {
        U256::ZERO
    } else {
        U256::from_str_radix(&frac_padded, 10)
            .map_err(|e| IntentError::Overflow(format!("frac part {frac_padded}: {e}")))?
    };
    let scale = U256::from(10u64)
        .checked_pow(U256::from(decimals))
        .ok_or_else(|| IntentError::Overflow(format!("10^{decimals} overflowed U256")))?;
    let scaled = int_u
        .checked_mul(scale)
        .ok_or_else(|| IntentError::Overflow(format!("{int_part} * 10^{decimals} overflowed")))?;
    scaled
        .checked_add(frac_u)
        .ok_or_else(|| IntentError::Overflow(format!("final sum overflowed")))
}

// Silence unused-import warning when no submodule pulls `solana`
// directly (it's used implicitly via Solana errors above).
#[allow(unused_imports)]
use solana as _solana_module_marker;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use serde_json::json;

    fn fresh_signer() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn make_intent(pubkey_bs58: &str, expiry: u64) -> Value {
        json!({
            "action": "polymarket_order",
            "solana_pubkey": pubkey_bs58,
            "expiry": expiry,
            "side": "BUY",
            "max_size_usdc": "1000000",
        })
    }

    #[test]
    fn parse_integer_string_basic() {
        assert_eq!(parse_integer_string("0").unwrap(), U256::ZERO);
        assert_eq!(parse_integer_string("42").unwrap(), U256::from(42u64));
        assert_eq!(parse_integer_string("1000000").unwrap(), U256::from(1_000_000u64));
    }

    #[test]
    fn parse_integer_string_rejects_bad_inputs() {
        assert!(parse_integer_string("").is_err());
        assert!(parse_integer_string("-1").is_err());
        assert!(parse_integer_string("1.5").is_err());
        assert!(parse_integer_string("1e2").is_err());
        assert!(parse_integer_string("0x10").is_err());
        assert!(parse_integer_string(" 1").is_err());
    }

    #[test]
    fn parse_decimal_basic() {
        // 6-dec scaling (Polymarket USDC).
        assert_eq!(parse_decimal_to_scaled("1", 6).unwrap(), U256::from(1_000_000u64));
        assert_eq!(parse_decimal_to_scaled("1.5", 6).unwrap(), U256::from(1_500_000u64));
        assert_eq!(parse_decimal_to_scaled("0.55", 6).unwrap(), U256::from(550_000u64));
        assert_eq!(parse_decimal_to_scaled("0", 6).unwrap(), U256::ZERO);
    }

    #[test]
    fn parse_decimal_truncates_excess_fraction() {
        // "1.23456789" at 6 decimals → take first 6 frac digits = "234567"
        // → 1 * 1e6 + 234567 = 1234567. Excess digits dropped.
        let scaled = parse_decimal_to_scaled("1.23456789", 6).unwrap();
        assert_eq!(scaled, U256::from(1_234_567u64));
    }

    #[test]
    fn parse_decimal_rejects_bad_inputs() {
        assert!(parse_decimal_to_scaled("", 6).is_err());
        assert!(parse_decimal_to_scaled(".5", 6).is_err());
        assert!(parse_decimal_to_scaled("1.", 6).is_err());
        assert!(parse_decimal_to_scaled("1..5", 6).is_err());
        assert!(parse_decimal_to_scaled("-1", 6).is_err());
        assert!(parse_decimal_to_scaled("1.5e2", 6).is_err());
    }

    #[test]
    fn verify_intent_signature_happy_path() {
        let signer = fresh_signer();
        let pubkey_bytes = signer.verifying_key().to_bytes();
        let pubkey_bs58 = bs58::encode(pubkey_bytes).into_string();

        let intent = make_intent(&pubkey_bs58, 9_999_999_999);
        let canonical = canonical_bytes(&intent).unwrap();
        let sig = signer.sign(&canonical);
        let sig_bs58 = bs58::encode(sig.to_bytes()).into_string();

        verify_intent_signature(IntentVerifyArgs {
            intent: &intent,
            signature_bs58: &sig_bs58,
            expected_pubkey_bs58: None,
            enforce_expiry: true,
            now_unix_secs: 1_700_000_000,
        })
        .expect("valid sig over canonical intent must verify");
    }

    #[test]
    fn verify_intent_signature_rejects_wrong_sig() {
        let signer = fresh_signer();
        let pubkey_bytes = signer.verifying_key().to_bytes();
        let pubkey_bs58 = bs58::encode(pubkey_bytes).into_string();
        let intent = make_intent(&pubkey_bs58, 9_999_999_999);

        // Sign DIFFERENT bytes than what we'll canonicalize → invalid.
        let sig = signer.sign(b"different message");
        let sig_bs58 = bs58::encode(sig.to_bytes()).into_string();

        let err = verify_intent_signature(IntentVerifyArgs {
            intent: &intent,
            signature_bs58: &sig_bs58,
            expected_pubkey_bs58: None,
            enforce_expiry: true,
            now_unix_secs: 1_700_000_000,
        })
        .unwrap_err();
        assert!(matches!(err, IntentError::InvalidSignature));
    }

    #[test]
    fn verify_intent_signature_rejects_expired() {
        let signer = fresh_signer();
        let pubkey_bs58 = bs58::encode(signer.verifying_key().to_bytes()).into_string();
        let intent = make_intent(&pubkey_bs58, 100); // ancient expiry
        let canonical = canonical_bytes(&intent).unwrap();
        let sig = signer.sign(&canonical);
        let sig_bs58 = bs58::encode(sig.to_bytes()).into_string();

        let err = verify_intent_signature(IntentVerifyArgs {
            intent: &intent,
            signature_bs58: &sig_bs58,
            expected_pubkey_bs58: None,
            enforce_expiry: true,
            now_unix_secs: 1_700_000_000,
        })
        .unwrap_err();
        assert!(matches!(err, IntentError::Expired { .. }));
    }

    #[test]
    fn verify_intent_signature_skips_expiry_when_disabled() {
        let signer = fresh_signer();
        let pubkey_bs58 = bs58::encode(signer.verifying_key().to_bytes()).into_string();
        let intent = make_intent(&pubkey_bs58, 100);
        let canonical = canonical_bytes(&intent).unwrap();
        let sig = signer.sign(&canonical);
        let sig_bs58 = bs58::encode(sig.to_bytes()).into_string();

        verify_intent_signature(IntentVerifyArgs {
            intent: &intent,
            signature_bs58: &sig_bs58,
            expected_pubkey_bs58: None,
            enforce_expiry: false,
            now_unix_secs: 1_700_000_000,
        })
        .expect("expiry skipped when enforce_expiry=false");
    }

    #[test]
    fn verify_intent_signature_missing_pubkey() {
        let intent = json!({"action": "x", "expiry": 9_999_999_999u64});
        let err = verify_intent_signature(IntentVerifyArgs {
            intent: &intent,
            signature_bs58: "any",
            expected_pubkey_bs58: None,
            enforce_expiry: true,
            now_unix_secs: 1_700_000_000,
        })
        .unwrap_err();
        assert!(matches!(err, IntentError::MissingPubkey));
    }

    #[test]
    fn verify_intent_signature_uses_override_pubkey() {
        let signer = fresh_signer();
        let pubkey_bs58 = bs58::encode(signer.verifying_key().to_bytes()).into_string();
        // Intent's own solana_pubkey is wrong, but override matches.
        let mut intent = make_intent("11111111111111111111111111111111", 9_999_999_999);
        let canonical = canonical_bytes(&intent).unwrap();
        let _ = &mut intent;
        let sig = signer.sign(&canonical);
        let sig_bs58 = bs58::encode(sig.to_bytes()).into_string();

        verify_intent_signature(IntentVerifyArgs {
            intent: &intent,
            signature_bs58: &sig_bs58,
            expected_pubkey_bs58: Some(&pubkey_bs58),
            enforce_expiry: true,
            now_unix_secs: 1_700_000_000,
        })
        .expect("override pubkey wins over intent.solana_pubkey");
    }
}
