//! Polymarket V2 CLOB L2 auth-header construction.
//!
//! Mirrors `eigen-tee/src/lib/clobL2Headers.ts`. Given a user's
//! `(api_key, secret, passphrase)` and the outgoing request shape,
//! returns the 5 `POLY_*` headers Polymarket expects.
//!
//! Pre-image format (matches Polymarket's reference clients):
//! ```text
//!   <ts_seconds><METHOD><path><body>
//! ```
//!
//! Signature: HMAC-SHA256(base64-decoded secret, preimage), then
//! base64-encode the digest with URL-safe substitutions
//! (`+` → `-`, `/` → `_`). Padding `=` retained.

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum L2HeadersError {
    #[error("malformed base64 secret: {0}")]
    BadSecret(String),
}

/// The 5 headers Polymarket's CLOB requires on every authenticated request.
#[derive(Debug, Clone)]
pub struct ClobL2Headers {
    pub poly_address: String,
    pub poly_api_key: String,
    pub poly_passphrase: String,
    pub poly_timestamp: String,
    pub poly_signature: String,
}

pub struct BuildL2HeadersArgs<'a> {
    /// EOA the API key is bound to. Sent verbatim as `POLY_ADDRESS`.
    pub address: &'a str,
    pub api_key: &'a str,
    /// Base64-encoded HMAC key. Decoded internally.
    pub secret: &'a str,
    pub passphrase: &'a str,
    /// HTTP method (case-insensitive — normalized to uppercase).
    pub method: &'a str,
    /// URL path (must start with `/`).
    pub path: &'a str,
    /// Stringified JSON body for POSTs; "" for GET/DELETE.
    pub body: &'a str,
    /// Unix seconds. Caller supplies — keeps the fn pure.
    pub timestamp_secs: u64,
}

type HmacSha256 = Hmac<Sha256>;

pub fn build_l2_headers(args: BuildL2HeadersArgs<'_>) -> Result<ClobL2Headers, L2HeadersError> {
    let ts = args.timestamp_secs.to_string();
    let preimage = format!(
        "{ts}{method}{path}{body}",
        ts = ts,
        method = args.method.to_uppercase(),
        path = args.path,
        body = args.body
    );

    let decoded_secret = B64_STANDARD
        .decode(args.secret.as_bytes())
        .map_err(|e| L2HeadersError::BadSecret(e.to_string()))?;
    let mut mac = HmacSha256::new_from_slice(&decoded_secret)
        .expect("HMAC accepts any key length");
    mac.update(preimage.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut sig_b64 = B64_STANDARD.encode(digest);
    // URL-safe substitutions, keep `=` padding.
    sig_b64 = sig_b64.replace('+', "-").replace('/', "_");

    Ok(ClobL2Headers {
        poly_address: args.address.to_string(),
        poly_api_key: args.api_key.to_string(),
        poly_passphrase: args.passphrase.to_string(),
        poly_timestamp: ts,
        poly_signature: sig_b64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_headers_deterministic() {
        let args = BuildL2HeadersArgs {
            address: "0xabc",
            api_key: "test-key",
            secret: "MTIzNDU2Nzg=", // base64("12345678")
            passphrase: "pp",
            method: "POST",
            path: "/order",
            body: r#"{"a":1}"#,
            timestamp_secs: 1_700_000_000,
        };
        let a = build_l2_headers(BuildL2HeadersArgs { ..args }).unwrap();
        let b = build_l2_headers(BuildL2HeadersArgs {
            address: "0xabc",
            api_key: "test-key",
            secret: "MTIzNDU2Nzg=",
            passphrase: "pp",
            method: "POST",
            path: "/order",
            body: r#"{"a":1}"#,
            timestamp_secs: 1_700_000_000,
        })
        .unwrap();
        assert_eq!(a.poly_signature, b.poly_signature);
        assert_eq!(a.poly_timestamp, "1700000000");
    }

    #[test]
    fn method_normalized_to_uppercase() {
        let lowercase = build_l2_headers(BuildL2HeadersArgs {
            address: "0xabc",
            api_key: "k",
            secret: "MTIzNDU2Nzg=",
            passphrase: "p",
            method: "post",
            path: "/x",
            body: "",
            timestamp_secs: 1_000_000,
        })
        .unwrap();
        let uppercase = build_l2_headers(BuildL2HeadersArgs {
            address: "0xabc",
            api_key: "k",
            secret: "MTIzNDU2Nzg=",
            passphrase: "p",
            method: "POST",
            path: "/x",
            body: "",
            timestamp_secs: 1_000_000,
        })
        .unwrap();
        assert_eq!(lowercase.poly_signature, uppercase.poly_signature);
    }

    #[test]
    fn url_safe_substitutions_applied() {
        // Pick inputs that produce `+` / `/` in the unsubstituted base64
        // form. The substitutions must replace them.
        let h = build_l2_headers(BuildL2HeadersArgs {
            address: "0xabc",
            api_key: "k",
            secret: "MTIzNDU2Nzg=",
            passphrase: "p",
            method: "POST",
            path: "/some-path",
            body: r#"{"x":42}"#,
            timestamp_secs: 1_700_000_000,
        })
        .unwrap();
        assert!(!h.poly_signature.contains('+'));
        assert!(!h.poly_signature.contains('/'));
    }

    #[test]
    fn bad_secret_rejected() {
        let err = build_l2_headers(BuildL2HeadersArgs {
            address: "0xabc",
            api_key: "k",
            secret: "!!!not base64!!!",
            passphrase: "p",
            method: "GET",
            path: "/",
            body: "",
            timestamp_secs: 1_000_000,
        })
        .unwrap_err();
        assert!(matches!(err, L2HeadersError::BadSecret(_)));
    }
}
