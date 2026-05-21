//! Canonical JSON serialization for signed intents.
//!
//! Mirrors `eigen-tee/src/lib/canonical.ts`. The signed-bytes ↔ JSON
//! mapping must be unambiguous: object keys sorted, no extra whitespace,
//! no implicit number coercion, no NaN/Infinity. Both client (frontend)
//! and server (this enclave) MUST canonicalize identically — any drift
//! is an unverifiable-intent bug class.
//!
//! Spec (RFC-8785-ish, but we don't pull JCS for our narrow needs):
//!
//! - `null`                         → `"null"`
//! - `bool`                         → `"true"` / `"false"`
//! - `string`                       → standard JSON string escaping
//! - `number` (integer or finite f) → JSON number form; **reject NaN/∞**
//! - `array`                        → `"[" + items.map(canon).join(",") + "]"`
//! - `object`                       → keys sorted **bytewise** at every
//!                                    level (matches JS `String.localeCompare`
//!                                    for ASCII keys — and our intents
//!                                    never use non-ASCII keys)
//!
//! ## Float caveat
//!
//! JS `JSON.stringify` for floats uses ECMAScript's `NumberToString`.
//! Rust `serde_json::Number::to_string` uses Ryu. For all integers and
//! most finite floats they agree, but a few exotic floats (e.g.,
//! `1e21` → `"1e+21"` in JS vs `"1e21"` in Ryu) diverge. Polylayer
//! intents only ever carry integer numbers (sizes in atoms, timestamps,
//! indices) — never floats — so this is theoretical. The TS-parity
//! fixtures (task #170) will catch any unexpected divergence.

use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("non-finite number is not allowed in a signed intent")]
    NonFiniteNumber,

    #[error("unsupported JSON value variant")]
    UnsupportedVariant,
}

/// Canonicalize a `serde_json::Value` into the exact UTF-8 string a
/// Solana wallet would have signed over.
pub fn canonicalize(input: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_canonical(input, &mut out)?;
    Ok(out)
}

/// Same, but returns the bytes directly (slightly cheaper than
/// `canonicalize` + `into_bytes` because we never re-allocate).
pub fn canonical_bytes(input: &Value) -> Result<Vec<u8>, CanonicalError> {
    canonicalize(input).map(String::into_bytes)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => {
            out.push_str("null");
            Ok(())
        }
        Value::Bool(true) => {
            out.push_str("true");
            Ok(())
        }
        Value::Bool(false) => {
            out.push_str("false");
            Ok(())
        }
        Value::String(s) => {
            // serde_json's display for Value::String produces RFC-8259
            // string escaping identical to `JSON.stringify` for any
            // valid UTF-8 input. Surrogate handling is not an issue
            // because Rust strings are guaranteed UTF-8 (lone surrogates
            // are unrepresentable here, unlike in JS).
            let escaped = serde_json::to_string(s).expect("serializing a string never fails");
            out.push_str(&escaped);
            Ok(())
        }
        Value::Number(n) => {
            // Reject non-finite numbers: serde_json::Number::is_f64
            // returns true for floats that fit f64, but the actual f64
            // could be NaN or ±Inf. Defensive check matches the TS
            // `Number.isFinite` guard.
            if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(CanonicalError::NonFiniteNumber);
                }
            }
            out.push_str(&n.to_string());
            Ok(())
        }
        Value::Array(items) => {
            out.push('[');
            let mut first = true;
            for item in items {
                if !first {
                    out.push(',');
                }
                first = false;
                write_canonical(item, out)?;
            }
            out.push(']');
            Ok(())
        }
        Value::Object(map) => {
            // Sort keys bytewise. serde_json::Map preserves insertion
            // order by default; canonicalization requires deterministic
            // ordering at every level.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            let mut first = true;
            for k in keys {
                if !first {
                    out.push(',');
                }
                first = false;
                let escaped =
                    serde_json::to_string(k).expect("serializing a string never fails");
                out.push_str(&escaped);
                out.push(':');
                write_canonical(&map[k], out)?;
            }
            out.push('}');
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn primitives() {
        assert_eq!(canonicalize(&Value::Null).unwrap(), "null");
        assert_eq!(canonicalize(&json!(true)).unwrap(), "true");
        assert_eq!(canonicalize(&json!(false)).unwrap(), "false");
        assert_eq!(canonicalize(&json!(0)).unwrap(), "0");
        assert_eq!(canonicalize(&json!(42)).unwrap(), "42");
        assert_eq!(canonicalize(&json!(-1)).unwrap(), "-1");
    }

    #[test]
    fn strings_match_json_stringify_escaping() {
        assert_eq!(canonicalize(&json!("hello")).unwrap(), r#""hello""#);
        assert_eq!(canonicalize(&json!("a\"b")).unwrap(), r#""a\"b""#);
        assert_eq!(canonicalize(&json!("a\\b")).unwrap(), r#""a\\b""#);
        assert_eq!(canonicalize(&json!("\n")).unwrap(), r#""\n""#);
        assert_eq!(canonicalize(&json!("\t")).unwrap(), r#""\t""#);
    }

    #[test]
    fn object_keys_sorted_bytewise() {
        let input = json!({"b": 1, "a": 2, "c": 3});
        let s = canonicalize(&input).unwrap();
        assert_eq!(s, r#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn nested_object_keys_sorted_at_every_level() {
        let input = json!({
            "z": {"y": 1, "x": 2},
            "a": [3, {"q": 4, "p": 5}]
        });
        let s = canonicalize(&input).unwrap();
        assert_eq!(
            s,
            r#"{"a":[3,{"p":5,"q":4}],"z":{"x":2,"y":1}}"#
        );
    }

    #[test]
    fn arrays_preserve_order() {
        let input = json!([3, 1, 2]);
        assert_eq!(canonicalize(&input).unwrap(), "[3,1,2]");
    }

    #[test]
    fn no_whitespace_anywhere() {
        let input = json!({"a": [1, 2], "b": {"c": 3}});
        let s = canonicalize(&input).unwrap();
        assert!(!s.contains(' '));
        assert!(!s.contains('\n'));
    }

    #[test]
    fn realistic_polymarket_intent() {
        // Shape close to what an actual signed Polymarket order intent
        // looks like. Canonical form must be deterministic; we check
        // structural properties + bytewise key order.
        let input = json!({
            "action": "polymarket_order",
            "max_price": "0.5",
            "max_size_usdc": "1000000",
            "market_id": "0xabc123",
            "salt": "0xdeadbeef",
            "side": "BUY",
            "solana_pubkey": "GgVfgUkkAJEErjDQ4Wq2WkmKjyMHgWj9Yk7K5UYYS6Az",
            "expiry": 1779000000,
            "token_id": "0xtoken"
        });
        let s = canonicalize(&input).unwrap();
        // Action key should come before all the others alphabetically.
        assert!(s.starts_with(r#"{"action":"polymarket_order","expiry":"#));
        // No whitespace.
        assert!(!s.contains(' '));
    }

    #[test]
    fn non_finite_numbers_rejected() {
        // serde_json::Number can't represent NaN/Inf directly via
        // standard parsing — they'd come in as nulls. Use json!() with
        // a manually-constructed Number to exercise the guard.
        let n = serde_json::Number::from_f64(f64::NAN);
        assert!(n.is_none(), "serde_json refuses to construct NaN Numbers");

        let inf = serde_json::Number::from_f64(f64::INFINITY);
        assert!(inf.is_none(), "serde_json refuses to construct Inf Numbers");
        // The CanonicalError::NonFiniteNumber branch is therefore
        // defensive — serde_json's own Number type bans non-finite
        // floats before they reach us. Documented in the canonical
        // module preamble.
    }

    #[test]
    fn deterministic_across_runs() {
        let input = json!({"b": [{"d": 1}, 2], "a": "x", "c": null});
        let a = canonicalize(&input).unwrap();
        let b = canonicalize(&input).unwrap();
        assert_eq!(a, b);
    }
}
