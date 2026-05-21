//! AES-256-GCM sealing of per-user session blobs.
//!
//! Session JSON is encrypted under a DEK derived from the master
//! mnemonic (`core::derive::Master::session_dek`). DynamoDB only ever
//! sees ciphertext + nonce. The AAD binds each ciphertext to its
//! session key, so a blob sealed for one user/venue cannot be replayed
//! into another session row.

use crate::StorageError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand_core::{OsRng, RngCore};

/// AES-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

/// Encrypt `plaintext` under `dek`, authenticating `aad`.
///
/// Returns `(ciphertext_b64, nonce_b64)` ready to drop straight into a
/// `SessionBlob`. A fresh random nonce is generated per call.
pub fn encrypt_blob(
    dek: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(String, String), StorageError> {
    let cipher = Aes256Gcm::new(dek.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| StorageError::Encrypt(format!("aes-gcm seal: {e}")))?;
    Ok((B64.encode(ct), B64.encode(nonce_bytes)))
}

/// Decrypt a `SessionBlob`'s `(ciphertext_b64, nonce_b64)` under `dek`,
/// verifying `aad`. A wrong DEK, tampered ciphertext, or mismatched
/// AAD all surface as `StorageError::Decrypt`.
pub fn decrypt_blob(
    dek: &[u8; 32],
    ciphertext_b64: &str,
    nonce_b64: &str,
    aad: &[u8],
) -> Result<Vec<u8>, StorageError> {
    let ct = B64
        .decode(ciphertext_b64)
        .map_err(|e| StorageError::Decrypt(format!("ciphertext base64: {e}")))?;
    let nonce_bytes = B64
        .decode(nonce_b64)
        .map_err(|e| StorageError::Decrypt(format!("nonce base64: {e}")))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(StorageError::Decrypt(format!(
            "nonce length {} != {NONCE_LEN}",
            nonce_bytes.len()
        )));
    }
    let cipher = Aes256Gcm::new(dek.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: &ct, aad })
        .map_err(|e| StorageError::Decrypt(format!("aes-gcm open: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dek = [7u8; 32];
        let (ct, nonce) = encrypt_blob(&dek, b"hello session", b"aad-1").unwrap();
        let pt = decrypt_blob(&dek, &ct, &nonce, b"aad-1").unwrap();
        assert_eq!(pt, b"hello session");
    }

    #[test]
    fn wrong_aad_fails() {
        let dek = [7u8; 32];
        let (ct, nonce) = encrypt_blob(&dek, b"hello", b"aad-1").unwrap();
        assert!(decrypt_blob(&dek, &ct, &nonce, b"aad-2").is_err());
    }

    #[test]
    fn wrong_dek_fails() {
        let (ct, nonce) = encrypt_blob(&[1u8; 32], b"hello", b"aad").unwrap();
        assert!(decrypt_blob(&[2u8; 32], &ct, &nonce, b"aad").is_err());
    }

    #[test]
    fn distinct_nonces_per_call() {
        let dek = [9u8; 32];
        let (_, n1) = encrypt_blob(&dek, b"x", b"a").unwrap();
        let (_, n2) = encrypt_blob(&dek, b"x", b"a").unwrap();
        assert_ne!(n1, n2, "nonce must be fresh per encryption");
    }
}
