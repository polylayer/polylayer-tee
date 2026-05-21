//! Typed, encrypted per-user session store.
//!
//! Wraps `DdbSessions` (raw ciphertext rows) + the session DEK into a
//! `put`/`get`/`delete` API over arbitrary `Serialize`/`Deserialize`
//! session structs. Every venue's session schema (Jupiter, HL,
//! polyleverage, generic) goes through this one layer.
//!
//! Each row's `session_id` is a composite key, e.g. `jup-v1#<bs58>`.
//! The session_id is also fed as the AEAD AAD, so a ciphertext sealed
//! for one key can't be lifted into another row.

use crate::ddb::{DdbSessions, SessionBlob};
use crate::session_crypto::{decrypt_blob, encrypt_blob};
use crate::StorageError;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SessionStore {
    ddb: DdbSessions,
    dek: [u8; 32],
}

impl SessionStore {
    pub fn new(ddb: DdbSessions, dek: [u8; 32]) -> Self {
        Self { ddb, dek }
    }

    /// Serialize `value` to JSON, AES-256-GCM seal it under the DEK
    /// (AAD = `key`), and write the row. `expires_at` is an optional
    /// unix-seconds DDB TTL.
    pub async fn put<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        expires_at: Option<u64>,
    ) -> Result<(), StorageError> {
        let plaintext = serde_json::to_vec(value)
            .map_err(|e| StorageError::Encrypt(format!("session json: {e}")))?;
        let (ciphertext_b64, nonce_b64) =
            encrypt_blob(&self.dek, &plaintext, key.as_bytes())?;
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.ddb
            .put(SessionBlob {
                session_id: key.to_string(),
                ciphertext_b64,
                nonce_b64,
                created_at,
                expires_at,
            })
            .await
    }

    /// Read + decrypt + deserialize the session row at `key`. Returns
    /// `None` if no row exists.
    pub async fn get<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let Some(blob) = self.ddb.get(key).await? else {
            return Ok(None);
        };
        let plaintext = decrypt_blob(
            &self.dek,
            &blob.ciphertext_b64,
            &blob.nonce_b64,
            key.as_bytes(),
        )?;
        let value = serde_json::from_slice(&plaintext)
            .map_err(|e| StorageError::Decrypt(format!("session json: {e}")))?;
        Ok(Some(value))
    }

    /// Delete the session row at `key`. Idempotent.
    pub async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.ddb.delete(key).await
    }
}
