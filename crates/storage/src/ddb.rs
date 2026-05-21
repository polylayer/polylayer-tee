//! DynamoDB-backed encrypted session store.
//!
//! Sessions are blobs encrypted by a DEK derived from the master
//! mnemonic (HKDF(master_seed, "polylayer-sessions-dek-v1")). The
//! enclave keeps the DEK in memory; DDB sees only ciphertext.
//!
//! Schema:
//!
//! ```text
//!   TableName: PolylayerTeeSessions (configurable via env)
//!   PrimaryKey: session_id (S)
//!   Attributes:
//!     - session_id (S)         — partition key
//!     - ciphertext_b64 (S)     — base64(AEAD(plaintext_json, DEK, nonce, AAD=session_id))
//!     - nonce_b64 (S)          — 12-byte AES-GCM nonce
//!     - created_at (N)         — unix seconds
//!     - expires_at (N, opt)    — unix seconds; DDB TTL attribute
//! ```

use crate::StorageError;
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;
use std::collections::HashMap;
use tracing::debug;

pub struct DdbSessions {
    client: Client,
    table: String,
}

#[derive(Debug, Clone)]
pub struct SessionBlob {
    pub session_id: String,
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

impl DdbSessions {
    pub fn new(client: Client, table: String) -> Self {
        Self { client, table }
    }

    pub async fn put(&self, blob: SessionBlob) -> Result<(), StorageError> {
        debug!(session_id = %blob.session_id, "ddb put session");
        let mut item: HashMap<String, AttributeValue> = HashMap::new();
        item.insert("session_id".into(), AttributeValue::S(blob.session_id));
        item.insert("ciphertext_b64".into(), AttributeValue::S(blob.ciphertext_b64));
        item.insert("nonce_b64".into(), AttributeValue::S(blob.nonce_b64));
        item.insert(
            "created_at".into(),
            AttributeValue::N(blob.created_at.to_string()),
        );
        if let Some(exp) = blob.expires_at {
            item.insert("expires_at".into(), AttributeValue::N(exp.to_string()));
        }
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| StorageError::Aws(format!("ddb put_item: {e}")))?;
        Ok(())
    }

    pub async fn get(&self, session_id: &str) -> Result<Option<SessionBlob>, StorageError> {
        let out = self
            .client
            .get_item()
            .table_name(&self.table)
            .key("session_id", AttributeValue::S(session_id.to_string()))
            .send()
            .await
            .map_err(|e| StorageError::Aws(format!("ddb get_item: {e}")))?;
        let Some(item) = out.item else {
            return Ok(None);
        };
        Ok(Some(SessionBlob {
            session_id: get_s(&item, "session_id")?,
            ciphertext_b64: get_s(&item, "ciphertext_b64")?,
            nonce_b64: get_s(&item, "nonce_b64")?,
            created_at: get_n(&item, "created_at")?,
            expires_at: try_get_n(&item, "expires_at"),
        }))
    }

    pub async fn delete(&self, session_id: &str) -> Result<(), StorageError> {
        self.client
            .delete_item()
            .table_name(&self.table)
            .key("session_id", AttributeValue::S(session_id.to_string()))
            .send()
            .await
            .map_err(|e| StorageError::Aws(format!("ddb delete_item: {e}")))?;
        Ok(())
    }
}

fn get_s(item: &HashMap<String, AttributeValue>, key: &str) -> Result<String, StorageError> {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .cloned()
        .ok_or_else(|| StorageError::Aws(format!("ddb item missing string attr {key}")))
}

fn get_n(item: &HashMap<String, AttributeValue>, key: &str) -> Result<u64, StorageError> {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| StorageError::Aws(format!("ddb item missing numeric attr {key}")))
}

fn try_get_n(item: &HashMap<String, AttributeValue>, key: &str) -> Option<u64> {
    item.get(key).and_then(|v| v.as_n().ok()).and_then(|s| s.parse().ok())
}
