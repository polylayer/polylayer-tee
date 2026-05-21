//! Runtime configuration read from env at boot.
//!
//! These are set by the parent EC2's user-data script. The enclave
//! itself has no filesystem; these env values come in via the
//! `nitro-cli run-enclave --enclave-cid ... --enclave-name ...`
//! mechanism that the parent provides.

use crate::StorageError;

pub struct StorageConfig {
    /// AWS region (e.g. "eu-central-1").
    pub region: String,
    /// S3 bucket holding the sealed mnemonic blob.
    pub mnemonic_bucket: String,
    /// S3 key for the sealed mnemonic blob.
    pub mnemonic_key: String,
    /// KMS Customer Master Key ARN/ID with attestation-gated decrypt policy.
    pub kms_key_id: String,
    /// DynamoDB table name for encrypted session blobs.
    pub sessions_table: String,
}

impl StorageConfig {
    pub fn from_env() -> Result<Self, StorageError> {
        Ok(Self {
            region: env("AWS_REGION")?,
            mnemonic_bucket: env("POLYLAYER_TEE_MNEMONIC_BUCKET")?,
            mnemonic_key: env_or("POLYLAYER_TEE_MNEMONIC_KEY", "master-seed.sealed"),
            kms_key_id: env("POLYLAYER_TEE_KMS_KEY_ID")?,
            sessions_table: env_or("POLYLAYER_TEE_SESSIONS_TABLE", "PolylayerTeeSessions"),
        })
    }
}

fn env(name: &str) -> Result<String, StorageError> {
    std::env::var(name).map_err(|_| StorageError::Config(format!("missing env {name}")))
}

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.into())
}
