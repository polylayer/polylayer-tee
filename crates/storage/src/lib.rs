//! Polylayer TEE — persistent storage layer.
//!
//! All AWS calls flow through the parent EC2's vsock-proxy. The enclave
//! has no direct network; see `deploy/cloud-init/vsock-proxy.yaml` for
//! the allowlist (KMS / S3 / DDB / clob.polymarket.com / api.hyperliquid.xyz).
//!
//! Modules:
//!
//! - `config`: env-driven runtime configuration (bucket names, key IDs)
//! - `kms`:    attestation-gated decrypt of the sealed master mnemonic
//! - `s3`:     read/write the sealed ciphertext blob
//! - `ddb`:    encrypted session storage keyed by session_id
//! - `bootstrap`: the boot-time master-mnemonic loader (KMS + S3 dance)

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod cms_envelope;
pub mod config;
pub mod ddb;
pub mod kms;
pub mod s3;
pub mod session_crypto;
pub mod session_store;
pub mod vsock_creds;
pub mod vsock_transport;

pub use bootstrap::{LoadedSecrets, Storage};
pub use config::StorageConfig;
pub use session_store::SessionStore;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("aws sdk error: {0}")]
    Aws(String),

    #[error("decrypt failed: {0}")]
    Decrypt(String),

    #[error("encrypt failed: {0}")]
    Encrypt(String),

    #[error("blob not found: {0}")]
    NotFound(String),

    #[error("nsm error: {0}")]
    Nsm(#[from] polylayer_tee_nsm::NsmError),

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(String),
}
