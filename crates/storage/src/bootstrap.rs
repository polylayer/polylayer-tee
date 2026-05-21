//! Master-mnemonic bootstrap orchestration.
//!
//! Boot sequence inside the enclave:
//!
//! 1. Load `StorageConfig` from env (set by parent EC2 user-data).
//! 2. Init AWS SDK clients (KMS, S3, DDB). All HTTP traffic goes
//!    through the parent's vsock-proxy.
//! 3. Try `s3.get_blob(mnemonic_key)`.
//!    - **Found** (the normal case): KMS-decrypt with attestation,
//!      return the plaintext mnemonic.
//!    - **NotFound** (first-ever boot): generate a fresh BIP-39
//!      mnemonic, KMS-encrypt it, write the ciphertext to S3, return
//!      the plaintext. Log distinctly so we know on first deploy.
//! 4. Caller (`server::main`) uses the plaintext to construct
//!    `core::derive::Master`. The plaintext is zeroized as soon as
//!    the Master is built.

use crate::config::StorageConfig;
use crate::ddb::DdbSessions;
use crate::kms::KmsClient;
use crate::s3::S3Client;
use crate::vsock_creds::VsockCredsProvider;
use crate::vsock_transport;
use crate::StorageError;
use aws_config::identity::IdentityCache;
use bip39::Mnemonic;
use rand_core::{OsRng, RngCore};
use std::time::Duration;
use tracing::{info, warn};
use zeroize::Zeroize;

pub struct LoadedSecrets {
    /// Plaintext BIP-39 mnemonic. ZEROIZE THIS as soon as derivation
    /// completes.
    pub mnemonic: String,
}

pub struct Storage {
    pub config: StorageConfig,
    pub kms: KmsClient,
    pub s3: S3Client,
    pub ddb: DdbSessions,
    /// Bearer token the trading lambda uses to auth against the TEE,
    /// vended by the parent's imds-bridge alongside AWS creds. `None`
    /// on the local-dev path — callers should fall back to the
    /// EIGEN_TEE_ADMIN_TOKEN env var.
    pub admin_token: Option<String>,
}

impl Storage {
    pub async fn from_env() -> Result<Self, StorageError> {
        let config = StorageConfig::from_env()?;
        let use_vsock = std::env::var("POLYLAYER_TEE_USE_VSOCK").is_ok();

        // Base SDK config. Inside the enclave we additionally:
        //   - spawn localhost-to-vsock bridge tasks (so loopback dials
        //     reach the parent's vsock-proxy);
        //   - fetch STS credentials from the parent over vsock 9000;
        //   - override per-service endpoint_url to the bridge ports.
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(config.region.clone()));

        let mut admin_token: Option<String> = None;
        if use_vsock {
            info!("POLYLAYER_TEE_USE_VSOCK=1 → enabling vsock transport for AWS SDK");
            vsock_transport::spawn_all_bridges().await?;

            // Build a self-refreshing credentials provider that hits
            // the parent's imds-bridge on each refresh. Pre-warm it
            // once so we can pick up the admin bearer token before
            // returning — the SDK refresh path won't surface it.
            let provider = VsockCredsProvider::new();
            let state = provider.state();
            use aws_credential_types::provider::ProvideCredentials;
            let _initial = provider.provide_credentials().await.map_err(|e| {
                StorageError::Aws(format!("vsock creds pre-warm: {e}"))
            })?;
            admin_token = state
                .admin_token
                .lock()
                .expect("admin_token mutex")
                .clone();

            // Wrap in an IdentityCache with a 1h buffer time. STS
            // instance-role tokens last ~6h; the SDK will call our
            // provider when within 1h of expiry. Sliding refresh gives
            // ~5h between vsock round-trips and a clean 1h fail-soft
            // window if the parent's IMDS hiccups.
            let cache = IdentityCache::lazy()
                .buffer_time(Duration::from_secs(3600))
                .build();
            loader = loader
                .credentials_provider(provider)
                .identity_cache(cache);
        }

        let aws_config = loader.load().await;

        let (kms_client, s3_client, ddb_client) = if use_vsock {
            // Per-service builders so we can override endpoint_url per
            // SDK. Each endpoint resolves to 127.0.0.1 (via baked-in
            // /etc/hosts) at the bridge port — TLS still presents the
            // real hostname's certificate via the parent's transparent
            // vsock-proxy.
            let kms_cfg = aws_sdk_kms::config::Builder::from(&aws_config)
                .endpoint_url(vsock_transport::kms_endpoint(&config.region))
                .build();
            let s3_cfg = aws_sdk_s3::config::Builder::from(&aws_config)
                .endpoint_url(vsock_transport::s3_endpoint(&config.region))
                .force_path_style(true)
                .build();
            let ddb_cfg = aws_sdk_dynamodb::config::Builder::from(&aws_config)
                .endpoint_url(vsock_transport::ddb_endpoint(&config.region))
                .build();
            (
                aws_sdk_kms::Client::from_conf(kms_cfg),
                aws_sdk_s3::Client::from_conf(s3_cfg),
                aws_sdk_dynamodb::Client::from_conf(ddb_cfg),
            )
        } else {
            (
                aws_sdk_kms::Client::new(&aws_config),
                aws_sdk_s3::Client::new(&aws_config),
                aws_sdk_dynamodb::Client::new(&aws_config),
            )
        };

        Ok(Self {
            kms: KmsClient::new(kms_client, config.kms_key_id.clone()),
            s3: S3Client::new(s3_client, config.mnemonic_bucket.clone()),
            ddb: DdbSessions::new(ddb_client, config.sessions_table.clone()),
            config,
            admin_token,
        })
    }

    /// Bootstrap the master mnemonic. Returns plaintext bytes — caller
    /// must zeroize after deriving the Master.
    pub async fn load_or_create_mnemonic(&self) -> Result<LoadedSecrets, StorageError> {
        match self.s3.get_blob(&self.config.mnemonic_key).await {
            Ok(ciphertext) => {
                info!("found sealed mnemonic in S3, decrypting with KMS attestation");
                let plaintext = self.kms.decrypt_with_attestation(&ciphertext).await?;
                let mnemonic = String::from_utf8(plaintext)
                    .map_err(|e| StorageError::Decrypt(format!("plaintext not utf-8: {e}")))?;
                Ok(LoadedSecrets { mnemonic })
            }
            Err(StorageError::NotFound(_)) => {
                warn!(
                    "no sealed mnemonic at s3://{}/{} — FIRST-TIME BOOTSTRAP. \
                     Generating a new mnemonic. This will only happen once.",
                    self.config.mnemonic_bucket, self.config.mnemonic_key
                );
                let mut entropy = [0u8; 32]; // 24-word mnemonic
                OsRng.fill_bytes(&mut entropy);
                let m = Mnemonic::from_entropy(&entropy)
                    .map_err(|e| StorageError::Encrypt(format!("bip39: {e}")))?;
                let mut phrase = m.to_string();

                let ciphertext = self.kms.encrypt(phrase.as_bytes()).await?;
                self.s3.put_blob(&self.config.mnemonic_key, ciphertext).await?;
                info!("sealed mnemonic written to S3");

                // Zero the local entropy copy; the returned mnemonic
                // String still holds the phrase but caller zeroizes
                // after deriving Master.
                entropy.zeroize();
                let result = LoadedSecrets {
                    mnemonic: phrase.clone(),
                };
                phrase.zeroize();
                Ok(result)
            }
            Err(other) => Err(other),
        }
    }
}
