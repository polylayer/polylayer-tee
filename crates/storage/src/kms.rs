//! Attestation-gated KMS decrypt + encrypt for the sealed master mnemonic.
//!
//! ## Decrypt (boot path)
//!
//! 1. Get a fresh Nitro attestation document via `polylayer_tee_nsm`.
//! 2. Call `KMS.Decrypt` with the ciphertext + `Recipient.AttestationDocument`.
//! 3. KMS verifies the attestation matches its key-policy condition
//!    (`kms:RecipientAttestation:PCR0/PCR8/...`), then encrypts the
//!    plaintext to the ephemeral public key embedded in the attestation
//!    doc and returns the wrapped result.
//! 4. The enclave decrypts the wrapped envelope with the matching
//!    private key (which only this attestation doc could be issued
//!    against), yielding the master mnemonic in enclave memory.
//!
//! See: <https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html>
//!
//! ## Encrypt (bootstrap path)
//!
//! First-time-only ceremony: enclave generates a fresh mnemonic, calls
//! `KMS.Encrypt` (no attestation needed for encrypt — the KEY POLICY
//! requires attestation for decrypt), stores the ciphertext in S3.

use crate::cms_envelope::decrypt_enveloped_data;
use crate::StorageError;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::RecipientInfo;
use aws_sdk_kms::Client;
use polylayer_tee_nsm::{get_attestation_document, AttestationRequest};
use rsa::pkcs8::EncodePublicKey;
use rsa::RsaPrivateKey;
use tracing::{debug, info};

pub struct KmsClient {
    client: Client,
    key_id: String,
}

impl KmsClient {
    pub fn new(client: Client, key_id: String) -> Self {
        Self { client, key_id }
    }

    /// Decrypt sealed ciphertext using a fresh Nitro attestation doc.
    ///
    /// Flow:
    /// 1. Generate a fresh 2048-bit RSA keypair in enclave memory.
    /// 2. DER-encode the public key as SubjectPublicKeyInfo and embed
    ///    it in the Nitro attestation document.
    /// 3. Call `KMS.Decrypt(ciphertext, Recipient{algorithm: RSAES-OAEP-SHA-256,
    ///    attestation_document})`. KMS validates the attestation, then
    ///    returns the plaintext re-encrypted as a CMS PKCS#7
    ///    EnvelopedData where the CEK is RSA-OAEP-encrypted to the
    ///    public key in the attestation doc.
    /// 4. RSA-OAEP-decrypt the CEK with our private key; AES-256-CBC
    ///    decrypt the encrypted content. That's the plaintext.
    ///
    /// The PCR0 binding lives in KMS's key policy
    /// (`kms:RecipientAttestation:PCR0` condition); KMS won't even
    /// produce the CMS envelope unless the attestation matches.
    ///
    /// On platforms without NSM (dev laptops) the `mock` feature
    /// returns canned attestation bytes; KMS rejects those, so this
    /// code path is only exercised inside a real enclave.
    pub async fn decrypt_with_attestation(
        &self,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, StorageError> {
        debug!(
            "kms decrypt with attestation, ciphertext_len={}",
            ciphertext.len()
        );

        // ── 1. Generate ephemeral RSA-2048 keypair ────────────────
        // Using OsRng (not NSM RNG) because we want plain `OsRng`
        // semantics for the rsa crate. Inside the enclave OsRng draws
        // from `/dev/urandom` which is seeded by NSM at boot.
        let mut rng = rand_core::OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).map_err(|e| {
            StorageError::Decrypt(format!("rsa keygen: {e}"))
        })?;
        let pub_key_der = priv_key
            .to_public_key()
            .to_public_key_der()
            .map_err(|e| StorageError::Decrypt(format!("encode pubkey der: {e}")))?
            .into_vec();

        // ── 2. Attestation doc binding this pubkey + a fresh nonce ─
        let mut nonce = [0u8; 32];
        polylayer_tee_nsm::get_random_bytes(&mut nonce)?;
        let attestation = get_attestation_document(AttestationRequest {
            user_data: None,
            nonce: Some(&nonce),
            public_key: Some(&pub_key_der),
        })?;

        // ── 3. KMS Decrypt with Recipient ─────────────────────────
        let recipient = RecipientInfo::builder()
            .key_encryption_algorithm(
                aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256,
            )
            .attestation_document(Blob::new(attestation))
            .build();

        let out = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(ciphertext.to_vec()))
            .recipient(recipient)
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(|e| StorageError::Decrypt(format!("kms decrypt: {e}")))?;

        // ── 4. Unwrap the CMS envelope ────────────────────────────
        let envelope = out
            .ciphertext_for_recipient()
            .ok_or_else(|| {
                StorageError::Decrypt(
                    "kms returned no ciphertext_for_recipient (was the Recipient \
                     attestation accepted?)"
                        .into(),
                )
            })?
            .as_ref()
            .to_vec();

        let plaintext = decrypt_enveloped_data(&envelope, &priv_key)
            .map_err(|e| StorageError::Decrypt(format!("cms unwrap: {e}")))?;
        info!(
            "kms decrypt-with-recipient unwrapped {} plaintext bytes",
            plaintext.len()
        );
        Ok(plaintext)
    }

    /// Encrypt plaintext under the configured KMS key. No attestation
    /// needed for encrypt — the key policy only gates DECRYPT on
    /// attestation. Used by the first-time bootstrap path.
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
        let out = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(Blob::new(plaintext.to_vec()))
            .send()
            .await
            .map_err(|e| StorageError::Encrypt(format!("kms encrypt: {e}")))?;
        let ciphertext = out
            .ciphertext_blob()
            .ok_or_else(|| StorageError::Encrypt("kms returned no ciphertext".into()))?
            .as_ref()
            .to_vec();
        info!("kms encrypted {} bytes → {} ciphertext bytes", plaintext.len(), ciphertext.len());
        Ok(ciphertext)
    }
}
