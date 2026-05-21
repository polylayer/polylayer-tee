//! Polylayer TEE — Nitro Security Module wrapper.
//!
//! Two-mode design via cargo features:
//!
//! - **Default (real NSM)**: calls into `/dev/nsm` via the
//!   `aws-nitro-enclaves-nsm-api` crate. Only works inside an actual
//!   Nitro enclave; the device is not present on dev laptops.
//!
//! - **`mock` feature**: returns canned attestation documents that look
//!   structurally valid but cannot be verified against a real Nitro root
//!   CA. Use for local dev + integration tests where you just need to
//!   exercise the rest of the stack without a real enclave.
//!
//! The `mock` mode is also auto-selected on non-Linux targets (Mac dev
//! laptops), because the upstream crate doesn't build there.

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NsmError {
    #[error("nsm device unavailable: {0}")]
    Unavailable(String),

    #[error("attestation request rejected by nsm: {0}")]
    AttestationRejected(String),
}

/// Arguments to attestation document generation. Mirrors the NSM API.
///
/// - `user_data`: arbitrary bytes the caller can pin to this attestation
///   (e.g., a hash of the request that the KMS Decrypt call covers).
/// - `nonce`: prevents replay; KMS verifies it matches its expectation.
/// - `public_key`: optional ephemeral key the document binds to (used
///   for `kms:RecipientAttestation` flows so KMS can encrypt the
///   response to a key only this enclave holds).
pub struct AttestationRequest<'a> {
    pub user_data: Option<&'a [u8]>,
    pub nonce: Option<&'a [u8]>,
    pub public_key: Option<&'a [u8]>,
}

/// Get a Nitro attestation document. Returns the COSE-signed bytes
/// suitable for passing in `kms:Decrypt`'s `Recipient` field.
pub fn get_attestation_document(req: AttestationRequest<'_>) -> Result<Vec<u8>, NsmError> {
    #[cfg(all(target_os = "linux", not(feature = "mock")))]
    {
        return real::get_attestation_document(req);
    }
    #[cfg(any(not(target_os = "linux"), feature = "mock"))]
    {
        return mock::get_attestation_document(req);
    }
}

/// Hardware entropy from the NSM. Same fallback strategy as
/// `get_attestation_document`.
pub fn get_random_bytes(out: &mut [u8]) -> Result<(), NsmError> {
    #[cfg(all(target_os = "linux", not(feature = "mock")))]
    {
        return real::get_random_bytes(out);
    }
    #[cfg(any(not(target_os = "linux"), feature = "mock"))]
    {
        return mock::get_random_bytes(out);
    }
}

#[cfg(all(target_os = "linux", not(feature = "mock")))]
mod real {
    use super::{AttestationRequest, NsmError};
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    pub fn get_attestation_document(req: AttestationRequest<'_>) -> Result<Vec<u8>, NsmError> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(NsmError::Unavailable(format!("nsm_init returned {fd}")));
        }
        let nsm_req = Request::Attestation {
            user_data: req.user_data.map(|b| b.to_vec().into()),
            nonce: req.nonce.map(|b| b.to_vec().into()),
            public_key: req.public_key.map(|b| b.to_vec().into()),
        };
        let resp = nsm_process_request(fd, nsm_req);
        nsm_exit(fd);
        match resp {
            Response::Attestation { document } => Ok(document),
            Response::Error(err) => Err(NsmError::AttestationRejected(format!("{err:?}"))),
            other => Err(NsmError::AttestationRejected(format!("unexpected: {other:?}"))),
        }
    }

    pub fn get_random_bytes(out: &mut [u8]) -> Result<(), NsmError> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(NsmError::Unavailable(format!("nsm_init returned {fd}")));
        }
        let resp = nsm_process_request(fd, Request::GetRandom);
        nsm_exit(fd);
        match resp {
            Response::GetRandom { random } => {
                if random.len() < out.len() {
                    return Err(NsmError::AttestationRejected(format!(
                        "nsm returned {} random bytes, need {}",
                        random.len(),
                        out.len()
                    )));
                }
                out.copy_from_slice(&random[..out.len()]);
                Ok(())
            }
            Response::Error(err) => Err(NsmError::AttestationRejected(format!("{err:?}"))),
            other => Err(NsmError::AttestationRejected(format!("unexpected: {other:?}"))),
        }
    }
}

#[cfg(any(not(target_os = "linux"), feature = "mock"))]
mod mock {
    use super::{AttestationRequest, NsmError};
    use tracing::warn;

    pub fn get_attestation_document(req: AttestationRequest<'_>) -> Result<Vec<u8>, NsmError> {
        warn!(
            "[nsm-mock] returning canned attestation document — DO NOT USE IN PRODUCTION. \
             Inputs: user_data={} bytes, nonce={} bytes, public_key={} bytes",
            req.user_data.map(|b| b.len()).unwrap_or(0),
            req.nonce.map(|b| b.len()).unwrap_or(0),
            req.public_key.map(|b| b.len()).unwrap_or(0),
        );
        // Structurally-shaped placeholder. NOT verifiable against any
        // Nitro root CA. KMS will reject this in real usage; this is
        // only for exercising the storage layer end-to-end in tests.
        let mut doc = Vec::with_capacity(64);
        doc.extend_from_slice(b"MOCK_NITRO_ATTESTATION_v1:");
        if let Some(b) = req.user_data {
            doc.extend_from_slice(b);
        }
        Ok(doc)
    }

    pub fn get_random_bytes(out: &mut [u8]) -> Result<(), NsmError> {
        warn!("[nsm-mock] returning OS-rng bytes instead of NSM entropy");
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(out);
        Ok(())
    }
}
