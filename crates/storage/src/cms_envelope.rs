//! CMS PKCS#7 EnvelopedData decryption for KMS Decrypt-with-Recipient.
//!
//! When `KMS.Decrypt` is called with a `Recipient` (Nitro attestation
//! document), KMS does not return the plaintext directly. Instead it
//! returns a `CiphertextForRecipient` blob — a DER-encoded CMS
//! ContentInfo wrapping an `EnvelopedData` structure. The wire format
//! is the same one the AWS Nitro Enclaves C SDK (`source/cms.c`)
//! produces and consumes.
//!
//! Structure (RFC 5652 § 6):
//!
//! ```text
//! ContentInfo {
//!   contentType: id-envelopedData (1.2.840.113549.1.7.3),
//!   content: EnvelopedData {
//!     version: 0,
//!     recipientInfos: [ KeyTransRecipientInfo {
//!       version: 0,
//!       rid: <issuer-and-serial> or <subjectKeyIdentifier>,
//!       keyEncryptionAlgorithm: { id-RSAES-OAEP, params: SHA-256 },
//!       encryptedKey: RSA-OAEP-encrypted(CEK)
//!     } ],
//!     encryptedContentInfo: {
//!       contentType: id-data,
//!       contentEncryptionAlgorithm: { id-aes256-CBC, params: IV },
//!       encryptedContent: AES-256-CBC(plaintext, CEK, IV)
//!     }
//!   }
//! }
//! ```
//!
//! Decryption sequence:
//! 1. Parse `ContentInfo`, descend to `EnvelopedData`.
//! 2. Take the first `KeyTransRecipientInfo`. RSA-OAEP-SHA-256-decrypt
//!    its `encryptedKey` field with our private key → plaintext CEK.
//! 3. AES-256-CBC-decrypt `encryptedContent` with `CEK` and the IV from
//!    the content-encryption-algorithm parameters. Strip PKCS#7
//!    padding. That's the plaintext KMS produced.

use aes::Aes256;
use cbc::Decryptor as CbcDecryptor;
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, KeyIvInit};
use cms::content_info::ContentInfo;
use cms::enveloped_data::{EnvelopedData, RecipientInfo};
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Decode, Encode};
use rsa::{Oaep, RsaPrivateKey};
use sha2::Sha256;
use thiserror::Error;

mod ber_to_der;

/// OID 2.16.840.1.101.3.4.1.42 — `id-aes256-CBC`. The content
/// encryption algorithm KMS uses for the `EnvelopedData`'s content.
const ID_AES256_CBC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");

/// OID 1.2.840.113549.1.7.3 — `id-envelopedData`.
const ID_ENVELOPED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");

#[derive(Debug, Error)]
pub enum CmsError {
    #[error("DER parse: {0}")]
    Der(der::Error),

    #[error("unexpected outer ContentInfo type (got {got}, expected envelopedData)")]
    WrongContentType { got: String },

    #[error("no KeyTransRecipientInfo found in EnvelopedData")]
    NoKeyTransRecipient,

    #[error("unsupported content encryption algorithm OID: {oid}")]
    UnsupportedContentAlgorithm { oid: String },

    #[error("missing IV in content-encryption-algorithm parameters")]
    MissingIv,

    #[error("IV is not 16 bytes (got {got})")]
    BadIvLength { got: usize },

    #[error("missing encryptedContent in EnvelopedData")]
    MissingContent,

    #[error("RSA-OAEP decrypt of CEK failed: {0}")]
    RsaDecrypt(rsa::Error),

    #[error("AES-CBC content decrypt failed: {0}")]
    AesDecrypt(String),
}

impl From<der::Error> for CmsError {
    fn from(e: der::Error) -> Self {
        CmsError::Der(e)
    }
}

/// Decrypt a `CiphertextForRecipient` blob using the private key whose
/// matching public key was embedded in the attestation document.
pub fn decrypt_enveloped_data(
    envelope_der: &[u8],
    priv_key: &RsaPrivateKey,
) -> Result<Vec<u8>, CmsError> {
    // KMS returns the CiphertextForRecipient as BER with
    // indefinite-length encoding on the outer ContentInfo's content
    // (typical for PKCS#7 streaming producers). The `der` crate is
    // strict DER and refuses indefinite lengths. Normalize BER → DER
    // up front so the rest of the path works unmodified.
    let envelope_der_buf = ber_to_der::normalize(envelope_der)?;

    // ── 1. Outer ContentInfo ──────────────────────────────────────
    let ci = ContentInfo::from_der(&envelope_der_buf)?;
    if ci.content_type != ID_ENVELOPED_DATA {
        return Err(CmsError::WrongContentType {
            got: ci.content_type.to_string(),
        });
    }

    // ── 2. EnvelopedData ──────────────────────────────────────────
    // ContentInfo.content is `Any`; re-encode to DER and decode as
    // `EnvelopedData`. (cms 0.2's helper `decode_as` would also work;
    // going through `to_der` + `from_der` keeps the dependency
    // narrow.)
    let ed_der = ci.content.to_der()?;
    let env: EnvelopedData = EnvelopedData::from_der(&ed_der)?;

    // ── 3. KeyTrans recipient → RSA-OAEP-decrypt CEK ──────────────
    let mut cek: Option<Vec<u8>> = None;
    for ri in env.recip_infos.0.iter() {
        if let RecipientInfo::Ktri(ktri) = ri {
            // RSA-OAEP-SHA-256 is what KMS uses; we don't bother
            // inspecting the algorithm OID — RSAES-OAEP with anything
            // other than SHA-256 isn't a wire we'd ever see from KMS.
            let padding = Oaep::new::<Sha256>();
            let enc_key = ktri.enc_key.as_bytes();
            let key = priv_key
                .decrypt(padding, enc_key)
                .map_err(CmsError::RsaDecrypt)?;
            cek = Some(key);
            break;
        }
    }
    let cek = cek.ok_or(CmsError::NoKeyTransRecipient)?;

    // ── 4. AES-256-CBC decrypt the content ────────────────────────
    let eci = env.encrypted_content;
    let alg = eci.content_enc_alg;
    if alg.oid != ID_AES256_CBC {
        return Err(CmsError::UnsupportedContentAlgorithm {
            oid: alg.oid.to_string(),
        });
    }
    let iv_any = alg.parameters.ok_or(CmsError::MissingIv)?;
    let iv = OctetString::from_der(&iv_any.to_der()?)?
        .as_bytes()
        .to_vec();
    if iv.len() != 16 {
        return Err(CmsError::BadIvLength { got: iv.len() });
    }

    let ct_octet = eci.encrypted_content.ok_or(CmsError::MissingContent)?;
    let ct = ct_octet.as_bytes();

    let mut buf = ct.to_vec();
    let pt = CbcDecryptor::<Aes256>::new(cek.as_slice().into(), iv.as_slice().into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| CmsError::AesDecrypt(format!("{e:?}")))?
        .to_vec();
    Ok(pt)
}
