//! Sign a Solana `VersionedTransaction` with the per-user delegate ed25519 key.
//!
//! Mirrors the signing portion of `eigen-tee/src/routes/sign-jupiter-tx.ts`.
//! The caller (server route) has already:
//!
//! 1. Verified the intent signature
//! 2. Derived the per-user delegate keypair via `solana_attestor::*`
//! 3. Decoded the unsigned tx's Jupiter perps ix via `jupiter::decode_*`
//! 4. Cross-checked decoded args (size, asset, owner) against the intent
//! 5. Run session-bounds + emergency-mode + on-chain delegation checks
//!
//! At that point this function takes the unsigned tx bytes + the
//! delegate's signing key and produces a signed tx ready to broadcast.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JupiterSignError {
    #[error("base64 decode failed: {0}")]
    Base64(String),

    #[error("bincode deserialize failed: {0}")]
    Deserialize(String),

    #[error("bincode serialize failed: {0}")]
    Serialize(String),

    #[error("delegate pubkey {delegate} is not in the message's static account keys")]
    DelegateNotSigner { delegate: Pubkey },

    #[error("signature slot {idx} out of range (signatures.len()={len})")]
    SignatureSlotOutOfRange { idx: usize, len: usize },
}

#[derive(Debug, Clone)]
pub struct SignedJupiterTx {
    /// Base64-encoded signed VersionedTransaction. Re-broadcastable as-is.
    pub signed_tx_b64: String,
    /// The signature bytes that were slotted into the tx.
    pub signature: [u8; 64],
    /// Where in the tx's signatures vector the delegate sig was placed.
    pub signature_index: usize,
}

/// Sign an unsigned (or partially-signed) base64-encoded
/// `VersionedTransaction` with the delegate ed25519 key. The delegate
/// MUST appear in the message's static account keys; otherwise the tx
/// has no slot for our signature and we reject.
///
/// Returns the re-encoded signed tx ready for the lambda to broadcast.
pub fn sign_versioned_transaction(
    unsigned_tx_b64: &str,
    delegate_priv_key: &[u8; 32],
) -> Result<SignedJupiterTx, JupiterSignError> {
    let raw = B64
        .decode(unsigned_tx_b64.as_bytes())
        .map_err(|e| JupiterSignError::Base64(e.to_string()))?;
    let mut tx: VersionedTransaction = bincode::deserialize(&raw)
        .map_err(|e| JupiterSignError::Deserialize(e.to_string()))?;

    let signing_key = SigningKey::from_bytes(delegate_priv_key);
    let delegate_pubkey = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());

    // Find the delegate's index in the static account keys. The
    // signatures vector parallels the first `header.num_required_signatures`
    // entries of static_account_keys.
    let static_keys = tx.message.static_account_keys();
    let idx = static_keys
        .iter()
        .position(|k| k == &delegate_pubkey)
        .ok_or(JupiterSignError::DelegateNotSigner { delegate: delegate_pubkey })?;

    if idx >= tx.signatures.len() {
        return Err(JupiterSignError::SignatureSlotOutOfRange {
            idx,
            len: tx.signatures.len(),
        });
    }

    // Sign the serialized message body (Solana convention).
    let message_bytes = serialize_message(&tx.message)?;
    let sig: ed25519_dalek::Signature = signing_key.sign(&message_bytes);
    let sig_bytes: [u8; 64] = sig.to_bytes();

    tx.signatures[idx] = Signature::from(sig_bytes);

    let signed_bytes = bincode::serialize(&tx)
        .map_err(|e| JupiterSignError::Serialize(e.to_string()))?;
    let signed_tx_b64 = B64.encode(signed_bytes);

    Ok(SignedJupiterTx {
        signed_tx_b64,
        signature: sig_bytes,
        signature_index: idx,
    })
}

fn serialize_message(msg: &VersionedMessage) -> Result<Vec<u8>, JupiterSignError> {
    bincode::serialize(msg).map_err(|e| JupiterSignError::Serialize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::{v0, Message, VersionedMessage};
    use solana_transaction::versioned::VersionedTransaction;

    fn make_unsigned_tx(delegate_pubkey: Pubkey) -> (String, Pubkey) {
        // Construct a legacy `Message` with the delegate as the sole
        // signer. This is the simplest shape that exercises our signer.
        let dummy_program = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let ix = Instruction {
            program_id: dummy_program,
            accounts: vec![
                AccountMeta::new(delegate_pubkey, true),
                AccountMeta::new(recipient, false),
            ],
            data: vec![0xab, 0xcd, 0xef],
        };
        let mut msg = Message::new(&[ix], Some(&delegate_pubkey));
        // Set a non-default blockhash so the bytes are non-trivial.
        msg.recent_blockhash = Hash::new_unique();
        let versioned = VersionedMessage::Legacy(msg);
        let signatures_len = versioned.header().num_required_signatures as usize;
        let tx = VersionedTransaction {
            signatures: vec![Signature::default(); signatures_len],
            message: versioned,
        };
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = B64.encode(bytes);
        (b64, recipient)
    }

    #[test]
    fn sign_round_trip_legacy_message() {
        let sk = SigningKey::generate(&mut OsRng);
        let priv_bytes: [u8; 32] = sk.to_bytes();
        let delegate_pubkey = Pubkey::new_from_array(sk.verifying_key().to_bytes());

        let (unsigned_b64, _) = make_unsigned_tx(delegate_pubkey);
        let signed = sign_versioned_transaction(&unsigned_b64, &priv_bytes).unwrap();
        assert_eq!(signed.signature_index, 0); // delegate is the sole + first signer

        // Decode the signed tx and verify the signature slots in.
        let raw = B64.decode(signed.signed_tx_b64.as_bytes()).unwrap();
        let tx: VersionedTransaction = bincode::deserialize(&raw).unwrap();
        assert_eq!(tx.signatures.len(), 1);
        assert_ne!(tx.signatures[0], Signature::default());

        // The signature must verify against the message bytes.
        let msg_bytes = bincode::serialize(&tx.message).unwrap();
        let vk = sk.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&signed.signature);
        ed25519_dalek::Verifier::verify(&vk, &msg_bytes, &sig).unwrap();
    }

    #[test]
    fn sign_rejects_when_delegate_not_in_account_keys() {
        // Delegate A constructs the tx, delegate B tries to sign — must reject.
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let pubkey_a = Pubkey::new_from_array(sk_a.verifying_key().to_bytes());

        let (unsigned_b64, _) = make_unsigned_tx(pubkey_a);
        let priv_b: [u8; 32] = sk_b.to_bytes();
        let err = sign_versioned_transaction(&unsigned_b64, &priv_b).unwrap_err();
        assert!(matches!(err, JupiterSignError::DelegateNotSigner { .. }));
    }
}
