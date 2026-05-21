//! Per-user Solana delegate keypair derivation.
//!
//! Mirrors `eigen-tee/src/lib/solana-attestor/jupiter-delegate-derive.ts`
//! and `delegate-derive.ts`. The attestor identity (`signer::Master ->
//! attestor_keypair`) is the SHARED master ed25519 key — used for
//! polyleverage attestations + protocol-level signing. Trade authority
//! must be PER-USER so that compromising one user's session can't
//! impersonate another. We derive that via HKDF over the master seed +
//! a domain-separated salt + the solana_pubkey.
//!
//! Domain salts:
//!   - "polylayer-jupiter-delegate-v1"   — Jupiter perps trading
//!   - "polylayer-session-delegate-v1"   — Polyleverage zero-click sessions
//!
//! Why HKDF on a 32-byte seed → ed25519 scalar instead of SLIP-0010
//! deeper paths? Because solana_pubkey is the unique input and HKDF
//! is collision-free over its full 256 bits, vs SLIP-0010's hardened
//! indices being 31-bit.

use ed25519_dalek::{Signature, Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::derive::Master;

/// Salt for Jupiter perps delegate derivation. Never mutate.
pub const JUPITER_DELEGATE_SALT: &[u8] = b"polylayer-jupiter-delegate-v1";

/// Salt for polyleverage zero-click session delegate derivation. Never mutate.
pub const SESSION_DELEGATE_SALT: &[u8] = b"polylayer-session-delegate-v1";

#[derive(Debug, Error)]
pub enum DelegateError {
    #[error("hkdf expand failed: {0}")]
    Hkdf(String),
}

/// A per-user Solana delegate keypair. Private key zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct SolanaDelegate {
    /// 32-byte ed25519 private scalar.
    private_key: [u8; 32],
    /// 32-byte ed25519 public key.
    #[zeroize(skip)]
    public_key: [u8; 32],
}

impl SolanaDelegate {
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn public_key_bs58(&self) -> String {
        bs58::encode(self.public_key).into_string()
    }

    pub fn private_key_bytes(&self) -> &[u8; 32] {
        &self.private_key
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sk = SigningKey::from_bytes(&self.private_key);
        let sig: Signature = sk.sign(message);
        sig.to_bytes()
    }
}

/// Derive the per-user Jupiter perps delegate keypair.
pub fn derive_jupiter_delegate(
    master: &Master,
    solana_pubkey: &[u8; 32],
) -> Result<SolanaDelegate, DelegateError> {
    derive_delegate_with_salt(master, solana_pubkey, JUPITER_DELEGATE_SALT)
}

/// Derive the per-user polyleverage session delegate keypair.
pub fn derive_session_delegate(
    master: &Master,
    solana_pubkey: &[u8; 32],
) -> Result<SolanaDelegate, DelegateError> {
    derive_delegate_with_salt(master, solana_pubkey, SESSION_DELEGATE_SALT)
}

fn derive_delegate_with_salt(
    master: &Master,
    solana_pubkey: &[u8; 32],
    salt: &[u8],
) -> Result<SolanaDelegate, DelegateError> {
    let seed = master.seed_bytes();
    let hk = Hkdf::<Sha256>::new(Some(salt), &seed);

    // ed25519 accepts any 32 bytes as a seed (the scalar is clamped on
    // use), so we don't need the retry loop the secp256k1 path has.
    let mut private_key = [0u8; 32];
    hk.expand(solana_pubkey, &mut private_key)
        .map_err(|e| DelegateError::Hkdf(e.to_string()))?;

    let signing_key = SigningKey::from_bytes(&private_key);
    let public_key = signing_key.verifying_key().to_bytes();

    let kp = SolanaDelegate {
        private_key,
        public_key,
    };
    // Defensive: clear the local copy. The struct owns its own copy now.
    private_key.zeroize();
    Ok(kp)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HARDHAT: &str = "test test test test test test test test test test test junk";

    #[test]
    fn jupiter_delegate_is_deterministic() {
        let m1 = Master::from_mnemonic(HARDHAT).unwrap();
        let m2 = Master::from_mnemonic(HARDHAT).unwrap();
        let pk = [0xab; 32];
        let a = derive_jupiter_delegate(&m1, &pk).unwrap();
        let b = derive_jupiter_delegate(&m2, &pk).unwrap();
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn jupiter_delegate_differs_per_user() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let a = derive_jupiter_delegate(&m, &[0x01; 32]).unwrap();
        let b = derive_jupiter_delegate(&m, &[0x02; 32]).unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn delegate_salt_domain_separation() {
        // Same master + solana_pubkey, different salt → different keys.
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let pk = [0x42; 32];
        let jup = derive_jupiter_delegate(&m, &pk).unwrap();
        let sess = derive_session_delegate(&m, &pk).unwrap();
        assert_ne!(jup.public_key(), sess.public_key());
    }

    #[test]
    fn delegate_signs_and_verifies() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let kp = derive_jupiter_delegate(&m, &[0x99; 32]).unwrap();
        let msg = b"trade intent";
        let sig = kp.sign(msg);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(kp.public_key()).unwrap();
        let sig_obj = ed25519_dalek::Signature::from_bytes(&sig);
        ed25519_dalek::Verifier::verify(&vk, msg, &sig_obj).unwrap();
    }
}
