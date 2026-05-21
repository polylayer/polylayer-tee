//! Solana Ed25519 attestor key derivation via SLIP-0010.
//!
//! Mirrors `eigen-tee/src/lib/solana-attestor/ed25519-signer.ts`.
//! Derivation path: `m/44'/501'/0'/0'` (SLIP-0044 coin 501 = SOL, all
//! hardened indices per the ed25519 derivation rule).
//!
//! The same master mnemonic that drives the EVM HKDF tree is used here
//! at a different curve + path, so the EVM and Solana keys cannot
//! cross-derive — BIP-32 hardened subtrees are independent.

use ed25519_dalek::{Signature, Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::derive::Master;

pub const SOLANA_ATTESTOR_BIP44_PATH: &str = "m/44'/501'/0'/0'";

/// All path components for `m/44'/501'/0'/0'` (the BIP-44 SOL path),
/// each marked hardened by OR-ing 0x80000000.
const SOLANA_ATTESTOR_PATH: &[u32] = &[44, 501, 0, 0];

#[derive(Debug, Error)]
pub enum SolanaAttestorError {
    #[error("slip-0010 hmac key size error: {0}")]
    Hmac(String),
}

/// A Solana ed25519 attestor keypair. Private key is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct SolanaAttestorKeypair {
    /// 32-byte ed25519 private scalar.
    private_key: [u8; 32],
    /// 32-byte ed25519 public key.
    #[zeroize(skip)]
    public_key: [u8; 32],
}

impl SolanaAttestorKeypair {
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns base58 encoding of the public key — the user-facing
    /// Solana address form.
    pub fn public_key_bs58(&self) -> String {
        bs58::encode(self.public_key).into_string()
    }

    /// Sign arbitrary bytes with the attestor key. Output is a 64-byte
    /// ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sk = SigningKey::from_bytes(&self.private_key);
        let sig: Signature = sk.sign(message);
        sig.to_bytes()
    }
}

/// Derive the Solana attestor keypair from the master mnemonic's BIP-39
/// seed (already cached on `Master`). Implements SLIP-0010 for ed25519
/// derivation along path `m/44'/501'/0'/0'`.
pub fn derive_solana_attestor_keypair(
    master: &Master,
) -> Result<SolanaAttestorKeypair, SolanaAttestorError> {
    let seed = master_seed_bytes(master);
    let (mut priv_key, _chain_code) = slip10_derive(&seed)?;
    let signing_key = SigningKey::from_bytes(&priv_key);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes();

    // Construct the keypair before zeroizing locals.
    let kp = SolanaAttestorKeypair {
        private_key: priv_key,
        public_key,
    };
    // Defensive: the loop output is now owned by the struct's
    // ZeroizeOnDrop — but clear the local stack copies anyway.
    priv_key.zeroize();
    Ok(kp)
}

/// Reach into `Master`'s private seed without exposing it on the public
/// API. We add a crate-internal getter on `Master` for this.
fn master_seed_bytes(master: &Master) -> [u8; 64] {
    master.seed_bytes()
}

/// SLIP-0010 derivation for ed25519 along the hard-coded
/// `m/44'/501'/0'/0'` path. Returns (private_key, chain_code).
///
/// Spec: <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>
fn slip10_derive(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), SolanaAttestorError> {
    // Master: I = HMAC-SHA512(key="ed25519 seed", data=seed).
    //   IL → master priv key, IR → master chain code.
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(b"ed25519 seed")
        .map_err(|e| SolanaAttestorError::Hmac(e.to_string()))?;
    mac.update(seed);
    let i = mac.finalize().into_bytes();
    let mut priv_key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    priv_key.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);

    // Each hardened child step:
    //   data = 0x00 || k_par || ser32(i_hardened)
    //   I = HMAC-SHA512(key=c_par, data=data)
    //   k_child = IL, c_child = IR
    for &index in SOLANA_ATTESTOR_PATH {
        let hardened = index | 0x8000_0000;
        let mut data = [0u8; 1 + 32 + 4];
        data[0] = 0x00;
        data[1..33].copy_from_slice(&priv_key);
        data[33..37].copy_from_slice(&hardened.to_be_bytes());

        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&chain_code)
            .map_err(|e| SolanaAttestorError::Hmac(e.to_string()))?;
        mac.update(&data);
        let i = mac.finalize().into_bytes();
        priv_key.copy_from_slice(&i[..32]);
        chain_code.copy_from_slice(&i[32..]);
    }

    Ok((priv_key, chain_code))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HARDHAT: &str = "test test test test test test test test test test test junk";

    #[test]
    fn attestor_keypair_is_deterministic() {
        let m1 = Master::from_mnemonic(HARDHAT).unwrap();
        let m2 = Master::from_mnemonic(HARDHAT).unwrap();
        let a = derive_solana_attestor_keypair(&m1).unwrap();
        let b = derive_solana_attestor_keypair(&m2).unwrap();
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn attestor_signs_and_verifies() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let kp = derive_solana_attestor_keypair(&m).unwrap();
        let msg = b"hello attestor";
        let sig = kp.sign(msg);
        assert_eq!(sig.len(), 64);

        // Verify with the public key via ed25519_dalek.
        let vk = ed25519_dalek::VerifyingKey::from_bytes(kp.public_key()).unwrap();
        let sig_obj = ed25519_dalek::Signature::from_bytes(&sig);
        ed25519_dalek::Verifier::verify(&vk, msg, &sig_obj).expect("self-verify must pass");
    }

    #[test]
    fn attestor_bs58_pubkey_decodes_to_32_bytes() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let kp = derive_solana_attestor_keypair(&m).unwrap();
        let s = kp.public_key_bs58();
        let decoded = bs58::decode(&s).into_vec().unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded.as_slice(), kp.public_key());
    }
}
