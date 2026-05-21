//! Per-user EVM key derivation from the TEE master mnemonic.
//!
//! Mirrors `eigen-tee/src/lib/derive.ts` byte-for-byte. The TS impl's
//! cache-the-master-seed-globally pattern is replaced with a `Master`
//! struct held by the server — same semantics, no global mutable state.
//!
//! ## HKDF-v1
//!
//! For each Solana pubkey, derive a per-user secp256k1 private key via
//! HKDF-SHA256:
//!
//! ```text
//!   IKM   = BIP-39 seed (64 bytes from mnemonic, empty passphrase)
//!   salt  = "polylayer-user-evm-hkdf-v1"  (UTF-8 bytes; NEVER mutate)
//!   info  = solana_pubkey               (32 raw bytes)
//!   L     = 32 bytes
//! ```
//!
//! If the HKDF output is ≥ secp256k1 group order (probability ~2^-128),
//! retry with `info || counter_byte`. The retry loop is defensive; we'll
//! never see it fire in production.
//!
//! ## Master EVM (BIP-44)
//!
//! Separate from per-user. Stays on `m/44'/60'/0'/0/0` — used for the
//! protocol-level address (registry link receipts + heartbeat events).
//!
//! ## Link message
//!
//! `sign_link_message` produces the raw secp256k1 sig consumed by the
//! Solana `polylayer-registry` program's Secp256k1Program-introspection
//! check. Self-checks the sig before returning — refuses to emit a sig
//! the Solana program would reject.

use alloy_primitives::Address;
use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use hkdf::Hkdf;
use k256::ecdsa::{
    signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey, VerifyingKey,
};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Derivation function version. Embedded in the HKDF salt so we can
/// keep multiple versions conceptually distinct. NEVER mutate the v1
/// bytes — addresses depend on them.
pub const DERIVATION_VERSION: &str = "hkdf-v1";

/// UTF-8 bytes of `polylayer-user-evm-hkdf-v1`. The Solana program is
/// agnostic to this constant; the bytes only matter for deterministic
/// per-user address derivation. NEVER mutate.
pub const DERIVATION_SALT: &[u8] = b"polylayer-user-evm-hkdf-v1";

/// UTF-8 bytes of `polylayer-link-v1`. The Solana registry program
/// reconstructs and verifies this exact prefix; bytes must match.
pub const LINK_MESSAGE_PREFIX: &[u8] = b"polylayer-link-v1";

/// Path used by `Master::derive_master_evm_account`. The platform-issued
/// mnemonic at `m/44'/60'/0'/0/0`. Used to sign address-binding receipts
/// and heartbeat events. Not affected by the HKDF migration.
pub const MASTER_EVM_PATH: &str = "m/44'/60'/0'/0/0";

/// HKDF salt for the session data-encryption key. Per-user session
/// blobs in DynamoDB are AES-256-GCM sealed under a DEK derived from
/// the master seed with this salt. NEVER mutate — existing sealed
/// blobs become unreadable.
pub const SESSION_DEK_SALT: &[u8] = b"polylayer-sessions-dek-v1";

const PRIVKEY_LEN: usize = 32;
const SOLANA_PUBKEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum DeriveError {
    #[error("invalid bip39 mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("bip32 derivation failed: {0}")]
    Bip32(String),

    #[error("invalid secp256k1 scalar (HKDF retry budget exhausted)")]
    HkdfRetryExhausted,

    #[error("signing failed: {0}")]
    Sign(String),

    #[error("self-check failed: recovered address does not match derived address")]
    SelfCheckFailed,

    #[error("unexpected recovery id {0}")]
    BadRecoveryId(u8),
}

/// Holds the pre-computed master state. One per process lifetime;
/// instantiated once at boot after the mnemonic is decrypted from KMS.
#[derive(ZeroizeOnDrop)]
pub struct Master {
    seed: [u8; 64],
    // Note: `XPrv` is not Zeroize, but it derives from `seed` which is.
    // Cleared via Drop of `seed`; the XPrv copy isn't a meaningful leak
    // because the same data is recomputable from any caller with `seed`.
    #[zeroize(skip)]
    master_hd: XPrv,
}

impl Master {
    /// Construct from a BIP-39 mnemonic phrase (24 or 12 words).
    pub fn from_mnemonic(phrase: &str) -> Result<Self, DeriveError> {
        let m = Mnemonic::parse(phrase)
            .map_err(|e| DeriveError::InvalidMnemonic(e.to_string()))?;
        // BIP-39 → 64-byte seed; empty passphrase to match the TS impl
        // (`mnemonicToSeedSync(mnemonic)` with no passphrase arg).
        let seed = m.to_seed("");
        Self::from_seed_bytes(seed)
    }

    /// Construct from a raw 64-byte BIP-39 seed. Test entry point.
    pub fn from_seed_bytes(seed: [u8; 64]) -> Result<Self, DeriveError> {
        let master_hd = XPrv::new(&seed).map_err(|e| DeriveError::Bip32(e.to_string()))?;
        Ok(Self { seed, master_hd })
    }

    /// Crate-internal: expose the BIP-39 seed bytes so the
    /// `solana_attestor` module can run SLIP-0010 (ed25519) derivation
    /// from the same master without re-decoding the mnemonic. The seed
    /// stays inside the enclave — never exposed on the public API.
    pub(crate) fn seed_bytes(&self) -> [u8; 64] {
        self.seed
    }

    /// Derive the per-user EVM private key for a given Solana pubkey.
    ///
    /// HKDF-SHA256 over (seed, salt, solana_pubkey). Pure function over
    /// inputs; safe to call concurrently.
    pub fn derive_user_private_key(
        &self,
        solana_pubkey: &[u8; SOLANA_PUBKEY_LEN],
    ) -> Result<DerivedSecret, DeriveError> {
        // 256-attempt retry on (vanishingly rare) HKDF output ≥ curve
        // order. attempt=0 uses pubkey as-is; attempt=N appends a single
        // counter byte. Bytewise-identical to the TS retry construction.
        for attempt in 0u8..=255 {
            let mut output = [0u8; PRIVKEY_LEN];
            let hk = Hkdf::<Sha256>::new(Some(DERIVATION_SALT), &self.seed);
            if attempt == 0 {
                hk.expand(solana_pubkey, &mut output)
                    .expect("hkdf expand never fails for L=32");
            } else {
                let mut info = [0u8; SOLANA_PUBKEY_LEN + 1];
                info[..SOLANA_PUBKEY_LEN].copy_from_slice(solana_pubkey);
                info[SOLANA_PUBKEY_LEN] = attempt;
                hk.expand(&info, &mut output)
                    .expect("hkdf expand never fails for L=32");
            }
            // k256::SecretKey::from_bytes rejects scalars ≥ n, matching
            // noble/curves' `secp256k1.utils.isValidPrivateKey`.
            if let Ok(_) = k256::SecretKey::from_bytes((&output).into()) {
                return Ok(DerivedSecret(output));
            }
            // Otherwise the candidate is invalid — zeroize before next attempt.
            output.zeroize();
        }
        Err(DeriveError::HkdfRetryExhausted)
    }

    /// Derive the per-user EVM account (private key + 0x-address) for a
    /// Solana pubkey.
    pub fn derive_user_evm_account(
        &self,
        solana_pubkey: &[u8; SOLANA_PUBKEY_LEN],
    ) -> Result<DerivedAccount, DeriveError> {
        let secret = self.derive_user_private_key(solana_pubkey)?;
        let signing_key = SigningKey::from_bytes((&secret.0).into())
            .map_err(|e| DeriveError::Sign(e.to_string()))?;
        let address = evm_address_from_verifying_key(signing_key.verifying_key());
        Ok(DerivedAccount {
            private_key: secret,
            address,
            solana_pubkey: *solana_pubkey,
            derivation_version: DERIVATION_VERSION,
        })
    }

    /// Derive the 32-byte data-encryption key used to seal per-user
    /// session blobs in DynamoDB. HKDF-SHA256 over the BIP-39 seed
    /// with a domain-separated salt. Deterministic, so the same DEK
    /// is recovered across enclave restarts and the existing sealed
    /// blobs stay readable.
    pub fn session_dek(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(SESSION_DEK_SALT), &self.seed);
        let mut dek = [0u8; 32];
        hk.expand(b"session-dek", &mut dek)
            .expect("hkdf expand never fails for L=32");
        dek
    }

    /// Master EVM account at `m/44'/60'/0'/0/0`. Used for protocol-level
    /// signing (registry link receipts, heartbeat).
    pub fn derive_master_evm_account(&self) -> Result<DerivedAccount, DeriveError> {
        let path: DerivationPath = MASTER_EVM_PATH
            .parse()
            .map_err(|e: bip32::Error| DeriveError::Bip32(e.to_string()))?;
        let xprv = XPrv::derive_from_path(&self.seed, &path)
            .map_err(|e| DeriveError::Bip32(e.to_string()))?;
        let priv_bytes = xprv.to_bytes();
        let mut secret = [0u8; PRIVKEY_LEN];
        secret.copy_from_slice(priv_bytes.as_slice());
        let signing_key = SigningKey::from_bytes((&secret).into())
            .map_err(|e| DeriveError::Sign(e.to_string()))?;
        let address = evm_address_from_verifying_key(signing_key.verifying_key());
        Ok(DerivedAccount {
            private_key: DerivedSecret(secret),
            address,
            solana_pubkey: [0u8; SOLANA_PUBKEY_LEN], // not applicable for master
            derivation_version: "bip44-m/44'/60'/0'/0/0",
        })
    }

    /// Sign the `polylayer-link-v1 || solana_pubkey` message with the
    /// user's derived EVM key. Self-checks the recovered address before
    /// returning — refuses to emit a sig the Solana registry program
    /// would reject.
    pub fn sign_link_message(
        &self,
        solana_pubkey: &[u8; SOLANA_PUBKEY_LEN],
    ) -> Result<LinkMessageSignature, DeriveError> {
        let secret = self.derive_user_private_key(solana_pubkey)?;
        let signing_key = SigningKey::from_bytes((&secret.0).into())
            .map_err(|e| DeriveError::Sign(e.to_string()))?;
        let address = evm_address_from_verifying_key(signing_key.verifying_key());

        // 17-byte prefix + 32-byte pubkey = 49 bytes. Identical layout
        // to what the Solana program reconstructs.
        let mut message = Vec::with_capacity(LINK_MESSAGE_PREFIX.len() + SOLANA_PUBKEY_LEN);
        message.extend_from_slice(LINK_MESSAGE_PREFIX);
        message.extend_from_slice(solana_pubkey);

        let hash: [u8; 32] = Keccak256::digest(&message).into();

        // k256 returns canonical (low-S) signatures with a recovery_id.
        let (sig, recovery_id): (Signature, RecoveryId) = signing_key
            .sign_prehash(&hash)
            .map_err(|e| DeriveError::Sign(e.to_string()))
            .and_then(|s: Signature| {
                // sign_prehash via PrehashSigner returns just the sig;
                // recovery has to be computed separately. Use the
                // recoverable signer trait.
                let _ = s;
                signing_key
                    .sign_prehash_recoverable(&hash)
                    .map_err(|e| DeriveError::Sign(e.to_string()))
            })?;

        let rec_byte = recovery_id.to_byte();
        if rec_byte != 0 && rec_byte != 1 {
            return Err(DeriveError::BadRecoveryId(rec_byte));
        }

        // Self-check: recover from the sig and compare addresses.
        let recovered_vk = VerifyingKey::recover_from_prehash(&hash, &sig, recovery_id)
            .map_err(|e| DeriveError::Sign(e.to_string()))?;
        let recovered_addr = evm_address_from_verifying_key(&recovered_vk);
        if recovered_addr != address {
            return Err(DeriveError::SelfCheckFailed);
        }

        let r_s: [u8; 64] = sig.to_bytes().into();
        Ok(LinkMessageSignature {
            evm_address: address,
            message,
            message_hash: hash,
            signature: r_s,
            recovery_id: rec_byte,
        })
    }
}

/// EVM address = last 20 bytes of keccak256(uncompressed_pubkey[1..65]).
pub(crate) fn evm_address_from_verifying_key(vk: &VerifyingKey) -> Address {
    let encoded = vk.to_encoded_point(false); // uncompressed: 0x04 || X(32) || Y(32) = 65 bytes
    let bytes = encoded.as_bytes();
    debug_assert_eq!(bytes.len(), 65);
    let hash: [u8; 32] = Keccak256::digest(&bytes[1..]).into();
    Address::from_slice(&hash[12..])
}

/// A derived 32-byte secp256k1 private key. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedSecret(pub [u8; PRIVKEY_LEN]);

impl DerivedSecret {
    /// Hex-encode with `0x` prefix. Caller is responsible for handling
    /// the returned String safely (it's a copy of the secret material).
    pub fn to_hex_0x(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

/// Per-user derivation result.
pub struct DerivedAccount {
    pub private_key: DerivedSecret,
    pub address: Address,
    pub solana_pubkey: [u8; SOLANA_PUBKEY_LEN],
    pub derivation_version: &'static str,
}

/// Output of `Master::sign_link_message`. Everything the lambda needs
/// to construct the Solana tx where instruction[0] is
/// `Secp256k1Program.verify` and instruction[1] is `polylayer_registry.link`.
pub struct LinkMessageSignature {
    /// 20-byte derived EVM address.
    pub evm_address: Address,
    /// Raw bytes: `polylayer-link-v1` || solana_pubkey (49 bytes total).
    pub message: Vec<u8>,
    /// keccak256(message) — the hash the secp256k1 sig is over.
    pub message_hash: [u8; 32],
    /// 64 raw bytes: r (32) || s (32). Low-S canonical.
    pub signature: [u8; 64],
    /// 0 or 1. Solana's Secp256k1Program calls this `recovery_id`.
    pub recovery_id: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic 24-word test mnemonic — BIP-39 spec test vector
    /// for entropy = 32 zero bytes. Used internally by these tests for
    /// reproducible derivation.
    const ABANDON24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    /// Hardhat's default 12-word mnemonic. BIP-44 m/44'/60'/0'/0/0
    /// is the well-known address 0xf39F…2266 — exhaustively documented.
    /// Used here to ground-truth our BIP-32 derivation against an
    /// independent implementation.
    const HARDHAT: &str = "test test test test test test test test test test test junk";

    #[test]
    fn derive_master_evm_path_matches_hardhat_default() {
        let m = Master::from_mnemonic(HARDHAT).unwrap();
        let acct = m.derive_master_evm_account().unwrap();
        let expected = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse::<Address>()
            .unwrap();
        assert_eq!(
            acct.address, expected,
            "BIP-44 m/44'/60'/0'/0/0 from the Hardhat default mnemonic should match the canonical address"
        );
    }

    #[test]
    fn derive_master_evm_path_is_stable() {
        let m1 = Master::from_mnemonic(ABANDON24).unwrap();
        let m2 = Master::from_mnemonic(ABANDON24).unwrap();
        let a = m1.derive_master_evm_account().unwrap();
        let b = m2.derive_master_evm_account().unwrap();
        assert_eq!(a.address, b.address);
    }

    #[test]
    fn derive_user_pubkey_yields_valid_secp256k1_scalar() {
        let m = Master::from_mnemonic(ABANDON24).unwrap();
        // Use a pubkey of all-1s — arbitrary but reproducible.
        let pubkey = [1u8; 32];
        let secret = m.derive_user_private_key(&pubkey).unwrap();
        // Must be a valid scalar.
        assert!(k256::SecretKey::from_bytes((&secret.0).into()).is_ok());
    }

    #[test]
    fn derive_user_evm_account_is_deterministic() {
        let m1 = Master::from_mnemonic(ABANDON24).unwrap();
        let m2 = Master::from_mnemonic(ABANDON24).unwrap();
        let pubkey = [7u8; 32];
        let a = m1.derive_user_evm_account(&pubkey).unwrap();
        let b = m2.derive_user_evm_account(&pubkey).unwrap();
        assert_eq!(a.address, b.address);
        assert_eq!(a.private_key.0, b.private_key.0);
    }

    #[test]
    fn derive_user_evm_account_differs_per_pubkey() {
        let m = Master::from_mnemonic(ABANDON24).unwrap();
        let a = m.derive_user_evm_account(&[1u8; 32]).unwrap();
        let b = m.derive_user_evm_account(&[2u8; 32]).unwrap();
        assert_ne!(a.address, b.address);
    }

    #[test]
    fn sign_link_message_passes_self_check() {
        let m = Master::from_mnemonic(ABANDON24).unwrap();
        let pubkey = [42u8; 32];
        let sig = m.sign_link_message(&pubkey).unwrap();
        // Self-check happens inside sign_link_message; if we got here,
        // the recovered address matched the derived address.
        assert_eq!(sig.message.len(), LINK_MESSAGE_PREFIX.len() + 32);
        assert_eq!(&sig.message[..LINK_MESSAGE_PREFIX.len()], LINK_MESSAGE_PREFIX);
        assert_eq!(&sig.message[LINK_MESSAGE_PREFIX.len()..], &pubkey);
        assert!(sig.recovery_id == 0 || sig.recovery_id == 1);
    }

    #[test]
    fn sign_link_message_matches_derived_address() {
        let m = Master::from_mnemonic(ABANDON24).unwrap();
        let pubkey = [99u8; 32];
        let derived = m.derive_user_evm_account(&pubkey).unwrap();
        let sig = m.sign_link_message(&pubkey).unwrap();
        assert_eq!(sig.evm_address, derived.address);
    }
}
