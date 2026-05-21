//! Solana Ed25519 attestor signer + attestation payload builders.
//!
//! Mirrors `eigen-tee/src/lib/solana-attestor/`. The attestor identity
//! is an Ed25519 key derived via SLIP-0010 from the same master
//! mnemonic used for the EVM master + per-user HKDF — but at a
//! different SLIP-0044 coin type (501 = SOL) so the curves never
//! cross-derive.
//!
//! On-chain `ProgramConfig.attestation_signer` pins the pubkey derived
//! here. Rotation requires re-deploying the image AND running the 24h
//! `ProposeSetAttestationSigner` → `ExecuteSetAttestationSigner`
//! timelock on the polyleverage program.

pub mod attestation;
pub mod delegate;
pub mod signer;

pub use delegate::{
    derive_jupiter_delegate, derive_session_delegate, DelegateError, SolanaDelegate,
    JUPITER_DELEGATE_SALT, SESSION_DELEGATE_SALT,
};

pub use attestation::{
    build_historical_liquidation, build_price_twap, build_resolution, AttestationCommon,
    AttestationError, HistoricalLiquidationPayload, PriceTwapPayload, ResolutionPayload,
    ATTESTATION_LEN, ATT_TYPE_HISTORICAL_LIQUIDATION, ATT_TYPE_PRICE_TWAP, ATT_TYPE_RESOLUTION,
};
pub use signer::{
    derive_solana_attestor_keypair, SolanaAttestorError, SolanaAttestorKeypair,
    SOLANA_ATTESTOR_BIP44_PATH,
};
