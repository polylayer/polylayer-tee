//! Jupiter Perpetuals signing.
//!
//! Mirrors `eigen-tee/src/lib/jupiter-perps-decode.ts` + the signing
//! portion of `routes/sign-jupiter-tx.ts`. Split into two layers:
//!
//! - `decode`: Anchor-style instruction discriminator + borsh arg
//!   decoder for `create_increase_position_market_request` and
//!   `create_decrease_position_market_request`. Pure logic.
//! - `sign`:  VersionedTransaction parsing + ed25519 signing with the
//!   per-user delegate key.
//!
//! Route-layer concerns (intent verification, session bounds check,
//! on-chain delegation lookup, emergency-mode gate) live in the server
//! crate — this module is just the cryptographic primitives.

pub mod decode;
pub mod sign;

pub use decode::{
    custody_to_asset, decode_jupiter_perps_ix, DecodedJupiterIx, DecreaseArgs, IncreaseArgs,
    JupiterAsset, DECREASE_ACCOUNT_INDEX, DECREASE_DISCRIMINATOR, INCREASE_ACCOUNT_INDEX,
    INCREASE_DISCRIMINATOR, JUPITER_CUSTODY_BTC, JUPITER_CUSTODY_ETH, JUPITER_CUSTODY_SOL,
    JUPITER_PERPS_PROGRAM_ID,
};
pub use sign::{sign_versioned_transaction, JupiterSignError, SignedJupiterTx};
