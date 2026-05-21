//! Polymarket V2 deposit-wallet signing.
//!
//! Mirrors the subset of `eigen-tee/src/lib/` that handles Polymarket
//! order construction + signing. The full DepositWallet batch helpers
//! (split/merge/redeem/etc.) live in `core::polymarket::deposit_wallet`
//! and ship in task #162 — this module already includes
//! `derive_deposit_wallet_address` (the helper that signing needs).

pub mod batch;
pub mod constants;
pub mod deposit_wallet;
pub mod sign;

pub use batch::{
    bootstrap_approval_calls, sign_deposit_wallet_batch, BatchError, DepositWalletBatchSignature,
    DepositWalletCall, SignBatchArgs,
};
pub use deposit_wallet::derive_deposit_wallet_address;
pub use sign::{sign_v2_order, PolymarketError, SignV2OrderArgs, V2Order, V2OrderSignature};
