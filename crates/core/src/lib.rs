//! Polylayer TEE — core signing primitives.
//!
//! No I/O, no tokio, no AWS SDKs. Just pure derivation + signing logic
//! that mirrors `eigen-tee/src/lib/*.ts` byte-for-byte. Used by the
//! `polylayer-tee-server` binary inside the enclave; reusable from any
//! host for parity testing.
//!
//! Modules are added incrementally as each TS source file is ported.
//! See `eigen-tee-rust/MIGRATION.md` for the porting order.

#![forbid(unsafe_code)]
#![deny(unused_must_use)]

pub mod canonical;
pub mod clob;
pub mod derive;
pub mod evm;
pub mod hyperliquid;
pub mod intents;
pub mod jupiter;
pub mod polymarket;
pub mod solana;
pub mod solana_attestor;
