//! HTTP route handlers, one per eigen-tee route. Each handler:
//!
//! 1. Parses + validates the request body via serde
//! 2. Calls into `polylayer-tee-core` for the actual cryptographic op
//! 3. Returns the response in the exact shape the legacy TS impl emits
//!    (so existing lambda consumers don't need parser changes)

pub mod derive;
pub mod generic_session;
pub mod health;
pub mod hl_session;
pub mod jupiter_session;
pub mod polyleverage_session;
pub mod sign_clob_l2_headers;
pub mod sign_evm_tx;
pub mod sign_hl_bridge_permit;
pub mod sign_hyperliquid_order;
pub mod sign_jupiter_tx;
pub mod sign_link_message;
pub mod sign_polymarket_order;
pub mod sign_solana_liquidation;
pub mod sign_solana_price_twap;
pub mod sign_solana_resolution;
