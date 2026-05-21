//! Generic EVM signing primitives.
//!
//! - `permits`: EIP-2612 permit signing (USDC on Arbitrum for HL Bridge2)
//! - `tx`:      Generic EIP-1559 transaction signing (CCTP, pUSD wrap/redeem)
//!
//! Both are pure — no chain reads. The lambda is responsible for fetching
//! on-chain state (nonces, fee oracles) and passing the values in.

pub mod abi;
pub mod cctp;
pub mod permits;
pub mod polymarket_flows;
pub mod tx;

pub use cctp::{
    decode_deposit_for_burn, deposit_for_burn_v2_selector, derive_solana_usdc_ata,
    validate_against_intent, CctpError, CctpIntentBounds, DepositForBurnArgs,
    ARBITRUM_USDC, CCTP_DOMAIN_ARBITRUM, CCTP_DOMAIN_POLYGON, CCTP_DOMAIN_SOLANA,
    CCTP_STANDARD_FINALITY, POLYGON_USDC, TOKEN_MESSENGER_V2_ADDRESS,
};
pub use permits::{sign_usdc_permit_arbitrum, Erc2612PermitSplitSig, PermitError};
pub use tx::{assert_owner, sign_eip1559, AccessListItem, Eip1559Tx, EvmTxError, SignedEip1559Tx};
