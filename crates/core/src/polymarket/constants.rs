//! Polymarket V2 + DepositWallet constants.
//!
//! Mirrors the subset of `eigen-tee/src/lib/constants.ts` that the
//! polymarket signer touches. All values are public on-chain; safe to
//! commit and inline. NEVER mutate — addresses + type hashes determine
//! signature validity, so any drift breaks every prior signed payload.

use alloy_primitives::{address, b256, Address, B256};
use once_cell::sync::Lazy;
use sha3::{Digest, Keccak256};

pub const POLYGON_CHAIN_ID: u64 = 137;

// ─── Exchange addresses ─────────────────────────────────────────────
pub const CTF_EXCHANGE_V2_ADDRESS: Address =
    address!("E111180000d2663C0091e4f400237545B87B996B");
pub const NEG_RISK_CTF_EXCHANGE_V2_ADDRESS: Address =
    address!("e2222d279d744050d28e00520010520000310F59");

// ─── DepositWallet bootstrap-approval targets (V2 collateral flow) ──
/// pUSD — the Polymarket V2 collateral token. Target of `approve`.
pub const PUSD_CONTRACT_ADDRESS: Address =
    address!("C011a7E12a19f7B1f670d46F03B03f3342E82DFB");
/// Conditional Tokens Framework. Target of `setApprovalForAll`.
pub const CTF_CONTRACT_ADDRESS: Address =
    address!("4D97DCd97eC945f40cF65F87097ACe5EA0476045");
/// Neg-risk adapter — the third V2 exchange spender, alongside the two
/// CTF exchanges above. The bootstrap batch approves all three.
pub const NEG_RISK_ADAPTER_ADDRESS: Address =
    address!("d91E80cF2E7be2e162c6513ceD06f1dD0dA35296");

// ─── DepositWallet factory ──────────────────────────────────────────
pub const DEPOSIT_WALLET_FACTORY_ADDRESS: Address =
    address!("00000000000Fb5C9ADea0298D729A0CB3823Cc07");
pub const DEPOSIT_WALLET_IMPLEMENTATION_ADDRESS: Address =
    address!("58CA52ebe0DadfdF531Cde7062e76746de4Db1eB");

pub const DEPOSIT_WALLET_DOMAIN_NAME: &str = "DepositWallet";
pub const DEPOSIT_WALLET_DOMAIN_VERSION: &str = "1";

// ─── Signature type enum ────────────────────────────────────────────
pub const SIDE_BUY: u8 = 0;
pub const SIDE_SELL: u8 = 1;
pub const SIG_TYPE_POLY_1271: u8 = 3;

pub const ZERO_BYTES32: B256 = B256::ZERO;

// ─── Type strings ───────────────────────────────────────────────────
pub const POLYMARKET_V2_ORDER_TYPE_STRING: &str =
    "Order(uint256 salt,address maker,address signer,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,uint256 timestamp,bytes32 metadata,bytes32 builder)";

pub const EIP712_DOMAIN_TYPE_STRING: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

pub const CTF_EXCHANGE_NAME: &str = "Polymarket CTF Exchange";
pub const CTF_EXCHANGE_VERSION: &str = "2";

// ─── Pre-computed type hashes (verified at runtime via Lazy) ────────
pub static POLYMARKET_V2_ORDER_TYPE_HASH: Lazy<B256> =
    Lazy::new(|| keccak256(POLYMARKET_V2_ORDER_TYPE_STRING.as_bytes()));

pub static EIP712_DOMAIN_TYPE_HASH: Lazy<B256> =
    Lazy::new(|| keccak256(EIP712_DOMAIN_TYPE_STRING.as_bytes()));

pub static CTF_EXCHANGE_NAME_HASH: Lazy<B256> =
    Lazy::new(|| keccak256(CTF_EXCHANGE_NAME.as_bytes()));

pub static CTF_EXCHANGE_VERSION_HASH: Lazy<B256> =
    Lazy::new(|| keccak256(CTF_EXCHANGE_VERSION.as_bytes()));

pub static DEPOSIT_WALLET_DOMAIN_NAME_HASH: Lazy<B256> =
    Lazy::new(|| keccak256(DEPOSIT_WALLET_DOMAIN_NAME.as_bytes()));

pub static DEPOSIT_WALLET_DOMAIN_VERSION_HASH: Lazy<B256> =
    Lazy::new(|| keccak256(DEPOSIT_WALLET_DOMAIN_VERSION.as_bytes()));

// ─── ERC-1967 init-code-hash template (DepositWallet derivation) ────
//
// These constants are pieces of EVM bytecode used to reconstruct the
// init-code hash of the deposit-wallet proxy. They come from
// Polymarket's relayer client — verified by the parity test vectors
// in tests::deposit_wallet_derivation_matches_polymarket_client.

pub const ERC1967_CONST1: B256 =
    b256!("cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3");
pub const ERC1967_CONST2: B256 =
    b256!("5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076");

/// 10-byte EVM-bytecode prefix used by `init_code_hash_erc1967`. The
/// upper 64 bits get OR-ed with the byte length of `args` at runtime.
pub const ERC1967_PREFIX_HEX: &str = "61003d3d8160233d3973";

fn keccak256(input: &[u8]) -> B256 {
    B256::from_slice(Keccak256::digest(input).as_slice())
}
