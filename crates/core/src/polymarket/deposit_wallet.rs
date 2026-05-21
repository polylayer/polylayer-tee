//! Deterministic Polymarket V2 DepositWallet address derivation.
//!
//! Mirrors `deriveDepositWalletAddress` from
//! `eigen-tee/src/lib/polymarketDepositWallet.ts`. The wallet is a
//! CREATE2-deployed ERC-1967 proxy; this fn computes the address that
//! `DepositWalletFactory.deploy(owner)` would create — without making
//! any RPC calls.
//!
//! The TS impl uses Solady's `LibClone`-style init-code-hash dance.
//! Reproducing it byte-for-byte requires the four `ERC1967_*` constants
//! defined in `constants.rs`. The two parity test vectors at the bottom
//! lock the derivation against Polymarket's own builder-relayer-client
//! snapshots — any drift will fail the test.

use alloy_primitives::{Address, B256, U256};
use sha3::{Digest, Keccak256};

use super::constants::{
    DEPOSIT_WALLET_FACTORY_ADDRESS, DEPOSIT_WALLET_IMPLEMENTATION_ADDRESS, ERC1967_CONST1,
    ERC1967_CONST2, ERC1967_PREFIX_HEX,
};

/// Compute the deterministic DepositWallet address for the given EOA owner.
pub fn derive_deposit_wallet_address(owner: Address) -> Address {
    // walletId = left-pad(owner, 32 bytes).
    let mut wallet_id = [0u8; 32];
    wallet_id[12..].copy_from_slice(owner.as_slice());

    // args = abi.encode(factory, wallet_id). For (address, bytes32),
    // the ABI encoding is: 32-byte left-padded address || 32-byte
    // bytes32, total 64 bytes.
    let args = abi_encode_address_bytes32(DEPOSIT_WALLET_FACTORY_ADDRESS, &wallet_id);

    // salt = keccak256(args).
    let salt = keccak256(&args);

    // bytecode_hash = ERC-1967 init-code hash (template above).
    let bytecode_hash = init_code_hash_erc1967(DEPOSIT_WALLET_IMPLEMENTATION_ADDRESS, &args);

    // CREATE2 address = keccak256(0xff || from || salt || bytecode_hash)[12..32]
    create2_address(DEPOSIT_WALLET_FACTORY_ADDRESS, salt, bytecode_hash)
}

fn abi_encode_address_bytes32(addr: Address, bytes32: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[12..32].copy_from_slice(addr.as_slice()); // left-pad address
    out[32..64].copy_from_slice(bytes32);
    out
}

fn init_code_hash_erc1967(implementation: Address, args: &[u8]) -> B256 {
    // combined = ERC1967_PREFIX + (args.len() << 56), rendered as 10 BE bytes.
    let prefix: U256 = U256::from_str_radix(ERC1967_PREFIX_HEX, 16)
        .expect("ERC1967_PREFIX_HEX is a valid hex literal");
    let n = U256::from(args.len() as u64);
    let combined: U256 = prefix + (n << 56);

    // Take the lower 10 bytes (big-endian).
    let combined_be: [u8; 32] = combined.to_be_bytes::<32>();
    let combined_10 = &combined_be[32 - 10..];

    let mut buf = Vec::with_capacity(10 + 20 + 2 + 32 + 32 + args.len());
    buf.extend_from_slice(combined_10);
    buf.extend_from_slice(implementation.as_slice());
    buf.extend_from_slice(&[0x60, 0x09]); // 2-byte EVM bytecode literal "0x6009"
    buf.extend_from_slice(ERC1967_CONST2.as_slice());
    buf.extend_from_slice(ERC1967_CONST1.as_slice());
    buf.extend_from_slice(args);

    keccak256(&buf)
}

fn create2_address(from: Address, salt: B256, bytecode_hash: B256) -> Address {
    let mut buf = Vec::with_capacity(1 + 20 + 32 + 32);
    buf.push(0xff);
    buf.extend_from_slice(from.as_slice());
    buf.extend_from_slice(salt.as_slice());
    buf.extend_from_slice(bytecode_hash.as_slice());
    let hash = keccak256(&buf);
    Address::from_slice(&hash[12..32])
}

fn keccak256(input: &[u8]) -> B256 {
    B256::from_slice(Keccak256::digest(input).as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn deposit_wallet_derivation_matches_polymarket_client() {
        // Two ground-truth vectors lifted directly from
        // `eigen-tee/test/polymarketSign.test.ts`, which themselves come
        // from Polymarket's own builder-relayer-client snapshots. Any
        // drift in our impl will fail these.
        let owner1 = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let expected1 = address!("df8b9E8f9AB23f261F6e1B171B7454ae6E46Ba76");
        assert_eq!(derive_deposit_wallet_address(owner1), expected1);

        let owner2 = address!("0000000000000000000000000000000000000001");
        let expected2 = address!("57ffBc34De23124fAeb8387fcd689d314E57aCcD");
        assert_eq!(derive_deposit_wallet_address(owner2), expected2);
    }

    #[test]
    fn deposit_wallet_derivation_is_deterministic() {
        let owner = address!("1234567890abcdef1234567890abcdef12345678");
        let a = derive_deposit_wallet_address(owner);
        let b = derive_deposit_wallet_address(owner);
        assert_eq!(a, b);
    }

    #[test]
    fn deposit_wallet_derivation_differs_per_owner() {
        let a = derive_deposit_wallet_address(address!("1111111111111111111111111111111111111111"));
        let b = derive_deposit_wallet_address(address!("2222222222222222222222222222222222222222"));
        assert_ne!(a, b);
    }
}
