//! Jupiter Perpetuals instruction decoder.
//!
//! Mirrors `eigen-tee/src/lib/jupiter-perps-decode.ts`. We hand-roll a
//! minimal borsh reader rather than pulling Anchor — same reasoning as
//! the TS impl, just translated to Rust.
//!
//! Anchor discriminators are `sha256("global:<ix_name>")[0..8]`,
//! computed once via `once_cell::Lazy`.

use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use thiserror::Error;

// ─── Anchor discriminators ──────────────────────────────────────────

pub static INCREASE_DISCRIMINATOR: Lazy<[u8; 8]> = Lazy::new(|| {
    let h = Sha256::digest(b"global:create_increase_position_market_request");
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
});

pub static DECREASE_DISCRIMINATOR: Lazy<[u8; 8]> = Lazy::new(|| {
    let h = Sha256::digest(b"global:create_decrease_position_market_request");
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
});

// ─── IDL-derived account-array positions ────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct AccountIndex {
    pub owner: usize,
    pub custody: usize,
    pub collateral_custody: usize,
}

/// `createIncreasePositionMarketRequest` accounts (0-indexed).
pub const INCREASE_ACCOUNT_INDEX: AccountIndex = AccountIndex {
    owner: 0,
    custody: 7,
    collateral_custody: 8,
};

/// `createDecreasePositionMarketRequest` accounts (0-indexed).
pub const DECREASE_ACCOUNT_INDEX: AccountIndex = AccountIndex {
    owner: 0,
    custody: 7,
    collateral_custody: 8,
};

// ─── Custody PDAs (mainnet) ─────────────────────────────────────────
//
// Bs58 → bytes lookup at module-load. Keeping these as `Lazy<Pubkey>`
// avoids a const-fn dance; the bs58 decoder isn't const.

pub static JUPITER_CUSTODY_SOL: Lazy<Pubkey> = Lazy::new(|| {
    "7xS2gz2bTp3fwCC7knJvUWTEU9Tycczu6VhJYKgi1wdz".parse().expect("hard-coded pubkey")
});
pub static JUPITER_CUSTODY_BTC: Lazy<Pubkey> = Lazy::new(|| {
    "5Pv3gM9JrFFH883SWAhvJC9RPYmo8UNxuFtv5bMMALkm".parse().expect("hard-coded pubkey")
});
pub static JUPITER_CUSTODY_ETH: Lazy<Pubkey> = Lazy::new(|| {
    "AQCGyheWPLeo6Qp9WpYS9m3Qj479t7R636N9ey1rEjEn".parse().expect("hard-coded pubkey")
});
pub static JUPITER_PERPS_PROGRAM_ID: Lazy<Pubkey> = Lazy::new(|| {
    "PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu".parse().expect("hard-coded pubkey")
});

pub type JupiterAsset = &'static str;

/// Resolve a custody pubkey to its tradeable asset label. Returns None
/// for any custody not in the static map — callers fail the intent
/// match if so.
pub fn custody_to_asset(custody: &Pubkey) -> Option<JupiterAsset> {
    if custody == &*JUPITER_CUSTODY_SOL {
        Some("SOL")
    } else if custody == &*JUPITER_CUSTODY_BTC {
        Some("BTC")
    } else if custody == &*JUPITER_CUSTODY_ETH {
        Some("ETH")
    } else {
        None
    }
}

// ─── Decoded args ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IncreaseArgs {
    pub size_usd_delta: u64,
    pub collateral_token_delta: u64,
    /// 0 = None, 1 = Long, 2 = Short.
    pub side: u8,
    pub price_slippage: u64,
    pub jupiter_minimum_out: Option<u64>,
    pub counter: u64,
}

#[derive(Debug, Clone)]
pub struct DecreaseArgs {
    pub collateral_usd_delta: u64,
    pub size_usd_delta: u64,
    pub price_slippage: u64,
    pub jupiter_minimum_out: Option<u64>,
    pub entire_position: Option<bool>,
    pub counter: u64,
}

#[derive(Debug, Clone)]
pub struct DecodedAccounts {
    pub owner: Pubkey,
    pub custody: Pubkey,
    pub collateral_custody: Pubkey,
}

#[derive(Debug, Clone)]
pub enum DecodedJupiterIx {
    Increase {
        args: IncreaseArgs,
        accounts: DecodedAccounts,
    },
    Decrease {
        args: DecreaseArgs,
        accounts: DecodedAccounts,
    },
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("ix data too short ({0} bytes); need at least 8 for discriminator")]
    TooShort(usize),

    #[error("invalid side tag {0} (expected 0|1|2)")]
    BadSide(u8),

    #[error("invalid bool value {0}")]
    BadBool(u8),

    #[error("invalid option tag {0} (expected 0|1)")]
    BadOptionTag(u8),

    #[error("borsh read out of bounds at offset {offset} (need {need} bytes, have {have})")]
    OutOfBounds {
        offset: usize,
        need: usize,
        have: usize,
    },

    #[error("missing account {name} at index {idx} (have {len})")]
    MissingAccount {
        name: &'static str,
        idx: usize,
        len: usize,
    },
}

/// Decode a Jupiter perpetuals instruction. Returns `Ok(None)` if the
/// discriminator doesn't match either of the two supported ixes — the
/// caller (router) should treat that as "skip this ix" but require
/// exactly one match per tx.
pub fn decode_jupiter_perps_ix(
    ix_data: &[u8],
    account_pubkeys: &[Pubkey],
) -> Result<Option<DecodedJupiterIx>, DecodeError> {
    if ix_data.len() < 8 {
        return Err(DecodeError::TooShort(ix_data.len()));
    }
    let disc = &ix_data[..8];
    let args_buf = &ix_data[8..];

    if disc == &INCREASE_DISCRIMINATOR[..] {
        let mut r = Reader::new(args_buf);
        let size_usd_delta = r.u64()?;
        let collateral_token_delta = r.u64()?;
        let side = r.u8()?;
        if side > 2 {
            return Err(DecodeError::BadSide(side));
        }
        let price_slippage = r.u64()?;
        let jupiter_minimum_out = r.opt_u64()?;
        let counter = r.u64()?;
        let accounts =
            collect_accounts(account_pubkeys, INCREASE_ACCOUNT_INDEX)?;
        return Ok(Some(DecodedJupiterIx::Increase {
            args: IncreaseArgs {
                size_usd_delta,
                collateral_token_delta,
                side,
                price_slippage,
                jupiter_minimum_out,
                counter,
            },
            accounts,
        }));
    }

    if disc == &DECREASE_DISCRIMINATOR[..] {
        let mut r = Reader::new(args_buf);
        let collateral_usd_delta = r.u64()?;
        let size_usd_delta = r.u64()?;
        let price_slippage = r.u64()?;
        let jupiter_minimum_out = r.opt_u64()?;
        let entire_position = r.opt_bool()?;
        let counter = r.u64()?;
        let accounts =
            collect_accounts(account_pubkeys, DECREASE_ACCOUNT_INDEX)?;
        return Ok(Some(DecodedJupiterIx::Decrease {
            args: DecreaseArgs {
                collateral_usd_delta,
                size_usd_delta,
                price_slippage,
                jupiter_minimum_out,
                entire_position,
                counter,
            },
            accounts,
        }));
    }

    Ok(None)
}

fn collect_accounts(
    pubkeys: &[Pubkey],
    idx: AccountIndex,
) -> Result<DecodedAccounts, DecodeError> {
    let owner = require(pubkeys, idx.owner, "owner")?;
    let custody = require(pubkeys, idx.custody, "custody")?;
    let collateral_custody = require(pubkeys, idx.collateral_custody, "collateral_custody")?;
    Ok(DecodedAccounts {
        owner,
        custody,
        collateral_custody,
    })
}

fn require(pubkeys: &[Pubkey], idx: usize, name: &'static str) -> Result<Pubkey, DecodeError> {
    pubkeys
        .get(idx)
        .copied()
        .ok_or(DecodeError::MissingAccount {
            name,
            idx,
            len: pubkeys.len(),
        })
}

// ─── Mini borsh reader ──────────────────────────────────────────────

struct Reader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    fn need(&self, n: usize) -> Result<(), DecodeError> {
        if self.offset + n > self.buf.len() {
            Err(DecodeError::OutOfBounds {
                offset: self.offset,
                need: n,
                have: self.buf.len(),
            })
        } else {
            Ok(())
        }
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        self.need(1)?;
        let v = self.buf[self.offset];
        self.offset += 1;
        Ok(v)
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        self.need(8)?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buf[self.offset..self.offset + 8]);
        self.offset += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    fn opt_u64(&mut self) -> Result<Option<u64>, DecodeError> {
        let tag = self.u8()?;
        match tag {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            other => Err(DecodeError::BadOptionTag(other)),
        }
    }

    fn opt_bool(&mut self) -> Result<Option<bool>, DecodeError> {
        let tag = self.u8()?;
        match tag {
            0 => Ok(None),
            1 => {
                let b = self.u8()?;
                match b {
                    0 => Ok(Some(false)),
                    1 => Ok(Some(true)),
                    other => Err(DecodeError::BadBool(other)),
                }
            }
            other => Err(DecodeError::BadOptionTag(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminators_are_stable() {
        // Lazy ensures these compute once. Re-derive bytewise here.
        let inc = {
            let h = Sha256::digest(b"global:create_increase_position_market_request");
            let mut x = [0u8; 8];
            x.copy_from_slice(&h[..8]);
            x
        };
        assert_eq!(*INCREASE_DISCRIMINATOR, inc);
    }

    #[test]
    fn custody_to_asset_known_mints() {
        assert_eq!(custody_to_asset(&JUPITER_CUSTODY_SOL), Some("SOL"));
        assert_eq!(custody_to_asset(&JUPITER_CUSTODY_BTC), Some("BTC"));
        assert_eq!(custody_to_asset(&JUPITER_CUSTODY_ETH), Some("ETH"));
        assert_eq!(custody_to_asset(&Pubkey::new_unique()), None);
    }

    #[test]
    fn decode_increase_round_trip() {
        // Build an instruction body manually.
        let mut data = Vec::new();
        data.extend_from_slice(&INCREASE_DISCRIMINATOR[..]);
        data.extend_from_slice(&100_000_000u64.to_le_bytes()); // size_usd_delta
        data.extend_from_slice(&5_000_000u64.to_le_bytes());   // collateral_token_delta
        data.push(1u8);                                          // side = Long
        data.extend_from_slice(&50u64.to_le_bytes());          // price_slippage
        data.push(0u8);                                          // jupiter_minimum_out = None
        data.extend_from_slice(&7u64.to_le_bytes());           // counter

        // Pad accounts list to cover the highest index referenced.
        let mut pubkeys = vec![Pubkey::default(); 16];
        pubkeys[INCREASE_ACCOUNT_INDEX.owner] = Pubkey::new_unique();
        pubkeys[INCREASE_ACCOUNT_INDEX.custody] = *JUPITER_CUSTODY_SOL;
        pubkeys[INCREASE_ACCOUNT_INDEX.collateral_custody] = *JUPITER_CUSTODY_SOL;

        let decoded = decode_jupiter_perps_ix(&data, &pubkeys).unwrap().unwrap();
        match decoded {
            DecodedJupiterIx::Increase { args, accounts } => {
                assert_eq!(args.size_usd_delta, 100_000_000);
                assert_eq!(args.side, 1);
                assert_eq!(args.counter, 7);
                assert!(args.jupiter_minimum_out.is_none());
                assert_eq!(custody_to_asset(&accounts.custody), Some("SOL"));
            }
            _ => panic!("expected increase"),
        }
    }

    #[test]
    fn decode_decrease_round_trip() {
        let mut data = Vec::new();
        data.extend_from_slice(&DECREASE_DISCRIMINATOR[..]);
        data.extend_from_slice(&1_000_000u64.to_le_bytes()); // collateral_usd_delta
        data.extend_from_slice(&5_000_000u64.to_le_bytes()); // size_usd_delta
        data.extend_from_slice(&25u64.to_le_bytes());        // price_slippage
        data.push(1u8);                                       // opt_u64 tag = Some
        data.extend_from_slice(&123u64.to_le_bytes());       // minimum_out
        data.push(1u8);                                       // opt_bool tag = Some
        data.push(1u8);                                       // bool true
        data.extend_from_slice(&42u64.to_le_bytes());        // counter

        let mut pubkeys = vec![Pubkey::default(); 16];
        pubkeys[DECREASE_ACCOUNT_INDEX.custody] = *JUPITER_CUSTODY_BTC;
        pubkeys[DECREASE_ACCOUNT_INDEX.collateral_custody] = *JUPITER_CUSTODY_BTC;
        pubkeys[DECREASE_ACCOUNT_INDEX.owner] = Pubkey::new_unique();

        let decoded = decode_jupiter_perps_ix(&data, &pubkeys).unwrap().unwrap();
        match decoded {
            DecodedJupiterIx::Decrease { args, accounts } => {
                assert_eq!(args.size_usd_delta, 5_000_000);
                assert_eq!(args.jupiter_minimum_out, Some(123));
                assert_eq!(args.entire_position, Some(true));
                assert_eq!(args.counter, 42);
                assert_eq!(custody_to_asset(&accounts.custody), Some("BTC"));
            }
            _ => panic!("expected decrease"),
        }
    }

    #[test]
    fn decode_unknown_discriminator_returns_none() {
        let data = [0u8; 32];
        assert!(decode_jupiter_perps_ix(&data, &[]).unwrap().is_none());
    }

    #[test]
    fn decode_rejects_bad_side() {
        let mut data = Vec::new();
        data.extend_from_slice(&INCREASE_DISCRIMINATOR[..]);
        data.extend_from_slice(&[0u8; 16]);
        data.push(99u8); // bad side
        data.extend_from_slice(&[0u8; 17]);

        let pubkeys = vec![Pubkey::default(); 16];
        let err = decode_jupiter_perps_ix(&data, &pubkeys).unwrap_err();
        assert!(matches!(err, DecodeError::BadSide(99)));
    }
}
