//! 104-byte polyleverage attestation payload builders.
//!
//! Mirrors `eigen-tee/src/lib/solana-attestor/attestation.ts`. Wire
//! format MUST stay byte-compatible with the Rust struct at
//! `polyleverage/src/attestation.rs::Attestation::parse` — any change
//! requires a coordinated on-chain release.
//!
//! ```text
//!   [0..4]   magic "ATT1"
//!   [4]      type (1=PRICE_TWAP, 2=RESOLUTION, 3=HISTORICAL_LIQUIDATION)
//!   [5..8]   pad (zeros)
//!   [8..40]  market_id (32 bytes)
//!   [40..48] signed_unix_ts (u64 LE)
//!   [48..56] nonce (u64 LE)
//!   [56..104] payload (48 bytes, type-specific)
//! ```

use thiserror::Error;

pub const ATTESTATION_LEN: usize = 104;
pub const ATTESTATION_PAYLOAD_OFFSET: usize = 56;
pub const ATTESTATION_MAGIC: &[u8; 4] = b"ATT1";

pub const ATT_TYPE_PRICE_TWAP: u8 = 1;
pub const ATT_TYPE_RESOLUTION: u8 = 2;
pub const ATT_TYPE_HISTORICAL_LIQUIDATION: u8 = 3;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("market_id must be 32 bytes, got {0}")]
    BadMarketId(usize),

    #[error("pmlc_pubkey must be 32 bytes, got {0}")]
    BadPmlcPubkey(usize),

    #[error("breach_unix_ts must be non-negative, got {0}")]
    NegativeBreachTs(i64),

    #[error("observation_end_ts ({end}) must be >= observation_start_ts ({start})")]
    ObservationOrdering { start: u64, end: u64 },
}

#[derive(Debug, Clone)]
pub struct AttestationCommon {
    /// 32-byte market identifier.
    pub market_id: [u8; 32],
    /// Wrapper signature timestamp (wall clock at sign time).
    pub signed_unix_ts: u64,
    /// Strictly increasing per market.
    pub nonce: u64,
}

#[derive(Debug, Clone)]
pub struct HistoricalLiquidationPayload {
    pub pmlc_pubkey: [u8; 32],
    /// u64 FP18 — TWAP at breach.
    pub breach_mark_fp: u64,
    /// i64 — unix ts of breach. Must be non-negative.
    pub breach_unix_ts: i64,
}

#[derive(Debug, Clone)]
pub struct ResolutionPayload {
    /// 0 | 5000 | 10000 (u16 LE on the wire).
    pub final_outcome_bps: u16,
    pub resolved_at_ts: u64,
}

#[derive(Debug, Clone)]
pub struct PriceTwapPayload {
    /// TWAP price (u64 FP18) over the observation window.
    pub price_fp: u64,
    /// Must match `instrument.twap_window_slots` — on-chain rejects otherwise.
    pub twap_window_slots: u64,
    pub observation_start_ts: u64,
    pub observation_end_ts: u64,
}

fn build_header(att_type: u8, common: &AttestationCommon) -> [u8; ATTESTATION_PAYLOAD_OFFSET] {
    let mut buf = [0u8; ATTESTATION_PAYLOAD_OFFSET];
    buf[0..4].copy_from_slice(ATTESTATION_MAGIC);
    buf[4] = att_type;
    // [5..8] padding stays zero.
    buf[8..40].copy_from_slice(&common.market_id);
    buf[40..48].copy_from_slice(&common.signed_unix_ts.to_le_bytes());
    buf[48..56].copy_from_slice(&common.nonce.to_le_bytes());
    buf
}

pub fn build_historical_liquidation(
    common: &AttestationCommon,
    payload: &HistoricalLiquidationPayload,
) -> Result<[u8; ATTESTATION_LEN], AttestationError> {
    if payload.breach_unix_ts < 0 {
        return Err(AttestationError::NegativeBreachTs(payload.breach_unix_ts));
    }
    let header = build_header(ATT_TYPE_HISTORICAL_LIQUIDATION, common);
    let mut out = [0u8; ATTESTATION_LEN];
    out[..ATTESTATION_PAYLOAD_OFFSET].copy_from_slice(&header);
    out[56..88].copy_from_slice(&payload.pmlc_pubkey);
    out[88..96].copy_from_slice(&payload.breach_mark_fp.to_le_bytes());
    out[96..104].copy_from_slice(&payload.breach_unix_ts.to_le_bytes());
    Ok(out)
}

pub fn build_resolution(
    common: &AttestationCommon,
    payload: &ResolutionPayload,
) -> [u8; ATTESTATION_LEN] {
    let header = build_header(ATT_TYPE_RESOLUTION, common);
    let mut out = [0u8; ATTESTATION_LEN];
    out[..ATTESTATION_PAYLOAD_OFFSET].copy_from_slice(&header);
    out[56..58].copy_from_slice(&payload.final_outcome_bps.to_le_bytes());
    out[58..66].copy_from_slice(&payload.resolved_at_ts.to_le_bytes());
    // [66..104] remains zero — reserved.
    out
}

pub fn build_price_twap(
    common: &AttestationCommon,
    payload: &PriceTwapPayload,
) -> Result<[u8; ATTESTATION_LEN], AttestationError> {
    if payload.observation_end_ts < payload.observation_start_ts {
        return Err(AttestationError::ObservationOrdering {
            start: payload.observation_start_ts,
            end: payload.observation_end_ts,
        });
    }
    let header = build_header(ATT_TYPE_PRICE_TWAP, common);
    let mut out = [0u8; ATTESTATION_LEN];
    out[..ATTESTATION_PAYLOAD_OFFSET].copy_from_slice(&header);
    out[56..64].copy_from_slice(&payload.price_fp.to_le_bytes());
    out[64..72].copy_from_slice(&payload.twap_window_slots.to_le_bytes());
    out[72..80].copy_from_slice(&payload.observation_start_ts.to_le_bytes());
    out[80..88].copy_from_slice(&payload.observation_end_ts.to_le_bytes());
    // [88..104] reserved.
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_common() -> AttestationCommon {
        AttestationCommon {
            market_id: [0xab; 32],
            signed_unix_ts: 1_700_000_000,
            nonce: 7,
        }
    }

    #[test]
    fn historical_liquidation_layout() {
        let payload = HistoricalLiquidationPayload {
            pmlc_pubkey: [0xcd; 32],
            breach_mark_fp: 1_000_000_000_000u64,
            breach_unix_ts: 1_600_000_000,
        };
        let out = build_historical_liquidation(&make_common(), &payload).unwrap();
        assert_eq!(out.len(), ATTESTATION_LEN);
        assert_eq!(&out[0..4], ATTESTATION_MAGIC);
        assert_eq!(out[4], ATT_TYPE_HISTORICAL_LIQUIDATION);
        assert_eq!(&out[5..8], &[0, 0, 0]);
        assert_eq!(&out[8..40], &[0xab; 32]);
        assert_eq!(
            u64::from_le_bytes(out[40..48].try_into().unwrap()),
            1_700_000_000
        );
        assert_eq!(u64::from_le_bytes(out[48..56].try_into().unwrap()), 7);
        assert_eq!(&out[56..88], &[0xcd; 32]);
        assert_eq!(
            u64::from_le_bytes(out[88..96].try_into().unwrap()),
            1_000_000_000_000
        );
        assert_eq!(
            i64::from_le_bytes(out[96..104].try_into().unwrap()),
            1_600_000_000
        );
    }

    #[test]
    fn historical_liquidation_rejects_negative_breach_ts() {
        let payload = HistoricalLiquidationPayload {
            pmlc_pubkey: [0xcd; 32],
            breach_mark_fp: 0,
            breach_unix_ts: -1,
        };
        assert!(matches!(
            build_historical_liquidation(&make_common(), &payload),
            Err(AttestationError::NegativeBreachTs(-1))
        ));
    }

    #[test]
    fn resolution_layout() {
        let payload = ResolutionPayload {
            final_outcome_bps: 10_000,
            resolved_at_ts: 1_700_000_000,
        };
        let out = build_resolution(&make_common(), &payload);
        assert_eq!(out[4], ATT_TYPE_RESOLUTION);
        assert_eq!(u16::from_le_bytes(out[56..58].try_into().unwrap()), 10_000);
        assert_eq!(
            u64::from_le_bytes(out[58..66].try_into().unwrap()),
            1_700_000_000
        );
        // Reserved bytes remain zero.
        assert!(out[66..104].iter().all(|&b| b == 0));
    }

    #[test]
    fn price_twap_layout() {
        let payload = PriceTwapPayload {
            price_fp: 12_345_678,
            twap_window_slots: 100,
            observation_start_ts: 1_700_000_000,
            observation_end_ts: 1_700_003_600,
        };
        let out = build_price_twap(&make_common(), &payload).unwrap();
        assert_eq!(out[4], ATT_TYPE_PRICE_TWAP);
        assert_eq!(u64::from_le_bytes(out[56..64].try_into().unwrap()), 12_345_678);
        assert_eq!(u64::from_le_bytes(out[64..72].try_into().unwrap()), 100);
        assert_eq!(
            u64::from_le_bytes(out[72..80].try_into().unwrap()),
            1_700_000_000
        );
        assert_eq!(
            u64::from_le_bytes(out[80..88].try_into().unwrap()),
            1_700_003_600
        );
    }

    #[test]
    fn price_twap_rejects_inverted_observation_window() {
        let payload = PriceTwapPayload {
            price_fp: 1,
            twap_window_slots: 1,
            observation_start_ts: 2,
            observation_end_ts: 1, // before start
        };
        assert!(matches!(
            build_price_twap(&make_common(), &payload),
            Err(AttestationError::ObservationOrdering { .. })
        ));
    }
}
