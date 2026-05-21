//! Polymarket V2 CLOB primitives.
//!
//! Two pure (no-I/O) helpers:
//!
//! - `headers`: builds the 5 `POLY_*` L2 HMAC headers required on every
//!   authenticated CLOB request.
//! - `auth`:    builds the L1 ClobAuth EIP-712 signature + headers used
//!   to derive/create per-user API credentials. The actual HTTP fetch
//!   to `clob.polymarket.com/auth/...` lives in the server crate (the
//!   pure crypto is here so it can be parity-tested standalone).

pub mod auth;
pub mod headers;

pub use auth::{build_l1_headers, ClobAuthError, L1Headers};
pub use headers::{build_l2_headers, BuildL2HeadersArgs, ClobL2Headers, L2HeadersError};
