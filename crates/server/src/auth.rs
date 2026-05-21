//! Bearer-token authentication middleware.
//!
//! Mirrors `eigen-tee/src/lib/adminAuth.ts`. Every authenticated route
//! requires `Authorization: Bearer <EIGEN_TEE_ADMIN_TOKEN>`. The token
//! is constant-time-compared to avoid timing leaks.

use crate::AppState;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;
use subtle::ConstantTimeEq;

pub async fn require_admin(
    State(state): State<Arc<AppState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .trim();

    let expected = state.admin_token.as_bytes();
    let provided = token.as_bytes();

    // Constant-time comparison; defensive against timing oracles even
    // though the token is in-memory and not attacker-controlled.
    if expected.ct_eq(provided).unwrap_u8() != 1 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}
