//! Error type mapping domain failures to the §11 status codes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub(crate) enum ApiError {
    /// Malformed JSON, invalid chunk hash, unsafe manifest path.
    BadRequest(String),
    /// Lease fencing: wrong holder, stale generation, expired lease. The
    /// body carries `"fenced": true` so a client can tell lease loss
    /// apart from an auth/role 403 (they share the status code).
    Fenced(String),
    /// Auth/role failures: admin-only routes, insufficient role.
    Forbidden(String),
    /// Unknown workspace, chunk, or head.
    NotFound(String),
    /// CAS conflict on the head log or lease held by another device. Body
    /// shapes are pinned by §11 (`{ current_seq }`, `{ holder, expires_at }`).
    Conflict(serde_json::Value),
    /// Server-side failure: logged, reported as a plain 500.
    Internal(anyhow::Error),
}

impl ApiError {
    pub(crate) fn internal_msg(msg: &'static str) -> Self {
        Self::Internal(anyhow::anyhow!(msg))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
            }
            Self::Fenced(msg) => (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": msg, "fenced": true })),
            )
                .into_response(),
            Self::Forbidden(msg) => {
                (StatusCode::FORBIDDEN, Json(json!({ "error": msg }))).into_response()
            }
            Self::NotFound(msg) => {
                (StatusCode::NOT_FOUND, Json(json!({ "error": msg }))).into_response()
            }
            Self::Conflict(body) => (StatusCode::CONFLICT, Json(body)).into_response(),
            Self::Internal(err) => {
                eprintln!("pear-relay internal error: {err:#}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "internal server error" })),
                )
                    .into_response()
            }
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Internal(err.into())
    }
}

impl From<std::io::Error> for ApiError {
    fn from(err: std::io::Error) -> Self {
        Self::Internal(err.into())
    }
}
