//! Error type mapping domain failures to the §11 status codes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub(crate) enum ApiError {
    /// Malformed JSON, invalid chunk hash, unsafe manifest path.
    BadRequest(String),
    /// Auth/role failures: admin-only routes, insufficient role.
    Forbidden(String),
    /// Unknown workspace, chunk, or head.
    NotFound(String),
    /// CAS conflict on the head log (§32: the only concurrency control).
    /// The body shape is pinned by §11 (`{ current_seq }`).
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
