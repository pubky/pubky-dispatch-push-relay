//! Structured HTTP API error types and responses.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Machine-readable error codes returned by the push relay HTTP API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// Request body or parameters failed validation (`400`).
    BadRequest,
    /// Webhook Ed25519 signature was missing, malformed, or did not verify (`401`).
    BadSignature,
    /// Webhook timestamp fell outside the allowed ±5 minute clock window (`401`).
    StaleTimestamp,
    /// Push handle or route was not found (`404`).
    NotFound,
    /// Request did not complete within the configured deadline (`408`).
    RequestTimeout,
    /// Webhook nonce was already seen within the 10-minute replay window (`409`).
    NonceReplay,
    /// Request body exceeded the configured size limit (`413`).
    TooLarge,
    /// Caller or handle exceeded its per-minute rate limit (`429`).
    RateLimited,
    /// Push key exceeded its active handle quota (`429`).
    QuotaExceeded,
    /// Unexpected internal error (`500`).
    Internal,
    /// Upstream APNs or FCM gateway returned a transient failure or timed out (`502`).
    UpstreamError,
    /// Service, storage capacity, replay capacity, or platform backend is unavailable (`503`).
    Unavailable,
}

impl ErrorCode {
    /// Returns the snake_case wire error code string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::BadSignature => "bad_signature",
            Self::StaleTimestamp => "stale_timestamp",
            Self::NotFound => "not_found",
            Self::RequestTimeout => "request_timeout",
            Self::NonceReplay => "nonce_replay",
            Self::TooLarge => "too_large",
            Self::RateLimited => "rate_limited",
            Self::QuotaExceeded => "quota_exceeded",
            Self::Internal => "internal_error",
            Self::UpstreamError => "upstream_error",
            Self::Unavailable => "unavailable",
        }
    }

    /// Returns the HTTP status code associated with this error code.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::BadSignature | Self::StaleTimestamp => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::NonceReplay => StatusCode::CONFLICT,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited | Self::QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UpstreamError => StatusCode::BAD_GATEWAY,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// JSON error response returned by HTTP endpoints.
#[derive(Debug)]
pub struct ApiError {
    /// Machine-readable error code.
    pub code: ErrorCode,
    /// Human-readable error message (never contains PII, tokens, or handles).
    pub message: String,
    /// Optional `Retry-After` duration in seconds for `429` responses.
    pub retry_after: Option<u64>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'static str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<u64>,
}

impl ApiError {
    /// Creates a `400 bad_request` error.
    #[must_use]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::BadRequest,
            message: message.into(),
            retry_after: None,
        }
    }

    /// Creates a `401 bad_signature` error.
    #[must_use]
    pub fn bad_signature(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::BadSignature,
            message: message.into(),
            retry_after: None,
        }
    }

    /// Creates a `401 stale_timestamp` error.
    #[must_use]
    pub fn stale_timestamp(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::StaleTimestamp,
            message: message.into(),
            retry_after: None,
        }
    }

    /// Creates a `404 not_found` error.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::NotFound,
            message: message.into(),
            retry_after: None,
        }
    }

    /// Creates a `408 request_timeout` error.
    #[must_use]
    pub fn request_timeout() -> Self {
        Self {
            code: ErrorCode::RequestTimeout,
            message: "request timed out".to_owned(),
            retry_after: None,
        }
    }

    /// Creates a `409 nonce_replay` error.
    #[must_use]
    pub fn nonce_replay() -> Self {
        Self {
            code: ErrorCode::NonceReplay,
            message: "webhook nonce has already been seen within the replay window".to_owned(),
            retry_after: None,
        }
    }

    /// Creates a `413 too_large` error.
    #[must_use]
    pub fn too_large(max_bytes: usize) -> Self {
        Self {
            code: ErrorCode::TooLarge,
            message: format!("request body exceeds limit of {max_bytes} bytes"),
            retry_after: None,
        }
    }

    /// Creates a `429 rate_limited` error with a `Retry-After` hint for `/v1/hook`.
    #[must_use]
    pub fn rate_limited(retry_after_secs: u64) -> Self {
        Self::rate_limited_with_message(retry_after_secs, "handle exceeded per-minute push limit")
    }

    /// Creates a `429 rate_limited` error with a custom message and `Retry-After` hint.
    #[must_use]
    pub fn rate_limited_with_message(retry_after_secs: u64, message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::RateLimited,
            message: message.into(),
            retry_after: Some(retry_after_secs),
        }
    }

    /// Creates a `429 quota_exceeded` error when a push key reaches its active handle cap.
    #[must_use]
    pub fn quota_exceeded(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::QuotaExceeded,
            message: message.into(),
            retry_after: None,
        }
    }

    /// Creates a `500 internal_error` response without leaking internal details.
    #[must_use]
    pub fn internal() -> Self {
        Self {
            code: ErrorCode::Internal,
            message: "internal server error".to_owned(),
            retry_after: None,
        }
    }

    /// Creates a `502 upstream_error` response.
    #[must_use]
    pub fn upstream(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::UpstreamError,
            message: message.into(),
            retry_after: None,
        }
    }

    /// Creates a `503 unavailable` response.
    #[must_use]
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::Unavailable,
            message: message.into(),
            retry_after: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.code.status();
        let body = ErrorBody {
            code: self.code.as_str(),
            message: &self.message,
            retry_after: self.retry_after,
        };
        let mut response = (status, Json(body)).into_response();
        if let Some(secs) = self.retry_after
            && let Ok(val) = HeaderValue::from_str(&secs.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, val);
        }
        response
    }
}
