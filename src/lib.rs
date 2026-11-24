//! Standalone reference push notification relay for Pubky Dispatch.
//!
//! This service decouples mobile push delivery (APNs and FCM) from Pubky identities:
//!
//! - Clients register a device token together with a registration's Ed25519 `push_key`
//!   at `POST /v1/register` and receive a cryptographically random opaque handle.
//! - The Pubky Dispatch server invokes `POST /v1/hook` with only the handle, timestamp,
//!   nonce, and an Ed25519 signature over `lp(label, relay_origin, raw_body)`.
//! - After enforcing all six Wire Format §8.3 verification rules, the relay dispatches a
//!   content-free wake push to APNs or FCM and deletes handles only on token-specific
//!   provider rejections.

#![forbid(unsafe_code)]

pub mod client_ip;
pub mod clock;
pub mod config;
pub mod crypto;
pub mod error;
pub mod http;
pub mod json;
pub mod metrics;
pub mod push;
pub mod rate_limit;
pub mod replay;
pub mod store;
pub mod time;

pub use config::{ProtocolConfig, RelaySettings};
pub use crypto::{SIGNATURE_HEADER, SIGNING_LABEL};
pub use http::{RateLimitBackends, RelayState, metrics_router, router};
