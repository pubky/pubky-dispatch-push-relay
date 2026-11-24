//! Runtime configuration and CLI/environment parsing for the push relay.
//!
//! Secrets (`DATABASE_URL`, `APNS_KEY_PEM`, `FCM_SERVICE_ACCOUNT_JSON`) are never printed
//! in `--help`, `Debug`, or logs; inline secrets are read exclusively from environment
//! variables or permission-checked files (mode `0600` or stricter on Unix).

use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use clap::{Parser, ValueEnum};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::client_ip::{DEFAULT_TRUSTED_PROXY_HEADER, TrustedProxies};
use crate::crypto::{SIGNATURE_HEADER, SIGNING_LABEL, validate_relay_origin};
use crate::push::apns::{ApnsConfig, ApnsPushMode};
use crate::push::fcm::{FcmConfig, FcmServiceAccount};
use crate::push::{DEFAULT_PROVIDER_TIMEOUT_MS, MAX_PROVIDER_TIMEOUT_MS};
use crate::rate_limit::{DEFAULT_MAX_TRACKED_HANDLES, DEFAULT_RATE_LIMIT_PER_MINUTE};
use crate::replay::{DEFAULT_MAX_NONCE_ENTRIES, DEFAULT_MAX_NONCES_PER_HANDLE};
use crate::store::{ApnsEnv, RegistrationLimits, is_postgres_url};

/// Default SQLite database path used when `DATABASE_URL` is unset.
pub const DEFAULT_DATABASE_URL: &str = "./data/push-relay.sqlite";

/// Default maximum HTTP request body size (16 KiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024;

/// Default overall HTTP request deadline in milliseconds (4.5 s).
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 4_500;

/// Default maximum concurrent in-flight `/v1/*` HTTP requests.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 256;

/// Default per-client-IP rate limit for `POST /v1/register` (requests per minute).
pub const DEFAULT_REGISTER_IP_RATE_LIMIT_PER_MINUTE: u32 = 10;

/// Default per-push-key rate limit for `POST /v1/register` (requests per minute).
pub const DEFAULT_REGISTER_KEY_RATE_LIMIT_PER_MINUTE: u32 = 20;

/// Default global rate limit for `POST /v1/register` (requests per minute).
pub const DEFAULT_REGISTER_RATE_LIMIT_PER_MINUTE: u32 = 120;

/// Default maximum active handles allowed per `push_key` (allows OS token rotation
/// headroom beyond Dispatch's 8-handle limit without evicting active handles).
pub const DEFAULT_MAX_HANDLES_PER_PUSH_KEY: u32 = 32;

/// Default maximum total registrations stored before rejecting new registrations with `503`.
pub const DEFAULT_MAX_REGISTRATIONS: u64 = 1_000_000;

/// Default inactivity expiry for registrations that receive no valid webhooks (90 days).
pub const DEFAULT_REGISTRATION_TTL_DAYS: u64 = 90;

const MS_PER_DAY: u64 = 86_400_000;

/// Environment variable for inline APNs `.p8` PEM (never accepted as a CLI flag).
pub const ENV_APNS_KEY_PEM: &str = "APNS_KEY_PEM";

/// Environment variable for inline FCM service account JSON (never accepted as a CLI flag).
pub const ENV_FCM_SERVICE_ACCOUNT_JSON: &str = "FCM_SERVICE_ACCOUNT_JSON";

/// Configuration validation errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// An environment variable, file permission, or CLI flag failed validation.
    #[error("invalid configuration: {0}")]
    Invalid(String),
    /// Failed to read a credential file from disk.
    #[error("failed to read credential file {path}: {source}")]
    Io {
        /// Path that could not be read.
        path: String,
        /// Underlying IO error.
        source: std::io::Error,
    },
}

/// Webhook header and Ed25519 domain-separation label settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolConfig {
    /// HTTP header carrying the base64url Ed25519 signature.
    pub signature_header: String,
    /// Signing label passed as the first element of `lp(label, relay_origin, body)`.
    pub signing_label: String,
}

impl ProtocolConfig {
    /// Returns the default Pubky Dispatch protocol configuration.
    #[must_use]
    pub fn dispatch() -> Self {
        Self {
            signature_header: SIGNATURE_HEADER.to_owned(),
            signing_label: SIGNING_LABEL.to_owned(),
        }
    }

    /// Creates a custom protocol configuration (primarily for vector/interoperability tests).
    #[must_use]
    pub fn custom(signature_header: impl Into<String>, signing_label: impl Into<String>) -> Self {
        Self {
            signature_header: signature_header.into(),
            signing_label: signing_label.into(),
        }
    }
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self::dispatch()
    }
}

/// Core runtime settings consumed by the HTTP service layer.
#[derive(Clone, Debug)]
pub struct RelaySettings {
    /// Exact `https://<host>` origin verified in webhook signatures (preserving host case,
    /// matching Wire Format §8.2 `relay_origin`).
    pub relay_origin: String,
    /// Webhook signature header and Ed25519 signing label.
    pub protocol: ProtocolConfig,
    /// Default APNs environment when a client omits `apns_env` on `/v1/register`.
    pub default_apns_env: ApnsEnv,
    /// Maximum wake pushes permitted per handle per minute.
    pub rate_limit_per_minute: u32,
    /// Maximum `POST /v1/register` requests per client IP per minute.
    pub register_ip_rate_limit_per_minute: u32,
    /// Maximum `POST /v1/register` requests per `push_key` per minute.
    pub register_key_rate_limit_per_minute: u32,
    /// Global maximum `POST /v1/register` requests permitted per minute.
    pub register_rate_limit_per_minute: u32,
    /// Maximum active handles bound to a single `push_key`.
    pub max_handles_per_push_key: u32,
    /// Maximum total active registrations retained in storage before returning `503`.
    pub max_registrations: u64,
    /// Inactivity expiry duration in milliseconds (default 90 days).
    pub registration_ttl_ms: u64,
    /// Maximum live nonces retained globally in replay storage (refuses new webhooks with `503` when full).
    pub nonce_cache_max_entries: usize,
    /// Maximum live nonces a single handle may hold simultaneously inside the 10-minute window.
    pub max_nonces_per_handle: usize,
    /// Maximum simultaneously tracked keys in in-memory rate limiters.
    pub rate_limit_max_handles: usize,
    /// Maximum HTTP request body size in bytes (16 KiB).
    pub max_body_bytes: usize,
    /// Deadline for upstream push delivery (strictly below Dispatch's 5-second timeout).
    pub provider_timeout: Duration,
    /// Overall deadline for handling an HTTP request (including body reads).
    pub request_timeout: Duration,
    /// Maximum concurrent in-flight `/v1/*` requests before shedding with `503`.
    pub max_concurrent_requests: usize,
    /// Trusted reverse-proxy CIDRs permitted to supply forwarded client IP headers.
    pub trusted_proxies: TrustedProxies,
    /// Forwarded header inspected when the TCP peer is in `trusted_proxies`.
    pub trusted_proxy_header: String,
}

impl RelaySettings {
    /// Creates validated [`RelaySettings`] with default limits for `relay_origin`.
    ///
    /// Preserves exact host casing per Wire Format §8.2.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if `relay_origin` is not a bare `https://<host>`.
    pub fn new(relay_origin: &str) -> Result<Self, ConfigError> {
        let validated = validate_relay_origin(relay_origin)
            .map_err(|e| ConfigError::Invalid(format!("RELAY_ORIGIN: {e}")))?;
        Ok(Self {
            relay_origin: validated,
            protocol: ProtocolConfig::dispatch(),
            default_apns_env: ApnsEnv::Production,
            rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            register_ip_rate_limit_per_minute: DEFAULT_REGISTER_IP_RATE_LIMIT_PER_MINUTE,
            register_key_rate_limit_per_minute: DEFAULT_REGISTER_KEY_RATE_LIMIT_PER_MINUTE,
            register_rate_limit_per_minute: DEFAULT_REGISTER_RATE_LIMIT_PER_MINUTE,
            max_handles_per_push_key: DEFAULT_MAX_HANDLES_PER_PUSH_KEY,
            max_registrations: DEFAULT_MAX_REGISTRATIONS,
            registration_ttl_ms: DEFAULT_REGISTRATION_TTL_DAYS * MS_PER_DAY,
            nonce_cache_max_entries: DEFAULT_MAX_NONCE_ENTRIES,
            max_nonces_per_handle: DEFAULT_MAX_NONCES_PER_HANDLE,
            rate_limit_max_handles: DEFAULT_MAX_TRACKED_HANDLES,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            provider_timeout: Duration::from_millis(DEFAULT_PROVIDER_TIMEOUT_MS),
            request_timeout: Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS),
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            trusted_proxies: TrustedProxies::none(),
            trusted_proxy_header: DEFAULT_TRUSTED_PROXY_HEADER.to_owned(),
        })
    }

    /// Returns the atomic [`RegistrationLimits`] derived from these settings.
    #[must_use]
    pub const fn registration_limits(&self) -> RegistrationLimits {
        RegistrationLimits {
            max_registrations: self.max_registrations,
            max_handles_per_push_key: self.max_handles_per_push_key,
            ttl_ms: self.registration_ttl_ms,
        }
    }
}

/// Push delivery mode selected at startup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum PushBackendMode {
    /// Use configured APNs and/or FCM providers (requires at least one provider).
    #[default]
    Providers,
    /// Use the no-op sender for local development without mobile credentials.
    Noop,
}

/// Log output format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    /// Structured JSON logs.
    #[default]
    Json,
    /// Human-readable logs for local development.
    Pretty,
}

/// APNs default environment CLI/env value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum ApnsEnvArg {
    /// Apple production gateway (`api.push.apple.com`).
    #[default]
    Production,
    /// Apple sandbox gateway (`api.sandbox.push.apple.com`).
    Sandbox,
}

impl From<ApnsEnvArg> for ApnsEnv {
    fn from(value: ApnsEnvArg) -> Self {
        match value {
            ApnsEnvArg::Production => Self::Production,
            ApnsEnvArg::Sandbox => Self::Sandbox,
        }
    }
}

/// APNs delivery mode CLI/env value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum ApnsPushModeArg {
    /// Content-free generic visible notification (`apns-push-type: alert`,
    /// `mutable-content: 1`, Spec §9 default).
    #[default]
    Alert,
    /// Opt-in silent background wake push (`apns-push-type: background`; throttled by iOS).
    Background,
}

impl From<ApnsPushModeArg> for ApnsPushMode {
    fn from(value: ApnsPushModeArg) -> Self {
        match value {
            ApnsPushModeArg::Alert => Self::Alert,
            ApnsPushModeArg::Background => Self::Background,
        }
    }
}

/// Command-line and environment configuration for the standalone push relay binary.
///
/// Inline credential secrets (`APNS_KEY_PEM`, `FCM_SERVICE_ACCOUNT_JSON`) are read only
/// from environment variables so they cannot appear in `--help` or process command lines.
#[derive(Clone, Parser)]
#[command(
    name = "pubky-dispatch-push-relay",
    version,
    about = "Standalone reference push notification relay for Pubky Dispatch"
)]
pub struct CliArgs {
    /// Socket address to bind the HTTP server on.
    #[arg(long, env = "RELAY_BIND_ADDR", default_value = "0.0.0.0:8080")]
    pub bind_addr: SocketAddr,

    /// Optional separate socket address for the Prometheus `/metrics` endpoint
    /// (for example `127.0.0.1:9090`). When unset, `/metrics` is not exposed.
    #[arg(long, env = "METRICS_BIND_ADDR")]
    pub metrics_bind_addr: Option<SocketAddr>,

    /// Exact public HTTPS origin of this relay (e.g. `https://push.example.com`).
    #[arg(long, env = "RELAY_ORIGIN")]
    pub relay_origin: String,

    /// Database path or connection URL (`postgres://` / `postgresql://` selects
    /// PostgreSQL; otherwise SQLite). Defaults to `./data/push-relay.sqlite` when unset.
    #[arg(
        long,
        env = "DATABASE_URL",
        hide_env_values = true,
        hide_default_value = true
    )]
    database_url: Option<String>,

    /// Maximum wake pushes per handle per minute.
    #[arg(long, env = "RATE_LIMIT_PER_MINUTE", default_value_t = DEFAULT_RATE_LIMIT_PER_MINUTE)]
    pub rate_limit_per_minute: u32,

    /// Maximum `POST /v1/register` requests per client IP per minute.
    #[arg(
        long,
        env = "REGISTER_IP_RATE_LIMIT_PER_MINUTE",
        default_value_t = DEFAULT_REGISTER_IP_RATE_LIMIT_PER_MINUTE
    )]
    pub register_ip_rate_limit_per_minute: u32,

    /// Maximum `POST /v1/register` requests per push key per minute.
    #[arg(
        long,
        env = "REGISTER_KEY_RATE_LIMIT_PER_MINUTE",
        default_value_t = DEFAULT_REGISTER_KEY_RATE_LIMIT_PER_MINUTE
    )]
    pub register_key_rate_limit_per_minute: u32,

    /// Global maximum `POST /v1/register` requests per minute.
    #[arg(
        long,
        env = "REGISTER_RATE_LIMIT_PER_MINUTE",
        default_value_t = DEFAULT_REGISTER_RATE_LIMIT_PER_MINUTE
    )]
    pub register_rate_limit_per_minute: u32,

    /// Maximum active handles allowed per push key.
    #[arg(
        long,
        env = "MAX_HANDLES_PER_PUSH_KEY",
        default_value_t = DEFAULT_MAX_HANDLES_PER_PUSH_KEY
    )]
    pub max_handles_per_push_key: u32,

    /// Maximum total active registrations stored before rejecting new registrations with `503`.
    #[arg(
        long,
        env = "MAX_REGISTRATIONS",
        default_value_t = DEFAULT_MAX_REGISTRATIONS
    )]
    pub max_registrations: u64,

    /// Days of webhook inactivity before a registration expires.
    #[arg(
        long,
        env = "REGISTRATION_TTL_DAYS",
        default_value_t = DEFAULT_REGISTRATION_TTL_DAYS
    )]
    pub registration_ttl_days: u64,

    /// Maximum live nonces retained globally in replay storage (refuses new webhooks with `503` when full).
    #[arg(long, env = "NONCE_CACHE_MAX_ENTRIES", default_value_t = DEFAULT_MAX_NONCE_ENTRIES)]
    pub nonce_cache_max_entries: usize,

    /// Maximum live nonces a single handle may retain inside the 10-minute replay window.
    #[arg(
        long,
        env = "MAX_NONCES_PER_HANDLE",
        default_value_t = DEFAULT_MAX_NONCES_PER_HANDLE
    )]
    pub max_nonces_per_handle: usize,

    /// Upstream provider timeout in milliseconds (100..=4500, below Dispatch's 5 s timeout).
    #[arg(long, env = "PROVIDER_TIMEOUT_MS", default_value_t = DEFAULT_PROVIDER_TIMEOUT_MS)]
    pub provider_timeout_ms: u64,

    /// Overall HTTP request deadline in milliseconds (slow-client protection).
    #[arg(long, env = "REQUEST_TIMEOUT_MS", default_value_t = DEFAULT_REQUEST_TIMEOUT_MS)]
    pub request_timeout_ms: u64,

    /// Maximum concurrent in-flight `/v1/*` requests before shedding with `503`.
    #[arg(
        long,
        env = "MAX_CONCURRENT_REQUESTS",
        default_value_t = DEFAULT_MAX_CONCURRENT_REQUESTS
    )]
    pub max_concurrent_requests: usize,

    /// Comma-separated trusted reverse-proxy CIDRs or IPs (empty = trust no forwarded headers).
    #[arg(long, env = "TRUSTED_PROXIES", default_value = "")]
    pub trusted_proxies: String,

    /// Forwarded client IP header name honoured only from `TRUSTED_PROXIES`.
    #[arg(
        long,
        env = "TRUSTED_PROXY_HEADER",
        default_value = DEFAULT_TRUSTED_PROXY_HEADER
    )]
    pub trusted_proxy_header: String,

    /// Push delivery backend mode (`providers` or `noop`).
    #[arg(long, env = "PUSH_BACKEND", value_enum, default_value_t = PushBackendMode::Providers)]
    pub push_backend: PushBackendMode,

    /// Log output format (`json` or `pretty`).
    #[arg(long, env = "LOG_FORMAT", value_enum, default_value_t = LogFormat::Json)]
    pub log_format: LogFormat,

    /// Apple Developer Team ID (10 characters) for APNs JWT signing.
    #[arg(long, env = "APNS_TEAM_ID")]
    pub apns_team_id: Option<String>,

    /// APNs Auth Key ID (10 characters) for ES256 JWT `kid` header.
    #[arg(long, env = "APNS_KEY_ID")]
    pub apns_key_id: Option<String>,

    /// Apple app bundle identifier used as `apns-topic`.
    #[arg(long, env = "APNS_BUNDLE_ID")]
    pub apns_bundle_id: Option<String>,

    /// Path to APNs `.p8` PKCS#8 PEM private key file (must not be group/world-accessible).
    #[arg(long, env = "APNS_KEY_PATH", hide_env_values = true)]
    pub apns_key_path: Option<PathBuf>,

    /// Default APNs environment when registrations omit `apns_env`.
    #[arg(long, env = "APNS_DEFAULT_ENV", value_enum, default_value_t = ApnsEnvArg::Production)]
    pub apns_default_env: ApnsEnvArg,

    /// APNs push style (`alert` visible notification default, or `background` silent wake).
    #[arg(long, env = "APNS_PUSH_MODE", value_enum, default_value_t = ApnsPushModeArg::Alert)]
    pub apns_push_mode: ApnsPushModeArg,

    /// Path to Google Cloud service account JSON file (must not be group/world-accessible).
    #[arg(long, env = "FCM_SERVICE_ACCOUNT_PATH", hide_env_values = true)]
    pub fcm_service_account_path: Option<PathBuf>,
}

impl Drop for CliArgs {
    fn drop(&mut self) {
        if let Some(url) = &mut self.database_url {
            zeroize::Zeroize::zeroize(url);
        }
    }
}

impl std::fmt::Debug for CliArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let db_backend = match self.database_url.as_deref() {
            Some(url) if is_postgres_url(url) => "postgres://<redacted>",
            _ => "<sqlite>",
        };
        f.debug_struct("CliArgs")
            .field("bind_addr", &self.bind_addr)
            .field("metrics_bind_addr", &self.metrics_bind_addr)
            .field("relay_origin", &self.relay_origin)
            .field("database_url", &db_backend)
            .field("rate_limit_per_minute", &self.rate_limit_per_minute)
            .field(
                "register_ip_rate_limit_per_minute",
                &self.register_ip_rate_limit_per_minute,
            )
            .field(
                "register_key_rate_limit_per_minute",
                &self.register_key_rate_limit_per_minute,
            )
            .field(
                "register_rate_limit_per_minute",
                &self.register_rate_limit_per_minute,
            )
            .field("max_handles_per_push_key", &self.max_handles_per_push_key)
            .field("max_registrations", &self.max_registrations)
            .field("registration_ttl_days", &self.registration_ttl_days)
            .field("nonce_cache_max_entries", &self.nonce_cache_max_entries)
            .field("max_nonces_per_handle", &self.max_nonces_per_handle)
            .field("provider_timeout_ms", &self.provider_timeout_ms)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("push_backend", &self.push_backend)
            .field("log_format", &self.log_format)
            .field("apns_configured", &self.has_any_apns_option())
            .field("fcm_configured", &self.has_any_fcm_option())
            .finish()
    }
}

impl CliArgs {
    /// Returns the resolved database URL/path wrapped in [`Zeroizing`] so connection
    /// strings containing passwords are scrubbed on drop.
    #[must_use]
    pub fn database_url(&self) -> Zeroizing<String> {
        Zeroizing::new(
            self.database_url
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(DEFAULT_DATABASE_URL)
                .to_owned(),
        )
    }

    /// Builds validated [`RelaySettings`] from CLI/environment options.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if `relay_origin`, timeouts, CIDRs, or bounds are invalid.
    pub fn to_relay_settings(&self) -> Result<RelaySettings, ConfigError> {
        if self.nonce_cache_max_entries == 0 {
            return Err(ConfigError::Invalid(
                "NONCE_CACHE_MAX_ENTRIES must be >= 1".to_owned(),
            ));
        }
        if self.max_nonces_per_handle == 0 {
            return Err(ConfigError::Invalid(
                "MAX_NONCES_PER_HANDLE must be >= 1".to_owned(),
            ));
        }
        if self.max_nonces_per_handle > self.nonce_cache_max_entries {
            return Err(ConfigError::Invalid(
                "MAX_NONCES_PER_HANDLE must be <= NONCE_CACHE_MAX_ENTRIES".to_owned(),
            ));
        }
        if self.registration_ttl_days == 0 {
            return Err(ConfigError::Invalid(
                "REGISTRATION_TTL_DAYS must be >= 1".to_owned(),
            ));
        }
        if self.provider_timeout_ms < 100 || self.provider_timeout_ms > MAX_PROVIDER_TIMEOUT_MS {
            return Err(ConfigError::Invalid(format!(
                "PROVIDER_TIMEOUT_MS must be between 100 and {MAX_PROVIDER_TIMEOUT_MS} (below Dispatch's 5000 ms timeout)"
            )));
        }
        if self.request_timeout_ms < 100 {
            return Err(ConfigError::Invalid(
                "REQUEST_TIMEOUT_MS must be >= 100".to_owned(),
            ));
        }
        if self.max_concurrent_requests == 0 {
            return Err(ConfigError::Invalid(
                "MAX_CONCURRENT_REQUESTS must be >= 1".to_owned(),
            ));
        }
        let trusted_proxies =
            TrustedProxies::parse_csv(&self.trusted_proxies).map_err(ConfigError::Invalid)?;
        let header = self.trusted_proxy_header.trim().to_ascii_lowercase();
        if header.is_empty() || axum::http::HeaderName::from_bytes(header.as_bytes()).is_err() {
            return Err(ConfigError::Invalid(
                "TRUSTED_PROXY_HEADER must be a valid HTTP header name".to_owned(),
            ));
        }

        let mut settings = RelaySettings::new(&self.relay_origin)?;
        settings.default_apns_env = self.apns_default_env.into();
        settings.rate_limit_per_minute = self.rate_limit_per_minute;
        settings.register_ip_rate_limit_per_minute = self.register_ip_rate_limit_per_minute;
        settings.register_key_rate_limit_per_minute = self.register_key_rate_limit_per_minute;
        settings.register_rate_limit_per_minute = self.register_rate_limit_per_minute;
        settings.max_handles_per_push_key = self.max_handles_per_push_key;
        settings.max_registrations = self.max_registrations;
        settings.registration_ttl_ms = self.registration_ttl_days.saturating_mul(MS_PER_DAY);
        settings.nonce_cache_max_entries = self.nonce_cache_max_entries;
        settings.max_nonces_per_handle = self.max_nonces_per_handle;
        settings.provider_timeout = Duration::from_millis(self.provider_timeout_ms);
        settings.request_timeout = Duration::from_millis(self.request_timeout_ms);
        settings.max_concurrent_requests = self.max_concurrent_requests;
        settings.trusted_proxies = trusted_proxies;
        settings.trusted_proxy_header = header;
        Ok(settings)
    }

    /// Loads optional [`ApnsConfig`] from CLI options, file path, or `APNS_KEY_PEM` env var.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if APNs options are partially configured, file permissions are
    /// overly permissive, or the key cannot be read.
    pub fn load_apns_config(&self) -> Result<Option<ApnsConfig>, ConfigError> {
        let env_pem = read_secret_env(ENV_APNS_KEY_PEM);
        if !self.has_any_apns_option() && env_pem.is_none() {
            return Ok(None);
        }

        let team_id = require_non_empty(self.apns_team_id.as_deref(), "APNS_TEAM_ID")?;
        let key_id = require_non_empty(self.apns_key_id.as_deref(), "APNS_KEY_ID")?;
        let bundle_id = require_non_empty(self.apns_bundle_id.as_deref(), "APNS_BUNDLE_ID")?;

        let pem = match (&self.apns_key_path, env_pem) {
            (Some(_), Some(_)) => {
                return Err(ConfigError::Invalid(
                    "set only one of APNS_KEY_PATH or APNS_KEY_PEM".to_owned(),
                ));
            }
            (Some(path), None) => read_secret_file(path)?,
            (None, Some(raw)) => decode_inline_secret(&raw, "-----BEGIN")?,
            (None, None) => {
                return Err(ConfigError::Invalid(
                    "APNs requires APNS_KEY_PATH or APNS_KEY_PEM".to_owned(),
                ));
            }
        };

        let mut cfg = ApnsConfig::new(
            team_id,
            key_id,
            bundle_id,
            pem,
            self.apns_default_env.into(),
        );
        cfg.push_mode = self.apns_push_mode.into();
        cfg.timeout = Duration::from_millis(self.provider_timeout_ms);
        Ok(Some(cfg))
    }

    /// Loads optional [`FcmConfig`] from file path or `FCM_SERVICE_ACCOUNT_JSON` env var.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if credentials are malformed, file permissions are overly
    /// permissive, or the file cannot be read.
    pub fn load_fcm_config(&self) -> Result<Option<FcmConfig>, ConfigError> {
        let env_json = read_secret_env(ENV_FCM_SERVICE_ACCOUNT_JSON);
        if !self.has_any_fcm_option() && env_json.is_none() {
            return Ok(None);
        }

        let json_text = match (&self.fcm_service_account_path, env_json) {
            (Some(_), Some(_)) => {
                return Err(ConfigError::Invalid(
                    "set only one of FCM_SERVICE_ACCOUNT_PATH or FCM_SERVICE_ACCOUNT_JSON"
                        .to_owned(),
                ));
            }
            (Some(path), None) => read_secret_file(path)?,
            (None, Some(raw)) => decode_inline_secret(&raw, "{")?,
            (None, None) => return Ok(None),
        };

        let service_account: FcmServiceAccount = serde_json::from_str(json_text.as_str())
            .map_err(|_| ConfigError::Invalid("invalid FCM service account JSON".to_owned()))?;

        let mut cfg = FcmConfig::new(service_account);
        cfg.timeout = Duration::from_millis(self.provider_timeout_ms);
        Ok(Some(cfg))
    }

    fn has_any_apns_option(&self) -> bool {
        self.apns_team_id.is_some()
            || self.apns_key_id.is_some()
            || self.apns_bundle_id.is_some()
            || self.apns_key_path.is_some()
    }

    fn has_any_fcm_option(&self) -> bool {
        self.fcm_service_account_path.is_some()
    }
}

fn require_non_empty(value: Option<&str>, name: &str) -> Result<String, ConfigError> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| ConfigError::Invalid(format!("{name} is required when APNs is enabled")))
}

fn read_secret_env(name: &str) -> Option<Zeroizing<String>> {
    std::env::var(name)
        .ok()
        .map(Zeroizing::new)
        .filter(|v| !v.trim().is_empty())
}

/// Reads a credential file into a [`Zeroizing<String>`], refusing files readable,
/// writable, or executable by group or others (`mode & 0o077 != 0`) on Unix.
///
/// # Errors
///
/// Returns [`ConfigError::Io`] on read errors or [`ConfigError::Invalid`] if permissions
/// are too broad.
pub fn read_secret_file(path: &Path) -> Result<Zeroizing<String>, ConfigError> {
    let mut file = std::fs::File::open(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = file.metadata().map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ConfigError::Invalid(format!(
                "credential file {} has permissive mode {mode:04o}; restrict permissions (for example `chmod 0600`)",
                path.display()
            )));
        }
    }

    let mut content = Zeroizing::new(String::new());
    file.read_to_string(&mut content)
        .map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
    Ok(content)
}

fn decode_inline_secret(
    raw: &Zeroizing<String>,
    expected_prefix: &str,
) -> Result<Zeroizing<String>, ConfigError> {
    let trimmed = raw.trim();
    if trimmed.starts_with(expected_prefix) {
        return Ok(Zeroizing::new(trimmed.to_owned()));
    }
    let mut decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
            .map_err(|_| {
                ConfigError::Invalid(
                    "inline credential must be raw text or valid base64-encoded text".to_owned(),
                )
            })?,
    );
    let bytes = std::mem::take(&mut *decoded);
    let text = String::from_utf8(bytes).map_err(|err| {
        let mut raw_bytes = err.into_bytes();
        zeroize::Zeroize::zeroize(&mut raw_bytes);
        ConfigError::Invalid("decoded credential is not valid UTF-8".to_owned())
    })?;
    Ok(Zeroizing::new(text))
}

impl FromStr for ApnsPushMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "alert" => Ok(Self::Alert),
            "background" => Ok(Self::Background),
            other => Err(ConfigError::Invalid(format!(
                "unknown APNS_PUSH_MODE: {other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn decodes_raw_and_base64_inline_secrets_into_zeroizing() {
        let raw_pem = Zeroizing::new(
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----".to_owned(),
        );
        assert_eq!(
            decode_inline_secret(&raw_pem, "-----BEGIN")
                .unwrap()
                .as_str(),
            raw_pem.as_str()
        );

        let b64_pem =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(raw_pem.as_str()));
        assert_eq!(
            decode_inline_secret(&b64_pem, "-----BEGIN")
                .unwrap()
                .as_str(),
            raw_pem.as_str()
        );

        let raw_json = r#"{"project_id":"demo"}"#;
        let b64_json =
            Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_json));
        assert_eq!(
            decode_inline_secret(&b64_json, "{").unwrap().as_str(),
            raw_json
        );
    }

    #[test]
    fn cli_help_never_prints_database_url_or_inline_secret_values() {
        let mut cmd = CliArgs::command();
        // Directly verify clap's redaction attributes so removing `hide_env_values` or
        // `hide_default_value` immediately fails even in a clean test environment.
        for id in ["database_url", "apns_key_path", "fcm_service_account_path"] {
            let arg = cmd
                .get_arguments()
                .find(|a| a.get_id().as_str() == id)
                .unwrap_or_else(|| panic!("expected CLI argument {id}"));
            assert!(
                arg.is_hide_env_values_set(),
                "CLI argument {id} must set hide_env_values = true"
            );
        }
        let db_arg = cmd
            .get_arguments()
            .find(|a| a.get_id().as_str() == "database_url")
            .unwrap();
        assert!(
            db_arg.is_hide_default_value_set(),
            "database_url must set hide_default_value = true"
        );

        let help = cmd.render_long_help().to_string();
        // Inline secret flags must not exist as CLI flags at all.
        assert!(!help.contains("--apns-key-pem"));
        assert!(!help.contains("--fcm-service-account-json"));
        // Default database path must not be printed by clap default_value.
        assert!(!help.contains("[default: ./data/push-relay.sqlite]"));
        // APNs mode defaults to alert (Spec §9).
        assert!(help.contains("[default: alert]"));
    }

    #[test]
    fn cli_args_validate_limits_timeouts_and_redact_postgres_password() {
        let ok = CliArgs::try_parse_from([
            "pubky-dispatch-push-relay",
            "--relay-origin",
            "https://Push.Example",
            "--push-backend",
            "noop",
            "--register-ip-rate-limit-per-minute",
            "15",
            "--register-key-rate-limit-per-minute",
            "25",
            "--register-rate-limit-per-minute",
            "250",
            "--max-handles-per-push-key",
            "32",
            "--max-registrations",
            "50000",
            "--registration-ttl-days",
            "90",
            "--provider-timeout-ms",
            "3000",
            "--trusted-proxies",
            "127.0.0.1,10.0.0.0/8",
        ])
        .unwrap();
        let settings = ok.to_relay_settings().unwrap();
        assert_eq!(settings.relay_origin, "https://Push.Example");
        assert_eq!(settings.register_ip_rate_limit_per_minute, 15);
        assert_eq!(settings.register_key_rate_limit_per_minute, 25);
        assert_eq!(settings.register_rate_limit_per_minute, 250);
        assert_eq!(settings.max_handles_per_push_key, 32);
        assert_eq!(settings.max_registrations, 50_000);
        assert_eq!(settings.provider_timeout, Duration::from_millis(3000));
        assert_eq!(ok.apns_push_mode, ApnsPushModeArg::Alert);

        // Per-handle nonce cap must not exceed global nonce cache cap.
        let bad_nonce_cap = CliArgs::try_parse_from([
            "pubky-dispatch-push-relay",
            "--relay-origin",
            "https://push.example",
            "--nonce-cache-max-entries",
            "100",
            "--max-nonces-per-handle",
            "101",
        ])
        .unwrap();
        assert!(bad_nonce_cap.to_relay_settings().is_err());

        // Provider timeout above 4500 ms is rejected (must stay below Dispatch's 5 s timeout).
        let bad_timeout = CliArgs::try_parse_from([
            "pubky-dispatch-push-relay",
            "--relay-origin",
            "https://push.example",
            "--provider-timeout-ms",
            "5000",
        ])
        .unwrap();
        assert!(bad_timeout.to_relay_settings().is_err());

        let pg_cli = CliArgs::try_parse_from([
            "pubky-dispatch-push-relay",
            "--relay-origin",
            "https://push.example",
            "--database-url",
            "postgres://relay:super_secret_pw@db.internal:5432/push",
        ])
        .unwrap();
        let debug = format!("{pg_cli:?}");
        assert!(!debug.contains("super_secret_pw"));
        assert!(debug.contains("postgres://<redacted>"));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_group_or_world_accessible_credential_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("key.p8");
        std::fs::write(
            &secret_path,
            "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
        )
        .unwrap();

        for bad_mode in [0o644, 0o640, 0o604, 0o660] {
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(bad_mode))
                .unwrap();
            let err = read_secret_file(&secret_path).unwrap_err();
            assert!(
                matches!(err, ConfigError::Invalid(_)),
                "mode {bad_mode:04o} must be rejected"
            );
        }

        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let loaded = read_secret_file(&secret_path).unwrap();
        assert!(loaded.starts_with("-----BEGIN PRIVATE KEY-----"));
    }
}
