//! Runtime configuration and CLI/environment parsing for the push relay.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use base64::Engine as _;
use clap::{Parser, ValueEnum};
use thiserror::Error;

use crate::crypto::{SIGNATURE_HEADER, SIGNING_LABEL, normalize_relay_origin};
use crate::push::apns::{ApnsConfig, ApnsPushMode};
use crate::push::fcm::{FcmConfig, FcmServiceAccount};
use crate::rate_limit::{DEFAULT_MAX_TRACKED_HANDLES, DEFAULT_RATE_LIMIT_PER_MINUTE};
use crate::replay::DEFAULT_MAX_NONCE_ENTRIES;
use crate::store::ApnsEnv;

/// Default maximum HTTP request body size (16 KiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024;

/// Configuration validation errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// An environment variable or CLI flag contained an invalid value.
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
///
/// Defaults to the locked Pubky Dispatch constants (`Dispatch-Signature` and
/// `pubky-dispatch/v1/push`), while allowing tests to substitute other labels/headers
/// (such as historical test vectors).
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
    /// Canonical `https://<host>` origin verified in webhook signatures (Wire Format §8.2).
    pub relay_origin: String,
    /// Webhook signature header and Ed25519 signing label.
    pub protocol: ProtocolConfig,
    /// Default APNs environment when a client omits `apns_env` on `/v1/register`.
    pub default_apns_env: ApnsEnv,
    /// Maximum wake pushes permitted per handle per minute.
    pub rate_limit_per_minute: u32,
    /// Maximum entries kept in the 10-minute nonce replay cache.
    pub nonce_cache_max_entries: usize,
    /// Maximum simultaneously tracked handles in the rate limiter.
    pub rate_limit_max_handles: usize,
    /// Maximum request body size in bytes.
    pub max_body_bytes: usize,
}

impl RelaySettings {
    /// Creates validated [`RelaySettings`] with production defaults for `relay_origin`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if `relay_origin` is not a canonical
    /// `https://<host>` origin without port or path.
    pub fn new(relay_origin: &str) -> Result<Self, ConfigError> {
        let normalized = normalize_relay_origin(relay_origin)
            .map_err(|e| ConfigError::Invalid(format!("RELAY_ORIGIN: {e}")))?;
        Ok(Self {
            relay_origin: normalized,
            protocol: ProtocolConfig::dispatch(),
            default_apns_env: ApnsEnv::Production,
            rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            nonce_cache_max_entries: DEFAULT_MAX_NONCE_ENTRIES,
            rate_limit_max_handles: DEFAULT_MAX_TRACKED_HANDLES,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        })
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
    /// Structured JSON logs (recommended for production).
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
    /// Content-free silent background wake push (`apns-push-type: background`).
    #[default]
    Background,
    /// Content-free alert wake push (`apns-push-type: alert`, `mutable-content: 1`).
    Alert,
}

impl From<ApnsPushModeArg> for ApnsPushMode {
    fn from(value: ApnsPushModeArg) -> Self {
        match value {
            ApnsPushModeArg::Background => Self::Background,
            ApnsPushModeArg::Alert => Self::Alert,
        }
    }
}

/// Command-line and environment configuration for the standalone push relay binary.
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

    /// Canonical public HTTPS origin of this relay (e.g. `https://push.example.com`).
    #[arg(long, env = "RELAY_ORIGIN")]
    pub relay_origin: String,

    /// SQLite database path or URL (e.g. `./data/push-relay.sqlite` or `:memory:`).
    #[arg(long, env = "DATABASE_URL", default_value = "./data/push-relay.sqlite")]
    pub database_url: String,

    /// Maximum wake pushes per handle per minute.
    #[arg(long, env = "RATE_LIMIT_PER_MINUTE", default_value_t = DEFAULT_RATE_LIMIT_PER_MINUTE)]
    pub rate_limit_per_minute: u32,

    /// Maximum entries kept in the 10-minute nonce replay cache.
    #[arg(long, env = "NONCE_CACHE_MAX_ENTRIES", default_value_t = DEFAULT_MAX_NONCE_ENTRIES)]
    pub nonce_cache_max_entries: usize,

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

    /// Path to APNs `.p8` PKCS#8 PEM private key file.
    #[arg(long, env = "APNS_KEY_PATH")]
    pub apns_key_path: Option<PathBuf>,

    /// Inline APNs `.p8` PEM private key (raw PEM or standard base64-encoded PEM).
    #[arg(long, env = "APNS_KEY_PEM")]
    pub apns_key_pem: Option<String>,

    /// Default APNs environment when registrations omit `apns_env`.
    #[arg(long, env = "APNS_DEFAULT_ENV", value_enum, default_value_t = ApnsEnvArg::Production)]
    pub apns_default_env: ApnsEnvArg,

    /// APNs push style (`background` silent wake or `alert` mutable-content wake).
    #[arg(long, env = "APNS_PUSH_MODE", value_enum, default_value_t = ApnsPushModeArg::Background)]
    pub apns_push_mode: ApnsPushModeArg,

    /// Path to Google Cloud service account JSON file for FCM HTTP v1.
    #[arg(long, env = "FCM_SERVICE_ACCOUNT_PATH")]
    pub fcm_service_account_path: Option<PathBuf>,

    /// Inline Google service account JSON (raw JSON or standard base64-encoded JSON).
    #[arg(long, env = "FCM_SERVICE_ACCOUNT_JSON")]
    pub fcm_service_account_json: Option<String>,
}

impl std::fmt::Debug for CliArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CliArgs")
            .field("bind_addr", &self.bind_addr)
            .field("relay_origin", &self.relay_origin)
            .field("database_url", &self.database_url)
            .field("rate_limit_per_minute", &self.rate_limit_per_minute)
            .field("nonce_cache_max_entries", &self.nonce_cache_max_entries)
            .field("push_backend", &self.push_backend)
            .field("log_format", &self.log_format)
            .field("apns_configured", &self.has_any_apns_option())
            .field("fcm_configured", &self.has_any_fcm_option())
            .finish()
    }
}

impl CliArgs {
    /// Builds validated [`RelaySettings`] from CLI/environment options.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] if `relay_origin` or numeric bounds are invalid.
    pub fn to_relay_settings(&self) -> Result<RelaySettings, ConfigError> {
        if self.nonce_cache_max_entries == 0 {
            return Err(ConfigError::Invalid(
                "NONCE_CACHE_MAX_ENTRIES must be >= 1".to_owned(),
            ));
        }
        let mut settings = RelaySettings::new(&self.relay_origin)?;
        settings.default_apns_env = self.apns_default_env.into();
        settings.rate_limit_per_minute = self.rate_limit_per_minute;
        settings.nonce_cache_max_entries = self.nonce_cache_max_entries;
        Ok(settings)
    }

    /// Loads optional [`ApnsConfig`] if any APNs option is configured.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if APNs options are partially configured or the key cannot be read.
    pub fn load_apns_config(&self) -> Result<Option<ApnsConfig>, ConfigError> {
        if !self.has_any_apns_option() {
            return Ok(None);
        }

        let team_id = require_non_empty(self.apns_team_id.as_deref(), "APNS_TEAM_ID")?;
        let key_id = require_non_empty(self.apns_key_id.as_deref(), "APNS_KEY_ID")?;
        let bundle_id = require_non_empty(self.apns_bundle_id.as_deref(), "APNS_BUNDLE_ID")?;

        let pem = match (&self.apns_key_path, &self.apns_key_pem) {
            (Some(_), Some(_)) => {
                return Err(ConfigError::Invalid(
                    "set only one of APNS_KEY_PATH or APNS_KEY_PEM".to_owned(),
                ));
            }
            (Some(path), None) => read_secret_file(path)?,
            (None, Some(raw)) => decode_inline_secret(raw, "-----BEGIN")?,
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
        Ok(Some(cfg))
    }

    /// Loads optional [`FcmConfig`] if any FCM option is configured.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if credentials are malformed or cannot be read.
    pub fn load_fcm_config(&self) -> Result<Option<FcmConfig>, ConfigError> {
        if !self.has_any_fcm_option() {
            return Ok(None);
        }

        let json_text = match (
            &self.fcm_service_account_path,
            &self.fcm_service_account_json,
        ) {
            (Some(_), Some(_)) => {
                return Err(ConfigError::Invalid(
                    "set only one of FCM_SERVICE_ACCOUNT_PATH or FCM_SERVICE_ACCOUNT_JSON"
                        .to_owned(),
                ));
            }
            (Some(path), None) => read_secret_file(path)?,
            (None, Some(raw)) => decode_inline_secret(raw, "{")?,
            (None, None) => return Ok(None),
        };

        let service_account: FcmServiceAccount = serde_json::from_str(&json_text)
            .map_err(|e| ConfigError::Invalid(format!("invalid FCM service account JSON: {e}")))?;

        Ok(Some(FcmConfig::new(service_account)))
    }

    fn has_any_apns_option(&self) -> bool {
        self.apns_team_id.is_some()
            || self.apns_key_id.is_some()
            || self.apns_bundle_id.is_some()
            || self.apns_key_path.is_some()
            || self.apns_key_pem.is_some()
    }

    fn has_any_fcm_option(&self) -> bool {
        self.fcm_service_account_path.is_some() || self.fcm_service_account_json.is_some()
    }
}

fn require_non_empty(value: Option<&str>, name: &str) -> Result<String, ConfigError> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| ConfigError::Invalid(format!("{name} is required when APNs is enabled")))
}

fn read_secret_file(path: &PathBuf) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn decode_inline_secret(raw: &str, expected_prefix: &str) -> Result<String, ConfigError> {
    let trimmed = raw.trim();
    if trimmed.starts_with(expected_prefix) {
        return Ok(trimmed.to_owned());
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|_| {
            ConfigError::Invalid(
                "inline credential must be raw text or valid base64-encoded text".to_owned(),
            )
        })?;
    String::from_utf8(decoded)
        .map_err(|_| ConfigError::Invalid("decoded credential is not valid UTF-8".to_owned()))
}

impl FromStr for ApnsPushMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "background" => Ok(Self::Background),
            "alert" => Ok(Self::Alert),
            other => Err(ConfigError::Invalid(format!(
                "unknown APNS_PUSH_MODE: {other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_raw_and_base64_inline_secrets() {
        let raw_pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";
        assert_eq!(
            decode_inline_secret(raw_pem, "-----BEGIN").unwrap(),
            raw_pem
        );

        let b64_pem = base64::engine::general_purpose::STANDARD.encode(raw_pem);
        assert_eq!(
            decode_inline_secret(&b64_pem, "-----BEGIN").unwrap(),
            raw_pem
        );

        let raw_json = r#"{"project_id":"demo"}"#;
        let b64_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_json);
        assert_eq!(decode_inline_secret(&b64_json, "{").unwrap(), raw_json);
    }

    #[test]
    fn cli_args_validate_partial_apns_config_and_origin() {
        let ok = CliArgs::try_parse_from([
            "pubky-dispatch-push-relay",
            "--relay-origin",
            "https://push.example",
            "--push-backend",
            "noop",
        ])
        .unwrap();
        assert_eq!(
            ok.to_relay_settings().unwrap().relay_origin,
            "https://push.example"
        );
        assert!(ok.load_apns_config().unwrap().is_none());
        assert!(ok.load_fcm_config().unwrap().is_none());

        let partial_apns = CliArgs::try_parse_from([
            "pubky-dispatch-push-relay",
            "--relay-origin",
            "https://push.example",
            "--apns-team-id",
            "TEAM123456",
        ])
        .unwrap();
        assert!(partial_apns.load_apns_config().is_err());
    }
}
