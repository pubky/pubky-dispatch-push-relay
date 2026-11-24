//! Prometheus metrics with closed, privacy-preserving label sets.
//!
//! All metric labels use fixed Rust enums rather than request-derived strings, making it
//! structurally impossible to emit device tokens, handles, push keys, or client IP addresses
//! in any metric series.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::store::Platform;

/// Histogram upper bounds in seconds for `push_relay_provider_latency_seconds`.
const LATENCY_BUCKETS_SECS: [f64; 9] = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

/// Closed outcome labels for `push_relay_webhooks_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum WebhookOutcome {
    /// Wire Format §8.3 Rule 1: invalid JSON, version, timestamp, or nonce (`400`).
    BadRequest = 0,
    /// Wire Format §8.3 Rule 2: handle unknown or expired (`404`).
    UnknownHandle = 1,
    /// Wire Format §8.3 Rule 3: missing, malformed, or invalid signature (`401`).
    BadSignature = 2,
    /// Wire Format §8.3 Rule 4: timestamp outside ±5 minutes (`401`).
    StaleTimestamp = 3,
    /// Wire Format §8.3 Rule 5: nonce already seen within 10 minutes (`409`).
    NonceReplay = 4,
    /// Wire Format §8.3 Rule 5 fail-closed: replay store full of live nonces (`503`).
    ReplayCapacityExceeded = 5,
    /// Wire Format §8.3 Rule 6: per-handle rolling minute limit exceeded (`429`).
    RateLimited = 6,
    /// Wake push accepted by upstream provider (`200`).
    Delivered = 7,
    /// Token-specific rejection from provider; handle deleted (`200`).
    Pruned = 8,
    /// Non-pruning upstream provider error or unconfigured platform (`502` / `503`).
    UpstreamFailure = 9,
    /// Upstream provider call exceeded `PROVIDER_TIMEOUT_MS` (`502`).
    ProviderTimeout = 10,
    /// Upstream provider call short-circuited due to active `Retry-After` backoff (`502`).
    ProviderBackoff = 11,
    /// Internal relay storage or serialization error (`500`).
    InternalError = 12,
}

impl WebhookOutcome {
    const ALL: [Self; 13] = [
        Self::BadRequest,
        Self::UnknownHandle,
        Self::BadSignature,
        Self::StaleTimestamp,
        Self::NonceReplay,
        Self::ReplayCapacityExceeded,
        Self::RateLimited,
        Self::Delivered,
        Self::Pruned,
        Self::UpstreamFailure,
        Self::ProviderTimeout,
        Self::ProviderBackoff,
        Self::InternalError,
    ];

    /// Fixed Prometheus label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::UnknownHandle => "unknown_handle",
            Self::BadSignature => "bad_signature",
            Self::StaleTimestamp => "stale_timestamp",
            Self::NonceReplay => "nonce_replay",
            Self::ReplayCapacityExceeded => "replay_capacity_exceeded",
            Self::RateLimited => "rate_limited",
            Self::Delivered => "delivered",
            Self::Pruned => "pruned",
            Self::UpstreamFailure => "upstream_failure",
            Self::ProviderTimeout => "provider_timeout",
            Self::ProviderBackoff => "provider_backoff",
            Self::InternalError => "internal_error",
        }
    }
}

/// Closed outcome labels for `push_relay_registrations_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum RegistrationOutcome {
    /// Fresh handle created (`200`).
    Created = 0,
    /// Idempotent re-registration returned existing active handle (`200`).
    Existing = 1,
    /// Invalid registration payload, token, or push key (`400` / `413`).
    BadRequest = 2,
    /// Per-client-IP registration rate limit exceeded (`429`).
    RateLimitedIp = 3,
    /// Per-push-key registration rate limit exceeded (`429`).
    RateLimitedKey = 4,
    /// Global registration rate limit exceeded (`429`).
    RateLimitedGlobal = 5,
    /// Per-push-key active handle cap reached (`429`).
    QuotaExceeded = 6,
    /// Global registration store capacity reached (`503`).
    CapacityExceeded = 7,
    /// Internal relay storage or RNG error (`500`).
    InternalError = 8,
}

impl RegistrationOutcome {
    const ALL: [Self; 9] = [
        Self::Created,
        Self::Existing,
        Self::BadRequest,
        Self::RateLimitedIp,
        Self::RateLimitedKey,
        Self::RateLimitedGlobal,
        Self::QuotaExceeded,
        Self::CapacityExceeded,
        Self::InternalError,
    ];

    /// Fixed Prometheus label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Existing => "existing",
            Self::BadRequest => "bad_request",
            Self::RateLimitedIp => "rate_limited_ip",
            Self::RateLimitedKey => "rate_limited_key",
            Self::RateLimitedGlobal => "rate_limited_global",
            Self::QuotaExceeded => "quota_exceeded",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::InternalError => "internal_error",
        }
    }
}

/// Closed outcome labels for `push_relay_provider_latency_seconds`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum ProviderCallOutcome {
    /// Push accepted by provider.
    Delivered = 0,
    /// Token-specific rejection caused handle pruning.
    Pruned = 1,
    /// Non-pruning provider error or auth failure.
    Error = 2,
    /// Provider call exceeded `PROVIDER_TIMEOUT_MS`.
    Timeout = 3,
    /// Provider call short-circuited during `Retry-After` backoff.
    Backoff = 4,
}

impl ProviderCallOutcome {
    const ALL: [Self; 5] = [
        Self::Delivered,
        Self::Pruned,
        Self::Error,
        Self::Timeout,
        Self::Backoff,
    ];

    /// Fixed Prometheus label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Pruned => "pruned",
            Self::Error => "error",
            Self::Timeout => "timeout",
            Self::Backoff => "backoff",
        }
    }
}

#[derive(Debug, Default)]
struct LatencyHistogram {
    /// Non-cumulative per-bucket counts (rendered cumulatively in Prometheus text format).
    buckets: [AtomicU64; LATENCY_BUCKETS_SECS.len()],
    count: AtomicU64,
    sum_micros: AtomicU64,
}

impl LatencyHistogram {
    fn observe(&self, duration: Duration) {
        let secs = duration.as_secs_f64();
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        for (i, bound) in LATENCY_BUCKETS_SECS.iter().enumerate() {
            if secs <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> ([u64; LATENCY_BUCKETS_SECS.len()], u64, f64) {
        let mut cumulative = [0u64; LATENCY_BUCKETS_SECS.len()];
        for (slot, counter) in cumulative.iter_mut().zip(self.buckets.iter()) {
            *slot = counter.load(Ordering::Relaxed);
        }
        let count = self.count.load(Ordering::Relaxed);
        #[allow(clippy::cast_precision_loss)]
        let sum_secs = self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        (cumulative, count, sum_secs)
    }
}

/// Thread-safe Prometheus metrics registry attached to [`crate::http::RelayState`].
#[derive(Debug, Default)]
pub struct RelayMetrics {
    webhooks: [AtomicU64; WebhookOutcome::ALL.len()],
    registrations: [AtomicU64; RegistrationOutcome::ALL.len()],
    provider_latency: [[LatencyHistogram; ProviderCallOutcome::ALL.len()]; 2],
}

impl RelayMetrics {
    /// Creates a zero-initialized metrics registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments `push_relay_webhooks_total{outcome=...}` by 1.
    pub fn inc_webhook(&self, outcome: WebhookOutcome) {
        self.webhooks[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `push_relay_registrations_total{outcome=...}` by 1.
    pub fn inc_registration(&self, outcome: RegistrationOutcome) {
        self.registrations[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Observes a provider delivery call duration for `(platform, outcome)`.
    pub fn observe_provider_latency(
        &self,
        platform: Platform,
        outcome: ProviderCallOutcome,
        duration: Duration,
    ) {
        let p_idx = match platform {
            Platform::Apns => 0,
            Platform::Fcm => 1,
        };
        self.provider_latency[p_idx][outcome as usize].observe(duration);
    }

    /// Reads the current webhook counter for `outcome`.
    #[must_use]
    pub fn webhook_count(&self, outcome: WebhookOutcome) -> u64 {
        self.webhooks[outcome as usize].load(Ordering::Relaxed)
    }

    /// Reads the current registration counter for `outcome`.
    #[must_use]
    pub fn registration_count(&self, outcome: RegistrationOutcome) -> u64 {
        self.registrations[outcome as usize].load(Ordering::Relaxed)
    }

    /// Renders all metrics in Prometheus text exposition format (`0.0.4`).
    #[must_use]
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(4096);

        let _ = writeln!(
            out,
            "# HELP push_relay_webhooks_total Total POST /v1/hook requests by relay outcome."
        );
        let _ = writeln!(out, "# TYPE push_relay_webhooks_total counter");
        for outcome in WebhookOutcome::ALL {
            let value = self.webhook_count(outcome);
            let _ = writeln!(
                out,
                "push_relay_webhooks_total{{outcome=\"{}\"}} {value}",
                outcome.as_str()
            );
        }

        let _ = writeln!(
            out,
            "# HELP push_relay_registrations_total Total POST /v1/register requests by outcome."
        );
        let _ = writeln!(out, "# TYPE push_relay_registrations_total counter");
        for outcome in RegistrationOutcome::ALL {
            let value = self.registration_count(outcome);
            let _ = writeln!(
                out,
                "push_relay_registrations_total{{outcome=\"{}\"}} {value}",
                outcome.as_str()
            );
        }

        let _ = writeln!(
            out,
            "# HELP push_relay_provider_latency_seconds Upstream push provider dispatch latency in seconds."
        );
        let _ = writeln!(out, "# TYPE push_relay_provider_latency_seconds histogram");
        for (p_idx, platform_label) in [(0usize, "apns"), (1usize, "fcm")] {
            for outcome in ProviderCallOutcome::ALL {
                let (buckets, count, sum_secs) =
                    self.provider_latency[p_idx][outcome as usize].snapshot();
                let outcome_label = outcome.as_str();
                for (bound, b_count) in LATENCY_BUCKETS_SECS.iter().zip(buckets.iter()) {
                    let _ = writeln!(
                        out,
                        "push_relay_provider_latency_seconds_bucket{{platform=\"{platform_label}\",outcome=\"{outcome_label}\",le=\"{bound}\"}} {b_count}"
                    );
                }
                let _ = writeln!(
                    out,
                    "push_relay_provider_latency_seconds_bucket{{platform=\"{platform_label}\",outcome=\"{outcome_label}\",le=\"+Inf\"}} {count}"
                );
                let _ = writeln!(
                    out,
                    "push_relay_provider_latency_seconds_sum{{platform=\"{platform_label}\",outcome=\"{outcome_label}\"}} {sum_secs:.6}"
                );
                let _ = writeln!(
                    out,
                    "push_relay_provider_latency_seconds_count{{platform=\"{platform_label}\",outcome=\"{outcome_label}\"}} {count}"
                );
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_valid_prometheus_text_without_dynamic_labels() {
        let metrics = RelayMetrics::new();
        metrics.inc_webhook(WebhookOutcome::Delivered);
        metrics.inc_webhook(WebhookOutcome::BadSignature);
        metrics.inc_registration(RegistrationOutcome::Created);
        metrics.observe_provider_latency(
            Platform::Apns,
            ProviderCallOutcome::Delivered,
            Duration::from_millis(42),
        );

        let text = metrics.render_prometheus();
        assert!(text.contains("push_relay_webhooks_total{outcome=\"delivered\"} 1"));
        assert!(text.contains("push_relay_webhooks_total{outcome=\"bad_signature\"} 1"));
        assert!(text.contains("push_relay_registrations_total{outcome=\"created\"} 1"));
        assert!(text.contains(
            "push_relay_provider_latency_seconds_bucket{platform=\"apns\",outcome=\"delivered\",le=\"0.05\"} 1"
        ));
        assert!(text.contains(
            "push_relay_provider_latency_seconds_bucket{platform=\"apns\",outcome=\"delivered\",le=\"0.025\"} 0"
        ));
        assert!(text.contains(
            "push_relay_provider_latency_seconds_count{platform=\"apns\",outcome=\"delivered\"} 1"
        ));
    }
}
