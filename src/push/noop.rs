//! No-op and recording mock [`PushSender`] implementations for local dev and tests.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

use crate::push::{PushError, PushOutcome, PushSender, UpstreamErrorClass};
use crate::store::{ApnsEnv, BoxFuture, Platform, Registration};

/// No-op push sender for local development without Apple/Google credentials.
///
/// Logs push dispatch metadata (platform only; never device tokens or handles) at
/// `debug` level and reports [`PushOutcome::Delivered`].
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSender;

impl PushSender for NoopSender {
    fn send_wake<'a>(
        &'a self,
        registration: &'a Registration,
    ) -> BoxFuture<'a, Result<PushOutcome, PushError>> {
        let platform = registration.platform;
        Box::pin(async move {
            tracing::debug!(platform = %platform, "noop push sender accepted wake push");
            Ok(PushOutcome::Delivered)
        })
    }
}

/// Captured wake push dispatch recorded by [`RecordingSender`].
///
/// Sensitive fields (`handle`, `device_token`) are redacted in [`fmt::Debug`].
#[derive(Clone, PartialEq, Eq)]
pub struct RecordedPush {
    /// Handle that triggered the push.
    pub handle: String,
    /// Target mobile platform.
    pub platform: Platform,
    /// Target device token.
    pub device_token: String,
    /// Optional APNs environment.
    pub apns_env: Option<ApnsEnv>,
}

impl fmt::Debug for RecordedPush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordedPush")
            .field("handle", &"<redacted>")
            .field("platform", &self.platform)
            .field("device_token", &"<redacted>")
            .field("apns_env", &self.apns_env)
            .finish()
    }
}

enum ScriptedResponse {
    Outcome(PushOutcome),
    Upstream(UpstreamErrorClass),
    Delayed(Duration, PushOutcome),
}

/// Scriptable mock [`PushSender`] for tests.
pub struct RecordingSender {
    recorded: Mutex<Vec<RecordedPush>>,
    scripted: Mutex<VecDeque<ScriptedResponse>>,
    ready: AtomicBool,
}

impl Default for RecordingSender {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RecordingSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingSender")
            .field("recorded_count", &self.recorded.lock().len())
            .field("ready", &self.ready.load(Ordering::Relaxed))
            .finish()
    }
}

impl RecordingSender {
    /// Creates a new [`RecordingSender`] that defaults to [`PushOutcome::Delivered`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            recorded: Mutex::new(Vec::new()),
            scripted: Mutex::new(VecDeque::new()),
            ready: AtomicBool::new(true),
        }
    }

    /// Sets whether [`PushSender::check_ready`] reports this mock provider as healthy.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Relaxed);
    }

    /// Enqueues an explicit [`PushOutcome`] for the next `send_wake` call.
    pub fn enqueue_outcome(&self, outcome: PushOutcome) {
        self.scripted
            .lock()
            .push_back(ScriptedResponse::Outcome(outcome));
    }

    /// Enqueues an upstream error class for the next `send_wake` call.
    pub fn enqueue_upstream_error(&self, class: UpstreamErrorClass) {
        self.scripted
            .lock()
            .push_back(ScriptedResponse::Upstream(class));
    }

    /// Enqueues a delayed response for testing provider timeout bounding.
    pub fn enqueue_delayed_outcome(&self, delay: Duration, outcome: PushOutcome) {
        self.scripted
            .lock()
            .push_back(ScriptedResponse::Delayed(delay, outcome));
    }

    /// Returns a snapshot of all recorded wake dispatches.
    #[must_use]
    pub fn recorded(&self) -> Vec<RecordedPush> {
        self.recorded.lock().clone()
    }
}

impl PushSender for RecordingSender {
    fn send_wake<'a>(
        &'a self,
        registration: &'a Registration,
    ) -> BoxFuture<'a, Result<PushOutcome, PushError>> {
        Box::pin(async move {
            self.recorded.lock().push(RecordedPush {
                handle: registration.handle.clone(),
                platform: registration.platform,
                device_token: registration.device_token.clone(),
                apns_env: registration.apns_env,
            });
            let next = self.scripted.lock().pop_front();
            match next {
                Some(ScriptedResponse::Outcome(outcome)) => Ok(outcome),
                Some(ScriptedResponse::Upstream(class)) => Err(PushError::Upstream {
                    class,
                    status: None,
                }),
                Some(ScriptedResponse::Delayed(delay, outcome)) => {
                    tokio::time::sleep(delay).await;
                    Ok(outcome)
                }
                None => Ok(PushOutcome::Delivered),
            }
        })
    }

    fn check_ready(&self) -> BoxFuture<'_, Result<(), PushError>> {
        let ready = self.ready.load(Ordering::Relaxed);
        Box::pin(async move {
            if ready {
                Ok(())
            } else {
                Err(PushError::Auth {
                    class: UpstreamErrorClass::Auth,
                })
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_push_debug_redacts_handle_and_device_token() {
        let recorded = RecordedPush {
            handle: "secret-handle-xyz".to_owned(),
            platform: Platform::Fcm,
            device_token: "secret-fcm-device-token-999".to_owned(),
            apns_env: None,
        };
        let shown = format!("{recorded:?}");
        assert!(!shown.contains("secret-handle-xyz"));
        assert!(!shown.contains("secret-fcm-device-token-999"));
        assert!(shown.contains("<redacted>"));
    }
}
