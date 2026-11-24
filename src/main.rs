//! Standalone Pubky Dispatch push relay binary.

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser as _;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use pubky_dispatch_push_relay::clock::SystemClock;
use pubky_dispatch_push_relay::config::{CliArgs, LogFormat, PushBackendMode};
use pubky_dispatch_push_relay::http::{RelayState, router};
use pubky_dispatch_push_relay::push::apns::ApnsSender;
use pubky_dispatch_push_relay::push::fcm::FcmSender;
use pubky_dispatch_push_relay::push::noop::NoopSender;
use pubky_dispatch_push_relay::push::{PushSender, RouterPushSender};
use pubky_dispatch_push_relay::store::sqlite::SqliteStore;

#[tokio::main]
async fn main() -> ExitCode {
    let args = CliArgs::parse();
    init_tracing(args.log_format);

    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "push relay exited with error");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    let settings = args.to_relay_settings()?;
    let store = Arc::new(SqliteStore::open(&args.database_url).await?);

    let push_sender: Arc<dyn PushSender> = match args.push_backend {
        PushBackendMode::Noop => {
            tracing::warn!("running with PUSH_BACKEND=noop (no pushes will be delivered)");
            Arc::new(NoopSender)
        }
        PushBackendMode::Providers => {
            let mut router_sender = RouterPushSender::new();
            if let Some(apns_cfg) = args.load_apns_config()? {
                tracing::info!(
                    default_env = %apns_cfg.default_env,
                    push_mode = ?apns_cfg.push_mode,
                    "configured APNs push backend"
                );
                router_sender = router_sender.with_apns(Arc::new(ApnsSender::new(apns_cfg)?));
            }
            if let Some(fcm_cfg) = args.load_fcm_config()? {
                tracing::info!(
                    project_id = %fcm_cfg.service_account.project_id,
                    "configured FCM HTTP v1 push backend"
                );
                router_sender = router_sender.with_fcm(Arc::new(FcmSender::new(fcm_cfg)?));
            }
            if !router_sender.has_any_provider() {
                return Err(
                    "no push providers configured: set APNS_* and/or FCM_* env vars, or use PUSH_BACKEND=noop for local development"
                        .into(),
                );
            }
            Arc::new(router_sender)
        }
    };

    let state = RelayState::new(store, push_sender, Arc::new(SystemClock), settings.clone());

    let sweep_state = state.clone();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let sweep_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => sweep_state.prune_caches(),
                _ = shutdown_rx.changed() => break,
            }
        }
    });

    let app = router(state);
    let listener = TcpListener::bind(args.bind_addr).await?;
    tracing::info!(
        bind_addr = %args.bind_addr,
        relay_origin = %settings.relay_origin,
        "pubky-dispatch-push-relay listening"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    let _ = shutdown_tx.send(true);
    let _ = sweep_task.await;
    tracing::info!("pubky-dispatch-push-relay shut down cleanly");
    Ok(())
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("pubky_dispatch_push_relay=info"));
    match format {
        LogFormat::Json => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .try_init();
        }
        LogFormat::Pretty => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .pretty()
                .try_init();
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = sigterm.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
