//! Standalone Pubky Dispatch push relay binary.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser as _;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use pubky_dispatch_push_relay::clock::SystemClock;
use pubky_dispatch_push_relay::config::{CliArgs, LogFormat, PushBackendMode};
use pubky_dispatch_push_relay::http::{RateLimitBackends, RelayState, metrics_router, router};
use pubky_dispatch_push_relay::push::apns::ApnsSender;
use pubky_dispatch_push_relay::push::fcm::FcmSender;
use pubky_dispatch_push_relay::push::noop::NoopSender;
use pubky_dispatch_push_relay::push::{PushSender, RouterPushSender};
use pubky_dispatch_push_relay::rate_limit::RATE_WINDOW_MS;
use pubky_dispatch_push_relay::replay::{NONCE_TTL_MS, ReplayStore};
use pubky_dispatch_push_relay::store::is_postgres_url;
use pubky_dispatch_push_relay::store::postgres::{
    PostgresRateLimitStore, PostgresReplayStore, PostgresStore,
};
use pubky_dispatch_push_relay::store::sqlite::{SqliteReplayStore, SqliteStore};

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

    let clock = Arc::new(SystemClock);
    let database_url = args.database_url();
    let state = if is_postgres_url(database_url.as_str()) {
        let pg_store = Arc::new(PostgresStore::open(database_url.as_str()).await?);
        let pool = pg_store.pool().clone();
        let replay: Arc<dyn ReplayStore> = Arc::new(
            PostgresReplayStore::with_limits(
                pool.clone(),
                NONCE_TTL_MS,
                settings.nonce_cache_max_entries,
                settings.max_nonces_per_handle,
            )
            .await?,
        );
        let limiters = RateLimitBackends {
            hook_per_handle: Arc::new(
                PostgresRateLimitStore::with_limits(
                    pool.clone(),
                    "hook",
                    RATE_WINDOW_MS,
                    settings.rate_limit_per_minute,
                    settings.rate_limit_max_handles,
                )
                .await?,
            ),
            register_per_ip: Arc::new(
                PostgresRateLimitStore::with_limits(
                    pool.clone(),
                    "register_ip",
                    RATE_WINDOW_MS,
                    settings.register_ip_rate_limit_per_minute,
                    settings.rate_limit_max_handles,
                )
                .await?,
            ),
            register_per_key: Arc::new(
                PostgresRateLimitStore::with_limits(
                    pool.clone(),
                    "register_key",
                    RATE_WINDOW_MS,
                    settings.register_key_rate_limit_per_minute,
                    settings.rate_limit_max_handles,
                )
                .await?,
            ),
            register_global: Arc::new(
                PostgresRateLimitStore::with_limits(
                    pool,
                    "register_global",
                    RATE_WINDOW_MS,
                    settings.register_rate_limit_per_minute,
                    1,
                )
                .await?,
            ),
        };
        tracing::info!(
            storage = "postgres",
            replay = "postgres_durable",
            rate_limits = "postgres_durable",
            "initialized multi-replica PostgreSQL backend"
        );
        RelayState::with_backends(
            pg_store,
            push_sender,
            clock,
            replay,
            limiters,
            settings.clone(),
        )
    } else {
        let sqlite_store = Arc::new(SqliteStore::open(database_url.as_str()).await?);
        let replay: Arc<dyn ReplayStore> = Arc::new(
            SqliteReplayStore::with_limits(
                sqlite_store.pool().clone(),
                NONCE_TTL_MS,
                settings.nonce_cache_max_entries,
                settings.max_nonces_per_handle,
            )
            .await?,
        );
        let limiters = RelayState::in_memory_limiters(&settings);
        tracing::info!(
            storage = "sqlite",
            replay = "sqlite_durable",
            rate_limits = "in_memory",
            "initialized single-instance SQLite backend"
        );
        RelayState::with_backends(
            sqlite_store,
            push_sender,
            clock,
            replay,
            limiters,
            settings.clone(),
        )
    };

    let sweep_state = state.clone();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let sweep_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => sweep_state.prune_caches().await,
                _ = shutdown_rx.changed() => break,
            }
        }
    });

    let metrics_task = if let Some(metrics_addr) = args.metrics_bind_addr {
        let metrics_listener = TcpListener::bind(metrics_addr).await?;
        let metrics_app = metrics_router(state.clone());
        let mut metrics_shutdown = shutdown_tx.subscribe();
        tracing::info!(metrics_bind_addr = %metrics_addr, "serving Prometheus metrics");
        Some(tokio::spawn(async move {
            let _ = axum::serve(metrics_listener, metrics_app)
                .with_graceful_shutdown(async move {
                    let _ = metrics_shutdown.changed().await;
                })
                .await;
        }))
    } else {
        None
    };

    let app = router(state);
    let listener = TcpListener::bind(args.bind_addr).await?;
    tracing::info!(
        bind_addr = %args.bind_addr,
        relay_origin = %settings.relay_origin,
        "pubky-dispatch-push-relay listening"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    let _ = shutdown_tx.send(true);
    let _ = sweep_task.await;
    if let Some(task) = metrics_task {
        let _ = task.await;
    }
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
