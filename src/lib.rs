pub mod admin;
pub mod auth;
pub mod config;
pub mod coordination;
pub mod db;
pub mod domain;
pub mod error;
pub mod metrics;
pub mod mime;
pub mod notifications;
pub mod protocol;
pub mod search;
pub mod security;
pub mod storage;
pub mod sync;
pub mod upstream;

use anyhow::{Context, Result};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, signal, task::JoinSet};
use tracing::{info, warn};

pub use imap_cache_imap_server::AppServices;

pub async fn run(config: config::Config) -> Result<()> {
    let services = Arc::new(AppServices::new(&config).await?);
    if let Some(repo) = services.repository.as_ref() {
        if let Some(mutation_engine) = services.mutation_engine.as_ref() {
            spawn_pending_mutation_worker(
                Arc::clone(repo),
                Arc::clone(mutation_engine),
                Arc::clone(&services.metrics),
                config.upstream_connection_limit_per_account,
            );
        }
    }
    let mut tasks = JoinSet::new();
    let starttls_acceptor = match protocol::imap::tls_acceptor(&config) {
        Ok(acceptor) => acceptor,
        Err(err) => {
            warn!(error = %err, "STARTTLS and TLS listener disabled");
            None
        }
    };

    if let Some(redis_url) = config.redis_url.as_deref() {
        let services = Arc::clone(&services);
        let notification_metrics: Arc<dyn notifications::NotificationMetrics> =
            services.metrics.clone();
        let relay =
            notifications::RedisMutationEventRelay::new(redis_url, Arc::clone(&services.events))?
                .with_metrics(notification_metrics);
        tasks.spawn(async move { relay.run().await });
    }

    if let Some(addr) = config.imap_plaintext_bind {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding plaintext IMAP listener at {addr}"))?;
        let services = Arc::clone(&services);
        let starttls_acceptor = starttls_acceptor.clone();
        tasks.spawn(async move {
            protocol::imap::serve_plaintext(listener, services, starttls_acceptor).await
        });
        info!(%addr, "plaintext IMAP listener started");
    }

    if let Some(addr) = config.imap_tls_bind {
        match starttls_acceptor.clone() {
            Some(acceptor) => {
                let listener = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("binding TLS IMAP listener at {addr}"))?;
                let services = Arc::clone(&services);
                tasks.spawn(async move {
                    protocol::imap::serve_tls(listener, acceptor, services).await
                });
                info!(%addr, "TLS IMAP listener started");
            }
            None => warn!(%addr, "TLS listener configured but certificate material is missing"),
        }
    }

    if let Some(addr) = config.http_bind {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding HTTP listener at {addr}"))?;
        let services = Arc::clone(&services);
        tasks.spawn(async move { protocol::http::serve(listener, services).await });
        info!(%addr, "HTTP listener started");
    }

    if let Some(addr) = config.metrics_bind {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding metrics listener at {addr}"))?;
        let services = Arc::clone(&services);
        tasks.spawn(async move { protocol::http::serve(listener, services).await });
        info!(%addr, "metrics listener started");
    }

    if tasks.is_empty() {
        anyhow::bail!("no listeners were configured");
    }

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("shutdown signal received");
        }
        maybe_task = tasks.join_next() => {
            if let Some(join_result) = maybe_task {
                join_result.context("listener task failed")??;
            }
        }
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
}

fn spawn_pending_mutation_worker(
    repository: Arc<db::repository::PostgresRepository>,
    mutation_engine: Arc<sync::MutationEngine>,
    metrics: Arc<metrics::AppMetrics>,
    upstream_connection_limit_per_account: usize,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(err) = flush_pending_mutations_once(
                Arc::clone(&repository),
                Arc::clone(&mutation_engine),
                Arc::clone(&metrics),
                upstream_connection_limit_per_account,
            )
            .await
            {
                warn!(error = %err, "pending mutation worker failed");
            }
        }
    });
}

async fn flush_pending_mutations_once(
    repository: Arc<db::repository::PostgresRepository>,
    mutation_engine: Arc<sync::MutationEngine>,
    metrics: Arc<metrics::AppMetrics>,
    upstream_connection_limit_per_account: usize,
) -> Result<()> {
    let accounts = repository.list_enabled_accounts().await?;
    for account in accounts {
        let Some(upstream_config) = repository.upstream_account_config_by_id(account.id).await?
        else {
            continue;
        };
        let mut client = crate::upstream::UpstreamClient::connect(&upstream_config)
            .await?
            .with_metrics(Arc::clone(&metrics))
            .with_account_connection_limit(account.id, upstream_connection_limit_per_account)
            .await?;
        client
            .authenticate_with_method(
                upstream_config.auth_method,
                &upstream_config.username,
                &upstream_config.secret,
            )
            .await?;
        let _ = mutation_engine
            .flush_pending_mutations(account.id, &mut client)
            .await?;
        client.logout().await?;
    }
    Ok(())
}
