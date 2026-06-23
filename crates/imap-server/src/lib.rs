pub use imap_cache_auth as auth;
pub use imap_cache_config as config;
pub use imap_cache_coordination as coordination;
pub use imap_cache_db as db;
pub use imap_cache_core::{domain, error, security};
pub use imap_cache_metrics as metrics;
pub use imap_cache_mime as mime;
pub use imap_cache_notifications as notifications;
pub use imap_cache_search as search;
pub use imap_cache_storage as storage;
pub use imap_cache_sync as sync;
pub use imap_cache_upstream as upstream;

pub mod http;
pub mod imap;

use anyhow::{Context, Result as AnyResult};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppServices {
    pub authenticator: Arc<dyn auth::Authenticator>,
    pub repository: Option<Arc<db::repository::PostgresRepository>>,
    pub object_store: Arc<dyn storage::ObjectStore>,
    pub search: Option<Arc<dyn search::SearchBackend>>,
    pub sync_engine: Option<Arc<sync::SyncEngine>>,
    pub mutation_engine: Option<Arc<sync::MutationEngine>>,
    pub events: Arc<notifications::MailboxEventHub>,
    pub metrics: Arc<metrics::AppMetrics>,
}

impl AppServices {
    pub async fn new(config: &config::Config) -> AnyResult<Self> {
        config::set_upstream_connection_limit_per_account(
            config.upstream_connection_limit_per_account,
        );
        config::set_idle_timeout_seconds(config.idle_timeout_seconds);
        let events = Arc::new(notifications::MailboxEventHub::new(1024));
        let metrics = Arc::new(metrics::AppMetrics::new());
        let notification_metrics: Arc<dyn notifications::NotificationMetrics> = metrics.clone();
        let repository = match config.database_url.as_deref() {
            Some(url) => {
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(5)
                    .connect(url)
                    .await
                    .with_context(|| format!("connecting to database at {url}"))?;
                db::run_migrations(&pool).await?;
                let mut sinks: Vec<Arc<dyn notifications::MutationEventSink>> = vec![Arc::new(
                    notifications::HubMutationEventSink::new(Arc::clone(&events)),
                )];
                if let Some(redis_url) = config.redis_url.as_deref() {
                    sinks.push(Arc::new(
                        notifications::RedisMutationEventSink::new(redis_url)?
                            .with_metrics(Arc::clone(&notification_metrics)),
                    ));
                }
                let repository = db::repository::PostgresRepository::new(
                    pool,
                    security::SecretBox::from_passphrase(&config.encryption_master_key),
                );
                let repository = repository.with_event_sink(Arc::new(
                    notifications::CompositeMutationEventSink::new(sinks),
                ));
                Some(Arc::new(repository))
            }
            None => None,
        };

        let object_store = build_object_store(config).await?;
        let search: Arc<dyn search::SearchBackend> = match config.search_index_path.as_deref() {
            Some(path) => Arc::new(search::TantivySearchEngine::persistent(path)?),
            None => Arc::new(search::TantivySearchEngine::memory()?),
        };
        let sync_engine = if let Some(repo) = repository.as_ref() {
            let mut engine = sync::SyncEngine::new(
                Arc::clone(repo),
                sync::MessageIngestor::with_metrics(
                    Arc::clone(repo),
                    Arc::clone(&object_store),
                    Some(Arc::clone(&search)),
                    Arc::clone(&metrics),
                ),
                Arc::clone(&metrics),
            );
            engine = engine.with_sync_limit(config.sync_concurrency);
            if let Some(redis_url) = config.redis_url.as_deref() {
                engine = engine.with_lock_manager(Arc::new(
                    coordination::RedisSyncLockManager::new(redis_url)?,
                ));
            } else {
                engine =
                    engine.with_lock_manager(Arc::new(coordination::MemorySyncLockManager::new()));
            }
            Some(Arc::new(engine))
        } else {
            None
        };
        let mutation_engine = repository.as_ref().map(|repo| {
            Arc::new(sync::MutationEngine::with_metrics(
                Arc::clone(repo),
                Arc::clone(&object_store),
                Arc::clone(&metrics),
            ))
        });

        Ok(Self {
            authenticator: auth::bootstrap_authenticator(config, repository.clone())?,
            repository,
            object_store,
            search: Some(search),
            sync_engine,
            mutation_engine,
            events,
            metrics,
        })
    }
}

async fn build_object_store(config: &config::Config) -> AnyResult<Arc<dyn storage::ObjectStore>> {
    if let Some(r2_config) = storage::r2::R2Config::from_app_config(config) {
        if r2_config.is_complete() {
            return Ok(Arc::new(
                storage::r2::S3ObjectStore::from_config(&r2_config).await?,
            ));
        }
    }

    if let Some(path) = config.object_store_path.as_deref() {
        return Ok(Arc::new(storage::filesystem::FilesystemObjectStore::new(
            path,
        )));
    }

    Ok(Arc::new(storage::memory::MemoryObjectStore::new()))
}

pub fn init_tracing(level: &str) -> error::Result<()> {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = fmt().with_env_filter(filter).json().finish();
    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
        error::Error::Config(format!("failed to install tracing subscriber: {e}"))
    })?;
    Ok(())
}
