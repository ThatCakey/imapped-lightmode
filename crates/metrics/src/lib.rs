use imap_cache_db::repository::PostgresRepository;
use imap_cache_core::error::Result;
use chrono::{DateTime, Utc};
use std::{
    collections::HashMap,
    fmt::Write as _,
    sync::atomic::{AtomicI64, AtomicU64, Ordering},
    sync::{Arc, Mutex},
    time::Duration,
};

impl imap_cache_notifications::NotificationMetrics for AppMetrics {
    fn record_redis_pubsub_event_published(&self) {
        AppMetrics::record_redis_pubsub_event_published(self);
    }

    fn record_redis_pubsub_event_relayed(&self) {
        AppMetrics::record_redis_pubsub_event_relayed(self);
    }
}

impl imap_cache_upstream::UpstreamMetrics for AppMetrics {
    fn inc_upstream_connections(&self) {
        AppMetrics::inc_upstream_connections(self);
    }

    fn dec_upstream_connections(&self) {
        AppMetrics::dec_upstream_connections(self);
    }

    fn record_upstream_bytes_fetched(&self, bytes: u64) {
        AppMetrics::record_upstream_bytes_fetched(self, bytes);
    }

    fn record_upstream_bytes_sent(&self, bytes: u64) {
        AppMetrics::record_upstream_bytes_sent(self, bytes);
    }
}

impl imap_cache_sync::SyncMetrics for AppMetrics {
    fn record_object_store_bytes_written(&self, bytes: u64) {
        AppMetrics::record_object_store_bytes_written(self, bytes);
    }

    fn record_object_store_bytes_read(&self, bytes: u64) {
        AppMetrics::record_object_store_bytes_read(self, bytes);
    }

    fn record_sync_run(&self, duration_seconds: u64, succeeded: bool) {
        AppMetrics::record_sync_run(self, duration_seconds, succeeded);
    }
}

#[derive(Debug, Default)]
pub struct AppMetrics {
    active_connections: AtomicI64,
    authenticated_sessions: AtomicI64,
    commands_total: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    downstream_bytes_served: AtomicU64,
    upstream_bytes_fetched: AtomicU64,
    upstream_bytes_sent: AtomicU64,
    upstream_connections: AtomicI64,
    object_store_bytes_read: AtomicU64,
    object_store_bytes_written: AtomicU64,
    redis_pubsub_events_published: AtomicU64,
    redis_pubsub_events_relayed: AtomicU64,
    sync_runs_total: AtomicU64,
    sync_runs_failed: AtomicU64,
    sync_duration_seconds_total: AtomicU64,
    command_duration_nanos_total: Mutex<HashMap<String, u128>>,
    command_duration_count: Mutex<HashMap<String, u64>>,
    command_error_counts: Mutex<HashMap<String, u64>>,
    command_counts: Mutex<HashMap<String, u64>>,
}

impl AppMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_authenticated_sessions(&self) {
        self.authenticated_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_authenticated_sessions(&self) {
        self.authenticated_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_command(&self, command: &str) {
        self.commands_total.fetch_add(1, Ordering::Relaxed);
        let mut counts = self.command_counts.lock().expect("metrics mutex poisoned");
        *counts.entry(command.to_ascii_uppercase()).or_insert(0) += 1;
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_downstream_bytes(&self, bytes: u64) {
        self.downstream_bytes_served
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_object_store_bytes_read(&self, bytes: u64) {
        self.object_store_bytes_read
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_object_store_bytes_written(&self, bytes: u64) {
        self.object_store_bytes_written
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_upstream_bytes_fetched(&self, bytes: u64) {
        self.upstream_bytes_fetched
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_upstream_bytes_sent(&self, bytes: u64) {
        self.upstream_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn inc_upstream_connections(&self) {
        self.upstream_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_upstream_connections(&self) {
        self.upstream_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_redis_pubsub_event_published(&self) {
        self.redis_pubsub_events_published
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_redis_pubsub_event_relayed(&self) {
        self.redis_pubsub_events_relayed
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_sync_run(&self, duration_seconds: u64, succeeded: bool) {
        self.sync_runs_total.fetch_add(1, Ordering::Relaxed);
        self.sync_duration_seconds_total
            .fetch_add(duration_seconds, Ordering::Relaxed);
        if !succeeded {
            self.sync_runs_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_command_duration(&self, command: &str, duration: Duration) {
        let mut nanos = self
            .command_duration_nanos_total
            .lock()
            .expect("metrics mutex poisoned");
        let mut counts = self
            .command_duration_count
            .lock()
            .expect("metrics mutex poisoned");
        let key = command.to_ascii_uppercase();
        *nanos.entry(key.clone()).or_insert(0) += duration.as_nanos();
        *counts.entry(key).or_insert(0) += 1;
    }

    pub fn record_command_error(&self, command: &str) {
        let mut counts = self
            .command_error_counts
            .lock()
            .expect("metrics mutex poisoned");
        *counts.entry(command.to_ascii_uppercase()).or_insert(0) += 1;
    }

    pub fn active_connections(&self) -> i64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn authenticated_sessions(&self) -> i64 {
        self.authenticated_sessions.load(Ordering::Relaxed)
    }

    pub fn commands_total(&self) -> u64 {
        self.commands_total.load(Ordering::Relaxed)
    }

    pub fn cache_hits(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    pub fn cache_misses(&self) -> u64 {
        self.cache_misses.load(Ordering::Relaxed)
    }

    pub fn downstream_bytes_served(&self) -> u64 {
        self.downstream_bytes_served.load(Ordering::Relaxed)
    }

    pub fn object_store_bytes_read(&self) -> u64 {
        self.object_store_bytes_read.load(Ordering::Relaxed)
    }

    pub fn object_store_bytes_written(&self) -> u64 {
        self.object_store_bytes_written.load(Ordering::Relaxed)
    }

    pub fn upstream_bytes_fetched(&self) -> u64 {
        self.upstream_bytes_fetched.load(Ordering::Relaxed)
    }

    pub fn upstream_bytes_sent(&self) -> u64 {
        self.upstream_bytes_sent.load(Ordering::Relaxed)
    }

    pub fn upstream_connections(&self) -> i64 {
        self.upstream_connections.load(Ordering::Relaxed)
    }

    pub fn redis_pubsub_events_published(&self) -> u64 {
        self.redis_pubsub_events_published.load(Ordering::Relaxed)
    }

    pub fn redis_pubsub_events_relayed(&self) -> u64 {
        self.redis_pubsub_events_relayed.load(Ordering::Relaxed)
    }

    pub fn sync_runs_total(&self) -> u64 {
        self.sync_runs_total.load(Ordering::Relaxed)
    }

    pub fn sync_runs_failed(&self) -> u64 {
        self.sync_runs_failed.load(Ordering::Relaxed)
    }

    pub fn sync_duration_seconds_total(&self) -> u64 {
        self.sync_duration_seconds_total.load(Ordering::Relaxed)
    }

    pub fn render_static(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(
            output,
            "# HELP imap_active_connections Active IMAP connections"
        );
        let _ = writeln!(output, "# TYPE imap_active_connections gauge");
        let _ = writeln!(
            output,
            "imap_active_connections {}",
            self.active_connections()
        );
        let _ = writeln!(
            output,
            "# HELP imap_authenticated_sessions Authenticated IMAP sessions"
        );
        let _ = writeln!(output, "# TYPE imap_authenticated_sessions gauge");
        let _ = writeln!(
            output,
            "imap_authenticated_sessions {}",
            self.authenticated_sessions()
        );
        let _ = writeln!(output, "# HELP imap_commands_total IMAP commands processed");
        let _ = writeln!(output, "# TYPE imap_commands_total counter");
        let _ = writeln!(output, "imap_commands_total {}", self.commands_total());

        let _ = writeln!(output, "# HELP imap_cache_hits Cache hits");
        let _ = writeln!(output, "# TYPE imap_cache_hits counter");
        let _ = writeln!(output, "imap_cache_hits {}", self.cache_hits());
        let _ = writeln!(output, "# HELP imap_cache_misses Cache misses");
        let _ = writeln!(output, "# TYPE imap_cache_misses counter");
        let _ = writeln!(output, "imap_cache_misses {}", self.cache_misses());
        let total_cache = self.cache_hits().saturating_add(self.cache_misses());
        let cache_hit_ratio = if total_cache == 0 {
            0.0
        } else {
            self.cache_hits() as f64 / total_cache as f64
        };
        let _ = writeln!(output, "# HELP imap_cache_hit_ratio Cache hit ratio");
        let _ = writeln!(output, "# TYPE imap_cache_hit_ratio gauge");
        let _ = writeln!(output, "imap_cache_hit_ratio {}", cache_hit_ratio);
        let _ = writeln!(
            output,
            "# HELP imap_downstream_bytes_served Bytes served to clients"
        );
        let _ = writeln!(output, "# TYPE imap_downstream_bytes_served counter");
        let _ = writeln!(
            output,
            "imap_downstream_bytes_served {}",
            self.downstream_bytes_served()
        );
        let _ = writeln!(
            output,
            "# HELP imap_upstream_bytes_fetched Bytes fetched from upstream IMAP servers"
        );
        let _ = writeln!(output, "# TYPE imap_upstream_bytes_fetched counter");
        let _ = writeln!(
            output,
            "imap_upstream_bytes_fetched {}",
            self.upstream_bytes_fetched()
        );
        let _ = writeln!(
            output,
            "# HELP imap_upstream_bytes_sent Bytes sent to upstream IMAP servers"
        );
        let _ = writeln!(output, "# TYPE imap_upstream_bytes_sent counter");
        let _ = writeln!(
            output,
            "imap_upstream_bytes_sent {}",
            self.upstream_bytes_sent()
        );
        let _ = writeln!(
            output,
            "# HELP imap_upstream_connections Active upstream IMAP connections"
        );
        let _ = writeln!(output, "# TYPE imap_upstream_connections gauge");
        let _ = writeln!(
            output,
            "imap_upstream_connections {}",
            self.upstream_connections()
        );
        let _ = writeln!(
            output,
            "# HELP imap_object_store_bytes_read Bytes read from object storage"
        );
        let _ = writeln!(output, "# TYPE imap_object_store_bytes_read counter");
        let _ = writeln!(
            output,
            "imap_object_store_bytes_read {}",
            self.object_store_bytes_read()
        );
        let _ = writeln!(
            output,
            "# HELP imap_object_store_bytes_written Bytes written to object storage"
        );
        let _ = writeln!(output, "# TYPE imap_object_store_bytes_written counter");
        let _ = writeln!(
            output,
            "imap_object_store_bytes_written {}",
            self.object_store_bytes_written()
        );
        let _ = writeln!(
            output,
            "# HELP imap_redis_pubsub_events_published Redis pub/sub events published"
        );
        let _ = writeln!(output, "# TYPE imap_redis_pubsub_events_published counter");
        let _ = writeln!(
            output,
            "imap_redis_pubsub_events_published {}",
            self.redis_pubsub_events_published()
        );
        let _ = writeln!(
            output,
            "# HELP imap_redis_pubsub_events_relayed Redis pub/sub events relayed"
        );
        let _ = writeln!(output, "# TYPE imap_redis_pubsub_events_relayed counter");
        let _ = writeln!(
            output,
            "imap_redis_pubsub_events_relayed {}",
            self.redis_pubsub_events_relayed()
        );
        let _ = writeln!(output, "# HELP imap_sync_runs_total Sync runs completed");
        let _ = writeln!(output, "# TYPE imap_sync_runs_total counter");
        let _ = writeln!(output, "imap_sync_runs_total {}", self.sync_runs_total());
        let _ = writeln!(output, "# HELP imap_sync_runs_failed Sync runs that failed");
        let _ = writeln!(output, "# TYPE imap_sync_runs_failed counter");
        let _ = writeln!(output, "imap_sync_runs_failed {}", self.sync_runs_failed());
        let _ = writeln!(
            output,
            "# HELP imap_sync_duration_seconds_total Total sync duration in seconds"
        );
        let _ = writeln!(output, "# TYPE imap_sync_duration_seconds_total counter");
        let _ = writeln!(
            output,
            "imap_sync_duration_seconds_total {}",
            self.sync_duration_seconds_total()
        );

        let counts = self.command_counts.lock().expect("metrics mutex poisoned");
        let mut entries = counts.iter().collect::<Vec<_>>();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (command, count) in entries {
            let _ = writeln!(
                output,
                "imap_commands_total{{command=\"{}\"}} {}",
                command, count
            );
        }
        let duration_nanos = self
            .command_duration_nanos_total
            .lock()
            .expect("metrics mutex poisoned");
        let duration_counts = self
            .command_duration_count
            .lock()
            .expect("metrics mutex poisoned");
        let error_counts = self
            .command_error_counts
            .lock()
            .expect("metrics mutex poisoned");
        let mut duration_entries = duration_counts.iter().collect::<Vec<_>>();
        duration_entries.sort_by(|a, b| a.0.cmp(b.0));
        if !duration_entries.is_empty() {
            let _ = writeln!(
                output,
                "# HELP imap_command_duration_seconds_total Total command duration in seconds"
            );
            let _ = writeln!(output, "# TYPE imap_command_duration_seconds_total counter");
            let _ = writeln!(
                output,
                "# HELP imap_command_duration_seconds_count Command count used for duration totals"
            );
            let _ = writeln!(output, "# TYPE imap_command_duration_seconds_count counter");
            for (command, count) in duration_entries {
                let nanos = duration_nanos.get(command).copied().unwrap_or(0);
                let seconds = nanos as f64 / 1_000_000_000.0;
                let _ = writeln!(
                    output,
                    "imap_command_duration_seconds_total{{command=\"{}\"}} {}",
                    command, seconds
                );
                let _ = writeln!(
                    output,
                    "imap_command_duration_seconds_count{{command=\"{}\"}} {}",
                    command, count
                );
                let errors = error_counts.get(command).copied().unwrap_or(0);
                let _ = writeln!(
                    output,
                    "imap_command_errors_total{{command=\"{}\"}} {}",
                    command, errors
                );
            }
        }
        output
    }

    pub async fn render(&self, repo: Option<Arc<PostgresRepository>>) -> Result<String> {
        let mut output = self.render_static();
        if let Some(repo) = repo {
            let pending = repo.count_pending_mutations().await?;
            let _ = writeln!(
                output,
                "# HELP imap_pending_mutations Pending mutation queue depth"
            );
            let _ = writeln!(output, "# TYPE imap_pending_mutations gauge");
            let _ = writeln!(output, "imap_pending_mutations {}", pending);

            let cache_objects = sqlx::query_scalar::<_, i64>(
                r#"
                SELECT COUNT(*)::bigint
                FROM cache_objects
                "#,
            )
            .fetch_one(repo.pool())
            .await
            .unwrap_or(0);
            let cache_object_bytes = sqlx::query_scalar::<_, i64>(
                r#"
                SELECT COALESCE(SUM(size_octets), 0)::bigint
                FROM cache_objects
                "#,
            )
            .fetch_one(repo.pool())
            .await
            .unwrap_or(0);
            let _ = writeln!(
                output,
                "# HELP imap_cache_objects Total cache objects tracked"
            );
            let _ = writeln!(output, "# TYPE imap_cache_objects gauge");
            let _ = writeln!(output, "imap_cache_objects {}", cache_objects);
            let _ = writeln!(
                output,
                "# HELP imap_cache_object_bytes Total bytes tracked in cache objects"
            );
            let _ = writeln!(output, "# TYPE imap_cache_object_bytes gauge");
            let _ = writeln!(output, "imap_cache_object_bytes {}", cache_object_bytes);

            let account_cache_rows = sqlx::query_as::<_, AccountCacheMetricRow>(
                r#"
                SELECT m.email_address, COUNT(*)::bigint AS object_count, COALESCE(SUM(c.size_octets), 0)::bigint AS object_bytes
                FROM cache_objects AS c
                JOIN mail_accounts AS m ON m.id = c.account_id
                GROUP BY m.email_address
                ORDER BY m.email_address ASC
                "#,
            )
            .fetch_all(repo.pool())
            .await
            .unwrap_or_default();
            if !account_cache_rows.is_empty() {
                let _ = writeln!(
                    output,
                    "# HELP imap_account_cache_objects Per-account cache object count"
                );
                let _ = writeln!(output, "# TYPE imap_account_cache_objects gauge");
                let _ = writeln!(
                    output,
                    "# HELP imap_account_cache_object_bytes Per-account cache object bytes"
                );
                let _ = writeln!(output, "# TYPE imap_account_cache_object_bytes gauge");
                for row in account_cache_rows {
                    let account = escape_metric_label(&row.email_address);
                    let _ = writeln!(
                        output,
                        "imap_account_cache_objects{{account=\"{}\"}} {}",
                        account, row.object_count
                    );
                    let _ = writeln!(
                        output,
                        "imap_account_cache_object_bytes{{account=\"{}\"}} {}",
                        account, row.object_bytes
                    );
                }
            }

            let accounts = sqlx::query_as::<_, AccountSyncMetricRow>(
                r#"
                SELECT id, email_address, last_sync_at, last_sync_error
                FROM mail_accounts
                WHERE disabled_at IS NULL
                ORDER BY id ASC
                "#,
            )
            .fetch_all(repo.pool())
            .await
            .unwrap_or_default();
            if !accounts.is_empty() {
                let _ = writeln!(
                    output,
                    "# HELP imap_account_last_sync_status Per-account last sync status"
                );
                let _ = writeln!(output, "# TYPE imap_account_last_sync_status gauge");
                for account in accounts {
                    let status = if account.last_sync_error.is_some() {
                        "error"
                    } else if account.last_sync_at.is_some() {
                        "ok"
                    } else {
                        "never"
                    };
                    let _ = writeln!(
                        output,
                        "imap_account_last_sync_status{{account=\"{}\",status=\"{}\"}} 1",
                        escape_metric_label(&account.email_address),
                        status
                    );
                    if let Some(last_sync_at) = account.last_sync_at {
                        let _ = writeln!(
                            output,
                            "imap_account_last_sync_timestamp_seconds{{account=\"{}\"}} {}",
                            escape_metric_label(&account.email_address),
                            last_sync_at.timestamp()
                        );
                    }
                }
            }
        }
        Ok(output)
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AccountSyncMetricRow {
    email_address: String,
    last_sync_at: Option<DateTime<Utc>>,
    last_sync_error: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct AccountCacheMetricRow {
    email_address: String,
    object_count: i64,
    object_bytes: i64,
}

fn escape_metric_label(value: &str) -> String {
    value.replace('\\', r"\\").replace('"', r#"\""#)
}

pub struct ConnectionGuard {
    metrics: Arc<AppMetrics>,
}

impl ConnectionGuard {
    pub fn new(metrics: Arc<AppMetrics>) -> Self {
        metrics.inc_active_connections();
        Self { metrics }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.metrics.dec_active_connections();
    }
}
