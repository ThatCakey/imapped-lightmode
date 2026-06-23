use imap_cache_rs::{
    AppServices,
    auth::{DenyAllAuthenticator, StaticAuthenticator},
    config::Config,
    db,
    db::repository::{NewCacheObject, NewMailAccount, NewUser, PostgresRepository},
    domain::{UpstreamAuthMethod, UpstreamTlsMode},
    metrics::AppMetrics,
    protocol::http,
    protocol::imap::{ImapSession, serve_plaintext},
    security,
    storage::memory::MemoryObjectStore,
};
use std::sync::Arc;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use uuid::Uuid;

async fn connect_pool() -> anyhow::Result<sqlx::PgPool> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
    });
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    db::run_migrations(&pool).await?;
    Ok(pool)
}

#[tokio::test]
async fn http_metrics_endpoint_reports_counters() -> anyhow::Result<()> {
    let services = Arc::new(AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(AppMetrics::new()),
    });
    services.metrics.inc_active_connections();
    services.metrics.inc_authenticated_sessions();
    services.metrics.record_command("LOGIN");
    services.metrics.record_command("FETCH");
    services.metrics.record_cache_hit();
    services.metrics.record_cache_miss();
    services.metrics.record_downstream_bytes(128);
    services.metrics.record_upstream_bytes_fetched(64);
    services.metrics.record_upstream_bytes_sent(32);
    services.metrics.inc_upstream_connections();
    services.metrics.record_object_store_bytes_read(64);
    services.metrics.record_object_store_bytes_written(32);
    services.metrics.record_redis_pubsub_event_published();
    services.metrics.record_redis_pubsub_event_relayed();
    services.metrics.record_sync_run(3, true);
    services.metrics.record_sync_run(4, false);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { http::serve(listener, services).await }
    });

    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let text = String::from_utf8(response)?;
    assert!(text.starts_with("HTTP/1.1 200 OK"));
    assert!(text.contains("imap_active_connections 1"));
    assert!(text.contains("imap_authenticated_sessions 1"));
    assert!(text.contains("imap_commands_total 2"));
    assert!(text.contains("imap_commands_total{command=\"FETCH\"} 1"));
    assert!(text.contains("imap_commands_total{command=\"LOGIN\"} 1"));
    assert!(text.contains("imap_cache_hits 1"));
    assert!(text.contains("imap_cache_misses 1"));
    assert!(text.contains("imap_cache_hit_ratio 0.5"));
    assert!(text.contains("imap_downstream_bytes_served 128"));
    assert!(text.contains("imap_upstream_bytes_fetched 64"));
    assert!(text.contains("imap_upstream_bytes_sent 32"));
    assert!(text.contains("imap_upstream_connections 1"));
    assert!(text.contains("imap_object_store_bytes_read 64"));
    assert!(text.contains("imap_object_store_bytes_written 32"));
    assert!(text.contains("imap_redis_pubsub_events_published 1"));
    assert!(text.contains("imap_redis_pubsub_events_relayed 1"));
    assert!(text.contains("imap_sync_runs_total 2"));
    assert!(text.contains("imap_sync_runs_failed 1"));
    assert!(text.contains("imap_sync_duration_seconds_total 7"));

    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let text = String::from_utf8(response)?;
    assert!(text.starts_with("HTTP/1.1 200 OK"));
    assert!(text.ends_with("ok"));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn http_metrics_endpoint_reports_storage_and_sync_state() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let user_email = format!("metrics-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: &security::hash_password("secret")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Metrics Test",
            email_address: &user_email,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    repo.upsert_cache_object(NewCacheObject {
        account_id: Some(account.id),
        object_type: "cache",
        blob_key: "cache/metrics",
        sha256: "deadbeef",
        size_octets: 512,
        ref_count: 1,
        last_accessed_at: None,
    })
    .await?;
    sqlx::query(
        "UPDATE mail_accounts SET last_sync_at = NOW(), last_sync_error = 'upstream timeout' WHERE id = $1",
    )
    .bind(account.id)
    .execute(repo.pool())
    .await?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { http::serve(listener, services).await }
    });

    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let text = String::from_utf8(response)?;
    assert!(text.contains("imap_cache_objects "));
    assert!(text.contains("imap_cache_object_bytes "));
    assert!(text.contains(&format!(
        "imap_account_cache_objects{{account=\"{}\"}} 1",
        user_email
    )));
    assert!(text.contains(&format!(
        "imap_account_cache_object_bytes{{account=\"{}\"}} 512",
        user_email
    )));
    assert!(text.contains(&format!(
        "imap_account_last_sync_status{{account=\"{}\",status=\"error\"}} 1",
        user_email
    )));
    assert!(text.contains(&format!(
        "imap_account_last_sync_timestamp_seconds{{account=\"{}\"}}",
        user_email
    )));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn metrics_bind_serves_metrics_endpoint() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    let blob_dir = tempfile::tempdir()?;
    let search_dir = tempfile::tempdir()?;

    let mut config = Config::default();
    config.imap_plaintext_bind = None;
    config.imap_tls_bind = None;
    config.http_bind = None;
    config.metrics_bind = Some(addr);
    config.database_url = None;
    config.object_store_path = Some(blob_dir.path().join("objects"));
    config.search_index_path = Some(search_dir.path().join("index"));

    let handle = tokio::spawn(async move { imap_cache_rs::run(config).await });

    let mut connected = None;
    for _ in 0..50 {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
        }
    }
    let mut stream = connected.ok_or_else(|| anyhow::anyhow!("metrics listener did not start"))?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let text = String::from_utf8(response)?;
    assert!(text.starts_with("HTTP/1.1 200 OK"));
    assert!(text.contains("imap_active_connections"));

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn imap_session_updates_metrics() -> anyhow::Result<()> {
    let services = AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.handle(&services, "A1 NOOP\r\n").await?;
    session
        .handle(&services, "A2 LOGIN \"user\" \"pass\"\r\n")
        .await?;

    assert_eq!(services.metrics.commands_total(), 2);
    assert_eq!(services.metrics.authenticated_sessions(), 0);
    Ok(())
}

#[tokio::test]
async fn live_imap_server_records_command_latency_and_errors() -> anyhow::Result<()> {
    let password_hash = security::hash_password("secret-password")?;
    let services = Arc::new(AppServices {
        authenticator: Arc::new(StaticAuthenticator::new(
            "user@example.test".to_string(),
            password_hash,
        )),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = TcpStream::connect(addr).await?;
    let mut stream = tokio::io::BufReader::new(client);
    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(b"A1 LOGIN \"user@example.test\" \"secret-password\"\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut login_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A1 OK");
        login_lines.push(line);
        if done {
            break;
        }
    }
    assert!(login_lines.iter().any(|line| line.starts_with("A1 OK")));

    stream.get_mut().write_all(b"A2 FOOBAR\r\n").await?;
    stream.get_mut().flush().await?;
    let mut unknown_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 NO") || line.starts_with("A2 BAD");
        unknown_lines.push(line);
        if done {
            break;
        }
    }
    assert!(unknown_lines.iter().any(|line| line.starts_with("A2 NO")));

    stream.get_mut().write_all(b"A3 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    let mut logout_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        logout_lines.push(line);
        if done {
            break;
        }
    }
    assert!(logout_lines.iter().any(|line| line.starts_with("* BYE")));

    let metrics = services.metrics.render_static();
    assert!(metrics.contains("imap_command_duration_seconds_count{command=\"LOGIN\"} 1"));
    assert!(metrics.contains("imap_command_duration_seconds_count{command=\"FOOBAR\"} 1"));
    assert!(metrics.contains("imap_command_errors_total{command=\"FOOBAR\"} 1"));

    server.abort();
    Ok(())
}
