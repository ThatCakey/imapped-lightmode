use chrono::Utc;
use base64::Engine as _;
use imap_cache_rs::{
    AppServices,
    auth::{AuthContext, DenyAllAuthenticator, PostgresAuthenticator, StaticAuthenticator},
    config::Config,
    db,
    db::repository::{
        NewMailAccount, NewMailbox, NewMailboxMessage, NewMessage, NewUser, PostgresRepository,
    },
    domain::{UpstreamAuthMethod, UpstreamTlsMode},
    mime::parse_message,
    notifications::{HubMutationEventSink, MailboxEventHub},
    protocol::imap::{ImapSession, ParsedCommand, State, parse_command, serve_plaintext},
    search::{SearchBackend, SearchDocument, TantivySearchEngine},
    security,
    storage::{ObjectStore, ObjectType, content_addressed_key, memory::MemoryObjectStore},
    upstream::UpstreamClient,
};
use imap_cache_test_support::{
    live_test_guard as support_live_test_guard,
    load_testing_credentials as load_live_testing_credentials,
};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::{fs, io::BufReader as StdBufReader, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;
use tempfile::tempdir;
use uuid::Uuid;

async fn connect_pool() -> anyhow::Result<sqlx::PgPool> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
    });
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    db::run_migrations(&pool).await?;
    Ok(pool)
}

fn testing_upstream_config() -> anyhow::Result<imap_cache_rs::upstream::UpstreamAccountConfig> {
    let creds = load_live_testing_credentials()?;
    Ok(imap_cache_rs::upstream::UpstreamAccountConfig {
        host: creds.imap_host,
        port: creds.imap_port,
        tls_mode: UpstreamTlsMode::Tls,
        auth_method: UpstreamAuthMethod::Login,
        username: creds.username,
        secret: creds.password,
    })
}

fn load_testing_credentials() -> anyhow::Result<imap_cache_rs::upstream::UpstreamAccountConfig> {
    testing_upstream_config()
}

async fn live_test_guard() -> imap_cache_test_support::LiveTestGuard {
    support_live_test_guard().await
}

fn literal_size(line: &str) -> anyhow::Result<usize> {
    let start = line
        .rfind('{')
        .ok_or_else(|| anyhow::anyhow!("missing literal marker in {line}"))?;
    let end = line
        .rfind('}')
        .ok_or_else(|| anyhow::anyhow!("missing literal terminator in {line}"))?;
    Ok(line[start + 1..end].parse::<usize>()?)
}

#[test]
fn parses_quoted_and_parenthesized_arguments() {
    let parsed = parse_command(r#"A1 LIST "" "*" "#).unwrap().unwrap();
    assert_eq!(parsed.tag, "A1");
    assert_eq!(parsed.name, "LIST");
    assert_eq!(parsed.args, vec!["", "*"]);
}

#[tokio::test]
async fn login_and_capability_flow_works() {
    let password_hash = security::hash_password("secret").unwrap();
    let authenticator = Arc::new(StaticAuthenticator::new(
        "user@example.test".into(),
        password_hash,
    ));
    let services = AppServices {
        authenticator,
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    let caps = session
        .handle(&services, "A1 CAPABILITY\r\n")
        .await
        .unwrap();
    assert!(caps.iter().any(|line| line.contains("CAPABILITY")));
    assert!(!caps.iter().any(|line| line.contains("UNSELECT")));

    let login = session
        .handle(&services, "A2 LOGIN \"user@example.test\" \"secret\"\r\n")
        .await
        .unwrap();
    assert!(login.iter().any(|line| line.starts_with("A2 OK")));
    assert_eq!(session.state, State::Authenticated);
    let authed_caps = session.capabilities();
    assert!(authed_caps.contains(&"UNSELECT"));
    assert!(authed_caps.contains(&"ESEARCH"));
    assert!(authed_caps.contains(&"ID"));
}

#[tokio::test]
async fn authenticate_plain_continuation_updates_capabilities_over_wire() -> anyhow::Result<()> {
    let password_hash = security::hash_password("secret")?;
    let services = Arc::new(AppServices {
        authenticator: Arc::new(StaticAuthenticator::new(
            "user@example.test".into(),
            password_hash,
        )),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream.get_mut().write_all(b"A1 CAPABILITY\r\n").await?;
    stream.get_mut().flush().await?;
    let mut capability_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A1 OK");
        capability_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        capability_lines
            .iter()
            .any(|line| line.contains("AUTH=PLAIN")),
        "{capability_lines:?}"
    );
    assert!(
        !capability_lines
            .iter()
            .any(|line| line.contains("UNSELECT")),
        "{capability_lines:?}"
    );

    stream.get_mut().write_all(b"A2 AUTHENTICATE PLAIN\r\n").await?;
    stream.get_mut().flush().await?;
    let mut continuation = String::new();
    stream.read_line(&mut continuation).await?;
    assert!(continuation.starts_with("+ "));

    let payload = base64::engine::general_purpose::STANDARD.encode(b"\0user@example.test\0secret");
    stream
        .get_mut()
        .write_all(format!("{payload}\r\n").as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut auth_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        auth_lines.push(line);
        if done {
            break;
        }
    }
    assert!(auth_lines.iter().any(|line| line.starts_with("A2 OK")));

    stream.get_mut().write_all(b"A3 CAPABILITY\r\n").await?;
    stream.get_mut().flush().await?;
    let mut authed_caps = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        authed_caps.push(line);
        if done {
            break;
        }
    }
    assert!(
        authed_caps.iter().any(|line| line.contains("UNSELECT")),
        "{authed_caps:?}"
    );

    stream.get_mut().write_all(b"A4 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    let mut logout_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        logout_lines.push(line);
        if done {
            break;
        }
    }
    assert!(logout_lines.iter().any(|line| line.starts_with("* BYE")));

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn malformed_search_returns_bad_without_closing_connection() -> anyhow::Result<()> {
    let password_hash = security::hash_password("secret")?;
    let services = Arc::new(AppServices {
        authenticator: Arc::new(StaticAuthenticator::new(
            "user@example.test".into(),
            password_hash,
        )),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(b"A1 LOGIN \"user@example.test\" \"secret\"\r\n")
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

    stream.get_mut().write_all(b"A2 SELECT INBOX\r\n").await?;
    stream.get_mut().flush().await?;
    let mut select_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        select_lines.push(line);
        if done {
            break;
        }
    }
    assert!(select_lines.iter().any(|line| line.starts_with("A2 OK")));

    stream.get_mut().write_all(b"A3 SEARCH RETURN\r\n").await?;
    stream.get_mut().flush().await?;
    let mut bad_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 BAD");
        bad_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        bad_lines
            .iter()
            .any(|line| line.contains("RETURN requires options")),
        "{bad_lines:?}"
    );

    stream.get_mut().write_all(b"A4 NOOP\r\n").await?;
    stream.get_mut().flush().await?;
    let mut noop_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        noop_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        noop_lines
            .iter()
            .any(|line| line.trim_end() == "A4 OK NOOP completed"),
        "{noop_lines:?}"
    );

    stream
        .get_mut()
        .write_all(b"A5 SEARCH CHARSET ISO-8859-1 UNSEEN\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut bad_charset_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A5 NO");
        bad_charset_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        bad_charset_lines
            .iter()
            .any(|line| line.contains("[BADCHARSET]")),
        "{bad_charset_lines:?}"
    );

    stream.get_mut().write_all(b"A6 NOOP\r\n").await?;
    stream.get_mut().flush().await?;
    let mut noop_after_bad_charset = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A6 OK");
        noop_after_bad_charset.push(line);
        if done {
            break;
        }
    }
    assert!(
        noop_after_bad_charset
            .iter()
            .any(|line| line.trim_end() == "A6 OK NOOP completed"),
        "{noop_after_bad_charset:?}"
    );

    stream.get_mut().write_all(b"A7 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    let mut bye = String::new();
    stream.read_line(&mut bye).await?;
    assert!(bye.starts_with("* BYE"));

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn authenticate_xoauth2_continuation_completes_over_wire() -> anyhow::Result<()> {
    let password_hash = security::hash_password("secret-token")?;
    let services = Arc::new(AppServices {
        authenticator: Arc::new(StaticAuthenticator::new(
            "user@example.test".into(),
            password_hash,
        )),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(b"A1 AUTHENTICATE XOAUTH2\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut continuation = String::new();
    stream.read_line(&mut continuation).await?;
    assert!(continuation.starts_with("+ "));

    let payload = base64::engine::general_purpose::STANDARD
        .encode(b"user=user@example.test\x01auth=Bearer secret-token\x01\x01");
    stream
        .get_mut()
        .write_all(format!("{payload}\r\n").as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut auth_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A1 OK");
        auth_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        auth_lines.iter().any(|line| line.starts_with("A1 OK")),
        "{auth_lines:?}"
    );

    stream.get_mut().write_all(b"A2 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    let mut logout_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        logout_lines.push(line);
        if done {
            break;
        }
    }
    assert!(logout_lines.iter().any(|line| line.starts_with("* BYE")));

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_searches_real_mailbox_with_or_not_and_esearch() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let store: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = imap_cache_rs::sync::MessageIngestor::new(
        repo.clone(),
        store.clone(),
        Some(search.clone()),
    );
    let metrics = Arc::new(imap_cache_rs::metrics::AppMetrics::new());
    let sync_engine = imap_cache_rs::sync::SyncEngine::new(
        repo.clone(),
        ingestor,
        Arc::clone(&metrics),
    );
    let local_email = format!("live-search-{}@example.test", Uuid::new_v4());
    let password = "secret";

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Search",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let mut upstream =
        tokio::time::timeout(Duration::from_secs(60), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(60), upstream.capability()).await??;
    tokio::time::timeout(
        Duration::from_secs(60),
        upstream.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;

    let mailboxes = tokio::time::timeout(Duration::from_secs(60), upstream.list_mailboxes()).await??;
    let mut selected_mailbox: Option<String> = None;
    let mut selected_uid: Option<u64> = None;
    let mut selected_selection: Option<imap_cache_rs::upstream::SelectedMailboxInfo> = None;
    for mailbox_name in mailboxes {
        let selection =
            tokio::time::timeout(Duration::from_secs(60), upstream.select_mailbox(&mailbox_name))
                .await??;
        let uids = tokio::time::timeout(Duration::from_secs(60), upstream.uid_search_all()).await??;
        let Some(uid) = uids.into_iter().max() else {
            continue;
        };
        selected_mailbox = Some(mailbox_name);
        selected_uid = Some(uid);
        selected_selection = Some(selection);
        break;
    }

    let selected_mailbox = selected_mailbox.ok_or_else(|| {
        anyhow::anyhow!("real upstream account does not contain a mailbox with messages")
    })?;
    let selected_uid = selected_uid.unwrap();
    let selected_selection = selected_selection.unwrap_or_default();
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: &selected_mailbox,
            canonical_name: &selected_mailbox.to_ascii_lowercase(),
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: if selected_mailbox.eq_ignore_ascii_case("INBOX") {
                Some("\\Inbox")
            } else {
                None
            },
            uidvalidity: selected_selection.uidvalidity,
            uidnext: selected_selection.uidnext,
            highestmodseq: selected_selection.highestmodseq,
            exists_count: selected_selection.exists.unwrap_or_default(),
            recent_count: selected_selection.recent.unwrap_or_default(),
            unseen_count: selected_selection.unseen.unwrap_or_default(),
        })
        .await?;
    repo.put_sync_state(imap_cache_rs::db::repository::NewSyncState {
        account_id: account.id,
        mailbox_id: Some(mailbox.id),
        state_json: serde_json::json!({
            "mailbox_name": selected_mailbox.clone(),
            "uidvalidity": selected_selection.uidvalidity,
            "last_uid": (selected_uid as i64) - 1,
        }),
        last_success_at: Some(chrono::Utc::now()),
        last_attempt_at: Some(chrono::Utc::now()),
        last_error: None,
    })
    .await?;
    let synced = tokio::time::timeout(
        Duration::from_secs(120),
        sync_engine.sync_mailbox(account.id, &selected_mailbox, &mut upstream),
    )
    .await??;
    assert_eq!(synced, 1);

    let refreshed_mailbox = repo
        .find_mailbox(account.id, &selected_mailbox)
        .await?
        .ok_or_else(|| anyhow::anyhow!("synced mailbox disappeared from local store"))?;
    let local_messages = repo.list_mailbox_messages(refreshed_mailbox.id).await?;
    assert_eq!(local_messages.len(), 1);
    let local_uid = local_messages[0].local_uid;

    let message_view = repo
        .list_mailbox_message_views(refreshed_mailbox.id)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("synced message view missing from local store"))?;
    let search_token_source = message_view
        .subject
        .clone()
        .or(message_view.text_preview.clone())
        .ok_or_else(|| anyhow::anyhow!("synced message did not contain searchable text"))?;
    let search_token = search_token_source
        .split_whitespace()
        .find_map(|part| {
            let token = part.trim_matches(|ch: char| !ch.is_ascii_alphanumeric());
            (!token.is_empty()).then(|| token.to_string())
        })
        .ok_or_else(|| anyhow::anyhow!("could not derive a live search token"))?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn imap_cache_rs::storage::ObjectStore>,
        search: Some(search.clone() as Arc<dyn SearchBackend>),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::clone(&metrics),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(format!("A4 SELECT \"{}\"\r\n", selected_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut select_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        select_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        select_lines.iter().any(|line| line.contains("* 1 EXISTS")),
        "{select_lines:?}"
    );

    stream
        .get_mut()
        .write_all(
            format!(
                "A5 SEARCH TEXT \"{}\"\r\n",
                search_token
            )
            .as_bytes(),
        )
        .await?;
    stream.get_mut().flush().await?;
    let mut search_or_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A5 ");
        search_or_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        search_or_lines
            .last()
            .is_some_and(|line| line.starts_with("A5 OK")),
        "{search_or_lines:?}"
    );
    assert!(
        search_or_lines
            .iter()
            .any(|line| line.trim_end() == "* SEARCH 1"),
        "{search_or_lines:?}"
    );

    stream
        .get_mut()
        .write_all(
            format!(
                "A6 UID SEARCH RETURN (COUNT MIN MAX ALL) TEXT \"{}\"\r\n",
                search_token
            )
            .as_bytes(),
        )
        .await?;
    stream.get_mut().flush().await?;
    let mut esearch_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A6 ");
        esearch_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        esearch_lines
            .last()
            .is_some_and(|line| line.starts_with("A6 OK")),
        "{esearch_lines:?}"
    );
    assert!(
        esearch_lines.iter().any(|line| line.trim_end()
            == format!(
                r#"* ESEARCH (TAG "A6") COUNT 1 MIN {local_uid} MAX {local_uid} ALL {local_uid}"#
            )),
        "{esearch_lines:?}"
    );

    stream.get_mut().write_all(b"A7 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A7 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn imap_connection_records_session_lifecycle() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let user_email = format!("session-{}@example.test", Uuid::new_v4());
    let password = "secret";
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let _account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Session Test",
            email_address: &user_email,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut client_stream = BufReader::new(client);

    let mut greeting = String::new();
    client_stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    client_stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", user_email, password).as_bytes())
        .await?;
    client_stream.get_mut().flush().await?;
    let mut login_lines = Vec::new();
    loop {
        let mut line = String::new();
        client_stream.read_line(&mut line).await?;
        let done = line.starts_with("A1 OK");
        login_lines.push(line);
        if done {
            break;
        }
    }
    assert!(login_lines.iter().any(|line| line.starts_with("A1 OK")));

    client_stream.get_mut().write_all(b"A2 LOGOUT\r\n").await?;
    client_stream.get_mut().flush().await?;
    let mut logout_lines = Vec::new();
    loop {
        let mut line = String::new();
        client_stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        logout_lines.push(line);
        if done {
            break;
        }
    }
    assert!(logout_lines.iter().any(|line| line.starts_with("* BYE")));

    drop(client_stream);
    let mut disconnected = None;
    for _ in 0..50 {
        let session: (
            uuid::Uuid,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
        ) = sqlx::query_as(
            "SELECT connection_id, remote_addr, authenticated_at, disconnected_at FROM sessions WHERE user_id = $1 ORDER BY id DESC LIMIT 1",
        )
        .bind(user.id)
        .fetch_one(repo.pool())
        .await?;
        if session.3.is_some() {
            disconnected = Some(session);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let session = disconnected.ok_or_else(|| anyhow::anyhow!("session disconnect was not recorded"))?;
    assert_ne!(session.0, uuid::Uuid::nil());
    assert!(
        session
            .1
            .as_deref()
            .is_some_and(|remote| remote.contains(&addr.ip().to_string()))
    );
    assert!(session.2.is_some());
    assert!(session.3.is_some());

    server.abort();
    let _ = server.await;

    Ok(())
}

#[tokio::test]
async fn append_literal_is_fetchable_over_imap() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let store: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
    let mutations = imap_cache_rs::sync::MutationEngine::new(repo.clone(), store.clone());

    let user_email = format!("append-fetch-{}@example.test", Uuid::new_v4());
    let password = "secret";
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Append Fetch Test",
            email_address: &user_email,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let mailbox_name = format!("imap-cache-rs-{}", Uuid::new_v4());
    let mailbox_canonical = mailbox_name.to_ascii_lowercase();
    repo.upsert_mailbox(NewMailbox {
        account_id: account.id,
        name: &mailbox_name,
        canonical_name: &mailbox_canonical,
        delimiter: Some("/"),
        attributes: vec!["\\HasNoChildren".to_string()],
        subscribed: true,
        special_use: None,
        uidvalidity: Some(1),
        uidnext: Some(1),
        highestmodseq: Some(0),
        exists_count: 0,
        recent_count: 0,
        unseen_count: 0,
    })
    .await?;
    let object_store: Arc<dyn ObjectStore> = store.clone();

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store,
        search: None,
        sync_engine: None,
        mutation_engine: Some(Arc::new(mutations)),
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut client_stream = BufReader::new(client);

    let mut greeting = String::new();
    client_stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    client_stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", user_email, password).as_bytes())
        .await?;
    client_stream.get_mut().flush().await?;
    let mut login_lines = Vec::new();
    loop {
        let mut line = String::new();
        client_stream.read_line(&mut line).await?;
        let done = line.starts_with("A1 OK");
        login_lines.push(line);
        if done {
            break;
        }
    }
    assert!(login_lines.iter().any(|line| line.starts_with("A1 OK")));

    client_stream
        .get_mut()
        .write_all(format!("A2 SELECT {}\r\n", mailbox_name).as_bytes())
        .await?;
    client_stream.get_mut().flush().await?;
    let mut select_lines = Vec::new();
    loop {
        let mut line = String::new();
        client_stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        select_lines.push(line);
        if done {
            break;
        }
    }
    assert!(select_lines.iter().any(|line| line.contains("EXISTS")));

    let raw = concat!(
        "From: Append Fetch <append-fetch@example.test>\r\n",
        "Subject: IMAP append fetch\r\n",
        "Message-ID: <append-fetch@example.test>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "This body must be readable back from the local cache.\r\n"
    )
    .as_bytes()
    .to_vec();

    client_stream
        .get_mut()
        .write_all(
            format!(
                "A3 APPEND {} (\\Seen) \"12-Feb-2024 10:00:00 +0000\" {{{}}}\r\n",
                mailbox_name,
                raw.len()
            )
            .as_bytes(),
        )
        .await?;
    client_stream.get_mut().flush().await?;

    let mut continuation = String::new();
    client_stream.read_line(&mut continuation).await?;
    assert!(continuation.starts_with("+ "));

    client_stream.get_mut().write_all(&raw).await?;
    client_stream.get_mut().flush().await?;

    let mut append_lines = Vec::new();
    loop {
        let mut line = String::new();
        client_stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        append_lines.push(line);
        if done {
            break;
        }
    }
    let append_joined = append_lines.join("");
    assert!(append_joined.contains("APPEND queued"));
    assert!(append_joined.contains("[APPENDUID 1 1]"));

    client_stream
        .get_mut()
        .write_all(b"A4 FETCH 1 (BODY[])\r\nA5 LOGOUT\r\n")
        .await?;
    client_stream.get_mut().flush().await?;
    client_stream.get_mut().shutdown().await?;

    let mut output = Vec::new();
    client_stream.read_to_end(&mut output).await?;
    let text = String::from_utf8_lossy(&output);
    assert!(text.contains("* 1 FETCH (BODY[] {"));
    assert!(text.contains("This body must be readable back from the local cache."));
    assert!(text.contains("A4 OK FETCH completed"));
    assert!(text.contains("* BYE IMAP cache proxy logging out"));

    server.abort();
    let _ = server.await;

    Ok(())
}

#[tokio::test]
async fn live_imap_server_serves_real_upstream_synced_message() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let store: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = imap_cache_rs::sync::MessageIngestor::new(
        repo.clone(),
        store.clone(),
        Some(search.clone()),
    );
    let metrics = Arc::new(imap_cache_rs::metrics::AppMetrics::new());
    let sync_engine = imap_cache_rs::sync::SyncEngine::new(
        repo.clone(),
        ingestor,
        Arc::clone(&metrics),
    );
    let local_email = format!("live-imap-{}@example.test", Uuid::new_v4());
    let password = "secret";

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live IMAP",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let mut upstream =
        tokio::time::timeout(Duration::from_secs(60), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(60), upstream.capability()).await??;
    tokio::time::timeout(
        Duration::from_secs(60),
        upstream.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;

    let mailboxes = tokio::time::timeout(Duration::from_secs(60), upstream.list_mailboxes()).await??;
    let mut selected_mailbox: Option<String> = None;
    let mut selected_uid: Option<u64> = None;
    let mut selected_selection: Option<imap_cache_rs::upstream::SelectedMailboxInfo> = None;
    let mut selected_raw: Option<Vec<u8>> = None;
    for mailbox_name in mailboxes {
        let selection =
            tokio::time::timeout(Duration::from_secs(60), upstream.select_mailbox(&mailbox_name))
                .await??;
        let uids = tokio::time::timeout(Duration::from_secs(60), upstream.uid_search_all()).await??;
        let Some(uid) = uids.into_iter().max() else {
            continue;
        };
        let raw = tokio::time::timeout(Duration::from_secs(60), upstream.uid_fetch_rfc822(uid))
            .await??;
        selected_mailbox = Some(mailbox_name);
        selected_uid = Some(uid);
        selected_selection = Some(selection);
        selected_raw = Some(raw);
        break;
    }

    let selected_mailbox = selected_mailbox.ok_or_else(|| {
        anyhow::anyhow!("real upstream account does not contain a mailbox with messages")
    })?;
    let selected_uid = selected_uid.unwrap();
    let selected_selection = selected_selection.unwrap_or_default();
    let selected_raw = selected_raw.unwrap();
    let parsed = parse_message(&selected_raw)?;
    let search_term = parsed
        .text_preview
        .as_deref()
        .or(parsed.subject.as_deref())
        .and_then(|value| {
            value
                .split(|c: char| !c.is_ascii_alphanumeric())
                .find(|token| token.len() >= 6)
        })
        .unwrap_or("message")
        .to_string();
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: &selected_mailbox,
            canonical_name: &selected_mailbox.to_ascii_lowercase(),
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: if selected_mailbox.eq_ignore_ascii_case("INBOX") {
                Some("\\Inbox")
            } else {
                None
            },
            uidvalidity: selected_selection.uidvalidity,
            uidnext: selected_selection.uidnext,
            highestmodseq: selected_selection.highestmodseq,
            exists_count: selected_selection.exists.unwrap_or_default(),
            recent_count: selected_selection.recent.unwrap_or_default(),
            unseen_count: selected_selection.unseen.unwrap_or_default(),
        })
        .await?;
    repo.put_sync_state(imap_cache_rs::db::repository::NewSyncState {
        account_id: account.id,
        mailbox_id: Some(mailbox.id),
        state_json: serde_json::json!({
            "mailbox_name": selected_mailbox,
            "uidvalidity": selected_selection.uidvalidity,
            "last_uid": (selected_uid as i64) - 1,
        }),
        last_success_at: Some(chrono::Utc::now()),
        last_attempt_at: Some(chrono::Utc::now()),
        last_error: None,
    })
    .await?;
    let synced = tokio::time::timeout(
        Duration::from_secs(120),
        sync_engine.sync_mailbox(account.id, &selected_mailbox, &mut upstream),
    )
    .await??;
    assert_eq!(synced, 1);

    let refreshed_mailbox = repo
        .find_mailbox(account.id, &selected_mailbox)
        .await?
        .ok_or_else(|| anyhow::anyhow!("synced mailbox disappeared from local store"))?;
    let local_messages = repo.list_mailbox_messages(refreshed_mailbox.id).await?;
    assert_eq!(local_messages.len(), 1);
    let local_uid = local_messages[0].local_uid;
    let object_store: Arc<dyn imap_cache_rs::storage::ObjectStore> = store.clone();
    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store,
        search: Some(search.clone() as Arc<dyn SearchBackend>),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::clone(&metrics),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut client_stream = BufReader::new(client);

    let mut greeting = String::new();
    client_stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    client_stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    client_stream.get_mut().flush().await?;
    let mut login_lines = Vec::new();
    loop {
        let mut line = String::new();
        client_stream.read_line(&mut line).await?;
        let done = line.starts_with("A1 OK");
        login_lines.push(line);
        if done {
            break;
        }
    }
    assert!(login_lines.iter().any(|line| line.starts_with("A1 OK")));

    client_stream
        .get_mut()
        .write_all(
            format!("A2 SELECT \"{}\"\r\n", selected_mailbox.replace('"', "\\\"")).as_bytes(),
        )
        .await?;
    client_stream.get_mut().flush().await?;
    let mut select_lines = Vec::new();
    loop {
        let mut line = String::new();
        client_stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        select_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        select_lines
            .iter()
            .any(|line| line.contains(&format!("* 1 EXISTS"))),
        "{select_lines:?}"
    );

    client_stream
        .get_mut()
        .write_all(format!("A3 UID SEARCH ALL\r\n").as_bytes())
        .await?;
    client_stream.get_mut().flush().await?;
    let mut search_lines = Vec::new();
    loop {
        let mut line = String::new();
        client_stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        search_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        search_lines
            .iter()
            .any(|line| line.trim_end() == format!("* SEARCH {local_uid}")),
        "{search_lines:?}"
    );

    client_stream
        .get_mut()
        .write_all(format!("A4 SEARCH TEXT \"{}\"\r\n", search_term).as_bytes())
        .await?;
    client_stream.get_mut().flush().await?;
    let mut text_search_lines = Vec::new();
    loop {
        let mut line = String::new();
        client_stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        text_search_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        text_search_lines
            .iter()
            .any(|line| line.trim_end() == "* SEARCH 1"),
        "{text_search_lines:?}"
    );

    let fetch_command = format!(
        "A5 UID FETCH {local_uid} (FLAGS UID RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[])\r\n"
    );
    client_stream.get_mut().write_all(fetch_command.as_bytes()).await?;
    client_stream.get_mut().flush().await?;
    let mut fetch_lines = Vec::new();
    let mut fetched_body = Vec::new();
    let mut fetch_tag_seen = false;
    while !fetch_tag_seen {
        let mut line = String::new();
        client_stream.read_line(&mut line).await?;
        if line.is_empty() {
            continue;
        }
        if line.starts_with("* ") && line.contains("FETCH") && line.contains('{') && line.ends_with("}\r\n") {
            let size = literal_size(&line)?;
            let mut bytes = vec![0; size];
            client_stream.read_exact(&mut bytes).await?;
            fetched_body = bytes;
            fetch_lines.push(line);
            continue;
        }
        fetch_tag_seen = line.starts_with("A5 OK");
        fetch_lines.push(line);
    }
    assert_eq!(fetched_body, selected_raw);
    assert!(
        fetch_lines.iter().any(|line| line.contains(&format!("UID {local_uid}"))),
        "{fetch_lines:?}"
    );
    assert!(
        fetch_lines
            .iter()
            .any(|line| line.contains(&format!("RFC822.SIZE {}", parsed.size_octets))),
        "{fetch_lines:?}"
    );
    assert!(
        fetch_lines.iter().any(|line| line.contains("BODYSTRUCTURE")),
        "{fetch_lines:?}"
    );

    client_stream.get_mut().write_all(b"A6 LOGOUT\r\n").await?;
    client_stream.get_mut().flush().await?;
    let mut logout_lines = Vec::new();
    loop {
        let mut line = String::new();
        client_stream.read_line(&mut line).await?;
        let done = line.starts_with("A6 OK");
        logout_lines.push(line);
        if done {
            break;
        }
    }
    assert!(logout_lines.iter().any(|line| line.starts_with("* BYE")));

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_examines_real_mailbox_read_only() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = imap_cache_rs::sync::MessageIngestor::new(
        repo.clone(),
        store.clone(),
        Some(search.clone()),
    );
    let metrics = Arc::new(imap_cache_rs::metrics::AppMetrics::new());
    let sync_engine = imap_cache_rs::sync::SyncEngine::new(
        repo.clone(),
        ingestor,
        Arc::clone(&metrics),
    );
    let local_email = format!("live-examine-{}@example.test", Uuid::new_v4());
    let password = "secret";

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Examine",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let mut upstream =
        tokio::time::timeout(Duration::from_secs(60), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(60), upstream.capability()).await??;
    tokio::time::timeout(
        Duration::from_secs(60),
        upstream.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;

    let mailboxes = tokio::time::timeout(Duration::from_secs(60), upstream.list_mailboxes()).await??;
    let mut selected_mailbox: Option<String> = None;
    let mut selected_uid: Option<u64> = None;
    let mut selected_selection: Option<imap_cache_rs::upstream::SelectedMailboxInfo> = None;
    for mailbox_name in mailboxes {
        let selection =
            tokio::time::timeout(Duration::from_secs(60), upstream.select_mailbox(&mailbox_name))
                .await??;
        let uids = tokio::time::timeout(Duration::from_secs(60), upstream.uid_search_all()).await??;
        let Some(uid) = uids.into_iter().max() else {
            continue;
        };
        selected_mailbox = Some(mailbox_name);
        selected_uid = Some(uid);
        selected_selection = Some(selection);
        break;
    }

    let selected_mailbox = selected_mailbox.ok_or_else(|| {
        anyhow::anyhow!("real upstream account does not contain a mailbox with messages")
    })?;
    let selected_uid = selected_uid.unwrap();
    let selected_selection = selected_selection.unwrap_or_default();
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: &selected_mailbox,
            canonical_name: &selected_mailbox.to_ascii_lowercase(),
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: if selected_mailbox.eq_ignore_ascii_case("INBOX") {
                Some("\\Inbox")
            } else {
                None
            },
            uidvalidity: selected_selection.uidvalidity,
            uidnext: selected_selection.uidnext,
            highestmodseq: selected_selection.highestmodseq,
            exists_count: selected_selection.exists.unwrap_or_default(),
            recent_count: selected_selection.recent.unwrap_or_default(),
            unseen_count: selected_selection.unseen.unwrap_or_default(),
        })
        .await?;
    repo.put_sync_state(imap_cache_rs::db::repository::NewSyncState {
        account_id: account.id,
        mailbox_id: Some(mailbox.id),
        state_json: serde_json::json!({
            "mailbox_name": selected_mailbox.clone(),
            "uidvalidity": selected_selection.uidvalidity,
            "last_uid": (selected_uid as i64) - 1,
        }),
        last_success_at: Some(chrono::Utc::now()),
        last_attempt_at: Some(chrono::Utc::now()),
        last_error: None,
    })
    .await?;
    let synced = tokio::time::timeout(
        Duration::from_secs(120),
        sync_engine.sync_mailbox(account.id, &selected_mailbox, &mut upstream),
    )
    .await??;
    assert_eq!(synced, 1);

    let refreshed_mailbox = repo
        .find_mailbox(account.id, &selected_mailbox)
        .await?
        .ok_or_else(|| anyhow::anyhow!("synced mailbox disappeared from local store"))?;
    let local_messages = repo.list_mailbox_messages(refreshed_mailbox.id).await?;
    assert_eq!(local_messages.len(), 1);

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn imap_cache_rs::storage::ObjectStore>,
        search: Some(search.clone() as Arc<dyn SearchBackend>),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::clone(&metrics),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(format!("A2 EXAMINE \"{}\"\r\n", selected_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut examine_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        examine_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        examine_lines
            .iter()
            .any(|line| line.contains("[READ-ONLY] EXAMINE completed")),
        "{examine_lines:?}"
    );

    stream
        .get_mut()
        .write_all(b"A3 STORE 1 +FLAGS (\\Seen)\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut store_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 NO") || line.starts_with("A3 BAD");
        store_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        store_lines.iter().any(|line| line.contains("[READ-ONLY]")),
        "{store_lines:?}"
    );

    stream.get_mut().write_all(b"A4 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    let mut logout = String::new();
    stream.read_line(&mut logout).await?;
    assert!(logout.starts_with("* BYE"));

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_idle_fanout_for_synced_real_message() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let events = Arc::new(MailboxEventHub::new(16));
    let repo = Arc::new(
        PostgresRepository::new(
            pool,
            security::SecretBox::from_passphrase("test-master-key"),
        )
        .with_event_sink(Arc::new(HubMutationEventSink::new(Arc::clone(&events)))),
    );
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = imap_cache_rs::sync::MessageIngestor::new(
        repo.clone(),
        store.clone(),
        Some(search.clone()),
    );
    let metrics = Arc::new(imap_cache_rs::metrics::AppMetrics::new());
    let sync_engine = imap_cache_rs::sync::SyncEngine::new(
        repo.clone(),
        ingestor,
        Arc::clone(&metrics),
    );
    let local_email = format!("live-idle-{}@example.test", Uuid::new_v4());
    let password = "secret";

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Idle",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let mut upstream =
        tokio::time::timeout(Duration::from_secs(60), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(60), upstream.capability()).await??;
    tokio::time::timeout(
        Duration::from_secs(60),
        upstream.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;

    let mailboxes = tokio::time::timeout(Duration::from_secs(60), upstream.list_mailboxes()).await??;
    let mut selected_mailbox: Option<String> = None;
    let mut selected_uid: Option<u64> = None;
    let mut selected_selection: Option<imap_cache_rs::upstream::SelectedMailboxInfo> = None;
    for mailbox_name in mailboxes {
        let selection =
            tokio::time::timeout(Duration::from_secs(60), upstream.select_mailbox(&mailbox_name))
                .await??;
        let uids = tokio::time::timeout(Duration::from_secs(60), upstream.uid_search_all()).await??;
        let Some(uid) = uids.into_iter().max() else {
            continue;
        };
        selected_mailbox = Some(mailbox_name);
        selected_uid = Some(uid);
        selected_selection = Some(selection);
        break;
    }

    let selected_mailbox = selected_mailbox.ok_or_else(|| {
        anyhow::anyhow!("real upstream account does not contain a mailbox with messages")
    })?;
    let selected_uid = selected_uid.unwrap();
    let selected_selection = selected_selection.unwrap_or_default();
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: &selected_mailbox,
            canonical_name: &selected_mailbox.to_ascii_lowercase(),
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: if selected_mailbox.eq_ignore_ascii_case("INBOX") {
                Some("\\Inbox")
            } else {
                None
            },
            uidvalidity: selected_selection.uidvalidity,
            uidnext: selected_selection.uidnext,
            highestmodseq: selected_selection.highestmodseq,
            exists_count: selected_selection.exists.unwrap_or_default(),
            recent_count: selected_selection.recent.unwrap_or_default(),
            unseen_count: selected_selection.unseen.unwrap_or_default(),
        })
        .await?;
    repo.put_sync_state(imap_cache_rs::db::repository::NewSyncState {
        account_id: account.id,
        mailbox_id: Some(mailbox.id),
        state_json: serde_json::json!({
            "mailbox_name": selected_mailbox,
            "uidvalidity": selected_selection.uidvalidity,
            "last_uid": (selected_uid as i64) - 1,
        }),
        last_success_at: Some(chrono::Utc::now()),
        last_attempt_at: Some(chrono::Utc::now()),
        last_error: None,
    })
    .await?;
    let synced = tokio::time::timeout(
        Duration::from_secs(120),
        sync_engine.sync_mailbox(account.id, &selected_mailbox, &mut upstream),
    )
    .await??;
    assert_eq!(synced, 1);

    let refreshed_mailbox = repo
        .find_mailbox(account.id, &selected_mailbox)
        .await?
        .ok_or_else(|| anyhow::anyhow!("synced mailbox disappeared from local store"))?;
    let local_messages = repo.list_mailbox_messages(refreshed_mailbox.id).await?;
    assert_eq!(local_messages.len(), 1);
    let _local_uid = local_messages[0].local_uid;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn imap_cache_rs::storage::ObjectStore>,
        search: Some(search.clone() as Arc<dyn SearchBackend>),
        sync_engine: None,
        mutation_engine: None,
        events,
        metrics: Arc::clone(&metrics),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client_a = tokio::net::TcpStream::connect(addr).await?;
    let mut a = BufReader::new(client_a);

    let mut greeting = String::new();
    a.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));
    a.get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    a.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        a.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }
    a.get_mut()
        .write_all(format!("A2 SELECT \"{}\"\r\n", selected_mailbox).as_bytes())
        .await?;
    a.get_mut().flush().await?;
    let mut select_lines = Vec::new();
    loop {
        let mut line = String::new();
        a.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        select_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        select_lines
            .iter()
            .any(|line| line.contains(&format!("* 1 EXISTS"))),
        "{select_lines:?}"
    );

    a.get_mut().write_all(b"A3 IDLE\r\n").await?;
    a.get_mut().flush().await?;
    let mut idle_ready = String::new();
    a.read_line(&mut idle_ready).await?;
    assert!(idle_ready.starts_with("+ idling"));

    let b_client = tokio::net::TcpStream::connect(addr).await?;
    let mut b = BufReader::new(b_client);
    let mut greeting_b = String::new();
    b.read_line(&mut greeting_b).await?;
    assert!(greeting_b.starts_with("* OK"));
    b.get_mut()
        .write_all(format!("B1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    b.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        b.read_line(&mut line).await?;
        if line.starts_with("B1 OK") {
            break;
        }
    }
    b.get_mut()
        .write_all(format!("B2 SELECT \"{}\"\r\n", selected_mailbox).as_bytes())
        .await?;
    b.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        b.read_line(&mut line).await?;
        if line.starts_with("B2 OK") {
            break;
        }
    }

    let idle_keyword = format!("LIVEIDLE{}", Uuid::new_v4().simple());
    b.get_mut()
        .write_all(format!("B3 STORE 1 +FLAGS ({idle_keyword})\r\n").as_bytes())
        .await?;
    b.get_mut().flush().await?;
    let mut store_lines = Vec::new();
    loop {
        let mut line = String::new();
        b.read_line(&mut line).await?;
        let done = line.starts_with("B3 OK");
        store_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        store_lines.iter().any(|line| line.starts_with("B3 OK")),
        "{store_lines:?}"
    );

    let mut saw_notification = false;
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    let mut idle_lines = Vec::new();
    loop {
        tokio::select! {
            _ = &mut deadline => {
                break;
            }
            result = async {
                let mut line = String::new();
                let bytes = a.read_line(&mut line).await?;
                Ok::<_, std::io::Error>((bytes, line))
            } => {
                let (bytes, line) = result?;
                if bytes == 0 {
                    break;
                }
                if line.contains(&idle_keyword) {
                    saw_notification = true;
                    idle_lines.push(line);
                    a.get_mut().write_all(b"DONE\r\n").await?;
                    a.get_mut().flush().await?;
                    break;
                }
                idle_lines.push(line);
            }
        }
    }
    assert!(saw_notification, "{idle_lines:?}");

    loop {
        let mut line = String::new();
        a.read_line(&mut line).await?;
        if line.starts_with("A3 OK") {
            break;
        }
    }

    b.get_mut().write_all(b"B4 LOGOUT\r\n").await?;
    b.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        b.read_line(&mut line).await?;
        if line.starts_with("B4 OK") {
            break;
        }
    }

    a.get_mut().write_all(b"A4 LOGOUT\r\n").await?;
    a.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        a.read_line(&mut line).await?;
        if line.starts_with("A4 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_store_and_expunge_synced_real_message() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = imap_cache_rs::sync::MessageIngestor::new(
        repo.clone(),
        store.clone(),
        Some(search.clone()),
    );
    let metrics = Arc::new(imap_cache_rs::metrics::AppMetrics::new());
    let sync_engine = imap_cache_rs::sync::SyncEngine::new(
        repo.clone(),
        ingestor,
        Arc::clone(&metrics),
    );
    let local_email = format!("live-expunge-{}@example.test", Uuid::new_v4());
    let password = "secret";

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Expunge",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let mut upstream =
        tokio::time::timeout(Duration::from_secs(60), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(60), upstream.capability()).await??;
    tokio::time::timeout(
        Duration::from_secs(60),
        upstream.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;

    let mailboxes = tokio::time::timeout(Duration::from_secs(60), upstream.list_mailboxes()).await??;
    let mut selected_mailbox: Option<String> = None;
    let mut selected_uid: Option<u64> = None;
    let mut selected_selection: Option<imap_cache_rs::upstream::SelectedMailboxInfo> = None;
    for mailbox_name in mailboxes {
        let selection =
            tokio::time::timeout(Duration::from_secs(60), upstream.select_mailbox(&mailbox_name))
                .await??;
        let uids = tokio::time::timeout(Duration::from_secs(60), upstream.uid_search_all()).await??;
        let Some(uid) = uids.into_iter().max() else {
            continue;
        };
        selected_mailbox = Some(mailbox_name);
        selected_uid = Some(uid);
        selected_selection = Some(selection);
        break;
    }

    let selected_mailbox = selected_mailbox.ok_or_else(|| {
        anyhow::anyhow!("real upstream account does not contain a mailbox with messages")
    })?;
    let selected_uid = selected_uid.unwrap();
    let selected_selection = selected_selection.unwrap_or_default();
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: &selected_mailbox,
            canonical_name: &selected_mailbox.to_ascii_lowercase(),
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: if selected_mailbox.eq_ignore_ascii_case("INBOX") {
                Some("\\Inbox")
            } else {
                None
            },
            uidvalidity: selected_selection.uidvalidity,
            uidnext: selected_selection.uidnext,
            highestmodseq: selected_selection.highestmodseq,
            exists_count: selected_selection.exists.unwrap_or_default(),
            recent_count: selected_selection.recent.unwrap_or_default(),
            unseen_count: selected_selection.unseen.unwrap_or_default(),
        })
        .await?;
    repo.put_sync_state(imap_cache_rs::db::repository::NewSyncState {
        account_id: account.id,
        mailbox_id: Some(mailbox.id),
        state_json: serde_json::json!({
            "mailbox_name": selected_mailbox,
            "uidvalidity": selected_selection.uidvalidity,
            "last_uid": (selected_uid as i64) - 1,
        }),
        last_success_at: Some(chrono::Utc::now()),
        last_attempt_at: Some(chrono::Utc::now()),
        last_error: None,
    })
    .await?;
    let synced = tokio::time::timeout(
        Duration::from_secs(120),
        sync_engine.sync_mailbox(account.id, &selected_mailbox, &mut upstream),
    )
    .await??;
    assert_eq!(synced, 1);

    let refreshed_mailbox = repo
        .find_mailbox(account.id, &selected_mailbox)
        .await?
        .ok_or_else(|| anyhow::anyhow!("synced mailbox disappeared from local store"))?;
    let local_messages = repo.list_mailbox_messages(refreshed_mailbox.id).await?;
    assert_eq!(local_messages.len(), 1);
    let _local_uid = local_messages[0].local_uid;
    let upstream_uid = local_messages[0]
        .upstream_uid
        .ok_or_else(|| anyhow::anyhow!("synced real message is missing upstream uid"))?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn imap_cache_rs::storage::ObjectStore>,
        search: Some(search.clone() as Arc<dyn SearchBackend>),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::clone(&metrics),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(format!("A2 SELECT \"{}\"\r\n", selected_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut select_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        select_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        select_lines
            .iter()
            .any(|line| line.contains(&format!("* 1 EXISTS"))),
        "{select_lines:?}"
    );

    stream
        .get_mut()
        .write_all(b"A3 STORE 1 +FLAGS.SILENT (\\Seen)\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut silent_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        silent_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        silent_lines.iter().all(|line| !line.contains("FETCH")),
        "{silent_lines:?}"
    );
    assert!(
        repo.list_mailbox_messages(mailbox.id)
            .await?[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Seen")),
        "silent STORE should update local flags"
    );

    stream
        .get_mut()
        .write_all(format!("A4 UID STORE {upstream_uid} +FLAGS (\\Deleted)\r\n").as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut store_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        store_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        store_lines.iter().any(|line| line.starts_with("A4 OK")),
        "{store_lines:?}"
    );

    stream
        .get_mut()
        .write_all(format!("A5 UID EXPUNGE {upstream_uid}\r\n").as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut expunge_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A5 OK");
        expunge_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        expunge_lines.iter().any(|line| line.starts_with("A5 OK")),
        "{expunge_lines:?}"
    );

    assert!(repo.list_mailbox_messages(mailbox.id).await?.is_empty());

    stream.get_mut().write_all(b"A6 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A6 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_copy_and_move_synced_real_message() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = imap_cache_rs::sync::MessageIngestor::new(
        repo.clone(),
        store.clone(),
        Some(search.clone()),
    );
    let metrics = Arc::new(imap_cache_rs::metrics::AppMetrics::new());
    let sync_engine = imap_cache_rs::sync::SyncEngine::new(
        repo.clone(),
        ingestor,
        Arc::clone(&metrics),
    );
    let local_email = format!("live-copy-move-{}@example.test", Uuid::new_v4());
    let password = "secret";

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Copy Move",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let mut upstream =
        tokio::time::timeout(Duration::from_secs(60), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(60), upstream.capability()).await??;
    tokio::time::timeout(
        Duration::from_secs(60),
        upstream.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;

    let mailboxes = tokio::time::timeout(Duration::from_secs(60), upstream.list_mailboxes()).await??;
    let mut selected_mailbox: Option<String> = None;
    let mut selected_uid: Option<u64> = None;
    let mut selected_selection: Option<imap_cache_rs::upstream::SelectedMailboxInfo> = None;
    for mailbox_name in mailboxes {
        let selection =
            tokio::time::timeout(Duration::from_secs(60), upstream.select_mailbox(&mailbox_name))
                .await??;
        let uids = tokio::time::timeout(Duration::from_secs(60), upstream.uid_search_all()).await??;
        let Some(uid) = uids.into_iter().max() else {
            continue;
        };
        selected_mailbox = Some(mailbox_name);
        selected_uid = Some(uid);
        selected_selection = Some(selection);
        break;
    }

    let selected_mailbox = selected_mailbox.ok_or_else(|| {
        anyhow::anyhow!("real upstream account does not contain a mailbox with messages")
    })?;
    let selected_uid = selected_uid.unwrap();
    let selected_selection = selected_selection.unwrap_or_default();
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: &selected_mailbox,
            canonical_name: &selected_mailbox.to_ascii_lowercase(),
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: if selected_mailbox.eq_ignore_ascii_case("INBOX") {
                Some("\\Inbox")
            } else {
                None
            },
            uidvalidity: selected_selection.uidvalidity,
            uidnext: selected_selection.uidnext,
            highestmodseq: selected_selection.highestmodseq,
            exists_count: selected_selection.exists.unwrap_or_default(),
            recent_count: selected_selection.recent.unwrap_or_default(),
            unseen_count: selected_selection.unseen.unwrap_or_default(),
        })
        .await?;
    repo.put_sync_state(imap_cache_rs::db::repository::NewSyncState {
        account_id: account.id,
        mailbox_id: Some(mailbox.id),
        state_json: serde_json::json!({
            "mailbox_name": selected_mailbox,
            "uidvalidity": selected_selection.uidvalidity,
            "last_uid": (selected_uid as i64) - 1,
        }),
        last_success_at: Some(chrono::Utc::now()),
        last_attempt_at: Some(chrono::Utc::now()),
        last_error: None,
    })
    .await?;
    let synced = tokio::time::timeout(
        Duration::from_secs(120),
        sync_engine.sync_mailbox(account.id, &selected_mailbox, &mut upstream),
    )
    .await??;
    assert_eq!(synced, 1);

    let refreshed_mailbox = repo
        .find_mailbox(account.id, &selected_mailbox)
        .await?
        .ok_or_else(|| anyhow::anyhow!("synced mailbox disappeared from local store"))?;
    let local_messages = repo.list_mailbox_messages(refreshed_mailbox.id).await?;
    assert_eq!(local_messages.len(), 1);
    let source_local_uid = local_messages[0].local_uid;

    let copy_mailbox = format!("live-copy-{}", Uuid::new_v4());
    let move_mailbox = format!("live-move-{}", Uuid::new_v4());

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn imap_cache_rs::storage::ObjectStore>,
        search: Some(search.clone() as Arc<dyn SearchBackend>),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::clone(&metrics),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(format!("A2 CREATE \"{}\"\r\n", copy_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A2 OK") {
            break;
        }
    }
    stream
        .get_mut()
        .write_all(format!("A3 CREATE \"{}\"\r\n", move_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A3 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(format!("A4 SELECT \"{}\"\r\n", selected_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut select_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        select_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        select_lines
            .iter()
            .any(|line| line.contains(&format!("* 1 EXISTS"))),
        "{select_lines:?}"
    );

    stream
        .get_mut()
        .write_all(format!("A5 UID COPY {source_local_uid} \"{}\"\r\n", copy_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut copy_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A5 OK");
        copy_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        copy_lines.iter().any(|line| line.contains("COPYUID")),
        "{copy_lines:?}"
    );

    stream
        .get_mut()
        .write_all(format!("A6 UID MOVE {source_local_uid} \"{}\"\r\n", move_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut move_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A6 OK");
        move_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        move_lines.iter().any(|line| line.contains("COPYUID")),
        "{move_lines:?}"
    );

    let source_after = repo.list_mailbox_messages(mailbox.id).await?;
    assert!(source_after.is_empty(), "{source_after:?}");

    stream
        .get_mut()
        .write_all(format!("A7 SELECT \"{}\"\r\n", copy_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A7 OK") {
            break;
        }
    }
    let copy_uids = {
        stream.get_mut().write_all(b"A8 UID SEARCH ALL\r\n").await?;
        stream.get_mut().flush().await?;
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            stream.read_line(&mut line).await?;
            let done = line.starts_with("A8 OK");
            lines.push(line);
            if done {
                break;
            }
        }
        let response = lines
            .iter()
            .find_map(|line| line.strip_prefix("* SEARCH "))
            .ok_or_else(|| anyhow::anyhow!("copy mailbox search response missing"))?;
        response
            .split_whitespace()
            .filter_map(|value| value.parse::<u64>().ok())
            .collect::<Vec<_>>()
    };
    assert_eq!(copy_uids.len(), 1);

    stream
        .get_mut()
        .write_all(
            format!("A9 UID STORE {} +FLAGS (\\Deleted)\r\n", copy_uids[0]).as_bytes(),
        )
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A9 OK") {
            break;
        }
    }
    stream.get_mut().write_all(b"A10 EXPUNGE\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A10 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(format!("A11 SELECT \"{}\"\r\n", move_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A11 OK") {
            break;
        }
    }
    let move_uids = {
        stream.get_mut().write_all(b"A12 UID SEARCH ALL\r\n").await?;
        stream.get_mut().flush().await?;
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            stream.read_line(&mut line).await?;
            let done = line.starts_with("A12 OK");
            lines.push(line);
            if done {
                break;
            }
        }
        let response = lines
            .iter()
            .find_map(|line| line.strip_prefix("* SEARCH "))
            .ok_or_else(|| anyhow::anyhow!("move mailbox search response missing"))?;
        response
            .split_whitespace()
            .filter_map(|value| value.parse::<u64>().ok())
            .collect::<Vec<_>>()
    };
    assert_eq!(move_uids.len(), 1);

    stream
        .get_mut()
        .write_all(
            format!("A13 UID STORE {} +FLAGS (\\Deleted)\r\n", move_uids[0]).as_bytes(),
        )
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A13 OK") {
            break;
        }
    }
    stream.get_mut().write_all(b"A14 EXPUNGE\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A14 OK") {
            break;
        }
    }

    let _ = stream
        .get_mut()
        .write_all(format!("A15 DELETE \"{}\"\r\n", copy_mailbox).as_bytes())
        .await;
    let _ = stream.get_mut().flush().await;
    loop {
        let mut line = String::new();
        if stream.read_line(&mut line).await? == 0 {
            break;
        }
        if line.starts_with("A15 OK") || line.starts_with("A15 NO") || line.starts_with("A15 BAD") {
            break;
        }
    }
    let _ = stream
        .get_mut()
        .write_all(format!("A16 DELETE \"{}\"\r\n", move_mailbox).as_bytes())
        .await;
    let _ = stream.get_mut().flush().await;
    loop {
        let mut line = String::new();
        if stream.read_line(&mut line).await? == 0 {
            break;
        }
        if line.starts_with("A16 OK") || line.starts_with("A16 NO") || line.starts_with("A16 BAD") {
            break;
        }
    }

    stream.get_mut().write_all(b"A17 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A17 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_close_expunge_synced_real_message() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = imap_cache_rs::sync::MessageIngestor::new(
        repo.clone(),
        store.clone(),
        Some(search.clone()),
    );
    let metrics = Arc::new(imap_cache_rs::metrics::AppMetrics::new());
    let sync_engine = imap_cache_rs::sync::SyncEngine::new(
        repo.clone(),
        ingestor,
        Arc::clone(&metrics),
    );
    let local_email = format!("live-close-{}@example.test", Uuid::new_v4());
    let password = "secret";

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Close",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let mut upstream =
        tokio::time::timeout(Duration::from_secs(60), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(60), upstream.capability()).await??;
    tokio::time::timeout(
        Duration::from_secs(60),
        upstream.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;

    let mailboxes = tokio::time::timeout(Duration::from_secs(60), upstream.list_mailboxes()).await??;
    let mut selected_mailbox: Option<String> = None;
    let mut selected_uid: Option<u64> = None;
    let mut selected_selection: Option<imap_cache_rs::upstream::SelectedMailboxInfo> = None;
    for mailbox_name in mailboxes {
        let selection =
            tokio::time::timeout(Duration::from_secs(60), upstream.select_mailbox(&mailbox_name))
                .await??;
        let uids = tokio::time::timeout(Duration::from_secs(60), upstream.uid_search_all()).await??;
        let Some(uid) = uids.into_iter().max() else {
            continue;
        };
        selected_mailbox = Some(mailbox_name);
        selected_uid = Some(uid);
        selected_selection = Some(selection);
        break;
    }

    let selected_mailbox = selected_mailbox.ok_or_else(|| {
        anyhow::anyhow!("real upstream account does not contain a mailbox with messages")
    })?;
    let selected_uid = selected_uid.unwrap();
    let selected_selection = selected_selection.unwrap_or_default();
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: &selected_mailbox,
            canonical_name: &selected_mailbox.to_ascii_lowercase(),
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: if selected_mailbox.eq_ignore_ascii_case("INBOX") {
                Some("\\Inbox")
            } else {
                None
            },
            uidvalidity: selected_selection.uidvalidity,
            uidnext: selected_selection.uidnext,
            highestmodseq: selected_selection.highestmodseq,
            exists_count: selected_selection.exists.unwrap_or_default(),
            recent_count: selected_selection.recent.unwrap_or_default(),
            unseen_count: selected_selection.unseen.unwrap_or_default(),
        })
        .await?;
    repo.put_sync_state(imap_cache_rs::db::repository::NewSyncState {
        account_id: account.id,
        mailbox_id: Some(mailbox.id),
        state_json: serde_json::json!({
            "mailbox_name": selected_mailbox,
            "uidvalidity": selected_selection.uidvalidity,
            "last_uid": (selected_uid as i64) - 1,
        }),
        last_success_at: Some(chrono::Utc::now()),
        last_attempt_at: Some(chrono::Utc::now()),
        last_error: None,
    })
    .await?;
    let synced = tokio::time::timeout(
        Duration::from_secs(120),
        sync_engine.sync_mailbox(account.id, &selected_mailbox, &mut upstream),
    )
    .await??;
    assert_eq!(synced, 1);

    let refreshed_mailbox = repo
        .find_mailbox(account.id, &selected_mailbox)
        .await?
        .ok_or_else(|| anyhow::anyhow!("synced mailbox disappeared from local store"))?;
    let local_messages = repo.list_mailbox_messages(refreshed_mailbox.id).await?;
    assert_eq!(local_messages.len(), 1);
    let upstream_uid = local_messages[0]
        .upstream_uid
        .ok_or_else(|| anyhow::anyhow!("synced real message is missing upstream uid"))?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn imap_cache_rs::storage::ObjectStore>,
        search: Some(search.clone() as Arc<dyn SearchBackend>),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::clone(&metrics),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(format!("A2 SELECT \"{}\"\r\n", selected_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut select_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        select_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        select_lines
            .iter()
            .any(|line| line.contains(&format!("* 1 EXISTS"))),
        "{select_lines:?}"
    );

    stream
        .get_mut()
        .write_all(format!("A3 UID STORE {upstream_uid} +FLAGS (\\Deleted)\r\n").as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A3 OK") {
            break;
        }
    }

    stream.get_mut().write_all(b"A4 CLOSE\r\n").await?;
    stream.get_mut().flush().await?;
    let mut close_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        close_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        close_lines.iter().any(|line| line.starts_with("A4 OK")),
        "{close_lines:?}"
    );
    assert!(
        close_lines.iter().all(|line| !line.contains("EXPUNGE")),
        "{close_lines:?}"
    );

    assert!(repo.list_mailbox_messages(mailbox.id).await?.is_empty());

    stream.get_mut().write_all(b"A5 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A5 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_unselect_keeps_deleted_message_intact() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = imap_cache_rs::sync::MessageIngestor::new(
        repo.clone(),
        store.clone(),
        Some(search.clone()),
    );
    let metrics = Arc::new(imap_cache_rs::metrics::AppMetrics::new());
    let sync_engine = imap_cache_rs::sync::SyncEngine::new(
        repo.clone(),
        ingestor,
        Arc::clone(&metrics),
    );
    let local_email = format!("live-unselect-{}@example.test", Uuid::new_v4());
    let password = "secret";

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Unselect",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let mut upstream =
        tokio::time::timeout(Duration::from_secs(60), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(60), upstream.capability()).await??;
    tokio::time::timeout(
        Duration::from_secs(60),
        upstream.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;

    let mailboxes = tokio::time::timeout(Duration::from_secs(60), upstream.list_mailboxes()).await??;
    let mut selected_mailbox: Option<String> = None;
    let mut selected_uid: Option<u64> = None;
    let mut selected_selection: Option<imap_cache_rs::upstream::SelectedMailboxInfo> = None;
    for mailbox_name in mailboxes {
        let selection =
            tokio::time::timeout(Duration::from_secs(60), upstream.select_mailbox(&mailbox_name))
                .await??;
        let uids = tokio::time::timeout(Duration::from_secs(60), upstream.uid_search_all()).await??;
        let Some(uid) = uids.into_iter().max() else {
            continue;
        };
        selected_mailbox = Some(mailbox_name);
        selected_uid = Some(uid);
        selected_selection = Some(selection);
        break;
    }

    let selected_mailbox = selected_mailbox.ok_or_else(|| {
        anyhow::anyhow!("real upstream account does not contain a mailbox with messages")
    })?;
    let selected_uid = selected_uid.unwrap();
    let selected_selection = selected_selection.unwrap_or_default();
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: &selected_mailbox,
            canonical_name: &selected_mailbox.to_ascii_lowercase(),
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: if selected_mailbox.eq_ignore_ascii_case("INBOX") {
                Some("\\Inbox")
            } else {
                None
            },
            uidvalidity: selected_selection.uidvalidity,
            uidnext: selected_selection.uidnext,
            highestmodseq: selected_selection.highestmodseq,
            exists_count: selected_selection.exists.unwrap_or_default(),
            recent_count: selected_selection.recent.unwrap_or_default(),
            unseen_count: selected_selection.unseen.unwrap_or_default(),
        })
        .await?;
    repo.put_sync_state(imap_cache_rs::db::repository::NewSyncState {
        account_id: account.id,
        mailbox_id: Some(mailbox.id),
        state_json: serde_json::json!({
            "mailbox_name": selected_mailbox.clone(),
            "uidvalidity": selected_selection.uidvalidity,
            "last_uid": (selected_uid as i64) - 1,
        }),
        last_success_at: Some(chrono::Utc::now()),
        last_attempt_at: Some(chrono::Utc::now()),
        last_error: None,
    })
    .await?;
    let synced = tokio::time::timeout(
        Duration::from_secs(120),
        sync_engine.sync_mailbox(account.id, &selected_mailbox, &mut upstream),
    )
    .await??;
    assert_eq!(synced, 1);

    let refreshed_mailbox = repo
        .find_mailbox(account.id, &selected_mailbox)
        .await?
        .ok_or_else(|| anyhow::anyhow!("synced mailbox disappeared from local store"))?;
    let local_messages = repo.list_mailbox_messages(refreshed_mailbox.id).await?;
    assert_eq!(local_messages.len(), 1);

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn imap_cache_rs::storage::ObjectStore>,
        search: Some(search.clone() as Arc<dyn SearchBackend>),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::clone(&metrics),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);
    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        let bytes = stream.read_line(&mut line).await?;
        assert!(bytes > 0, "unexpected EOF while waiting for A1 OK");
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(format!("A2 SELECT \"{}\"\r\n", selected_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        let bytes = stream.read_line(&mut line).await?;
        assert!(bytes > 0, "unexpected EOF while waiting for A2 OK");
        if line.starts_with("A2 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(b"A3 STORE 1 +FLAGS (\\Deleted)\r\n")
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A3 OK") {
            break;
        }
    }

    stream.get_mut().write_all(b"A4 UNSELECT\r\n").await?;
    stream.get_mut().flush().await?;
    let mut unselect_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        unselect_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        unselect_lines.iter().any(|line| line.starts_with("A4 OK")),
        "{unselect_lines:?}"
    );

    stream
        .get_mut()
        .write_all(b"A5 STORE 1 +FLAGS (\\Seen)\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut post_unselect_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A5 NO") || line.starts_with("A5 BAD");
        post_unselect_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        post_unselect_lines
            .iter()
            .any(|line| line.contains("[BADSTATE]")),
        "{post_unselect_lines:?}"
    );

    assert_eq!(repo.list_mailbox_messages(refreshed_mailbox.id).await?.len(), 1);
    assert!(
        repo.list_mailbox_messages(refreshed_mailbox.id).await?[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Deleted")),
        "UNSELECT should not expunge deleted messages"
    );

    stream.get_mut().write_all(b"A6 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A6 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_check_completes_and_preserves_selection_over_wire() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("live-check-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Check",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(1),
            exists_count: 0,
            recent_count: 1,
            unseen_count: 0,
        })
        .await?;
    repo.upsert_message(NewMessage {
        account_id: account.id,
        rfc822_blob_key: "rfc822/live-check",
        rfc822_sha256: "sha256-live-check",
        message_id_header: Some("<live-check@example.test>"),
        subject: Some("Live Check"),
        from_json: json!([{"address": "check@example.test"}]),
        to_json: json!([{"address": "check@example.test"}]),
        cc_json: json!([]),
        bcc_json: json!([]),
        reply_to_json: json!([]),
        envelope_json: json!({"subject": "Live Check"}),
        bodystructure_json: json!({"type": "text"}),
        internal_date: None,
        sent_date: None,
        size_octets: 16,
        text_preview: Some("check body"),
    })
    .await?;
    repo.upsert_mailbox_message(NewMailboxMessage {
        mailbox_id: mailbox.id,
        message_id: 1,
        local_uid: 1,
        upstream_uid: Some(1),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);
    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", username, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream.get_mut().write_all(b"A2 SELECT INBOX\r\n").await?;
    stream.get_mut().flush().await?;
    let mut select_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        select_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        select_lines
            .iter()
            .any(|line| line.contains("[HIGHESTMODSEQ 1]")),
        "{select_lines:?}"
    );

    stream.get_mut().write_all(b"A3 CHECK\r\n").await?;
    stream.get_mut().flush().await?;
    let mut check_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        check_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        check_lines
            .iter()
            .any(|line| line.trim_end() == "A3 OK CHECK completed"),
        "{check_lines:?}"
    );

    stream.get_mut().write_all(b"A4 FETCH 1 FLAGS\r\n").await?;
    stream.get_mut().flush().await?;
    let mut fetch_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        fetch_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        fetch_lines
            .iter()
            .any(|line| line.contains("* 1 FETCH (FLAGS ())")),
        "{fetch_lines:?}"
    );
    assert!(fetch_lines.iter().any(|line| line.trim_end() == "A4 OK FETCH completed"));

    stream.get_mut().write_all(b"A5 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A5 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_fetches_header_field_sections_over_wire() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("live-body-fields-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Body Fields",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(1),
            exists_count: 0,
            recent_count: 1,
            unseen_count: 0,
        })
        .await?;
    let raw = concat!(
        "From: Live Fields <from@example.test>\r\n",
        "To: Live Fields <to@example.test>\r\n",
        "Subject: Live Body Fields\r\n",
        "X-Trace: drop-me\r\n",
        "Message-ID: <live-body-fields@example.test>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "body fields\r\n",
    );
    let store = Arc::new(MemoryObjectStore::new());
    let raw_blob_key = content_addressed_key(ObjectType::Rfc822, raw.as_bytes());
    store.put(&raw_blob_key, raw.as_bytes()).await?;
    let message = repo
        .upsert_message(NewMessage {
        account_id: account.id,
        rfc822_blob_key: &raw_blob_key,
        rfc822_sha256: "sha256-live-body-fields",
        message_id_header: Some("<live-body-fields@example.test>"),
        subject: Some("Live Body Fields"),
        from_json: json!([{"address": "from@example.test"}]),
        to_json: json!([{"address": "to@example.test"}]),
        cc_json: json!([]),
        bcc_json: json!([]),
        reply_to_json: json!([]),
        envelope_json: json!({"subject": "Live Body Fields"}),
        bodystructure_json: json!({"type": "text"}),
        internal_date: None,
        sent_date: None,
        size_octets: 16,
        text_preview: Some("body fields"),
    })
        .await?;
    repo.upsert_mailbox_message(NewMailboxMessage {
        mailbox_id: mailbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(1),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn ObjectStore>,
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);
    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", username, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream.get_mut().write_all(b"A2 SELECT INBOX\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A2 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(b"A3 FETCH 1 (BODY[HEADER.FIELDS (Subject From)] FLAGS)\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut header_fields_lines = Vec::new();
    let mut header_fields_body = Vec::new();
    loop {
        let mut line = String::new();
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            stream.read_line(&mut line),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout while waiting for A3 response"))??;
        if bytes == 0 {
            let server_result = server.await;
            panic!("unexpected EOF while waiting for A3 response; server result: {server_result:?}");
        }
        if line.starts_with("* ")
            && line.contains("FETCH")
            && line.contains('{')
            && line.ends_with("}\r\n")
        {
            let size = literal_size(&line)?;
            let mut bytes = vec![0; size];
            stream.read_exact(&mut bytes).await?;
            header_fields_body = bytes;
            header_fields_lines.push(line);
            continue;
        }
        let done = line.starts_with("A3 OK");
        header_fields_lines.push(line);
        if done {
            break;
        }
    }
    let header_fields_text = String::from_utf8_lossy(&header_fields_body);
    assert!(
        header_fields_lines
            .iter()
            .any(|line| line.contains("* 1 FETCH (BODY[HEADER.FIELDS (SUBJECT FROM)] {")),
        "{header_fields_lines:?}"
    );
    assert!(
        header_fields_lines
            .iter()
            .any(|line| line.contains("FLAGS ()")),
        "{header_fields_lines:?}"
    );
    assert!(
        header_fields_text.contains("From: Live Fields <from@example.test>"),
        "{header_fields_text}"
    );
    assert!(
        header_fields_text.contains("Subject: Live Body Fields"),
        "{header_fields_text}"
    );
    assert!(
        !header_fields_text.contains("To: Live Fields <to@example.test>"),
        "{header_fields_text}"
    );
    assert!(
        !header_fields_text.contains("X-Trace: drop-me"),
        "{header_fields_text}"
    );
    assert!(
        repo.list_mailbox_messages(mailbox.id)
            .await?[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Seen")),
        "plain BODY[HEADER.FIELDS] should mark the message seen"
    );

    stream
        .get_mut()
        .write_all(b"A4 FETCH 1 (BODY.PEEK[HEADER.FIELDS.NOT (X-Trace)])\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut header_not_lines = Vec::new();
    let mut header_not_body = Vec::new();
    loop {
        let mut line = String::new();
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            stream.read_line(&mut line),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout while waiting for A4 response"))??;
        if bytes == 0 {
            let server_result = server.await;
            panic!("unexpected EOF while waiting for A4 response; server result: {server_result:?}");
        }
        if line.starts_with("* ")
            && line.contains("FETCH")
            && line.contains('{')
            && line.ends_with("}\r\n")
        {
            let size = literal_size(&line)?;
            let mut bytes = vec![0; size];
            stream.read_exact(&mut bytes).await?;
            header_not_body = bytes;
            header_not_lines.push(line);
            continue;
        }
        let done = line.starts_with("A4 OK");
        header_not_lines.push(line);
        if done {
            break;
        }
    }
    let header_not_text = String::from_utf8_lossy(&header_not_body);
    assert!(
        header_not_lines
            .iter()
            .any(|line| line.contains("* 1 FETCH (BODY.PEEK[HEADER.FIELDS.NOT (X-TRACE)] {")),
        "{header_not_lines:?}"
    );
    assert!(
        header_not_text.contains("From: Live Fields <from@example.test>"),
        "{header_not_text}"
    );
    assert!(
        header_not_text.contains("To: Live Fields <to@example.test>"),
        "{header_not_text}"
    );
    assert!(
        header_not_text.contains("Subject: Live Body Fields"),
        "{header_not_text}"
    );
    assert!(
        !header_not_text.contains("X-Trace: drop-me"),
        "{header_not_text}"
    );
    assert!(
        repo.list_mailbox_messages(mailbox.id)
            .await?[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Seen")),
        "BODY.PEEK should not change the seen state"
    );

    stream.get_mut().write_all(b"A5 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        let bytes = tokio::time::timeout(
            Duration::from_secs(5),
            stream.read_line(&mut line),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout while waiting for A5 OK"))??;
        if bytes == 0 {
            let server_result = server.await;
            panic!("unexpected EOF while waiting for A5 OK; server result: {server_result:?}");
        }
        if line.starts_with("A5 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_fetches_nested_mime_part_over_wire() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let store: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());
    let ingestor = imap_cache_rs::sync::MessageIngestor::new(
        Arc::clone(&repo),
        Arc::clone(&store),
        None,
    );

    let username = format!("live-mime-part-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live MIME Part",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(1),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;
    let raw = concat!(
        "From: Alice <alice@example.com>\r\n",
        "To: Bob <bob@example.com>\r\n",
        "Subject: MIME Part Fetch\r\n",
        "Message-ID: <mime-part-fetch@example.com>\r\n",
        "Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"outer\"\r\n",
        "\r\n",
        "--outer\r\n",
        "Content-Type: multipart/alternative; boundary=\"inner\"\r\n",
        "\r\n",
        "--inner\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "Hello plain world.\r\n",
        "--inner\r\n",
        "Content-Type: text/html; charset=\"utf-8\"\r\n",
        "\r\n",
        "<html><body>Hello <b>HTML</b>.</body></html>\r\n",
        "--inner--\r\n",
        "--outer\r\n",
        "Content-Type: application/pdf\r\n",
        "Content-Disposition: attachment; filename=\"file.pdf\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "Zm9v\r\n",
        "--outer--\r\n"
    );
    ingestor
        .ingest_raw_message(
            account.id,
            mailbox.id,
            "INBOX",
            1,
            Some(11),
            None,
            raw.as_bytes(),
            vec![],
        )
        .await?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn ObjectStore>,
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);
    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", username, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream.get_mut().write_all(b"A2 SELECT INBOX\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A2 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(b"A3 FETCH 1 (BODY[1.1.TEXT])\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut fetch_lines = Vec::new();
    let mut literal = Vec::new();
    loop {
        let mut line = String::new();
        let bytes = stream.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }
        if line.starts_with("* ")
            && line.contains("FETCH")
            && line.contains('{')
            && line.ends_with("}\r\n")
        {
            let size = literal_size(&line)?;
            let mut bytes = vec![0; size];
            stream.read_exact(&mut bytes).await?;
            literal = bytes;
            fetch_lines.push(line);
            continue;
        }
        let done = line.starts_with("A3 OK");
        fetch_lines.push(line);
        if done {
            break;
        }
    }
    assert_eq!(literal, b"Hello plain world.\r\n", "{fetch_lines:?}");
    assert!(
        fetch_lines
            .iter()
            .any(|line| line.contains("* 1 FETCH (BODY[1.1.TEXT] {")),
        "{fetch_lines:?}"
    );
    assert!(
        repo.list_mailbox_messages(mailbox.id)
            .await?[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Seen")),
        "nested part fetch should mark the message seen"
    );

    stream
        .get_mut()
        .write_all(b"A4 FETCH 1 (BODY[1.1.HEADER])\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut header_lines = Vec::new();
    let mut header_literal = Vec::new();
    loop {
        let mut line = String::new();
        let bytes = stream.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }
        if line.starts_with("* ")
            && line.contains("FETCH")
            && line.contains('{')
            && line.ends_with("}\r\n")
        {
            let size = literal_size(&line)?;
            let mut bytes = vec![0; size];
            stream.read_exact(&mut bytes).await?;
            header_literal = bytes;
            header_lines.push(line);
            continue;
        }
        let done = line.starts_with("A4 OK");
        header_lines.push(line);
        if done {
            break;
        }
    }
    let header_text = String::from_utf8_lossy(&header_literal);
    assert!(
        header_lines
            .iter()
            .any(|line| line.contains("* 1 FETCH (BODY[1.1.HEADER] {")),
        "{header_lines:?}"
    );
    assert!(
        header_text.contains("Content-Type: text/plain; charset=\"utf-8\""),
        "{header_text}"
    );
    assert!(
        header_text.contains("Content-Disposition: inline"),
        "{header_text}"
    );

    stream
        .get_mut()
        .write_all(b"A5 FETCH 1 (BODY[1.1.HEADER.FIELDS (Content-Type Content-Disposition)])\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut field_lines = Vec::new();
    let mut field_literal = Vec::new();
    loop {
        let mut line = String::new();
        let bytes = stream.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }
        if line.starts_with("* ")
            && line.contains("FETCH")
            && line.contains('{')
            && line.ends_with("}\r\n")
        {
            let size = literal_size(&line)?;
            let mut bytes = vec![0; size];
            stream.read_exact(&mut bytes).await?;
            field_literal = bytes;
            field_lines.push(line);
            continue;
        }
        let done = line.starts_with("A5 OK");
        field_lines.push(line);
        if done {
            break;
        }
    }
    let field_text = String::from_utf8_lossy(&field_literal);
    assert!(
        field_lines
            .iter()
            .any(|line| line.contains("* 1 FETCH (BODY[1.1.HEADER.FIELDS (CONTENT-TYPE CONTENT-DISPOSITION)] {")),
        "{field_lines:?}"
    );
    assert!(
        field_text.contains("Content-Type: text/plain; charset=\"utf-8\""),
        "{field_text}"
    );
    assert!(
        field_text.contains("Content-Disposition: inline"),
        "{field_text}"
    );
    assert!(
        !field_text.contains("Content-Transfer-Encoding"),
        "{field_text}"
    );

    stream
        .get_mut()
        .write_all(b"A6 FETCH 1 (BODY[1.1.MIME])\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut mime_lines = Vec::new();
    let mut mime_literal = Vec::new();
    loop {
        let mut line = String::new();
        let bytes = stream.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }
        if line.starts_with("* ")
            && line.contains("FETCH")
            && line.contains('{')
            && line.ends_with("}\r\n")
        {
            let size = literal_size(&line)?;
            let mut bytes = vec![0; size];
            stream.read_exact(&mut bytes).await?;
            mime_literal = bytes;
            mime_lines.push(line);
            continue;
        }
        let done = line.starts_with("A6 OK");
        mime_lines.push(line);
        if done {
            break;
        }
    }
    let mime_text = String::from_utf8_lossy(&mime_literal);
    assert!(
        mime_lines
            .iter()
            .any(|line| line.contains("* 1 FETCH (BODY[1.1.MIME] {")),
        "{mime_lines:?}"
    );
    assert!(
        mime_text.contains("Content-Type: text/plain; charset=\"utf-8\""),
        "{mime_text}"
    );
    assert!(
        mime_text.contains("Content-Disposition: inline"),
        "{mime_text}"
    );
    assert!(
        !mime_text.contains("Content-Transfer-Encoding"),
        "{mime_text}"
    );

    stream
        .get_mut()
        .write_all(b"A7 FETCH 1 (BODY[1.1]<0.6>)\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut partial_lines = Vec::new();
    let mut partial_literal = Vec::new();
    loop {
        let mut line = String::new();
        let bytes = stream.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }
        if line.starts_with("* ")
            && line.contains("FETCH")
            && line.contains('{')
            && line.ends_with("}\r\n")
        {
            let size = literal_size(&line)?;
            let mut bytes = vec![0; size];
            stream.read_exact(&mut bytes).await?;
            partial_literal = bytes;
            partial_lines.push(line);
            continue;
        }
        let done = line.starts_with("A7 OK");
        partial_lines.push(line);
        if done {
            break;
        }
    }
    assert_eq!(partial_literal, b"Hello ", "{partial_lines:?}");
    assert!(
        partial_lines
            .iter()
            .any(|line| line.contains("* 1 FETCH (BODY[1.1]<0.6> {")),
        "{partial_lines:?}"
    );

    stream.get_mut().write_all(b"A8 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A8 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_append_replays_to_real_upstream() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let mutations = imap_cache_rs::sync::MutationEngine::new(repo.clone(), store.clone());
    let local_email = format!("live-append-socket-{}@example.test", Uuid::new_v4());
    let password = "secret";

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Append Socket",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let scratch_mailbox = format!("imap-cache-rs-append-{}", Uuid::new_v4());
    let scratch_mailbox_canonical = scratch_mailbox.to_ascii_lowercase();
    repo.upsert_mailbox(NewMailbox {
        account_id: account.id,
        name: &scratch_mailbox,
        canonical_name: &scratch_mailbox_canonical,
        delimiter: Some("/"),
        attributes: vec!["\\HasNoChildren".to_string()],
        subscribed: true,
        special_use: None,
        uidvalidity: Some(1),
        uidnext: Some(1),
        highestmodseq: Some(0),
        exists_count: 0,
        recent_count: 0,
        unseen_count: 0,
    })
    .await?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn imap_cache_rs::storage::ObjectStore>,
        search: None,
        sync_engine: None,
        mutation_engine: Some(Arc::new(mutations.clone())),
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let unique_subject = format!("imap-cache-rs-live-append-{}", Uuid::new_v4());
    let raw = format!(
        concat!(
            "From: Live Test <live-test@example.test>\r\n",
            "To: Live Test <live-test@example.test>\r\n",
            "Subject: {subject}\r\n",
            "Message-ID: <{subject}@example.test>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Live append body for {subject}\r\n",
        ),
        subject = unique_subject
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(
            format!(
                "A2 APPEND \"{}\" (\\Seen) \"12-Feb-2024 10:00:00 +0000\" {{{}}}\r\n",
                scratch_mailbox,
                raw.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.get_mut().flush().await?;
    let mut continuation = String::new();
    stream.read_line(&mut continuation).await?;
    assert!(continuation.starts_with("+ "));
    stream.get_mut().write_all(raw.as_bytes()).await?;
    stream.get_mut().flush().await?;
    let mut append_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        append_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        append_lines.iter().any(|line| line.contains("APPEND queued")),
        "{append_lines:?}"
    );
    assert!(
        append_lines.iter().any(|line| line.contains("APPENDUID")),
        "{append_lines:?}"
    );

    let pending = repo
        .list_pending_mutations(account.id, imap_cache_rs::domain::MutationStatus::Pending)
        .await?;
    assert_eq!(pending.len(), 1);
    let local_messages = repo.list_mailbox_messages(
        repo.find_mailbox(account.id, &scratch_mailbox)
            .await?
            .ok_or_else(|| anyhow::anyhow!("scratch mailbox not found"))?
            .id,
    )
    .await?;
    assert_eq!(local_messages.len(), 1);

    let mut upstream =
        tokio::time::timeout(Duration::from_secs(60), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(60), upstream.capability()).await??;
    tokio::time::timeout(
        Duration::from_secs(60),
        upstream.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;
    let create_response = upstream
        .send_command("CREATE", &[format!("\"{}\"", scratch_mailbox)])
        .await?;
    assert!(
        create_response.tagged.starts_with("A") && create_response.tagged.contains("OK"),
        "{create_response:?}"
    );

    let applied = tokio::time::timeout(
        Duration::from_secs(60),
        mutations.flush_pending_mutations(account.id, &mut upstream),
    )
    .await??;
    assert_eq!(applied, 1);

    let selection = tokio::time::timeout(
        Duration::from_secs(60),
        upstream.select_mailbox(&scratch_mailbox),
    )
    .await??;
    assert_eq!(selection.exists.unwrap_or_default(), 1);
    let uids = tokio::time::timeout(Duration::from_secs(60), upstream.uid_search_all()).await??;
    let appended_uid = *uids
        .iter()
        .max()
        .ok_or_else(|| anyhow::anyhow!("appended message was not found upstream"))?;
    let fetched =
        tokio::time::timeout(Duration::from_secs(60), upstream.uid_fetch_rfc822(appended_uid))
            .await??;
    assert_eq!(fetched, raw.as_bytes());

    let delete_response = upstream
        .send_command("DELETE", &[format!("\"{}\"", scratch_mailbox)])
        .await?;
    assert!(
        delete_response.tagged.contains("OK"),
        "{delete_response:?}"
    );
    tokio::time::timeout(Duration::from_secs(60), upstream.logout()).await??;
    stream.get_mut().write_all(b"A3 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A3 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_lists_and_statuses_real_mailbox() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = imap_cache_rs::sync::MessageIngestor::new(
        repo.clone(),
        store.clone(),
        Some(search.clone()),
    );
    let metrics = Arc::new(imap_cache_rs::metrics::AppMetrics::new());
    let sync_engine = imap_cache_rs::sync::SyncEngine::new(
        repo.clone(),
        ingestor,
        Arc::clone(&metrics),
    );
    let local_email = format!("live-list-status-{}@example.test", Uuid::new_v4());
    let password = "secret";

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live List Status",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let mut upstream =
        tokio::time::timeout(Duration::from_secs(60), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(60), upstream.capability()).await??;
    tokio::time::timeout(
        Duration::from_secs(60),
        upstream.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;

    let mailboxes = tokio::time::timeout(Duration::from_secs(60), upstream.list_mailboxes()).await??;
    let mut selected_mailbox: Option<String> = None;
    let mut selected_uid: Option<u64> = None;
    let mut selected_selection: Option<imap_cache_rs::upstream::SelectedMailboxInfo> = None;
    for mailbox_name in mailboxes {
        let selection =
            tokio::time::timeout(Duration::from_secs(60), upstream.select_mailbox(&mailbox_name))
                .await??;
        let uids = tokio::time::timeout(Duration::from_secs(60), upstream.uid_search_all()).await??;
        let Some(uid) = uids.into_iter().max() else {
            continue;
        };
        selected_mailbox = Some(mailbox_name);
        selected_uid = Some(uid);
        selected_selection = Some(selection);
        break;
    }

    let selected_mailbox = selected_mailbox.ok_or_else(|| {
        anyhow::anyhow!("real upstream account does not contain a mailbox with messages")
    })?;
    let selected_uid = selected_uid.unwrap();
    let selected_selection = selected_selection.unwrap_or_default();
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: &selected_mailbox,
            canonical_name: &selected_mailbox.to_ascii_lowercase(),
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: if selected_mailbox.eq_ignore_ascii_case("INBOX") {
                Some("\\Inbox")
            } else {
                None
            },
            uidvalidity: selected_selection.uidvalidity,
            uidnext: selected_selection.uidnext,
            highestmodseq: selected_selection.highestmodseq,
            exists_count: selected_selection.exists.unwrap_or_default(),
            recent_count: selected_selection.recent.unwrap_or_default(),
            unseen_count: selected_selection.unseen.unwrap_or_default(),
        })
        .await?;
    repo.put_sync_state(imap_cache_rs::db::repository::NewSyncState {
        account_id: account.id,
        mailbox_id: Some(mailbox.id),
        state_json: serde_json::json!({
            "mailbox_name": selected_mailbox.clone(),
            "uidvalidity": selected_selection.uidvalidity,
            "last_uid": (selected_uid as i64) - 1,
        }),
        last_success_at: Some(chrono::Utc::now()),
        last_attempt_at: Some(chrono::Utc::now()),
        last_error: None,
    })
    .await?;
    let synced = tokio::time::timeout(
        Duration::from_secs(120),
        sync_engine.sync_mailbox(account.id, &selected_mailbox, &mut upstream),
    )
    .await??;
    assert_eq!(synced, 1);

    let refreshed_mailbox = repo
        .find_mailbox(account.id, &selected_mailbox)
        .await?
        .ok_or_else(|| anyhow::anyhow!("synced mailbox disappeared from local store"))?;
    let local_messages = repo.list_mailbox_messages(refreshed_mailbox.id).await?;
    assert_eq!(local_messages.len(), 1);

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn imap_cache_rs::storage::ObjectStore>,
        search: Some(search.clone() as Arc<dyn SearchBackend>),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::clone(&metrics),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream.get_mut().write_all(b"A2 LIST \"\" \"*\"\r\n").await?;
    stream.get_mut().flush().await?;
    let mut list_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        list_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        list_lines
            .iter()
            .any(|line| line.contains(&format!("\"{}\"", selected_mailbox))),
        "{list_lines:?}"
    );

    stream
        .get_mut()
        .write_all(b"A3 LSUB \"\" \"*\"\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut lsub_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        lsub_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        lsub_lines
            .iter()
            .any(|line| line.contains(&format!("\"{}\"", selected_mailbox))),
        "{lsub_lines:?}"
    );

    stream
        .get_mut()
        .write_all(
            format!(
                "A4 STATUS \"{}\" (MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)\r\n",
                selected_mailbox.replace('"', "\\\"")
            )
            .as_bytes(),
        )
        .await?;
    stream.get_mut().flush().await?;
    let mut status_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        status_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        status_lines
            .iter()
            .any(|line| line.contains(&format!("MESSAGES {}", refreshed_mailbox.exists_count))),
        "{status_lines:?}"
    );
    assert!(
        status_lines
            .iter()
            .any(|line| line.contains(&format!(
                "UIDNEXT {}",
                refreshed_mailbox.uidnext.unwrap_or(1)
            ))),
        "{status_lines:?}"
    );
    assert!(
        status_lines.iter().any(|line| line.contains(&format!(
            "UIDVALIDITY {}",
            refreshed_mailbox.uidvalidity.unwrap_or(1)
        ))),
        "{status_lines:?}"
    );

    let message_view = repo
        .list_mailbox_message_views(refreshed_mailbox.id)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("synced message view missing from local store"))?;
    let raw_bytes = store
        .get(&message_view.rfc822_blob_key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("synced raw message missing from object store"))?;
    let partial_len = raw_bytes.len().min(12);
    let expected_slice = raw_bytes[..partial_len].to_vec();

    stream
        .get_mut()
        .write_all(
            format!("A5 SELECT \"{}\"\r\nA6 FETCH 1 (BODY[]<0.12>)\r\nA7 LOGOUT\r\n", selected_mailbox)
                .as_bytes(),
        )
        .await?;
    stream.get_mut().flush().await?;
    let mut output = Vec::new();
    stream.read_to_end(&mut output).await?;
    let text = String::from_utf8_lossy(&output);
    assert!(text.contains("A5 OK [READ-WRITE] SELECT completed"));
    assert!(
        text.contains(&format!("* 1 FETCH (BODY[]<0.12> {{{}}}", partial_len)),
        "response:\n{text}"
    );
    assert!(output.windows(expected_slice.len()).any(|window| window == expected_slice));
    assert!(text.contains("A6 OK FETCH completed"));
    assert!(text.contains("A7 OK LOGOUT completed"));

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_sorts_messages_over_wire() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("live-sort-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Sort",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 1,
            unseen_count: 0,
        })
        .await?;

    let alpha = repo
        .upsert_message(NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/live-sort-alpha",
            rfc822_sha256: "sha256-live-sort-alpha",
            message_id_header: Some("<live-sort-alpha@example.test>"),
            subject: Some("Alpha"),
            from_json: json!([{"address": "alpha@example.test"}]),
            to_json: json!([{"address": "sort@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Alpha"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 10,
            text_preview: Some("alpha body"),
        })
        .await?;
    repo.upsert_mailbox_message(NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: alpha.id,
        local_uid: 20,
        upstream_uid: Some(520),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let zulu = repo
        .upsert_message(NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/live-sort-zulu",
            rfc822_sha256: "sha256-live-sort-zulu",
            message_id_header: Some("<live-sort-zulu@example.test>"),
            subject: Some("Zulu"),
            from_json: json!([{"address": "zulu@example.test"}]),
            to_json: json!([{"address": "sort@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Zulu"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 11,
            text_preview: Some("zulu body"),
        })
        .await?;
    repo.upsert_mailbox_message(NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: zulu.id,
        local_uid: 10,
        upstream_uid: Some(510),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);
    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", username, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream.get_mut().write_all(b"A2 SELECT INBOX\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A2 OK") {
            break;
        }
    }

    stream
        .get_mut()
        .write_all(b"A3 SORT (SUBJECT) UTF-8 ALL\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut sort_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        sort_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        sort_lines.iter().any(|line| line.trim_end() == "* SORT 2 1"),
        "{sort_lines:?}"
    );
    assert!(
        sort_lines
            .iter()
            .any(|line| line.trim_end() == "A3 OK SORT completed")
    );

    stream
        .get_mut()
        .write_all(b"A4 UID SORT (SUBJECT) UTF-8 ALL\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut uid_sort_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        uid_sort_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        uid_sort_lines.iter().any(|line| line.trim_end() == "* SORT 20 10"),
        "{uid_sort_lines:?}"
    );
    assert!(
        uid_sort_lines
            .iter()
            .any(|line| line.trim_end() == "A4 OK UID SORT completed")
    );

    stream.get_mut().write_all(b"A5 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A5 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_enables_condstore_over_wire() -> anyhow::Result<()> {
    let _live_guard = live_test_guard().await;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("live-condstore-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Condstore",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(1),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;
    let message = repo
        .upsert_message(NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/live-condstore",
            rfc822_sha256: "sha256-live-condstore",
            message_id_header: Some("<live-condstore@example.test>"),
            subject: Some("Live Condstore"),
            from_json: json!([{"address": "condstore@example.test"}]),
            to_json: json!([{"address": "condstore@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Live Condstore"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 16,
            text_preview: Some("condstore body"),
        })
        .await?;
    repo.upsert_mailbox_message(NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(1),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);
    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", username, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    stream.get_mut().write_all(b"A2 SELECT INBOX\r\n").await?;
    stream.get_mut().flush().await?;
    let mut select_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        select_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        select_lines
            .iter()
            .any(|line| line.contains("[HIGHESTMODSEQ 1]")),
        "{select_lines:?}"
    );

    stream.get_mut().write_all(b"A3 ENABLE CONDSTORE\r\n").await?;
    stream.get_mut().flush().await?;
    let mut enable_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        enable_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        enable_lines
            .iter()
            .any(|line| line.trim_end() == "* ENABLED CONDSTORE"),
        "{enable_lines:?}"
    );
    assert!(
        enable_lines
            .iter()
            .any(|line| line.trim_end() == "A3 OK ENABLE completed"),
        "{enable_lines:?}"
    );

    stream.get_mut().write_all(b"A4 CONDSTORE\r\n").await?;
    stream.get_mut().flush().await?;
    let mut condstore_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        condstore_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        condstore_lines
            .iter()
            .any(|line| line.trim_end() == "A4 OK CONDSTORE completed"),
        "{condstore_lines:?}"
    );

    stream.get_mut().write_all(b"A5 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A5 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_reports_namespace_and_id_over_wire() -> anyhow::Result<()> {
    let _live_guard = live_test_guard().await;
    let services = Arc::new(AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream.get_mut().write_all(b"A1 NAMESPACE\r\n").await?;
    stream.get_mut().flush().await?;
    let mut namespace_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A1 OK");
        namespace_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        namespace_lines
            .iter()
            .any(|line| line.trim_end() == r#"* NAMESPACE (("" "/")) NIL NIL"#),
        "{namespace_lines:?}"
    );
    assert!(
        namespace_lines
            .iter()
            .any(|line| line.trim_end() == "A1 OK NAMESPACE completed"),
        "{namespace_lines:?}"
    );

    stream.get_mut().write_all(b"A2 ID NIL\r\n").await?;
    stream.get_mut().flush().await?;
    let mut id_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        id_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        id_lines
            .iter()
            .any(|line| line.contains(r#"* ID ("name" "imap-cache-rs""#)),
        "{id_lines:?}"
    );
    assert!(
        id_lines
            .iter()
            .any(|line| line.trim_end() == "A2 OK ID completed"),
        "{id_lines:?}"
    );

    stream.get_mut().write_all(b"A3 NOOP\r\n").await?;
    stream.get_mut().flush().await?;
    let mut noop_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        noop_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        noop_lines
            .iter()
            .any(|line| line.trim_end() == "A3 OK NOOP completed"),
        "{noop_lines:?}"
    );

    stream.get_mut().write_all(b"A4 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A4 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_manages_mailbox_lifecycle_over_wire() -> anyhow::Result<()> {
    let _live_guard = live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));
    let local_email = format!("live-lifecycle-{}@example.test", Uuid::new_v4());
    let password = "secret";

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Lifecycle",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()) as Arc<dyn imap_cache_rs::storage::ObjectStore>,
        search: Some(Arc::new(TantivySearchEngine::memory()?) as Arc<dyn SearchBackend>),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream
        .get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", local_email, password).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }

    let mailbox_name = format!("Lifecycle {}", Uuid::new_v4().simple());
    let renamed_mailbox = format!("{mailbox_name} Renamed");

    stream
        .get_mut()
        .write_all(format!("A2 CREATE \"{}\"\r\n", mailbox_name).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut create_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        create_lines.push(line);
        if done {
            break;
        }
    }
    assert!(create_lines.iter().any(|line| line.starts_with("A2 OK")), "{create_lines:?}");

    stream
        .get_mut()
        .write_all(format!("A3 LIST \"\" \"{}\"\r\n", mailbox_name).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut list_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        list_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        list_lines
            .iter()
            .any(|line| line.contains(&format!("\"{}\"", mailbox_name))),
        "{list_lines:?}"
    );

    stream
        .get_mut()
        .write_all(
            format!("A4 RENAME \"{}\" \"{}\"\r\n", mailbox_name, renamed_mailbox).as_bytes(),
        )
        .await?;
    stream.get_mut().flush().await?;
    let mut rename_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        rename_lines.push(line);
        if done {
            break;
        }
    }
    assert!(rename_lines.iter().any(|line| line.starts_with("A4 OK")), "{rename_lines:?}");
    assert!(repo.find_mailbox(account.id, &mailbox_name).await?.is_none());
    assert!(repo.find_mailbox(account.id, &renamed_mailbox).await?.is_some());

    stream
        .get_mut()
        .write_all(format!("A5 SUBSCRIBE \"{}\"\r\n", renamed_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut subscribe_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A5 OK");
        subscribe_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        subscribe_lines.iter().any(|line| line.starts_with("A5 OK")),
        "{subscribe_lines:?}"
    );
    assert!(
        repo.find_mailbox(account.id, &renamed_mailbox)
            .await?
            .is_some_and(|mailbox| mailbox.subscribed),
        "mailbox should be subscribed locally"
    );

    stream
        .get_mut()
        .write_all(b"A6 LSUB \"\" \"*\"\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut lsub_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A6 OK");
        lsub_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        lsub_lines
            .iter()
            .any(|line| line.contains(&format!("\"{}\"", renamed_mailbox))),
        "{lsub_lines:?}"
    );

    stream
        .get_mut()
        .write_all(format!("A7 UNSUBSCRIBE \"{}\"\r\n", renamed_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut unsubscribe_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A7 OK");
        unsubscribe_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        unsubscribe_lines
            .iter()
            .any(|line| line.starts_with("A7 OK")),
        "{unsubscribe_lines:?}"
    );
    assert!(
        repo.find_mailbox(account.id, &renamed_mailbox)
            .await?
            .is_some_and(|mailbox| !mailbox.subscribed),
        "mailbox should be unsubscribed locally"
    );

    stream
        .get_mut()
        .write_all(b"A8 LSUB \"\" \"*\"\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut post_unsub_lsub_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A8 OK");
        post_unsub_lsub_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        post_unsub_lsub_lines
            .iter()
            .all(|line| !line.contains(&format!("\"{}\"", renamed_mailbox))),
        "{post_unsub_lsub_lines:?}"
    );

    stream
        .get_mut()
        .write_all(format!("A9 DELETE \"{}\"\r\n", renamed_mailbox).as_bytes())
        .await?;
    stream.get_mut().flush().await?;
    let mut delete_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A9 OK");
        delete_lines.push(line);
        if done {
            break;
        }
    }
    assert!(delete_lines.iter().any(|line| line.starts_with("A9 OK")), "{delete_lines:?}");
    assert!(repo.find_mailbox(account.id, &renamed_mailbox).await?.is_none());

    stream.get_mut().write_all(b"A10 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        if line.starts_with("A10 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_upgrades_plaintext_connection_via_starttls() -> anyhow::Result<()> {
    let _live_guard = live_test_guard().await;

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|err| anyhow::anyhow!("failed to generate test certificate: {err}"))?;
    let tempdir = tempdir()?;
    let cert_path = tempdir.path().join("imap.crt");
    let key_path = tempdir.path().join("imap.key");
    fs::write(&cert_path, certified.cert.pem())?;
    fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let config = Config {
        imap_tls_cert_path: Some(cert_path.clone()),
        imap_tls_key_path: Some(key_path.clone()),
        ..Default::default()
    };
    let acceptor = imap_cache_rs::protocol::imap::tls_acceptor(&config)?
        .ok_or_else(|| anyhow::anyhow!("expected STARTTLS acceptor"))?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(StaticAuthenticator::new(
            "user@example.test".into(),
            security::hash_password("secret-password")?,
        )),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, Some(acceptor)).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut stream = BufReader::new(client);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream.get_mut().write_all(b"A1 CAPABILITY\r\n").await?;
    stream.get_mut().flush().await?;
    let mut capability_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A1 OK");
        capability_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        capability_lines
            .iter()
            .any(|line| line.contains("STARTTLS")),
        "{capability_lines:?}"
    );

    stream.get_mut().write_all(b"A2 STARTTLS\r\n").await?;
    stream.get_mut().flush().await?;
    let mut starttls_response = String::new();
    stream.read_line(&mut starttls_response).await?;
    assert!(starttls_response.starts_with("A2 OK"));

    let plain_stream = stream.into_inner();
    let mut roots = RootCertStore::empty();
    let mut cert_reader = StdBufReader::new(fs::File::open(&cert_path)?);
    let certs =
        rustls_pemfile::certs(&mut cert_reader).collect::<std::result::Result<Vec<_>, _>>()?;
    for cert in certs {
        roots
            .add(cert)
            .map_err(|err| anyhow::anyhow!("failed to add test root certificate: {err}"))?;
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost")
        .map_err(|err| anyhow::anyhow!("invalid TLS server name: {err}"))?;
    let tls_stream = connector.connect(server_name, plain_stream).await?;
    let mut tls_stream = BufReader::new(tls_stream);

    tls_stream.get_mut().write_all(b"A3 CAPABILITY\r\n").await?;
    tls_stream.get_mut().flush().await?;
    let mut tls_capability_lines = Vec::new();
    loop {
        let mut line = String::new();
        tls_stream.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        tls_capability_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        !tls_capability_lines
            .iter()
            .any(|line| line.contains("STARTTLS")),
        "{tls_capability_lines:?}"
    );

    tls_stream
        .write_all(b"A4 LOGIN \"user@example.test\" \"secret-password\"\r\n")
        .await?;
    tls_stream.get_mut().flush().await?;
    let mut login_lines = Vec::new();
    loop {
        let mut line = String::new();
        tls_stream.read_line(&mut line).await?;
        let done = line.starts_with("A4 OK");
        login_lines.push(line);
        if done {
            break;
        }
    }
    assert!(login_lines.iter().any(|line| line.starts_with("A4 OK")));

    tls_stream.get_mut().write_all(b"A5 LOGOUT\r\n").await?;
    tls_stream.get_mut().flush().await?;
    let mut logout = String::new();
    tls_stream.read_line(&mut logout).await?;
    assert!(logout.starts_with("* BYE"));

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn live_imap_server_accepts_implicit_tls_connections() -> anyhow::Result<()> {
    let _live_guard = live_test_guard().await;

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|err| anyhow::anyhow!("failed to generate test certificate: {err}"))?;
    let tempdir = tempdir()?;
    let cert_path = tempdir.path().join("imap.crt");
    let key_path = tempdir.path().join("imap.key");
    fs::write(&cert_path, certified.cert.pem())?;
    fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let config = Config {
        imap_tls_cert_path: Some(cert_path.clone()),
        imap_tls_key_path: Some(key_path.clone()),
        ..Default::default()
    };
    let acceptor = imap_cache_rs::protocol::imap::tls_acceptor(&config)?
        .ok_or_else(|| anyhow::anyhow!("expected TLS acceptor"))?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(StaticAuthenticator::new(
            "user@example.test".into(),
            security::hash_password("secret-password")?,
        )),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { imap_cache_rs::protocol::imap::serve_tls(listener, acceptor, services).await }
    });

    let client = tokio::net::TcpStream::connect(addr).await?;
    let mut roots = RootCertStore::empty();
    let mut cert_reader = StdBufReader::new(fs::File::open(&cert_path)?);
    let certs =
        rustls_pemfile::certs(&mut cert_reader).collect::<std::result::Result<Vec<_>, _>>()?;
    for cert in certs {
        roots
            .add(cert)
            .map_err(|err| anyhow::anyhow!("failed to add test root certificate: {err}"))?;
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost")
        .map_err(|err| anyhow::anyhow!("invalid TLS server name: {err}"))?;
    let tls_stream = connector.connect(server_name, client).await?;
    let mut stream = BufReader::new(tls_stream);

    let mut greeting = String::new();
    stream.read_line(&mut greeting).await?;
    assert!(greeting.starts_with("* OK"));

    stream.get_mut().write_all(b"A1 CAPABILITY\r\n").await?;
    stream.get_mut().flush().await?;
    let mut capability_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A1 OK");
        capability_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        !capability_lines
            .iter()
            .any(|line| line.contains("STARTTLS")),
        "{capability_lines:?}"
    );

    stream
        .get_mut()
        .write_all(b"A2 LOGIN \"user@example.test\" \"secret-password\"\r\n")
        .await?;
    stream.get_mut().flush().await?;
    let mut login_lines = Vec::new();
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let done = line.starts_with("A2 OK");
        login_lines.push(line);
        if done {
            break;
        }
    }
    assert!(login_lines.iter().any(|line| line.starts_with("A2 OK")));

    stream.get_mut().write_all(b"A3 LOGOUT\r\n").await?;
    stream.get_mut().flush().await?;
    let mut logout = String::new();
    stream.read_line(&mut logout).await?;
    assert!(logout.starts_with("* BYE"));

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn namespace_id_and_enable_return_metadata() -> anyhow::Result<()> {
    let services = AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.state = State::Authenticated;

    let namespace = session.handle(&services, "A1 NAMESPACE\r\n").await?;
    assert!(
        namespace
            .iter()
            .any(|line| line == r#"* NAMESPACE (("" "/")) NIL NIL"#)
    );
    assert!(
        namespace
            .iter()
            .any(|line| line == "A1 OK NAMESPACE completed")
    );

    let id = session.handle(&services, "A2 ID NIL\r\n").await?;
    assert!(
        id.iter()
            .any(|line| line.contains(r#"* ID ("name" "imap-cache-rs""#))
    );
    assert!(id.iter().any(|line| line == "A2 OK ID completed"));
    assert!(session.capabilities().contains(&"LIST-STATUS"));

    let enable = session.handle(&services, "A3 ENABLE CONDSTORE\r\n").await?;
    assert!(enable.iter().any(|line| line == "* ENABLED CONDSTORE"));
    assert!(enable.iter().any(|line| line == "A3 OK ENABLE completed"));

    Ok(())
}

#[tokio::test]
async fn enable_requires_authentication() -> anyhow::Result<()> {
    let services = AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();

    let enable = session.handle(&services, "A1 ENABLE CONDSTORE\r\n").await?;
    assert!(enable.iter().any(|line| line.contains("[BADSTATE]")));

    let condstore = session.handle(&services, "A2 CONDSTORE\r\n").await?;
    assert!(condstore.iter().any(|line| line.contains("[BADSTATE]")));

    Ok(())
}

#[tokio::test]
async fn mailbox_commands_use_database_state() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-protocol-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Protocol Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    repo.create_mailbox(NewMailbox {
        account_id: account.id,
        name: "INBOX",
        canonical_name: "inbox",
        delimiter: Some("/"),
        attributes: vec!["\\HasNoChildren".to_string()],
        subscribed: true,
        special_use: Some("\\Inbox"),
        uidvalidity: Some(1),
        uidnext: Some(1),
        highestmodseq: Some(0),
        exists_count: 0,
        recent_count: 0,
        unseen_count: 0,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    let login = session
        .handle(
            &services,
            &format!("A1 LOGIN \"{username}\" \"{password}\"\r\n"),
        )
        .await?;
    assert!(login.iter().any(|line| line.starts_with("A1 OK")));
    assert_eq!(session.state, State::Authenticated);
    assert_eq!(
        session
            .authenticated
            .as_ref()
            .and_then(|ctx| ctx.account_id),
        Some(account.id)
    );

    let mailbox_name = format!("Projects-{}", Uuid::new_v4());
    let create = session
        .handle(&services, &format!("A2 CREATE \"{mailbox_name}\"\r\n"))
        .await?;
    assert!(create.iter().any(|line| line.starts_with("A2 OK")));
    assert!(
        repo.find_mailbox(account.id, &mailbox_name)
            .await?
            .is_some()
    );

    let list = session.handle(&services, "A3 LIST \"\" \"*\"\r\n").await?;
    assert!(list.iter().any(|line| line.contains("INBOX")));
    assert!(list.iter().any(|line| line.contains(&mailbox_name)));

    let list_status = session
        .handle(
            &services,
            "A4 LIST \"\" \"*\" RETURN (STATUS (MESSAGES UIDNEXT HIGHESTMODSEQ))\r\n",
        )
        .await?;
    assert!(list_status.iter().any(|line| line.contains("INBOX")));
    assert!(
        list_status
            .iter()
            .any(|line| line.contains(&format!(r#"* STATUS "INBOX" (MESSAGES 0 UIDNEXT 1 HIGHESTMODSEQ 0)"#)))
    );
    assert!(
        list_status
            .iter()
            .any(|line| line.contains(&format!(r#"* STATUS "{}" (MESSAGES 0 UIDNEXT 1 HIGHESTMODSEQ 0)"#, mailbox_name)))
    );

    let status = session
        .handle(
            &services,
            &format!(
                "A5 STATUS \"{mailbox_name}\" (MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN HIGHESTMODSEQ)\r\n"
            ),
        )
        .await?;
    assert!(status.iter().any(|line| line.contains("MESSAGES 0")));
    assert!(status.iter().any(|line| line.contains("UIDNEXT 1")));
    assert!(status.iter().any(|line| line.contains("HIGHESTMODSEQ 0")));

    let filtered_status = session
        .handle(
            &services,
            &format!("A6 STATUS \"{mailbox_name}\" (MESSAGES UIDNEXT HIGHESTMODSEQ)\r\n"),
        )
        .await?;
    assert!(
        filtered_status
            .iter()
            .any(|line| line.contains("MESSAGES 0"))
    );
    assert!(
        filtered_status
            .iter()
            .any(|line| line.contains("UIDNEXT 1"))
    );
    assert!(
        filtered_status
            .iter()
            .any(|line| line.contains("HIGHESTMODSEQ 0"))
    );
    assert!(filtered_status.iter().all(|line| !line.contains("RECENT")));
    assert!(filtered_status.iter().all(|line| !line.contains("UNSEEN")));
    assert!(
        filtered_status
            .iter()
            .all(|line| !line.contains("UIDVALIDITY"))
    );

    let renamed = format!("{mailbox_name}-renamed");
    let rename = session
        .handle(
            &services,
            &format!("A7 RENAME \"{mailbox_name}\" \"{renamed}\"\r\n"),
        )
        .await?;
    assert!(rename.iter().any(|line| line.starts_with("A7 OK")));
    assert!(
        repo.find_mailbox(account.id, &mailbox_name)
            .await?
            .is_none()
    );
    assert!(repo.find_mailbox(account.id, &renamed).await?.is_some());

    let subscribe = session
        .handle(&services, &format!("A8 SUBSCRIBE \"{renamed}\"\r\n"))
        .await?;
    assert!(subscribe.iter().any(|line| line.starts_with("A8 OK")));
    assert!(
        repo.find_mailbox(account.id, &renamed)
            .await?
            .unwrap()
            .subscribed
    );

    let unsubscribe = session
        .handle(&services, &format!("A9 UNSUBSCRIBE \"{renamed}\"\r\n"))
        .await?;
    assert!(unsubscribe.iter().any(|line| line.starts_with("A9 OK")));
    assert!(
        !repo
            .find_mailbox(account.id, &renamed)
            .await?
            .unwrap()
            .subscribed
    );

    let lsub = session.handle(&services, "A10 LSUB \"\" \"*\"\r\n").await?;
    assert!(lsub.iter().all(|line| !line.contains(&renamed)));
    assert!(lsub.iter().any(|line| line.contains("INBOX")));

    let delete = session
        .handle(&services, &format!("A11 DELETE \"{renamed}\"\r\n"))
        .await?;
    assert!(delete.iter().any(|line| line.starts_with("A11 OK")));
    assert!(repo.find_mailbox(account.id, &renamed).await?.is_none());

    Ok(())
}

#[tokio::test]
async fn close_and_unselect_update_selected_mailbox_state() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-close-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Close Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .create_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?
        .expect("mailbox should be created");
    let message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/test-close",
            rfc822_sha256: "sha256-test-close",
            message_id_header: Some("<close@example.test>"),
            subject: Some("Close test"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([{"address": "bob@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Close test"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 32,
            text_preview: Some("close body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(201),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session
        .handle(
            &services,
            &format!("A1 LOGIN \"{username}\" \"{password}\"\r\n"),
        )
        .await?;
    let select = session.handle(&services, "A2 SELECT INBOX\r\n").await?;
    assert!(select.iter().any(|line| line.starts_with("A2 OK")));
    assert!(select.iter().any(|line| line.contains("HIGHESTMODSEQ 1")));
    assert_eq!(
        session.state,
        State::SelectedMailbox {
            read_only: false,
            mailbox: "INBOX".to_string()
        }
    );

    let store = session
        .handle(&services, "A3 STORE 1 (\\Deleted)\r\n")
        .await?;
    assert!(store.iter().any(|line| line.starts_with("A3 OK")));

    let unselect = session.handle(&services, "A4 UNSELECT\r\n").await?;
    assert!(unselect.iter().any(|line| line.starts_with("A4 OK")));
    assert_eq!(session.state, State::Authenticated);
    assert_eq!(repo.list_mailbox_messages(inbox.id).await?.len(), 1);

    session.handle(&services, "A5 SELECT INBOX\r\n").await?;
    let close = session.handle(&services, "A6 CLOSE\r\n").await?;
    assert!(close.iter().any(|line| line.starts_with("A6 OK")));
    assert_eq!(session.state, State::Authenticated);
    assert!(repo.list_mailbox_messages(inbox.id).await?.is_empty());

    Ok(())
}

#[tokio::test]
async fn mailbox_commands_require_selected_mailbox() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-selected-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    repo.create_mail_account(NewMailAccount {
        user_id: user.id,
        display_name: "Selected State Test",
        email_address: &username,
        upstream_host: "imap.example.test",
        upstream_port: 993,
        upstream_tls_mode: UpstreamTlsMode::Tls,
        upstream_auth_method: UpstreamAuthMethod::Login,
        upstream_username: "upstream-user",
        upstream_secret: "upstream-secret",
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session
        .handle(
            &services,
            &format!("A1 LOGIN \"{username}\" \"{password}\"\r\n"),
        )
        .await?;

    let check = session.handle(&services, "A2 CHECK\r\n").await?;
    assert!(check.iter().any(|line| line.contains("[BADSTATE]")));

    let idle = session.handle(&services, "A3 IDLE\r\n").await?;
    assert!(idle.iter().any(|line| line.contains("[BADSTATE]")));

    let unselect = session.handle(&services, "A4 UNSELECT\r\n").await?;
    assert!(unselect.iter().any(|line| line.contains("[BADSTATE]")));

    let close = session.handle(&services, "A5 CLOSE\r\n").await?;
    assert!(close.iter().any(|line| line.contains("[BADSTATE]")));

    Ok(())
}

#[tokio::test]
async fn examine_keeps_mailbox_read_only() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-examine-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Examine Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .create_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?
        .expect("mailbox should be created");
    let message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/test-examine",
            rfc822_sha256: "sha256-test-examine",
            message_id_header: Some("<examine@example.test>"),
            subject: Some("Examine test"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([{"address": "bob@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Examine test"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 32,
            text_preview: Some("examine body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(301),
        modseq: Some(1),
        flags: vec!["\\Deleted".to_string()],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session
        .handle(
            &services,
            &format!("A1 LOGIN \"{username}\" \"{password}\"\r\n"),
        )
        .await?;
    let examine = session.handle(&services, "A2 EXAMINE INBOX\r\n").await?;
    assert!(
        examine
            .iter()
            .any(|line| line.contains("[READ-ONLY] EXAMINE completed"))
    );
    assert_eq!(
        session.state,
        State::SelectedMailbox {
            read_only: true,
            mailbox: "INBOX".to_string()
        }
    );

    let store = session
        .handle(&services, "A3 STORE 1 +FLAGS (\\Seen)\r\n")
        .await?;
    assert!(store.iter().any(|line| line.contains("[READ-ONLY]")));
    assert_eq!(
        repo.list_mailbox_messages(inbox.id).await?[0]
            .flags
            .iter()
            .filter(|flag| flag.eq_ignore_ascii_case("\\Seen"))
            .count(),
        0
    );

    let expunge = session.handle(&services, "A4 EXPUNGE\r\n").await?;
    assert!(expunge.iter().any(|line| line.contains("[READ-ONLY]")));
    assert_eq!(repo.list_mailbox_messages(inbox.id).await?.len(), 1);

    let close = session.handle(&services, "A5 CLOSE\r\n").await?;
    assert!(close.iter().any(|line| line.starts_with("A5 OK")));
    assert_eq!(session.state, State::Authenticated);
    let remaining = repo.list_mailbox_messages(inbox.id).await?;
    assert_eq!(remaining.len(), 1);
    assert!(
        remaining[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Deleted"))
    );

    Ok(())
}

#[tokio::test]
async fn store_updates_flags_and_honors_silent_modifier() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-store-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Store Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 1,
            unseen_count: 0,
        })
        .await?;
    let message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/test-store",
            rfc822_sha256: "sha256-test-store",
            message_id_header: Some("<store@example.test>"),
            subject: Some("Store test"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([{"address": "bob@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Store test"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 32,
            text_preview: Some("store body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(301),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session
        .handle(
            &services,
            &format!("A1 LOGIN \"{username}\" \"{password}\"\r\n"),
        )
        .await?;
    session.handle(&services, "A2 SELECT INBOX\r\n").await?;

    let store = session
        .handle(&services, "A3 STORE 1 +FLAGS (\\Seen)\r\n")
        .await?;
    assert!(
        store
            .iter()
            .any(|line| line.contains("* 1 FETCH (FLAGS (\\Seen))"))
    );
    assert!(store.iter().any(|line| line.starts_with("A3 OK")));
    let modseq = session
        .handle(&services, "A4 FETCH 1 (MODSEQ)\r\n")
        .await?;
    assert!(
        modseq
            .iter()
            .any(|line| line.contains("* 1 FETCH (MODSEQ (2))"))
    );
    assert!(modseq.iter().any(|line| line.starts_with("A4 OK")));
    let updated = repo.list_mailbox_messages(inbox.id).await?;
    assert!(
        updated[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
    );

    let silent = session
        .handle(&services, "A5 STORE 1 +FLAGS.SILENT (\\Flagged)\r\n")
        .await?;
    assert!(silent.iter().all(|line| !line.contains("FETCH")));
    assert!(silent.iter().any(|line| line.starts_with("A5 OK")));
    let modseq = session
        .handle(&services, "A6 FETCH 1 (MODSEQ)\r\n")
        .await?;
    assert!(
        modseq
            .iter()
            .any(|line| line.contains("* 1 FETCH (MODSEQ (3))"))
    );
    assert!(modseq.iter().any(|line| line.starts_with("A6 OK")));
    let updated = repo.list_mailbox_messages(inbox.id).await?;
    assert!(
        updated[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
    );
    assert!(
        updated[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Flagged"))
    );

    Ok(())
}

#[tokio::test]
async fn concurrent_clients_see_store_updates() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-concurrent-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Concurrent Store Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 1,
            unseen_count: 0,
        })
        .await?;
    let message = repo
        .upsert_message(NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/concurrent-store",
            rfc822_sha256: "sha256-concurrent-store",
            message_id_header: Some("<concurrent-store@example.test>"),
            subject: Some("Concurrent Store Test"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([{"address": "bob@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Concurrent Store Test"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 32,
            text_preview: Some("store body"),
        })
        .await?;
    repo.upsert_mailbox_message(NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(401),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session_a = ImapSession::new();
    session_a
        .handle(
            &services,
            &format!("A1 LOGIN \"{username}\" \"{password}\"\r\n"),
        )
        .await?;
    session_a.handle(&services, "A2 SELECT INBOX\r\n").await?;

    let mut session_b = ImapSession::new();
    session_b
        .handle(
            &services,
            &format!("B1 LOGIN \"{username}\" \"{password}\"\r\n"),
        )
        .await?;
    session_b.handle(&services, "B2 SELECT INBOX\r\n").await?;

    let store = session_b
        .handle(&services, "B3 STORE 1 +FLAGS (\\Seen)\r\n")
        .await?;
    assert!(
        store
            .iter()
            .any(|line| line.contains("* 1 FETCH (FLAGS (\\Seen))"))
    );
    assert!(store.iter().any(|line| line.starts_with("B3 OK")));

    let fetch = session_a.handle(&services, "A3 FETCH 1 FLAGS\r\n").await?;
    assert!(
        fetch
            .iter()
            .any(|line| line.contains("* 1 FETCH (FLAGS (\\Seen))"))
    );
    assert!(fetch.iter().any(|line| line.starts_with("A3 OK")));

    Ok(())
}

#[tokio::test]
async fn live_imap_server_concurrent_clients_see_store_updates_over_wire() -> anyhow::Result<()> {
    let _live_guard = live_test_guard().await;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("live-concurrent-{}@example.test", Uuid::new_v4());
    let password = "secret";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Concurrent Store",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;
    let message = repo
        .upsert_message(NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/live-concurrent-store",
            rfc822_sha256: "sha256-live-concurrent-store",
            message_id_header: Some("<live-concurrent-store@example.test>"),
            subject: Some("Live Concurrent Store"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([{"address": "bob@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Live Concurrent Store"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 32,
            text_preview: Some("live concurrent body"),
        })
        .await?;
    repo.upsert_mailbox_message(NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(401),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = Arc::new(AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn({
        let services = Arc::clone(&services);
        async move { serve_plaintext(listener, services, None).await }
    });

    let client_a = tokio::net::TcpStream::connect(addr).await?;
    let mut a = BufReader::new(client_a);
    let mut greeting_a = String::new();
    a.read_line(&mut greeting_a).await?;
    assert!(greeting_a.starts_with("* OK"));
    a.get_mut()
        .write_all(format!("A1 LOGIN \"{}\" \"{}\"\r\n", username, password).as_bytes())
        .await?;
    a.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        a.read_line(&mut line).await?;
        if line.starts_with("A1 OK") {
            break;
        }
    }
    a.get_mut().write_all(b"A2 SELECT INBOX\r\n").await?;
    a.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        a.read_line(&mut line).await?;
        if line.starts_with("A2 OK") {
            break;
        }
    }

    let client_b = tokio::net::TcpStream::connect(addr).await?;
    let mut b = BufReader::new(client_b);
    let mut greeting_b = String::new();
    b.read_line(&mut greeting_b).await?;
    assert!(greeting_b.starts_with("* OK"));
    b.get_mut()
        .write_all(format!("B1 LOGIN \"{}\" \"{}\"\r\n", username, password).as_bytes())
        .await?;
    b.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        b.read_line(&mut line).await?;
        if line.starts_with("B1 OK") {
            break;
        }
    }
    b.get_mut().write_all(b"B2 SELECT INBOX\r\n").await?;
    b.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        b.read_line(&mut line).await?;
        if line.starts_with("B2 OK") {
            break;
        }
    }

    b.get_mut().write_all(b"B3 STORE 1 +FLAGS.SILENT (\\Seen)\r\n").await?;
    b.get_mut().flush().await?;
    let mut store_lines = Vec::new();
    loop {
        let mut line = String::new();
        b.read_line(&mut line).await?;
        let done = line.starts_with("B3 OK");
        store_lines.push(line);
        if done {
            break;
        }
    }
    assert!(store_lines.iter().all(|line| !line.contains("FETCH")), "{store_lines:?}");
    assert!(store_lines.iter().any(|line| line.starts_with("B3 OK")), "{store_lines:?}");

    a.get_mut().write_all(b"A3 FETCH 1 FLAGS\r\n").await?;
    a.get_mut().flush().await?;
    let mut fetch_lines = Vec::new();
    loop {
        let mut line = String::new();
        a.read_line(&mut line).await?;
        let done = line.starts_with("A3 OK");
        fetch_lines.push(line);
        if done {
            break;
        }
    }
    assert!(
        fetch_lines
            .iter()
            .any(|line| line.contains("* 1 FETCH (FLAGS (\\Seen))")),
        "{fetch_lines:?}"
    );
    assert!(fetch_lines.iter().any(|line| line.starts_with("A3 OK")));

    a.get_mut().write_all(b"A4 LOGOUT\r\n").await?;
    a.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        a.read_line(&mut line).await?;
        if line.starts_with("A4 OK") {
            break;
        }
    }

    b.get_mut().write_all(b"B4 LOGOUT\r\n").await?;
    b.get_mut().flush().await?;
    loop {
        let mut line = String::new();
        b.read_line(&mut line).await?;
        if line.starts_with("B4 OK") {
            break;
        }
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn list_and_lsub_apply_wildcard_patterns() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-list-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "List Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    repo.create_mailbox(NewMailbox {
        account_id: account.id,
        name: "INBOX",
        canonical_name: "inbox",
        delimiter: Some("/"),
        attributes: vec!["\\HasNoChildren".to_string()],
        subscribed: true,
        special_use: Some("\\Inbox"),
        uidvalidity: Some(1),
        uidnext: Some(1),
        highestmodseq: Some(0),
        exists_count: 0,
        recent_count: 0,
        unseen_count: 0,
    })
    .await?;
    repo.create_mailbox(NewMailbox {
        account_id: account.id,
        name: "Projects/Alpha",
        canonical_name: "projects/alpha",
        delimiter: Some("/"),
        attributes: vec!["\\HasNoChildren".to_string()],
        subscribed: true,
        special_use: None,
        uidvalidity: Some(1),
        uidnext: Some(1),
        highestmodseq: Some(0),
        exists_count: 0,
        recent_count: 0,
        unseen_count: 0,
    })
    .await?;
    repo.create_mailbox(NewMailbox {
        account_id: account.id,
        name: "Projects/Alpha/Child",
        canonical_name: "projects/alpha/child",
        delimiter: Some("/"),
        attributes: vec!["\\HasNoChildren".to_string()],
        subscribed: true,
        special_use: None,
        uidvalidity: Some(1),
        uidnext: Some(1),
        highestmodseq: Some(0),
        exists_count: 0,
        recent_count: 0,
        unseen_count: 0,
    })
    .await?;
    repo.create_mailbox(NewMailbox {
        account_id: account.id,
        name: "Projects/Private",
        canonical_name: "projects/private",
        delimiter: Some("/"),
        attributes: vec!["\\HasNoChildren".to_string()],
        subscribed: false,
        special_use: None,
        uidvalidity: Some(1),
        uidnext: Some(1),
        highestmodseq: Some(0),
        exists_count: 0,
        recent_count: 0,
        unseen_count: 0,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session
        .handle(
            &services,
            &format!("A1 LOGIN \"{username}\" \"secret-password\"\r\n"),
        )
        .await?;

    let list_one_level = session
        .handle(&services, "A2 LIST \"\" \"Projects/%\"\r\n")
        .await?;
    assert!(
        list_one_level
            .iter()
            .any(|line| line.contains("\"Projects/Alpha\""))
    );
    assert!(
        list_one_level
            .iter()
            .any(|line| line.contains("\"Projects/Private\""))
    );
    assert!(
        !list_one_level
            .iter()
            .any(|line| line.contains("\"Projects/Alpha/Child\""))
    );

    let list_recursive = session
        .handle(&services, "A3 LIST \"\" \"Projects/*\"\r\n")
        .await?;
    assert!(
        list_recursive
            .iter()
            .any(|line| line.contains("\"Projects/Alpha\""))
    );
    assert!(
        list_recursive
            .iter()
            .any(|line| line.contains("\"Projects/Private\""))
    );
    assert!(
        list_recursive
            .iter()
            .any(|line| line.contains("\"Projects/Alpha/Child\""))
    );

    let lsub = session
        .handle(&services, "A4 LSUB \"\" \"Projects/%\"\r\n")
        .await?;
    assert!(lsub.iter().any(|line| line.contains("\"Projects/Alpha\"")));
    assert!(
        !lsub
            .iter()
            .any(|line| line.contains("\"Projects/Private\""))
    );
    assert!(
        lsub.iter()
            .all(|line| !line.contains("\"Projects/Alpha/Child\""))
    );

    Ok(())
}

#[tokio::test]
async fn search_and_uid_search_return_sequence_and_uid_results() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));
    let search = Arc::new(TantivySearchEngine::memory()?);

    let username = format!("imap-search-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Search Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let raw_a = concat!(
        "From: Alice <alice@example.test>\r\n",
        "Subject: Alpha\r\n",
        "\r\n",
        "first body\r\n",
    );
    let parsed_a = parse_message(raw_a.as_bytes())?;
    let message_a = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/search-a",
            rfc822_sha256: "sha256-search-a",
            message_id_header: Some("<search-a@example.test>"),
            subject: Some("Alpha"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Alpha"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: raw_a.len() as i64,
            text_preview: Some("first body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message_a.id,
        local_uid: 2,
        upstream_uid: Some(102),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;
    search
        .index_message("INBOX", SearchDocument::from_parsed_message(2, &parsed_a))
        .await?;

    let raw_b = concat!(
        "From: Alice <alice@example.test>\r\n",
        "Bcc: Hidden <hiddenbeta@example.test>\r\n",
        "Subject: Beta\r\n",
        "\r\n",
        "uniquebeta body\r\n",
    );
    let parsed_b = parse_message(raw_b.as_bytes())?;
    let message_b = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/search-b",
            rfc822_sha256: "sha256-search-b",
            message_id_header: Some("<search-b@example.test>"),
            subject: Some("Beta"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([]),
            cc_json: json!([]),
            bcc_json: parsed_b.bcc_json.clone(),
            reply_to_json: json!([]),
            envelope_json: json!({
                "subject": "Beta",
                "message_id": "<search-unseen@example.test>"
            }),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: raw_b.len() as i64,
            text_preview: Some("uniquebeta body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message_b.id,
        local_uid: 7,
        upstream_uid: Some(107),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;
    search
        .index_message("INBOX", SearchDocument::from_parsed_message(7, &parsed_b))
        .await?;

    let services = AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: Some(search),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: username.clone(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let search_lines = session
        .handle(&services, "A1 SEARCH TEXT \"uniquebeta\"\r\n")
        .await?;
    assert!(search_lines.iter().any(|line| line == "* SEARCH 2"));
    assert!(
        search_lines
            .iter()
            .any(|line| line == "A1 OK SEARCH completed")
    );

    let bcc_search_lines = session
        .handle(&services, "A1 SEARCH BCC hiddenbeta@example.test\r\n")
        .await?;
    assert!(bcc_search_lines.iter().any(|line| line == "* SEARCH 2"));
    assert!(
        bcc_search_lines
            .iter()
            .any(|line| line == "A1 OK SEARCH completed")
    );

    let uid_search_lines = session
        .handle(&services, "A2 UID SEARCH TEXT \"uniquebeta\"\r\n")
        .await?;
    assert!(uid_search_lines.iter().any(|line| line == "* SEARCH 7"));
    assert!(
        uid_search_lines
            .iter()
            .any(|line| line == "A2 OK UID SEARCH completed")
    );

    Ok(())
}

#[tokio::test]
async fn search_filters_by_seen_and_size() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-search-flags-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Search Flags Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 1,
            unseen_count: 0,
        })
        .await?;

    let seen_message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/search-seen",
            rfc822_sha256: "sha256-search-seen",
            message_id_header: Some("<search-seen@example.test>"),
            subject: Some("Seen message"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Seen message"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 200,
            text_preview: Some("seen body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: seen_message.id,
        local_uid: 1,
        upstream_uid: Some(401),
        modseq: Some(1),
        flags: vec!["\\Seen".to_string()],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let unseen_message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/search-unseen",
            rfc822_sha256: "sha256-search-unseen",
            message_id_header: Some("<search-unseen@example.test>"),
            subject: Some("Unseen message"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Unseen message"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 20,
            text_preview: Some("unseen body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: unseen_message.id,
        local_uid: 2,
        upstream_uid: Some(402),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: username.clone(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let seen_lines = session.handle(&services, "A1 SEARCH SEEN\r\n").await?;
    assert!(seen_lines.iter().any(|line| line == "* SEARCH 1"));
    assert!(
        seen_lines
            .iter()
            .any(|line| line == "A1 OK SEARCH completed")
    );

    let all_seen_lines = session.handle(&services, "A1 SEARCH ALL SEEN\r\n").await?;
    assert!(all_seen_lines.iter().any(|line| line == "* SEARCH 1"));
    assert!(
        all_seen_lines
            .iter()
            .any(|line| line == "A1 OK SEARCH completed")
    );

    let unseen_small_lines = session
        .handle(&services, "A2 SEARCH UNSEEN SMALLER 50\r\n")
        .await?;
    assert!(unseen_small_lines.iter().any(|line| line == "* SEARCH 2"));
    assert!(
        unseen_small_lines
            .iter()
            .any(|line| line == "A2 OK SEARCH completed")
    );

    let charset_lines = session
        .handle(&services, "A3 SEARCH CHARSET UTF-8 UNSEEN\r\n")
        .await?;
    assert!(charset_lines.iter().any(|line| line == "* SEARCH 2"));
    assert!(charset_lines.iter().any(|line| line == "A3 OK SEARCH completed"));

    let recent_lines = session.handle(&services, "A4 SEARCH RECENT\r\n").await?;
    assert!(recent_lines.iter().any(|line| line == "* SEARCH 2"));
    assert!(recent_lines.iter().any(|line| line == "A4 OK SEARCH completed"));

    let new_lines = session.handle(&services, "A5 SEARCH NEW\r\n").await?;
    assert!(new_lines.iter().any(|line| line == "* SEARCH 2"));
    assert!(new_lines.iter().any(|line| line == "A5 OK SEARCH completed"));

    let old_lines = session.handle(&services, "A6 SEARCH OLD\r\n").await?;
    assert!(old_lines.iter().any(|line| line == "* SEARCH 1"));
    assert!(old_lines.iter().any(|line| line == "A6 OK SEARCH completed"));

    let header_lines = session
        .handle(
            &services,
            "A7 SEARCH HEADER Subject \"Unseen message\"\r\n",
        )
        .await?;
    assert!(header_lines.iter().any(|line| line == "* SEARCH 2"));
    assert!(header_lines.iter().any(|line| line == "A7 OK SEARCH completed"));

    let uid_charset_lines = session
        .handle(&services, "A8 UID SEARCH RETURN (COUNT) CHARSET UTF-8 SEEN\r\n")
        .await?;
    assert!(
        uid_charset_lines
            .iter()
            .any(|line| line == r#"* ESEARCH (TAG "A8") COUNT 1"#)
    );
    assert!(
        uid_charset_lines
            .iter()
            .any(|line| line == "A8 OK UID SEARCH completed")
    );

    let uid_all_seen_lines = session
        .handle(&services, "A9 UID SEARCH ALL SEEN\r\n")
        .await?;
    assert!(
        uid_all_seen_lines
            .iter()
            .any(|line| line == "* SEARCH 1")
    );
    assert!(
        uid_all_seen_lines
            .iter()
            .any(|line| line == "A9 OK UID SEARCH completed")
    );

    let not_seen_lines = session.handle(&services, "A10 SEARCH NOT SEEN\r\n").await?;
    assert!(not_seen_lines.iter().any(|line| line == "* SEARCH 2"));
    assert!(not_seen_lines.iter().any(|line| line == "A10 OK SEARCH completed"));

    let or_lines = session
        .handle(&services, "A11 SEARCH OR SEEN UNSEEN\r\n")
        .await?;
    assert!(or_lines.iter().any(|line| line == "* SEARCH 1 2"));
    assert!(or_lines.iter().any(|line| line == "A11 OK SEARCH completed"));

    let uid_or_lines = session
        .handle(&services, "A12 UID SEARCH OR SEEN UNSEEN\r\n")
        .await?;
    assert!(uid_or_lines.iter().any(|line| line == "* SEARCH 1 2"));
    assert!(uid_or_lines.iter().any(|line| line == "A12 OK UID SEARCH completed"));

    Ok(())
}

#[tokio::test]
async fn search_return_count_min_max_all_emits_esearch() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-esearch-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "ESearch Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let seen_message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/esearch-seen",
            rfc822_sha256: "sha256-esearch-seen",
            message_id_header: Some("<esearch-seen@example.test>"),
            subject: Some("Seen esearch"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Seen esearch"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 200,
            text_preview: Some("seen esearch body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: seen_message.id,
        local_uid: 1,
        upstream_uid: Some(701),
        modseq: Some(1),
        flags: vec!["\\Seen".to_string()],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let unseen_message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/esearch-unseen",
            rfc822_sha256: "sha256-esearch-unseen",
            message_id_header: Some("<esearch-unseen@example.test>"),
            subject: Some("Unseen esearch"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Unseen esearch"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 20,
            text_preview: Some("unseen esearch body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: unseen_message.id,
        local_uid: 2,
        upstream_uid: Some(702),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: username.clone(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let search_lines = session
        .handle(&services, "A1 SEARCH RETURN (COUNT MIN MAX ALL) SEEN\r\n")
        .await?;
    assert!(
        search_lines
            .iter()
            .any(|line| line == r#"* ESEARCH (TAG "A1") COUNT 1 MIN 1 MAX 1 ALL 1"#)
    );
    assert!(
        search_lines
            .iter()
            .any(|line| line == "A1 OK SEARCH completed")
    );

    let uid_search_lines = session
        .handle(
            &services,
            "A2 UID SEARCH RETURN (COUNT MIN MAX ALL) SEEN\r\n",
        )
        .await?;
    assert!(
        uid_search_lines
            .iter()
            .any(|line| line == r#"* ESEARCH (TAG "A2") COUNT 1 MIN 1 MAX 1 ALL 1"#),
        "{uid_search_lines:?}"
    );
    assert!(
        uid_search_lines
            .iter()
            .any(|line| line == "A2 OK UID SEARCH completed")
    );

    Ok(())
}

#[tokio::test]
async fn sort_and_uid_sort_order_by_subject() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-sort-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Sort Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let alpha = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/sort-alpha",
            rfc822_sha256: "sha256-sort-alpha",
            message_id_header: Some("<sort-alpha@example.test>"),
            subject: Some("Alpha"),
            from_json: json!([{"address": "alpha@example.test"}]),
            to_json: json!([]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Alpha"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: Some(Utc::now()),
            sent_date: Some(Utc::now()),
            size_octets: 11,
            text_preview: Some("alpha body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: alpha.id,
        local_uid: 20,
        upstream_uid: Some(520),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let zulu = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/sort-zulu",
            rfc822_sha256: "sha256-sort-zulu",
            message_id_header: Some("<sort-zulu@example.test>"),
            subject: Some("Zulu"),
            from_json: json!([{"address": "zulu@example.test"}]),
            to_json: json!([]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Zulu"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: Some(Utc::now()),
            sent_date: Some(Utc::now()),
            size_octets: 12,
            text_preview: Some("zulu body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: zulu.id,
        local_uid: 10,
        upstream_uid: Some(510),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: username.clone(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let sort_lines = session
        .handle(&services, "A1 SORT (SUBJECT) UTF-8 ALL\r\n")
        .await?;
    assert!(sort_lines.iter().any(|line| line == "* SORT 2 1"));
    assert!(sort_lines.iter().any(|line| line == "A1 OK SORT completed"));

    let uid_sort_lines = session
        .handle(&services, "A2 UID SORT (SUBJECT) UTF-8 ALL\r\n")
        .await?;
    assert!(uid_sort_lines.iter().any(|line| line == "* SORT 20 10"));
    assert!(
        uid_sort_lines
            .iter()
            .any(|line| line == "A2 OK UID SORT completed")
    );

    Ok(())
}

#[tokio::test]
async fn copy_move_store_and_expunge_update_local_mailbox_rows() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-copy-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Copy Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;
    let archive = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "Archive",
            canonical_name: "archive",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: None,
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/test-copy",
            rfc822_sha256: "sha256-test-copy",
            message_id_header: Some("<copy@example.test>"),
            subject: Some("Copy test"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([{"address": "bob@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Copy test"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 32,
            text_preview: Some("copy body"),
        })
        .await?;

    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(101),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 2,
        upstream_uid: Some(102),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: username.clone(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let copy = session.handle(&services, "A1 COPY 1 Archive\r\n").await?;
    assert!(copy.iter().any(|line| line.starts_with("A1 OK")));
    assert!(copy.iter().any(|line| line.contains("COPYUID")));
    assert_eq!(repo.list_mailbox_messages(archive.id).await?.len(), 1);
    assert_eq!(repo.list_mailbox_messages(inbox.id).await?.len(), 2);

    let uid_move = session
        .handle(&services, "A2 UID MOVE 2 Archive\r\n")
        .await?;
    assert!(uid_move.iter().any(|line| line.starts_with("A2 OK")));
    assert!(uid_move.iter().any(|line| line.contains("COPYUID")));
    assert_eq!(repo.list_mailbox_messages(archive.id).await?.len(), 2);
    assert_eq!(repo.list_mailbox_messages(inbox.id).await?.len(), 1);

    let store = session
        .handle(&services, "A3 STORE 1 (\\Deleted)\r\n")
        .await?;
    assert!(store.iter().any(|line| line.starts_with("A3 OK")));
    assert!(
        repo.list_mailbox_messages(inbox.id)
            .await?
            .into_iter()
            .any(|message| message.local_uid == 1
                && message.flags.iter().any(|flag| flag == "\\Deleted"))
    );

    let expunge = session.handle(&services, "A4 EXPUNGE\r\n").await?;
    assert!(expunge.iter().any(|line| line.contains("EXPUNGE")));
    assert!(repo.list_mailbox_messages(inbox.id).await?.is_empty());

    Ok(())
}

#[tokio::test]
async fn uid_expunge_only_removes_deleted_messages() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-uid-expunge-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "UID EXPUNGE Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/test-uid-expunge",
            rfc822_sha256: "sha256-test-uid-expunge",
            message_id_header: Some("<uid-expunge@example.test>"),
            subject: Some("UID expunge test"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([{"address": "bob@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "UID expunge test"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 32,
            text_preview: Some("uid expunge body"),
        })
        .await?;

    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(201),
        modseq: Some(1),
        flags: vec!["\\Deleted".to_string()],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 2,
        upstream_uid: Some(202),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: username.clone(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let response = session.handle(&services, "A1 UID EXPUNGE 1:2\r\n").await?;
    assert!(response.iter().any(|line| line == "* 1 EXPUNGE"));
    assert!(
        response
            .iter()
            .any(|line| line == "A1 OK UID EXPUNGE completed")
    );

    let remaining = repo.list_mailbox_messages(inbox.id).await?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].local_uid, 2);
    assert!(
        !remaining[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Deleted"))
    );

    Ok(())
}

#[tokio::test]
async fn expunge_renumbers_sequence_numbers_for_other_selected_clients() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-expunge-race-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Expunge Race Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let message_one = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/test-expunge-race-1",
            rfc822_sha256: "sha256-test-expunge-race-1",
            message_id_header: Some("<expunge-race-1@example.test>"),
            subject: Some("Expunge race one"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([{"address": "bob@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Expunge race one"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 32,
            text_preview: Some("expunge race one"),
        })
        .await?;
    let message_two = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/test-expunge-race-2",
            rfc822_sha256: "sha256-test-expunge-race-2",
            message_id_header: Some("<expunge-race-2@example.test>"),
            subject: Some("Expunge race two"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([{"address": "bob@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Expunge race two"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 32,
            text_preview: Some("expunge race two"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message_one.id,
        local_uid: 1,
        upstream_uid: Some(501),
        modseq: Some(1),
        flags: vec!["\\Deleted".to_string()],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message_two.id,
        local_uid: 2,
        upstream_uid: Some(502),
        modseq: Some(1),
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session_a = ImapSession::new();
    session_a
        .handle(
            &services,
            &format!("A1 LOGIN \"{username}\" \"{password}\"\r\n"),
        )
        .await?;
    session_a.handle(&services, "A2 SELECT INBOX\r\n").await?;

    let mut session_b = ImapSession::new();
    session_b
        .handle(
            &services,
            &format!("B1 LOGIN \"{username}\" \"{password}\"\r\n"),
        )
        .await?;
    session_b.handle(&services, "B2 SELECT INBOX\r\n").await?;

    let expunge = session_a.handle(&services, "A3 EXPUNGE\r\n").await?;
    assert!(expunge.iter().any(|line| line == "* 1 EXPUNGE"));
    assert!(expunge.iter().any(|line| line == "A3 OK EXPUNGE completed"));

    let fetch = session_b
        .handle(&services, "B3 FETCH 1 (UID FLAGS)\r\n")
        .await?;
    assert!(fetch.iter().any(|line| line.contains("UID 2")));
    assert!(
        fetch
            .iter()
            .any(|line| line.contains("FLAGS ()") || line.contains("FLAGS (\\Seen)"))
    );
    assert!(fetch.iter().any(|line| line.starts_with("B3 OK")));

    let mailbox_messages = repo.list_mailbox_messages(inbox.id).await?;
    assert_eq!(mailbox_messages.len(), 1);
    assert_eq!(mailbox_messages[0].local_uid, 2);

    Ok(())
}

#[tokio::test]
async fn append_persists_locally_and_returns_appenduid() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-append-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Append Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: username.clone(),
    });
    session.state = State::Authenticated;

    let raw = concat!(
        "From: Alice <alice@example.test>\r\n",
        "Subject: Append test\r\n",
        "\r\n",
        "Append body.\r\n"
    )
    .as_bytes()
    .to_vec();

    let expected_internal_date =
        chrono::DateTime::parse_from_str("12-Feb-2024 10:00:00 +0000", "%d-%b-%Y %H:%M:%S %z")?
            .with_timezone(&Utc);

    let response = session
        .handle_parsed_command(
            &services,
            ParsedCommand {
                tag: "A1".to_string(),
                name: "APPEND".to_string(),
                args: vec![
                    "INBOX".to_string(),
                    "(\\Seen)".to_string(),
                    "12-Feb-2024 10:00:00 +0000".to_string(),
                    "{44}".to_string(),
                ],
            },
            Some(raw.clone()),
        )
        .await?;
    assert!(response.iter().any(|line| line.contains("APPENDUID")));
    let joined = response.join("\n");
    assert!(joined.contains("A1 OK [APPENDUID 1 1] APPEND completed"));

    let messages = repo.list_mailbox_message_views(mailbox.id).await?;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].local_uid, 1);
    assert_eq!(messages[0].subject.as_deref(), Some("Append test"));
    assert!(
        messages[0]
            .flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
    );
    assert_eq!(messages[0].internal_date, Some(expected_internal_date));
    assert_eq!(messages[0].size_octets, raw.len() as i64);

    Ok(())
}

#[tokio::test]
async fn fetch_returns_database_backed_message_metadata() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-fetch-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Fetch Test",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/test-fetch",
            rfc822_sha256: "sha256-test-fetch",
            message_id_header: Some("<fetch@example.test>"),
            subject: Some("Fetch test"),
            from_json: json!([{"kind": "mailbox", "display_name": "Alice", "address": "alice@example.test"}]),
            to_json: json!([{"kind": "mailbox", "display_name": "Bob", "address": "bob@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({
                "date": Utc::now().timestamp(),
                "subject": "Fetch test",
                "message_id": "<fetch@example.test>",
                "from": [{"kind": "mailbox", "display_name": "Alice", "address": "alice@example.test"}],
                "reply_to": [],
                "to": [{"kind": "mailbox", "display_name": "Bob", "address": "bob@example.test"}],
                "cc": [],
                "bcc": []
            }),
            bodystructure_json: json!({
                "type": "text",
                "subtype": "plain",
                "charset": "utf-8",
                "params": {"charset": "utf-8"},
                "transfer_encoding": "7BIT",
                "size": 42
            }),
            internal_date: Some(Utc::now()),
            sent_date: Some(Utc::now()),
            size_octets: 42,
            text_preview: Some("fetch body"),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(11),
        modseq: Some(1),
        flags: vec!["\\Seen".to_string()],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store: Arc::new(MemoryObjectStore::new()),
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: username.clone(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let fetch = session
        .handle(
            &services,
            "A1 FETCH 1 (FLAGS UID RFC822.SIZE ENVELOPE BODYSTRUCTURE MODSEQ)\r\n",
        )
        .await?;
    let joined = fetch.join("\n");
    assert!(joined.contains("* 1 FETCH"));
    assert!(joined.contains("FLAGS (\\Seen)"));
    assert!(joined.contains("UID 1"));
    assert!(joined.contains("RFC822.SIZE 42"));
    assert!(joined.contains("ENVELOPE"));
    assert!(joined.contains("BODYSTRUCTURE"));
    assert!(joined.contains("MODSEQ (1)"));

    Ok(())
}

#[tokio::test]
async fn fetch_encodes_nested_message_rfc822_bodystructure() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-nested-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Nested MIME Fetch",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let inbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(1),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let raw = concat!(
        "From: Outer <outer@example.com>\r\n",
        "To: Recipient <recipient@example.com>\r\n",
        "Subject: Encapsulated MIME Test\r\n",
        "Message-ID: <outer@example.com>\r\n",
        "Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: message/rfc822\r\n",
        "\r\n",
        "From: Nested <nested@example.com>\r\n",
        "To: Recipient <recipient@example.com>\r\n",
        "Subject: Nested Message\r\n",
        "Message-ID: <nested@example.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"inner\"\r\n",
        "\r\n",
        "--inner\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "Nested body.\r\n",
        "--inner\r\n",
        "Content-Type: application/pdf\r\n",
        "Content-Disposition: attachment; filename=\"nested.pdf\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "Zm9v\r\n",
        "--inner--\r\n"
    );
    let parsed = parse_message(raw.as_bytes())?;
    let blob_key = content_addressed_key(ObjectType::Rfc822, raw.as_bytes());
    let object_store = Arc::new(MemoryObjectStore::new());
    object_store.put(&blob_key, raw.as_bytes()).await?;
    let message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: &blob_key,
            rfc822_sha256: &parsed.raw_sha256,
            message_id_header: parsed.message_id_header.as_deref(),
            subject: parsed.subject.as_deref(),
            from_json: parsed.from_json.clone(),
            to_json: parsed.to_json.clone(),
            cc_json: parsed.cc_json.clone(),
            bcc_json: parsed.bcc_json.clone(),
            reply_to_json: parsed.reply_to_json.clone(),
            envelope_json: parsed.envelope_json.clone(),
            bodystructure_json: parsed.bodystructure_json.clone(),
            internal_date: Some(Utc::now()),
            sent_date: Some(Utc::now()),
            size_octets: raw.len() as i64,
            text_preview: parsed.text_preview.as_deref(),
        })
        .await?;
    repo.upsert_mailbox_message(imap_cache_rs::db::repository::NewMailboxMessage {
        mailbox_id: inbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(11),
        modseq: Some(1),
        flags: vec!["\\Seen".to_string()],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let services = AppServices {
        authenticator: Arc::new(PostgresAuthenticator::new(Arc::clone(&repo))),
        repository: Some(Arc::clone(&repo)),
        object_store,
        search: None,
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: username.clone(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let fetch = session
        .handle(&services, "A1 FETCH 1 (BODYSTRUCTURE)\r\n")
        .await?;
    let joined = fetch.join("\n");
    assert!(joined.contains(r#""message" "rfc822""#));
    assert!(joined.contains("Nested Message"));
    assert!(joined.contains("Nested body.") || joined.contains(r#""text" "plain""#));
    assert!(joined.contains("A1 OK FETCH completed"));

    Ok(())
}
