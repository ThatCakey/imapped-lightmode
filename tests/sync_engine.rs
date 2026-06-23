use imap_cache_rs::{
    AppServices,
    auth::{AuthContext, DenyAllAuthenticator},
    coordination::MemorySyncLockManager,
    db,
    db::repository::{NewMailAccount, NewMailbox, NewSyncState, NewUser, PostgresRepository},
    domain::{UpstreamAuthMethod, UpstreamTlsMode},
    metrics::AppMetrics,
    mime::parse_message,
    search::TantivySearchEngine,
    security::SecretBox,
    storage::memory::MemoryObjectStore,
    sync::{MessageIngestor, SyncEngine},
    upstream::{UpstreamAccountConfig, UpstreamClient},
};
use sqlx::postgres::PgPoolOptions;
use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};
use uuid::Uuid;
use imap_cache_test_support::live_test_guard as support_live_test_guard;

fn load_testing_credentials() -> anyhow::Result<UpstreamAccountConfig> {
    let text = fs::read_to_string(".testing-credentials")?;
    let mut username = None;
    let mut password = None;
    let mut imap_host = None;
    let mut imap_port = None;

    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Username: ") {
            username = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Password: ") {
            password = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("IMAP (SSL/TLS): ") {
            if let Some((host, port)) = value.trim().rsplit_once(':') {
                imap_host = Some(host.to_string());
                imap_port = Some(port.parse::<u16>()?);
            }
        }
    }

    Ok(UpstreamAccountConfig {
        host: imap_host.ok_or_else(|| anyhow::anyhow!("missing IMAP host"))?,
        port: imap_port.ok_or_else(|| anyhow::anyhow!("missing IMAP port"))?,
        tls_mode: UpstreamTlsMode::Tls,
        auth_method: UpstreamAuthMethod::Login,
        username: username.ok_or_else(|| anyhow::anyhow!("missing username"))?,
        secret: password.ok_or_else(|| anyhow::anyhow!("missing password"))?,
    })
}

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

#[tokio::test]
async fn sync_engine_discovers_mailbox_and_skips_already_synced_uids() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = MessageIngestor::new(repo.clone(), store.clone(), Some(search.clone()));
    let metrics = Arc::new(AppMetrics::new());
    let sync_engine = SyncEngine::new(repo.clone(), ingestor, Arc::clone(&metrics));

    let user_email = format!("sync-engine-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Sync Engine",
            email_address: &user_email,
            upstream_host: "127.0.0.1",
            upstream_port: 0,
            upstream_tls_mode: UpstreamTlsMode::Plain,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let fetch_count = Arc::new(AtomicUsize::new(0));
    let fetch_count_server = fetch_count.clone();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        reader
            .get_mut()
            .write_all(b"* OK fake sync upstream ready\r\n")
            .await
            .unwrap();

        loop {
            let mut line = String::new();
            let bytes = reader.read_line(&mut line).await.unwrap();
            if bytes == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            let tag = line
                .split_whitespace()
                .next()
                .unwrap_or("A0000")
                .to_string();
            if line.contains("CAPABILITY") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n{tag} OK CAPABILITY completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("LOGIN") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LIST") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n{tag} OK LIST completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("SELECT") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* FLAGS (\\Seen)\r\n* 1 EXISTS\r\n{tag} OK [READ-WRITE] SELECT completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("UID") && line.contains("SEARCH") {
                reader
                    .get_mut()
                    .write_all(format!("* SEARCH 1\r\n{tag} OK SEARCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("UID FETCH") && line.contains("FLAGS") {
                reader
                    .get_mut()
                    .write_all(b"* 1 FETCH (UID 1 FLAGS ())\r\n")
                    .await
                    .unwrap();
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK FETCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("UID FETCH") {
                fetch_count_server.fetch_add(1, Ordering::SeqCst);
                let body = concat!(
                    "From: Alice <alice@example.com>\r\n",
                    "To: Bob <bob@example.com>\r\n",
                    "Subject: Sync Engine Target\r\n",
                    "Message-ID: <sync-engine@example.com>\r\n",
                    "MIME-Version: 1.0\r\n",
                    "Content-Type: text/plain; charset=\"utf-8\"\r\n",
                    "\r\n",
                    "Hello from the sync engine.\r\n",
                )
                .as_bytes()
                .to_vec();
                let header = format!("* 1 FETCH (UID 1 BODY[] {{{}}}\r\n", body.len());
                reader.get_mut().write_all(header.as_bytes()).await.unwrap();
                reader.get_mut().write_all(&body).await.unwrap();
                reader
                    .get_mut()
                    .write_all(format!("\r\n)\r\n{tag} OK FETCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LOGOUT") {
                reader
                    .get_mut()
                    .write_all(
                        format!("* BYE logging out\r\n{tag} OK LOGOUT completed\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                break;
            }
        }
    });

    let mut client = UpstreamClient::connect(&UpstreamAccountConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls_mode: UpstreamTlsMode::Plain,
        auth_method: UpstreamAuthMethod::Login,
        username: "upstream-user".to_string(),
        secret: "upstream-secret".to_string(),
    })
    .await?
    .with_metrics(Arc::clone(&metrics));
    client.capability().await?;
    client.login("upstream-user", "upstream-secret").await?;

    let first = tokio::time::timeout(
        Duration::from_secs(20),
        sync_engine.sync_account(account.id, &mut client),
    )
    .await??;
    assert_eq!(first.mailboxes_synced, 1);
    assert_eq!(first.messages_synced, 1);

    let second = tokio::time::timeout(
        Duration::from_secs(20),
        sync_engine.sync_account(account.id, &mut client),
    )
    .await??;
    assert_eq!(second.mailboxes_synced, 1);
    assert_eq!(second.messages_synced, 0);

    let fetches = fetch_count.load(Ordering::SeqCst);
    assert_eq!(fetches, 1);
    assert_eq!(metrics.sync_runs_total(), 2);
    assert_eq!(metrics.sync_runs_failed(), 0);
    assert_eq!(metrics.upstream_connections(), 1);

    let synced_account = repo
        .find_account_by_id_any_state(account.id)
        .await?
        .expect("account should still exist");
    assert!(synced_account.last_sync_at.is_some());
    assert!(synced_account.last_sync_error.is_none());

    let message_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE account_id = $1")
            .bind(account.id)
            .fetch_one(repo.pool())
            .await?;
    assert_eq!(message_count, 1);

    client.logout().await?;
    let mailbox_id: i64 = sqlx::query_scalar(
        "SELECT id FROM mailboxes WHERE account_id = $1 AND canonical_name = $2",
    )
    .bind(account.id)
    .bind("inbox")
    .fetch_one(repo.pool())
    .await?;
    let sync_state = repo.load_sync_state(account.id, Some(mailbox_id)).await?;
    assert!(sync_state.is_some(), "mailbox checkpoint should be written");

    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn sync_engine_updates_flags_for_existing_messages() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = MessageIngestor::new(repo.clone(), store.clone(), Some(search.clone()));
    let metrics = Arc::new(AppMetrics::new());
    let sync_engine = SyncEngine::new(repo.clone(), ingestor, Arc::clone(&metrics));

    let user_email = format!("sync-flag-update-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Sync Flag Update",
            email_address: &user_email,
            upstream_host: "127.0.0.1",
            upstream_port: 0,
            upstream_tls_mode: UpstreamTlsMode::Plain,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let fetch_round = Arc::new(AtomicUsize::new(0));
    let fetch_round_server = Arc::clone(&fetch_round);

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        reader
            .get_mut()
            .write_all(b"* OK fake sync upstream ready\r\n")
            .await
            .unwrap();

        loop {
            let mut line = String::new();
            let bytes = reader.read_line(&mut line).await.unwrap();
            if bytes == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            let tag = line
                .split_whitespace()
                .next()
                .unwrap_or("A0000")
                .to_string();
            if line.contains("CAPABILITY") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n{tag} OK CAPABILITY completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("LOGIN") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LIST") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n{tag} OK LIST completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("SELECT") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* FLAGS (\\Seen)\r\n* 1 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n* OK [UIDNEXT 2] Predicted next UID\r\n* OK [HIGHESTMODSEQ 1] Highest mod-sequence value\r\n* OK [UNSEEN 1] First unseen message\r\n{tag} OK [READ-WRITE] SELECT completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("UID") && line.contains("SEARCH") {
                reader
                    .get_mut()
                    .write_all(format!("* SEARCH 1\r\n{tag} OK SEARCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("UID FETCH") && line.contains("FLAGS") {
                let round = fetch_round_server.fetch_add(1, Ordering::SeqCst);
                let flags = if round == 0 { "" } else { "\\Seen" };
                reader
                    .get_mut()
                    .write_all(
                        format!("* 1 FETCH (UID 1 FLAGS ({flags}))\r\n{tag} OK FETCH completed\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("UID FETCH") && line.contains("BODY.PEEK[]") {
                let body = concat!(
                    "From: Alice <alice@example.com>\r\n",
                    "To: Bob <bob@example.com>\r\n",
                    "Subject: Flag Sync\r\n",
                    "Message-ID: <sync-flag-update@example.com>\r\n",
                    "MIME-Version: 1.0\r\n",
                    "Content-Type: text/plain; charset=\"utf-8\"\r\n",
                    "\r\n",
                    "Flag sync body\r\n",
                )
                .as_bytes()
                .to_vec();
                let header = format!("* 1 FETCH (UID 1 BODY[] {{{}}}\r\n", body.len());
                reader.get_mut().write_all(header.as_bytes()).await.unwrap();
                reader.get_mut().write_all(&body).await.unwrap();
                reader
                    .get_mut()
                    .write_all(format!("\r\n)\r\n{tag} OK FETCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LOGOUT") {
                reader
                    .get_mut()
                    .write_all(
                        format!("* BYE logging out\r\n{tag} OK LOGOUT completed\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                break;
            }
        }
    });

    let mut client = UpstreamClient::connect(&UpstreamAccountConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls_mode: UpstreamTlsMode::Plain,
        auth_method: UpstreamAuthMethod::Login,
        username: "upstream-user".to_string(),
        secret: "upstream-secret".to_string(),
    })
    .await?
    .with_metrics(Arc::clone(&metrics));
    client.capability().await?;
    client.login("upstream-user", "upstream-secret").await?;

    let first = tokio::time::timeout(
        Duration::from_secs(20),
        sync_engine.sync_account(account.id, &mut client),
    )
    .await??;
    assert_eq!(first.mailboxes_synced, 1);
    assert_eq!(first.messages_synced, 1);

    let inbox = repo
        .find_mailbox(account.id, "INBOX")
        .await?
        .expect("mailbox should exist");
    let initial = repo.list_mailbox_messages(inbox.id).await?;
    assert_eq!(initial.len(), 1);
    assert!(initial[0].flags.is_empty());

    let second = tokio::time::timeout(
        Duration::from_secs(20),
        sync_engine.sync_account(account.id, &mut client),
    )
    .await??;
    assert_eq!(second.mailboxes_synced, 1);
    assert_eq!(second.messages_synced, 0);

    let updated = repo.list_mailbox_messages(inbox.id).await?;
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].flags, vec!["\\Seen".to_string()]);

    client.logout().await?;
    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn sync_engine_removes_mailboxes_deleted_upstream() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = MessageIngestor::new(repo.clone(), store.clone(), Some(search.clone()));
    let metrics = Arc::new(AppMetrics::new());
    let sync_engine = SyncEngine::new(repo.clone(), ingestor, Arc::clone(&metrics));

    let user_email = format!("sync-mailbox-drop-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Sync Mailbox Drop",
            email_address: &user_email,
            upstream_host: "127.0.0.1",
            upstream_port: 0,
            upstream_tls_mode: UpstreamTlsMode::Plain,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let list_round = Arc::new(AtomicUsize::new(0));
    let list_round_server = Arc::clone(&list_round);
    let fetch_round = Arc::new(AtomicUsize::new(0));
    let fetch_round_server = Arc::clone(&fetch_round);

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        let mut current_mailbox = String::new();
        reader
            .get_mut()
            .write_all(b"* OK fake sync upstream ready\r\n")
            .await
            .unwrap();

        loop {
            let mut line = String::new();
            let bytes = reader.read_line(&mut line).await.unwrap();
            if bytes == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            let tag = line
                .split_whitespace()
                .next()
                .unwrap_or("A0000")
                .to_string();
            if line.contains("CAPABILITY") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n{tag} OK CAPABILITY completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("LOGIN") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LIST") {
                let round = list_round_server.fetch_add(1, Ordering::SeqCst);
                let mut response = String::new();
                response.push_str("* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n");
                if round == 0 {
                    response.push_str("* LIST (\\HasNoChildren) \"/\" \"Archive\"\r\n");
                }
                response.push_str(&format!("{tag} OK LIST completed\r\n"));
                reader.get_mut().write_all(response.as_bytes()).await.unwrap();
            } else if line.contains("SELECT") {
                current_mailbox = line
                    .split_whitespace()
                    .nth(2)
                    .unwrap_or("INBOX")
                    .trim_matches('"')
                    .to_string();
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* FLAGS (\\Seen)\r\n* 1 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n* OK [UIDNEXT 2] Predicted next UID\r\n* OK [HIGHESTMODSEQ 1] Highest mod-sequence value\r\n* OK [UNSEEN 1] First unseen message\r\n{tag} OK [READ-WRITE] SELECT completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("UID") && line.contains("SEARCH") {
                reader
                    .get_mut()
                    .write_all(format!("* SEARCH 1\r\n{tag} OK SEARCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("UID FETCH") && line.contains("FLAGS") {
                let round = fetch_round_server.fetch_add(1, Ordering::SeqCst);
                let flags = if round == 0 { "" } else { "\\Seen" };
                reader
                    .get_mut()
                    .write_all(
                        format!("* 1 FETCH (UID 1 FLAGS ({flags}))\r\n{tag} OK FETCH completed\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("UID FETCH") {
                let subject = if current_mailbox.eq_ignore_ascii_case("archive") {
                    "Archive message"
                } else {
                    "Inbox message"
                };
                let mailbox_token = current_mailbox.to_ascii_lowercase();
                let body = format!(
                    concat!(
                        "From: Alice <alice@example.com>\r\n",
                        "To: Bob <bob@example.com>\r\n",
                        "Subject: {subject}\r\n",
                        "Message-ID: <sync-mailbox-drop-{mailbox_token}@example.com>\r\n",
                        "MIME-Version: 1.0\r\n",
                        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
                        "\r\n",
                        "{subject}\r\n"
                    ),
                    subject = subject,
                    mailbox_token = mailbox_token
                )
                .into_bytes();
                let header = format!("* 1 FETCH (UID 1 BODY[] {{{}}}\r\n", body.len());
                reader.get_mut().write_all(header.as_bytes()).await.unwrap();
                reader.get_mut().write_all(&body).await.unwrap();
                reader
                    .get_mut()
                    .write_all(format!("\r\n)\r\n{tag} OK FETCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LOGOUT") {
                reader
                    .get_mut()
                    .write_all(
                        format!("* BYE logging out\r\n{tag} OK LOGOUT completed\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                break;
            }
        }
    });

    let mut client = UpstreamClient::connect(&UpstreamAccountConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls_mode: UpstreamTlsMode::Plain,
        auth_method: UpstreamAuthMethod::Login,
        username: "upstream-user".to_string(),
        secret: "upstream-secret".to_string(),
    })
    .await?
    .with_metrics(Arc::clone(&metrics));
    client.capability().await?;
    client.login("upstream-user", "upstream-secret").await?;

    let first = tokio::time::timeout(
        Duration::from_secs(20),
        sync_engine.sync_account(account.id, &mut client),
    )
    .await??;
    assert_eq!(first.mailboxes_synced, 2);
    assert_eq!(first.messages_synced, 2);

    let mailboxes_after_first = repo.list_mailboxes(account.id, None).await?;
    assert_eq!(mailboxes_after_first.len(), 2);

    let second = tokio::time::timeout(
        Duration::from_secs(20),
        sync_engine.sync_account(account.id, &mut client),
    )
    .await??;
    assert_eq!(second.mailboxes_synced, 1);
    assert_eq!(second.messages_synced, 0);

    let mailboxes_after_second = repo.list_mailboxes(account.id, None).await?;
    assert_eq!(mailboxes_after_second.len(), 1);
    assert_eq!(mailboxes_after_second[0].canonical_name, "inbox");

    let inbox = mailboxes_after_second[0].clone();
    let inbox_messages = repo.list_mailbox_messages(inbox.id).await?;
    assert_eq!(inbox_messages.len(), 1);

    client.logout().await?;
    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn sync_engine_removes_expunged_upstream_messages_on_resync() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = MessageIngestor::new(repo.clone(), store.clone(), Some(search.clone()));
    let metrics = Arc::new(AppMetrics::new());
    let sync_engine = SyncEngine::new(repo.clone(), ingestor, Arc::clone(&metrics));

    let user_email = format!("sync-expunge-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Sync Expunge",
            email_address: &user_email,
            upstream_host: "127.0.0.1",
            upstream_port: 0,
            upstream_tls_mode: UpstreamTlsMode::Plain,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let search_round = Arc::new(AtomicUsize::new(0));
    let search_round_server = search_round.clone();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        reader
            .get_mut()
            .write_all(b"* OK fake sync upstream ready\r\n")
            .await
            .unwrap();

        loop {
            let mut line = String::new();
            let bytes = reader.read_line(&mut line).await.unwrap();
            if bytes == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            let tag = line
                .split_whitespace()
                .next()
                .unwrap_or("A0000")
                .to_string();
            if line.contains("CAPABILITY") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n{tag} OK CAPABILITY completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("LOGIN") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LIST") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n{tag} OK LIST completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("SELECT") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* FLAGS (\\Seen)\r\n* 2 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n* OK [UIDNEXT 3] Predicted next UID\r\n* OK [HIGHESTMODSEQ 9] Highest mod-sequence value\r\n* OK [UNSEEN 2] First unseen message\r\n{tag} OK [READ-WRITE] SELECT completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("UID") && line.contains("SEARCH") {
                let round = search_round_server.fetch_add(1, Ordering::SeqCst);
                let payload = if round == 0 { "1 2" } else { "2" };
                reader
                    .get_mut()
                    .write_all(
                        format!("* SEARCH {payload}\r\n{tag} OK SEARCH completed\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("UID FETCH") && line.contains("FLAGS") {
                let uid = line
                    .split_whitespace()
                    .find_map(|token| token.parse::<u64>().ok())
                    .unwrap_or_default();
                reader
                    .get_mut()
                    .write_all(format!("* {uid} FETCH (UID {uid} FLAGS ())\r\n{tag} OK FETCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("UID FETCH") && line.contains("FLAGS") {
                let uid = line
                    .split_whitespace()
                    .find_map(|token| token.parse::<u64>().ok())
                    .unwrap_or_default();
                reader
                    .get_mut()
                    .write_all(format!("* {uid} FETCH (UID {uid} FLAGS ())\r\n{tag} OK FETCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("UID FETCH") {
                let uid = line
                    .split_whitespace()
                    .find_map(|token| token.parse::<u64>().ok())
                    .unwrap_or_default();
                let subject = if uid == 1 {
                    "First upstream message"
                } else {
                    "Second upstream message"
                };
                let body = format!(
                    concat!(
                        "From: Alice <alice@example.com>\r\n",
                        "To: Bob <bob@example.com>\r\n",
                        "Subject: {subject}\r\n",
                        "Message-ID: <sync-expunge-{uid}@example.com>\r\n",
                        "MIME-Version: 1.0\r\n",
                        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
                        "\r\n",
                        "Message {uid}\r\n"
                    ),
                    subject = subject,
                    uid = uid
                )
                .into_bytes();
                let header = format!("* {uid} FETCH (UID {uid} BODY[] {{{}}}\r\n", body.len());
                reader.get_mut().write_all(header.as_bytes()).await.unwrap();
                reader.get_mut().write_all(&body).await.unwrap();
                reader
                    .get_mut()
                    .write_all(format!("\r\n)\r\n{tag} OK FETCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LOGOUT") {
                reader
                    .get_mut()
                    .write_all(
                        format!("* BYE logging out\r\n{tag} OK LOGOUT completed\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                break;
            }
        }
    });

    let mut client = UpstreamClient::connect(&UpstreamAccountConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls_mode: UpstreamTlsMode::Plain,
        auth_method: UpstreamAuthMethod::Login,
        username: "upstream-user".to_string(),
        secret: "upstream-secret".to_string(),
    })
    .await?
    .with_metrics(Arc::clone(&metrics));
    client.capability().await?;
    client.login("upstream-user", "upstream-secret").await?;

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
            uidnext: Some(3),
            highestmodseq: Some(9),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let first = tokio::time::timeout(
        Duration::from_secs(20),
        sync_engine.sync_mailbox(account.id, "INBOX", &mut client),
    )
    .await??;
    assert_eq!(first, 2);

    let after_first = repo.list_mailbox_messages(mailbox.id).await?;
    assert_eq!(after_first.len(), 2);

    let second = tokio::time::timeout(
        Duration::from_secs(20),
        sync_engine.sync_mailbox(account.id, "INBOX", &mut client),
    )
    .await??;
    assert_eq!(second, 0);

    let remaining = repo.list_mailbox_messages(mailbox.id).await?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].upstream_uid, Some(2));

    let sync_state = repo.load_sync_state(account.id, Some(mailbox.id)).await?;
    let sync_state = sync_state.expect("sync checkpoint should exist");
    assert_eq!(sync_state.state_json["uidvalidity"].as_i64(), Some(1));
    assert_eq!(sync_state.state_json["uidnext"].as_i64(), Some(3));
    assert_eq!(sync_state.state_json["last_uid"].as_i64(), Some(2));

    client.logout().await?;
    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn sync_engine_resets_mailbox_mapping_on_uidvalidity_change() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = MessageIngestor::new(repo.clone(), store.clone(), Some(search.clone()));
    let metrics = Arc::new(AppMetrics::new());
    let sync_engine = SyncEngine::new(repo.clone(), ingestor, Arc::clone(&metrics));

    let user_email = format!("sync-uidvalidity-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Sync UIDVALIDITY",
            email_address: &user_email,
            upstream_host: "127.0.0.1",
            upstream_port: 0,
            upstream_tls_mode: UpstreamTlsMode::Plain,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let select_round = Arc::new(AtomicUsize::new(0));
    let select_round_server = select_round.clone();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        reader
            .get_mut()
            .write_all(b"* OK fake sync upstream ready\r\n")
            .await
            .unwrap();

        loop {
            let mut line = String::new();
            let bytes = reader.read_line(&mut line).await.unwrap();
            if bytes == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            let tag = line
                .split_whitespace()
                .next()
                .unwrap_or("A0000")
                .to_string();
            if line.contains("CAPABILITY") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n{tag} OK CAPABILITY completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("LOGIN") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LIST") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n{tag} OK LIST completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("SELECT") {
                let round = select_round_server.fetch_add(1, Ordering::SeqCst);
                let uidvalidity = if round == 0 { 7 } else { 99 };
                let exists = if round == 0 { 2 } else { 1 };
                let uidnext = if round == 0 { 3 } else { 4 };
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* FLAGS (\\Seen)\r\n* {exists} EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY {uidvalidity}] UIDs valid\r\n* OK [UIDNEXT {uidnext}] Predicted next UID\r\n* OK [HIGHESTMODSEQ 9] Highest mod-sequence value\r\n* OK [UNSEEN {exists}] First unseen message\r\n{tag} OK [READ-WRITE] SELECT completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("UID") && line.contains("SEARCH") {
                let round = select_round_server.load(Ordering::SeqCst);
                let payload = if round <= 1 { "1 2" } else { "2" };
                reader
                    .get_mut()
                    .write_all(
                        format!("* SEARCH {payload}\r\n{tag} OK SEARCH completed\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("UID FETCH") && line.contains("FLAGS") {
                let uid = line
                    .split_whitespace()
                    .find_map(|token| token.parse::<u64>().ok())
                    .unwrap_or_default();
                reader
                    .get_mut()
                    .write_all(format!("* {uid} FETCH (UID {uid} FLAGS ())\r\n{tag} OK FETCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("UID FETCH") {
                let uid = line
                    .split_whitespace()
                    .find_map(|token| token.parse::<u64>().ok())
                    .unwrap_or_default();
                let body = format!(
                    concat!(
                        "From: Alice <alice@example.com>\r\n",
                        "To: Bob <bob@example.com>\r\n",
                        "Subject: UIDVALIDITY {uid}\r\n",
                        "Message-ID: <sync-uidvalidity-{uid}@example.com>\r\n",
                        "MIME-Version: 1.0\r\n",
                        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
                        "\r\n",
                        "Message {uid}\r\n"
                    ),
                    uid = uid
                )
                .into_bytes();
                let header = format!("* {uid} FETCH (UID {uid} BODY[] {{{}}}\r\n", body.len());
                reader.get_mut().write_all(header.as_bytes()).await.unwrap();
                reader.get_mut().write_all(&body).await.unwrap();
                reader
                    .get_mut()
                    .write_all(format!("\r\n)\r\n{tag} OK FETCH completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LOGOUT") {
                reader
                    .get_mut()
                    .write_all(
                        format!("* BYE logging out\r\n{tag} OK LOGOUT completed\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                break;
            }
        }
    });

    let mut client = UpstreamClient::connect(&UpstreamAccountConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls_mode: UpstreamTlsMode::Plain,
        auth_method: UpstreamAuthMethod::Login,
        username: "upstream-user".to_string(),
        secret: "upstream-secret".to_string(),
    })
    .await?
    .with_metrics(Arc::clone(&metrics));
    client.capability().await?;
    client.login("upstream-user", "upstream-secret").await?;

    let mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(7),
            uidnext: Some(3),
            highestmodseq: Some(9),
            exists_count: 2,
            recent_count: 0,
            unseen_count: 2,
        })
        .await?;

    let first = tokio::time::timeout(
        Duration::from_secs(20),
        sync_engine.sync_mailbox(account.id, "INBOX", &mut client),
    )
    .await??;
    assert_eq!(first, 2);

    let messages_after_first = repo.list_mailbox_messages(mailbox.id).await?;
    assert_eq!(messages_after_first.len(), 2);

    let second = tokio::time::timeout(
        Duration::from_secs(20),
        sync_engine.sync_mailbox(account.id, "INBOX", &mut client),
    )
    .await??;
    assert_eq!(second, 1);

    let messages_after_second = repo.list_mailbox_messages(mailbox.id).await?;
    assert_eq!(messages_after_second.len(), 1);
    assert_eq!(messages_after_second[0].upstream_uid, Some(2));

    let sync_state = repo.load_sync_state(account.id, Some(mailbox.id)).await?;
    let sync_state = sync_state.expect("sync checkpoint should exist");
    assert_eq!(sync_state.state_json["uidvalidity"].as_i64(), Some(99));
    assert_eq!(sync_state.state_json["last_uid"].as_i64(), Some(2));

    client.logout().await?;
    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn sync_engine_respects_sync_concurrency_limit() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let metrics = Arc::new(AppMetrics::new());
    let ingestor = MessageIngestor::new(repo.clone(), store.clone(), Some(search.clone()));
    let sync_engine =
        SyncEngine::new(repo.clone(), ingestor, Arc::clone(&metrics)).with_sync_limit(1);

    let user_email = format!("sync-limit-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Sync Limit",
            email_address: &user_email,
            upstream_host: "127.0.0.1",
            upstream_port: 0,
            upstream_tls_mode: UpstreamTlsMode::Plain,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let list_count = Arc::new(AtomicUsize::new(0));
    let release_first_list = Arc::new(tokio::sync::Notify::new());

    let server = tokio::spawn({
        let list_count = Arc::clone(&list_count);
        let release_first_list = Arc::clone(&release_first_list);
        async move {
            for _ in 0..2 {
                let (socket, _) = listener.accept().await.unwrap();
                let list_count = Arc::clone(&list_count);
                let release_first_list = Arc::clone(&release_first_list);
                tokio::spawn(async move {
                    let mut reader = BufReader::new(socket);
                    reader
                        .get_mut()
                        .write_all(b"* OK fake sync upstream ready\r\n")
                        .await
                        .unwrap();

                    loop {
                        let mut line = String::new();
                        let bytes = reader.read_line(&mut line).await.unwrap();
                        if bytes == 0 {
                            break;
                        }
                        let line = line.trim_end_matches(['\r', '\n']).to_string();
                        let tag = line
                            .split_whitespace()
                            .next()
                            .unwrap_or("A0000")
                            .to_string();
                        if line.contains("CAPABILITY") {
                            reader
                                .get_mut()
                                .write_all(
                                    format!(
                                        "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n{tag} OK CAPABILITY completed\r\n"
                                    )
                                    .as_bytes(),
                                )
                                .await
                                .unwrap();
                        } else if line.contains("LOGIN") {
                            reader
                                .get_mut()
                                .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                                .await
                                .unwrap();
                        } else if line.contains("LIST") {
                            let seen = list_count.fetch_add(1, Ordering::SeqCst) + 1;
                            if seen == 1 {
                                release_first_list.notified().await;
                            }
                            reader
                                .get_mut()
                                .write_all(
                                    format!(
                                        "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n{tag} OK LIST completed\r\n"
                                    )
                                    .as_bytes(),
                                )
                                .await
                                .unwrap();
                        } else if line.contains("SELECT") {
                            reader
                                .get_mut()
                                .write_all(
                                    format!(
                                        "* FLAGS (\\Seen)\r\n* 1 EXISTS\r\n{tag} OK [READ-WRITE] SELECT completed\r\n"
                                    )
                                    .as_bytes(),
                                )
                                .await
                                .unwrap();
                        } else if line.contains("UID") && line.contains("SEARCH") {
                            reader
                                .get_mut()
                                .write_all(
                                    format!("* SEARCH 1\r\n{tag} OK SEARCH completed\r\n")
                                        .as_bytes(),
                                )
                                .await
                                .unwrap();
                        } else if line.contains("UID FETCH") && line.contains("FLAGS") {
                            reader
                                .get_mut()
                                .write_all(b"* 1 FETCH (UID 1 FLAGS ())\r\n")
                                .await
                                .unwrap();
                            reader
                                .get_mut()
                                .write_all(format!("{tag} OK FETCH completed\r\n").as_bytes())
                                .await
                                .unwrap();
                        } else if line.contains("UID FETCH") {
                            let body = concat!(
                                "From: Alice <alice@example.com>\r\n",
                                "To: Bob <bob@example.com>\r\n",
                                "Subject: Sync Limit Target\r\n",
                                "Message-ID: <sync-limit@example.com>\r\n",
                                "MIME-Version: 1.0\r\n",
                                "Content-Type: text/plain; charset=\"utf-8\"\r\n",
                                "\r\n",
                                "Hello from the sync limit test.\r\n",
                            )
                            .as_bytes()
                            .to_vec();
                            let header = format!("* 1 FETCH (UID 1 BODY[] {{{}}}\r\n", body.len());
                            reader.get_mut().write_all(header.as_bytes()).await.unwrap();
                            reader.get_mut().write_all(&body).await.unwrap();
                            reader
                                .get_mut()
                                .write_all(
                                    format!("\r\n)\r\n{tag} OK FETCH completed\r\n").as_bytes(),
                                )
                                .await
                                .unwrap();
                        } else if line.contains("LOGOUT") {
                            reader
                                .get_mut()
                                .write_all(
                                    format!("* BYE logging out\r\n{tag} OK LOGOUT completed\r\n")
                                        .as_bytes(),
                                )
                                .await
                                .unwrap();
                            break;
                        }
                    }
                });
            }
        }
    });

    let mut client1 = UpstreamClient::connect(&UpstreamAccountConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls_mode: UpstreamTlsMode::Plain,
        auth_method: UpstreamAuthMethod::Login,
        username: "upstream-user".to_string(),
        secret: "upstream-secret".to_string(),
    })
    .await?
    .with_metrics(Arc::clone(&metrics));
    let mut client2 = UpstreamClient::connect(&UpstreamAccountConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls_mode: UpstreamTlsMode::Plain,
        auth_method: UpstreamAuthMethod::Login,
        username: "upstream-user".to_string(),
        secret: "upstream-secret".to_string(),
    })
    .await?
    .with_metrics(Arc::clone(&metrics));
    client1.capability().await?;
    client1.login("upstream-user", "upstream-secret").await?;
    client2.capability().await?;
    client2.login("upstream-user", "upstream-secret").await?;

    let first_engine = sync_engine.clone();
    let first =
        tokio::spawn(async move { first_engine.sync_account(account.id, &mut client1).await });

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if list_count.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert_eq!(list_count.load(Ordering::SeqCst), 1);

    let second_engine = sync_engine.clone();
    let second =
        tokio::spawn(async move { second_engine.sync_account(account.id, &mut client2).await });

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(list_count.load(Ordering::SeqCst), 1);

    release_first_list.notify_waiters();

    let first_report = first.await??;
    let second_report = second.await??;
    assert_eq!(first_report.mailboxes_synced, 1);
    assert_eq!(second_report.mailboxes_synced, 1);
    assert_eq!(metrics.sync_runs_total(), 2);
    assert_eq!(metrics.sync_runs_failed(), 0);
    assert_eq!(list_count.load(Ordering::SeqCst), 2);

    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn sync_engine_skips_disabled_accounts_without_touching_upstream() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = MessageIngestor::new(repo.clone(), store.clone(), Some(search.clone()));
    let metrics = Arc::new(AppMetrics::new());
    let sync_engine = SyncEngine::new(repo.clone(), ingestor, Arc::clone(&metrics));

    let user_email = format!("sync-disabled-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Sync Disabled",
            email_address: &user_email,
            upstream_host: "127.0.0.1",
            upstream_port: 0,
            upstream_tls_mode: UpstreamTlsMode::Plain,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let _ = repo.disable_mail_account(account.id).await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let command_count = Arc::new(AtomicUsize::new(0));
    let command_count_server = command_count.clone();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        reader
            .get_mut()
            .write_all(b"* OK fake sync upstream ready\r\n")
            .await
            .unwrap();

        loop {
            let mut line = String::new();
            let bytes = reader.read_line(&mut line).await.unwrap();
            if bytes == 0 {
                break;
            }
            command_count_server.fetch_add(1, Ordering::SeqCst);
        }
    });

    let mut client = UpstreamClient::connect(&UpstreamAccountConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls_mode: UpstreamTlsMode::Plain,
        auth_method: UpstreamAuthMethod::Login,
        username: "upstream-user".to_string(),
        secret: "upstream-secret".to_string(),
    })
    .await?;

    let report = tokio::time::timeout(
        Duration::from_secs(10),
        sync_engine.sync_account(account.id, &mut client),
    )
    .await??;
    assert_eq!(report.mailboxes_synced, 0);
    assert_eq!(report.messages_synced, 0);
    drop(client);
    server.await.unwrap();
    assert_eq!(command_count.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn sync_engine_account_lock_serializes_acquisition() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = MessageIngestor::new(repo.clone(), store.clone(), Some(search.clone()));
    let metrics = Arc::new(AppMetrics::new());
    let sync_engine = SyncEngine::new(repo.clone(), ingestor, Arc::clone(&metrics))
        .with_lock_manager(Arc::new(MemorySyncLockManager::new()));

    let first = sync_engine
        .acquire_account_lock(42, Duration::from_secs(1))
        .await?;
    assert!(first.is_some());

    let second = sync_engine
        .acquire_account_lock(42, Duration::from_secs(1))
        .await?;
    assert!(second.is_none());

    drop(first);
    tokio::time::sleep(Duration::from_millis(20)).await;

    let third = sync_engine
        .acquire_account_lock(42, Duration::from_secs(1))
        .await?;
    assert!(third.is_some());
    Ok(())
}

#[tokio::test]
async fn live_sync_engine_mirrors_a_real_upstream_message() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = MessageIngestor::new(repo.clone(), store.clone(), Some(search.clone()));
    let metrics = Arc::new(AppMetrics::new());
    let sync_engine = SyncEngine::new(repo.clone(), ingestor, Arc::clone(&metrics));
    let local_email = format!("live-sync-{}@example.test", Uuid::new_v4());

    let user = repo
        .create_user(NewUser {
            username_email: &local_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Sync",
            email_address: &local_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;

    let mut client =
        tokio::time::timeout(Duration::from_secs(60), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(60), client.capability()).await??;
    tokio::time::timeout(
        Duration::from_secs(60),
        client.login(&config.username, &config.secret),
    )
    .await??;

    let mailboxes =
        tokio::time::timeout(Duration::from_secs(60), client.list_mailboxes()).await??;
    let mut selected_mailbox = None;
    let mut selected_uid = None;
    let mut selected_sha256 = None;
    let mut selected_selection = None;
    for mailbox_name in mailboxes {
        let selection = tokio::time::timeout(
            Duration::from_secs(60),
            client.select_mailbox(&mailbox_name),
        )
        .await??;
        let uids = tokio::time::timeout(Duration::from_secs(60), client.uid_search_all()).await??;
        let Some(uid) = uids.into_iter().max() else {
            continue;
        };
        let raw =
            tokio::time::timeout(Duration::from_secs(60), client.uid_fetch_rfc822(uid)).await??;
        let parsed = parse_message(&raw)?;
        selected_mailbox = Some(mailbox_name);
        selected_uid = Some(uid);
        selected_sha256 = Some(parsed.raw_sha256);
        selected_selection = Some(selection);
        break;
    }

    let selected_mailbox = selected_mailbox.ok_or_else(|| {
        anyhow::anyhow!("real upstream account does not contain a mailbox with messages")
    })?;
    let selected_uid = selected_uid.unwrap();
    let selected_sha256 = selected_sha256.unwrap();
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

    repo.put_sync_state(NewSyncState {
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

    let messages_synced = tokio::time::timeout(
        Duration::from_secs(120),
        sync_engine.sync_mailbox(account.id, &selected_mailbox, &mut client),
    )
    .await??;
    assert_eq!(messages_synced, 1);

    let synced_subjects: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages WHERE account_id = $1 AND rfc822_sha256 = $2",
    )
    .bind(account.id)
    .bind(&selected_sha256)
    .fetch_one(repo.pool())
    .await?;
    assert_eq!(synced_subjects, 1);

    let sync_state = repo.load_sync_state(account.id, Some(mailbox.id)).await?;
    assert!(sync_state.is_some(), "sync checkpoint should be preserved");

    let services = AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone() as Arc<dyn imap_cache_rs::storage::ObjectStore>,
        search: Some(search.clone() as Arc<dyn imap_cache_rs::search::SearchBackend>),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::clone(&metrics),
    };
    let mut session = imap_cache_rs::protocol::imap::ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: local_email.clone(),
    });
    session.state = imap_cache_rs::protocol::imap::State::Authenticated;
    let select = session
        .handle(
            &services,
            &format!(
                "A1 SELECT \"{}\"\r\n",
                selected_mailbox.replace('"', "\\\"")
            ),
        )
        .await?;
    assert!(select.iter().any(|line| line.starts_with("A1 OK")));

    let fetch = session
        .handle(
            &services,
            "A2 FETCH 1 (FLAGS UID RFC822.SIZE ENVELOPE BODYSTRUCTURE)\r\n",
        )
        .await?;
    let joined = fetch.join("\n");
    assert!(joined.contains("* 1 FETCH"));
    assert!(joined.contains(&format!("UID {selected_uid}")));
    assert!(joined.contains("RFC822.SIZE"));
    assert!(joined.contains("ENVELOPE"));
    assert!(joined.contains("BODYSTRUCTURE"));

    tokio::time::timeout(Duration::from_secs(60), client.logout()).await??;
    Ok(())
}
