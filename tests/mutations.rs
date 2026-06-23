use imap_cache_rs::{
    AppServices,
    auth::AuthContext,
    auth::DenyAllAuthenticator,
    db,
    db::repository::{NewMailAccount, NewMailbox, NewMailboxMessage, NewMessage, NewUser, PostgresRepository},
    domain::{MutationStatus, UpstreamAuthMethod, UpstreamTlsMode},
    protocol::imap::{ImapSession, ParsedCommand, State},
    security::SecretBox,
    storage::memory::MemoryObjectStore,
    sync::MutationEngine,
    upstream::{UpstreamAccountConfig, UpstreamClient},
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::fs;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};
use uuid::Uuid;

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
async fn pending_mutations_flush_to_upstream() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let mutations = MutationEngine::new(repo.clone(), store.clone());

    let user_email = format!("mutations-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Mutations",
            email_address: &user_email,
            upstream_host: "127.0.0.1",
            upstream_port: 0,
            upstream_tls_mode: UpstreamTlsMode::Plain,
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
            uidvalidity: Some(42),
            uidnext: Some(7),
            highestmodseq: Some(9),
            exists_count: 1,
            recent_count: 0,
            unseen_count: 1,
        })
        .await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let append_count = Arc::new(AtomicUsize::new(0));
    let store_count = Arc::new(AtomicUsize::new(0));
    let append_count_server = append_count.clone();
    let store_count_server = store_count.clone();
    let expected_internal_date =
        chrono::DateTime::parse_from_str("12-Feb-2024 10:00:00 +0000", "%d-%b-%Y %H:%M:%S %z")?
            .with_timezone(&chrono::Utc);

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        reader
            .get_mut()
            .write_all(b"* OK fake mutation upstream ready\r\n")
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
            if line.contains("LOGIN") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("APPEND") {
                append_count_server.fetch_add(1, Ordering::SeqCst);
                assert!(line.contains("\"12-Feb-2024 10:00:00 +0000\""));
                reader
                    .get_mut()
                    .write_all(b"+ send literal\r\n")
                    .await
                    .unwrap();
                let mut literal = vec![0; 16];
                let _ = reader.read_exact(&mut literal).await.unwrap();
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK APPEND completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("UID") && line.contains("STORE") {
                store_count_server.fetch_add(1, Ordering::SeqCst);
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK STORE completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LOGOUT") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGOUT completed\r\n").as_bytes())
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
    .await?;
    client.login("upstream-user", "upstream-secret").await?;

    mutations
        .queue_append(
            account.id,
            mailbox.id,
            "INBOX",
            None,
            b"0123456789abcdef",
            vec!["\\Seen".to_string()],
            Some(expected_internal_date),
        )
        .await?;
    mutations
        .queue_flag_update(account.id, mailbox.id, None, 7, vec!["\\Seen".to_string()])
        .await?;

    let applied = mutations
        .flush_pending_mutations(account.id, &mut client)
        .await?;
    assert_eq!(applied, 2);
    assert_eq!(append_count.load(Ordering::SeqCst), 1);
    assert_eq!(store_count.load(Ordering::SeqCst), 1);

    let succeeded = repo
        .list_pending_mutations(account.id, MutationStatus::Succeeded)
        .await?;
    assert_eq!(succeeded.len(), 2);

    client.logout().await?;
    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn copy_and_move_mutations_flush_to_upstream() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let mutations = MutationEngine::new(repo.clone(), store.clone());

    let user_email = format!("mutations-copy-move-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Mutations Copy Move",
            email_address: &user_email,
            upstream_host: "127.0.0.1",
            upstream_port: 0,
            upstream_tls_mode: UpstreamTlsMode::Plain,
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
            uidvalidity: Some(42),
            uidnext: Some(7),
            highestmodseq: Some(9),
            exists_count: 1,
            recent_count: 0,
            unseen_count: 1,
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
            uidvalidity: Some(42),
            uidnext: Some(7),
            highestmodseq: Some(9),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;
    let trash = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "Trash",
            canonical_name: "trash",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: None,
            uidvalidity: Some(42),
            uidnext: Some(7),
            highestmodseq: Some(9),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let message = repo
        .upsert_message(NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/copy-move",
            rfc822_sha256: "sha256-copy-move",
            message_id_header: Some("<copy-move@example.test>"),
            subject: Some("Copy move test"),
            from_json: json!([{"kind": "mailbox", "display_name": "Alice", "address": "alice@example.test"}]),
            to_json: json!([]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({
                "date": 1704110400i64,
                "subject": "Copy move test",
                "message_id": "<copy-move@example.test>",
                "from": [{"kind": "mailbox", "display_name": "Alice", "address": "alice@example.test"}],
                "reply_to": [],
                "to": [],
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
            internal_date: None,
            sent_date: None,
            size_octets: 42,
            text_preview: Some("copy move body"),
        })
        .await?;
    repo.upsert_mailbox_message(NewMailboxMessage {
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
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone(),
        search: None,
        sync_engine: None,
        mutation_engine: Some(Arc::new(mutations.clone())),
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: user_email.clone(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let copy = session.handle(&services, "A1 COPY 1 Archive\r\n").await?;
    assert!(copy.iter().any(|line| line.starts_with("A1 OK")));
    assert!(copy.iter().any(|line| line.contains("COPYUID")));

    let move_response = session.handle(&services, "A2 MOVE 1 Trash\r\n").await?;
    assert!(move_response.iter().any(|line| line.starts_with("A2 OK")));
    assert!(move_response.iter().any(|line| line.contains("COPYUID")));

    let pending = repo
        .list_pending_mutations(account.id, MutationStatus::Pending)
        .await?;
    assert_eq!(pending.len(), 2);
    assert!(pending.iter().any(|mutation| mutation.mutation_type == "copy_message"));
    assert!(pending.iter().any(|mutation| mutation.mutation_type == "move_message"));

    let copy_count = Arc::new(AtomicUsize::new(0));
    let store_count = Arc::new(AtomicUsize::new(0));
    let expunge_count = Arc::new(AtomicUsize::new(0));
    let copy_count_server = copy_count.clone();
    let store_count_server = store_count.clone();
    let expunge_count_server = expunge_count.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        reader
            .get_mut()
            .write_all(b"* OK fake copy/move upstream ready\r\n")
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
            if line.contains("LOGIN") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("SELECT") {
                reader
                    .get_mut()
                    .write_all(
                        format!(
                            "* FLAGS (\\Seen \\Deleted)\r\n* 1 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 42] UIDs valid\r\n* OK [UIDNEXT 12] Predicted next UID\r\n* OK [HIGHESTMODSEQ 9] Highest mod-sequence value\r\n* OK [UNSEEN 1] First unseen message\r\n{tag} OK [READ-WRITE] SELECT completed\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            } else if line.contains("UID COPY") {
                copy_count_server.fetch_add(1, Ordering::SeqCst);
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK [COPYUID 42 11 21] UID COPY completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("UID STORE") {
                store_count_server.fetch_add(1, Ordering::SeqCst);
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK UID STORE completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("EXPUNGE") {
                expunge_count_server.fetch_add(1, Ordering::SeqCst);
                reader
                    .get_mut()
                    .write_all(format!("* 1 EXPUNGE\r\n{tag} OK EXPUNGE completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LOGOUT") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGOUT completed\r\n").as_bytes())
                    .await
                    .unwrap();
                break;
            } else {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK completed\r\n").as_bytes())
                    .await
                    .unwrap();
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
    .await?;
    client.login("upstream-user", "upstream-secret").await?;

    let applied = mutations.flush_pending_mutations(account.id, &mut client).await?;
    assert_eq!(applied, 2);
    assert_eq!(copy_count.load(Ordering::SeqCst), 2);
    assert_eq!(store_count.load(Ordering::SeqCst), 1);
    assert_eq!(expunge_count.load(Ordering::SeqCst), 1);

    let succeeded = repo
        .list_pending_mutations(account.id, MutationStatus::Succeeded)
        .await?;
    assert_eq!(succeeded.len(), 2);

    let archive_messages = repo.list_mailbox_messages(archive.id).await?;
    assert_eq!(archive_messages.len(), 1);
    let trash_messages = repo.list_mailbox_messages(trash.id).await?;
    assert_eq!(trash_messages.len(), 1);
    let inbox_messages = repo.list_mailbox_messages(inbox.id).await?;
    assert!(inbox_messages.is_empty());
    assert!(
        repo.upstream_uid_for_mailbox_message(inbox.id, 1)
            .await?
            .is_some(),
        "deleted source message should still be resolvable through UID mappings"
    );

    client.logout().await?;
    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn live_pending_append_replays_to_real_upstream() -> anyhow::Result<()> {
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let mutations = MutationEngine::new(repo.clone(), store.clone());

    let user_email = format!("live-mutations-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live Mutations",
            email_address: &user_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;
    let scratch_mailbox = format!("imap-cache-rs-{}", Uuid::new_v4());
    let scratch_mailbox_canonical = scratch_mailbox.to_ascii_lowercase();
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
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

    let unique_subject = format!("imap-cache-rs-live-mutation-{}", Uuid::new_v4());
    let raw = format!(
        concat!(
            "From: Live Test <live-test@example.test>\r\n",
            "To: Live Test <live-test@example.test>\r\n",
            "Subject: {subject}\r\n",
            "Message-ID: <{subject}@example.test>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Live mutation body for {subject}\r\n",
        ),
        subject = unique_subject
    );

    mutations
        .queue_append(
            account.id,
            mailbox.id,
            "INBOX",
            None,
            raw.as_bytes(),
            vec!["\\Seen".to_string()],
            None,
        )
        .await?;

    let mut client =
        tokio::time::timeout(std::time::Duration::from_secs(60), UpstreamClient::connect(&config))
            .await??;
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;
    let before = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.select_mailbox("INBOX"),
    )
    .await??;
    let before_exists = before.exists.unwrap_or_default();

    let applied = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        mutations.flush_pending_mutations(account.id, &mut client),
    )
    .await??;
    assert_eq!(applied, 1);

    let after = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.select_mailbox("INBOX"),
    )
    .await??;
    assert_eq!(after.exists.unwrap_or_default(), before_exists + 1);
    let uids = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.uid_search_all(),
    )
    .await??;
    let appended_uid = *uids
        .iter()
        .max()
        .ok_or_else(|| anyhow::anyhow!("live upstream append was not found"))?;

    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.send_command(
            "UID",
            &[
                "STORE".to_string(),
                appended_uid.to_string(),
                "+FLAGS.SILENT".to_string(),
                "(\\Deleted)".to_string(),
            ],
        ),
    )
    .await??;
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.send_command("EXPUNGE", &[]),
    )
    .await??;
    tokio::time::timeout(std::time::Duration::from_secs(60), client.logout()).await??;

    let succeeded = repo
        .list_pending_mutations(account.id, MutationStatus::Succeeded)
        .await?;
    assert_eq!(succeeded.len(), 1);

    Ok(())
}

#[tokio::test]
async fn imap_append_queues_and_replays_to_real_upstream() -> anyhow::Result<()> {
    let config = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let mutations = MutationEngine::new(repo.clone(), store.clone());

    let user_email = format!("live-append-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Live IMAP Append",
            email_address: &user_email,
            upstream_host: &config.host,
            upstream_port: i32::from(config.port),
            upstream_tls_mode: config.tls_mode,
            upstream_auth_method: config.auth_method,
            upstream_username: &config.username,
            upstream_secret: &config.secret,
        })
        .await?;
    let scratch_mailbox = format!("imap-cache-rs-{}", Uuid::new_v4());
    let scratch_mailbox_canonical = scratch_mailbox.to_ascii_lowercase();
    let mailbox = repo
        .upsert_mailbox(NewMailbox {
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

    let services = AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: Some(Arc::clone(&repo)),
        object_store: store.clone(),
        search: None,
        sync_engine: None,
        mutation_engine: Some(Arc::new(mutations.clone())),
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

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

    let mut session = ImapSession::new();
    session.authenticated = Some(AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: user_email.clone(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: scratch_mailbox.clone(),
    };

    let append_response = session
        .handle_parsed_command(
            &services,
            ParsedCommand {
                tag: "A1".to_string(),
                name: "APPEND".to_string(),
                args: vec![
                    scratch_mailbox.clone(),
                    "(\\Seen)".to_string(),
                    "12-Feb-2024 10:00:00 +0000".to_string(),
                    format!("{{{}}}", raw.len()),
                ],
            },
            Some(raw.as_bytes().to_vec()),
        )
        .await?;
    assert!(
        append_response
            .iter()
            .any(|line| line.contains("APPEND queued"))
    );

    let pending = repo
        .list_pending_mutations(account.id, MutationStatus::Pending)
        .await?;
    assert_eq!(pending.len(), 1);

    let mut client = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        UpstreamClient::connect(&config),
    )
    .await??;
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.send_command("CREATE", &[scratch_mailbox.clone()]),
    )
    .await??;
    let before = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.select_mailbox(&scratch_mailbox),
    )
    .await??;

    let applied = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        mutations.flush_pending_mutations(account.id, &mut client),
    )
    .await??;
    assert_eq!(applied, 1);
    let local_messages = repo.list_mailbox_messages(mailbox.id).await?;
    assert_eq!(local_messages.len(), 1);
    assert!(
        local_messages[0].upstream_uid.is_some(),
        "append replay should backfill the upstream UID locally"
    );

    let after = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.select_mailbox(&scratch_mailbox),
    )
    .await??;
    assert_eq!(after.exists.unwrap_or_default(), before.exists.unwrap_or_default() + 1);

    let store_response = session
        .handle_parsed_command(
            &services,
            ParsedCommand {
                tag: "A2".to_string(),
                name: "STORE".to_string(),
                args: vec![
                    "1".to_string(),
                    "+FLAGS.SILENT".to_string(),
                    "(\\Flagged)".to_string(),
                ],
            },
            None,
        )
        .await?;
    assert!(
        store_response
            .iter()
            .any(|line| line.contains("STORE queued"))
    );

    let pending = repo
        .list_pending_mutations(account.id, MutationStatus::Pending)
        .await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].mutation_type, "store_flags");

    let applied = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        mutations.flush_pending_mutations(account.id, &mut client),
    )
    .await??;
    assert_eq!(applied, 1);

    let uids = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.uid_search_all(),
    )
    .await??;
    let appended_uid = *uids
        .iter()
        .max()
        .ok_or_else(|| anyhow::anyhow!("live upstream append was not found"))?;
    let fetch_flags = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.send_command(
            "UID",
            &[
                "FETCH".to_string(),
                appended_uid.to_string(),
                "(FLAGS)".to_string(),
            ],
        ),
    )
    .await??;
    let fetched = fetch_flags.untagged.join("\n");
    assert!(fetched.contains("\\Seen"));
    assert!(fetched.contains("\\Flagged"));

    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.send_command(
            "UID",
            &[
                "STORE".to_string(),
                appended_uid.to_string(),
                "+FLAGS.SILENT".to_string(),
                "(\\Deleted)".to_string(),
            ],
        ),
    )
    .await??;
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.send_command("EXPUNGE", &[]),
    )
    .await??;
    tokio::time::timeout(std::time::Duration::from_secs(60), client.logout()).await??;
    let mut cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        UpstreamClient::connect(&config),
    )
    .await??;
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        cleanup.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        cleanup.send_command("DELETE", &[scratch_mailbox.clone()]),
    )
    .await?;
    tokio::time::timeout(std::time::Duration::from_secs(60), cleanup.logout()).await??;

    let succeeded = repo
        .list_pending_mutations(account.id, MutationStatus::Succeeded)
        .await?;
    assert_eq!(succeeded.len(), 2);

    Ok(())
}

#[tokio::test]
async fn pending_mutations_survive_engine_restart() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let mutation_engine = MutationEngine::new(repo.clone(), store.clone());

    let user_email = format!("restart-mutations-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Restart Mutations",
            email_address: &user_email,
            upstream_host: "127.0.0.1",
            upstream_port: 0,
            upstream_tls_mode: UpstreamTlsMode::Plain,
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
            uidvalidity: Some(42),
            uidnext: Some(7),
            highestmodseq: Some(9),
            exists_count: 1,
            recent_count: 0,
            unseen_count: 1,
        })
        .await?;

    mutation_engine
        .queue_append(
            account.id,
            mailbox.id,
            "INBOX",
            None,
            b"restart-append",
            vec!["\\Seen".to_string()],
            None,
        )
        .await?;
    mutation_engine
        .queue_flag_update(account.id, mailbox.id, None, 7, vec!["\\Seen".to_string()])
        .await?;

    drop(mutation_engine);

    let restarted_engine = MutationEngine::new(repo.clone(), store.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let append_count = Arc::new(AtomicUsize::new(0));
    let store_count = Arc::new(AtomicUsize::new(0));
    let append_count_server = append_count.clone();
    let store_count_server = store_count.clone();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        reader
            .get_mut()
            .write_all(b"* OK restarted mutation upstream ready\r\n")
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
            if line.contains("LOGIN") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("APPEND") {
                append_count_server.fetch_add(1, Ordering::SeqCst);
                reader
                    .get_mut()
                    .write_all(b"+ send literal\r\n")
                    .await
                    .unwrap();
                let mut literal = vec![0; "restart-append".len()];
                let _ = reader.read_exact(&mut literal).await.unwrap();
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK APPEND completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("UID") && line.contains("STORE") {
                store_count_server.fetch_add(1, Ordering::SeqCst);
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK STORE completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("LOGOUT") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGOUT completed\r\n").as_bytes())
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
    .await?;
    client.login("upstream-user", "upstream-secret").await?;

    let applied = restarted_engine
        .flush_pending_mutations(account.id, &mut client)
        .await?;
    assert_eq!(applied, 2);
    assert_eq!(append_count.load(Ordering::SeqCst), 1);
    assert_eq!(store_count.load(Ordering::SeqCst), 1);
    assert!(
        repo.list_pending_mutations(account.id, MutationStatus::Pending)
            .await?
            .is_empty()
    );
    let succeeded = repo
        .list_pending_mutations(account.id, MutationStatus::Succeeded)
        .await?;
    assert_eq!(succeeded.len(), 2);
    client.logout().await?;
    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn failed_pending_mutations_retry_after_backoff() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let mutations = MutationEngine::new(repo.clone(), store.clone());

    let user_email = format!("retry-mutations-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Retry Mutations",
            email_address: &user_email,
            upstream_host: "127.0.0.1",
            upstream_port: 0,
            upstream_tls_mode: UpstreamTlsMode::Plain,
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
            uidvalidity: Some(42),
            uidnext: Some(7),
            highestmodseq: Some(9),
            exists_count: 1,
            recent_count: 0,
            unseen_count: 1,
        })
        .await?;

    mutations
        .queue_flag_update(account.id, mailbox.id, None, 7, vec!["\\Seen".to_string()])
        .await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let attempt_count = Arc::new(AtomicUsize::new(0));
    let attempt_count_server = attempt_count.clone();

    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        reader
            .get_mut()
            .write_all(b"* OK retry mutation upstream ready\r\n")
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
            if line.contains("LOGIN") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else if line.contains("UID") && line.contains("STORE") {
                let attempt = attempt_count_server.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    reader
                        .get_mut()
                        .write_all(format!("{tag} NO mailbox busy\r\n").as_bytes())
                        .await
                        .unwrap();
                } else {
                    reader
                        .get_mut()
                        .write_all(format!("{tag} OK STORE completed\r\n").as_bytes())
                        .await
                        .unwrap();
                }
            } else if line.contains("LOGOUT") {
                reader
                    .get_mut()
                    .write_all(format!("{tag} OK LOGOUT completed\r\n").as_bytes())
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
    .await?;
    client.login("upstream-user", "upstream-secret").await?;

    let first = mutations
        .flush_pending_mutations(account.id, &mut client)
        .await;
    assert!(first.is_err());

    let failed = repo
        .list_pending_mutations(account.id, MutationStatus::Failed)
        .await?;
    assert_eq!(failed.len(), 1);
    let failed_row = &failed[0];
    assert_eq!(failed_row.attempts, 1);
    assert!(failed_row.next_attempt_at.is_some());

    sqlx::query(
        "UPDATE pending_mutations SET next_attempt_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(failed_row.id)
    .execute(repo.pool())
    .await?;

    let applied = mutations
        .flush_pending_mutations(account.id, &mut client)
        .await?;
    assert_eq!(applied, 1);
    assert_eq!(attempt_count.load(Ordering::SeqCst), 2);

    let succeeded = repo
        .list_pending_mutations(account.id, MutationStatus::Succeeded)
        .await?;
    assert_eq!(succeeded.len(), 1);
    client.logout().await?;
    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn imap_append_and_store_queue_pending_mutations() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let mutation_engine = Arc::new(MutationEngine::new(repo.clone(), store.clone()));

    let user_email = format!("protocol-mutations-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Protocol Mutations",
            email_address: &user_email,
            upstream_host: "imap.example.com",
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
            uidvalidity: Some(42),
            uidnext: Some(7),
            highestmodseq: Some(9),
            exists_count: 1,
            recent_count: 0,
            unseen_count: 1,
        })
        .await?;

    let services = imap_cache_rs::AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: Some(repo.clone()),
        object_store: store,
        search: None,
        sync_engine: None,
        mutation_engine: Some(mutation_engine),
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(imap_cache_rs::auth::AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username: user_email.clone(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let append = session
        .handle(
            &services,
            "A1 APPEND INBOX (\\Seen) \"12-Feb-2024 10:00:00 +0000\" \"From: Alice <alice@example.com>\\r\\nSubject: queued\\r\\n\\r\\nbody\\r\\n\"\r\n",
        )
        .await?;
    assert!(append.iter().any(|line| line.contains("APPEND queued")));

    let store = session.handle(&services, "A2 STORE 1 (\\Seen)\r\n").await?;
    assert!(store.iter().any(|line| line.contains("STORE queued")));

    let pending = repo
        .list_pending_mutations(account.id, MutationStatus::Pending)
        .await?;
    assert_eq!(pending.len(), 2);
    let mutation_types = pending
        .iter()
        .map(|mutation| mutation.mutation_type.as_str())
        .collect::<Vec<_>>();
    assert!(mutation_types.contains(&"append"));
    assert!(mutation_types.contains(&"store_flags"));
    let append_mutation = pending
        .iter()
        .find(|mutation| mutation.mutation_type == "append")
        .expect("append mutation should be present");
    assert_eq!(
        append_mutation
            .payload_json
            .get("internal_date")
            .and_then(|value| value.as_str()),
        Some("2024-02-12T10:00:00Z")
    );

    let _ = mailbox;
    Ok(())
}
