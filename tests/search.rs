use imap_cache_rs::{
    AppServices,
    auth::DenyAllAuthenticator,
    db::repository::{
        NewMailAccount, NewMailbox, NewMailboxMessage, NewMessage, NewUser, PostgresRepository,
    },
    domain::{UpstreamAuthMethod, UpstreamTlsMode},
    mime::parse_message,
    protocol::imap::{ImapSession, State},
    search::{SearchBackend, SearchDocument, TantivySearchEngine},
    security,
    storage::memory::MemoryObjectStore,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

async fn connect_pool() -> anyhow::Result<sqlx::PgPool> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
    });
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    imap_cache_rs::db::run_migrations(&pool).await?;
    Ok(pool)
}

#[tokio::test]
async fn imap_search_returns_tantivy_matches() {
    let engine = TantivySearchEngine::memory().unwrap();
    let raw = concat!(
        "From: Alice <alice@example.com>\r\n",
        "To: Bob <bob@example.com>\r\n",
        "Subject: Search Target\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "Hello searchable world.\r\n",
    );
    let parsed = parse_message(raw.as_bytes()).unwrap();
    engine
        .index_message("INBOX", SearchDocument::from_parsed_message(7, &parsed))
        .await
        .unwrap();

    let services = AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: Some(Arc::new(engine)),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };
    let lines = session
        .handle(&services, "A1 SEARCH TEXT \"searchable\"\r\n")
        .await
        .unwrap();
    assert!(lines.iter().any(|line| line == "* SEARCH 7"));
    assert!(lines.iter().any(|line| line == "A1 OK SEARCH completed"));
}

#[tokio::test]
async fn imap_search_simple_text_terms_fall_back_without_tantivy() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));

    let username = format!("imap-search-fallback-{}@example.test", uuid::Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Search Fallback",
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
        .upsert_message(NewMessage {
            account_id: account.id,
            rfc822_blob_key: "rfc822/search-fallback",
            rfc822_sha256: "sha256-search-fallback",
            message_id_header: Some("<search-fallback@example.test>"),
            subject: Some("Fallback Search Target"),
            from_json: json!([{"address": "alice@example.test"}]),
            to_json: json!([{"address": "bob@example.test"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Fallback Search Target"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 42,
            text_preview: Some("searchable fallback body"),
        })
        .await?;
    repo.upsert_mailbox_message(NewMailboxMessage {
        mailbox_id: mailbox.id,
        message_id: message.id,
        local_uid: 1,
        upstream_uid: Some(7),
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
    session.authenticated = Some(imap_cache_rs::auth::AuthContext {
        user_id: user.id,
        account_id: Some(account.id),
        username,
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let lines = session
        .handle(&services, "A1 SEARCH TEXT \"searchable\"\r\n")
        .await?;
    assert!(lines.iter().any(|line| line == "* SEARCH 1"), "{lines:?}");
    assert!(lines.iter().any(|line| line == "A1 OK SEARCH completed"));

    Ok(())
}

#[tokio::test]
async fn imap_search_boolean_terms_use_tantivy_backend() {
    let engine = TantivySearchEngine::memory().unwrap();
    let matching_raw = concat!(
        "From: Alice <alice@example.com>\r\n",
        "To: Bob <bob@example.com>\r\n",
        "Subject: Boolean Match\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "searchable fallback body\r\n",
    );
    let matching_parsed = parse_message(matching_raw.as_bytes()).unwrap();
    engine
        .index_message(
            "INBOX",
            SearchDocument::from_parsed_message(1, &matching_parsed),
        )
        .await
        .unwrap();

    let other_raw = concat!(
        "From: Alice <alice@example.com>\r\n",
        "To: Bob <bob@example.com>\r\n",
        "Subject: Boolean Miss\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "completely different body\r\n",
    );
    let other_parsed = parse_message(other_raw.as_bytes()).unwrap();
    engine
        .index_message(
            "INBOX",
            SearchDocument::from_parsed_message(2, &other_parsed),
        )
        .await
        .unwrap();

    let services = AppServices {
        authenticator: Arc::new(DenyAllAuthenticator),
        repository: None,
        object_store: Arc::new(MemoryObjectStore::new()),
        search: Some(Arc::new(engine)),
        sync_engine: None,
        mutation_engine: None,
        events: Arc::new(imap_cache_rs::notifications::MailboxEventHub::new(16)),
        metrics: Arc::new(imap_cache_rs::metrics::AppMetrics::new()),
    };

    let mut session = ImapSession::new();
    session.authenticated = Some(imap_cache_rs::auth::AuthContext {
        user_id: 1,
        account_id: None,
        username: "user@example.test".to_string(),
    });
    session.state = State::SelectedMailbox {
        read_only: false,
        mailbox: "INBOX".to_string(),
    };

    let or_lines = session
        .handle(
            &services,
            "A1 SEARCH OR TEXT \"searchable\" TEXT \"different\"\r\n",
        )
        .await
        .unwrap();
    assert!(
        or_lines.iter().any(|line| line == "* SEARCH 1 2"),
        "{or_lines:?}"
    );
    assert!(or_lines.iter().any(|line| line == "A1 OK SEARCH completed"));

    let not_lines = session
        .handle(&services, "A2 SEARCH NOT TEXT \"searchable\"\r\n")
        .await
        .unwrap();
    assert!(
        not_lines.iter().any(|line| line == "* SEARCH 2"),
        "{not_lines:?}"
    );
    assert!(
        not_lines
            .iter()
            .any(|line| line == "A2 OK SEARCH completed")
    );
}
