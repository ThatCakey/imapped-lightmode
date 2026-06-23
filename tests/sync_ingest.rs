use imap_cache_rs::{
    db,
    db::repository::{NewMailAccount, NewMailbox, NewUser, PostgresRepository},
    domain::{UpstreamAuthMethod, UpstreamTlsMode},
    mime::parse_message,
    search::{SearchBackend, TantivySearchEngine},
    security::SecretBox,
    storage::{ObjectStore, ObjectType, content_addressed_key, memory::MemoryObjectStore},
    sync::MessageIngestor,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
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

#[tokio::test]
async fn message_ingestion_persists_message_blob_and_search_document() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let search = Arc::new(TantivySearchEngine::memory()?);
    let ingestor = MessageIngestor::new(repo.clone(), store.clone(), Some(search.clone()));

    let user_email = format!("sync-test-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Sync Test",
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
    repo.upsert_account_quota(account.id, 1_000_000).await?;

    let token = Uuid::new_v4();
    let raw = format!(
        "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nSubject: Sync Target {token}\r\nMessage-ID: <sync-target-{token}@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\nHello sync pipeline {token}.\r\n"
    );
    let parsed = parse_message(raw.as_bytes()).unwrap();
    let result = ingestor
        .ingest_raw_message(
            account.id,
            mailbox.id,
            "INBOX",
            11,
            Some(22),
            None,
            raw.as_bytes(),
            vec!["\\Seen".to_string()],
        )
        .await?;

    let message_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE id = $1 AND account_id = $2")
            .bind(result.message_id)
            .bind(account.id)
            .fetch_one(repo.pool())
            .await?;
    assert_eq!(message_count, 1);

    let mailbox_message_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mailbox_messages WHERE mailbox_id = $1 AND local_uid = $2",
    )
    .bind(mailbox.id)
    .bind(11_i64)
    .fetch_one(repo.pool())
    .await?;
    assert_eq!(mailbox_message_count, 1);

    let cache_object = sqlx::query_as::<_, (Option<i64>, String)>(
        "SELECT account_id, object_type FROM cache_objects WHERE blob_key = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(&result.blob_key)
    .fetch_optional(repo.pool())
    .await?;
    assert_eq!(cache_object, Some((Some(account.id), "rfc822".to_string())));

    let cache_objects = repo.list_cache_objects_for_account(account.id).await?;
    assert_eq!(cache_objects.len(), parsed.mime_parts.len() + 1);
    assert!(
        cache_objects
            .iter()
            .any(|object| object.object_type == "MimePart")
    );

    let mime_part_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mime_parts WHERE message_id = $1")
            .bind(result.message_id)
            .fetch_one(repo.pool())
            .await?;
    assert_eq!(mime_part_count, parsed.mime_parts.len() as i64);

    let quota = repo.get_account_quota(account.id).await?.unwrap();
    let expected_used_bytes = parsed.size_octets as i64
        + parsed
            .mime_parts
            .iter()
            .map(|part| part.raw_bytes.len() as i64)
            .sum::<i64>();
    assert_eq!(quota.max_bytes, 1_000_000);
    assert_eq!(quota.used_bytes, expected_used_bytes);

    let stored = store.get(&result.blob_key).await?;
    assert_eq!(stored.as_deref(), Some(raw.as_bytes()));

    let search_results = search
        .search(
            "INBOX",
            imap_cache_rs::search::SearchQuery::from_imap_args(&[
                "TEXT".into(),
                "pipeline".into(),
            ])?,
        )
        .await?;
    assert_eq!(search_results, vec![11]);

    assert_eq!(
        parsed.message_id_header.as_deref(),
        Some(format!("<sync-target-{token}@example.com>").as_str())
    );
    Ok(())
}

#[tokio::test]
async fn message_ingestion_rejects_messages_that_exceed_quota() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let ingestor = MessageIngestor::new(repo.clone(), store.clone(), None);

    let user_email = format!("quota-test-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Quota Test",
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
    repo.upsert_account_quota(account.id, 32).await?;

    let raw = b"From: Alice <alice@example.com>\r\nSubject: too big\r\n\r\nthis message is definitely too large\r\n";
    let parsed = parse_message(raw).unwrap();
    let expected_key = content_addressed_key(ObjectType::Rfc822, raw);
    let result = ingestor
        .ingest_raw_message(account.id, mailbox.id, "INBOX", 1, None, None, raw, vec![])
        .await;
    assert!(result.is_err());
    assert!(store.get(&expected_key).await?.is_none());

    let message_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE account_id = $1")
            .bind(account.id)
            .fetch_one(repo.pool())
            .await?;
    assert_eq!(message_count, 0);

    let quota = repo.get_account_quota(account.id).await?.unwrap();
    assert_eq!(quota.used_bytes, 0);
    assert!(parsed.size_octets as i64 > quota.max_bytes);
    Ok(())
}
