use imap_cache_rs::{
    db,
    db::repository::{
        NewCacheObject, NewMailAccount, NewMailbox, NewMailboxMessage, NewPendingMutation,
        NewSyncState, NewUser, PostgresRepository,
    },
    domain::{MutationStatus, UpstreamAuthMethod, UpstreamTlsMode},
    mime::parse_message,
    security::SecretBox,
    storage::memory::MemoryObjectStore,
    sync::MessageIngestor,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::{env, sync::Arc};
use uuid::Uuid;

async fn connect_pool() -> anyhow::Result<sqlx::PgPool> {
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
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
async fn postgres_repository_round_trips_core_records() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let secrets = SecretBox::from_passphrase("test-master-key");
    let repo = PostgresRepository::new(pool, secrets.clone());

    let user_email = format!("repo-test-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    assert_eq!(user.username_email, user_email);

    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Repo Test",
            email_address: "repo-test@example.com",
            upstream_host: "imap.example.com",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    assert_eq!(account.user_id, user.id);
    assert_eq!(
        String::from_utf8(secrets.decrypt(&account.encrypted_upstream_username)?)?,
        "upstream-user"
    );
    assert_eq!(
        String::from_utf8(secrets.decrypt(&account.encrypted_upstream_secret)?)?,
        "upstream-secret"
    );

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
            exists_count: 3,
            recent_count: 1,
            unseen_count: 2,
        })
        .await?;
    assert_eq!(mailbox.canonical_name, "inbox");

    let message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "Rfc822/abc",
            rfc822_sha256: "deadbeef",
            message_id_header: Some("<id@example.com>"),
            subject: Some("Test"),
            from_json: json!([{"address": "alice@example.com"}]),
            to_json: json!([{"address": "bob@example.com"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Test"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 5,
            text_preview: Some("hello"),
        })
        .await?;
    assert_eq!(message.subject.as_deref(), Some("Test"));

    let mailbox_message = repo
        .upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message.id,
            local_uid: 7,
            upstream_uid: Some(9),
            modseq: Some(11),
            flags: vec!["\\Seen".to_string()],
            keywords: vec!["$important".to_string()],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;
    assert_eq!(mailbox_message.local_uid, 7);

    let cache_object = repo
        .upsert_cache_object(NewCacheObject {
            account_id: Some(account.id),
            object_type: "rfc822",
            blob_key: "Rfc822/abc",
            sha256: "deadbeef",
            size_octets: 5,
            ref_count: 1,
            last_accessed_at: None,
        })
        .await?;
    assert_eq!(cache_object.object_type, "rfc822");

    let sync_state = repo
        .put_sync_state(NewSyncState {
            account_id: account.id,
            mailbox_id: Some(mailbox.id),
            state_json: json!({"cursor": 1}),
            last_success_at: None,
            last_attempt_at: None,
            last_error: None,
        })
        .await?;
    assert_eq!(sync_state.mailbox_id, Some(mailbox.id));

    let loaded_sync = repo.load_sync_state(account.id, Some(mailbox.id)).await?;
    assert!(loaded_sync.is_some());

    let idempotency_key = Uuid::new_v4().to_string();
    let mutation = repo
        .enqueue_mutation(NewPendingMutation {
            account_id: account.id,
            mailbox_id: mailbox.id,
            message_id: Some(message.id),
            mutation_type: "store",
            payload_json: json!({"flags": ["\\Seen"]}),
            status: MutationStatus::Pending,
            attempts: 0,
            next_attempt_at: None,
            idempotency_key: &idempotency_key,
        })
        .await?;
    assert_eq!(mutation.status, MutationStatus::Pending);

    Ok(())
}

#[tokio::test]
async fn copy_and_delete_adjust_message_cache_refcounts() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(PostgresRepository::new(
        pool,
        SecretBox::from_passphrase("test-master-key"),
    ));
    let store = Arc::new(MemoryObjectStore::new());
    let ingestor = MessageIngestor::new(Arc::clone(&repo), store.clone(), None);

    let user_email = format!("cache-refcount-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Cache Refcount",
            email_address: &user_email,
            upstream_host: "imap.example.com",
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
            uidvalidity: Some(43),
            uidnext: Some(1),
            highestmodseq: Some(0),
            exists_count: 0,
            recent_count: 0,
            unseen_count: 0,
        })
        .await?;

    let token = Uuid::new_v4();
    let raw = format!(
        concat!(
            "From: Alice <alice@example.com>\r\n",
            "To: Bob <bob@example.com>\r\n",
            "Subject: Cache Refcount {token}\r\n",
            "Message-ID: <cache-refcount-{token}@example.com>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Refcount body {token}.\r\n"
        ),
        token = token
    );
    let parsed = parse_message(raw.as_bytes()).unwrap();
    assert_eq!(parsed.mime_parts.len(), 1);
    let ingested = ingestor
        .ingest_raw_message(
            account.id,
            inbox.id,
            "INBOX",
            7,
            Some(11),
            None,
            raw.as_bytes(),
            vec![],
        )
        .await?;

    let raw_cache = repo
        .find_cache_object_by_account_type_and_blob_key(account.id, "rfc822", &ingested.blob_key)
        .await?
        .expect("raw cache object");
    assert_eq!(raw_cache.ref_count, 1);

    let part = repo
        .find_mime_part_by_message_and_path(account.id, ingested.message_id, "1")
        .await?
        .expect("mime part");
    let part_cache = repo
        .find_cache_object_by_account_type_and_blob_key(account.id, "MimePart", &part.blob_key)
        .await?
        .expect("mime part cache object");
    assert_eq!(part_cache.ref_count, 1);

    let copied = repo
        .copy_mailbox_message(inbox.id, archive.id, 7)
        .await?
        .expect("copied message");
    assert_eq!(copied.message_id, ingested.message_id);
    let raw_cache = repo
        .find_cache_object_by_account_type_and_blob_key(account.id, "rfc822", &ingested.blob_key)
        .await?
        .expect("raw cache object after copy");
    assert_eq!(raw_cache.ref_count, 2);
    let part_cache = repo
        .find_cache_object_by_account_type_and_blob_key(account.id, "MimePart", &part.blob_key)
        .await?
        .expect("mime part cache object after copy");
    assert_eq!(part_cache.ref_count, 2);

    let deleted = repo.delete_mailbox_message(archive.id, copied.local_uid).await?;
    assert_eq!(deleted, 1);
    let raw_cache = repo
        .find_cache_object_by_account_type_and_blob_key(account.id, "rfc822", &ingested.blob_key)
        .await?
        .expect("raw cache object after delete");
    assert_eq!(raw_cache.ref_count, 1);
    let part_cache = repo
        .find_cache_object_by_account_type_and_blob_key(account.id, "MimePart", &part.blob_key)
        .await?
        .expect("mime part cache object after delete");
    assert_eq!(part_cache.ref_count, 1);

    Ok(())
}

#[tokio::test]
async fn delete_mailbox_message_only_advances_modseq_when_a_row_is_removed() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = PostgresRepository::new(pool, SecretBox::from_passphrase("test-master-key"));

    let user_email = format!("delete-modseq-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Delete Modseq",
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
            rfc822_blob_key: "Rfc822/delete-modseq",
            rfc822_sha256: "delete-modseq",
            message_id_header: Some("<delete-modseq@example.com>"),
            subject: Some("Delete modseq"),
            from_json: json!([{"address": "alice@example.com"}]),
            to_json: json!([{"address": "bob@example.com"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "Delete modseq"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 12,
            text_preview: Some("delete body"),
        })
        .await?;
    repo.upsert_mailbox_message(NewMailboxMessage {
        mailbox_id: mailbox.id,
        message_id: message.id,
        local_uid: 7,
        upstream_uid: Some(33),
        modseq: None,
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let initial = repo.find_mailbox(account.id, "INBOX").await?.unwrap();
    assert_eq!(initial.highestmodseq, Some(1));

    let missing = repo.delete_mailbox_message(mailbox.id, 99).await?;
    assert_eq!(missing, 0);
    let after_missing = repo.find_mailbox(account.id, "INBOX").await?.unwrap();
    assert_eq!(after_missing.highestmodseq, Some(1));

    let removed = repo.delete_mailbox_message(mailbox.id, 7).await?;
    assert_eq!(removed, 1);
    let after_delete = repo.find_mailbox(account.id, "INBOX").await?.unwrap();
    assert_eq!(after_delete.highestmodseq, Some(2));
    assert!(
        repo.find_mailbox_message_view(mailbox.id, 7)
            .await?
            .is_none()
    );

    Ok(())
}

#[tokio::test]
async fn mailbox_message_auto_assigns_local_uid_and_copy_uses_next_slot() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = PostgresRepository::new(pool, SecretBox::from_passphrase("test-master-key"));

    let user_email = format!("uid-alloc-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "UID Alloc",
            email_address: &user_email,
            upstream_host: "imap.example.com",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let source_mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "Source",
            canonical_name: "source",
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
    let dest_mailbox = repo
        .upsert_mailbox(NewMailbox {
            account_id: account.id,
            name: "Dest",
            canonical_name: "dest",
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

    let first_message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "Rfc822/uid-1",
            rfc822_sha256: "uid-1",
            message_id_header: Some("<uid-1@example.com>"),
            subject: Some("UID 1"),
            from_json: json!([{"address": "alice@example.com"}]),
            to_json: json!([{"address": "bob@example.com"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "UID 1"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 8,
            text_preview: Some("uid 1"),
        })
        .await?;
    let auto_one = repo
        .upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: source_mailbox.id,
            message_id: first_message.id,
            local_uid: 0,
            upstream_uid: Some(11),
            modseq: None,
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;
    assert_eq!(auto_one.local_uid, 1);

    let second_message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "Rfc822/uid-2",
            rfc822_sha256: "uid-2",
            message_id_header: Some("<uid-2@example.com>"),
            subject: Some("UID 2"),
            from_json: json!([{"address": "alice@example.com"}]),
            to_json: json!([{"address": "bob@example.com"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "UID 2"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 8,
            text_preview: Some("uid 2"),
        })
        .await?;
    let auto_two = repo
        .upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: source_mailbox.id,
            message_id: second_message.id,
            local_uid: 0,
            upstream_uid: Some(12),
            modseq: None,
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;
    assert_eq!(auto_two.local_uid, 2);

    let third_message = repo
        .upsert_message(imap_cache_rs::db::repository::NewMessage {
            account_id: account.id,
            rfc822_blob_key: "Rfc822/uid-3",
            rfc822_sha256: "uid-3",
            message_id_header: Some("<uid-3@example.com>"),
            subject: Some("UID 3"),
            from_json: json!([{"address": "alice@example.com"}]),
            to_json: json!([{"address": "bob@example.com"}]),
            cc_json: json!([]),
            bcc_json: json!([]),
            reply_to_json: json!([]),
            envelope_json: json!({"subject": "UID 3"}),
            bodystructure_json: json!({"type": "text"}),
            internal_date: None,
            sent_date: None,
            size_octets: 8,
            text_preview: Some("uid 3"),
        })
        .await?;
    repo.upsert_mailbox_message(NewMailboxMessage {
        mailbox_id: dest_mailbox.id,
        message_id: third_message.id,
        local_uid: 1,
        upstream_uid: Some(21),
        modseq: None,
        flags: vec![],
        keywords: vec![],
        is_expunged: false,
        expunged_at: None,
    })
    .await?;

    let copied = repo
        .copy_mailbox_message(source_mailbox.id, dest_mailbox.id, 1)
        .await?
        .expect("copy should succeed");
    assert_eq!(copied.local_uid, 2);

    let dest_uids: Vec<i64> = repo
        .list_mailbox_messages(dest_mailbox.id)
        .await?
        .into_iter()
        .map(|message| message.local_uid)
        .collect();
    assert_eq!(dest_uids, vec![1, 2]);

    Ok(())
}

#[tokio::test]
async fn cache_object_ref_counts_increment_and_release() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = PostgresRepository::new(pool, SecretBox::from_passphrase("test-master-key"));

    let user_email = format!("cache-ref-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Cache Ref",
            email_address: &user_email,
            upstream_host: "imap.example.com",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;

    let first = repo
        .upsert_cache_object(NewCacheObject {
            account_id: Some(account.id),
            object_type: "cache",
            blob_key: "Cache/abc",
            sha256: "deadbeef",
            size_octets: 7,
            ref_count: 1,
            last_accessed_at: None,
        })
        .await?;
    assert_eq!(first.ref_count, 1);

    let second = repo
        .upsert_cache_object(NewCacheObject {
            account_id: Some(account.id),
            object_type: "cache",
            blob_key: "Cache/abc",
            sha256: "deadbeef",
            size_octets: 7,
            ref_count: 1,
            last_accessed_at: None,
        })
        .await?;
    assert_eq!(second.ref_count, 2);

    let released_one = repo
        .delete_cache_object_for_account(account.id, "Cache/abc")
        .await?;
    assert!(!released_one);
    let cached = repo.list_cache_objects_for_account(account.id).await?;
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].ref_count, 1);

    let released_two = repo
        .delete_cache_object_for_account(account.id, "Cache/abc")
        .await?;
    assert!(released_two);
    assert!(
        repo.list_cache_objects_for_account(account.id)
            .await?
            .is_empty()
    );

    Ok(())
}

#[tokio::test]
async fn audit_log_entries_are_persisted() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = PostgresRepository::new(pool, SecretBox::from_passphrase("test-master-key"));

    let user_email = format!("audit-{}@example.com", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &user_email,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$c2FsdA",
        })
        .await?;
    let entry = repo
        .record_audit_log(
            Some(user.id),
            None,
            "test_action",
            json!({"hello": "world"}),
        )
        .await?;
    assert_eq!(entry.user_id, Some(user.id));
    assert_eq!(entry.action, "test_action");
    assert_eq!(entry.metadata_json["hello"], "world");

    let stored_action: String =
        sqlx::query_scalar("SELECT action FROM audit_log WHERE id = $1 ORDER BY id DESC LIMIT 1")
            .bind(entry.id)
            .fetch_one(repo.pool())
            .await?;
    assert_eq!(stored_action, "test_action");

    Ok(())
}
