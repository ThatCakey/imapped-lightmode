use chrono::{Duration, Utc};
use imap_cache_rs::{
    admin::{AdminCommand, run_admin_command},
    config::Config,
    db,
    db::repository::{NewCacheObject, NewMailAccount, NewSyncState, NewUser},
    domain::{UpstreamAuthMethod, UpstreamTlsMode},
    security,
    storage::{ObjectStore, filesystem::FilesystemObjectStore},
    sync::MessageIngestor,
};
use imap_cache_test_support::live_test_guard as support_live_test_guard;
use std::fs;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

fn load_testing_credentials() -> anyhow::Result<imap_cache_rs::upstream::UpstreamAccountConfig> {
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

    Ok(imap_cache_rs::upstream::UpstreamAccountConfig {
        host: imap_host.ok_or_else(|| anyhow::anyhow!("missing IMAP host"))?,
        port: imap_port.ok_or_else(|| anyhow::anyhow!("missing IMAP port"))?,
        tls_mode: UpstreamTlsMode::Tls,
        auth_method: UpstreamAuthMethod::Login,
        username: username.ok_or_else(|| anyhow::anyhow!("missing username"))?,
        secret: password.ok_or_else(|| anyhow::anyhow!("missing password"))?,
    })
}

#[tokio::test]
async fn admin_commands_manage_users_and_accounts() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = imap_cache_rs::db::repository::PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    );
    let config = Config {
        encryption_master_key: "test-master-key".to_string(),
        database_url: Some(std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
        })),
        ..Config::default()
    };

    let username = format!("admin-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let _user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(password)?,
        })
        .await?;
    let output = run_admin_command(
        &config,
        AdminCommand::ListAccounts {
            user_email: username.clone(),
        },
    )
    .await?;
    assert!(output.is_empty());

    let account_output = run_admin_command(
        &config,
        AdminCommand::AddAccount {
            user_email: username.clone(),
            display_name: "Admin Test".to_string(),
            email_address: username.clone(),
            upstream_host: "imap.example.test".to_string(),
            upstream_port: 993,
            upstream_tls_mode: "tls".to_string(),
            upstream_auth_method: "login".to_string(),
            upstream_username: "upstream-user".to_string(),
            upstream_secret: Some("upstream-secret".to_string()),
            upstream_secret_stdin: false,
        },
    )
    .await?;
    assert!(account_output.contains("created account"));
    assert!(account_output.contains("with quota"));

    let quota: (i64, i64) = sqlx::query_as(
        "SELECT max_bytes, used_bytes FROM quotas WHERE account_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(
        repo.find_account_by_email_address_any_state(&username)
            .await?
            .unwrap()
            .id,
    )
    .fetch_one(repo.pool())
    .await?;
    assert_eq!(quota.0, config.default_account_quota_bytes as i64);
    assert_eq!(quota.1, 0);

    let list_accounts = run_admin_command(
        &config,
        AdminCommand::ListAccounts {
            user_email: username.clone(),
        },
    )
    .await?;
    assert!(list_accounts.contains("Admin Test"));
    assert!(list_accounts.contains(&username));

    let pause = run_admin_command(
        &config,
        AdminCommand::PauseSync {
            account_email: username.clone(),
        },
    )
    .await?;
    assert!(pause.contains("paused"));

    let resume = run_admin_command(
        &config,
        AdminCommand::ResumeSync {
            account_email: username.clone(),
        },
    )
    .await?;
    assert!(resume.contains("resumed"));

    let delete = run_admin_command(
        &config,
        AdminCommand::DeleteAccount {
            account_email: username.clone(),
        },
    )
    .await?;
    assert!(delete.contains("deleted"));

    let post_delete = run_admin_command(
        &config,
        AdminCommand::ListAccounts {
            user_email: username.clone(),
        },
    )
    .await?;
    assert!(post_delete.is_empty());

    let audit_actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_log WHERE user_id = $1 ORDER BY id")
            .bind(_user.id)
            .fetch_all(repo.pool())
            .await?;
    assert!(audit_actions.contains(&"add_account".to_string()));
    assert!(audit_actions.contains(&"pause_sync".to_string()));
    assert!(audit_actions.contains(&"resume_sync".to_string()));
    assert!(audit_actions.contains(&"delete_account".to_string()));

    let post_delete_lookup = imap_cache_rs::db::repository::PostgresRepository::new(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&config.database_url.clone().unwrap())
            .await?,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    )
    .find_account_by_email_address_any_state(&username)
    .await?;
    assert!(post_delete_lookup.is_none());

    Ok(())
}

#[tokio::test]
async fn admin_create_user_records_audit_log() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = imap_cache_rs::db::repository::PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    );
    let config = Config {
        encryption_master_key: "test-master-key".to_string(),
        database_url: Some(std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
        })),
        ..Config::default()
    };

    let username = format!("create-user-{}@example.test", Uuid::new_v4());
    let password = "secret-password";
    let output = run_admin_command(
        &config,
        AdminCommand::CreateUser {
            username_email: username.clone(),
            password: Some(password.to_string()),
            password_stdin: false,
        },
    )
    .await?;
    assert!(output.contains("created user"));

    let audit: (String, serde_json::Value) = sqlx::query_as(
        "SELECT action, metadata_json FROM audit_log WHERE action = 'create_user' AND metadata_json->>'username_email' = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(&username)
    .fetch_one(repo.pool())
    .await?;
    assert_eq!(audit.0, "create_user");
    assert_eq!(audit.1["username_email"], username);

    Ok(())
}

#[tokio::test]
async fn admin_user_and_mailbox_commands_cover_state_transitions() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = imap_cache_rs::db::repository::PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    );
    let config = Config {
        encryption_master_key: "test-master-key".to_string(),
        database_url: Some(std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
        })),
        ..Config::default()
    };

    let username = format!("admin-state-{}@example.test", Uuid::new_v4());
    let original_password = "original-password";
    let updated_password = "updated-password";
    let _user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password(original_password)?,
        })
        .await?;

    let set_password = run_admin_command(
        &config,
        AdminCommand::SetPassword {
            username_email: username.clone(),
            password: Some(updated_password.to_string()),
            password_stdin: false,
        },
    )
    .await?;
    assert!(set_password.contains("updated 1 user(s)"));
    let stored_user = repo.find_user_by_username(&username).await?.unwrap();
    assert!(security::verify_password(
        &stored_user.password_hash,
        updated_password
    )?);
    assert!(!security::verify_password(
        &stored_user.password_hash,
        original_password
    )?);

    let disable_user = run_admin_command(
        &config,
        AdminCommand::DisableUser {
            username_email: username.clone(),
        },
    )
    .await?;
    assert!(disable_user.contains("disabled 1 user(s)"));
    let disabled_user = repo.find_user_by_username(&username).await?.unwrap();
    assert!(disabled_user.disabled_at.is_some());

    let account_output = run_admin_command(
        &config,
        AdminCommand::AddAccount {
            user_email: username.clone(),
            display_name: "Admin State".to_string(),
            email_address: username.clone(),
            upstream_host: "imap.example.test".to_string(),
            upstream_port: 993,
            upstream_tls_mode: "tls".to_string(),
            upstream_auth_method: "login".to_string(),
            upstream_username: "upstream-user".to_string(),
            upstream_secret: Some("upstream-secret".to_string()),
            upstream_secret_stdin: false,
        },
    )
    .await?;
    assert!(account_output.contains("created account"));

    let account = repo
        .find_account_by_email_address_any_state(&username)
        .await?
        .unwrap();
    let inbox = repo
        .upsert_mailbox(imap_cache_rs::db::repository::NewMailbox {
            account_id: account.id,
            name: "INBOX",
            canonical_name: "inbox",
            delimiter: Some("/"),
            attributes: vec!["\\HasNoChildren".to_string()],
            subscribed: true,
            special_use: Some("\\Inbox"),
            uidvalidity: Some(42),
            uidnext: Some(7),
            highestmodseq: Some(3),
            exists_count: 2,
            recent_count: 1,
            unseen_count: 1,
        })
        .await?;
    repo.upsert_mailbox(imap_cache_rs::db::repository::NewMailbox {
        account_id: account.id,
        name: "Archive",
        canonical_name: "archive",
        delimiter: Some("/"),
        attributes: vec!["\\HasNoChildren".to_string()],
        subscribed: false,
        special_use: None,
        uidvalidity: Some(42),
        uidnext: Some(1),
        highestmodseq: Some(0),
        exists_count: 0,
        recent_count: 0,
        unseen_count: 0,
    })
    .await?;
    repo.put_sync_state(NewSyncState {
        account_id: account.id,
        mailbox_id: Some(inbox.id),
        state_json: serde_json::json!({
            "mailbox_name": "INBOX",
            "phase": "idle"
        }),
        last_success_at: Some(Utc::now()),
        last_attempt_at: Some(Utc::now()),
        last_error: Some("waiting for upstream"),
    })
    .await?;

    let mailboxes = run_admin_command(
        &config,
        AdminCommand::ListMailboxes {
            account_email: username.clone(),
        },
    )
    .await?;
    assert!(mailboxes.contains("INBOX"));
    assert!(mailboxes.contains("Archive"));
    assert!(mailboxes.contains("true"));
    assert!(mailboxes.contains("false"));

    let status = run_admin_command(
        &config,
        AdminCommand::ShowSyncStatus {
            account_email: username.clone(),
            mailbox: Some("INBOX".to_string()),
        },
    )
    .await?;
    assert!(status.contains("mailbox=INBOX"));
    assert!(status.contains(r#""phase":"idle""#));
    assert!(status.contains("last_error=Some"));

    let account_status = run_admin_command(
        &config,
        AdminCommand::ShowSyncStatus {
            account_email: username.clone(),
            mailbox: None,
        },
    )
    .await?;
    assert!(account_status.contains("account="));

    Ok(())
}

#[tokio::test]
async fn admin_test_upstream_works_against_real_account() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let upstream = load_testing_credentials()?;
    let pool = connect_pool().await?;
    let repo = imap_cache_rs::db::repository::PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    );
    let config = Config {
        encryption_master_key: "test-master-key".to_string(),
        database_url: Some(std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
        })),
        ..Config::default()
    };

    let live_email = format!("admin-live-{}@example.test", Uuid::new_v4());
    let live_user = repo
        .create_user(NewUser {
            username_email: &live_email,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let _live_account = repo
        .create_mail_account(NewMailAccount {
            user_id: live_user.id,
            display_name: "Admin Live",
            email_address: &live_email,
            upstream_host: &upstream.host,
            upstream_port: i32::from(upstream.port),
            upstream_tls_mode: upstream.tls_mode,
            upstream_auth_method: upstream.auth_method,
            upstream_username: &upstream.username,
            upstream_secret: &upstream.secret,
        })
        .await?;
    let upstream_output = run_admin_command(
        &config,
        AdminCommand::TestUpstream {
            account_email: live_email.clone(),
        },
    )
    .await?;
    assert!(upstream_output.contains("upstream ok"));

    Ok(())
}

#[tokio::test]
async fn admin_force_syncs_a_real_account_record_against_fake_upstream() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = imap_cache_rs::db::repository::PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    );
    let mut config = Config {
        encryption_master_key: "test-master-key".to_string(),
        database_url: Some(std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
        })),
        ..Config::default()
    };
    let object_dir = tempfile::tempdir()?;
    let search_dir = tempfile::tempdir()?;
    config.object_store_path = Some(object_dir.path().join("objects"));
    config.search_index_path = Some(search_dir.path().join("index"));

    let upstream_username = format!("force-sync-user-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &upstream_username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        reader
            .get_mut()
            .write_all(b"* OK fake force-sync upstream ready\r\n")
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
                let body = concat!(
                    "From: Alice <alice@example.com>\r\n",
                    "To: Bob <bob@example.com>\r\n",
                    "Subject: Force Sync Target\r\n",
                    "Message-ID: <force-sync@example.com>\r\n",
                    "MIME-Version: 1.0\r\n",
                    "Content-Type: text/plain; charset=\"utf-8\"\r\n",
                    "\r\n",
                    "Hello from force sync.\r\n",
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

    let account_email = format!("force-sync-{}@example.test", Uuid::new_v4());
    let upstream_host = addr.ip().to_string();
    let upstream_port = addr.port();
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Force Sync",
            email_address: &account_email,
            upstream_host: &upstream_host,
            upstream_port: i32::from(upstream_port),
            upstream_tls_mode: UpstreamTlsMode::Plain,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: &upstream_username,
            upstream_secret: "secret-password",
        })
        .await?;

    let output = run_admin_command(
        &config,
        AdminCommand::ForceSync {
            account_email: account_email.clone(),
        },
    )
    .await?;
    assert!(output.contains("synced 1 mailbox(es), 1 message(s)"));

    let mailbox_id: i64 = sqlx::query_scalar(
        "SELECT id FROM mailboxes WHERE account_id = $1 AND canonical_name = $2",
    )
    .bind(account.id)
    .bind("inbox")
    .fetch_one(repo.pool())
    .await?;
    repo.put_sync_state(NewSyncState {
        account_id: account.id,
        mailbox_id: Some(mailbox_id),
        state_json: serde_json::json!({"last_uid": 1}),
        last_success_at: Some(chrono::Utc::now()),
        last_attempt_at: Some(chrono::Utc::now()),
        last_error: None,
    })
    .await?;

    let reset = run_admin_command(
        &config,
        AdminCommand::ResetMailboxState {
            account_email: account_email.clone(),
            mailbox: "INBOX".to_string(),
        },
    )
    .await?;
    assert!(reset.contains("reset 1 mailbox state row(s)"));
    assert!(
        repo.load_sync_state(account.id, Some(mailbox_id))
            .await?
            .is_none()
    );

    let message_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE account_id = $1 AND subject = $2")
            .bind(account.id)
            .bind("Force Sync Target")
            .fetch_one(repo.pool())
            .await?;
    assert_eq!(message_count, 1);

    server.await.unwrap();
    Ok(())
}

#[tokio::test]
async fn admin_clear_cache_removes_tracked_objects_and_blobs() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = imap_cache_rs::db::repository::PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    );
    let mut config = Config {
        encryption_master_key: "test-master-key".to_string(),
        database_url: Some(std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
        })),
        ..Config::default()
    };
    let object_dir = tempfile::tempdir()?;
    let search_dir = tempfile::tempdir()?;
    config.object_store_path = Some(object_dir.path().join("objects"));
    config.search_index_path = Some(search_dir.path().join("index"));

    let username = format!("clear-cache-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Clear Cache",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let object_store = FilesystemObjectStore::new(object_dir.path().join("objects"));
    let payload = b"cached object payload";
    let blob_key = imap_cache_rs::storage::content_addressed_key(
        imap_cache_rs::storage::ObjectType::Cache,
        payload,
    );
    let metadata = object_store.put(&blob_key, payload).await?;
    repo.upsert_cache_object(NewCacheObject {
        account_id: Some(account.id),
        object_type: "cache",
        blob_key: &metadata.key,
        sha256: &metadata.sha256,
        size_octets: metadata.size_octets as i64,
        ref_count: 1,
        last_accessed_at: Some(chrono::Utc::now()),
    })
    .await?;

    let cleared = run_admin_command(
        &config,
        AdminCommand::ClearCache {
            account_email: username.clone(),
        },
    )
    .await?;
    assert!(cleared.contains("cleared 1 cache object(s)"));
    assert!(object_store.get(&metadata.key).await?.is_none());
    assert_eq!(
        repo.list_cache_objects_for_account(account.id).await?.len(),
        0
    );
    Ok(())
}

#[tokio::test]
async fn admin_clear_cache_keeps_latest_objects_when_configured() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = imap_cache_rs::db::repository::PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    );
    let mut config = Config {
        encryption_master_key: "test-master-key".to_string(),
        database_url: Some(std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
        })),
        cache_eviction_keep_latest_objects: 1,
        ..Config::default()
    };
    let object_dir = tempfile::tempdir()?;
    let search_dir = tempfile::tempdir()?;
    config.object_store_path = Some(object_dir.path().join("objects"));
    config.search_index_path = Some(search_dir.path().join("index"));

    let username = format!("clear-cache-keep-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Clear Cache Keep Latest",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let object_store = FilesystemObjectStore::new(object_dir.path().join("objects"));

    let old_payload = b"old cached object payload";
    let old_key = imap_cache_rs::storage::content_addressed_key(
        imap_cache_rs::storage::ObjectType::Cache,
        old_payload,
    );
    let old_metadata = object_store.put(&old_key, old_payload).await?;
    repo.upsert_cache_object(NewCacheObject {
        account_id: Some(account.id),
        object_type: "cache",
        blob_key: &old_metadata.key,
        sha256: &old_metadata.sha256,
        size_octets: old_metadata.size_octets as i64,
        ref_count: 1,
        last_accessed_at: Some(Utc::now() - Duration::minutes(10)),
    })
    .await?;

    let new_payload = b"new cached object payload";
    let new_key = imap_cache_rs::storage::content_addressed_key(
        imap_cache_rs::storage::ObjectType::Cache,
        new_payload,
    );
    let new_metadata = object_store.put(&new_key, new_payload).await?;
    repo.upsert_cache_object(NewCacheObject {
        account_id: Some(account.id),
        object_type: "cache",
        blob_key: &new_metadata.key,
        sha256: &new_metadata.sha256,
        size_octets: new_metadata.size_octets as i64,
        ref_count: 1,
        last_accessed_at: Some(Utc::now()),
    })
    .await?;

    let cleared = run_admin_command(
        &config,
        AdminCommand::ClearCache {
            account_email: username.clone(),
        },
    )
    .await?;
    assert!(cleared.contains("cleared 1 cache object(s)"));
    assert!(object_store.get(&old_metadata.key).await?.is_none());
    assert!(object_store.get(&new_metadata.key).await?.is_some());
    let remaining = repo.list_cache_objects_for_account(account.id).await?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].blob_key, new_metadata.key);
    Ok(())
}

#[tokio::test]
async fn admin_delete_account_removes_tracked_cache_objects_and_blobs() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(imap_cache_rs::db::repository::PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));
    let mut config = Config {
        encryption_master_key: "test-master-key".to_string(),
        database_url: Some(std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
        })),
        ..Config::default()
    };
    let object_dir = tempfile::tempdir()?;
    let search_dir = tempfile::tempdir()?;
    config.object_store_path = Some(object_dir.path().join("objects"));
    config.search_index_path = Some(search_dir.path().join("index"));

    let username = format!("delete-cache-{}@example.test", Uuid::new_v4());
    let user = repo
        .create_user(NewUser {
            username_email: &username,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name: "Delete Cache",
            email_address: &username,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;
    let object_store: Arc<dyn ObjectStore> = Arc::new(FilesystemObjectStore::new(
        object_dir.path().join("objects"),
    ));
    let ingestor = MessageIngestor::new(Arc::clone(&repo), Arc::clone(&object_store), None);
    let mailbox = repo
        .upsert_mailbox(imap_cache_rs::db::repository::NewMailbox {
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
    let raw_message = concat!(
        "From: Alice <alice@example.com>\r\n",
        "To: Bob <bob@example.com>\r\n",
        "Subject: Delete Account Fixture\r\n",
        "Message-ID: <delete-account@example.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"outer\"\r\n",
        "\r\n",
        "--outer\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "Delete me.\r\n",
        "--outer\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-Disposition: attachment; filename=\"file.bin\"\r\n",
        "\r\n",
        "payload\r\n",
        "--outer--\r\n",
    );
    let ingested = ingestor
        .ingest_raw_message(
            account.id,
            mailbox.id,
            "INBOX",
            1,
            Some(1),
            None,
            raw_message.as_bytes(),
            vec!["\\Seen".to_string()],
        )
        .await?;
    let mime_blob_keys: Vec<String> =
        sqlx::query_scalar("SELECT blob_key FROM mime_parts WHERE message_id = $1 ORDER BY id ASC")
            .bind(ingested.message_id)
            .fetch_all(repo.pool())
            .await?;
    assert_eq!(mime_blob_keys.len(), 2);
    assert!(object_store.get(&ingested.blob_key).await?.is_some());
    for key in &mime_blob_keys {
        assert!(object_store.get(key).await?.is_some());
    }

    let deleted = run_admin_command(
        &config,
        AdminCommand::DeleteAccount {
            account_email: username.clone(),
        },
    )
    .await?;
    assert!(deleted.contains("deleted 1 account(s)"));
    assert!(object_store.get(&ingested.blob_key).await?.is_none());
    for key in &mime_blob_keys {
        assert!(object_store.get(key).await?.is_none());
    }
    assert!(
        repo.find_account_by_email_address_any_state(&username)
            .await?
            .is_none()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages WHERE account_id = $1")
            .bind(account.id)
            .fetch_one(repo.pool())
            .await?,
        0
    );
    assert_eq!(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM mime_parts mp JOIN messages m ON m.id = mp.message_id WHERE m.account_id = $1"
    )
    .bind(account.id)
    .fetch_one(repo.pool())
    .await?, 0);
    Ok(())
}

#[tokio::test]
async fn admin_delete_account_preserves_shared_blobs_for_other_accounts() -> anyhow::Result<()> {
    let pool = connect_pool().await?;
    let repo = Arc::new(imap_cache_rs::db::repository::PostgresRepository::new(
        pool,
        imap_cache_rs::security::SecretBox::from_passphrase("test-master-key"),
    ));
    let mut config = Config {
        encryption_master_key: "test-master-key".to_string(),
        database_url: Some(std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
        })),
        ..Config::default()
    };
    let object_dir = tempfile::tempdir()?;
    let search_dir = tempfile::tempdir()?;
    config.object_store_path = Some(object_dir.path().join("objects"));
    config.search_index_path = Some(search_dir.path().join("index"));

    let shared_token = Uuid::new_v4();
    let shared_raw = format!(
        "From: Alice <alice@example.com>\r\n\
To: Bob <bob@example.com>\r\n\
Subject: Shared Blob {shared_token}\r\n\
Message-ID: <shared-blob-{shared_token}@example.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=\"utf-8\"\r\n\
\r\n\
Shared content {shared_token}.\r\n"
    );

    let user_one_email = format!("shared-one-{}@example.test", Uuid::new_v4());
    let user_one = repo
        .create_user(NewUser {
            username_email: &user_one_email,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account_one = repo
        .create_mail_account(NewMailAccount {
            user_id: user_one.id,
            display_name: "Shared One",
            email_address: &user_one_email,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;

    let user_two_email = format!("shared-two-{}@example.test", Uuid::new_v4());
    let user_two = repo
        .create_user(NewUser {
            username_email: &user_two_email,
            password_hash: &security::hash_password("secret-password")?,
        })
        .await?;
    let account_two = repo
        .create_mail_account(NewMailAccount {
            user_id: user_two.id,
            display_name: "Shared Two",
            email_address: &user_two_email,
            upstream_host: "imap.example.test",
            upstream_port: 993,
            upstream_tls_mode: UpstreamTlsMode::Tls,
            upstream_auth_method: UpstreamAuthMethod::Login,
            upstream_username: "upstream-user",
            upstream_secret: "upstream-secret",
        })
        .await?;

    let object_store: Arc<dyn ObjectStore> = Arc::new(FilesystemObjectStore::new(
        object_dir.path().join("objects"),
    ));
    let ingestor = MessageIngestor::new(Arc::clone(&repo), Arc::clone(&object_store), None);

    let mailbox_one = repo
        .upsert_mailbox(imap_cache_rs::db::repository::NewMailbox {
            account_id: account_one.id,
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
    let mailbox_two = repo
        .upsert_mailbox(imap_cache_rs::db::repository::NewMailbox {
            account_id: account_two.id,
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

    let first = ingestor
        .ingest_raw_message(
            account_one.id,
            mailbox_one.id,
            "INBOX",
            1,
            Some(1),
            None,
            shared_raw.as_bytes(),
            vec!["\\Seen".to_string()],
        )
        .await?;
    let second = ingestor
        .ingest_raw_message(
            account_two.id,
            mailbox_two.id,
            "INBOX",
            1,
            Some(1),
            None,
            shared_raw.as_bytes(),
            vec!["\\Seen".to_string()],
        )
        .await?;
    assert_eq!(first.blob_key, second.blob_key);
    assert!(object_store.get(&first.blob_key).await?.is_some());
    assert_eq!(repo.list_cache_objects_for_account(account_one.id).await?.len(), 2);
    assert_eq!(repo.list_cache_objects_for_account(account_two.id).await?.len(), 2);

    let deleted = run_admin_command(
        &config,
        AdminCommand::DeleteAccount {
            account_email: user_one_email.clone(),
        },
    )
    .await?;
    assert!(deleted.contains("deleted 1 account(s)"));
    assert!(object_store.get(&first.blob_key).await?.is_some());
    assert!(
        repo.find_account_by_email_address_any_state(&user_two_email)
            .await?
            .is_some()
    );
    assert!(repo.list_cache_objects_for_account(account_one.id).await?.is_empty());
    assert_eq!(repo.list_cache_objects_for_account(account_two.id).await?.len(), 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages WHERE account_id = $1")
            .bind(account_two.id)
            .fetch_one(repo.pool())
            .await?,
        1
    );

    let deleted_two = run_admin_command(
        &config,
        AdminCommand::DeleteAccount {
            account_email: user_two_email.clone(),
        },
    )
    .await?;
    assert!(deleted_two.contains("deleted 1 account(s)"));
    assert!(object_store.get(&first.blob_key).await?.is_none());
    assert!(repo.list_cache_objects_for_account(account_two.id).await?.is_empty());

    Ok(())
}
