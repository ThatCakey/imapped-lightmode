use crate::{
    config::Config,
    db,
    db::repository::{NewMailAccount, NewUser, PostgresRepository},
    domain::{UpstreamAuthMethod, UpstreamTlsMode},
    error::{Error, Result},
    security,
    storage::ObjectStore,
};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::{convert::TryFrom, fmt::Write as _, path::PathBuf, sync::Arc};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};

#[derive(Debug, Parser)]
pub struct Cli {
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<AdminCommand>,
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    Run,
    RunMigrations,
    CreateUser {
        #[arg(long)]
        username_email: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = false)]
        password_stdin: bool,
    },
    DisableUser {
        #[arg(long)]
        username_email: String,
    },
    SetPassword {
        #[arg(long)]
        username_email: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = false)]
        password_stdin: bool,
    },
    AddAccount {
        #[arg(long)]
        user_email: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        email_address: String,
        #[arg(long)]
        upstream_host: String,
        #[arg(long)]
        upstream_port: u16,
        #[arg(long)]
        upstream_tls_mode: String,
        #[arg(long)]
        upstream_auth_method: String,
        #[arg(long)]
        upstream_username: String,
        #[arg(long)]
        upstream_secret: Option<String>,
        #[arg(long, default_value_t = false)]
        upstream_secret_stdin: bool,
    },
    DisableAccount {
        #[arg(long)]
        account_email: String,
    },
    PauseSync {
        #[arg(long)]
        account_email: String,
    },
    ResumeSync {
        #[arg(long)]
        account_email: String,
    },
    DeleteAccount {
        #[arg(long)]
        account_email: String,
    },
    TestUpstream {
        #[arg(long)]
        account_email: String,
    },
    ForceSync {
        #[arg(long)]
        account_email: String,
    },
    ResetMailboxState {
        #[arg(long)]
        account_email: String,
        #[arg(long)]
        mailbox: String,
    },
    ClearCache {
        #[arg(long)]
        account_email: String,
    },
    ListAccounts {
        #[arg(long)]
        user_email: String,
    },
    ListMailboxes {
        #[arg(long)]
        account_email: String,
    },
    ShowSyncStatus {
        #[arg(long)]
        account_email: String,
        #[arg(long)]
        mailbox: Option<String>,
    },
}

pub async fn run_cli(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load(cli.config.as_deref())?;
    security::ensure_rustls_crypto_provider();
    crate::protocol::init_tracing(&config.log_level)?;

    match cli.command.unwrap_or(AdminCommand::Run) {
        AdminCommand::Run => crate::run(config).await,
        AdminCommand::RunMigrations => {
            run_migrations_only(&config).await?;
            Ok(())
        }
        other => {
            let output = run_admin_command(&config, other).await?;
            if !output.is_empty() {
                println!("{output}");
            }
            Ok(())
        }
    }
}

pub async fn run_migrations_only(config: &Config) -> Result<()> {
    let Some(database_url) = config.database_url.as_deref() else {
        return Err(Error::Config(
            "run-migrations requires DATABASE_URL or database_url in config".to_string(),
        ));
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(|e| Error::Storage(format!("connecting to database failed: {e}")))?;
    db::run_migrations(&pool).await?;
    Ok(())
}

pub async fn run_admin_command(config: &Config, command: AdminCommand) -> Result<String> {
    if matches!(command, AdminCommand::Run | AdminCommand::RunMigrations) {
        return Err(Error::ImapCommand(
            "run and run-migrations are handled by the top-level dispatcher".to_string(),
        ));
    }

    if let AdminCommand::ForceSync { account_email } = &command {
        return run_force_sync_command(config, &account_email).await;
    }

    if let AdminCommand::ClearCache { account_email } = &command {
        return run_clear_cache_command(config, &account_email).await;
    }

    if let AdminCommand::DeleteAccount { account_email } = &command {
        return run_delete_account_command(config, &account_email).await;
    }

    if let AdminCommand::AddAccount {
        user_email,
        display_name,
        email_address,
        upstream_host,
        upstream_port,
        upstream_tls_mode,
        upstream_auth_method,
        upstream_username,
        upstream_secret,
        upstream_secret_stdin,
    } = &command
    {
        return run_add_account_command(
            config,
            user_email,
            display_name,
            email_address,
            upstream_host,
            *upstream_port,
            upstream_tls_mode,
            upstream_auth_method,
            upstream_username,
            upstream_secret,
            *upstream_secret_stdin,
        )
        .await;
    }

    let repo = open_repository(config).await?;
    execute_repository_command(repo, command, config.upstream_connection_limit_per_account).await
}

async fn run_force_sync_command(config: &Config, account_email: &str) -> Result<String> {
    let services = crate::AppServices::new(config)
        .await
        .map_err(|e| Error::Storage(format!("building application services failed: {e}")))?;
    let Some(repo) = services.repository.as_ref() else {
        return Err(Error::Config(
            "force-sync requires a database-backed repository".to_string(),
        ));
    };
    let Some(sync_engine) = services.sync_engine.as_ref() else {
        return Err(Error::Config(
            "force-sync requires sync engine support".to_string(),
        ));
    };
    let Some(account) = repo
        .find_account_by_email_address_any_state(account_email)
        .await?
    else {
        return Err(Error::Storage(format!(
            "account not found: {account_email}"
        )));
    };
    if account.disabled_at.is_some() {
        return Err(Error::Storage(format!(
            "account is disabled: {account_email}"
        )));
    }
    let Some(upstream_config) = repo.upstream_account_config(account_email).await? else {
        return Err(Error::Storage(format!(
            "account not found: {account_email}"
        )));
    };
    let mut client = crate::upstream::UpstreamClient::connect(&upstream_config)
        .await?
        .with_metrics(Arc::clone(&services.metrics))
        .with_account_connection_limit(account.id, config.upstream_connection_limit_per_account)
        .await?;
    client
        .authenticate_with_method(
            upstream_config.auth_method,
            &upstream_config.username,
            &upstream_config.secret,
        )
        .await?;
    let report = sync_engine.sync_account(account.id, &mut client).await?;
    client.logout().await?;
    record_admin_audit(
        repo,
        Some(account.user_id),
        Some(account.id),
        "force_sync",
        json!({
            "account_email": account_email,
            "mailboxes_synced": report.mailboxes_synced,
            "messages_synced": report.messages_synced
        }),
    )
    .await;
    Ok(format!(
        "synced {} mailbox(es), {} message(s) for {account_email}",
        report.mailboxes_synced, report.messages_synced
    ))
}

async fn run_clear_cache_command(config: &Config, account_email: &str) -> Result<String> {
    let services = crate::AppServices::new(config)
        .await
        .map_err(|e| Error::Storage(format!("building application services failed: {e}")))?;
    let Some(repo) = services.repository.as_ref() else {
        return Err(Error::Config(
            "clear-cache requires a database-backed repository".to_string(),
        ));
    };
    let Some(account) = repo
        .find_account_by_email_address_any_state(account_email)
        .await?
    else {
        return Err(Error::Storage(format!(
            "account not found: {account_email}"
        )));
    };
    let rows = prune_cache_objects_for_account(
        repo,
        services.object_store.as_ref(),
        account.id,
        config.cache_eviction_keep_latest_objects,
    )
    .await?;
    record_admin_audit(
        repo,
        Some(account.user_id),
        Some(account.id),
        "clear_cache",
        json!({"account_email": account_email, "removed_objects": rows}),
    )
    .await;
    Ok(format!(
        "cleared {rows} cache object(s) for {account_email}"
    ))
}

async fn run_delete_account_command(config: &Config, account_email: &str) -> Result<String> {
    let services = crate::AppServices::new(config)
        .await
        .map_err(|e| Error::Storage(format!("building application services failed: {e}")))?;
    let Some(repo) = services.repository.as_ref() else {
        return Err(Error::Config(
            "delete-account requires a database-backed repository".to_string(),
        ));
    };
    let Some(account) = repo
        .find_account_by_email_address_any_state(account_email)
        .await?
    else {
        return Err(Error::Storage(format!(
            "account not found: {account_email}"
        )));
    };
    let _lock_guard = if let Some(sync_engine) = services.sync_engine.as_ref() {
        let lock = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            sync_engine.acquire_account_lock(account.id, std::time::Duration::from_secs(600)),
        )
        .await
        .map_err(|_| {
            Error::Storage(format!(
                "timed out waiting for account sync lock: {account_email}"
            ))
        })??;
        Some(lock.ok_or_else(|| Error::Storage(format!("account sync is busy: {account_email}")))?)
    } else {
        None
    };
    let _ = repo.disable_mail_account(account.id).await?;
    record_admin_audit(
        repo,
        Some(account.user_id),
        Some(account.id),
        "delete_account",
        json!({"account_email": account_email}),
    )
    .await;
    purge_account_objects_for_deletion(repo, services.object_store.as_ref(), account.id).await?;
    let rows = repo.delete_mail_account(account.id).await?;
    Ok(format!("deleted {rows} account(s) for {account_email}"))
}

async fn run_add_account_command(
    config: &Config,
    user_email: &str,
    display_name: &str,
    email_address: &str,
    upstream_host: &str,
    upstream_port: u16,
    upstream_tls_mode: &str,
    upstream_auth_method: &str,
    upstream_username: &str,
    upstream_secret: &Option<String>,
    upstream_secret_stdin: bool,
) -> Result<String> {
    let repo = open_repository(config).await?;
    let Some(user) = repo.find_user_by_username(user_email).await? else {
        return Err(Error::Storage(format!("user not found: {user_email}")));
    };
    let tls_mode = upstream_tls_mode
        .parse::<UpstreamTlsMode>()
        .map_err(|e| Error::Storage(e.to_string()))?;
    let auth_method = upstream_auth_method
        .parse::<UpstreamAuthMethod>()
        .map_err(|e| Error::Storage(e.to_string()))?;
    let upstream_secret =
        resolve_secret_input(upstream_secret.clone(), upstream_secret_stdin, "upstream secret")
            .await?;
    let account = repo
        .create_mail_account(NewMailAccount {
            user_id: user.id,
            display_name,
            email_address,
            upstream_host,
            upstream_port: i32::from(upstream_port),
            upstream_tls_mode: tls_mode,
            upstream_auth_method: auth_method,
            upstream_username,
            upstream_secret: &upstream_secret,
        })
        .await?;
    let quota = repo
        .upsert_account_quota(
            account.id,
            i64::try_from(config.default_account_quota_bytes).map_err(|e| {
                Error::Config(format!("default_account_quota_bytes is too large: {e}"))
            })?,
        )
        .await?;
    record_admin_audit(
        &repo,
        Some(user.id),
        Some(account.id),
        "add_account",
        json!({
            "user_email": user_email,
            "account_email": email_address,
            "upstream_host": upstream_host,
            "upstream_port": upstream_port,
            "upstream_tls_mode": upstream_tls_mode,
            "upstream_auth_method": upstream_auth_method
        }),
    )
    .await;
    Ok(format!(
        "created account {} (id={}) with quota {} bytes",
        account.email_address, account.id, quota.max_bytes
    ))
}

async fn purge_account_objects_for_deletion(
    repo: &PostgresRepository,
    object_store: &dyn ObjectStore,
    account_id: i64,
) -> Result<()> {
    let mut cache_keys = std::collections::BTreeSet::new();
    loop {
        let cache_objects = repo.list_cache_objects_for_account(account_id).await?;
        if cache_objects.is_empty() {
            break;
        }
        for object in cache_objects {
            cache_keys.insert(object.blob_key.clone());
            if repo
                .delete_cache_object_for_account(account_id, &object.blob_key)
                .await?
            {
                object_store.delete(&object.blob_key).await?;
            }
        }
    }

    let object_keys = repo.list_object_keys_for_account(account_id).await?;
    for key in object_keys
        .into_iter()
        .filter(|key| !cache_keys.contains(key))
    {
        if repo
            .count_blob_key_references_elsewhere(&key, account_id)
            .await?
            == 0
        {
            object_store.delete(&key).await?;
        }
    }
    Ok(())
}

async fn prune_cache_objects_for_account(
    repo: &PostgresRepository,
    object_store: &dyn ObjectStore,
    account_id: i64,
    keep_latest_objects: usize,
) -> Result<u64> {
    let cache_objects = if keep_latest_objects == 0 {
        repo.list_cache_objects_for_account(account_id).await?
    } else {
        repo.list_cache_objects_for_account_by_recency(account_id)
            .await?
    };
    let to_delete = if keep_latest_objects == 0 {
        cache_objects.as_slice()
    } else {
        let keep_from = cache_objects.len().saturating_sub(keep_latest_objects);
        &cache_objects[..keep_from]
    };
    let mut deleted = 0u64;
    for object in to_delete {
        if repo
            .delete_cache_object_for_account(account_id, &object.blob_key)
            .await?
        {
            object_store.delete(&object.blob_key).await?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

async fn open_repository(config: &Config) -> Result<Arc<PostgresRepository>> {
    let Some(database_url) = config.database_url.as_deref() else {
        return Err(Error::Config(
            "database-backed admin commands require DATABASE_URL or database_url".to_string(),
        ));
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(|e| Error::Storage(format!("connecting to database failed: {e}")))?;
    db::run_migrations(&pool).await?;
    Ok(Arc::new(PostgresRepository::new(
        pool,
        security::SecretBox::from_passphrase(&config.encryption_master_key),
    )))
}

async fn record_admin_audit(
    repo: &PostgresRepository,
    user_id: Option<i64>,
    account_id: Option<i64>,
    action: &str,
    metadata: serde_json::Value,
) {
    let _ = repo
        .record_audit_log(user_id, account_id, action, metadata)
        .await;
}

async fn resolve_secret_input(
    value: Option<String>,
    from_stdin: bool,
    label: &str,
) -> Result<String> {
    match (value, from_stdin) {
        (Some(value), false) => Ok(value),
        (Some(_), true) => Err(Error::Config(format!(
            "{label} may be provided inline or via stdin, not both"
        ))),
        (None, true) => read_secret_line(label).await,
        (None, false) => Err(Error::Config(format!(
            "{label} is required unless the corresponding --*-stdin flag is used"
        ))),
    }
}

async fn read_secret_line(label: &str) -> Result<String> {
    let mut reader = BufReader::new(tokio::io::stdin());
    read_secret_line_from_reader(&mut reader, label).await
}

async fn read_secret_line_from_reader<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    label: &str,
) -> Result<String> {
    let mut input = String::new();
    let bytes = reader.read_line(&mut input).await?;
    if bytes == 0 {
        return Err(Error::Config(format!("stdin closed while reading {label}")));
    }
    if input.ends_with('\n') {
        input.pop();
        if input.ends_with('\r') {
            input.pop();
        }
    }
    Ok(input)
}

pub async fn execute_repository_command(
    repo: Arc<PostgresRepository>,
    command: AdminCommand,
    upstream_connection_limit_per_account: usize,
) -> Result<String> {
    match command {
        AdminCommand::CreateUser {
            username_email,
            password,
            password_stdin,
        } => {
            let password = resolve_secret_input(password, password_stdin, "password").await?;
            let user = repo
                .create_user(NewUser {
                    username_email: &username_email,
                    password_hash: &security::hash_password(&password)?,
                })
                .await?;
            record_admin_audit(
                &repo,
                Some(user.id),
                None,
                "create_user",
                json!({"username_email": user.username_email}),
            )
            .await;
            Ok(format!(
                "created user {} (id={})",
                user.username_email, user.id
            ))
        }
        AdminCommand::DisableUser { username_email } => {
            let rows = repo.disable_user(&username_email).await?;
            if rows > 0 {
                if let Some(user) = repo.find_user_by_username(&username_email).await? {
                    record_admin_audit(
                        &repo,
                        Some(user.id),
                        None,
                        "disable_user",
                        json!({"username_email": username_email}),
                    )
                    .await;
                }
            }
            Ok(format!("disabled {rows} user(s) for {username_email}"))
        }
        AdminCommand::SetPassword {
            username_email,
            password,
            password_stdin,
        } => {
            let password = resolve_secret_input(password, password_stdin, "password").await?;
            let rows = repo
                .set_user_password(&username_email, &security::hash_password(&password)?)
                .await?;
            if let Some(user) = repo.find_user_by_username(&username_email).await? {
                record_admin_audit(
                    &repo,
                    Some(user.id),
                    None,
                    "set_password",
                    json!({"username_email": username_email}),
                )
                .await;
            }
            Ok(format!("updated {rows} user(s) for {username_email}"))
        }
        AdminCommand::AddAccount { .. } => unreachable!(),
        AdminCommand::DisableAccount { account_email } => {
            let Some(account) = repo.find_account_by_email_address(&account_email).await? else {
                return Err(Error::Storage(format!(
                    "account not found: {account_email}"
                )));
            };
            let rows = repo.disable_mail_account(account.id).await?;
            if rows > 0 {
                record_admin_audit(
                    &repo,
                    Some(account.user_id),
                    Some(account.id),
                    "disable_account",
                    json!({"account_email": account_email}),
                )
                .await;
            }
            Ok(format!("disabled {rows} account(s) for {account_email}"))
        }
        AdminCommand::PauseSync { account_email } => {
            let Some(account) = repo.find_account_by_email_address(&account_email).await? else {
                return Err(Error::Storage(format!(
                    "account not found: {account_email}"
                )));
            };
            let rows = repo.disable_mail_account(account.id).await?;
            if rows > 0 {
                record_admin_audit(
                    &repo,
                    Some(account.user_id),
                    Some(account.id),
                    "pause_sync",
                    json!({"account_email": account_email}),
                )
                .await;
            }
            Ok(format!("paused {rows} account(s) for {account_email}"))
        }
        AdminCommand::ResumeSync { account_email } => {
            let Some(account) = repo
                .find_account_by_email_address_any_state(&account_email)
                .await?
            else {
                return Err(Error::Storage(format!(
                    "account not found: {account_email}"
                )));
            };
            let rows = repo.enable_mail_account(account.id).await?;
            if rows > 0 {
                record_admin_audit(
                    &repo,
                    Some(account.user_id),
                    Some(account.id),
                    "resume_sync",
                    json!({"account_email": account_email}),
                )
                .await;
            }
            Ok(format!("resumed {rows} account(s) for {account_email}"))
        }
        AdminCommand::DeleteAccount { account_email: _ } => {
            unreachable!()
        }
        AdminCommand::TestUpstream { account_email } => {
            let Some(account) = repo
                .find_account_by_email_address_any_state(&account_email)
                .await?
            else {
                return Err(Error::Storage(format!(
                    "account not found: {account_email}"
                )));
            };
            let Some(config) = repo.upstream_account_config(&account_email).await? else {
                return Err(Error::Storage(format!(
                    "account not found: {account_email}"
                )));
            };
            let mut client = crate::upstream::UpstreamClient::connect(&config)
                .await?
                .with_account_connection_limit(account.id, upstream_connection_limit_per_account)
                .await?;
            let _ = client.capability().await?;
            client
                .authenticate_with_method(config.auth_method, &config.username, &config.secret)
                .await?;
            let mailboxes = client.list_mailboxes().await?;
            if let Some(mailbox) = mailboxes
                .iter()
                .find(|mailbox| mailbox.eq_ignore_ascii_case("INBOX"))
            {
                client.select(mailbox).await?;
            }
            client.noop().await?;
            client.logout().await?;
            Ok(format!("upstream ok for {account_email}"))
        }
        AdminCommand::ForceSync { .. } => unreachable!(),
        AdminCommand::ResetMailboxState {
            account_email,
            mailbox,
        } => {
            let Some(account) = repo
                .find_account_by_email_address_any_state(&account_email)
                .await?
            else {
                return Err(Error::Storage(format!(
                    "account not found: {account_email}"
                )));
            };
            let Some(mailbox_row) = repo.find_mailbox(account.id, &mailbox).await? else {
                return Err(Error::Storage(format!("mailbox not found: {mailbox}")));
            };
            let rows = repo
                .delete_sync_state(account.id, Some(mailbox_row.id))
                .await?;
            if rows > 0 {
                record_admin_audit(
                    &repo,
                    Some(account.user_id),
                    Some(account.id),
                    "reset_mailbox_state",
                    json!({"account_email": account_email, "mailbox": mailbox}),
                )
                .await;
            }
            Ok(format!(
                "reset {rows} mailbox state row(s) for {account_email}/{mailbox}"
            ))
        }
        AdminCommand::ClearCache { .. } => unreachable!(),
        AdminCommand::ListAccounts { user_email } => {
            let Some(user) = repo.find_user_by_username(&user_email).await? else {
                return Err(Error::Storage(format!("user not found: {user_email}")));
            };
            let accounts = repo.list_accounts_for_user(user.id).await?;
            let mut output = String::new();
            for account in accounts {
                let _ = writeln!(
                    &mut output,
                    "{}\t{}\t{}",
                    account.id, account.email_address, account.display_name
                );
            }
            Ok(output.trim_end().to_string())
        }
        AdminCommand::ListMailboxes { account_email } => {
            let Some(account) = repo.find_account_by_email_address(&account_email).await? else {
                return Err(Error::Storage(format!(
                    "account not found: {account_email}"
                )));
            };
            let mailboxes = repo.list_mailboxes(account.id, None).await?;
            let mut output = String::new();
            for mailbox in mailboxes {
                let _ = writeln!(
                    &mut output,
                    "{}\t{}\t{}\t{}",
                    mailbox.id, mailbox.name, mailbox.exists_count, mailbox.subscribed
                );
            }
            Ok(output.trim_end().to_string())
        }
        AdminCommand::ShowSyncStatus {
            account_email,
            mailbox,
        } => {
            let Some(account) = repo.find_account_by_email_address(&account_email).await? else {
                return Err(Error::Storage(format!(
                    "account not found: {account_email}"
                )));
            };
            let mut output = String::new();
            if let Some(mailbox_name) = mailbox {
                let Some(mailbox_row) = repo.find_mailbox(account.id, &mailbox_name).await? else {
                    return Err(Error::Storage(format!("mailbox not found: {mailbox_name}")));
                };
                if let Some(sync_state) = repo
                    .load_sync_state(account.id, Some(mailbox_row.id))
                    .await?
                {
                    let _ = writeln!(
                        &mut output,
                        "mailbox={} state={} last_success_at={:?} last_attempt_at={:?} last_error={:?}",
                        mailbox_row.name,
                        sync_state.state_json,
                        sync_state.last_success_at,
                        sync_state.last_attempt_at,
                        sync_state.last_error
                    );
                } else {
                    let _ = writeln!(&mut output, "mailbox={} state=none", mailbox_row.name);
                }
            } else {
                let _ = writeln!(
                    &mut output,
                    "account={} id={}",
                    account.email_address, account.id
                );
            }
            Ok(output.trim_end().to_string())
        }
        AdminCommand::Run | AdminCommand::RunMigrations => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::repository::NewCacheObject,
        storage::{ObjectType, content_addressed_key, filesystem::FilesystemObjectStore},
    };
    use tokio::io::{AsyncWriteExt, BufReader, duplex};

    async fn connect_pool() -> Result<sqlx::PgPool> {
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
    async fn prune_cache_objects_keeps_the_newest_entry() -> Result<()> {
        let pool = connect_pool().await?;
        let repo = PostgresRepository::new(
            pool,
            security::SecretBox::from_passphrase("test-master-key"),
        );
        let object_dir = tempfile::tempdir().map_err(Error::from)?;
        let object_store = FilesystemObjectStore::new(object_dir.path().join("objects"));

        let username = format!("admin-lru-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(crate::db::repository::NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Cache LRU",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;

        let oldest = format!("oldest-cache-object-{}", uuid::Uuid::new_v4());
        let middle = format!("middle-cache-object-{}", uuid::Uuid::new_v4());
        let newest = format!("newest-cache-object-{}", uuid::Uuid::new_v4());
        let oldest_key = content_addressed_key(ObjectType::Cache, oldest.as_bytes());
        let middle_key = content_addressed_key(ObjectType::Cache, middle.as_bytes());
        let newest_key = content_addressed_key(ObjectType::Cache, newest.as_bytes());
        let oldest_meta = object_store.put(&oldest_key, oldest.as_bytes()).await?;
        let middle_meta = object_store.put(&middle_key, middle.as_bytes()).await?;
        let newest_meta = object_store.put(&newest_key, newest.as_bytes()).await?;

        let old_time = chrono::Utc::now() - chrono::Duration::days(3);
        let middle_time = chrono::Utc::now() - chrono::Duration::days(2);
        let new_time = chrono::Utc::now() - chrono::Duration::days(1);
        repo.upsert_cache_object(NewCacheObject {
            account_id: Some(account.id),
            object_type: "cache",
            blob_key: &oldest_meta.key,
            sha256: &oldest_meta.sha256,
            size_octets: oldest_meta.size_octets as i64,
            ref_count: 1,
            last_accessed_at: Some(old_time),
        })
        .await?;
        repo.upsert_cache_object(NewCacheObject {
            account_id: Some(account.id),
            object_type: "cache",
            blob_key: &middle_meta.key,
            sha256: &middle_meta.sha256,
            size_octets: middle_meta.size_octets as i64,
            ref_count: 1,
            last_accessed_at: Some(middle_time),
        })
        .await?;
        repo.upsert_cache_object(NewCacheObject {
            account_id: Some(account.id),
            object_type: "cache",
            blob_key: &newest_meta.key,
            sha256: &newest_meta.sha256,
            size_octets: newest_meta.size_octets as i64,
            ref_count: 1,
            last_accessed_at: Some(new_time),
        })
        .await?;

        let before = repo.list_cache_objects_for_account(account.id).await?;
        assert_eq!(before.len(), 3);
        let pruned = prune_cache_objects_for_account(&repo, &object_store, account.id, 1).await?;
        assert_eq!(pruned, 2);
        assert!(object_store.get(&oldest_meta.key).await?.is_none());
        assert!(object_store.get(&middle_meta.key).await?.is_none());
        assert!(object_store.get(&newest_meta.key).await?.is_some());
        let remaining = repo.list_cache_objects_for_account(account.id).await?;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].blob_key, newest_meta.key);
        Ok(())
    }

    #[tokio::test]
    async fn reads_secret_input_from_async_reader() -> Result<()> {
        let (client, server) = duplex(16);
        let mut reader = BufReader::new(server);
        let writer = tokio::spawn(async move {
            let mut client = client;
            client.write_all(b"secret-line\r\n").await.unwrap();
        });

        let secret = read_secret_line_from_reader(&mut reader, "password").await?;
        writer.await.unwrap();
        assert_eq!(secret, "secret-line");
        Ok(())
    }
}
