use imap_cache_core::{
    domain::{
        AuditLogEntry, CacheObject, MailAccount, Mailbox, MailboxMessage, Message, MimePart,
        MutationStatus, PendingMutation, Quota, SessionRecord, SyncState, UpstreamAuthMethod,
        UpstreamTlsMode, User,
    },
    error::{Error, Result},
    security::SecretBox,
};
use imap_cache_notifications::{MutationEvent, MutationEventSink};
use imap_cache_upstream::UpstreamAccountConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use std::{str::FromStr, sync::Arc};
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresRepository {
    pool: PgPool,
    secrets: SecretBox,
    event_sink: Option<Arc<dyn MutationEventSink>>,
}

impl PostgresRepository {
    pub fn new(pool: PgPool, secrets: SecretBox) -> Self {
        Self {
            pool,
            secrets,
            event_sink: None,
        }
    }

    pub fn with_event_sink(mut self, event_sink: Arc<dyn MutationEventSink>) -> Self {
        self.event_sink = Some(event_sink);
        self
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn publish_event(&self, event: MutationEvent) {
        let Some(sink) = &self.event_sink else {
            return;
        };
        if let Err(err) = sink.publish(event).await {
            tracing::warn!(error = %err, "failed to publish redis mutation event");
        }
    }

    async fn account_id_for_mailbox(&self, mailbox_id: i64) -> Result<Option<i64>> {
        let account_id = sqlx::query_scalar::<_, Option<i64>>(
            r#"
            SELECT account_id
            FROM mailboxes
            WHERE id = $1
            "#,
        )
        .bind(mailbox_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(account_id.flatten())
    }

    async fn assign_mailbox_modseq(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        mailbox_id: i64,
        requested: Option<i64>,
    ) -> Result<i64> {
        let current = sqlx::query_scalar::<_, Option<i64>>(
            r#"
            SELECT highestmodseq
            FROM mailboxes
            WHERE id = $1
            FOR UPDATE
            "#,
        )
        .bind(mailbox_id)
        .fetch_one(&mut **tx)
        .await?
        .unwrap_or(0);
        let assigned = requested.unwrap_or_else(|| current.saturating_add(1));
        let next = assigned.max(current);
        if next != current {
            sqlx::query(
                r#"
                UPDATE mailboxes
                SET highestmodseq = $2, updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(mailbox_id)
            .bind(next)
            .execute(&mut **tx)
            .await?;
        }
        Ok(next)
    }

    async fn assign_mailbox_local_uid(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        mailbox_id: i64,
    ) -> Result<i64> {
        let _ = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT id
            FROM mailboxes
            WHERE id = $1
            FOR UPDATE
            "#,
        )
        .bind(mailbox_id)
        .fetch_one(&mut **tx)
        .await?;
        let next_uid = sqlx::query_scalar::<_, Option<i64>>(
            r#"
            SELECT MAX(local_uid) + 1
            FROM mailbox_messages
            WHERE mailbox_id = $1 AND is_expunged = FALSE
            "#,
        )
        .bind(mailbox_id)
        .fetch_one(&mut **tx)
        .await?;
        Ok(next_uid.unwrap_or(1))
    }

    async fn mailbox_sequence_number_in_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        mailbox_id: i64,
        local_uid: i64,
    ) -> Result<i64> {
        let preceding = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM mailbox_messages
            WHERE mailbox_id = $1
              AND is_expunged = FALSE
              AND local_uid < $2
            "#,
        )
        .bind(mailbox_id)
        .bind(local_uid)
        .fetch_one(&mut **tx)
        .await?;
        Ok(preceding + 1)
    }

    pub async fn create_user(&self, input: NewUser<'_>) -> Result<User> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            INSERT INTO users (username_email, password_hash)
            VALUES ($1, $2)
            RETURNING id, username_email, password_hash, created_at, disabled_at
            "#,
        )
        .bind(input.username_email)
        .bind(input.password_hash)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    pub async fn set_user_password(
        &self,
        username_email: &str,
        password_hash: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE users
            SET password_hash = $2
            WHERE lower(username_email) = lower($1)
            "#,
        )
        .bind(username_email)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn record_audit_log(
        &self,
        user_id: Option<i64>,
        account_id: Option<i64>,
        action: &str,
        metadata_json: Value,
    ) -> Result<AuditLogEntry> {
        let row = sqlx::query_as::<_, AuditLogRow>(
            r#"
            INSERT INTO audit_log (user_id, account_id, action, metadata_json)
            VALUES ($1, $2, $3, $4)
            RETURNING id, user_id, account_id, action, metadata_json, created_at
            "#,
        )
        .bind(user_id)
        .bind(account_id)
        .bind(action)
        .bind(metadata_json)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    pub async fn create_session(&self, input: NewSession<'_>) -> Result<SessionRecord> {
        let connection_id = Uuid::parse_str(input.connection_id)
            .map_err(|e| Error::Storage(format!("invalid session connection_id: {e}")))?;
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            INSERT INTO sessions (
                user_id,
                account_id,
                connection_id,
                remote_addr,
                authenticated_at,
                disconnected_at
            )
            VALUES ($1, $2, $3, $4, NOW(), NULL)
            RETURNING
                id,
                user_id,
                account_id,
                connection_id,
                remote_addr,
                authenticated_at,
                disconnected_at
            "#,
        )
        .bind(input.user_id)
        .bind(input.account_id)
        .bind(connection_id)
        .bind(input.remote_addr)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    pub async fn mark_session_disconnected(
        &self,
        connection_id: &str,
    ) -> Result<Option<SessionRecord>> {
        let connection_id = Uuid::parse_str(connection_id)
            .map_err(|e| Error::Storage(format!("invalid session connection_id: {e}")))?;
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            UPDATE sessions
            SET disconnected_at = COALESCE(disconnected_at, NOW())
            WHERE connection_id = $1
            RETURNING
                id,
                user_id,
                account_id,
                connection_id,
                remote_addr,
                authenticated_at,
                disconnected_at
            "#,
        )
        .bind(connection_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn disable_user(&self, username_email: &str) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE users
            SET disabled_at = NOW()
            WHERE lower(username_email) = lower($1) AND disabled_at IS NULL
            "#,
        )
        .bind(username_email)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn find_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, username_email, password_hash, created_at, disabled_at
            FROM users
            WHERE lower(username_email) = lower($1)
            ORDER BY id DESC
            LIMIT 1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn create_mail_account(&self, input: NewMailAccount<'_>) -> Result<MailAccount> {
        let encrypted_upstream_username =
            self.secrets.encrypt(input.upstream_username.as_bytes())?;
        let encrypted_upstream_secret = self.secrets.encrypt(input.upstream_secret.as_bytes())?;
        let row = sqlx::query_as::<_, MailAccountRow>(
            r#"
            INSERT INTO mail_accounts (
                user_id,
                display_name,
                email_address,
                upstream_host,
                upstream_port,
                upstream_tls_mode,
                upstream_auth_method,
                encrypted_upstream_username,
                encrypted_upstream_secret
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING
                id,
                user_id,
                display_name,
                email_address,
                upstream_host,
                upstream_port,
                upstream_tls_mode,
                upstream_auth_method,
                encrypted_upstream_username,
                encrypted_upstream_secret,
                created_at,
                disabled_at,
                last_sync_at,
                last_sync_error
            "#,
        )
        .bind(input.user_id)
        .bind(input.display_name)
        .bind(input.email_address)
        .bind(input.upstream_host)
        .bind(input.upstream_port)
        .bind(input.upstream_tls_mode.to_string())
        .bind(input.upstream_auth_method.to_string())
        .bind(encrypted_upstream_username)
        .bind(encrypted_upstream_secret)
        .fetch_one(&self.pool)
        .await?;
        self.publish_event(MutationEvent::account_changed(
            row.id,
            "create_mail_account",
        ))
        .await;
        row.try_into()
    }

    pub async fn get_account_quota(&self, account_id: i64) -> Result<Option<Quota>> {
        let row = sqlx::query_as::<_, QuotaRow>(
            r#"
            SELECT id, user_id, account_id, max_bytes, used_bytes, updated_at
            FROM quotas
            WHERE account_id = $1
            ORDER BY id DESC
            LIMIT 1
            "#,
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn upsert_account_quota(&self, account_id: i64, max_bytes: i64) -> Result<Quota> {
        let row = sqlx::query_as::<_, QuotaRow>(
            r#"
            INSERT INTO quotas (account_id, max_bytes, used_bytes, updated_at)
            VALUES ($1, $2, 0, NOW())
            ON CONFLICT (account_id) WHERE account_id IS NOT NULL
            DO UPDATE SET
                max_bytes = EXCLUDED.max_bytes,
                updated_at = NOW()
            RETURNING id, user_id, account_id, max_bytes, used_bytes, updated_at
            "#,
        )
        .bind(account_id)
        .bind(max_bytes)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    pub async fn adjust_account_quota_usage(
        &self,
        account_id: i64,
        delta_bytes: i64,
    ) -> Result<Option<Quota>> {
        let row = sqlx::query_as::<_, QuotaRow>(
            r#"
            UPDATE quotas
            SET used_bytes = used_bytes + $2,
                updated_at = NOW()
            WHERE account_id = $1
            RETURNING id, user_id, account_id, max_bytes, used_bytes, updated_at
            "#,
        )
        .bind(account_id)
        .bind(delta_bytes)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn disable_mail_account(&self, account_id: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE mail_accounts
            SET disabled_at = NOW()
            WHERE id = $1 AND disabled_at IS NULL
            "#,
        )
        .bind(account_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() > 0 {
            self.publish_event(MutationEvent::account_changed(
                account_id,
                "disable_mail_account",
            ))
            .await;
        }
        Ok(result.rows_affected())
    }

    pub async fn enable_mail_account(&self, account_id: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE mail_accounts
            SET disabled_at = NULL
            WHERE id = $1 AND disabled_at IS NOT NULL
            "#,
        )
        .bind(account_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() > 0 {
            self.publish_event(MutationEvent::account_changed(
                account_id,
                "enable_mail_account",
            ))
            .await;
        }
        Ok(result.rows_affected())
    }

    pub async fn set_mail_account_sync_status(
        &self,
        account_id: i64,
        last_sync_at: Option<DateTime<Utc>>,
        last_sync_error: Option<&str>,
    ) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE mail_accounts
            SET last_sync_at = $2,
                last_sync_error = $3
            WHERE id = $1
            "#,
        )
        .bind(account_id)
        .bind(last_sync_at)
        .bind(last_sync_error)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn delete_mail_account(&self, account_id: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM mail_accounts
            WHERE id = $1
            "#,
        )
        .bind(account_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() > 0 {
            self.publish_event(MutationEvent::account_changed(
                account_id,
                "delete_mail_account",
            ))
            .await;
        }
        Ok(result.rows_affected())
    }

    pub async fn upsert_mailbox(&self, input: NewMailbox<'_>) -> Result<Mailbox> {
        let row = sqlx::query_as::<_, MailboxRow>(
            r#"
            INSERT INTO mailboxes (
                account_id,
                name,
                canonical_name,
                delimiter,
                attributes,
                subscribed,
                special_use,
                uidvalidity,
                uidnext,
                highestmodseq,
                exists_count,
                recent_count,
                unseen_count,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
            ON CONFLICT (account_id, canonical_name) DO UPDATE
            SET
                name = EXCLUDED.name,
                delimiter = EXCLUDED.delimiter,
                attributes = EXCLUDED.attributes,
                subscribed = EXCLUDED.subscribed,
                special_use = EXCLUDED.special_use,
                uidvalidity = EXCLUDED.uidvalidity,
                uidnext = EXCLUDED.uidnext,
                highestmodseq = EXCLUDED.highestmodseq,
                exists_count = EXCLUDED.exists_count,
                recent_count = EXCLUDED.recent_count,
                unseen_count = EXCLUDED.unseen_count,
                updated_at = NOW()
            RETURNING
                id,
                account_id,
                name,
                canonical_name,
                delimiter,
                attributes,
                subscribed,
                special_use,
                uidvalidity,
                uidnext,
                highestmodseq,
                exists_count,
                recent_count,
                unseen_count,
                created_at,
                updated_at
            "#,
        )
        .bind(input.account_id)
        .bind(input.name)
        .bind(input.canonical_name)
        .bind(input.delimiter)
        .bind(input.attributes)
        .bind(input.subscribed)
        .bind(input.special_use)
        .bind(input.uidvalidity)
        .bind(input.uidnext)
        .bind(input.highestmodseq)
        .bind(input.exists_count)
        .bind(input.recent_count)
        .bind(input.unseen_count)
        .fetch_one(&self.pool)
        .await?;
        self.publish_event(MutationEvent::mailbox_changed(
            Some(row.account_id),
            Some(row.id),
            "upsert_mailbox",
        ))
        .await;
        Ok(row.into())
    }

    pub async fn find_mailbox(
        &self,
        account_id: i64,
        mailbox_name: &str,
    ) -> Result<Option<Mailbox>> {
        let row = sqlx::query_as::<_, MailboxRow>(
            r#"
            SELECT
                id,
                account_id,
                name,
                canonical_name,
                delimiter,
                attributes,
                subscribed,
                special_use,
                uidvalidity,
                uidnext,
                highestmodseq,
                exists_count,
                recent_count,
                unseen_count,
                created_at,
                updated_at
            FROM mailboxes
            WHERE account_id = $1 AND (name = $2 OR canonical_name = $3)
            ORDER BY id DESC
            LIMIT 1
            "#,
        )
        .bind(account_id)
        .bind(mailbox_name)
        .bind(mailbox_name.to_ascii_lowercase())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn list_mailboxes(
        &self,
        account_id: i64,
        subscribed_only: Option<bool>,
    ) -> Result<Vec<Mailbox>> {
        let rows = match subscribed_only {
            Some(true) => {
                sqlx::query_as::<_, MailboxRow>(
                    r#"
                    SELECT
                        id,
                        account_id,
                        name,
                        canonical_name,
                        delimiter,
                        attributes,
                        subscribed,
                        special_use,
                        uidvalidity,
                        uidnext,
                        highestmodseq,
                        exists_count,
                        recent_count,
                        unseen_count,
                        created_at,
                        updated_at
                    FROM mailboxes
                    WHERE account_id = $1 AND subscribed = TRUE
                    ORDER BY canonical_name ASC, id ASC
                    "#,
                )
                .bind(account_id)
                .fetch_all(&self.pool)
                .await?
            }
            Some(false) => {
                sqlx::query_as::<_, MailboxRow>(
                    r#"
                    SELECT
                        id,
                        account_id,
                        name,
                        canonical_name,
                        delimiter,
                        attributes,
                        subscribed,
                        special_use,
                        uidvalidity,
                        uidnext,
                        highestmodseq,
                        exists_count,
                        recent_count,
                        unseen_count,
                        created_at,
                        updated_at
                    FROM mailboxes
                    WHERE account_id = $1 AND subscribed = FALSE
                    ORDER BY canonical_name ASC, id ASC
                    "#,
                )
                .bind(account_id)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, MailboxRow>(
                    r#"
                    SELECT
                        id,
                        account_id,
                        name,
                        canonical_name,
                        delimiter,
                        attributes,
                        subscribed,
                        special_use,
                        uidvalidity,
                        uidnext,
                        highestmodseq,
                        exists_count,
                        recent_count,
                        unseen_count,
                        created_at,
                        updated_at
                    FROM mailboxes
                    WHERE account_id = $1
                    ORDER BY canonical_name ASC, id ASC
                    "#,
                )
                .bind(account_id)
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn create_mailbox(&self, input: NewMailbox<'_>) -> Result<Option<Mailbox>> {
        let row = sqlx::query_as::<_, MailboxRow>(
            r#"
            INSERT INTO mailboxes (
                account_id,
                name,
                canonical_name,
                delimiter,
                attributes,
                subscribed,
                special_use,
                uidvalidity,
                uidnext,
                highestmodseq,
                exists_count,
                recent_count,
                unseen_count,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
            ON CONFLICT (account_id, canonical_name) DO NOTHING
            RETURNING
                id,
                account_id,
                name,
                canonical_name,
                delimiter,
                attributes,
                subscribed,
                special_use,
                uidvalidity,
                uidnext,
                highestmodseq,
                exists_count,
                recent_count,
                unseen_count,
                created_at,
                updated_at
            "#,
        )
        .bind(input.account_id)
        .bind(input.name)
        .bind(input.canonical_name)
        .bind(input.delimiter)
        .bind(input.attributes)
        .bind(input.subscribed)
        .bind(input.special_use)
        .bind(input.uidvalidity)
        .bind(input.uidnext)
        .bind(input.highestmodseq)
        .bind(input.exists_count)
        .bind(input.recent_count)
        .bind(input.unseen_count)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(ref row) = row {
            self.publish_event(MutationEvent::mailbox_changed(
                Some(row.account_id),
                Some(row.id),
                "create_mailbox",
            ))
            .await;
        }
        Ok(row.map(Into::into))
    }

    pub async fn delete_mailbox(&self, account_id: i64, mailbox_name: &str) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM mailboxes
            WHERE account_id = $1 AND (name = $2 OR canonical_name = $3)
            "#,
        )
        .bind(account_id)
        .bind(mailbox_name)
        .bind(mailbox_name.to_ascii_lowercase())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() > 0 {
            self.publish_event(MutationEvent::mailbox_changed(
                Some(account_id),
                None,
                format!("delete_mailbox:{mailbox_name}"),
            ))
            .await;
        }
        Ok(result.rows_affected())
    }

    pub async fn rename_mailbox(
        &self,
        account_id: i64,
        mailbox_name: &str,
        new_name: &str,
    ) -> Result<Option<Mailbox>> {
        let new_canonical_name = new_name.to_ascii_lowercase();
        if self.find_mailbox(account_id, new_name).await?.is_some() {
            return Ok(None);
        }
        let row = sqlx::query_as::<_, MailboxRow>(
            r#"
            UPDATE mailboxes
            SET name = $3, canonical_name = $4, updated_at = NOW()
            WHERE account_id = $1 AND (name = $2 OR canonical_name = $5)
            RETURNING
                id,
                account_id,
                name,
                canonical_name,
                delimiter,
                attributes,
                subscribed,
                special_use,
                uidvalidity,
                uidnext,
                highestmodseq,
                exists_count,
                recent_count,
                unseen_count,
                created_at,
                updated_at
            "#,
        )
        .bind(account_id)
        .bind(mailbox_name)
        .bind(new_name)
        .bind(&new_canonical_name)
        .bind(mailbox_name.to_ascii_lowercase())
        .fetch_optional(&self.pool)
        .await?;
        if let Some(ref row) = row {
            self.publish_event(MutationEvent::mailbox_changed(
                Some(row.account_id),
                Some(row.id),
                format!("rename_mailbox:{mailbox_name}->{new_name}"),
            ))
            .await;
        }
        Ok(row.map(Into::into))
    }

    pub async fn set_mailbox_subscribed(
        &self,
        account_id: i64,
        mailbox_name: &str,
        subscribed: bool,
    ) -> Result<Option<Mailbox>> {
        let row = sqlx::query_as::<_, MailboxRow>(
            r#"
            UPDATE mailboxes
            SET subscribed = $3, updated_at = NOW()
            WHERE account_id = $1 AND (name = $2 OR canonical_name = $4)
            RETURNING
                id,
                account_id,
                name,
                canonical_name,
                delimiter,
                attributes,
                subscribed,
                special_use,
                uidvalidity,
                uidnext,
                highestmodseq,
                exists_count,
                recent_count,
                unseen_count,
                created_at,
                updated_at
            "#,
        )
        .bind(account_id)
        .bind(mailbox_name)
        .bind(subscribed)
        .bind(mailbox_name.to_ascii_lowercase())
        .fetch_optional(&self.pool)
        .await?;
        if let Some(ref row) = row {
            self.publish_event(MutationEvent::mailbox_changed(
                Some(row.account_id),
                Some(row.id),
                format!("set_mailbox_subscribed:{subscribed}"),
            ))
            .await;
        }
        Ok(row.map(Into::into))
    }

    pub async fn list_accounts_for_user(&self, user_id: i64) -> Result<Vec<MailAccount>> {
        let rows = sqlx::query_as::<_, MailAccountRow>(
            r#"
            SELECT
                id,
                user_id,
                display_name,
                email_address,
                upstream_host,
                upstream_port,
                upstream_tls_mode,
                upstream_auth_method,
                encrypted_upstream_username,
                encrypted_upstream_secret,
                created_at,
                disabled_at,
                last_sync_at,
                last_sync_error
            FROM mail_accounts
            WHERE user_id = $1 AND disabled_at IS NULL
            ORDER BY id ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    pub async fn list_enabled_accounts(&self) -> Result<Vec<MailAccount>> {
        let rows = sqlx::query_as::<_, MailAccountRow>(
            r#"
            SELECT
                id,
                user_id,
                display_name,
                email_address,
                upstream_host,
                upstream_port,
                upstream_tls_mode,
                upstream_auth_method,
                encrypted_upstream_username,
                encrypted_upstream_secret,
                created_at,
                disabled_at,
                last_sync_at,
                last_sync_error
            FROM mail_accounts
            WHERE disabled_at IS NULL
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    pub async fn find_account_by_email_address(
        &self,
        email_address: &str,
    ) -> Result<Option<MailAccount>> {
        let row = sqlx::query_as::<_, MailAccountRow>(
            r#"
            SELECT
                id,
                user_id,
                display_name,
                email_address,
                upstream_host,
                upstream_port,
                upstream_tls_mode,
                upstream_auth_method,
                encrypted_upstream_username,
                encrypted_upstream_secret,
                created_at,
                disabled_at,
                last_sync_at,
                last_sync_error
            FROM mail_accounts
            WHERE lower(email_address) = lower($1) AND disabled_at IS NULL
            ORDER BY id DESC
            LIMIT 1
            "#,
        )
        .bind(email_address)
        .fetch_optional(&self.pool)
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn find_account_by_email_address_any_state(
        &self,
        email_address: &str,
    ) -> Result<Option<MailAccount>> {
        let row = sqlx::query_as::<_, MailAccountRow>(
            r#"
            SELECT
                id,
                user_id,
                display_name,
                email_address,
                upstream_host,
                upstream_port,
                upstream_tls_mode,
                upstream_auth_method,
                encrypted_upstream_username,
                encrypted_upstream_secret,
                created_at,
                disabled_at,
                last_sync_at,
                last_sync_error
            FROM mail_accounts
            WHERE lower(email_address) = lower($1)
            ORDER BY id DESC
            LIMIT 1
            "#,
        )
        .bind(email_address)
        .fetch_optional(&self.pool)
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn find_account_by_id_any_state(
        &self,
        account_id: i64,
    ) -> Result<Option<MailAccount>> {
        let row = sqlx::query_as::<_, MailAccountRow>(
            r#"
            SELECT
                id,
                user_id,
                display_name,
                email_address,
                upstream_host,
                upstream_port,
                upstream_tls_mode,
                upstream_auth_method,
                encrypted_upstream_username,
                encrypted_upstream_secret,
                created_at,
                disabled_at,
                last_sync_at,
                last_sync_error
            FROM mail_accounts
            WHERE id = $1
            LIMIT 1
            "#,
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    pub async fn upstream_account_config(
        &self,
        email_address: &str,
    ) -> Result<Option<UpstreamAccountConfig>> {
        let Some(account) = self
            .find_account_by_email_address_any_state(email_address)
            .await?
        else {
            return Ok(None);
        };
        self.upstream_account_config_from_account(&account).await
    }

    pub async fn upstream_account_config_by_id(
        &self,
        account_id: i64,
    ) -> Result<Option<UpstreamAccountConfig>> {
        let Some(account) = self.find_account_by_id_any_state(account_id).await? else {
            return Ok(None);
        };
        self.upstream_account_config_from_account(&account).await
    }

    async fn upstream_account_config_from_account(
        &self,
        account: &MailAccount,
    ) -> Result<Option<UpstreamAccountConfig>> {
        let username = self
            .secrets
            .decrypt(&account.encrypted_upstream_username)
            .map_err(|e| Error::Storage(format!("failed to decrypt upstream username: {e}")))?;
        let secret = self
            .secrets
            .decrypt(&account.encrypted_upstream_secret)
            .map_err(|e| Error::Storage(format!("failed to decrypt upstream secret: {e}")))?;
        Ok(Some(UpstreamAccountConfig {
            host: account.upstream_host.clone(),
            port: account.upstream_port as u16,
            tls_mode: account.upstream_tls_mode,
            auth_method: account.upstream_auth_method,
            username: String::from_utf8(username).map_err(|e| {
                Error::Storage(format!("upstream username is not valid UTF-8: {e}"))
            })?,
            secret: String::from_utf8(secret)
                .map_err(|e| Error::Storage(format!("upstream secret is not valid UTF-8: {e}")))?,
        }))
    }

    pub async fn upsert_message(&self, input: NewMessage<'_>) -> Result<Message> {
        let row = sqlx::query_as::<_, MessageRow>(
            r#"
            INSERT INTO messages (
                account_id,
                rfc822_blob_key,
                rfc822_sha256,
                message_id_header,
                subject,
                from_json,
                to_json,
                cc_json,
                bcc_json,
                reply_to_json,
                envelope_json,
                bodystructure_json,
                internal_date,
                sent_date,
                size_octets,
                text_preview
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
            RETURNING
                id, account_id, rfc822_blob_key, rfc822_sha256, message_id_header, subject,
                from_json, to_json, cc_json, bcc_json, reply_to_json, envelope_json, bodystructure_json,
                internal_date, sent_date, size_octets, text_preview, created_at
            "#,
        )
        .bind(input.account_id)
        .bind(input.rfc822_blob_key)
        .bind(input.rfc822_sha256)
        .bind(input.message_id_header)
        .bind(input.subject)
        .bind(input.from_json)
        .bind(input.to_json)
        .bind(input.cc_json)
        .bind(input.bcc_json)
        .bind(input.reply_to_json)
        .bind(input.envelope_json)
        .bind(input.bodystructure_json)
        .bind(input.internal_date)
        .bind(input.sent_date)
        .bind(input.size_octets)
        .bind(input.text_preview)
        .fetch_one(&self.pool)
        .await?;
        self.publish_event(MutationEvent::message_changed(
            Some(row.account_id),
            None,
            Some(row.id),
            "upsert_message",
        ))
        .await;
        Ok(row.into())
    }

    pub async fn insert_mime_part(&self, input: NewMimePart<'_>) -> Result<MimePart> {
        let row = sqlx::query_as::<_, MimePartRow>(
            r#"
            INSERT INTO mime_parts (
                message_id,
                part_path,
                content_type,
                charset,
                disposition,
                filename,
                content_id,
                size_octets,
                blob_key,
                sha256,
                transfer_encoding,
                metadata_json
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            RETURNING
                id,
                message_id,
                part_path,
                content_type,
                charset,
                disposition,
                filename,
                content_id,
                size_octets,
                blob_key,
                sha256,
                transfer_encoding,
                metadata_json
            "#,
        )
        .bind(input.message_id)
        .bind(input.part_path)
        .bind(input.content_type)
        .bind(input.charset)
        .bind(input.disposition)
        .bind(input.filename)
        .bind(input.content_id)
        .bind(input.size_octets)
        .bind(input.blob_key)
        .bind(input.sha256)
        .bind(input.transfer_encoding)
        .bind(input.metadata_json)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    pub async fn delete_mime_parts_for_message(&self, message_id: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM mime_parts
            WHERE message_id = $1
            "#,
        )
        .bind(message_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn list_message_cache_objects(
        &self,
        account_id: i64,
        message_id: i64,
    ) -> Result<Vec<CacheObjectReference>> {
        let rows = sqlx::query_as::<_, CacheObjectReferenceRow>(
            r#"
            SELECT
                'rfc822' AS object_type,
                m.rfc822_blob_key AS blob_key,
                m.rfc822_sha256 AS sha256,
                m.size_octets AS size_octets
            FROM messages m
            WHERE m.account_id = $1
              AND m.id = $2
            UNION ALL
            SELECT
                CASE
                    WHEN COALESCE(mp.disposition, '') = 'attachment' OR mp.filename IS NOT NULL
                        THEN 'Attachment'
                    ELSE 'MimePart'
                END AS object_type,
                mp.blob_key,
                mp.sha256,
                mp.size_octets
            FROM mime_parts mp
            JOIN messages m ON m.id = mp.message_id
            WHERE m.account_id = $1
              AND mp.message_id = $2
            ORDER BY object_type ASC, blob_key ASC
            "#,
        )
        .bind(account_id)
        .bind(message_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn find_mime_part_by_message_and_path(
        &self,
        account_id: i64,
        message_id: i64,
        part_path: &str,
    ) -> Result<Option<MimePart>> {
        let row = sqlx::query_as::<_, MimePartRow>(
            r#"
            SELECT
                mp.id,
                mp.message_id,
                mp.part_path,
                mp.content_type,
                mp.charset,
                mp.disposition,
                mp.filename,
                mp.content_id,
                mp.size_octets,
                mp.blob_key,
                mp.sha256,
                mp.transfer_encoding,
                mp.metadata_json
            FROM mime_parts mp
            JOIN messages m ON m.id = mp.message_id
            WHERE m.account_id = $1
              AND mp.message_id = $2
              AND mp.part_path = $3
            LIMIT 1
            "#,
        )
        .bind(account_id)
        .bind(message_id)
        .bind(part_path)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn upsert_mailbox_message(&self, input: NewMailboxMessage) -> Result<MailboxMessage> {
        let mut tx = self.pool.begin().await?;
        let local_uid = if input.local_uid == 0 {
            self.assign_mailbox_local_uid(&mut tx, input.mailbox_id)
                .await?
        } else {
            input.local_uid
        };
        let modseq = self
            .assign_mailbox_modseq(&mut tx, input.mailbox_id, input.modseq)
            .await?;
        let row = sqlx::query_as::<_, MailboxMessageRow>(
            r#"
            INSERT INTO mailbox_messages (
                mailbox_id,
                message_id,
                local_uid,
                upstream_uid,
                modseq,
                flags,
                keywords,
                is_expunged,
                expunged_at,
                updated_at
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
            ON CONFLICT (mailbox_id, local_uid) DO UPDATE
            SET
                message_id = EXCLUDED.message_id,
                upstream_uid = EXCLUDED.upstream_uid,
                modseq = EXCLUDED.modseq,
                flags = EXCLUDED.flags,
                keywords = EXCLUDED.keywords,
                is_expunged = EXCLUDED.is_expunged,
                expunged_at = EXCLUDED.expunged_at,
                updated_at = NOW()
            RETURNING
                id,
                mailbox_id,
                message_id,
                local_uid,
                upstream_uid,
                modseq,
                flags,
                keywords,
                is_expunged,
                expunged_at,
                created_at,
                updated_at
            "#,
        )
        .bind(input.mailbox_id)
        .bind(input.message_id)
        .bind(local_uid)
        .bind(input.upstream_uid)
        .bind(Some(modseq))
        .bind(input.flags)
        .bind(input.keywords)
        .bind(input.is_expunged)
        .bind(input.expunged_at)
        .fetch_one(&mut *tx)
        .await?;
        let sequence_number = self
            .mailbox_sequence_number_in_tx(&mut tx, row.mailbox_id, row.local_uid)
            .await?;
        tx.commit().await?;
        let account_id = self.account_id_for_mailbox(row.mailbox_id).await?;
        if let Some(upstream_uid) = row.upstream_uid {
            let uidvalidity = self.mailbox_uidvalidity(row.mailbox_id).await?;
            self.upsert_uid_mapping(row.mailbox_id, row.local_uid, upstream_uid, uidvalidity)
                .await?;
        }
        self.publish_event(MutationEvent::message_changed_with_context(
            account_id,
            Some(row.mailbox_id),
            Some(row.message_id),
            Some(row.local_uid),
            Some(sequence_number),
            row.flags.clone(),
            "upsert_mailbox_message",
        ))
        .await;
        Ok(row.into())
    }

    pub async fn set_mailbox_message_upstream_uid(
        &self,
        mailbox_id: i64,
        local_uid: i64,
        upstream_uid: i64,
    ) -> Result<Option<MailboxMessage>> {
        let row = sqlx::query_as::<_, MailboxMessageRow>(
            r#"
            UPDATE mailbox_messages
            SET upstream_uid = $3, updated_at = NOW()
            WHERE mailbox_id = $1 AND local_uid = $2 AND is_expunged = FALSE
            RETURNING
                id,
                mailbox_id,
                message_id,
                local_uid,
                upstream_uid,
                modseq,
                flags,
                keywords,
                is_expunged,
                expunged_at,
                created_at,
                updated_at
            "#,
        )
        .bind(mailbox_id)
        .bind(local_uid)
        .bind(upstream_uid)
        .fetch_optional(&self.pool)
        .await?;
        if row.is_some() {
            let uidvalidity = self.mailbox_uidvalidity(mailbox_id).await?;
            self.upsert_uid_mapping(mailbox_id, local_uid, upstream_uid, uidvalidity)
                .await?;
        }
        Ok(row.map(Into::into))
    }

    pub async fn upstream_uid_for_mailbox_message(
        &self,
        mailbox_id: i64,
        local_uid: i64,
    ) -> Result<Option<i64>> {
        let mailbox_uidvalidity = self.mailbox_uidvalidity(mailbox_id).await?;
        let upstream_uid = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT upstream_uid
            FROM mailbox_messages
            WHERE mailbox_id = $1 AND local_uid = $2 AND is_expunged = FALSE
            LIMIT 1
            "#,
        )
        .bind(mailbox_id)
        .bind(local_uid)
        .fetch_optional(&self.pool)
        .await?;
        if upstream_uid.is_some() {
            return Ok(upstream_uid);
        }
        let upstream_uid = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT upstream_uid
            FROM uid_mappings
            WHERE mailbox_id = $1 AND local_uid = $2
              AND upstream_uidvalidity = $3
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(mailbox_id)
        .bind(local_uid)
        .bind(mailbox_uidvalidity)
        .fetch_optional(&self.pool)
        .await?;
        Ok(upstream_uid)
    }

    pub async fn upsert_uid_mapping(
        &self,
        mailbox_id: i64,
        local_uid: i64,
        upstream_uid: i64,
        upstream_uidvalidity: i64,
    ) -> Result<()> {
        let _ = sqlx::query(
            r#"
            INSERT INTO uid_mappings (
                mailbox_id,
                local_uid,
                upstream_uid,
                upstream_uidvalidity
            )
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (mailbox_id, local_uid) DO UPDATE
            SET
                upstream_uid = EXCLUDED.upstream_uid,
                upstream_uidvalidity = EXCLUDED.upstream_uidvalidity
            "#,
        )
        .bind(mailbox_id)
        .bind(local_uid)
        .bind(upstream_uid)
        .bind(upstream_uidvalidity)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mailbox_uidvalidity(&self, mailbox_id: i64) -> Result<i64> {
        let uidvalidity = sqlx::query_scalar::<_, Option<i64>>(
            r#"
            SELECT uidvalidity
            FROM mailboxes
            WHERE id = $1
            "#,
        )
        .bind(mailbox_id)
        .fetch_optional(&self.pool)
        .await?
        .flatten()
        .unwrap_or(1);
        Ok(uidvalidity)
    }

    pub async fn list_mailbox_messages(&self, mailbox_id: i64) -> Result<Vec<MailboxMessage>> {
        let rows = sqlx::query_as::<_, MailboxMessageRow>(
            r#"
            SELECT
                id,
                mailbox_id,
                message_id,
                local_uid,
                upstream_uid,
                modseq,
                flags,
                keywords,
                is_expunged,
                expunged_at,
                created_at,
                updated_at
            FROM mailbox_messages
            WHERE mailbox_id = $1 AND is_expunged = FALSE
            ORDER BY local_uid ASC
            "#,
        )
        .bind(mailbox_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn list_mailbox_message_views(
        &self,
        mailbox_id: i64,
    ) -> Result<Vec<MailboxMessageView>> {
        let rows = sqlx::query_as::<_, MailboxMessageViewRow>(
            r#"
            SELECT
                mm.id,
                mm.mailbox_id,
                mm.message_id,
                mm.local_uid,
                mm.upstream_uid,
                mm.modseq,
                mm.flags,
                mm.keywords,
                mm.is_expunged,
                mm.expunged_at,
                mm.created_at,
                mm.updated_at,
                m.rfc822_blob_key,
                m.rfc822_sha256,
                m.message_id_header,
                m.subject,
                m.envelope_json,
                m.bodystructure_json,
                m.internal_date,
                m.sent_date,
                m.size_octets,
                m.text_preview
            FROM mailbox_messages mm
            JOIN messages m ON m.id = mm.message_id
            WHERE mm.mailbox_id = $1 AND mm.is_expunged = FALSE
            ORDER BY mm.local_uid ASC
            "#,
        )
        .bind(mailbox_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn find_mailbox_message_view(
        &self,
        mailbox_id: i64,
        local_uid: i64,
    ) -> Result<Option<MailboxMessageView>> {
        let row = sqlx::query_as::<_, MailboxMessageViewRow>(
            r#"
            SELECT
                mm.id,
                mm.mailbox_id,
                mm.message_id,
                mm.local_uid,
                mm.upstream_uid,
                mm.modseq,
                mm.flags,
                mm.keywords,
                mm.is_expunged,
                mm.expunged_at,
                mm.created_at,
                mm.updated_at,
                m.rfc822_blob_key,
                m.rfc822_sha256,
                m.message_id_header,
                m.subject,
                m.envelope_json,
                m.bodystructure_json,
                m.internal_date,
                m.sent_date,
                m.size_octets,
                m.text_preview
            FROM mailbox_messages mm
            JOIN messages m ON m.id = mm.message_id
            WHERE mm.mailbox_id = $1 AND mm.local_uid = $2 AND mm.is_expunged = FALSE
            LIMIT 1
            "#,
        )
        .bind(mailbox_id)
        .bind(local_uid)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn update_mailbox_message_flags(
        &self,
        mailbox_id: i64,
        local_uid: i64,
        flags: Vec<String>,
    ) -> Result<Option<MailboxMessage>> {
        let mut tx = self.pool.begin().await?;
        let modseq = self.assign_mailbox_modseq(&mut tx, mailbox_id, None).await?;
        let row = sqlx::query_as::<_, MailboxMessageRow>(
            r#"
            UPDATE mailbox_messages
            SET flags = $3, modseq = $4, updated_at = NOW()
            WHERE mailbox_id = $1 AND local_uid = $2 AND is_expunged = FALSE
            RETURNING
                id,
                mailbox_id,
                message_id,
                local_uid,
                upstream_uid,
                modseq,
                flags,
                keywords,
                is_expunged,
                expunged_at,
                created_at,
                updated_at
            "#,
        )
        .bind(mailbox_id)
        .bind(local_uid)
        .bind(flags)
        .bind(modseq)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(ref row) = row {
            let sequence_number = self
                .mailbox_sequence_number_in_tx(&mut tx, row.mailbox_id, row.local_uid)
                .await?;
            tx.commit().await?;
            let account_id = self.account_id_for_mailbox(row.mailbox_id).await?;
            self.publish_event(MutationEvent::message_changed_with_context(
                account_id,
                Some(row.mailbox_id),
                Some(row.message_id),
                Some(row.local_uid),
                Some(sequence_number),
                row.flags.clone(),
                "update_mailbox_message_flags",
            ))
            .await;
        } else {
            tx.commit().await?;
        }
        Ok(row.map(Into::into))
    }

    pub async fn next_mailbox_local_uid(&self, mailbox_id: i64) -> Result<i64> {
        let next_uid = sqlx::query_scalar::<_, Option<i64>>(
            r#"
            SELECT MAX(local_uid) + 1
            FROM mailbox_messages
            WHERE mailbox_id = $1 AND is_expunged = FALSE
            "#,
        )
        .bind(mailbox_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(next_uid.unwrap_or(1))
    }

    pub async fn copy_mailbox_message(
        &self,
        source_mailbox_id: i64,
        destination_mailbox_id: i64,
        source_local_uid: i64,
    ) -> Result<Option<MailboxMessage>> {
        let mut tx = self.pool.begin().await?;
        let source = sqlx::query_as::<_, MailboxMessageRow>(
            r#"
            SELECT
                id,
                mailbox_id,
                message_id,
                local_uid,
                upstream_uid,
                modseq,
                flags,
                keywords,
                is_expunged,
                expunged_at,
                created_at,
                updated_at
            FROM mailbox_messages
            WHERE mailbox_id = $1 AND local_uid = $2 AND is_expunged = FALSE
            "#,
        )
        .bind(source_mailbox_id)
        .bind(source_local_uid)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(source) = source else {
            tx.commit().await?;
            return Ok(None);
        };

        let next_uid = self
            .assign_mailbox_local_uid(&mut tx, destination_mailbox_id)
            .await?;
        let modseq = self
            .assign_mailbox_modseq(&mut tx, destination_mailbox_id, None)
            .await?;
        let row = sqlx::query_as::<_, MailboxMessageRow>(
            r#"
            INSERT INTO mailbox_messages (
                mailbox_id,
                message_id,
                local_uid,
                upstream_uid,
                modseq,
                flags,
                keywords,
                is_expunged,
                expunged_at,
                updated_at
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,FALSE,NULL,NOW())
            RETURNING
                id,
                mailbox_id,
                message_id,
                local_uid,
                upstream_uid,
                modseq,
                flags,
                keywords,
                is_expunged,
                expunged_at,
                created_at,
                updated_at
            "#,
        )
        .bind(destination_mailbox_id)
        .bind(source.message_id)
        .bind(next_uid)
        .bind(None::<i64>)
        .bind(Some(modseq))
        .bind(source.flags)
        .bind(source.keywords)
        .fetch_one(&mut *tx)
        .await?;
        let sequence_number = self
            .mailbox_sequence_number_in_tx(&mut tx, row.mailbox_id, row.local_uid)
            .await?;
        tx.commit().await?;
        let Some(account_id) = self.account_id_for_mailbox(destination_mailbox_id).await? else {
            return Err(Error::Storage(format!(
                "mailbox not found for cache refcount update: {}",
                destination_mailbox_id
            )));
        };
        for object in self
            .list_message_cache_objects(account_id, source.message_id)
            .await?
        {
            let _ = self
                .upsert_cache_object(NewCacheObject {
                    account_id: Some(account_id),
                    object_type: &object.object_type,
                    blob_key: &object.blob_key,
                    sha256: &object.sha256,
                    size_octets: object.size_octets,
                    ref_count: 1,
                    last_accessed_at: Some(Utc::now()),
                })
                .await?;
        }
        self.publish_event(MutationEvent::message_changed_with_context(
            Some(account_id),
            Some(destination_mailbox_id),
            Some(row.message_id),
            Some(row.local_uid),
            Some(sequence_number),
            row.flags.clone(),
            "copy_mailbox_message",
        ))
        .await;
        Ok(Some(row.into()))
    }

    pub async fn delete_mailbox_message(&self, mailbox_id: i64, local_uid: i64) -> Result<u64> {
        let mut tx = self.pool.begin().await?;
        let target_exists = sqlx::query_as::<_, (i64, i64)>(
            r#"
            SELECT id, message_id
            FROM mailbox_messages
            WHERE mailbox_id = $1 AND local_uid = $2 AND is_expunged = FALSE
            FOR UPDATE
            "#,
        )
        .bind(mailbox_id)
        .bind(local_uid)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((_, message_id)) = target_exists else {
            tx.commit().await?;
            return Ok(0);
        };

        let sequence_number = self
            .mailbox_sequence_number_in_tx(&mut tx, mailbox_id, local_uid)
            .await?;
        let _ = self.assign_mailbox_modseq(&mut tx, mailbox_id, None).await?;
        let result = sqlx::query(
            r#"
            DELETE FROM mailbox_messages
            WHERE mailbox_id = $1 AND local_uid = $2 AND is_expunged = FALSE
            "#,
        )
        .bind(mailbox_id)
        .bind(local_uid)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        if result.rows_affected() > 0 {
        let Some(account_id) = self.account_id_for_mailbox(mailbox_id).await? else {
            return Err(Error::Storage(format!(
                "mailbox not found for cache refcount update: {}",
                mailbox_id
            )));
        };
            for object in self
                .list_message_cache_objects(account_id, message_id)
                .await?
            {
                let _ = self
                    .delete_cache_object_for_account(account_id, &object.blob_key)
                    .await?;
            }
            self.publish_event(MutationEvent::message_changed_with_context(
                Some(account_id),
                Some(mailbox_id),
                None,
                Some(local_uid),
                Some(sequence_number),
                Vec::new(),
                format!("delete_mailbox_message:{local_uid}"),
            ))
            .await;
        }
        Ok(result.rows_affected())
    }

    pub async fn refresh_mailbox_counts(&self, mailbox_id: i64) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE mailboxes
            SET
                exists_count = (
                    SELECT COUNT(*)
                    FROM mailbox_messages
                    WHERE mailbox_id = $1 AND is_expunged = FALSE
                ),
                unseen_count = (
                    SELECT COUNT(*)
                    FROM mailbox_messages
                    WHERE mailbox_id = $1
                      AND is_expunged = FALSE
                      AND NOT ('\\Seen' = ANY(flags))
                ),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(mailbox_id)
        .execute(&self.pool)
        .await?;
        self.publish_event(MutationEvent::mailbox_changed(
            self.account_id_for_mailbox(mailbox_id).await?,
            Some(mailbox_id),
            "refresh_mailbox_counts",
        ))
        .await;
        Ok(())
    }

    pub async fn upsert_cache_object(&self, input: NewCacheObject<'_>) -> Result<CacheObject> {
        let row = sqlx::query_as::<_, CacheObjectRow>(
            r#"
            INSERT INTO cache_objects (
                account_id,
                object_type,
                blob_key,
                sha256,
                size_octets,
                ref_count,
                last_accessed_at
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            ON CONFLICT (account_id, object_type, blob_key) DO UPDATE
            SET
                account_id = EXCLUDED.account_id,
                sha256 = EXCLUDED.sha256,
                size_octets = EXCLUDED.size_octets,
                ref_count = cache_objects.ref_count + EXCLUDED.ref_count,
                last_accessed_at = GREATEST(
                    COALESCE(EXCLUDED.last_accessed_at, cache_objects.last_accessed_at),
                    cache_objects.last_accessed_at
                )
            RETURNING
                id,
                account_id,
                object_type,
                blob_key,
                sha256,
                size_octets,
                ref_count,
                last_accessed_at,
                created_at
            "#,
        )
        .bind(input.account_id)
        .bind(input.object_type)
        .bind(input.blob_key)
        .bind(input.sha256)
        .bind(input.size_octets)
        .bind(input.ref_count)
        .bind(input.last_accessed_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    pub async fn list_cache_objects_for_account(
        &self,
        account_id: i64,
    ) -> Result<Vec<CacheObject>> {
        let rows = sqlx::query_as::<_, CacheObjectRow>(
            r#"
            SELECT
                id,
                account_id,
                object_type,
                blob_key,
                sha256,
                size_octets,
                ref_count,
                last_accessed_at,
                created_at
            FROM cache_objects
            WHERE account_id = $1
            ORDER BY id ASC
            "#,
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn find_cache_object_by_account_type_and_blob_key(
        &self,
        account_id: i64,
        object_type: &str,
        blob_key: &str,
    ) -> Result<Option<CacheObject>> {
        let row = sqlx::query_as::<_, CacheObjectRow>(
            r#"
            SELECT
                id,
                account_id,
                object_type,
                blob_key,
                sha256,
                size_octets,
                ref_count,
                last_accessed_at,
                created_at
            FROM cache_objects
            WHERE account_id = $1
              AND object_type = $2
              AND blob_key = $3
            LIMIT 1
            "#,
        )
        .bind(account_id)
        .bind(object_type)
        .bind(blob_key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn list_cache_objects_for_account_by_recency(
        &self,
        account_id: i64,
    ) -> Result<Vec<CacheObject>> {
        let rows = sqlx::query_as::<_, CacheObjectRow>(
            r#"
            SELECT
                id,
                account_id,
                object_type,
                blob_key,
                sha256,
                size_octets,
                ref_count,
                last_accessed_at,
                created_at
            FROM cache_objects
            WHERE account_id = $1
            ORDER BY COALESCE(last_accessed_at, created_at) ASC, id ASC
            "#,
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn touch_cache_object(&self, account_id: i64, blob_key: &str) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE cache_objects
            SET last_accessed_at = NOW()
            WHERE account_id = $1
              AND blob_key = $2
            "#,
        )
        .bind(account_id)
        .bind(blob_key)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn delete_cache_object_for_account(
        &self,
        account_id: i64,
        blob_key: &str,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let Some(row) = sqlx::query_as::<_, CacheObjectRow>(
            r#"
            SELECT
                id,
                account_id,
                object_type,
                blob_key,
                sha256,
                size_octets,
                ref_count,
                last_accessed_at,
                created_at
            FROM cache_objects
            WHERE account_id = $1
              AND blob_key = $2
            FOR UPDATE
            "#,
        )
        .bind(account_id)
        .bind(blob_key)
        .fetch_optional(&mut *tx)
        .await?
        else {
            tx.commit().await?;
            return Ok(false);
        };

        if row.ref_count > 1 {
            sqlx::query(
                r#"
                UPDATE cache_objects
                SET
                    ref_count = ref_count - 1,
                    last_accessed_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(row.id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(false);
        }

        let elsewhere = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT
                (
                    SELECT COUNT(*)
                    FROM messages
                    WHERE rfc822_blob_key = $1
                      AND account_id <> $2
                )
                +
                (
                    SELECT COUNT(*)
                    FROM mime_parts mp
                    JOIN messages m ON m.id = mp.message_id
                    WHERE mp.blob_key = $1
                      AND m.account_id <> $2
                )
            "#,
        )
        .bind(blob_key)
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            DELETE FROM cache_objects
            WHERE id = $1
            "#,
        )
        .bind(row.id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(elsewhere == 0)
    }

    pub async fn list_object_keys_for_account(&self, account_id: i64) -> Result<Vec<String>> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT blob_key
            FROM (
                SELECT blob_key
                FROM cache_objects
                WHERE account_id = $1
                UNION ALL
                SELECT m.rfc822_blob_key AS blob_key
                FROM messages m
                WHERE m.account_id = $1
                UNION ALL
                SELECT mp.blob_key
                FROM mime_parts mp
                JOIN messages m ON m.id = mp.message_id
                WHERE m.account_id = $1
            ) AS keys
            ORDER BY blob_key ASC
            "#,
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn count_blob_key_references_elsewhere(
        &self,
        blob_key: &str,
        account_id: i64,
    ) -> Result<i64> {
        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT
                (
                    SELECT COUNT(*)
                    FROM messages
                    WHERE rfc822_blob_key = $1
                      AND account_id <> $2
                )
                +
                (
                    SELECT COUNT(*)
                    FROM mime_parts mp
                    JOIN messages m ON m.id = mp.message_id
                    WHERE mp.blob_key = $1
                      AND m.account_id <> $2
                )
            "#,
        )
        .bind(blob_key)
        .bind(account_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    pub async fn delete_cache_objects_for_account(&self, account_id: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM cache_objects
            WHERE account_id = $1
            "#,
        )
        .bind(account_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn put_sync_state(&self, input: NewSyncState<'_>) -> Result<SyncState> {
        let row = sqlx::query_as::<_, SyncStateRow>(
            r#"
            INSERT INTO sync_state (
                account_id,
                mailbox_id,
                state_json,
                last_success_at,
                last_attempt_at,
                last_error
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (account_id, mailbox_id) DO UPDATE
            SET
                state_json = EXCLUDED.state_json,
                last_success_at = EXCLUDED.last_success_at,
                last_attempt_at = EXCLUDED.last_attempt_at,
                last_error = EXCLUDED.last_error
            RETURNING id, account_id, mailbox_id, state_json, last_success_at, last_attempt_at, last_error
            "#,
        )
        .bind(input.account_id)
        .bind(input.mailbox_id)
        .bind(input.state_json)
        .bind(input.last_success_at)
        .bind(input.last_attempt_at)
        .bind(input.last_error)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    pub async fn load_sync_state(
        &self,
        account_id: i64,
        mailbox_id: Option<i64>,
    ) -> Result<Option<SyncState>> {
        let row = sqlx::query_as::<_, SyncStateRow>(
            r#"
            SELECT id, account_id, mailbox_id, state_json, last_success_at, last_attempt_at, last_error
            FROM sync_state
            WHERE account_id = $1 AND mailbox_id IS NOT DISTINCT FROM $2
            ORDER BY id DESC
            LIMIT 1
            "#,
        )
        .bind(account_id)
        .bind(mailbox_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn delete_sync_state(&self, account_id: i64, mailbox_id: Option<i64>) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM sync_state
            WHERE account_id = $1 AND mailbox_id IS NOT DISTINCT FROM $2
            "#,
        )
        .bind(account_id)
        .bind(mailbox_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn enqueue_mutation(&self, input: NewPendingMutation<'_>) -> Result<PendingMutation> {
        let row = sqlx::query_as::<_, PendingMutationRow>(
            r#"
            INSERT INTO pending_mutations (
                account_id,
                mailbox_id,
                message_id,
                mutation_type,
                payload_json,
                status,
                attempts,
                next_attempt_at,
                idempotency_key
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            RETURNING
                id, account_id, mailbox_id, message_id, mutation_type, payload_json,
                status, attempts, next_attempt_at, idempotency_key, created_at, updated_at
            "#,
        )
        .bind(input.account_id)
        .bind(input.mailbox_id)
        .bind(input.message_id)
        .bind(input.mutation_type)
        .bind(input.payload_json)
        .bind(input.status.to_string())
        .bind(input.attempts)
        .bind(input.next_attempt_at)
        .bind(input.idempotency_key)
        .fetch_one(&self.pool)
        .await?;
        self.publish_event(MutationEvent::pending_mutation_changed(
            Some(row.account_id),
            Some(row.mailbox_id),
            Some(row.id),
            "enqueue_mutation",
        ))
        .await;
        row.try_into()
    }

    pub async fn list_pending_mutations(
        &self,
        account_id: i64,
        status: MutationStatus,
    ) -> Result<Vec<PendingMutation>> {
        let rows = sqlx::query_as::<_, PendingMutationRow>(
            r#"
            SELECT
                id, account_id, mailbox_id, message_id, mutation_type, payload_json,
                status, attempts, next_attempt_at, idempotency_key, created_at, updated_at
            FROM pending_mutations
            WHERE account_id = $1 AND status = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(account_id)
        .bind(status.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    pub async fn list_due_pending_mutations(
        &self,
        account_id: i64,
    ) -> Result<Vec<PendingMutation>> {
        let rows = sqlx::query_as::<_, PendingMutationRow>(
            r#"
            SELECT
                id, account_id, mailbox_id, message_id, mutation_type, payload_json,
                status, attempts, next_attempt_at, idempotency_key, created_at, updated_at
            FROM pending_mutations
            WHERE account_id = $1
              AND status IN ('pending', 'failed')
              AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
            ORDER BY created_at ASC
            "#,
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    pub async fn count_pending_mutations(&self) -> Result<i64> {
        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM pending_mutations
            WHERE status = 'pending'
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    pub async fn update_pending_mutation(
        &self,
        id: i64,
        status: MutationStatus,
        attempts: i32,
        next_attempt_at: Option<DateTime<Utc>>,
    ) -> Result<PendingMutation> {
        let row = sqlx::query_as::<_, PendingMutationRow>(
            r#"
            UPDATE pending_mutations
            SET status = $2, attempts = $3, next_attempt_at = $4, updated_at = NOW()
            WHERE id = $1
            RETURNING
                id, account_id, mailbox_id, message_id, mutation_type, payload_json,
                status, attempts, next_attempt_at, idempotency_key, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(status.to_string())
        .bind(attempts)
        .bind(next_attempt_at)
        .fetch_one(&self.pool)
        .await?;
        self.publish_event(MutationEvent::pending_mutation_changed(
            Some(row.account_id),
            Some(row.mailbox_id),
            Some(row.id),
            format!("update_pending_mutation:{status}"),
        ))
        .await;
        row.try_into()
    }
}

#[derive(Debug, Clone)]
pub struct NewMailAccount<'a> {
    pub user_id: i64,
    pub display_name: &'a str,
    pub email_address: &'a str,
    pub upstream_host: &'a str,
    pub upstream_port: i32,
    pub upstream_tls_mode: UpstreamTlsMode,
    pub upstream_auth_method: UpstreamAuthMethod,
    pub upstream_username: &'a str,
    pub upstream_secret: &'a str,
}

#[derive(Debug, Clone)]
pub struct NewUser<'a> {
    pub username_email: &'a str,
    pub password_hash: &'a str,
}

#[derive(Debug, Clone)]
pub struct NewMailbox<'a> {
    pub account_id: i64,
    pub name: &'a str,
    pub canonical_name: &'a str,
    pub delimiter: Option<&'a str>,
    pub attributes: Vec<String>,
    pub subscribed: bool,
    pub special_use: Option<&'a str>,
    pub uidvalidity: Option<i64>,
    pub uidnext: Option<i64>,
    pub highestmodseq: Option<i64>,
    pub exists_count: i64,
    pub recent_count: i64,
    pub unseen_count: i64,
}

#[derive(Debug, Clone)]
pub struct NewMessage<'a> {
    pub account_id: i64,
    pub rfc822_blob_key: &'a str,
    pub rfc822_sha256: &'a str,
    pub message_id_header: Option<&'a str>,
    pub subject: Option<&'a str>,
    pub from_json: Value,
    pub to_json: Value,
    pub cc_json: Value,
    pub bcc_json: Value,
    pub reply_to_json: Value,
    pub envelope_json: Value,
    pub bodystructure_json: Value,
    pub internal_date: Option<DateTime<Utc>>,
    pub sent_date: Option<DateTime<Utc>>,
    pub size_octets: i64,
    pub text_preview: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct NewMimePart<'a> {
    pub message_id: i64,
    pub part_path: &'a str,
    pub content_type: &'a str,
    pub charset: Option<&'a str>,
    pub disposition: Option<&'a str>,
    pub filename: Option<&'a str>,
    pub content_id: Option<&'a str>,
    pub size_octets: i64,
    pub blob_key: &'a str,
    pub sha256: &'a str,
    pub transfer_encoding: Option<&'a str>,
    pub metadata_json: Value,
}

#[derive(Debug, Clone)]
pub struct NewMailboxMessage {
    pub mailbox_id: i64,
    pub message_id: i64,
    pub local_uid: i64,
    pub upstream_uid: Option<i64>,
    pub modseq: Option<i64>,
    pub flags: Vec<String>,
    pub keywords: Vec<String>,
    pub is_expunged: bool,
    pub expunged_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct NewCacheObject<'a> {
    pub account_id: Option<i64>,
    pub object_type: &'a str,
    pub blob_key: &'a str,
    pub sha256: &'a str,
    pub size_octets: i64,
    pub ref_count: i64,
    pub last_accessed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct CacheObjectReference {
    pub object_type: String,
    pub blob_key: String,
    pub sha256: String,
    pub size_octets: i64,
}

#[derive(Debug, Clone)]
pub struct NewSyncState<'a> {
    pub account_id: i64,
    pub mailbox_id: Option<i64>,
    pub state_json: Value,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub last_error: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct NewPendingMutation<'a> {
    pub account_id: i64,
    pub mailbox_id: i64,
    pub message_id: Option<i64>,
    pub mutation_type: &'a str,
    pub payload_json: Value,
    pub status: MutationStatus,
    pub attempts: i32,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub idempotency_key: &'a str,
}

#[derive(Debug, Clone)]
pub struct NewSession<'a> {
    pub user_id: i64,
    pub account_id: Option<i64>,
    pub connection_id: &'a str,
    pub remote_addr: Option<&'a str>,
}

#[derive(Debug, FromRow)]
struct UserRow {
    id: i64,
    username_email: String,
    password_hash: String,
    created_at: DateTime<Utc>,
    disabled_at: Option<DateTime<Utc>>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        Self {
            id: row.id,
            username_email: row.username_email,
            password_hash: row.password_hash,
            created_at: row.created_at,
            disabled_at: row.disabled_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct MailAccountRow {
    id: i64,
    user_id: i64,
    display_name: String,
    email_address: String,
    upstream_host: String,
    upstream_port: i32,
    upstream_tls_mode: String,
    upstream_auth_method: String,
    encrypted_upstream_username: Vec<u8>,
    encrypted_upstream_secret: Vec<u8>,
    created_at: DateTime<Utc>,
    disabled_at: Option<DateTime<Utc>>,
    last_sync_at: Option<DateTime<Utc>>,
    last_sync_error: Option<String>,
}

impl TryFrom<MailAccountRow> for MailAccount {
    type Error = Error;

    fn try_from(row: MailAccountRow) -> Result<Self> {
        Ok(Self {
            id: row.id,
            user_id: row.user_id,
            display_name: row.display_name,
            email_address: row.email_address,
            upstream_host: row.upstream_host,
            upstream_port: row.upstream_port,
            upstream_tls_mode: UpstreamTlsMode::from_str(&row.upstream_tls_mode)
                .map_err(|e| Error::Storage(e.to_string()))?,
            upstream_auth_method: UpstreamAuthMethod::from_str(&row.upstream_auth_method)
                .map_err(|e| Error::Storage(e.to_string()))?,
            encrypted_upstream_username: row.encrypted_upstream_username,
            encrypted_upstream_secret: row.encrypted_upstream_secret,
            created_at: row.created_at,
            disabled_at: row.disabled_at,
            last_sync_at: row.last_sync_at,
            last_sync_error: row.last_sync_error,
        })
    }
}

#[derive(Debug, FromRow)]
struct MailboxRow {
    id: i64,
    account_id: i64,
    name: String,
    canonical_name: String,
    delimiter: Option<String>,
    attributes: Vec<String>,
    subscribed: bool,
    special_use: Option<String>,
    uidvalidity: Option<i64>,
    uidnext: Option<i64>,
    highestmodseq: Option<i64>,
    exists_count: i64,
    recent_count: i64,
    unseen_count: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<MailboxRow> for Mailbox {
    fn from(row: MailboxRow) -> Self {
        Self {
            id: row.id,
            account_id: row.account_id,
            name: row.name,
            canonical_name: row.canonical_name,
            delimiter: row.delimiter,
            attributes: row.attributes,
            subscribed: row.subscribed,
            special_use: row.special_use,
            uidvalidity: row.uidvalidity,
            uidnext: row.uidnext,
            highestmodseq: row.highestmodseq,
            exists_count: row.exists_count,
            recent_count: row.recent_count,
            unseen_count: row.unseen_count,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct MessageRow {
    id: i64,
    account_id: i64,
    rfc822_blob_key: String,
    rfc822_sha256: String,
    message_id_header: Option<String>,
    subject: Option<String>,
    from_json: Value,
    to_json: Value,
    cc_json: Value,
    bcc_json: Value,
    reply_to_json: Value,
    envelope_json: Value,
    bodystructure_json: Value,
    internal_date: Option<DateTime<Utc>>,
    sent_date: Option<DateTime<Utc>>,
    size_octets: i64,
    text_preview: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<MessageRow> for Message {
    fn from(row: MessageRow) -> Self {
        Self {
            id: row.id,
            account_id: row.account_id,
            rfc822_blob_key: row.rfc822_blob_key,
            rfc822_sha256: row.rfc822_sha256,
            message_id_header: row.message_id_header,
            subject: row.subject,
            from_json: row.from_json,
            to_json: row.to_json,
            cc_json: row.cc_json,
            bcc_json: row.bcc_json,
            reply_to_json: row.reply_to_json,
            envelope_json: row.envelope_json,
            bodystructure_json: row.bodystructure_json,
            internal_date: row.internal_date,
            sent_date: row.sent_date,
            size_octets: row.size_octets,
            text_preview: row.text_preview,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct MimePartRow {
    id: i64,
    message_id: i64,
    part_path: String,
    content_type: String,
    charset: Option<String>,
    disposition: Option<String>,
    filename: Option<String>,
    content_id: Option<String>,
    size_octets: i64,
    blob_key: String,
    sha256: String,
    transfer_encoding: Option<String>,
    metadata_json: Value,
}

impl From<MimePartRow> for MimePart {
    fn from(row: MimePartRow) -> Self {
        Self {
            id: row.id,
            message_id: row.message_id,
            part_path: row.part_path,
            content_type: row.content_type,
            charset: row.charset,
            disposition: row.disposition,
            filename: row.filename,
            content_id: row.content_id,
            size_octets: row.size_octets,
            blob_key: row.blob_key,
            sha256: row.sha256,
            transfer_encoding: row.transfer_encoding,
            metadata_json: row.metadata_json,
        }
    }
}

#[derive(Debug, FromRow)]
struct SyncStateRow {
    id: i64,
    account_id: i64,
    mailbox_id: Option<i64>,
    state_json: Value,
    last_success_at: Option<DateTime<Utc>>,
    last_attempt_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
}

impl From<SyncStateRow> for SyncState {
    fn from(row: SyncStateRow) -> Self {
        Self {
            id: row.id,
            account_id: row.account_id,
            mailbox_id: row.mailbox_id,
            state_json: row.state_json,
            last_success_at: row.last_success_at,
            last_attempt_at: row.last_attempt_at,
            last_error: row.last_error,
        }
    }
}

#[derive(Debug, FromRow)]
struct PendingMutationRow {
    id: i64,
    account_id: i64,
    mailbox_id: i64,
    message_id: Option<i64>,
    mutation_type: String,
    payload_json: Value,
    status: String,
    attempts: i32,
    next_attempt_at: Option<DateTime<Utc>>,
    idempotency_key: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<PendingMutationRow> for PendingMutation {
    type Error = Error;

    fn try_from(row: PendingMutationRow) -> Result<Self> {
        Ok(Self {
            id: row.id,
            account_id: row.account_id,
            mailbox_id: row.mailbox_id,
            message_id: row.message_id,
            mutation_type: row.mutation_type,
            payload_json: row.payload_json,
            status: MutationStatus::from_str(&row.status)
                .map_err(|e| Error::Storage(e.to_string()))?,
            attempts: row.attempts,
            next_attempt_at: row.next_attempt_at,
            idempotency_key: row.idempotency_key,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Debug, FromRow)]
struct MailboxMessageRow {
    id: i64,
    mailbox_id: i64,
    message_id: i64,
    local_uid: i64,
    upstream_uid: Option<i64>,
    modseq: Option<i64>,
    flags: Vec<String>,
    keywords: Vec<String>,
    is_expunged: bool,
    expunged_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<MailboxMessageRow> for MailboxMessage {
    fn from(row: MailboxMessageRow) -> Self {
        Self {
            id: row.id,
            mailbox_id: row.mailbox_id,
            message_id: row.message_id,
            local_uid: row.local_uid,
            upstream_uid: row.upstream_uid,
            modseq: row.modseq,
            flags: row.flags,
            keywords: row.keywords,
            is_expunged: row.is_expunged,
            expunged_at: row.expunged_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct MailboxMessageViewRow {
    id: i64,
    mailbox_id: i64,
    message_id: i64,
    local_uid: i64,
    upstream_uid: Option<i64>,
    modseq: Option<i64>,
    flags: Vec<String>,
    keywords: Vec<String>,
    is_expunged: bool,
    expunged_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    rfc822_blob_key: String,
    rfc822_sha256: String,
    message_id_header: Option<String>,
    subject: Option<String>,
    envelope_json: Value,
    bodystructure_json: Value,
    internal_date: Option<DateTime<Utc>>,
    sent_date: Option<DateTime<Utc>>,
    size_octets: i64,
    text_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxMessageView {
    pub id: i64,
    pub mailbox_id: i64,
    pub message_id: i64,
    pub local_uid: i64,
    pub upstream_uid: Option<i64>,
    pub modseq: Option<i64>,
    pub flags: Vec<String>,
    pub keywords: Vec<String>,
    pub is_expunged: bool,
    pub expunged_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub rfc822_blob_key: String,
    pub rfc822_sha256: String,
    pub message_id_header: Option<String>,
    pub subject: Option<String>,
    pub envelope_json: Value,
    pub bodystructure_json: Value,
    pub internal_date: Option<DateTime<Utc>>,
    pub sent_date: Option<DateTime<Utc>>,
    pub size_octets: i64,
    pub text_preview: Option<String>,
}

impl From<MailboxMessageViewRow> for MailboxMessageView {
    fn from(row: MailboxMessageViewRow) -> Self {
        Self {
            id: row.id,
            mailbox_id: row.mailbox_id,
            message_id: row.message_id,
            local_uid: row.local_uid,
            upstream_uid: row.upstream_uid,
            modseq: row.modseq,
            flags: row.flags,
            keywords: row.keywords,
            is_expunged: row.is_expunged,
            expunged_at: row.expunged_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            rfc822_blob_key: row.rfc822_blob_key,
            rfc822_sha256: row.rfc822_sha256,
            message_id_header: row.message_id_header,
            subject: row.subject,
            envelope_json: row.envelope_json,
            bodystructure_json: row.bodystructure_json,
            internal_date: row.internal_date,
            sent_date: row.sent_date,
            size_octets: row.size_octets,
            text_preview: row.text_preview,
        }
    }
}

#[derive(Debug, FromRow)]
struct CacheObjectRow {
    id: i64,
    account_id: Option<i64>,
    object_type: String,
    blob_key: String,
    sha256: String,
    size_octets: i64,
    ref_count: i64,
    last_accessed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
struct CacheObjectReferenceRow {
    object_type: String,
    blob_key: String,
    sha256: String,
    size_octets: i64,
}

impl From<CacheObjectRow> for CacheObject {
    fn from(row: CacheObjectRow) -> Self {
        Self {
            id: row.id,
            account_id: row.account_id,
            object_type: row.object_type,
            blob_key: row.blob_key,
            sha256: row.sha256,
            size_octets: row.size_octets,
            ref_count: row.ref_count,
            last_accessed_at: row.last_accessed_at,
            created_at: row.created_at,
        }
    }
}

impl From<CacheObjectReferenceRow> for CacheObjectReference {
    fn from(row: CacheObjectReferenceRow) -> Self {
        Self {
            object_type: row.object_type,
            blob_key: row.blob_key,
            sha256: row.sha256,
            size_octets: row.size_octets,
        }
    }
}

#[derive(Debug, FromRow)]
struct QuotaRow {
    id: i64,
    user_id: Option<i64>,
    account_id: Option<i64>,
    max_bytes: i64,
    used_bytes: i64,
    updated_at: DateTime<Utc>,
}

impl From<QuotaRow> for Quota {
    fn from(row: QuotaRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            account_id: row.account_id,
            max_bytes: row.max_bytes,
            used_bytes: row.used_bytes,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct AuditLogRow {
    id: i64,
    user_id: Option<i64>,
    account_id: Option<i64>,
    action: String,
    metadata_json: Value,
    created_at: DateTime<Utc>,
}

impl From<AuditLogRow> for AuditLogEntry {
    fn from(row: AuditLogRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            account_id: row.account_id,
            action: row.action,
            metadata_json: row.metadata_json,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct SessionRow {
    id: i64,
    user_id: i64,
    account_id: Option<i64>,
    connection_id: Uuid,
    remote_addr: Option<String>,
    authenticated_at: Option<DateTime<Utc>>,
    disconnected_at: Option<DateTime<Utc>>,
}

impl From<SessionRow> for SessionRecord {
    fn from(row: SessionRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            account_id: row.account_id,
            connection_id: row.connection_id.to_string(),
            remote_addr: row.remote_addr,
            authenticated_at: row.authenticated_at,
            disconnected_at: row.disconnected_at,
        }
    }
}
