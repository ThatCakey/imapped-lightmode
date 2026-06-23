use imap_cache_coordination::{SyncLockGuard, SyncLockManager};
use imap_cache_core::{
    domain::{Mailbox, MutationStatus, PendingMutation},
    error::{Error, Result},
};
use imap_cache_db::repository::{
    NewCacheObject, NewMailbox, NewMailboxMessage, NewMessage, NewMimePart, NewPendingMutation,
    NewSyncState, PostgresRepository,
};
use imap_cache_mime::{MimePartRecord, ParsedMessage, parse_message};
use imap_cache_search::{SearchBackend, SearchDocument};
use imap_cache_storage::{ObjectStore, ObjectType, content_addressed_key};
use imap_cache_upstream::{SelectedMailboxInfo, UpstreamClient};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use std::sync::Arc;
use std::time::Duration;
use std::{collections::{HashMap, HashSet}, convert::TryFrom};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

pub trait SyncMetrics: Send + Sync {
    fn record_object_store_bytes_written(&self, bytes: u64);
    fn record_object_store_bytes_read(&self, bytes: u64);
    fn record_sync_run(&self, duration_seconds: u64, succeeded: bool);
}

#[derive(Debug, Default, Clone)]
pub struct NoopSyncMetrics;

impl SyncMetrics for NoopSyncMetrics {
    fn record_object_store_bytes_written(&self, _bytes: u64) {}

    fn record_object_store_bytes_read(&self, _bytes: u64) {}

    fn record_sync_run(&self, _duration_seconds: u64, _succeeded: bool) {}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    pub account_id: i64,
    pub mailbox_id: Option<i64>,
    pub uidvalidity: Option<i64>,
    pub highestmodseq: Option<i64>,
    pub last_uid: Option<i64>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationJob {
    pub id: Uuid,
    pub account_id: i64,
    pub mailbox_id: i64,
    pub mutation_type: String,
    pub payload_json: Value,
    pub idempotency_key: String,
}

pub fn retry_delay(attempt: u32) -> std::time::Duration {
    let capped = attempt.min(10);
    std::time::Duration::from_secs(2u64.saturating_pow(capped).min(300))
}

#[derive(Clone)]
pub struct MessageIngestor {
    repository: Arc<PostgresRepository>,
    store: Arc<dyn ObjectStore>,
    search: Option<Arc<dyn SearchBackend>>,
    metrics: Arc<dyn SyncMetrics>,
}

#[derive(Debug, Clone)]
pub struct IngestedMessage {
    pub message_id: i64,
    pub mailbox_message_id: i64,
    pub local_uid: i64,
    pub blob_key: String,
}

#[derive(Debug, Clone, Default)]
pub struct SyncRunReport {
    pub mailboxes_synced: usize,
    pub messages_synced: usize,
}

#[derive(Clone)]
pub struct MutationEngine {
    repository: Arc<PostgresRepository>,
    store: Arc<dyn ObjectStore>,
    metrics: Arc<dyn SyncMetrics>,
}

impl MessageIngestor {
    pub fn new(
        repository: Arc<PostgresRepository>,
        store: Arc<dyn ObjectStore>,
        search: Option<Arc<dyn SearchBackend>>,
    ) -> Self {
        Self {
            repository,
            store,
            search,
            metrics: Arc::new(NoopSyncMetrics::default()),
        }
    }

    pub fn with_metrics<M: SyncMetrics + 'static>(
        repository: Arc<PostgresRepository>,
        store: Arc<dyn ObjectStore>,
        search: Option<Arc<dyn SearchBackend>>,
        metrics: Arc<M>,
    ) -> Self {
        Self {
            repository,
            store,
            search,
            metrics,
        }
    }

    pub async fn ingest_raw_message(
        &self,
        account_id: i64,
        mailbox_id: i64,
        mailbox_name: &str,
        local_uid: i64,
        upstream_uid: Option<i64>,
        internal_date: Option<DateTime<Utc>>,
        raw: &[u8],
        flags: Vec<String>,
    ) -> Result<IngestedMessage> {
        let parsed = parse_message(raw)?;
        self.ingest_parsed_message(
            account_id,
            mailbox_id,
            mailbox_name,
            local_uid,
            upstream_uid,
            internal_date,
            raw,
            parsed,
            flags,
        )
        .await
    }

    pub async fn ingest_parsed_message(
        &self,
        account_id: i64,
        mailbox_id: i64,
        mailbox_name: &str,
        local_uid: i64,
        upstream_uid: Option<i64>,
        internal_date: Option<DateTime<Utc>>,
        raw: &[u8],
        mut parsed: ParsedMessage,
        flags: Vec<String>,
    ) -> Result<IngestedMessage> {
        let incoming_bytes = estimate_message_bytes(raw, &parsed)?;
        if let Some(quota) = self.repository.get_account_quota(account_id).await? {
            let projected = quota
                .used_bytes
                .checked_add(incoming_bytes)
                .ok_or_else(|| {
                    Error::Storage("account quota calculation overflowed".to_string())
                })?;
            if projected > quota.max_bytes {
                return Err(Error::Storage(format!(
                    "account quota exceeded: used={} incoming={} limit={}",
                    quota.used_bytes, incoming_bytes, quota.max_bytes
                )));
            }
        }

        let blob_key = content_addressed_key(ObjectType::Rfc822, raw);
        let metadata = self.store.put(&blob_key, raw).await?;
        self.metrics
            .record_object_store_bytes_written(metadata.size_octets);
        let mut accounted_bytes = metadata.size_octets as i64;

        let message = self
            .repository
            .upsert_message(NewMessage {
                account_id,
                rfc822_blob_key: &metadata.key,
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
                internal_date,
                sent_date: None,
                size_octets: parsed.size_octets as i64,
                text_preview: parsed.text_preview.as_deref(),
            })
            .await?;

        let mime_parts = std::mem::take(&mut parsed.mime_parts);
        if !mime_parts.is_empty() {
            let _ = self
                .repository
                .delete_mime_parts_for_message(message.id)
                .await?;
        }
        for part in mime_parts {
            let metadata = self.store.put(&part.blob_key, &part.raw_bytes).await?;
            self.metrics
                .record_object_store_bytes_written(metadata.size_octets);
            accounted_bytes += metadata.size_octets as i64;
            let object_type = cache_object_type_for_mime_part(&part);
            self.repository
                .insert_mime_part(NewMimePart {
                    message_id: message.id,
                    part_path: &part.part_path,
                    content_type: &part.content_type,
                    charset: part.charset.as_deref(),
                    disposition: part.disposition.as_deref(),
                    filename: part.filename.as_deref(),
                    content_id: part.content_id.as_deref(),
                    size_octets: part.size_octets as i64,
                    blob_key: &metadata.key,
                    sha256: &metadata.sha256,
                    transfer_encoding: part.transfer_encoding.as_deref(),
                    metadata_json: part.metadata_json.clone(),
                })
                .await?;
            self.repository
                .upsert_cache_object(NewCacheObject {
                    account_id: Some(account_id),
                    object_type,
                    blob_key: &metadata.key,
                    sha256: &metadata.sha256,
                    size_octets: metadata.size_octets as i64,
                    ref_count: 1,
                    last_accessed_at: Some(Utc::now()),
                })
                .await?;
        }

        let mailbox_message = self
            .repository
            .upsert_mailbox_message(NewMailboxMessage {
                mailbox_id,
                message_id: message.id,
                local_uid,
                upstream_uid,
                modseq: None,
                flags,
                keywords: Vec::new(),
                is_expunged: false,
                expunged_at: None,
            })
            .await?;

        self.repository
            .upsert_cache_object(NewCacheObject {
                account_id: Some(account_id),
                object_type: "rfc822",
                blob_key: &metadata.key,
                sha256: &metadata.sha256,
                size_octets: metadata.size_octets as i64,
                ref_count: 1,
                last_accessed_at: Some(Utc::now()),
            })
            .await?;

        if let Some(search) = &self.search {
            search
                .index_message(
                    mailbox_name,
                    SearchDocument::from_parsed_message(local_uid as u64, &parsed),
                )
                .await?;
        }

        let _ = self
            .repository
            .adjust_account_quota_usage(account_id, accounted_bytes)
            .await?;

        Ok(IngestedMessage {
            message_id: message.id,
            mailbox_message_id: mailbox_message.id,
            local_uid: mailbox_message.local_uid,
            blob_key: metadata.key,
        })
    }

}

fn estimate_message_bytes(raw: &[u8], parsed: &ParsedMessage) -> Result<i64> {
    let mut total = i64::try_from(raw.len())
        .map_err(|e| Error::Storage(format!("message size does not fit in i64: {e}")))?;
    for part in &parsed.mime_parts {
        total =
            total
                .checked_add(i64::try_from(part.raw_bytes.len()).map_err(|e| {
                    Error::Storage(format!("mime part size does not fit in i64: {e}"))
                })?)
                .ok_or_else(|| Error::Storage("message size calculation overflowed".to_string()))?;
    }
    Ok(total)
}

fn cache_object_type_for_mime_part(part: &MimePartRecord) -> &'static str {
    if matches!(part.disposition.as_deref(), Some("attachment")) || part.filename.is_some() {
        "Attachment"
    } else {
        "MimePart"
    }
}

impl MutationEngine {
    pub fn new(repository: Arc<PostgresRepository>, store: Arc<dyn ObjectStore>) -> Self {
        Self {
            repository,
            store,
            metrics: Arc::new(NoopSyncMetrics::default()),
        }
    }

    pub fn with_metrics<M: SyncMetrics + 'static>(
        repository: Arc<PostgresRepository>,
        store: Arc<dyn ObjectStore>,
        metrics: Arc<M>,
    ) -> Self {
        Self {
            repository,
            store,
            metrics,
        }
    }

    pub async fn queue_append(
        &self,
        account_id: i64,
        mailbox_id: i64,
        mailbox_name: &str,
        local_uid: Option<i64>,
        raw: &[u8],
        flags: Vec<String>,
        internal_date: Option<DateTime<Utc>>,
    ) -> Result<PendingMutation> {
        let blob_key = content_addressed_key(ObjectType::Rfc822, raw);
        let metadata = self.store.put(&blob_key, raw).await?;
        self.metrics
            .record_object_store_bytes_written(metadata.size_octets);
        let payload = serde_json::json!({
            "mailbox": mailbox_name,
            "mailbox_id": mailbox_id,
            "local_uid": local_uid,
            "blob_key": metadata.key,
            "flags": flags,
            "internal_date": internal_date
                .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        });
        let idempotency_key = idempotency_key(account_id, mailbox_id, "append", &payload);
        self.repository
            .enqueue_mutation(NewPendingMutation {
                account_id,
                mailbox_id,
                message_id: None,
                mutation_type: "append",
                payload_json: payload,
                status: MutationStatus::Pending,
                attempts: 0,
                next_attempt_at: None,
                idempotency_key: &idempotency_key,
            })
            .await
    }

    pub async fn queue_flag_update(
        &self,
        account_id: i64,
        mailbox_id: i64,
        message_id: Option<i64>,
        local_uid: i64,
        flags: Vec<String>,
    ) -> Result<PendingMutation> {
        let payload = serde_json::json!({
            "local_uid": local_uid,
            "flags": flags,
        });
        let idempotency_key = idempotency_key(account_id, mailbox_id, "store_flags", &payload);
        self.repository
            .enqueue_mutation(NewPendingMutation {
                account_id,
                mailbox_id,
                message_id,
                mutation_type: "store_flags",
                payload_json: payload.clone(),
                status: MutationStatus::Pending,
                attempts: 0,
                next_attempt_at: None,
                idempotency_key: &idempotency_key,
            })
            .await
    }

    pub async fn queue_copy_message(
        &self,
        account_id: i64,
        source_mailbox_id: i64,
        destination_mailbox_id: i64,
        source_mailbox_name: &str,
        destination_mailbox_name: &str,
        local_uid: i64,
        destination_local_uid: i64,
        flags: Vec<String>,
    ) -> Result<PendingMutation> {
        let payload = serde_json::json!({
            "source_mailbox_id": source_mailbox_id,
            "source_mailbox": source_mailbox_name,
            "destination_mailbox_id": destination_mailbox_id,
            "destination_mailbox": destination_mailbox_name,
            "local_uid": local_uid,
            "destination_local_uid": destination_local_uid,
            "flags": flags,
        });
        let idempotency_key = idempotency_key(account_id, source_mailbox_id, "copy_message", &payload);
        self.repository
            .enqueue_mutation(NewPendingMutation {
                account_id,
                mailbox_id: source_mailbox_id,
                message_id: None,
                mutation_type: "copy_message",
                payload_json: payload,
                status: MutationStatus::Pending,
                attempts: 0,
                next_attempt_at: None,
                idempotency_key: &idempotency_key,
            })
            .await
    }

    pub async fn queue_move_message(
        &self,
        account_id: i64,
        source_mailbox_id: i64,
        destination_mailbox_id: i64,
        source_mailbox_name: &str,
        destination_mailbox_name: &str,
        local_uid: i64,
        destination_local_uid: i64,
        flags: Vec<String>,
    ) -> Result<PendingMutation> {
        let payload = serde_json::json!({
            "source_mailbox_id": source_mailbox_id,
            "source_mailbox": source_mailbox_name,
            "destination_mailbox_id": destination_mailbox_id,
            "destination_mailbox": destination_mailbox_name,
            "local_uid": local_uid,
            "destination_local_uid": destination_local_uid,
            "flags": flags,
        });
        let idempotency_key = idempotency_key(account_id, source_mailbox_id, "move_message", &payload);
        self.repository
            .enqueue_mutation(NewPendingMutation {
                account_id,
                mailbox_id: source_mailbox_id,
                message_id: None,
                mutation_type: "move_message",
                payload_json: payload,
                status: MutationStatus::Pending,
                attempts: 0,
                next_attempt_at: None,
                idempotency_key: &idempotency_key,
            })
            .await
    }

    pub async fn flush_pending_mutations(
        &self,
        account_id: i64,
        upstream: &mut UpstreamClient,
    ) -> Result<usize> {
        let pending = self
            .repository
            .list_due_pending_mutations(account_id)
            .await?;
        let mut applied = 0usize;

        for mutation in pending {
            let in_flight = self
                .repository
                .update_pending_mutation(
                    mutation.id,
                    MutationStatus::InFlight,
                    mutation.attempts + 1,
                    None,
                )
                .await?;

            let result = match mutation.mutation_type.as_str() {
                "append" => self.apply_append(upstream, &mutation.payload_json).await,
                "store_flags" => {
                    self.apply_flag_update(upstream, &mutation.payload_json)
                        .await
                }
                "copy_message" => {
                    self.apply_copy_message(upstream, &mutation.payload_json)
                        .await
                }
                "move_message" => {
                    self.apply_move_message(upstream, &mutation.payload_json)
                        .await
                }
                other => Err(Error::Storage(format!(
                    "unsupported mutation type: {other}"
                ))),
            };

            match result {
                Ok(()) => {
                    self.repository
                        .update_pending_mutation(
                            in_flight.id,
                            MutationStatus::Succeeded,
                            in_flight.attempts,
                            None,
                        )
                        .await?;
                    applied += 1;
                }
                Err(err) => {
                    let next_attempt = Utc::now()
                        + chrono::Duration::from_std(retry_delay(in_flight.attempts as u32))
                            .map_err(|e| {
                                Error::Storage(format!("invalid retry delay: {e}"))
                            })?;
                    self.repository
                        .update_pending_mutation(
                            in_flight.id,
                            MutationStatus::Failed,
                            in_flight.attempts,
                            Some(next_attempt),
                        )
                        .await?;
                    return Err(err);
                }
            }
        }

        Ok(applied)
    }

    async fn apply_append(
        &self,
        upstream: &mut UpstreamClient,
        payload_json: &serde_json::Value,
    ) -> Result<()> {
        let mailbox = payload_json
            .get("mailbox")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                Error::Parse("append mutation missing mailbox".to_string())
            })?;
        let mailbox_id = payload_json
            .get("mailbox_id")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| {
                Error::Parse("append mutation missing mailbox_id".to_string())
            })?;
        let local_uid = payload_json
            .get("local_uid")
            .and_then(|value| value.as_i64());
        let blob_key = payload_json
            .get("blob_key")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                Error::Parse("append mutation missing blob_key".to_string())
            })?;
        let flags = payload_json
            .get("flags")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let internal_date = payload_json
            .get("internal_date")
            .and_then(|value| value.as_str())
            .map(|value| {
                chrono::DateTime::parse_from_rfc3339(value)
                    .map(|parsed| parsed.with_timezone(&Utc))
                    .map_err(|err| {
                        Error::Parse(format!(
                            "invalid append internal_date {value:?}: {err}"
                        ))
                    })
            })
            .transpose()?;
        let raw = self.store.get(blob_key).await?.ok_or_else(|| {
            Error::Storage(format!("missing blob for append: {blob_key}"))
        })?;
        self.metrics
            .record_object_store_bytes_read(u64::try_from(raw.len()).map_err(|e| {
                Error::Storage(format!("append blob size does not fit in u64: {e}"))
            })?);
        let append_uid = upstream
            .append_with_internal_date(mailbox, &flags, internal_date, &raw)
            .await?;
        if let (Some(append_uid), Some(local_uid)) = (append_uid, local_uid) {
            let _ = self
                .repository
                .set_mailbox_message_upstream_uid(mailbox_id, local_uid, append_uid as i64)
                .await?;
        }
        Ok(())
    }

    async fn apply_flag_update(
        &self,
        upstream: &mut UpstreamClient,
        payload_json: &serde_json::Value,
    ) -> Result<()> {
        let local_uid = payload_json
            .get("local_uid")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| {
                Error::Parse("flag mutation missing local_uid".to_string())
            })?;
        let flags = payload_json
            .get("flags")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
        })
        .unwrap_or_default();
        upstream.uid_store_flags(local_uid, &flags).await
    }

    async fn apply_copy_message(
        &self,
        upstream: &mut UpstreamClient,
        payload_json: &serde_json::Value,
    ) -> Result<()> {
        let source_mailbox_id = payload_json
            .get("source_mailbox_id")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| {
                Error::Parse("copy mutation missing source_mailbox_id".to_string())
            })?;
        let source_mailbox = payload_json
            .get("source_mailbox")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                Error::Parse("copy mutation missing source_mailbox".to_string())
            })?;
        let destination_mailbox = payload_json
            .get("destination_mailbox")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                Error::Parse(
                    "copy mutation missing destination_mailbox".to_string(),
                )
            })?;
        let destination_mailbox_id = payload_json
            .get("destination_mailbox_id")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| {
                Error::Parse(
                    "copy mutation missing destination_mailbox_id".to_string(),
                )
            })?;
        let local_uid = payload_json
            .get("local_uid")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| {
                Error::Parse("copy mutation missing local_uid".to_string())
            })?;
        let destination_local_uid = payload_json
            .get("destination_local_uid")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| {
                Error::Parse(
                    "copy mutation missing destination_local_uid".to_string(),
                )
            })?;
        let source_upstream_uid = self
            .repository
            .upstream_uid_for_mailbox_message(source_mailbox_id, local_uid)
            .await?
            .ok_or_else(|| {
                Error::Storage(format!(
                    "copy mutation missing upstream uid for mailbox {source_mailbox_id} uid {local_uid}"
                ))
        })?;
        upstream.select(source_mailbox).await?;
        let destination_upstream_uid = upstream
            .uid_copy_message(source_upstream_uid as u64, destination_mailbox)
            .await?;
        let _ = self
            .repository
            .set_mailbox_message_upstream_uid(
                destination_mailbox_id,
                destination_local_uid,
                destination_upstream_uid as i64,
            )
            .await?;
        Ok(())
    }

    async fn apply_move_message(
        &self,
        upstream: &mut UpstreamClient,
        payload_json: &serde_json::Value,
    ) -> Result<()> {
        let source_mailbox_id = payload_json
            .get("source_mailbox_id")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| {
                Error::Parse("move mutation missing source_mailbox_id".to_string())
            })?;
        let source_mailbox = payload_json
            .get("source_mailbox")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                Error::Parse("move mutation missing source_mailbox".to_string())
            })?;
        let destination_mailbox = payload_json
            .get("destination_mailbox")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                Error::Parse(
                    "move mutation missing destination_mailbox".to_string(),
                )
            })?;
        let destination_mailbox_id = payload_json
            .get("destination_mailbox_id")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| {
                Error::Parse(
                    "move mutation missing destination_mailbox_id".to_string(),
                )
            })?;
        let local_uid = payload_json
            .get("local_uid")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| {
                Error::Parse("move mutation missing local_uid".to_string())
            })?;
        let destination_local_uid = payload_json
            .get("destination_local_uid")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| {
                Error::Parse(
                    "move mutation missing destination_local_uid".to_string(),
                )
            })?;
        let mut flags = payload_json
            .get("flags")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\Deleted")) {
            flags.push("\\Deleted".to_string());
        }
        let source_upstream_uid = self
            .repository
            .upstream_uid_for_mailbox_message(source_mailbox_id, local_uid)
            .await?
            .ok_or_else(|| {
                Error::Storage(format!(
                    "move mutation missing upstream uid for mailbox {source_mailbox_id} uid {local_uid}"
                ))
        })?;
        upstream.select(source_mailbox).await?;
        let destination_upstream_uid = upstream
            .uid_copy_message(source_upstream_uid as u64, destination_mailbox)
            .await?;
        let _ = self
            .repository
            .set_mailbox_message_upstream_uid(
                destination_mailbox_id,
                destination_local_uid,
                destination_upstream_uid as i64,
            )
            .await?;
        upstream.uid_store_flags(source_upstream_uid as u64, &flags).await?;
        upstream.expunge_selected().await
    }
}

#[derive(Clone)]
pub struct SyncEngine {
    repository: Arc<PostgresRepository>,
    ingestor: MessageIngestor,
    lock_manager: Option<Arc<dyn SyncLockManager>>,
    metrics: Arc<dyn SyncMetrics>,
    sync_limit: Option<Arc<Semaphore>>,
}

impl SyncEngine {
    pub fn new<M: SyncMetrics + 'static>(
        repository: Arc<PostgresRepository>,
        ingestor: MessageIngestor,
        metrics: Arc<M>,
    ) -> Self {
        Self {
            repository,
            ingestor,
            lock_manager: None,
            metrics,
            sync_limit: None,
        }
    }

    pub fn with_sync_limit(mut self, limit: usize) -> Self {
        self.sync_limit = if limit == 0 {
            None
        } else {
            Some(Arc::new(Semaphore::new(limit)))
        };
        self
    }

    pub fn with_lock_manager(mut self, lock_manager: Arc<dyn SyncLockManager>) -> Self {
        self.lock_manager = Some(lock_manager);
        self
    }

    pub async fn acquire_account_lock(
        &self,
        account_id: i64,
        ttl: Duration,
    ) -> Result<Option<SyncLockGuard>> {
        let Some(lock_manager) = &self.lock_manager else {
            return Ok(None);
        };
        lock_manager
            .acquire(&format!("imap-cache-rs:sync:account:{account_id}"), ttl)
            .await
    }

    pub async fn sync_account(
        &self,
        account_id: i64,
        upstream: &mut UpstreamClient,
    ) -> Result<SyncRunReport> {
        let _sync_permit: Option<OwnedSemaphorePermit> =
            if let Some(limit) = &self.sync_limit {
                Some(
                    limit.clone().acquire_owned().await.map_err(|e| {
                        Error::Storage(format!("sync concurrency limiter failed: {e}"))
                    })?,
                )
            } else {
                None
            };
        let started = std::time::Instant::now();
        let Some(account) = self
            .repository
            .find_account_by_id_any_state(account_id)
            .await?
        else {
            tracing::info!(account_id, "sync skipped because account no longer exists");
            return Ok(SyncRunReport::default());
        };
        let outcome: Result<SyncRunReport> = async {
            if account.disabled_at.is_some() {
                tracing::info!(account_id, "sync skipped because account is disabled");
                return Ok(SyncRunReport::default());
            }
            let _lock_guard = if let Some(lock_manager) = &self.lock_manager {
                match lock_manager
                    .acquire(
                        &format!("imap-cache-rs:sync:account:{account_id}"),
                        std::time::Duration::from_secs(600),
                    )
                    .await?
                {
                    Some(lock) => Some(lock),
                    None => {
                        tracing::info!(account_id, "sync skipped because account lock is busy");
                        return Ok(SyncRunReport::default());
                    }
                }
            } else {
                None
            };
            let mut report = SyncRunReport::default();
            let mut upstream_mailboxes = HashSet::new();
            for mailbox_name in upstream.list_mailboxes().await? {
                let canonical_name = mailbox_name.to_ascii_lowercase();
                upstream_mailboxes.insert(canonical_name.clone());
                let special_use = if canonical_name == "inbox" {
                    Some("\\Inbox")
                } else {
                    None
                };
                let mailbox = self
                    .repository
                    .upsert_mailbox(NewMailbox {
                        account_id,
                        name: &mailbox_name,
                        canonical_name: &canonical_name,
                        delimiter: Some("/"),
                        attributes: Vec::new(),
                        subscribed: true,
                        special_use,
                        uidvalidity: None,
                        uidnext: None,
                        highestmodseq: None,
                        exists_count: 0,
                        recent_count: 0,
                        unseen_count: 0,
                    })
                    .await?;
                let synced = self
                    .sync_mailbox_inner(account_id, &mailbox_name, mailbox, upstream)
                    .await?;
                report.mailboxes_synced += 1;
                report.messages_synced += synced;
            }
            self.remove_missing_mailboxes(account_id, &upstream_mailboxes)
                .await?;
            Ok(report)
        }
        .await;

        let duration_seconds = started.elapsed().as_secs();
        match &outcome {
            Ok(_) => {
                self.metrics.record_sync_run(duration_seconds, true);
                let _ = self
                    .repository
                    .set_mail_account_sync_status(account_id, Some(Utc::now()), None)
                    .await;
            }
            Err(err) => {
                self.metrics.record_sync_run(duration_seconds, false);
                let error = err.to_string();
                let _ = self
                    .repository
                    .set_mail_account_sync_status(
                        account_id,
                        Some(Utc::now()),
                        Some(error.as_str()),
                    )
                    .await;
            }
        }

        outcome
    }

    pub async fn sync_mailbox(
        &self,
        account_id: i64,
        mailbox_name: &str,
        upstream: &mut UpstreamClient,
    ) -> Result<usize> {
        let canonical_name = mailbox_name.to_ascii_lowercase();
        let special_use = if canonical_name == "inbox" {
            Some("\\Inbox")
        } else {
            None
        };
        let mailbox = self
            .repository
            .upsert_mailbox(NewMailbox {
                account_id,
                name: mailbox_name,
                canonical_name: &canonical_name,
                delimiter: Some("/"),
                attributes: Vec::new(),
                subscribed: true,
                special_use,
                uidvalidity: None,
                uidnext: None,
                highestmodseq: None,
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;
        self.sync_mailbox_inner(account_id, mailbox_name, mailbox, upstream)
            .await
    }

    async fn sync_mailbox_inner(
        &self,
        account_id: i64,
        mailbox_name: &str,
        mailbox: Mailbox,
        upstream: &mut UpstreamClient,
    ) -> Result<usize> {
        let selection = upstream.select_mailbox(mailbox_name).await?;
        let checkpoint = self
            .repository
            .load_sync_state(account_id, Some(mailbox.id))
            .await?;
        let checkpoint_uidvalidity = checkpoint
            .as_ref()
            .and_then(|state| state.state_json.get("uidvalidity"))
            .and_then(|value| value.as_i64());
        let uidvalidity_changed =
            selection.uidvalidity.is_some() && checkpoint_uidvalidity != selection.uidvalidity;

        if uidvalidity_changed {
            self.clear_synced_mailbox_messages(mailbox.id).await?;
        }

        let last_uid = checkpoint
            .as_ref()
            .and_then(|state| state.state_json.get("last_uid"))
            .and_then(|value| value.as_i64())
            .unwrap_or_default();
        let last_uid = if uidvalidity_changed { 0 } else { last_uid };

        let mut messages_synced = 0usize;
        let mut newest_uid = None;
        let upstream_uids = upstream.uid_search_all().await?;
        let upstream_uid_set = upstream_uids
            .iter()
            .filter_map(|uid| i64::try_from(*uid).ok())
            .collect::<HashSet<_>>();
        let local_messages = self.repository.list_mailbox_messages(mailbox.id).await?;
        let local_by_upstream_uid = local_messages
            .iter()
            .filter_map(|message| {
                message
                    .upstream_uid
                    .map(|upstream_uid| (upstream_uid, message))
            })
            .collect::<HashMap<_, _>>();
        for uid in upstream_uids {
            let uid_i64 = i64::try_from(uid).map_err(|_| {
                Error::Storage(format!("upstream UID out of range: {uid}"))
            })?;
            let fetched_flags = normalize_flags(upstream.uid_fetch_flags(uid).await?);
            if let Some(local_message) = local_by_upstream_uid.get(&uid_i64)
                && normalize_flags(local_message.flags.clone()) != fetched_flags
            {
                let _ = self
                    .repository
                    .update_mailbox_message_flags(
                        mailbox.id,
                        local_message.local_uid,
                        fetched_flags.clone(),
                    )
                    .await?;
            }
            if uid_i64 <= last_uid {
                continue;
            }
            let raw = upstream.uid_fetch_rfc822(uid).await?;
            self.ingestor
                .ingest_raw_message(
                    account_id,
                    mailbox.id,
                    mailbox_name,
                    uid_i64,
                    Some(uid_i64),
                    None,
                    &raw,
                    fetched_flags,
                )
                .await?;
            messages_synced += 1;
            newest_uid = Some(uid_i64);
        }

        let state_json = serde_json::json!({
            "mailbox_name": mailbox_name,
            "uidvalidity": selection.uidvalidity,
            "uidnext": selection.uidnext,
            "highestmodseq": selection.highestmodseq,
            "exists": selection.exists,
            "recent": selection.recent,
            "unseen": selection.unseen,
            "last_uid": newest_uid.or(Some(last_uid)),
        });
        let sync_state = SyncCheckpoint {
            account_id,
            mailbox_id: Some(mailbox.id),
            uidvalidity: selection.uidvalidity.or(mailbox.uidvalidity),
            highestmodseq: selection.highestmodseq.or(mailbox.highestmodseq),
            last_uid: newest_uid.or(Some(last_uid)),
            updated_at: Utc::now(),
        };
        validate_checkpoint(&sync_state)?;
        self.repository
            .put_sync_state(NewSyncState {
                account_id,
                mailbox_id: Some(mailbox.id),
                state_json,
                last_success_at: Some(Utc::now()),
                last_attempt_at: Some(Utc::now()),
                last_error: None,
            })
            .await?;
        self.update_mailbox_sync_metadata(mailbox.id, &selection)
            .await?;
        self.reconcile_missing_upstream_messages_with_set(mailbox.id, &upstream_uid_set)
            .await?;
        self.repository.refresh_mailbox_counts(mailbox.id).await?;
        Ok(messages_synced)
    }
}

impl SyncEngine {
    async fn clear_synced_mailbox_messages(&self, mailbox_id: i64) -> Result<()> {
        let messages = self.repository.list_mailbox_messages(mailbox_id).await?;
        for message in messages
            .into_iter()
            .filter(|message| message.upstream_uid.is_some())
        {
            self.repository
                .delete_mailbox_message(mailbox_id, message.local_uid)
                .await?;
        }
        Ok(())
    }

    async fn reconcile_missing_upstream_messages_with_set(
        &self,
        mailbox_id: i64,
        upstream_uids: &HashSet<i64>,
    ) -> Result<()> {
        let messages = self.repository.list_mailbox_messages(mailbox_id).await?;
        for message in messages.into_iter().filter(|message| {
            matches!(message.upstream_uid, Some(upstream_uid) if !upstream_uids.contains(&upstream_uid))
        }) {
            self.repository
                .delete_mailbox_message(mailbox_id, message.local_uid)
                .await?;
        }
        Ok(())
    }

    async fn update_mailbox_sync_metadata(
        &self,
        mailbox_id: i64,
        selection: &SelectedMailboxInfo,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE mailboxes
            SET
                uidvalidity = COALESCE($2, uidvalidity),
                uidnext = COALESCE($3, uidnext),
                highestmodseq = COALESCE($4, highestmodseq),
                exists_count = COALESCE($5, exists_count),
                recent_count = COALESCE($6, recent_count),
                unseen_count = COALESCE($7, unseen_count),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(mailbox_id)
        .bind(selection.uidvalidity)
        .bind(selection.uidnext)
        .bind(selection.highestmodseq)
        .bind(selection.exists)
        .bind(selection.recent)
        .bind(selection.unseen)
        .execute(self.repository.pool())
        .await?;
        Ok(())
    }

    async fn remove_missing_mailboxes(
        &self,
        account_id: i64,
        upstream_mailboxes: &HashSet<String>,
    ) -> Result<()> {
        let mailboxes = self.repository.list_mailboxes(account_id, None).await?;
        for mailbox in mailboxes {
            if upstream_mailboxes.contains(&mailbox.canonical_name) {
                continue;
            }
            let messages = self.repository.list_mailbox_messages(mailbox.id).await?;
            for message in messages {
                let _ = self
                    .repository
                    .delete_mailbox_message(mailbox.id, message.local_uid)
                    .await?;
            }
            let _ = self
                .repository
                .delete_mailbox(account_id, &mailbox.name)
                .await?;
        }
        Ok(())
    }
}

pub fn idempotency_key(
    account_id: i64,
    mailbox_id: i64,
    mutation_type: &str,
    payload_json: &Value,
) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(account_id.to_be_bytes());
    hasher.update(mailbox_id.to_be_bytes());
    hasher.update(mutation_type.as_bytes());
    hasher.update(payload_json.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

pub fn validate_checkpoint(checkpoint: &SyncCheckpoint) -> Result<()> {
    if checkpoint.account_id <= 0 {
        return Err(Error::Storage(
            "account_id must be positive".to_string(),
        ));
    }
    Ok(())
}

fn normalize_flags(mut flags: Vec<String>) -> Vec<String> {
    flags.sort_unstable();
    flags.dedup();
    flags
}
