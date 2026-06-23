use imap_cache_core::error::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{Mutex as AsyncMutex, broadcast};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MutationEventKind {
    AccountChanged,
    MailboxChanged,
    MessageChanged,
    PendingMutationChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationEvent {
    pub kind: MutationEventKind,
    pub account_id: Option<i64>,
    pub mailbox_id: Option<i64>,
    pub message_id: Option<i64>,
    pub mutation_id: Option<i64>,
    pub local_uid: Option<i64>,
    pub sequence_number: Option<i64>,
    pub flags: Vec<String>,
    pub detail: String,
    pub occurred_at: DateTime<Utc>,
}

impl MutationEvent {
    pub fn new(
        kind: MutationEventKind,
        account_id: Option<i64>,
        mailbox_id: Option<i64>,
        message_id: Option<i64>,
        mutation_id: Option<i64>,
        local_uid: Option<i64>,
        sequence_number: Option<i64>,
        flags: Vec<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            account_id,
            mailbox_id,
            message_id,
            mutation_id,
            local_uid,
            sequence_number,
            flags,
            detail: detail.into(),
            occurred_at: Utc::now(),
        }
    }

    pub fn account_changed(account_id: i64, detail: impl Into<String>) -> Self {
        Self::new(
            MutationEventKind::AccountChanged,
            Some(account_id),
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
            detail,
        )
    }

    pub fn mailbox_changed(
        account_id: Option<i64>,
        mailbox_id: Option<i64>,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(
            MutationEventKind::MailboxChanged,
            account_id,
            mailbox_id,
            None,
            None,
            None,
            None,
            Vec::new(),
            detail,
        )
    }

    pub fn message_changed(
        account_id: Option<i64>,
        mailbox_id: Option<i64>,
        message_id: Option<i64>,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(
            MutationEventKind::MessageChanged,
            account_id,
            mailbox_id,
            message_id,
            None,
            None,
            None,
            Vec::new(),
            detail,
        )
    }

    pub fn message_changed_with_context(
        account_id: Option<i64>,
        mailbox_id: Option<i64>,
        message_id: Option<i64>,
        local_uid: Option<i64>,
        sequence_number: Option<i64>,
        flags: Vec<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(
            MutationEventKind::MessageChanged,
            account_id,
            mailbox_id,
            message_id,
            None,
            local_uid,
            sequence_number,
            flags,
            detail,
        )
    }

    pub fn pending_mutation_changed(
        account_id: Option<i64>,
        mailbox_id: Option<i64>,
        mutation_id: Option<i64>,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(
            MutationEventKind::PendingMutationChanged,
            account_id,
            mailbox_id,
            None,
            mutation_id,
            None,
            None,
            Vec::new(),
            detail,
        )
    }

    pub fn mailbox_changed_with_context(
        account_id: Option<i64>,
        mailbox_id: Option<i64>,
        local_uid: Option<i64>,
        sequence_number: Option<i64>,
        flags: Vec<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(
            MutationEventKind::MailboxChanged,
            account_id,
            mailbox_id,
            None,
            None,
            local_uid,
            sequence_number,
            flags,
            detail,
        )
    }
}

#[derive(Clone)]
pub struct MailboxEventHub {
    sender: broadcast::Sender<MutationEvent>,
}

impl MailboxEventHub {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MutationEvent> {
        self.sender.subscribe()
    }

    pub fn publish(&self, event: MutationEvent) {
        let _ = self.sender.send(event);
    }
}

#[derive(Clone)]
pub struct HubMutationEventSink {
    hub: Arc<MailboxEventHub>,
}

impl HubMutationEventSink {
    pub fn new(hub: Arc<MailboxEventHub>) -> Self {
        Self { hub }
    }
}

#[async_trait]
impl MutationEventSink for HubMutationEventSink {
    async fn publish(&self, event: MutationEvent) -> Result<()> {
        self.hub.publish(event);
        Ok(())
    }
}

#[derive(Clone)]
pub struct CompositeMutationEventSink {
    sinks: Arc<AsyncMutex<Vec<Arc<dyn MutationEventSink>>>>,
}

impl CompositeMutationEventSink {
    pub fn new(sinks: Vec<Arc<dyn MutationEventSink>>) -> Self {
        Self {
            sinks: Arc::new(AsyncMutex::new(sinks)),
        }
    }
}

#[async_trait]
impl MutationEventSink for CompositeMutationEventSink {
    async fn publish(&self, event: MutationEvent) -> Result<()> {
        let sinks = self.sinks.lock().await.clone();
        for sink in sinks {
            sink.publish(event.clone()).await?;
        }
        Ok(())
    }
}

#[async_trait]
pub trait MutationEventSink: Send + Sync {
    async fn publish(&self, event: MutationEvent) -> Result<()>;
}

pub trait NotificationMetrics: Send + Sync {
    fn record_redis_pubsub_event_published(&self);
    fn record_redis_pubsub_event_relayed(&self);
}

#[derive(Debug, Default, Clone)]
pub struct NoopMutationEventSink;

#[async_trait]
impl MutationEventSink for NoopMutationEventSink {
    async fn publish(&self, _event: MutationEvent) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisMutationEventSink {
    client: redis::Client,
    channel: String,
    metrics: Option<Arc<dyn NotificationMetrics>>,
}

impl RedisMutationEventSink {
    pub fn new(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)
            .map_err(|err| Error::Storage(format!("connecting to redis at {url}: {err}")))?;
        Ok(Self {
            client,
            channel: "imap:mutations".to_string(),
            metrics: None,
        })
    }

    pub fn with_metrics(mut self, metrics: Arc<dyn NotificationMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }
}

#[async_trait]
impl MutationEventSink for RedisMutationEventSink {
    async fn publish(&self, event: MutationEvent) -> Result<()> {
        let payload = serde_json::to_string(&event)
            .map_err(|err| Error::Storage(format!("serializing redis mutation event: {err}")))?;
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| Error::Storage(format!("connecting to redis: {err}")))?;
        let _: i64 = redis::cmd("PUBLISH")
            .arg(&self.channel)
            .arg(payload)
            .query_async(&mut connection)
            .await
            .map_err(|err| Error::Storage(format!("publishing redis mutation event: {err}")))?;
        if let Some(metrics) = &self.metrics {
            metrics.record_redis_pubsub_event_published();
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisMutationEventRelay {
    client: redis::Client,
    channel: String,
    hub: Arc<MailboxEventHub>,
    metrics: Option<Arc<dyn NotificationMetrics>>,
}

impl RedisMutationEventRelay {
    pub fn new(url: &str, hub: Arc<MailboxEventHub>) -> Result<Self> {
        let client = redis::Client::open(url)
            .map_err(|err| Error::Storage(format!("connecting to redis at {url}: {err}")))?;
        Ok(Self {
            client,
            channel: "imap:mutations".to_string(),
            hub,
            metrics: None,
        })
    }

    pub fn with_metrics(mut self, metrics: Arc<dyn NotificationMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub async fn run(&self) -> Result<()> {
        let mut pubsub = self
            .client
            .get_async_pubsub()
            .await
            .map_err(|err| Error::Storage(format!("connecting to redis pubsub: {err}")))?;
        pubsub
            .subscribe(&self.channel)
            .await
            .map_err(|err| Error::Storage(format!("subscribing to redis channel: {err}")))?;
        let mut messages = pubsub.on_message();
        while let Some(message) = messages.next().await {
            let payload: String = message
                .get_payload()
                .map_err(|err| Error::Storage(format!("reading redis event payload: {err}")))?;
            match serde_json::from_str::<MutationEvent>(&payload) {
                Ok(event) => {
                    self.hub.publish(event);
                    if let Some(metrics) = &self.metrics {
                        metrics.record_redis_pubsub_event_relayed();
                    }
                }
                Err(err) => tracing::warn!(error = %err, "discarding invalid redis mutation event"),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct RecordingMutationEventSink {
        events: Arc<Mutex<Vec<MutationEvent>>>,
    }

    #[async_trait]
    impl MutationEventSink for RecordingMutationEventSink {
        async fn publish(&self, event: MutationEvent) -> Result<()> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    #[tokio::test]
    async fn recording_sink_captures_events() {
        let sink = RecordingMutationEventSink::default();
        let event =
            MutationEvent::pending_mutation_changed(Some(3), Some(4), Some(5), "enqueue_mutation");

        sink.publish(event.clone()).await.unwrap();

        assert_eq!(*sink.events.lock().unwrap(), vec![event]);
    }

    #[test]
    fn event_serializes_with_expected_shape() {
        let event = MutationEvent::mailbox_changed(Some(7), Some(11), "refresh_mailbox_counts");
        let json = serde_json::to_value(event).unwrap();

        assert_eq!(json["kind"], "MailboxChanged");
        assert_eq!(json["account_id"], 7);
        assert_eq!(json["mailbox_id"], 11);
        assert_eq!(json["detail"], "refresh_mailbox_counts");
        assert!(json["occurred_at"].as_str().is_some());
    }
}
