use imap_cache_core::error::{Error, Result};
use async_trait::async_trait;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

#[async_trait]
pub trait SyncLockManager: Send + Sync {
    async fn acquire(&self, key: &str, ttl: Duration) -> Result<Option<SyncLockGuard>>;
    async fn release(&self, key: &str, token: &str) -> Result<()>;
}

#[derive(Clone)]
pub struct SyncLockGuard {
    manager: Arc<dyn SyncLockManager>,
    key: String,
    token: String,
}

impl SyncLockGuard {
    fn new(manager: Arc<dyn SyncLockManager>, key: String, token: String) -> Self {
        Self {
            manager,
            key,
            token,
        }
    }
}

impl Drop for SyncLockGuard {
    fn drop(&mut self) {
        let manager = Arc::clone(&self.manager);
        let key = self.key.clone();
        let token = self.token.clone();
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(async move {
                let _ = manager.release(&key, &token).await;
            });
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct NoopSyncLockManager;

#[async_trait]
impl SyncLockManager for NoopSyncLockManager {
    async fn acquire(&self, _key: &str, _ttl: Duration) -> Result<Option<SyncLockGuard>> {
        Ok(None)
    }

    async fn release(&self, _key: &str, _token: &str) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemorySyncLockManager {
    locks: Arc<AsyncMutex<HashSet<String>>>,
}

impl MemorySyncLockManager {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SyncLockManager for MemorySyncLockManager {
    async fn acquire(&self, key: &str, _ttl: Duration) -> Result<Option<SyncLockGuard>> {
        let mut locks = self.locks.lock().await;
        if !locks.insert(key.to_string()) {
            return Ok(None);
        }
        Ok(Some(SyncLockGuard::new(
            Arc::new(self.clone()),
            key.to_string(),
            Uuid::new_v4().to_string(),
        )))
    }

    async fn release(&self, key: &str, _token: &str) -> Result<()> {
        let mut locks = self.locks.lock().await;
        locks.remove(key);
        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisSyncLockManager {
    client: redis::Client,
}

impl RedisSyncLockManager {
    pub fn new(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)
            .map_err(|err| Error::Storage(format!("connecting to redis at {url}: {err}")))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl SyncLockManager for RedisSyncLockManager {
    async fn acquire(&self, key: &str, ttl: Duration) -> Result<Option<SyncLockGuard>> {
        let token = Uuid::new_v4().to_string();
        let ttl_ms = ttl.as_millis().min(i64::MAX as u128) as i64;
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| Error::Storage(format!("connecting to redis: {err}")))?;
        let acquired: Option<String> = redis::cmd("SET")
            .arg(key)
            .arg(&token)
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query_async(&mut connection)
            .await
            .map_err(|err| Error::Storage(format!("acquiring redis lock: {err}")))?;
        if acquired.is_some() {
            Ok(Some(SyncLockGuard::new(
                Arc::new(self.clone()),
                key.to_string(),
                token,
            )))
        } else {
            Ok(None)
        }
    }

    async fn release(&self, key: &str, token: &str) -> Result<()> {
        let script = redis::Script::new(
            r#"
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("DEL", KEYS[1])
            end
            return 0
            "#,
        );
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| Error::Storage(format!("connecting to redis: {err}")))?;
        let _: i32 = script
            .key(key)
            .arg(token)
            .invoke_async(&mut connection)
            .await
            .map_err(|err| Error::Storage(format!("releasing redis lock: {err}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_lock_manager_serializes_acquisition() {
        let manager = MemorySyncLockManager::new();
        let lock = manager
            .acquire("sync:account:1", Duration::from_secs(1))
            .await
            .unwrap()
            .expect("first lock should be granted");
        assert!(
            manager
                .acquire("sync:account:1", Duration::from_secs(1))
                .await
                .unwrap()
                .is_none()
        );
        drop(lock);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            manager
                .acquire("sync:account:1", Duration::from_secs(1))
                .await
                .unwrap()
                .is_some()
        );
    }
}
