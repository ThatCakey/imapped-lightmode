use super::{ObjectMetadata, ObjectStore, validate_content_addressed_bytes};
use crate::error::Result;
use async_trait::async_trait;
use sha2::Digest;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct MemoryObjectStore {
    blobs: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemoryObjectStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ObjectStore for MemoryObjectStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ObjectMetadata> {
        validate_content_addressed_bytes(key, bytes)?;
        self.blobs
            .write()
            .await
            .insert(key.to_string(), bytes.to_vec());
        Ok(ObjectMetadata {
            key: key.to_string(),
            sha256: hex::encode(sha2::Sha256::digest(bytes)),
            size_octets: bytes.len() as u64,
        })
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = self.blobs.read().await.get(key).cloned() else {
            return Ok(None);
        };
        validate_content_addressed_bytes(key, &bytes)?;
        Ok(Some(bytes))
    }

    async fn get_range(
        &self,
        key: &str,
        start: usize,
        end: Option<usize>,
    ) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = self.blobs.read().await.get(key).cloned() else {
            return Ok(None);
        };
        if start >= bytes.len() {
            return Ok(Some(Vec::new()));
        }
        let end = end.unwrap_or(bytes.len()).min(bytes.len());
        Ok(Some(bytes[start..end].to_vec()))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.blobs.write().await.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.blobs.read().await.contains_key(key))
    }
}
