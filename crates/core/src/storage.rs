use crate::error::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectType {
    Rfc822,
    MimePart,
    Attachment,
    Cache,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMetadata {
    pub key: String,
    pub sha256: String,
    pub size_octets: u64,
}

#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ObjectMetadata>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn get_range(
        &self,
        key: &str,
        start: usize,
        end: Option<usize>,
    ) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = self.get(key).await? else {
            return Ok(None);
        };
        if start >= bytes.len() {
            return Ok(Some(Vec::new()));
        }
        let end = end.unwrap_or(bytes.len()).min(bytes.len());
        Ok(Some(bytes[start..end].to_vec()))
    }
    async fn delete(&self, key: &str) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;
}

pub fn content_addressed_key(object_type: ObjectType, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:?}/{}", object_type, hex::encode(hasher.finalize()))
}

pub fn validate_content_addressed_bytes(expected_key: &str, bytes: &[u8]) -> Result<()> {
    let Some((prefix, hash)) = expected_key.split_once('/') else {
        return Err(Error::Storage(format!(
            "invalid content-addressed key: {expected_key}"
        )));
    };
    let object_type = match prefix {
        "Rfc822" => ObjectType::Rfc822,
        "MimePart" => ObjectType::MimePart,
        "Attachment" => ObjectType::Attachment,
        "Cache" => ObjectType::Cache,
        other => {
            return Err(Error::Storage(format!(
                "unknown content-addressed key prefix: {other}"
            )));
        }
    };

    let actual_key = content_addressed_key(object_type, bytes);
    if actual_key != expected_key {
        return Err(Error::Storage(format!(
            "content hash mismatch for {expected_key}: expected {hash}, got {}",
            actual_key
                .split_once('/')
                .map(|(_, value)| value)
                .unwrap_or_default()
        )));
    }
    Ok(())
}

pub fn validate_object_key(expected: &str, actual: &ObjectMetadata) -> Result<()> {
    if expected != actual.key {
        return Err(Error::Storage(format!(
            "object key mismatch: expected {expected}, got {}",
            actual.key
        )));
    }
    Ok(())
}
