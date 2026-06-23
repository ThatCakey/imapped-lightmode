use super::{ObjectMetadata, ObjectStore, validate_content_addressed_bytes};
use crate::error::Result;
use async_trait::async_trait;
use sha2::Digest;
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};

#[derive(Clone)]
pub struct FilesystemObjectStore {
    root: Arc<PathBuf>,
}

impl FilesystemObjectStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: Arc::new(root.as_ref().to_path_buf()),
        }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }
}

#[async_trait]
impl ObjectStore for FilesystemObjectStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ObjectMetadata> {
        validate_content_addressed_bytes(key, bytes)?;
        let path = self.path_for(key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut file = fs::File::create(&path).await?;
        file.write_all(bytes).await?;
        file.flush().await?;
        Ok(ObjectMetadata {
            key: key.to_string(),
            sha256: hex::encode(sha2::Sha256::digest(bytes)),
            size_octets: bytes.len() as u64,
        })
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(key);
        match fs::read(path).await {
            Ok(bytes) => {
                validate_content_addressed_bytes(key, &bytes)?;
                Ok(Some(bytes))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    async fn get_range(
        &self,
        key: &str,
        start: usize,
        end: Option<usize>,
    ) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(key);
        let mut file = match fs::File::open(path).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let metadata = file.metadata().await?;
        let len = metadata.len() as usize;
        if start >= len {
            return Ok(Some(Vec::new()));
        }
        let end = end.unwrap_or(len).min(len);
        file.seek(SeekFrom::Start(start as u64)).await?;
        let mut bytes = vec![0u8; end - start];
        file.read_exact(&mut bytes).await?;
        Ok(Some(bytes))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key);
        match fs::remove_file(path).await {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        Ok(fs::metadata(self.path_for(key)).await.is_ok())
    }
}
