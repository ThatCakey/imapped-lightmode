use imap_cache_core::error::{Error, Result};
use imap_cache_core::storage::{ObjectMetadata, ObjectStore, validate_content_addressed_bytes};
use async_trait::async_trait;
use aws_credential_types::Credentials;
use aws_sdk_s3::{Client, config::Region, primitives::ByteStream};
use aws_sdk_s3::operation::{get_object::GetObjectError, head_object::HeadObjectError};
use aws_smithy_runtime_api::client::{orchestrator::HttpResponse, result::SdkError};
use sha2::Digest;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct R2Config {
    pub endpoint: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
}

impl R2Config {
    pub fn is_complete(&self) -> bool {
        !self.endpoint.is_empty()
            && !self.bucket.is_empty()
            && !self.access_key_id.is_empty()
            && !self.secret_access_key.is_empty()
            && !self.region.is_empty()
    }

    pub fn from_app_config(config: &impl R2ConfigSource) -> Option<Self> {
        Some(Self {
            endpoint: config.r2_endpoint()?,
            bucket: config.r2_bucket()?,
            access_key_id: config.r2_access_key_id()?,
            secret_access_key: config.r2_secret_access_key()?,
            region: config.r2_region(),
        })
    }
}

pub trait R2ConfigSource {
    fn r2_endpoint(&self) -> Option<String>;
    fn r2_bucket(&self) -> Option<String>;
    fn r2_access_key_id(&self) -> Option<String>;
    fn r2_secret_access_key(&self) -> Option<String>;
    fn r2_region(&self) -> String;
}

#[derive(Clone)]
pub struct S3ObjectStore {
    client: Arc<Client>,
    bucket: String,
}

impl S3ObjectStore {
    pub async fn from_config(config: &R2Config) -> Result<Self> {
        if !config.is_complete() {
            return Err(Error::Config("incomplete R2 configuration".to_string()));
        }

        let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .credentials_provider(Credentials::new(
                config.access_key_id.clone(),
                config.secret_access_key.clone(),
                None,
                None,
                "static-r2",
            ))
            .region(Region::new(config.region.clone()))
            .load()
            .await;

        let client_config = aws_sdk_s3::config::Builder::from(&shared_config)
            .endpoint_url(config.endpoint.clone())
            .force_path_style(true)
            .build();

        Ok(Self {
            client: Arc::new(Client::from_conf(client_config)),
            bucket: config.bucket.clone(),
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    fn is_head_not_found(err: &SdkError<HeadObjectError, HttpResponse>) -> bool {
        err.as_service_error().is_some_and(|err| err.is_not_found())
    }

    fn is_get_not_found(err: &SdkError<GetObjectError, HttpResponse>) -> bool {
        err.as_service_error()
            .is_some_and(|err| err.is_no_such_key())
    }
}

#[async_trait]
impl ObjectStore for S3ObjectStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<ObjectMetadata> {
        validate_content_addressed_bytes(key, bytes)?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes.to_vec()))
            .send()
            .await
            .map_err(|e| Error::Storage(format!("S3 put_object failed: {e}")))?;

        Ok(ObjectMetadata {
            key: key.to_string(),
            sha256: hex::encode(sha2::Sha256::digest(bytes)),
            size_octets: bytes.len() as u64,
        })
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => {}
            Err(err) if Self::is_head_not_found(&err) => return Ok(None),
            Err(err) => {
                return Err(Error::Storage(format!("S3 head_object failed: {err}")));
            }
        }

        let output = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(err) if Self::is_get_not_found(&err) => return Ok(None),
            Err(err) => {
                return Err(Error::Storage(format!("S3 get_object failed: {err}")));
            }
        };

        let bytes = output
            .body
            .collect()
            .await
            .map_err(|e| Error::Storage(format!("S3 body collection failed: {e}")))?
            .into_bytes()
            .to_vec();
        validate_content_addressed_bytes(key, &bytes)?;
        Ok(Some(bytes))
    }

    async fn get_range(
        &self,
        key: &str,
        start: usize,
        end: Option<usize>,
    ) -> Result<Option<Vec<u8>>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => {}
            Err(err) if Self::is_head_not_found(&err) => return Ok(None),
            Err(err) => {
                return Err(Error::Storage(format!("S3 head_object failed: {err}")));
            }
        }

        let range = match end {
            Some(end) if end > 0 && end > start => format!("bytes={start}-{}", end - 1),
            Some(_) => return Ok(Some(Vec::new())),
            None => format!("bytes={start}-"),
        };
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(range)
            .send()
            .await
            .map_err(|e| Error::Storage(format!("S3 ranged get_object failed: {e}")))?;
        let bytes = output
            .body
            .collect()
            .await
            .map_err(|e| Error::Storage(format!("S3 ranged body collection failed: {e}")))?
            .into_bytes()
            .to_vec();
        Ok(Some(bytes))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| Error::Storage(format!("S3 delete_object failed: {e}")))?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err) if Self::is_head_not_found(&err) => Ok(false),
            Err(err) => Err(Error::Storage(format!("S3 head_object failed: {err}"))),
        }
    }
}
