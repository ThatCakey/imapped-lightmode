use imap_cache_core::error::{Error, Result};
use imap_cache_storage::r2::R2ConfigSource;
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

static UPSTREAM_CONNECTION_LIMIT_PER_ACCOUNT: AtomicUsize = AtomicUsize::new(2);
static IDLE_TIMEOUT_SECONDS: AtomicU64 = AtomicU64::new(1740);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FileConfig {
    app_env: Option<String>,
    app_base_url: Option<String>,
    log_level: Option<String>,
    encryption_master_key: Option<String>,
    imap_plaintext_bind: Option<String>,
    imap_tls_bind: Option<String>,
    imap_tls_cert_path: Option<String>,
    imap_tls_key_path: Option<String>,
    http_bind: Option<String>,
    metrics_bind: Option<String>,
    database_url: Option<String>,
    redis_url: Option<String>,
    r2_endpoint: Option<String>,
    r2_bucket: Option<String>,
    r2_access_key_id: Option<String>,
    r2_secret_access_key: Option<String>,
    r2_region: Option<String>,
    object_store_path: Option<String>,
    search_index_path: Option<String>,
    max_literal_size_bytes: Option<u64>,
    max_message_size_bytes: Option<u64>,
    default_account_quota_bytes: Option<u64>,
    cache_eviction_keep_latest_objects: Option<usize>,
    sync_concurrency: Option<usize>,
    idle_timeout_seconds: Option<u64>,
    upstream_connection_limit_per_account: Option<usize>,
    login_rate_limit_failures: Option<u32>,
    login_rate_limit_lockout_seconds: Option<u64>,
    bootstrap_imap_username: Option<String>,
    bootstrap_imap_password_hash: Option<String>,
    bootstrap_imap_password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub app_env: String,
    pub app_base_url: String,
    pub log_level: String,
    pub encryption_master_key: String,
    pub imap_plaintext_bind: Option<SocketAddr>,
    pub imap_tls_bind: Option<SocketAddr>,
    pub imap_tls_cert_path: Option<PathBuf>,
    pub imap_tls_key_path: Option<PathBuf>,
    pub http_bind: Option<SocketAddr>,
    pub metrics_bind: Option<SocketAddr>,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub r2_endpoint: Option<String>,
    pub r2_bucket: Option<String>,
    pub r2_access_key_id: Option<String>,
    pub r2_secret_access_key: Option<String>,
    pub r2_region: String,
    pub object_store_path: Option<PathBuf>,
    pub search_index_path: Option<PathBuf>,
    pub max_literal_size_bytes: u64,
    pub max_message_size_bytes: u64,
    pub default_account_quota_bytes: u64,
    pub cache_eviction_keep_latest_objects: usize,
    pub sync_concurrency: usize,
    pub idle_timeout_seconds: u64,
    pub upstream_connection_limit_per_account: usize,
    pub login_rate_limit_failures: u32,
    pub login_rate_limit_lockout_seconds: u64,
    pub bootstrap_imap_username: Option<String>,
    pub bootstrap_imap_password_hash: Option<String>,
    pub bootstrap_imap_password: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            app_env: "development".to_string(),
            app_base_url: "http://localhost:8080".to_string(),
            log_level: "debug".to_string(),
            encryption_master_key: "change-me-32-bytes-minimum".to_string(),
            imap_plaintext_bind: "0.0.0.0:1143".parse().ok(),
            imap_tls_bind: "0.0.0.0:1993".parse().ok(),
            imap_tls_cert_path: Some(PathBuf::from("/certs/imap.crt")),
            imap_tls_key_path: Some(PathBuf::from("/certs/imap.key")),
            http_bind: "0.0.0.0:8080".parse().ok(),
            metrics_bind: None,
            database_url: None,
            redis_url: None,
            r2_endpoint: None,
            r2_bucket: None,
            r2_access_key_id: None,
            r2_secret_access_key: None,
            r2_region: "auto".to_string(),
            object_store_path: Some(PathBuf::from("./data/blob")),
            search_index_path: Some(PathBuf::from("./data/search")),
            max_literal_size_bytes: 50 * 1024 * 1024,
            max_message_size_bytes: 100 * 1024 * 1024,
            default_account_quota_bytes: 10 * 1024 * 1024 * 1024,
            cache_eviction_keep_latest_objects: 0,
            sync_concurrency: 4,
            idle_timeout_seconds: 1740,
            upstream_connection_limit_per_account: 2,
            login_rate_limit_failures: 5,
            login_rate_limit_lockout_seconds: 60,
            bootstrap_imap_username: None,
            bootstrap_imap_password_hash: None,
            bootstrap_imap_password: None,
        }
    }
}

impl Config {
    pub fn load(config_path: Option<&Path>) -> Result<Self> {
        let mut config = Self::default();

        let config_path = config_path
            .map(Path::to_path_buf)
            .or_else(|| env::var_os("APP_CONFIG_PATH").map(PathBuf::from));

        if let Some(path) = config_path.as_ref() {
            if path.exists() {
                let text = fs::read_to_string(path)?;
                let file_config: FileConfig = toml::from_str(&text)?;
                config.apply_file_config(file_config)?;
            }
        }

        config.apply_env()?;
        Ok(config)
    }

    fn apply_file_config(&mut self, file: FileConfig) -> Result<()> {
        if let Some(value) = file.app_env {
            self.app_env = value;
        }
        if let Some(value) = file.app_base_url {
            self.app_base_url = value;
        }
        if let Some(value) = file.log_level {
            self.log_level = value;
        }
        if let Some(value) = file.encryption_master_key {
            self.encryption_master_key = value;
        }
        if let Some(value) = file.imap_plaintext_bind {
            self.imap_plaintext_bind = Some(
                value
                    .parse()
                    .map_err(|e| Error::Config(format!("invalid imap_plaintext_bind: {e}")))?,
            );
        }
        if let Some(value) = file.imap_tls_bind {
            self.imap_tls_bind = Some(
                value
                    .parse()
                    .map_err(|e| Error::Config(format!("invalid imap_tls_bind: {e}")))?,
            );
        }
        if let Some(value) = file.imap_tls_cert_path {
            self.imap_tls_cert_path = Some(value.into());
        }
        if let Some(value) = file.imap_tls_key_path {
            self.imap_tls_key_path = Some(value.into());
        }
        if let Some(value) = file.http_bind {
            self.http_bind = Some(
                value
                    .parse()
                    .map_err(|e| Error::Config(format!("invalid http_bind: {e}")))?,
            );
        }
        if let Some(value) = file.metrics_bind {
            self.metrics_bind = Some(
                value
                    .parse()
                    .map_err(|e| Error::Config(format!("invalid metrics_bind: {e}")))?,
            );
        }
        if let Some(value) = file.database_url {
            self.database_url = Some(value);
        }
        if let Some(value) = file.redis_url {
            self.redis_url = Some(value);
        }
        if let Some(value) = file.r2_endpoint {
            self.r2_endpoint = Some(value);
        }
        if let Some(value) = file.r2_bucket {
            self.r2_bucket = Some(value);
        }
        if let Some(value) = file.r2_access_key_id {
            self.r2_access_key_id = Some(value);
        }
        if let Some(value) = file.r2_secret_access_key {
            self.r2_secret_access_key = Some(value);
        }
        if let Some(value) = file.r2_region {
            self.r2_region = value;
        }
        if let Some(value) = file.object_store_path {
            self.object_store_path = Some(value.into());
        }
        if let Some(value) = file.search_index_path {
            self.search_index_path = Some(value.into());
        }
        if let Some(value) = file.max_literal_size_bytes {
            self.max_literal_size_bytes = value;
        }
        if let Some(value) = file.max_message_size_bytes {
            self.max_message_size_bytes = value;
        }
        if let Some(value) = file.default_account_quota_bytes {
            self.default_account_quota_bytes = value;
        }
        if let Some(value) = file.cache_eviction_keep_latest_objects {
            self.cache_eviction_keep_latest_objects = value;
        }
        if let Some(value) = file.sync_concurrency {
            self.sync_concurrency = value;
        }
        if let Some(value) = file.idle_timeout_seconds {
            self.idle_timeout_seconds = value;
        }
        if let Some(value) = file.upstream_connection_limit_per_account {
            self.upstream_connection_limit_per_account = value;
        }
        if let Some(value) = file.login_rate_limit_failures {
            self.login_rate_limit_failures = value;
        }
        if let Some(value) = file.login_rate_limit_lockout_seconds {
            self.login_rate_limit_lockout_seconds = value;
        }
        if let Some(value) = file.bootstrap_imap_username {
            self.bootstrap_imap_username = Some(value);
        }
        if let Some(value) = file.bootstrap_imap_password_hash {
            self.bootstrap_imap_password_hash = Some(value);
        }
        if let Some(value) = file.bootstrap_imap_password {
            self.bootstrap_imap_password = Some(value);
        }
        Ok(())
    }

    fn apply_env(&mut self) -> Result<()> {
        self.app_env = env_or("APP_ENV", &self.app_env);
        self.app_base_url = env_or("APP_BASE_URL", &self.app_base_url);
        self.log_level = env_or("LOG_LEVEL", &self.log_level);
        self.encryption_master_key = env_or("ENCRYPTION_MASTER_KEY", &self.encryption_master_key);
        self.imap_plaintext_bind = parse_socket("IMAP_PLAINTEXT_BIND", self.imap_plaintext_bind)?;
        self.imap_tls_bind = parse_socket("IMAP_TLS_BIND", self.imap_tls_bind)?;
        self.imap_tls_cert_path = env::var_os("IMAP_TLS_CERT_PATH")
            .map(PathBuf::from)
            .or_else(|| self.imap_tls_cert_path.clone());
        self.imap_tls_key_path = env::var_os("IMAP_TLS_KEY_PATH")
            .map(PathBuf::from)
            .or_else(|| self.imap_tls_key_path.clone());
        self.http_bind = parse_socket("HTTP_BIND", self.http_bind)?;
        self.metrics_bind = parse_socket("METRICS_BIND", self.metrics_bind)?;
        self.database_url = env::var("DATABASE_URL")
            .ok()
            .or_else(|| self.database_url.clone());
        self.redis_url = env::var("REDIS_URL")
            .ok()
            .or_else(|| self.redis_url.clone());
        self.r2_endpoint = env::var("R2_ENDPOINT")
            .ok()
            .or_else(|| self.r2_endpoint.clone());
        self.r2_bucket = env::var("R2_BUCKET")
            .ok()
            .or_else(|| self.r2_bucket.clone());
        self.r2_access_key_id = env::var("R2_ACCESS_KEY_ID")
            .ok()
            .or_else(|| self.r2_access_key_id.clone());
        self.r2_secret_access_key = env::var("R2_SECRET_ACCESS_KEY")
            .ok()
            .or_else(|| self.r2_secret_access_key.clone());
        self.r2_region = env_or("R2_REGION", &self.r2_region);
        self.object_store_path = env::var_os("OBJECT_STORE_PATH")
            .map(PathBuf::from)
            .or_else(|| self.object_store_path.clone());
        self.search_index_path = env::var_os("SEARCH_INDEX_PATH")
            .map(PathBuf::from)
            .or_else(|| self.search_index_path.clone());
        self.max_literal_size_bytes =
            env_num("MAX_LITERAL_SIZE_BYTES", self.max_literal_size_bytes)?;
        self.max_message_size_bytes =
            env_num("MAX_MESSAGE_SIZE_BYTES", self.max_message_size_bytes)?;
        self.default_account_quota_bytes = env_num(
            "DEFAULT_ACCOUNT_QUOTA_BYTES",
            self.default_account_quota_bytes,
        )?;
        self.cache_eviction_keep_latest_objects = env_num(
            "CACHE_EVICTION_KEEP_LATEST_OBJECTS",
            self.cache_eviction_keep_latest_objects,
        )?;
        self.sync_concurrency = env_num("SYNC_CONCURRENCY", self.sync_concurrency)?;
        self.idle_timeout_seconds = env_num("IDLE_TIMEOUT_SECONDS", self.idle_timeout_seconds)?;
        self.upstream_connection_limit_per_account = env_num(
            "UPSTREAM_CONNECTION_LIMIT_PER_ACCOUNT",
            self.upstream_connection_limit_per_account,
        )?;
        self.login_rate_limit_failures =
            env_num("LOGIN_RATE_LIMIT_FAILURES", self.login_rate_limit_failures)?;
        self.login_rate_limit_lockout_seconds = env_num(
            "LOGIN_RATE_LIMIT_LOCKOUT_SECONDS",
            self.login_rate_limit_lockout_seconds,
        )?;
        self.bootstrap_imap_username = env::var("BOOTSTRAP_IMAP_USERNAME")
            .ok()
            .or_else(|| self.bootstrap_imap_username.clone());
        self.bootstrap_imap_password_hash = env::var("BOOTSTRAP_IMAP_PASSWORD_HASH")
            .ok()
            .or_else(|| self.bootstrap_imap_password_hash.clone());
        self.bootstrap_imap_password = env::var("BOOTSTRAP_IMAP_PASSWORD")
            .ok()
            .or_else(|| self.bootstrap_imap_password.clone());
        Ok(())
    }

    pub fn tls_material_configured(&self) -> bool {
        self.imap_tls_cert_path
            .as_ref()
            .is_some_and(|path| path.exists())
            && self
                .imap_tls_key_path
                .as_ref()
                .is_some_and(|path| path.exists())
    }
}

impl R2ConfigSource for Config {
    fn r2_endpoint(&self) -> Option<String> {
        self.r2_endpoint.clone()
    }

    fn r2_bucket(&self) -> Option<String> {
        self.r2_bucket.clone()
    }

    fn r2_access_key_id(&self) -> Option<String> {
        self.r2_access_key_id.clone()
    }

    fn r2_secret_access_key(&self) -> Option<String> {
        self.r2_secret_access_key.clone()
    }

    fn r2_region(&self) -> String {
        self.r2_region.clone()
    }
}

pub fn set_upstream_connection_limit_per_account(limit: usize) {
    UPSTREAM_CONNECTION_LIMIT_PER_ACCOUNT.store(limit, Ordering::Relaxed);
}

pub fn upstream_connection_limit_per_account() -> usize {
    UPSTREAM_CONNECTION_LIMIT_PER_ACCOUNT.load(Ordering::Relaxed)
}

pub fn set_idle_timeout_seconds(timeout_seconds: u64) {
    IDLE_TIMEOUT_SECONDS.store(timeout_seconds, Ordering::Relaxed);
}

pub fn idle_timeout_seconds() -> u64 {
    IDLE_TIMEOUT_SECONDS.load(Ordering::Relaxed)
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_num<T>(name: &str, default: T) -> Result<T>
where
    T: std::str::FromStr + Copy,
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|e| Error::Config(format!("invalid {name}: {e}"))),
        Err(_) => Ok(default),
    }
}

fn parse_socket(name: &str, default: Option<SocketAddr>) -> Result<Option<SocketAddr>> {
    match env::var(name) {
        Ok(value) => {
            Ok(Some(value.parse().map_err(|e| {
                Error::Config(format!("invalid {name}: {e}"))
            })?))
        }
        Err(_) => Ok(default),
    }
}
