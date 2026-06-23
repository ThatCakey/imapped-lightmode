use imap_cache_config::Config;
use imap_cache_core::{error::{Error, Result}, security};
use imap_cache_db::repository::PostgresRepository;
use async_trait::async_trait;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: i64,
    pub account_id: Option<i64>,
    pub username: String,
}

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, username: &str, password: &str) -> Result<Option<AuthContext>>;
}

#[derive(Debug, Clone)]
pub struct DenyAllAuthenticator;

#[async_trait]
impl Authenticator for DenyAllAuthenticator {
    async fn authenticate(&self, _username: &str, _password: &str) -> Result<Option<AuthContext>> {
        Ok(None)
    }
}

#[derive(Clone)]
pub struct StaticAuthenticator {
    expected_username: String,
    expected_password_hash: String,
    user_id: i64,
    throttle: Arc<dyn LoginThrottle>,
}

#[derive(Clone)]
pub struct PostgresAuthenticator {
    repository: Arc<PostgresRepository>,
    throttle: Arc<dyn LoginThrottle>,
}

#[derive(Debug)]
struct AttemptState {
    failures: u32,
    blocked_until: Option<Instant>,
}

#[async_trait]
trait LoginThrottle: Send + Sync {
    async fn is_blocked(&self, username: &str) -> Result<bool>;
    async fn record_failure(&self, username: &str) -> Result<()>;
    async fn record_success(&self, username: &str) -> Result<()>;
}

struct MemoryLoginThrottle {
    attempts: AsyncMutex<HashMap<String, AttemptState>>,
    max_failures: u32,
    lockout: Duration,
}

struct RedisLoginThrottle {
    client: redis::Client,
    max_failures: u32,
    lockout: Duration,
    namespace: String,
}

impl MemoryLoginThrottle {
    fn new() -> Self {
        Self::with_limits(5, Duration::from_secs(60))
    }

    fn with_limits(max_failures: u32, lockout: Duration) -> Self {
        Self {
            attempts: AsyncMutex::new(HashMap::new()),
            max_failures,
            lockout,
        }
    }
}

impl RedisLoginThrottle {
    fn with_limits(client: redis::Client, max_failures: u32, lockout: Duration) -> Self {
        Self {
            client,
            max_failures,
            lockout,
            namespace: "imap-cache-rs:login".to_string(),
        }
    }

    fn blocked_key(&self, username: &str) -> String {
        format!("{}:blocked:{}", self.namespace, username)
    }

    fn failures_key(&self, username: &str) -> String {
        format!("{}:failures:{}", self.namespace, username)
    }

    fn lockout_seconds(&self) -> i64 {
        self.lockout.as_secs().max(1) as i64
    }
}

#[async_trait]
impl LoginThrottle for MemoryLoginThrottle {
    async fn is_blocked(&self, username: &str) -> Result<bool> {
        let username = username.to_ascii_lowercase();
        let mut attempts = self.attempts.lock().await;
        let now = Instant::now();
        let Some(state) = attempts.get_mut(&username) else {
            return Ok(false);
        };
        if let Some(blocked_until) = state.blocked_until {
            if blocked_until > now {
                return Ok(true);
            }
            state.blocked_until = None;
            state.failures = 0;
        }
        Ok(false)
    }

    async fn record_failure(&self, username: &str) -> Result<()> {
        let username = username.to_ascii_lowercase();
        let mut attempts = self.attempts.lock().await;
        let now = Instant::now();
        let state = attempts.entry(username).or_insert(AttemptState {
            failures: 0,
            blocked_until: None,
        });
        if let Some(blocked_until) = state.blocked_until {
            if blocked_until > now {
                return Ok(());
            }
            state.blocked_until = None;
            state.failures = 0;
        }
        state.failures = state.failures.saturating_add(1);
        if state.failures >= self.max_failures {
            state.blocked_until = Some(now + self.lockout);
            state.failures = 0;
        }
        Ok(())
    }

    async fn record_success(&self, username: &str) -> Result<()> {
        let username = username.to_ascii_lowercase();
        let mut attempts = self.attempts.lock().await;
        attempts.remove(&username);
        Ok(())
    }
}

#[async_trait]
impl LoginThrottle for RedisLoginThrottle {
    async fn is_blocked(&self, username: &str) -> Result<bool> {
        let username = username.to_ascii_lowercase();
        let blocked_key = self.blocked_key(&username);
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| Error::Storage(format!("connecting to redis: {err}")))?;
        let blocked: i64 = redis::cmd("EXISTS")
            .arg(&blocked_key)
            .query_async(&mut connection)
            .await
            .map_err(|err| Error::Storage(format!("checking login throttle in redis: {err}")))?;
        Ok(blocked > 0)
    }

    async fn record_failure(&self, username: &str) -> Result<()> {
        let username = username.to_ascii_lowercase();
        let blocked_key = self.blocked_key(&username);
        let failures_key = self.failures_key(&username);
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| Error::Storage(format!("connecting to redis: {err}")))?;
        let script = redis::Script::new(
            r#"
            if redis.call("EXISTS", KEYS[1]) == 1 then
                return -1
            end
            local failures = redis.call("INCR", KEYS[2])
            if failures == 1 then
                redis.call("EXPIRE", KEYS[2], ARGV[1])
            end
            if failures >= tonumber(ARGV[2]) then
                redis.call("SET", KEYS[1], "1", "EX", ARGV[1])
                redis.call("DEL", KEYS[2])
                return 1
            end
            return failures
            "#,
        );
        let _: i64 = script
            .key(&blocked_key)
            .key(&failures_key)
            .arg(self.lockout_seconds())
            .arg(self.max_failures)
            .invoke_async(&mut connection)
            .await
            .map_err(|err| Error::Storage(format!("updating login throttle in redis: {err}")))?;
        Ok(())
    }

    async fn record_success(&self, username: &str) -> Result<()> {
        let username = username.to_ascii_lowercase();
        let blocked_key = self.blocked_key(&username);
        let failures_key = self.failures_key(&username);
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| Error::Storage(format!("connecting to redis: {err}")))?;
        let _: i64 = redis::cmd("DEL")
            .arg(&blocked_key)
            .query_async(&mut connection)
            .await
            .map_err(|err| Error::Storage(format!("clearing login throttle in redis: {err}")))?;
        let _: i64 = redis::cmd("DEL")
            .arg(&failures_key)
            .query_async(&mut connection)
            .await
            .map_err(|err| Error::Storage(format!("clearing login throttle in redis: {err}")))?;
        Ok(())
    }
}

impl StaticAuthenticator {
    pub fn new(expected_username: String, expected_password_hash: String) -> Self {
        Self::with_throttle(
            expected_username,
            expected_password_hash,
            Arc::new(MemoryLoginThrottle::new()),
        )
    }

    fn with_throttle(
        expected_username: String,
        expected_password_hash: String,
        throttle: Arc<dyn LoginThrottle>,
    ) -> Self {
        Self {
            expected_username,
            expected_password_hash,
            user_id: 1,
            throttle,
        }
    }
}

impl PostgresAuthenticator {
    pub fn new(repository: Arc<PostgresRepository>) -> Self {
        Self::with_throttle(repository, Arc::new(MemoryLoginThrottle::new()))
    }

    fn with_throttle(
        repository: Arc<PostgresRepository>,
        throttle: Arc<dyn LoginThrottle>,
    ) -> Self {
        Self {
            repository,
            throttle,
        }
    }
}

#[async_trait]
impl Authenticator for StaticAuthenticator {
    async fn authenticate(&self, username: &str, password: &str) -> Result<Option<AuthContext>> {
        if self.throttle.is_blocked(username).await? {
            return Ok(None);
        }
        if username == self.expected_username
            && security::verify_password(&self.expected_password_hash, password)?
        {
            self.throttle.record_success(username).await?;
            Ok(Some(AuthContext {
                user_id: self.user_id,
                account_id: None,
                username: username.to_string(),
            }))
        } else {
            self.throttle.record_failure(username).await?;
            Ok(None)
        }
    }
}

#[async_trait]
impl Authenticator for PostgresAuthenticator {
    async fn authenticate(&self, username: &str, password: &str) -> Result<Option<AuthContext>> {
        if self.throttle.is_blocked(username).await? {
            return Ok(None);
        }
        let Some(user) = self.repository.find_user_by_username(username).await? else {
            self.throttle.record_failure(username).await?;
            let _ = self
                .repository
                .record_audit_log(
                    None,
                    None,
                    "login_failure",
                    json!({"username_email": username, "reason": "user_not_found"}),
                )
                .await;
            return Ok(None);
        };
        if user.disabled_at.is_some() {
            let _ = self
                .repository
                .record_audit_log(
                    Some(user.id),
                    None,
                    "login_failure",
                    json!({"username_email": username, "reason": "user_disabled"}),
                )
                .await;
            return Ok(None);
        }
        if !security::verify_password(&user.password_hash, password)? {
            self.throttle.record_failure(username).await?;
            let _ = self
                .repository
                .record_audit_log(
                    Some(user.id),
                    None,
                    "login_failure",
                    json!({"username_email": username, "reason": "invalid_password"}),
                )
                .await;
            return Ok(None);
        }
        self.throttle.record_success(username).await?;

        let account_id = if let Some(account) = self
            .repository
            .find_account_by_email_address(username)
            .await?
        {
            Some(account.id)
        } else {
            let accounts = self.repository.list_accounts_for_user(user.id).await?;
            if accounts.len() == 1 {
                Some(accounts[0].id)
            } else {
                None
            }
        };

        let context = AuthContext {
            user_id: user.id,
            account_id,
            username: user.username_email,
        };
        let _ = self
            .repository
            .record_audit_log(
                Some(context.user_id),
                context.account_id,
                "login_success",
                json!({"username_email": context.username}),
            )
            .await;
        Ok(Some(context))
    }
}

pub fn bootstrap_authenticator(
    config: &Config,
    repository: Option<Arc<PostgresRepository>>,
) -> Result<Arc<dyn Authenticator>> {
    let throttle: Arc<dyn LoginThrottle> = if let Some(redis_url) = config.redis_url.as_deref() {
        Arc::new(RedisLoginThrottle::with_limits(
            redis::Client::open(redis_url).map_err(|err| {
                Error::Storage(format!("connecting to redis at {redis_url}: {err}"))
            })?,
            config.login_rate_limit_failures,
            Duration::from_secs(config.login_rate_limit_lockout_seconds),
        ))
    } else {
        Arc::new(MemoryLoginThrottle::with_limits(
            config.login_rate_limit_failures,
            Duration::from_secs(config.login_rate_limit_lockout_seconds),
        ))
    };

    match (
        &config.bootstrap_imap_username,
        &config.bootstrap_imap_password_hash,
        &config.bootstrap_imap_password,
    ) {
        (Some(username), Some(password_hash), _) => {
            Ok(Arc::new(StaticAuthenticator::with_throttle(
                username.clone(),
                password_hash.clone(),
                Arc::clone(&throttle),
            )))
        }
        (Some(username), None, Some(password)) => Ok(Arc::new(StaticAuthenticator::with_throttle(
            username.clone(),
            security::hash_password(password)?,
            Arc::clone(&throttle),
        ))),
        _ => match repository {
            Some(repository) => Ok(Arc::new(PostgresAuthenticator::with_throttle(
                repository, throttle,
            ))),
            None => Ok(Arc::new(DenyAllAuthenticator)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imap_cache_core::domain::{UpstreamAuthMethod, UpstreamTlsMode};
    use imap_cache_db::{
        repository::{NewMailAccount, NewUser, PostgresRepository},
        run_migrations,
    };
    use imap_cache_core::security::SecretBox;
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    #[tokio::test]
    async fn static_authenticator_rate_limits_repeated_failures() {
        let authenticator = StaticAuthenticator::new(
            "user@example.test".to_string(),
            security::hash_password("secret-password").unwrap(),
        );

        for _ in 0..5 {
            assert!(
                authenticator
                    .authenticate("user@example.test", "wrong-password")
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        assert!(
            authenticator
                .authenticate("user@example.test", "secret-password")
                .await
                .unwrap()
                .is_none(),
            "account should be temporarily blocked after repeated failures"
        );
    }

    async fn connect_pool() -> anyhow::Result<sqlx::PgPool> {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
        });
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await?;
        run_migrations(&pool).await?;
        Ok(pool)
    }

    #[tokio::test]
    async fn postgres_authenticator_records_login_audit_events() -> anyhow::Result<()> {
        let pool = connect_pool().await?;
        let repo = PostgresRepository::new(pool, SecretBox::from_passphrase("test-master-key"));
        let authenticator = PostgresAuthenticator::new(std::sync::Arc::new(repo.clone()));

        let email = format!("auth-audit-{}@example.com", Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &email,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let _account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Auth Audit",
                email_address: &email,
                upstream_host: "imap.example.com",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;

        assert!(
            authenticator
                .authenticate(&email, "wrong-password")
                .await?
                .is_none()
        );
        let context = authenticator
            .authenticate(&email, "secret-password")
            .await?
            .expect("successful login");
        assert_eq!(context.user_id, user.id);
        assert_eq!(context.username, email);
        assert_eq!(context.account_id.is_some(), true);

        let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
            "SELECT action, metadata_json FROM audit_log WHERE user_id = $1 ORDER BY id",
        )
        .bind(user.id)
        .fetch_all(repo.pool())
        .await?;
        let actions: Vec<String> = rows.iter().map(|(action, _)| action.clone()).collect();
        assert!(actions.contains(&"login_failure".to_string()));
        assert!(actions.contains(&"login_success".to_string()));
        let failure_reason = rows
            .iter()
            .find(|(action, _)| action == "login_failure")
            .map(|(_, metadata)| metadata["reason"].as_str().unwrap().to_string())
            .expect("login_failure audit row");
        assert_eq!(failure_reason, "invalid_password");
        let success_username = rows
            .iter()
            .find(|(action, _)| action == "login_success")
            .map(|(_, metadata)| metadata["username_email"].as_str().unwrap().to_string())
            .expect("login_success audit row");
        assert_eq!(success_username, email);

        Ok(())
    }
}
