use imap_cache_rs::config::Config;
use std::{fs, path::Path};
use tempfile::tempdir;

#[test]
fn loads_config_from_toml_and_env_overlay() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        r#"
app_env = "production"
log_level = "warn"
imap_plaintext_bind = "127.0.0.1:1144"
max_literal_size_bytes = 1024
login_rate_limit_failures = 11
login_rate_limit_lockout_seconds = 120
"#,
    )
    .unwrap();

    let original_app_base_url = std::env::var("APP_BASE_URL").ok();
    let original_sync_concurrency = std::env::var("SYNC_CONCURRENCY").ok();
    let original_idle_timeout_seconds = std::env::var("IDLE_TIMEOUT_SECONDS").ok();
    let original_metrics_bind = std::env::var("METRICS_BIND").ok();
    let original_upstream_connection_limit_per_account =
        std::env::var("UPSTREAM_CONNECTION_LIMIT_PER_ACCOUNT").ok();
    let original_object_store_path = std::env::var("OBJECT_STORE_PATH").ok();
    let original_login_rate_limit_failures = std::env::var("LOGIN_RATE_LIMIT_FAILURES").ok();
    let original_login_rate_limit_lockout_seconds =
        std::env::var("LOGIN_RATE_LIMIT_LOCKOUT_SECONDS").ok();

    unsafe {
        std::env::set_var("APP_BASE_URL", "https://example.test");
        std::env::set_var("SYNC_CONCURRENCY", "8");
        std::env::set_var("IDLE_TIMEOUT_SECONDS", "12");
        std::env::set_var("METRICS_BIND", "127.0.0.1:9099");
        std::env::set_var("UPSTREAM_CONNECTION_LIMIT_PER_ACCOUNT", "7");
        std::env::set_var("OBJECT_STORE_PATH", "./var/blob");
        std::env::set_var("LOGIN_RATE_LIMIT_FAILURES", "7");
        std::env::set_var("LOGIN_RATE_LIMIT_LOCKOUT_SECONDS", "90");
    }

    let config = Config::load(Some(Path::new(&path))).unwrap();

    assert_eq!(config.app_env, "production");
    assert_eq!(config.app_base_url, "https://example.test");
    assert_eq!(config.log_level, "warn");
    assert_eq!(config.max_literal_size_bytes, 1024);
    assert_eq!(config.sync_concurrency, 8);
    assert_eq!(config.idle_timeout_seconds, 12);
    assert_eq!(config.metrics_bind.unwrap().to_string(), "127.0.0.1:9099");
    assert_eq!(config.upstream_connection_limit_per_account, 7);
    assert_eq!(config.login_rate_limit_failures, 7);
    assert_eq!(config.login_rate_limit_lockout_seconds, 90);
    assert_eq!(
        config.object_store_path.as_deref(),
        Some(Path::new("./var/blob"))
    );

    unsafe {
        match original_app_base_url {
            Some(value) => std::env::set_var("APP_BASE_URL", value),
            None => std::env::remove_var("APP_BASE_URL"),
        }
        match original_sync_concurrency {
            Some(value) => std::env::set_var("SYNC_CONCURRENCY", value),
            None => std::env::remove_var("SYNC_CONCURRENCY"),
        }
        match original_idle_timeout_seconds {
            Some(value) => std::env::set_var("IDLE_TIMEOUT_SECONDS", value),
            None => std::env::remove_var("IDLE_TIMEOUT_SECONDS"),
        }
        match original_metrics_bind {
            Some(value) => std::env::set_var("METRICS_BIND", value),
            None => std::env::remove_var("METRICS_BIND"),
        }
        match original_upstream_connection_limit_per_account {
            Some(value) => std::env::set_var("UPSTREAM_CONNECTION_LIMIT_PER_ACCOUNT", value),
            None => std::env::remove_var("UPSTREAM_CONNECTION_LIMIT_PER_ACCOUNT"),
        }
        match original_object_store_path {
            Some(value) => std::env::set_var("OBJECT_STORE_PATH", value),
            None => std::env::remove_var("OBJECT_STORE_PATH"),
        }
        match original_login_rate_limit_failures {
            Some(value) => std::env::set_var("LOGIN_RATE_LIMIT_FAILURES", value),
            None => std::env::remove_var("LOGIN_RATE_LIMIT_FAILURES"),
        }
        match original_login_rate_limit_lockout_seconds {
            Some(value) => std::env::set_var("LOGIN_RATE_LIMIT_LOCKOUT_SECONDS", value),
            None => std::env::remove_var("LOGIN_RATE_LIMIT_LOCKOUT_SECONDS"),
        }
    }
}
