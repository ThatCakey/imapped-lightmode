use anyhow::{Result, anyhow};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    path::PathBuf,
    sync::OnceLock,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestingCredentials {
    pub username: String,
    pub password: String,
    pub imap_host: String,
    pub imap_port: u16,
}

pub fn load_testing_credentials() -> Result<TestingCredentials> {
    let text = fs::read_to_string(".testing-credentials")?;
    let mut username = None;
    let mut password = None;
    let mut imap_host = None;
    let mut imap_port = None;

    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Username: ") {
            username = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("Password: ") {
            password = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("IMAP (SSL/TLS): ") {
            if let Some((host, port)) = value.trim().rsplit_once(':') {
                imap_host = Some(host.to_string());
                imap_port = Some(port.parse::<u16>()?);
            }
        }
    }

    Ok(TestingCredentials {
        username: username.ok_or_else(|| anyhow!("missing username"))?,
        password: password.ok_or_else(|| anyhow!("missing password"))?,
        imap_host: imap_host.ok_or_else(|| anyhow!("missing IMAP host"))?,
        imap_port: imap_port.ok_or_else(|| anyhow!("missing IMAP port"))?,
    })
}

pub struct LiveTestGuard {
    _file: File,
}

impl Drop for LiveTestGuard {
    fn drop(&mut self) {
        let _ = self._file.unlock();
    }
}

fn live_test_lock_path() -> PathBuf {
    static LIVE_TEST_LOCK_PATH: OnceLock<PathBuf> = OnceLock::new();
    LIVE_TEST_LOCK_PATH
        .get_or_init(|| std::env::temp_dir().join("imap-cache-rs-live-test.lock"))
        .clone()
}

pub async fn live_test_guard() -> LiveTestGuard {
    let path = live_test_lock_path();
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap_or_else(|err| panic!("failed to open live test lock file {path:?}: {err}"));
    file.lock_exclusive()
        .unwrap_or_else(|err| panic!("failed to lock live test file {path:?}: {err}"));
    LiveTestGuard { _file: file }
}
