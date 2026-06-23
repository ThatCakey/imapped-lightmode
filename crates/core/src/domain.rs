use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UpstreamTlsMode {
    Plain,
    StartTls,
    Tls,
}

impl fmt::Display for UpstreamTlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            UpstreamTlsMode::Plain => "plain",
            UpstreamTlsMode::StartTls => "starttls",
            UpstreamTlsMode::Tls => "tls",
        };
        f.write_str(value)
    }
}

impl FromStr for UpstreamTlsMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "plain" => Ok(UpstreamTlsMode::Plain),
            "starttls" => Ok(UpstreamTlsMode::StartTls),
            "tls" => Ok(UpstreamTlsMode::Tls),
            _ => Err("invalid upstream TLS mode"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UpstreamAuthMethod {
    Login,
    OAuth2,
    XOAuth2,
}

impl fmt::Display for UpstreamAuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            UpstreamAuthMethod::Login => "login",
            UpstreamAuthMethod::OAuth2 => "oauth2",
            UpstreamAuthMethod::XOAuth2 => "xoauth2",
        };
        f.write_str(value)
    }
}

impl FromStr for UpstreamAuthMethod {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "login" => Ok(UpstreamAuthMethod::Login),
            "oauth2" => Ok(UpstreamAuthMethod::OAuth2),
            "xoauth2" | "xoauth" => Ok(UpstreamAuthMethod::XOAuth2),
            _ => Err("invalid upstream auth method"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MutationStatus {
    Pending,
    InFlight,
    Succeeded,
    Failed,
    DeadLetter,
}

impl fmt::Display for MutationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            MutationStatus::Pending => "pending",
            MutationStatus::InFlight => "in_flight",
            MutationStatus::Succeeded => "succeeded",
            MutationStatus::Failed => "failed",
            MutationStatus::DeadLetter => "dead_letter",
        };
        f.write_str(value)
    }
}

impl FromStr for MutationStatus {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "pending" => Ok(MutationStatus::Pending),
            "in_flight" | "inflight" => Ok(MutationStatus::InFlight),
            "succeeded" => Ok(MutationStatus::Succeeded),
            "failed" => Ok(MutationStatus::Failed),
            "dead_letter" | "deadletter" => Ok(MutationStatus::DeadLetter),
            _ => Err("invalid mutation status"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuotaScope {
    User,
    Account,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username_email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailAccount {
    pub id: i64,
    pub user_id: i64,
    pub display_name: String,
    pub email_address: String,
    pub upstream_host: String,
    pub upstream_port: i32,
    pub upstream_tls_mode: UpstreamTlsMode,
    pub upstream_auth_method: UpstreamAuthMethod,
    pub encrypted_upstream_username: Vec<u8>,
    pub encrypted_upstream_secret: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mailbox {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub canonical_name: String,
    pub delimiter: Option<String>,
    pub attributes: Vec<String>,
    pub subscribed: bool,
    pub special_use: Option<String>,
    pub uidvalidity: Option<i64>,
    pub uidnext: Option<i64>,
    pub highestmodseq: Option<i64>,
    pub exists_count: i64,
    pub recent_count: i64,
    pub unseen_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: i64,
    pub account_id: i64,
    pub rfc822_blob_key: String,
    pub rfc822_sha256: String,
    pub message_id_header: Option<String>,
    pub subject: Option<String>,
    pub from_json: Value,
    pub to_json: Value,
    pub cc_json: Value,
    pub bcc_json: Value,
    pub reply_to_json: Value,
    pub envelope_json: Value,
    pub bodystructure_json: Value,
    pub internal_date: Option<DateTime<Utc>>,
    pub sent_date: Option<DateTime<Utc>>,
    pub size_octets: i64,
    pub text_preview: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxMessage {
    pub id: i64,
    pub mailbox_id: i64,
    pub message_id: i64,
    pub local_uid: i64,
    pub upstream_uid: Option<i64>,
    pub modseq: Option<i64>,
    pub flags: Vec<String>,
    pub keywords: Vec<String>,
    pub is_expunged: bool,
    pub expunged_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MimePart {
    pub id: i64,
    pub message_id: i64,
    pub part_path: String,
    pub content_type: String,
    pub charset: Option<String>,
    pub disposition: Option<String>,
    pub filename: Option<String>,
    pub content_id: Option<String>,
    pub size_octets: i64,
    pub blob_key: String,
    pub sha256: String,
    pub transfer_encoding: Option<String>,
    pub metadata_json: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UidMapping {
    pub id: i64,
    pub mailbox_id: i64,
    pub local_uid: i64,
    pub upstream_uid: i64,
    pub upstream_uidvalidity: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    pub id: i64,
    pub account_id: i64,
    pub mailbox_id: Option<i64>,
    pub state_json: Value,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMutation {
    pub id: i64,
    pub account_id: i64,
    pub mailbox_id: i64,
    pub message_id: Option<i64>,
    pub mutation_type: String,
    pub payload_json: Value,
    pub status: MutationStatus,
    pub attempts: i32,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub idempotency_key: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: i64,
    pub user_id: i64,
    pub account_id: Option<i64>,
    pub connection_id: String,
    pub remote_addr: Option<String>,
    pub authenticated_at: Option<DateTime<Utc>>,
    pub disconnected_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: i64,
    pub user_id: Option<i64>,
    pub account_id: Option<i64>,
    pub action: String,
    pub metadata_json: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheObject {
    pub id: i64,
    pub account_id: Option<i64>,
    pub object_type: String,
    pub blob_key: String,
    pub sha256: String,
    pub size_octets: i64,
    pub ref_count: i64,
    pub last_accessed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quota {
    pub id: i64,
    pub user_id: Option<i64>,
    pub account_id: Option<i64>,
    pub max_bytes: i64,
    pub used_bytes: i64,
    pub updated_at: DateTime<Utc>,
}
