use imap_cache_core::{
    domain::{UpstreamAuthMethod, UpstreamTlsMode},
    error::{Error, Result},
    security::ensure_rustls_crypto_provider,
};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use std::{
    collections::HashMap,
    convert::TryFrom,
    sync::{Arc, Mutex, OnceLock},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{self, RootCertStore, pki_types::ServerName},
};

#[derive(Debug, Clone)]
pub struct UpstreamAccountConfig {
    pub host: String,
    pub port: u16,
    pub tls_mode: UpstreamTlsMode,
    pub auth_method: UpstreamAuthMethod,
    pub username: String,
    pub secret: String,
}

#[derive(Debug, Clone)]
pub struct CommandResponse {
    pub tagged: String,
    pub untagged: Vec<String>,
    pub continuations: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelectedMailboxInfo {
    pub flags: Vec<String>,
    pub exists: Option<i64>,
    pub recent: Option<i64>,
    pub uidvalidity: Option<i64>,
    pub uidnext: Option<i64>,
    pub highestmodseq: Option<i64>,
    pub unseen: Option<i64>,
    pub read_only: bool,
}

pub struct UpstreamClient {
    stream: Option<BufReader<UpstreamTransport>>,
    next_tag: u64,
    greeting: Option<String>,
    capabilities: Vec<String>,
    metrics: Option<Arc<dyn UpstreamMetrics>>,
    metrics_counted: bool,
    connection_limit_guard: Option<OwnedSemaphorePermit>,
}

#[derive(Debug)]
enum UpstreamTransport {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for UpstreamTransport {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.as_mut().get_mut() {
            UpstreamTransport::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            UpstreamTransport::Tls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamTransport {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.as_mut().get_mut() {
            UpstreamTransport::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            UpstreamTransport::Tls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.as_mut().get_mut() {
            UpstreamTransport::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            UpstreamTransport::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.as_mut().get_mut() {
            UpstreamTransport::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            UpstreamTransport::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl UpstreamClient {
    pub async fn connect(config: &UpstreamAccountConfig) -> Result<Self> {
        match config.tls_mode {
            UpstreamTlsMode::Plain => {
                let stream = TcpStream::connect((&config.host[..], config.port)).await?;
                let mut client = Self::from_plain(stream);
                client.read_greeting().await?;
                Ok(client)
            }
            UpstreamTlsMode::Tls => {
                let stream = TcpStream::connect((&config.host[..], config.port)).await?;
                let stream = wrap_tls_client(stream, &config.host).await?;
                let mut client = Self::from_tls(stream);
                client.read_greeting().await?;
                Ok(client)
            }
            UpstreamTlsMode::StartTls => {
                let stream = TcpStream::connect((&config.host[..], config.port)).await?;
                let mut client = Self::from_plain(stream);
                client.read_greeting().await?;
                let caps = client.capability().await?;
                if !caps.iter().any(|cap| cap.eq_ignore_ascii_case("STARTTLS")) {
                    return Err(Error::Storage(
                        "upstream server does not advertise STARTTLS".to_string(),
                    ));
                }
                client.starttls().await?;
                client.upgrade_to_tls(&config.host).await?;
                Ok(client)
            }
        }
    }

    pub fn from_plain(stream: TcpStream) -> Self {
        Self {
            stream: Some(BufReader::new(UpstreamTransport::Plain(stream))),
            next_tag: 1,
            greeting: None,
            capabilities: Vec::new(),
            metrics: None,
            metrics_counted: false,
            connection_limit_guard: None,
        }
    }

    pub fn from_tls(stream: tokio_rustls::client::TlsStream<TcpStream>) -> Self {
        Self {
            stream: Some(BufReader::new(UpstreamTransport::Tls(stream))),
            next_tag: 1,
            greeting: None,
            capabilities: Vec::new(),
            metrics: None,
            metrics_counted: false,
            connection_limit_guard: None,
        }
    }

    pub fn with_metrics<M: UpstreamMetrics + 'static>(mut self, metrics: Arc<M>) -> Self {
        if !self.metrics_counted {
            metrics.inc_upstream_connections();
            self.metrics_counted = true;
        }
        let metrics: Arc<dyn UpstreamMetrics> = metrics;
        self.metrics = Some(metrics);
        self
    }

    pub async fn with_account_connection_limit(
        mut self,
        account_id: i64,
        limit: usize,
    ) -> Result<Self> {
        if limit == 0 || self.connection_limit_guard.is_some() {
            return Ok(self);
        }

        let semaphore = account_connection_semaphore(account_id, limit);
        let permit = semaphore
            .acquire_owned()
            .await
            .map_err(|e| Error::Storage(format!("upstream connection limiter failed: {e}")))?;
        self.connection_limit_guard = Some(permit);
        Ok(self)
    }

    pub async fn authenticate_with_method(
        &mut self,
        auth_method: UpstreamAuthMethod,
        username: &str,
        secret: &str,
    ) -> Result<()> {
        match auth_method {
            UpstreamAuthMethod::Login => self.login(username, secret).await,
            UpstreamAuthMethod::OAuth2 | UpstreamAuthMethod::XOAuth2 => {
                let response = format!("user={username}\x01auth=Bearer {secret}\x01\x01");
                self.authenticate_sasl("XOAUTH2", &response).await
            }
        }
    }

    pub fn greeting(&self) -> Option<&str> {
        self.greeting.as_deref()
    }

    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    pub async fn capability(&mut self) -> Result<Vec<String>> {
        let response = self.send_command("CAPABILITY", &[]).await?;
        let caps = response
            .untagged
            .iter()
            .find_map(|line| line.strip_prefix("* CAPABILITY "))
            .map(|line| {
                line.split_whitespace()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        self.capabilities = caps.clone();
        Ok(caps)
    }

    pub async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        let response = self
            .send_command("LOGIN", &[quote(username), quote(password)])
            .await?;
        ensure_ok(&response.tagged)
    }

    pub async fn select(&mut self, mailbox: &str) -> Result<()> {
        let _ = self.select_mailbox(mailbox).await?;
        Ok(())
    }

    pub async fn select_mailbox(&mut self, mailbox: &str) -> Result<SelectedMailboxInfo> {
        let response = self.send_command("SELECT", &[quote(mailbox)]).await?;
        let mut info = SelectedMailboxInfo::default();
        for line in &response.untagged {
            if let Some(rest) = line.strip_prefix("* FLAGS ") {
                info.flags = parse_parenthesized_list(rest)
                    .into_iter()
                    .map(|item| item.trim_matches('"').to_string())
                    .collect();
                continue;
            }
            if let Some(rest) = line.strip_prefix("* ") {
                if let Some(rest) = rest.strip_suffix(" EXISTS") {
                    info.exists = rest.trim().parse::<i64>().ok();
                    continue;
                }
                if let Some(rest) = rest.strip_suffix(" RECENT") {
                    info.recent = rest.trim().parse::<i64>().ok();
                    continue;
                }
            }
            if let Some(value) = extract_bracketed_response_code(line, "UIDVALIDITY") {
                info.uidvalidity = value.parse::<i64>().ok();
                continue;
            }
            if let Some(value) = extract_bracketed_response_code(line, "UIDNEXT") {
                info.uidnext = value.parse::<i64>().ok();
                continue;
            }
            if let Some(value) = extract_bracketed_response_code(line, "HIGHESTMODSEQ") {
                info.highestmodseq = value.parse::<i64>().ok();
                continue;
            }
            if let Some(value) = extract_bracketed_response_code(line, "UNSEEN") {
                info.unseen = value.parse::<i64>().ok();
                continue;
            }
            if line.contains("[READ-ONLY]") {
                info.read_only = true;
            }
        }
        ensure_ok(&response.tagged)?;
        Ok(info)
    }

    pub async fn noop(&mut self) -> Result<()> {
        let response = self.send_command("NOOP", &[]).await?;
        ensure_ok(&response.tagged)
    }

    pub async fn list_mailboxes(&mut self) -> Result<Vec<String>> {
        let response = self.send_command("LIST", &[quote(""), quote("*")]).await?;
        ensure_ok(&response.tagged)?;

        let mut mailboxes = Vec::new();
        for line in response.untagged {
            if let Some(name) = parse_list_mailbox_name(&line) {
                mailboxes.push(name);
            }
        }
        Ok(mailboxes)
    }

    pub async fn uid_search_all(&mut self) -> Result<Vec<u64>> {
        let response = self
            .send_command("UID", &["SEARCH".to_string(), "ALL".to_string()])
            .await?;
        ensure_ok(&response.tagged)?;

        let mut uids = Vec::new();
        for line in response.untagged {
            if let Some(rest) = line.strip_prefix("* SEARCH ") {
                for token in rest.split_whitespace() {
                    if let Ok(uid) = token.parse::<u64>() {
                        uids.push(uid);
                    }
                }
            }
        }
        Ok(uids)
    }

    pub async fn append(
        &mut self,
        mailbox: &str,
        flags: &[String],
        data: &[u8],
    ) -> Result<Option<u64>> {
        self.append_with_internal_date(mailbox, flags, None, data)
            .await
    }

    pub async fn append_with_internal_date(
        &mut self,
        mailbox: &str,
        flags: &[String],
        internal_date: Option<DateTime<Utc>>,
        data: &[u8],
    ) -> Result<Option<u64>> {
        let tag = self.next_tag();
        let mut line = String::new();
        line.push_str(&tag);
        line.push(' ');
        line.push_str("APPEND");
        line.push(' ');
        line.push_str(&quote(mailbox));
        if !flags.is_empty() {
            line.push(' ');
            line.push_str(&format!("({})", flags.join(" ")));
        }
        if let Some(internal_date) = internal_date {
            line.push(' ');
            line.push_str(&quote(
                &internal_date.format("%d-%b-%Y %H:%M:%S %z").to_string(),
            ));
        }
        line.push(' ');
        line.push_str(&format!("{{{}}}\r\n", data.len()));
        self.write_all(line.as_bytes()).await?;

        loop {
            let response = self.read_line().await?;
            if response.starts_with("+ ") {
                break;
            }
            if response.starts_with(&tag) {
                ensure_ok(&response)?;
                return Ok(None);
            }
        }

        let mut payload = Vec::with_capacity(data.len() + 2);
        payload.extend_from_slice(data);
        payload.extend_from_slice(b"\r\n");
        self.write_all(&payload).await?;
        loop {
            let response_line = self.read_line().await?;
            if response_line.starts_with(&tag) {
                ensure_ok(&response_line)?;
                let append_uid = extract_bracketed_response_code(&response_line, "APPENDUID")
                    .and_then(|value| value.split_whitespace().last())
                    .and_then(|value| value.parse::<u64>().ok());
                return Ok(append_uid);
            }
        }
    }

    async fn authenticate_sasl(&mut self, mechanism: &str, response: &str) -> Result<()> {
        let tag = self.next_tag();
        let command = format!("{tag} AUTHENTICATE {mechanism}\r\n");
        self.write_all(command.as_bytes()).await?;

        loop {
            let line = self.read_line().await?;
            if line.starts_with('+') {
                let encoded = base64::engine::general_purpose::STANDARD.encode(response);
                let payload = format!("{encoded}\r\n");
                self.write_all(payload.as_bytes()).await?;
                break;
            }
            if line.starts_with(&tag) {
                return ensure_ok(&line);
            }
        }

        loop {
            let line = self.read_line().await?;
            if line.starts_with(&tag) {
                return ensure_ok(&line);
            }
        }
    }

    pub async fn uid_store_flags(&mut self, uid: u64, flags: &[String]) -> Result<()> {
        let response = self
            .send_command(
                "UID",
                &[
                    "STORE".to_string(),
                    uid.to_string(),
                    format!("FLAGS.SILENT"),
                    format!("({})", flags.join(" ")),
                ],
            )
            .await?;
        ensure_ok(&response.tagged)
    }

    pub async fn uid_copy_message(&mut self, uid: u64, mailbox: &str) -> Result<u64> {
        let response = self
            .send_command(
                "UID",
                &["COPY".to_string(), uid.to_string(), quote(mailbox)],
            )
            .await?;
        ensure_ok(&response.tagged)?;
        extract_bracketed_response_code(&response.tagged, "COPYUID")
            .and_then(|value| value.split_whitespace().last())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| Error::Parse(format!("COPYUID response missing destination uid: {}", response.tagged)))
    }

    pub async fn uid_move_message(&mut self, uid: u64, mailbox: &str) -> Result<u64> {
        let has_move = if self.capabilities.is_empty() {
            self.capability()
                .await?
                .iter()
                .any(|cap| cap.eq_ignore_ascii_case("MOVE"))
        } else {
            self.capabilities
                .iter()
                .any(|cap| cap.eq_ignore_ascii_case("MOVE"))
        };

        if has_move {
            let response = self
                .send_command(
                    "UID",
                    &["MOVE".to_string(), uid.to_string(), quote(mailbox)],
                )
                .await?;
            ensure_ok(&response.tagged)?;
            return extract_bracketed_response_code(&response.tagged, "COPYUID")
                .and_then(|value| value.split_whitespace().last())
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| {
                    Error::Parse(format!(
                        "COPYUID response missing destination uid: {}",
                        response.tagged
                    ))
                });
        }

        let copied_uid = self.uid_copy_message(uid, mailbox).await?;
        let deleted = vec![String::from("\\Deleted")];
        self.uid_store_flags(uid, &deleted).await?;
        self.expunge_selected().await?;
        Ok(copied_uid)
    }

    pub async fn expunge_selected(&mut self) -> Result<()> {
        let response = self.send_command("EXPUNGE", &[]).await?;
        ensure_ok(&response.tagged)
    }

    pub async fn uid_fetch_rfc822(&mut self, uid: u64) -> Result<Vec<u8>> {
        let tag = self.next_tag();
        let command = format!("{tag} UID FETCH {uid} (UID BODY.PEEK[])\r\n");
        self.write_all(command.as_bytes()).await?;

        let mut body = None;
        loop {
            let response = self.read_line().await?;
            if response.is_empty() || response == ")" {
                continue;
            }
            if response.starts_with("* ")
                && response.contains("FETCH")
                && response.contains('{')
                && response.ends_with('}')
            {
                if let Some(size) = parse_literal_size(&response)? {
                    let mut bytes = vec![0; size];
                    let stream = self
                        .stream
                        .as_mut()
                        .ok_or_else(|| Error::Storage("missing upstream transport".to_string()))?;
                    stream.read_exact(&mut bytes).await?;
                    if let Some(metrics) = &self.metrics {
                        metrics.record_upstream_bytes_fetched(bytes.len() as u64);
                    }
                    body = Some(bytes);
                    continue;
                }
            }
            if response.starts_with(&tag) {
                self.update_capabilities_from_untagged(&[]);
                ensure_ok(&response)?;
                return body.ok_or_else(|| {
                    Error::Parse("FETCH completed without a literal body".to_string())
                });
            }
        }
    }

    pub async fn uid_fetch_flags(&mut self, uid: u64) -> Result<Vec<String>> {
        let response = self
            .send_command(
                "UID",
                &["FETCH".to_string(), uid.to_string(), "(UID FLAGS)".to_string()],
            )
            .await?;
        ensure_ok(&response.tagged)?;

        for line in response.untagged {
            if let Some(flags) = parse_fetch_flags(&line, uid) {
                return Ok(flags);
            }
        }

        Err(Error::Parse(format!(
            "FETCH response missing flags for UID {uid}"
        )))
    }

    pub async fn logout(&mut self) -> Result<()> {
        let response = self.send_command("LOGOUT", &[]).await?;
        ensure_ok(&response.tagged)
    }

    pub async fn read_greeting(&mut self) -> Result<Option<String>> {
        let line = self.read_line().await?;
        if line.starts_with("* OK") {
            self.greeting = Some(line.clone());
        }
        Ok(Some(line))
    }

    pub async fn send_command(
        &mut self,
        command: &str,
        args: &[String],
    ) -> Result<CommandResponse> {
        let tag = self.next_tag();
        let mut line = String::new();
        line.push_str(&tag);
        line.push(' ');
        line.push_str(command);
        for arg in args {
            line.push(' ');
            line.push_str(arg);
        }
        line.push_str("\r\n");
        self.write_all(line.as_bytes()).await?;

        let mut untagged = Vec::new();
        let mut continuations = Vec::new();
        loop {
            let response = self.read_line().await?;
            if response.starts_with("+ ") {
                continuations.push(response);
                continue;
            }
            if response.starts_with("* ") {
                untagged.push(response);
                continue;
            }
            if response.starts_with(&tag) {
                self.update_capabilities_from_untagged(&untagged);
                return Ok(CommandResponse {
                    tagged: response,
                    untagged,
                    continuations,
                });
            }
            return Err(Error::Parse(format!(
                "unexpected IMAP response line: {response}"
            )));
        }
    }

    async fn read_line(&mut self) -> Result<String> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| Error::Storage("missing upstream transport".to_string()))?;
        let mut line = String::new();
        let bytes = stream.read_line(&mut line).await?;
        if bytes == 0 {
            return Err(Error::Parse("upstream closed connection".to_string()));
        }
        if let Some(metrics) = &self.metrics {
            metrics.record_upstream_bytes_fetched(bytes as u64);
        }
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| Error::Storage("missing upstream transport".to_string()))?;
        stream.get_mut().write_all(bytes).await?;
        stream.get_mut().flush().await?;
        if let Some(metrics) = &self.metrics {
            metrics.record_upstream_bytes_sent(bytes.len() as u64);
        }
        Ok(())
    }

    fn next_tag(&mut self) -> String {
        let tag = format!("A{:04}", self.next_tag);
        self.next_tag += 1;
        tag
    }

    async fn starttls(&mut self) -> Result<()> {
        let response = self.send_command("STARTTLS", &[]).await?;
        ensure_ok(&response.tagged)
    }

    fn update_capabilities_from_untagged(&mut self, untagged: &[String]) {
        for line in untagged {
            if let Some(caps) = line.strip_prefix("* CAPABILITY ") {
                self.capabilities = caps.split_whitespace().map(|s| s.to_string()).collect();
            }
        }
    }

    async fn upgrade_to_tls(&mut self, host: &str) -> Result<()> {
        let plain = match self
            .stream
            .take()
            .ok_or_else(|| Error::Storage("missing upstream transport".to_string()))?
            .into_inner()
        {
            UpstreamTransport::Plain(stream) => stream,
            UpstreamTransport::Tls(_) => {
                return Err(Error::Storage("connection is already TLS".to_string()));
            }
        };
        let tls = wrap_tls_client(plain, host).await?;
        self.stream = Some(BufReader::new(UpstreamTransport::Tls(tls)));
        Ok(())
    }
}

impl Drop for UpstreamClient {
    fn drop(&mut self) {
        if self.metrics_counted {
            if let Some(metrics) = &self.metrics {
                metrics.dec_upstream_connections();
            }
            self.metrics_counted = false;
        }
    }
}

fn ensure_ok(tagged: &str) -> Result<()> {
    if tagged.contains(" OK ") {
        Ok(())
    } else if tagged.contains(" NO ") {
        Err(Error::AuthenticationFailed)
    } else if tagged.contains(" BAD ") {
        Err(Error::ImapCommand(tagged.to_string()))
    } else {
        Err(Error::Parse(format!(
            "unexpected tagged response: {tagged}"
        )))
    }
}

fn quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn account_connection_semaphore(account_id: i64, limit: usize) -> Arc<Semaphore> {
    static ACCOUNT_LIMITS: OnceLock<Mutex<HashMap<i64, Arc<Semaphore>>>> = OnceLock::new();
    let map = ACCOUNT_LIMITS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map.lock().expect("account connection limit map poisoned");
    map.entry(account_id)
        .or_insert_with(|| Arc::new(Semaphore::new(limit)))
        .clone()
}

fn parse_list_mailbox_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.starts_with("* LIST ") {
        return None;
    }
    let (_, mailbox) = trimmed.rsplit_once(' ')?;
    Some(unquote(mailbox))
}

fn extract_bracketed_response_code<'a>(line: &'a str, code: &str) -> Option<&'a str> {
    let marker = format!("[{code} ");
    let start = line.find(&marker)? + marker.len();
    let end = line[start..].find(']')? + start;
    Some(line[start..end].trim())
}

fn parse_parenthesized_list(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    let Some(inner) = trimmed.strip_prefix('(').and_then(|s| s.strip_suffix(')')) else {
        return Vec::new();
    };
    inner
        .split_whitespace()
        .map(|item| item.trim_matches('"').to_string())
        .collect()
}

fn parse_fetch_flags(line: &str, uid: u64) -> Option<Vec<String>> {
    let trimmed = line.trim();
    if !trimmed.starts_with("* ") || !trimmed.contains(" FETCH ") {
        return None;
    }
    if !trimmed.contains(&format!("UID {uid}")) {
        return None;
    }
    let start = trimmed.find("FLAGS (")? + "FLAGS ".len();
    let end = trimmed[start..].find(')')? + start;
    Some(parse_parenthesized_list(&trimmed[start..=end]))
}

fn parse_literal_size(line: &str) -> Result<Option<usize>> {
    let start = line
        .rfind('{')
        .ok_or_else(|| Error::Parse(format!("missing literal marker in response: {line}")))?;
    let end = line
        .rfind('}')
        .ok_or_else(|| Error::Parse(format!("missing literal terminator in response: {line}")))?;
    let size = line[start + 1..end]
        .parse::<usize>()
        .map_err(|e| Error::Parse(format!("invalid literal size in response: {e}")))?;
    Ok(Some(size))
}

fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut out = String::new();
        let mut escaped = false;
        for ch in inner.chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                out.push(ch);
            }
        }
        out
    } else {
        trimmed.to_string()
    }
}

async fn wrap_tls_client(
    stream: TcpStream,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    ensure_rustls_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| Error::Config(format!("invalid TLS host name: {host}")))?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|e| Error::Storage(format!("upstream TLS handshake failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc,
    };
    use tokio::net::TcpListener;

    #[derive(Default)]
    struct TestUpstreamMetrics {
        upstream_connections: AtomicI64,
        upstream_bytes_fetched: AtomicU64,
        upstream_bytes_sent: AtomicU64,
    }

    impl UpstreamMetrics for TestUpstreamMetrics {
        fn inc_upstream_connections(&self) {
            self.upstream_connections.fetch_add(1, Ordering::Relaxed);
        }

        fn dec_upstream_connections(&self) {
            self.upstream_connections.fetch_sub(1, Ordering::Relaxed);
        }

        fn record_upstream_bytes_fetched(&self, bytes: u64) {
            self.upstream_bytes_fetched
                .fetch_add(bytes, Ordering::Relaxed);
        }

        fn record_upstream_bytes_sent(&self, bytes: u64) {
            self.upstream_bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    impl TestUpstreamMetrics {
        fn upstream_bytes_fetched(&self) -> u64 {
            self.upstream_bytes_fetched.load(Ordering::Relaxed)
        }

        fn upstream_bytes_sent(&self) -> u64 {
            self.upstream_bytes_sent.load(Ordering::Relaxed)
        }
    }

    #[tokio::test]
    async fn plain_client_can_login_and_select_against_fake_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(b"* OK fake upstream ready\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            let mut reader = BufReader::new(socket);

            loop {
                let mut line = String::new();
                let bytes = reader.read_line(&mut line).await.unwrap();
                if bytes == 0 {
                    break;
                }
                buf.extend_from_slice(line.as_bytes());
                let line = line.trim_end_matches(['\r', '\n']).to_string();
                if line.contains("CAPABILITY") {
                    reader.get_mut().write_all(b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\nA0001 OK CAPABILITY completed\r\n").await.unwrap();
                } else if line.contains("LOGIN") {
                    reader
                        .get_mut()
                        .write_all(b"A0002 OK LOGIN completed\r\n")
                        .await
                        .unwrap();
                } else if line.contains("SELECT") {
                    reader.get_mut().write_all(b"* FLAGS (\\Seen)\r\n* 1 EXISTS\r\nA0003 OK [READ-WRITE] SELECT completed\r\n").await.unwrap();
                } else if line.contains("LOGOUT") {
                    reader
                        .get_mut()
                        .write_all(b"* BYE logging out\r\nA0004 OK LOGOUT completed\r\n")
                        .await
                        .unwrap();
                    break;
                }
            }
            let _ = buf;
        });

        let config = UpstreamAccountConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls_mode: UpstreamTlsMode::Plain,
            auth_method: UpstreamAuthMethod::Login,
            username: "user@example.test".to_string(),
            secret: "secret".to_string(),
        };
        let metrics = Arc::new(TestUpstreamMetrics::default());

        let mut client = UpstreamClient::connect(&config)
            .await
            .unwrap()
            .with_metrics(Arc::clone(&metrics));
        client.capability().await.unwrap();
        client.login("user@example.test", "secret").await.unwrap();
        client.select("INBOX").await.unwrap();
        client.logout().await.unwrap();

        assert!(metrics.upstream_bytes_fetched() > 0);
        assert!(metrics.upstream_bytes_sent() > 0);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn xoauth2_authentication_uses_bearer_token_flow() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(b"* OK fake upstream ready\r\n")
                .await
                .unwrap();
            let mut reader = BufReader::new(socket);

            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.contains("AUTHENTICATE XOAUTH2"));
            reader.get_mut().write_all(b"+ \r\n").await.unwrap();

            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(line.trim_end_matches(['\r', '\n']))
                .unwrap();
            let decoded = String::from_utf8(decoded).unwrap();
            assert!(decoded.contains("user=user@example.test"));
            assert!(decoded.contains("auth=Bearer secret-token"));

            reader
                .get_mut()
                .write_all(b"A0001 OK AUTHENTICATE completed\r\n")
                .await
                .unwrap();

            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.contains("LOGOUT"));
            reader
                .get_mut()
                .write_all(b"* BYE logging out\r\nA0002 OK LOGOUT completed\r\n")
                .await
                .unwrap();
        });

        let config = UpstreamAccountConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls_mode: UpstreamTlsMode::Plain,
            auth_method: UpstreamAuthMethod::OAuth2,
            username: "user@example.test".to_string(),
            secret: "secret-token".to_string(),
        };

        let mut client = UpstreamClient::connect(&config).await.unwrap();
        client
            .authenticate_with_method(config.auth_method, &config.username, &config.secret)
            .await
            .unwrap();
        client.logout().await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn account_connection_limit_blocks_second_client_until_first_is_dropped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                socket
                    .write_all(b"* OK fake upstream ready\r\n")
                    .await
                    .unwrap();
            }
        });

        let config = UpstreamAccountConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls_mode: UpstreamTlsMode::Plain,
            auth_method: UpstreamAuthMethod::Login,
            username: "user@example.test".to_string(),
            secret: "secret".to_string(),
        };

        let client1 = UpstreamClient::connect(&config).await.unwrap();
        let client2 = UpstreamClient::connect(&config).await.unwrap();
        let client1 = client1.with_account_connection_limit(42, 1).await.unwrap();

        let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let client2 = client2.with_account_connection_limit(42, 1).await.unwrap();
            let _ = ready_tx.send(true);
            client2
        });

        tokio::task::yield_now().await;
        assert!(!*ready_rx.borrow());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), ready_rx.changed())
                .await
                .is_err()
        );

        drop(client1);

        tokio::time::timeout(std::time::Duration::from_secs(1), ready_rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*ready_rx.borrow());

        let _client2 = task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn fetch_parses_literal_bodies() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            socket.writable().await.expect("socket should be writable");
            let mut reader = BufReader::new(socket);
            reader
                .get_mut()
                .write_all(b"* OK fake upstream ready\r\n")
                .await
                .unwrap();

            loop {
                let mut line = String::new();
                let bytes = reader.read_line(&mut line).await.unwrap();
                if bytes == 0 {
                    break;
                }
                let line = line.trim_end_matches(['\r', '\n']).to_string();
                if line.contains("UID FETCH") {
                    let body = b"From: Alice <alice@example.com>\r\nSubject: Upstream fetch\r\n\r\nHello from upstream.\r\n";
                    let header = format!("* 1 FETCH (UID 7 BODY[] {{{}}}\r\n", body.len());
                    reader.get_mut().write_all(header.as_bytes()).await.unwrap();
                    reader.get_mut().write_all(body).await.unwrap();
                    reader
                        .get_mut()
                        .write_all(b"\r\n)\r\nA0001 OK FETCH completed\r\n")
                        .await
                        .unwrap();
                } else if line.contains("LOGOUT") {
                    reader
                        .get_mut()
                        .write_all(b"* BYE logging out\r\nA0002 OK LOGOUT completed\r\n")
                        .await
                        .unwrap();
                    break;
                }
            }
        });

        let config = UpstreamAccountConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls_mode: UpstreamTlsMode::Plain,
            auth_method: UpstreamAuthMethod::Login,
            username: "user@example.test".to_string(),
            secret: "secret".to_string(),
        };
        let metrics = Arc::new(TestUpstreamMetrics::default());

        let mut client = UpstreamClient::connect(&config)
            .await
            .unwrap()
            .with_metrics(Arc::clone(&metrics));
        let body = client.uid_fetch_rfc822(7).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Hello from upstream."));
        client.logout().await.unwrap();

        assert!(metrics.upstream_bytes_fetched() > 0);
        assert!(metrics.upstream_bytes_sent() > 0);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn fetch_parses_flags() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);
            reader
                .get_mut()
                .write_all(b"* OK fake upstream ready\r\n")
                .await
                .unwrap();

            loop {
                let mut line = String::new();
                let bytes = reader.read_line(&mut line).await.unwrap();
                if bytes == 0 {
                    break;
                }
                let line = line.trim_end_matches(['\r', '\n']).to_string();
                if line.contains("UID FETCH") && line.contains("FLAGS") {
                    reader
                        .get_mut()
                        .write_all(b"* 1 FETCH (UID 7 FLAGS (\\Seen \\Flagged))\r\nA0001 OK FETCH completed\r\n")
                        .await
                        .unwrap();
                } else if line.contains("LOGOUT") {
                    reader
                        .get_mut()
                        .write_all(b"* BYE logging out\r\nA0002 OK LOGOUT completed\r\n")
                        .await
                        .unwrap();
                    break;
                }
            }
        });

        let config = UpstreamAccountConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls_mode: UpstreamTlsMode::Plain,
            auth_method: UpstreamAuthMethod::Login,
            username: "user@example.test".to_string(),
            secret: "secret".to_string(),
        };

        let mut client = UpstreamClient::connect(&config).await.unwrap();
        let flags = client.uid_fetch_flags(7).await.unwrap();
        assert_eq!(flags, vec!["\\Seen".to_string(), "\\Flagged".to_string()]);
        client.logout().await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn append_metrics_match_wire_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let wire_bytes = Arc::new(AtomicU64::new(0));
        let wire_bytes_server = Arc::clone(&wire_bytes);

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(b"* OK fake upstream ready\r\n")
                .await
                .unwrap();
            let mut reader = BufReader::new(socket);

            loop {
                let mut line = String::new();
                let bytes = reader.read_line(&mut line).await.unwrap();
                if bytes == 0 {
                    break;
                }
                wire_bytes_server.fetch_add(bytes as u64, Ordering::SeqCst);
                let line = line.trim_end_matches(['\r', '\n']).to_string();
                if line.contains("LOGIN") {
                    reader
                        .get_mut()
                        .write_all(b"A0001 OK LOGIN completed\r\n")
                        .await
                        .unwrap();
                } else if line.contains("APPEND") {
                    let literal_size = parse_literal_size(&line).unwrap().unwrap();
                    reader.get_mut().write_all(b"+ go\r\n").await.unwrap();
                    let mut literal = vec![0; literal_size];
                    reader.read_exact(&mut literal).await.unwrap();
                    wire_bytes_server.fetch_add(literal_size as u64, Ordering::SeqCst);
                    let mut crlf = [0u8; 2];
                    reader.read_exact(&mut crlf).await.unwrap();
                    wire_bytes_server.fetch_add(crlf.len() as u64, Ordering::SeqCst);
                    reader
                        .get_mut()
                        .write_all(b"A0002 OK APPEND completed\r\n")
                        .await
                        .unwrap();
                } else if line.contains("LOGOUT") {
                    reader
                        .get_mut()
                        .write_all(b"* BYE logging out\r\nA0003 OK LOGOUT completed\r\n")
                        .await
                        .unwrap();
                    break;
                }
            }
        });

        let config = UpstreamAccountConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            tls_mode: UpstreamTlsMode::Plain,
            auth_method: UpstreamAuthMethod::Login,
            username: "user@example.test".to_string(),
            secret: "secret".to_string(),
        };
        let metrics = Arc::new(TestUpstreamMetrics::default());

        let mut client = UpstreamClient::connect(&config)
            .await
            .unwrap()
            .with_metrics(Arc::clone(&metrics));
        client.login("user@example.test", "secret").await.unwrap();
        let baseline = metrics.upstream_bytes_sent();
        wire_bytes.store(0, Ordering::SeqCst);

        let _ = client
            .append_with_internal_date(
                "INBOX",
                &[String::from("\\Seen")],
                Some(Utc::now()),
                b"append-body",
            )
            .await
            .unwrap();
        let after_append = metrics.upstream_bytes_sent();
        assert_eq!(
            after_append - baseline,
            wire_bytes.load(Ordering::SeqCst),
            "upstream bytes sent should match the actual APPEND wire bytes"
        );

        client.logout().await.unwrap();

        server.await.unwrap();
    }
}

pub trait UpstreamMetrics: Send + Sync {
    fn inc_upstream_connections(&self);
    fn dec_upstream_connections(&self);
    fn record_upstream_bytes_fetched(&self, bytes: u64);
    fn record_upstream_bytes_sent(&self, bytes: u64);
}
