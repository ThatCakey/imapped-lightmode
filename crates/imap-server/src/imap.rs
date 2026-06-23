use crate::{
    AppServices,
    auth::AuthContext,
    config::Config,
    db::repository::NewCacheObject,
    domain::Mailbox,
    error::{Error, Result},
    metrics::AppMetrics,
    search::{SearchExpr, SearchQuery},
};
pub use imap_cache_protocol::{
    FetchBodySection, ParsedCommand, RawFetchSection, State, StoreMode, bad,
    format_number_set, format_status_response, format_status_response_with_defaults,
    no, ok, parse_command, parse_fetch_items, parse_flag_list, parse_literal_marker,
    parse_number_set, parse_raw_fetch_request, parse_status_items, parse_store_request,
};
use base64::Engine as _;
use mailparse::MailHeaderMap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::time::{Duration, Instant};
use std::{fs::File, io::BufReader, sync::Arc};
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufStream as TokioBufStream,
    },
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use uuid::Uuid;

#[derive(Debug)]
enum ImapTransport {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl ImapTransport {
    async fn upgrade_to_tls(self, acceptor: &TlsAcceptor) -> Result<Self> {
        match self {
            Self::Plain(stream) => acceptor
                .accept(stream)
                .await
                .map(Self::Tls)
                .map_err(|err| Error::Storage(format!("STARTTLS handshake failed: {err}"))),
            Self::Tls(_) => Err(Error::Config(
                "STARTTLS attempted after TLS was already active".to_string(),
            )),
        }
    }
}

impl AsyncRead for ImapTransport {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.as_mut().get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ImapTransport {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.as_mut().get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.as_mut().get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.as_mut().get_mut() {
            Self::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImapSession {
    pub state: State,
    pub authenticated: Option<AuthContext>,
    auth_counted: bool,
    connection_id: String,
    remote_addr: Option<String>,
    session_record_created: bool,
    selected_mailbox_snapshot: Option<SelectedMailboxSnapshot>,
    starttls_available: bool,
    tls_active: bool,
    pub metrics: Arc<crate::metrics::AppMetrics>,
}

#[derive(Debug, Clone)]
struct SelectedMailboxSnapshot {
    account_id: i64,
    mailbox_id: i64,
    exists_count: i64,
}

impl ImapSession {
    pub fn new() -> Self {
        Self {
            state: State::NotAuthenticated,
            authenticated: None,
            auth_counted: false,
            connection_id: Uuid::new_v4().to_string(),
            remote_addr: None,
            session_record_created: false,
            selected_mailbox_snapshot: None,
            starttls_available: true,
            tls_active: false,
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        }
    }

    fn set_connection_context(&mut self, connection_id: String, remote_addr: Option<String>) {
        self.connection_id = connection_id;
        self.remote_addr = remote_addr;
    }

    fn set_starttls_available(&mut self, available: bool) {
        self.starttls_available = available;
    }

    fn set_tls_active(&mut self, active: bool) {
        self.tls_active = active;
    }

    pub fn capabilities(&self) -> Vec<&'static str> {
        match self.state {
            State::NotAuthenticated => {
                let mut capabilities = vec!["IMAP4rev1", "AUTH=PLAIN", "AUTH=XOAUTH2"];
                if self.starttls_available && !self.tls_active {
                    capabilities.insert(1, "STARTTLS");
                }
                capabilities
            }
            State::Authenticated | State::SelectedMailbox { .. } => vec![
                "IMAP4rev1",
                "UIDPLUS",
                "NAMESPACE",
                "SPECIAL-USE",
                "LIST-STATUS",
                "IDLE",
                "CONDSTORE",
                "ENABLE",
                "ID",
                "ESEARCH",
                "MOVE",
                "SORT",
                "THREAD=REFERENCES",
                "THREAD=ORDEREDSUBJECT",
                "UNSELECT",
                "AUTH=PLAIN",
                "AUTH=XOAUTH2",
            ],
            State::Logout => vec!["IMAP4rev1"],
        }
    }

    fn selected_mailbox_name_ref(&self) -> Option<&str> {
        match &self.state {
            State::SelectedMailbox { mailbox, .. } => Some(mailbox.as_str()),
            _ => None,
        }
    }

    fn selected_mailbox_is_read_only(&self) -> Option<bool> {
        match &self.state {
            State::SelectedMailbox { read_only, .. } => Some(*read_only),
            _ => None,
        }
    }

    async fn activate_authenticated_session(&mut self, services: &AppServices, ctx: AuthContext) {
        if !self.auth_counted {
            self.metrics.inc_authenticated_sessions();
            services.metrics.inc_authenticated_sessions();
            self.auth_counted = true;
        }
        if !self.session_record_created {
            if let Some(repo) = &services.repository {
                if repo
                    .create_session(crate::db::repository::NewSession {
                        user_id: ctx.user_id,
                        account_id: ctx.account_id,
                        connection_id: &self.connection_id,
                        remote_addr: self.remote_addr.as_deref(),
                    })
                    .await
                    .is_ok()
                {
                    self.session_record_created = true;
                }
            }
        }
        self.authenticated = Some(ctx);
        self.state = State::Authenticated;
        self.selected_mailbox_snapshot = None;
    }

    async fn record_disconnected(&mut self, services: &AppServices) {
        if !self.session_record_created {
            return;
        }
        if let Some(repo) = &services.repository {
            let _ = repo.mark_session_disconnected(&self.connection_id).await;
        }
    }

    pub async fn handle(&mut self, services: &AppServices, line: &str) -> Result<Vec<String>> {
        let Some(command) = parse_command(line)? else {
            return Ok(vec![]);
        };
        self.handle_parsed_command(services, command, None).await
    }

    pub async fn handle_parsed_command(
        &mut self,
        services: &AppServices,
        command: ParsedCommand,
        literal: Option<Vec<u8>>,
    ) -> Result<Vec<String>> {
        let tag = command.tag;
        let name = command.name.to_ascii_uppercase();
        let mut out = Vec::new();
        self.metrics.record_command(&name);
        services.metrics.record_command(&name);

        match name.as_str() {
            "CAPABILITY" => {
                out.push(format!("* CAPABILITY {}", self.capabilities().join(" ")));
                out.push(ok(&tag, "CAPABILITY completed"));
            }
            "NOOP" => out.push(ok(&tag, "NOOP completed")),
            "LOGOUT" => {
                if self.auth_counted {
                    self.metrics.dec_authenticated_sessions();
                    services.metrics.dec_authenticated_sessions();
                    self.auth_counted = false;
                }
                self.state = State::Logout;
                self.selected_mailbox_snapshot = None;
                out.push("* BYE IMAP cache proxy logging out".to_string());
                out.push(ok(&tag, "LOGOUT completed"));
            }
            "LOGIN" => {
                if command.args.len() < 2 {
                    return Ok(vec![bad(&tag, "LOGIN requires username and password")]);
                }
                match services
                    .authenticator
                    .authenticate(&command.args[0], &command.args[1])
                    .await?
                {
                    Some(ctx) => {
                        self.activate_authenticated_session(services, ctx).await;
                        out.push(ok(&tag, "LOGIN completed"));
                    }
                    None => out.push(no(&tag, "AUTHENTICATIONFAILED", "invalid credentials")),
                }
            }
            "STARTTLS" => {
                if self.tls_active {
                    out.push(no(&tag, "BADSTATE", "STARTTLS is already active"));
                } else if !self.starttls_available {
                    out.push(no(&tag, "BADSTATE", "STARTTLS is not available"));
                } else if !matches!(self.state, State::NotAuthenticated) {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "STARTTLS requires a not-authenticated session",
                    ));
                } else {
                    out.push(ok(&tag, "Begin TLS negotiation now"));
                }
            }
            "SELECT" | "EXAMINE" => {
                let mailbox_name = command
                    .args
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "INBOX".to_string());
                let mailbox_record = if let Some(repo) = &services.repository {
                    if let Some(account_id) =
                        self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                    {
                        match repo.find_mailbox(account_id, &mailbox_name).await? {
                            Some(mailbox) => Some(mailbox),
                            None => {
                                out.push(no(&tag, "NONEXISTENT", "mailbox not found"));
                                return Ok(out);
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                let mailbox = mailbox_record.unwrap_or_else(|| Mailbox {
                    id: 0,
                    account_id: self
                        .authenticated
                        .as_ref()
                        .and_then(|ctx| ctx.account_id)
                        .unwrap_or_default(),
                    name: mailbox_name.clone(),
                    canonical_name: canonical_mailbox_name(&mailbox_name),
                    delimiter: Some("/".to_string()),
                    attributes: vec!["\\HasNoChildren".to_string()],
                    subscribed: true,
                    special_use: if mailbox_name.eq_ignore_ascii_case("INBOX") {
                        Some("\\Inbox".to_string())
                    } else {
                        None
                    },
                    uidvalidity: Some(1),
                    uidnext: Some(1),
                    highestmodseq: Some(0),
                    exists_count: 0,
                    recent_count: 0,
                    unseen_count: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                });

                self.state = State::SelectedMailbox {
                    read_only: name == "EXAMINE",
                    mailbox: mailbox.name.clone(),
                };
                self.selected_mailbox_snapshot = Some(SelectedMailboxSnapshot {
                    account_id: mailbox.account_id,
                    mailbox_id: mailbox.id,
                    exists_count: mailbox.exists_count,
                });
                out.push("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)".to_string());
                out.push(format!("* {} EXISTS", mailbox.exists_count));
                out.push(format!("* {} RECENT", mailbox.recent_count));
                out.push(format!(
                    "* OK [UIDVALIDITY {}] UIDs valid",
                    mailbox.uidvalidity.unwrap_or(1)
                ));
                out.push(format!(
                    "* OK [UIDNEXT {}] Predicted next UID",
                    mailbox.uidnext.unwrap_or(1)
                ));
                if let Some(highestmodseq) = mailbox.highestmodseq {
                    out.push(format!(
                        "* OK [HIGHESTMODSEQ {}] Highest mod-sequence value",
                        highestmodseq
                    ));
                }
                out.push(format!(
                    "* OK [UNSEEN {}] First unseen message",
                    mailbox.unseen_count
                ));
                out.push(ok(
                    tag.as_str(),
                    if name == "EXAMINE" {
                        "[READ-ONLY] EXAMINE completed"
                    } else {
                        "[READ-WRITE] SELECT completed"
                    },
                ));
            }
            "LIST" | "LSUB" => {
                if let Some(repo) = &services.repository {
                    let Some(account_id) =
                        self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                    else {
                        out.push(no(
                            &tag,
                            "BADSTATE",
                            &format!("{name} requires an authenticated account"),
                        ));
                        return Ok(out);
                    };
                    let subscribed_only = if name == "LSUB" { Some(true) } else { None };
                    let mailboxes = repo.list_mailboxes(account_id, subscribed_only).await?;
                    let (pattern, status_items) = parse_list_request(&command.args)?;
                    for mailbox in mailboxes.into_iter().filter(|mailbox| {
                        imap_list_pattern_matches(
                            pattern,
                            &mailbox.name,
                            mailbox.delimiter.as_deref().unwrap_or("/"),
                        )
                    }) {
                        out.push(mailbox_list_line(&name, &mailbox));
                        if let Some(status_items) = status_items.as_ref() {
                            out.push(format_status_response(&mailbox, status_items));
                        }
                    }
                    out.push(ok(&tag, &format!("{name} completed")));
                } else {
                    out.push(r#"* LIST (\HasNoChildren) "/" "INBOX""#.to_string());
                    out.push(ok(&tag, &format!("{name} completed")));
                }
            }
            "STATUS" => {
                if let Some(repo) = &services.repository {
                    let Some(account_id) =
                        self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                    else {
                        out.push(no(
                            &tag,
                            "BADSTATE",
                            "STATUS requires an authenticated account",
                        ));
                        return Ok(out);
                    };
                    let mailbox_name = command
                        .args
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "INBOX".to_string());
                    let Some(mailbox) = repo.find_mailbox(account_id, &mailbox_name).await? else {
                        out.push(no(&tag, "NONEXISTENT", "mailbox not found"));
                        return Ok(out);
                    };
                    let requested_items = parse_status_items(&command.args[1..])?;
                    out.push(format_status_response(&mailbox, &requested_items));
                    out.push(ok(&tag, "STATUS completed"));
                } else {
                    let mailbox = command
                        .args
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "INBOX".to_string());
                    let requested_items = parse_status_items(&command.args[1..])?;
                    out.push(format_status_response_with_defaults(
                        &mailbox,
                        &requested_items,
                    ));
                    out.push(ok(&tag, "STATUS completed"));
                }
            }
            "SEARCH" => {
                if let State::SelectedMailbox { mailbox, .. } = &self.state {
                    let (query, return_options) = parse_search_request(&command.args)?;
                    let results = execute_search(
                        services.repository.as_ref(),
                        services.search.as_ref(),
                        self.authenticated.as_ref().and_then(|ctx| ctx.account_id),
                        mailbox,
                        &query,
                        false,
                    )
                    .await?;
                    if return_options.is_some() {
                        out.push(format!(
                            "* ESEARCH (TAG \"{}\"){}",
                            tag,
                            format_esearch_summary(&results, return_options.unwrap())
                        ));
                    } else if results.is_empty() {
                        out.push("* SEARCH".to_string());
                    } else {
                        out.push(format!(
                            "* SEARCH {}",
                            results
                                .into_iter()
                                .map(|value| value.to_string())
                                .collect::<Vec<_>>()
                                .join(" ")
                        ));
                    }
                } else {
                    out.push(no(&tag, "BADSTATE", "SEARCH requires a selected mailbox"));
                    return Ok(out);
                }
                out.push(ok(&tag, "SEARCH completed"));
            }
            "SORT" => {
                if let State::SelectedMailbox { mailbox, .. } = &self.state {
                    let Some((sort_keys, reverse, query)) = parse_sort_request(&command.args)?
                    else {
                        out.push(bad(
                            &tag,
                            "SORT requires sort criteria, charset, and search criteria",
                        ));
                        return Ok(out);
                    };
                    let results = execute_sort(
                        services.repository.as_ref(),
                        services.search.as_ref(),
                        self.authenticated.as_ref().and_then(|ctx| ctx.account_id),
                        mailbox,
                        &query,
                        &sort_keys,
                        reverse,
                        false,
                    )
                    .await?;
                    if results.is_empty() {
                        out.push("* SORT".to_string());
                    } else {
                        out.push(format!(
                            "* SORT {}",
                            results
                                .into_iter()
                                .map(|value| value.to_string())
                                .collect::<Vec<_>>()
                                .join(" ")
                        ));
                    }
                } else {
                    out.push(no(&tag, "BADSTATE", "SORT requires a selected mailbox"));
                    return Ok(out);
                }
                out.push(ok(&tag, "SORT completed"));
            }
            "THREAD" => {
                if let State::SelectedMailbox { mailbox, .. } = &self.state {
                    let Some((algorithm, query)) = parse_thread_request(&command.args)? else {
                        out.push(bad(
                            &tag,
                            "THREAD requires a threading algorithm, charset, and search criteria",
                        ));
                        return Ok(out);
                    };
                    let results = execute_thread(
                        services,
                        self.authenticated.as_ref().and_then(|ctx| ctx.account_id),
                        mailbox,
                        &query,
                        algorithm,
                        false,
                    )
                    .await?;
                    if results.is_empty() {
                        out.push("* THREAD".to_string());
                    } else {
                        out.push(format!("* THREAD {}", results.join(" ")));
                    }
                } else {
                    out.push(no(&tag, "BADSTATE", "THREAD requires a selected mailbox"));
                    return Ok(out);
                }
                out.push(ok(&tag, "THREAD completed"));
            }
            "FETCH" => {
                let Some(account_id) = self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "FETCH requires an authenticated account",
                    ));
                    return Ok(out);
                };
                let Some(selected_mailbox) = self.selected_mailbox_name_ref() else {
                    out.push(no(&tag, "BADSTATE", "FETCH requires a selected mailbox"));
                    return Ok(out);
                };
                let Some(repo) = &services.repository else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "FETCH requires a database-backed repository",
                    ));
                    return Ok(out);
                };
                let Some(mailbox) = repo.find_mailbox(account_id, selected_mailbox).await? else {
                    out.push(no(&tag, "NONEXISTENT", "selected mailbox not found"));
                    return Ok(out);
                };
                let Some(set) = command.args.first() else {
                    out.push(bad(&tag, "FETCH requires a message set"));
                    return Ok(out);
                };
                let items = parse_fetch_items(&command.args[1..]);
                for (sequence, view) in
                    resolve_sequence_views(repo.as_ref(), mailbox.id, set).await?
                {
                    out.push(format_fetch_response(sequence, &view, &items));
                }
                out.push(ok(&tag, "FETCH completed"));
            }
            "STORE" => {
                let Some(account_id) = self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "STORE requires an authenticated account",
                    ));
                    return Ok(out);
                };
                let Some(selected_mailbox) = self.selected_mailbox_name_ref() else {
                    out.push(no(&tag, "BADSTATE", "STORE requires a selected mailbox"));
                    return Ok(out);
                };
                let Some(repo) = &services.repository else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "STORE requires a database-backed repository",
                    ));
                    return Ok(out);
                };
                let Some(mailbox) = repo.find_mailbox(account_id, selected_mailbox).await? else {
                    out.push(no(&tag, "NONEXISTENT", "selected mailbox not found"));
                    return Ok(out);
                };
                if self.selected_mailbox_is_read_only().unwrap_or(false) {
                    out.push(no(
                        &tag,
                        "READ-ONLY",
                        "STORE is not permitted in a read-only mailbox",
                    ));
                    return Ok(out);
                }
                let (sequence_set, store_mode, silent, requested_flags) =
                    parse_store_request(&command.args)?;
                let targets =
                    resolve_sequence_targets(repo.as_ref(), mailbox.id, &sequence_set).await?;
                for (sequence_number, message) in targets {
                    let updated_flags =
                        apply_store_flags(&message.flags, store_mode, &requested_flags);
                    repo.update_mailbox_message_flags(
                        mailbox.id,
                        message.local_uid,
                        updated_flags.clone(),
                    )
                    .await?;
                    if !silent {
                        out.push(format!(
                            "* {sequence_number} FETCH (FLAGS ({}))",
                            updated_flags.join(" ")
                        ));
                    }
                    if let Some(engine) = &services.mutation_engine {
                        engine
                            .queue_flag_update(
                                account_id,
                                mailbox.id,
                                None,
                                message.local_uid,
                                updated_flags,
                            )
                            .await?;
                    }
                }
                repo.refresh_mailbox_counts(mailbox.id).await?;
                if services.mutation_engine.is_some() {
                    out.push(ok(&tag, "STORE queued"));
                } else {
                    out.push(ok(&tag, "STORE completed"));
                }
            }
            "UID" => {
                let Some(subcommand) = command.args.first().map(|value| value.to_ascii_uppercase())
                else {
                    out.push(bad(&tag, "UID requires a subcommand"));
                    return Ok(out);
                };
                let Some(account_id) = self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "UID requires an authenticated account",
                    ));
                    return Ok(out);
                };
                let Some(selected_mailbox) = self.selected_mailbox_name_ref() else {
                    out.push(no(&tag, "BADSTATE", "UID requires a selected mailbox"));
                    return Ok(out);
                };
                let Some(repo) = &services.repository else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "UID requires a database-backed repository",
                    ));
                    return Ok(out);
                };
                let Some(source_mailbox) = repo.find_mailbox(account_id, selected_mailbox).await?
                else {
                    out.push(no(&tag, "NONEXISTENT", "selected mailbox not found"));
                    return Ok(out);
                };
                match subcommand.as_str() {
                    "FETCH" => {
                        let Some(set) = command.args.get(1) else {
                            out.push(bad(&tag, "UID FETCH requires a UID set"));
                            return Ok(out);
                        };
                        let items = parse_fetch_items(&command.args[2..]);
                        let views =
                            resolve_uid_views(repo.as_ref(), source_mailbox.id, set).await?;
                        for view in views {
                            out.push(format_fetch_response(view.local_uid, &view, &items));
                        }
                        out.push(ok(&tag, "UID FETCH completed"));
                    }
                    "SEARCH" => {
                        let (query, return_options) = parse_search_request(&command.args[1..])?;
                        let results = execute_search(
                            services.repository.as_ref(),
                            services.search.as_ref(),
                            Some(account_id),
                            selected_mailbox,
                            &query,
                            true,
                        )
                        .await?;
                        if return_options.is_some() {
                            out.push(format!(
                                "* ESEARCH (TAG \"{}\"){}",
                                tag,
                                format_esearch_summary(&results, return_options.unwrap())
                            ));
                        } else if results.is_empty() {
                            out.push("* SEARCH".to_string());
                        } else {
                            out.push(format!(
                                "* SEARCH {}",
                                results
                                    .into_iter()
                                    .map(|value| value.to_string())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            ));
                        }
                        out.push(ok(&tag, "UID SEARCH completed"));
                    }
                    "SORT" => {
                        let Some((sort_keys, reverse, query)) =
                            parse_sort_request(&command.args[1..])?
                        else {
                            out.push(bad(
                                &tag,
                                "UID SORT requires sort criteria, charset, and search criteria",
                            ));
                            return Ok(out);
                        };
                        let results = execute_sort(
                            services.repository.as_ref(),
                            services.search.as_ref(),
                            Some(account_id),
                            selected_mailbox,
                            &query,
                            &sort_keys,
                            reverse,
                            true,
                        )
                        .await?;
                        if results.is_empty() {
                            out.push("* SORT".to_string());
                        } else {
                            out.push(format!(
                                "* SORT {}",
                                results
                                    .into_iter()
                                    .map(|value| value.to_string())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            ));
                        }
                        out.push(ok(&tag, "UID SORT completed"));
                    }
                    "THREAD" => {
                        let Some((algorithm, query)) = parse_thread_request(&command.args[1..])?
                        else {
                            out.push(bad(
                                &tag,
                                "UID THREAD requires a threading algorithm, charset, and search criteria",
                            ));
                            return Ok(out);
                        };
                        let results = execute_thread(
                            services,
                            Some(account_id),
                            selected_mailbox,
                            &query,
                            algorithm,
                            true,
                        )
                        .await?;
                        if results.is_empty() {
                            out.push("* THREAD".to_string());
                        } else {
                            out.push(format!("* THREAD {}", results.join(" ")));
                        }
                        out.push(ok(&tag, "UID THREAD completed"));
                    }
                    "COPY" | "MOVE" => {
                        if subcommand == "MOVE"
                            && self.selected_mailbox_is_read_only().unwrap_or(false)
                        {
                            out.push(no(
                                &tag,
                                "READ-ONLY",
                                "MOVE is not permitted in a read-only mailbox",
                            ));
                            return Ok(out);
                        }
                        let Some(set) = command.args.get(1) else {
                            out.push(bad(&tag, &format!("UID {subcommand} requires a UID set")));
                            return Ok(out);
                        };
                        let Some(destination_name) = command.args.get(2) else {
                            out.push(bad(
                                &tag,
                                &format!("UID {subcommand} requires a destination mailbox"),
                            ));
                            return Ok(out);
                        };
                        let Some(destination_mailbox) =
                            repo.find_mailbox(account_id, destination_name).await?
                        else {
                            out.push(no(&tag, "NONEXISTENT", "destination mailbox not found"));
                            return Ok(out);
                        };
                        let targets =
                            resolve_uid_targets(repo.as_ref(), source_mailbox.id, set).await?;
                        let mut copied = Vec::new();
                        for message in targets {
                            let copied_message = repo
                                .copy_mailbox_message(
                                    source_mailbox.id,
                                    destination_mailbox.id,
                                    message.local_uid,
                                )
                                .await?;
                            if let Some(copied_message) = copied_message {
                                copied.push((message.local_uid, copied_message.local_uid));
                                if let Some(engine) = &services.mutation_engine {
                                    if subcommand == "MOVE" {
                                        engine
                                            .queue_move_message(
                                                account_id,
                                                source_mailbox.id,
                                                destination_mailbox.id,
                                                &source_mailbox.name,
                                                &destination_mailbox.name,
                                                message.local_uid,
                                                copied_message.local_uid,
                                                message.flags.clone(),
                                            )
                                            .await?;
                                    } else {
                                        engine
                                            .queue_copy_message(
                                                account_id,
                                                source_mailbox.id,
                                                destination_mailbox.id,
                                                &source_mailbox.name,
                                                &destination_mailbox.name,
                                                message.local_uid,
                                                copied_message.local_uid,
                                                message.flags.clone(),
                                            )
                                            .await?;
                                    }
                                }
                            }
                            if subcommand == "MOVE" {
                                repo.delete_mailbox_message(source_mailbox.id, message.local_uid)
                                    .await?;
                            }
                        }
                        repo.refresh_mailbox_counts(source_mailbox.id).await?;
                        repo.refresh_mailbox_counts(destination_mailbox.id).await?;
                        if copied.is_empty() {
                            out.push(ok(&tag, &format!("UID {subcommand} completed")));
                        } else {
                            let uidvalidity = destination_mailbox.uidvalidity.unwrap_or(1);
                            let source_uids = copied
                                .iter()
                                .map(|(source_uid, _)| source_uid.to_string())
                                .collect::<Vec<_>>()
                                .join(",");
                            let dest_uids = copied
                                .iter()
                                .map(|(_, dest_uid)| dest_uid.to_string())
                                .collect::<Vec<_>>()
                                .join(",");
                            out.push(format!(
                                "{tag} OK [COPYUID {uidvalidity} {source_uids} {dest_uids}] UID {subcommand} completed"
                            ));
                        }
                    }
                    "EXPUNGE" => {
                        if self.selected_mailbox_is_read_only().unwrap_or(false) {
                            out.push(no(
                                &tag,
                                "READ-ONLY",
                                "UID EXPUNGE is not permitted in a read-only mailbox",
                            ));
                            return Ok(out);
                        }
                        let Some(uid_set) = command.args.get(1) else {
                            out.push(bad(&tag, "UID EXPUNGE requires a UID set"));
                            return Ok(out);
                        };
                        let messages = repo.list_mailbox_messages(source_mailbox.id).await?;
                        let uids = parse_number_set(
                            uid_set,
                            messages
                                .iter()
                                .map(|message| message.local_uid)
                                .max()
                                .unwrap_or(0),
                        );
                        let mut targets = messages
                            .into_iter()
                            .enumerate()
                            .filter_map(|(index, message)| {
                                if uids.contains(&message.local_uid)
                                    && flags_contain_deleted(&message.flags)
                                {
                                    Some((index + 1, message))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>();
                        targets.sort_by_key(|(sequence, _)| *sequence);
                        for (sequence, message) in targets.into_iter().rev() {
                            repo.delete_mailbox_message(source_mailbox.id, message.local_uid)
                                .await?;
                            out.push(format!("* {sequence} EXPUNGE"));
                        }
                        repo.refresh_mailbox_counts(source_mailbox.id).await?;
                        out.push(ok(&tag, "UID EXPUNGE completed"));
                    }
                    "STORE" => {
                        if self.selected_mailbox_is_read_only().unwrap_or(false) {
                            out.push(no(
                                &tag,
                                "READ-ONLY",
                                "UID STORE is not permitted in a read-only mailbox",
                            ));
                            return Ok(out);
                        }
                        let (uid_set, store_mode, silent, requested_flags) =
                            parse_store_request(&command.args[1..])?;
                        let targets =
                            resolve_uid_targets(repo.as_ref(), source_mailbox.id, &uid_set).await?;
                        for message in &targets {
                            let updated_flags =
                                apply_store_flags(&message.flags, store_mode, &requested_flags);
                            repo.update_mailbox_message_flags(
                                source_mailbox.id,
                                message.local_uid,
                                updated_flags.clone(),
                            )
                            .await?;
                            if !silent {
                                let Some(sequence_number) = sequence_number_for_local_uid(
                                    repo.as_ref(),
                                    source_mailbox.id,
                                    message.local_uid,
                                )
                                .await?
                                else {
                                    continue;
                                };
                                out.push(format!(
                                    "* {sequence_number} FETCH (FLAGS ({}))",
                                    updated_flags.join(" ")
                                ));
                            }
                        }
                        repo.refresh_mailbox_counts(source_mailbox.id).await?;
                        if let Some(engine) = &services.mutation_engine {
                            for message in targets {
                                let updated_flags =
                                    apply_store_flags(&message.flags, store_mode, &requested_flags);
                                engine
                                    .queue_flag_update(
                                        account_id,
                                        source_mailbox.id,
                                        None,
                                        message.local_uid,
                                        updated_flags,
                                    )
                                    .await?;
                            }
                            out.push(ok(&tag, "UID STORE queued"));
                        } else {
                            out.push(ok(&tag, "UID STORE completed"));
                        }
                    }
                    other => {
                        out.push(no(
                            &tag,
                            "UNIMPLEMENTED",
                            &format!("UID {other} is not yet implemented"),
                        ));
                    }
                }
            }
            "APPEND" => {
                let Some(account_id) = self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "APPEND requires an authenticated account",
                    ));
                    return Ok(out);
                };
                let Some(repo) = &services.repository else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "APPEND requires a database-backed repository",
                    ));
                    return Ok(out);
                };
                let Some(mailbox_name) = command.args.first() else {
                    out.push(bad(&tag, "APPEND requires a mailbox"));
                    return Ok(out);
                };
                let Some(mailbox) = repo.find_mailbox(account_id, mailbox_name).await? else {
                    out.push(no(&tag, "NONEXISTENT", "selected mailbox not found"));
                    return Ok(out);
                };
                let body_index = command
                    .args
                    .iter()
                    .rposition(|value| value.starts_with('{'))
                    .unwrap_or(command.args.len().saturating_sub(1));
                let (flags, internal_date) = match parse_append_metadata(&command.args, body_index)
                {
                    Ok(value) => value,
                    Err(err) => {
                        out.push(bad(&tag, &err.to_string()));
                        return Ok(out);
                    }
                };
                let raw = match literal {
                    Some(raw) => raw,
                    None if body_index > 0 => command
                        .args
                        .get(body_index)
                        .map(|value| value.as_bytes().to_vec())
                        .unwrap_or_default(),
                    None => {
                        out.push(bad(&tag, "APPEND requires a literal"));
                        return Ok(out);
                    }
                };
                let ingestor = crate::sync::MessageIngestor::with_metrics(
                    Arc::clone(repo),
                    Arc::clone(&services.object_store),
                    services.search.clone(),
                    Arc::clone(&services.metrics),
                );
                let ingested = ingestor
                    .ingest_raw_message(
                        account_id,
                        mailbox.id,
                        mailbox_name,
                        0,
                        None,
                        internal_date,
                        &raw,
                        flags.clone(),
                    )
                    .await?;
                repo.refresh_mailbox_counts(mailbox.id).await?;
                let response_text = if services.mutation_engine.is_some() {
                    if let Some(engine) = &services.mutation_engine {
                        engine
                            .queue_append(
                                account_id,
                                mailbox.id,
                                mailbox_name,
                                Some(ingested.local_uid),
                                &raw,
                                flags,
                                internal_date,
                            )
                            .await?;
                    }
                    "APPEND queued"
                } else {
                    "APPEND completed"
                };
                let uidvalidity = mailbox.uidvalidity.unwrap_or(1);
                out.push(format!(
                    "{tag} OK [APPENDUID {uidvalidity} {}] {response_text}",
                    ingested.local_uid
                ));
            }
            "IDLE" => {
                if self.selected_mailbox_name_ref().is_none() {
                    out.push(no(&tag, "BADSTATE", "IDLE requires a selected mailbox"));
                    return Ok(out);
                }
                out.push("+ idling".to_string());
                out.push(ok(&tag, "IDLE terminated"));
            }
            "CHECK" => {
                if self.selected_mailbox_name_ref().is_none() {
                    out.push(no(&tag, "BADSTATE", "CHECK requires a selected mailbox"));
                    return Ok(out);
                }
                out.push(ok(&tag, "CHECK completed"));
            }
            "UNSELECT" => {
                if self.selected_mailbox_name_ref().is_none() {
                    out.push(no(&tag, "BADSTATE", "UNSELECT requires a selected mailbox"));
                    return Ok(out);
                }
                self.selected_mailbox_snapshot = None;
                self.state = State::Authenticated;
                out.push(ok(&tag, "UNSELECT completed"));
            }
            "CLOSE" => {
                if self.selected_mailbox_name_ref().is_none() {
                    out.push(no(&tag, "BADSTATE", "CLOSE requires a selected mailbox"));
                    return Ok(out);
                }
                if !self.selected_mailbox_is_read_only().unwrap_or(false) {
                    if let (Some(repo), Some(snapshot)) =
                        (&services.repository, self.selected_mailbox_snapshot.clone())
                    {
                        if snapshot.mailbox_id > 0 {
                            let deleted_messages = repo
                                .list_mailbox_messages(snapshot.mailbox_id)
                                .await?
                                .into_iter()
                                .filter(|message| flags_contain_deleted(&message.flags))
                                .collect::<Vec<_>>();
                            for message in deleted_messages {
                                repo.delete_mailbox_message(snapshot.mailbox_id, message.local_uid)
                                    .await?;
                            }
                            repo.refresh_mailbox_counts(snapshot.mailbox_id).await?;
                        }
                    }
                }
                self.selected_mailbox_snapshot = None;
                self.state = State::Authenticated;
                out.push(ok(&tag, "CLOSE completed"));
            }
            "EXPUNGE" => {
                let Some(account_id) = self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "EXPUNGE requires an authenticated account",
                    ));
                    return Ok(out);
                };
                let Some(selected_mailbox) = self.selected_mailbox_name_ref() else {
                    out.push(no(&tag, "BADSTATE", "EXPUNGE requires a selected mailbox"));
                    return Ok(out);
                };
                let Some(repo) = &services.repository else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "EXPUNGE requires a database-backed repository",
                    ));
                    return Ok(out);
                };
                let Some(mailbox) = repo.find_mailbox(account_id, selected_mailbox).await? else {
                    out.push(no(&tag, "NONEXISTENT", "selected mailbox not found"));
                    return Ok(out);
                };
                if self.selected_mailbox_is_read_only().unwrap_or(false) {
                    out.push(no(
                        &tag,
                        "READ-ONLY",
                        "EXPUNGE is not permitted in a read-only mailbox",
                    ));
                    return Ok(out);
                }
                let targets = if let Some(set) = command.args.first() {
                    resolve_sequence_targets(repo.as_ref(), mailbox.id, set).await?
                } else {
                    repo.list_mailbox_messages(mailbox.id)
                        .await?
                        .into_iter()
                        .enumerate()
                        .filter_map(|(index, message)| {
                            if flags_contain_deleted(&message.flags) {
                                Some((index + 1, message))
                            } else {
                                None
                            }
                        })
                        .collect()
                };
                let mut targets = targets;
                targets.sort_by_key(|(sequence, _)| *sequence);
                for (sequence, message) in targets.into_iter().rev() {
                    repo.delete_mailbox_message(mailbox.id, message.local_uid)
                        .await?;
                    out.push(format!("* {sequence} EXPUNGE"));
                }
                repo.refresh_mailbox_counts(mailbox.id).await?;
                out.push(ok(&tag, "EXPUNGE completed"));
            }
            "CREATE" => {
                if let Some(repo) = &services.repository {
                    let Some(account_id) =
                        self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                    else {
                        out.push(no(
                            &tag,
                            "BADSTATE",
                            "CREATE requires an authenticated account",
                        ));
                        return Ok(out);
                    };
                    let Some(mailbox_name) = command.args.first() else {
                        out.push(bad(&tag, "CREATE requires a mailbox name"));
                        return Ok(out);
                    };
                    let canonical_name = canonical_mailbox_name(mailbox_name);
                    let created = repo
                        .create_mailbox(crate::db::repository::NewMailbox {
                            account_id,
                            name: mailbox_name,
                            canonical_name: &canonical_name,
                            delimiter: Some("/"),
                            attributes: vec!["\\HasNoChildren".to_string()],
                            subscribed: false,
                            special_use: None,
                            uidvalidity: Some(1),
                            uidnext: Some(1),
                            highestmodseq: Some(0),
                            exists_count: 0,
                            recent_count: 0,
                            unseen_count: 0,
                        })
                        .await?;
                    match created {
                        Some(_) => out.push(ok(&tag, "CREATE completed")),
                        None => out.push(no(&tag, "ALREADYEXISTS", "mailbox already exists")),
                    }
                } else {
                    out.push(ok(&tag, "CREATE completed"));
                }
            }
            "DELETE" => {
                if let Some(repo) = &services.repository {
                    let Some(account_id) =
                        self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                    else {
                        out.push(no(
                            &tag,
                            "BADSTATE",
                            "DELETE requires an authenticated account",
                        ));
                        return Ok(out);
                    };
                    let Some(mailbox_name) = command.args.first() else {
                        out.push(bad(&tag, "DELETE requires a mailbox name"));
                        return Ok(out);
                    };
                    let rows = repo.delete_mailbox(account_id, mailbox_name).await?;
                    if rows == 0 {
                        out.push(no(&tag, "NONEXISTENT", "mailbox not found"));
                    } else {
                        out.push(ok(&tag, "DELETE completed"));
                    }
                } else {
                    out.push(ok(&tag, "DELETE completed"));
                }
            }
            "RENAME" => {
                if let Some(repo) = &services.repository {
                    let Some(account_id) =
                        self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                    else {
                        out.push(no(
                            &tag,
                            "BADSTATE",
                            "RENAME requires an authenticated account",
                        ));
                        return Ok(out);
                    };
                    let Some(source_name) = command.args.first() else {
                        out.push(bad(&tag, "RENAME requires a source mailbox"));
                        return Ok(out);
                    };
                    let Some(dest_name) = command.args.get(1) else {
                        out.push(bad(&tag, "RENAME requires a destination mailbox"));
                        return Ok(out);
                    };
                    let renamed = repo
                        .rename_mailbox(account_id, source_name, dest_name)
                        .await?;
                    match renamed {
                        Some(_) => {
                            if let State::SelectedMailbox { mailbox, .. } = &mut self.state {
                                if mailbox.eq_ignore_ascii_case(source_name) {
                                    *mailbox = dest_name.clone();
                                }
                            }
                            out.push(ok(&tag, "RENAME completed"));
                        }
                        None => out.push(no(
                            &tag,
                            "NONEXISTENT",
                            "mailbox not found or destination already exists",
                        )),
                    }
                } else {
                    out.push(ok(&tag, "RENAME completed"));
                }
            }
            "SUBSCRIBE" | "UNSUBSCRIBE" => {
                if let Some(repo) = &services.repository {
                    let Some(account_id) =
                        self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                    else {
                        out.push(no(
                            &tag,
                            "BADSTATE",
                            &format!("{name} requires an authenticated account"),
                        ));
                        return Ok(out);
                    };
                    let Some(mailbox_name) = command.args.first() else {
                        out.push(bad(&tag, &format!("{name} requires a mailbox name")));
                        return Ok(out);
                    };
                    let subscribed = name == "SUBSCRIBE";
                    let updated = repo
                        .set_mailbox_subscribed(account_id, mailbox_name, subscribed)
                        .await?;
                    match updated {
                        Some(_) => out.push(ok(&tag, &format!("{name} completed"))),
                        None => out.push(no(&tag, "NONEXISTENT", "mailbox not found")),
                    }
                } else {
                    out.push(ok(&tag, &format!("{name} completed")));
                }
            }
            "COPY" | "MOVE" => {
                let Some(account_id) = self.authenticated.as_ref().and_then(|ctx| ctx.account_id)
                else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        &format!("{name} requires an authenticated account"),
                    ));
                    return Ok(out);
                };
                let Some(selected_mailbox) = self.selected_mailbox_name_ref() else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        &format!("{name} requires a selected mailbox"),
                    ));
                    return Ok(out);
                };
                let Some(repo) = &services.repository else {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        &format!("{name} requires a database-backed repository"),
                    ));
                    return Ok(out);
                };
                let Some(source_mailbox) = repo.find_mailbox(account_id, selected_mailbox).await?
                else {
                    out.push(no(&tag, "NONEXISTENT", "selected mailbox not found"));
                    return Ok(out);
                };
                let Some(set) = command.args.first() else {
                    out.push(bad(&tag, &format!("{name} requires a message set")));
                    return Ok(out);
                };
                let Some(destination_name) = command.args.get(1) else {
                    out.push(bad(&tag, &format!("{name} requires a destination mailbox")));
                    return Ok(out);
                };
                let Some(destination_mailbox) =
                    repo.find_mailbox(account_id, destination_name).await?
                else {
                    out.push(no(&tag, "NONEXISTENT", "destination mailbox not found"));
                    return Ok(out);
                };
                if name == "MOVE" && self.selected_mailbox_is_read_only().unwrap_or(false) {
                    out.push(no(
                        &tag,
                        "READ-ONLY",
                        "MOVE is not permitted in a read-only mailbox",
                    ));
                    return Ok(out);
                }
                let targets =
                    resolve_sequence_targets(repo.as_ref(), source_mailbox.id, set).await?;
                let mut copied = Vec::new();
                for (sequence, message) in targets {
                    let copied_message = repo
                        .copy_mailbox_message(
                            source_mailbox.id,
                            destination_mailbox.id,
                            message.local_uid,
                        )
                        .await?;
                    if let Some(copied_message) = copied_message {
                        copied.push((message.local_uid, copied_message.local_uid));
                        if let Some(engine) = &services.mutation_engine {
                            if name == "MOVE" {
                                engine
                                    .queue_move_message(
                                        account_id,
                                        source_mailbox.id,
                                        destination_mailbox.id,
                                        &source_mailbox.name,
                                        &destination_mailbox.name,
                                        message.local_uid,
                                        copied_message.local_uid,
                                        message.flags.clone(),
                                    )
                                    .await?;
                            } else {
                                engine
                                    .queue_copy_message(
                                        account_id,
                                        source_mailbox.id,
                                        destination_mailbox.id,
                                        &source_mailbox.name,
                                        &destination_mailbox.name,
                                        message.local_uid,
                                        copied_message.local_uid,
                                        message.flags.clone(),
                                    )
                                    .await?;
                            }
                        }
                    }
                    if name == "MOVE" {
                        repo.delete_mailbox_message(source_mailbox.id, message.local_uid)
                            .await?;
                        out.push(format!("* {sequence} EXPUNGE"));
                    }
                }
                repo.refresh_mailbox_counts(source_mailbox.id).await?;
                repo.refresh_mailbox_counts(destination_mailbox.id).await?;
                if copied.is_empty() {
                    out.push(ok(&tag, &format!("{name} completed")));
                } else {
                    let uidvalidity = destination_mailbox.uidvalidity.unwrap_or(1);
                    let source_uids = copied
                        .iter()
                        .map(|(source_uid, _)| source_uid.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    let dest_uids = copied
                        .iter()
                        .map(|(_, dest_uid)| dest_uid.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    out.push(format!(
                        "{tag} OK [COPYUID {uidvalidity} {source_uids} {dest_uids}] {name} completed"
                    ));
                }
            }
            "NAMESPACE" => {
                out.push(r#"* NAMESPACE (("" "/")) NIL NIL"#.to_string());
                out.push(ok(&tag, "NAMESPACE completed"));
            }
            "ID" => {
                out.push(
                    r#"* ID ("name" "imap-cache-rs" "vendor" "openai" "support-url" "https://openai.com")"#
                        .to_string(),
                );
                out.push(ok(&tag, "ID completed"));
            }
            "ENABLE" => {
                if !matches!(
                    self.state,
                    State::Authenticated | State::SelectedMailbox { .. }
                ) {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "ENABLE requires an authenticated session",
                    ));
                    return Ok(out);
                }
                let enabled = command
                    .args
                    .iter()
                    .filter(|arg| arg.eq_ignore_ascii_case("CONDSTORE"))
                    .map(|arg| arg.to_ascii_uppercase())
                    .collect::<Vec<_>>();
                if !enabled.is_empty() {
                    out.push(format!("* ENABLED {}", enabled.join(" ")));
                }
                out.push(ok(&tag, "ENABLE completed"));
            }
            "CONDSTORE" => {
                if !matches!(
                    self.state,
                    State::Authenticated | State::SelectedMailbox { .. }
                ) {
                    out.push(no(
                        &tag,
                        "BADSTATE",
                        "CONDSTORE requires an authenticated session",
                    ));
                    return Ok(out);
                }
                out.push(ok(&tag, "CONDSTORE completed"));
            }
            other => out.push(no(
                &tag,
                "UNIMPLEMENTED",
                &format!("{other} is not yet implemented"),
            )),
        }

        Ok(out)
    }
}
fn apply_store_flags(current: &[String], mode: StoreMode, requested: &[String]) -> Vec<String> {
    match mode {
        StoreMode::Replace => dedupe_flags(requested),
        StoreMode::Add => {
            let mut out = current.to_vec();
            for flag in requested {
                if !out
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(flag))
                {
                    out.push(flag.clone());
                }
            }
            out
        }
        StoreMode::Remove => current
            .iter()
            .filter(|existing| {
                !requested
                    .iter()
                    .any(|flag| existing.eq_ignore_ascii_case(flag))
            })
            .cloned()
            .collect(),
    }
}

fn dedupe_flags(flags: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for flag in flags {
        if !out
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(flag))
        {
            out.push(flag.clone());
        }
    }
    out
}

fn split_rfc822(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(index) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
        let header_end = index + 2;
        let body_start = index + 4;
        (&raw[..header_end], &raw[body_start..])
    } else {
        (raw, &[])
    }
}

fn header_blocks(headers: &[u8]) -> Vec<&[u8]> {
    let mut blocks = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    while index < headers.len() {
        if index + 1 < headers.len() && &headers[index..index + 2] == b"\r\n" {
            let line = &headers[start..index];
            let next_start = index + 2;
            if next_start >= headers.len() {
                if !line.is_empty() {
                    blocks.push(&headers[start..index]);
                }
                break;
            }
            let next_is_continuation = headers[next_start] == b' ' || headers[next_start] == b'\t';
            if !next_is_continuation {
                blocks.push(&headers[start..index]);
                start = next_start;
            }
            index = next_start;
            continue;
        }
        index += 1;
    }
    if start < headers.len() {
        blocks.push(&headers[start..]);
    }
    blocks
        .into_iter()
        .filter(|block| !block.is_empty())
        .collect()
}

fn header_name(block: &[u8]) -> Option<String> {
    let line_end = block
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(block.len());
    let first_line = &block[..line_end];
    let colon = first_line.iter().position(|byte| *byte == b':')?;
    Some(
        String::from_utf8_lossy(&first_line[..colon])
            .trim()
            .to_ascii_uppercase(),
    )
}

fn select_header_blocks(headers: &[u8], names: &[String], not: bool) -> Vec<u8> {
    let blocks = header_blocks(headers);
    let mut out = Vec::new();
    for block in blocks {
        let name = header_name(block).unwrap_or_default();
        let contains = names
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&name));
        if contains ^ not {
            out.extend_from_slice(block);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn raw_fetch_bytes(raw: &[u8], section: &FetchBodySection) -> Vec<u8> {
    let (headers, body) = split_rfc822(raw);
    let selected = match section {
        FetchBodySection::Full => raw.to_vec(),
        FetchBodySection::Header | FetchBodySection::Mime => {
            let mut out = headers.to_vec();
            out.extend_from_slice(b"\r\n");
            out
        }
        FetchBodySection::Text => body.to_vec(),
        FetchBodySection::HeaderFields { names, not } => {
            select_header_blocks(headers, names, *not)
        }
    };
    selected
}

fn mime_part_fetch_bytes(
    raw: &[u8],
    part: &crate::domain::MimePart,
    section: &FetchBodySection,
) -> Vec<u8> {
    if part.content_type.eq_ignore_ascii_case("message/rfc822") {
        return raw_fetch_bytes(raw, section);
    }

    match section {
        FetchBodySection::Full | FetchBodySection::Text => raw.to_vec(),
        FetchBodySection::Header | FetchBodySection::Mime => {
            synthesize_mime_part_headers(part)
        }
        FetchBodySection::HeaderFields { names, not } => {
            let headers = synthesize_mime_part_headers(part);
            select_header_blocks(&headers, names, *not)
        }
    }
}

fn synthesize_mime_part_headers(part: &crate::domain::MimePart) -> Vec<u8> {
    let mut headers = Vec::new();
    headers.extend_from_slice(
        format!(
            "Content-Type: {}{}\r\n",
            part.content_type,
            part.charset
                .as_deref()
                .map(|charset| format!("; charset=\"{charset}\""))
                .unwrap_or_default()
        )
        .as_bytes(),
    );
    if let Some(transfer_encoding) = &part.transfer_encoding {
        headers.extend_from_slice(
            format!("Content-Transfer-Encoding: {}\r\n", transfer_encoding).as_bytes(),
        );
    }
    if let Some(content_id) = &part.content_id {
        headers.extend_from_slice(format!("Content-ID: <{content_id}>\r\n").as_bytes());
    }
    if let Some(description) = part.metadata_json.get("description").and_then(|value| value.as_str()) {
        headers.extend_from_slice(format!("Content-Description: {description}\r\n").as_bytes());
    }
    if let Some(disposition) = &part.disposition {
        if let Some(filename) = &part.filename {
            headers.extend_from_slice(
                format!(
                    "Content-Disposition: {};\r\n\tfilename=\"{}\"\r\n",
                    disposition, filename
                )
                .as_bytes(),
            );
        } else {
            headers.extend_from_slice(
                format!("Content-Disposition: {}\r\n", disposition).as_bytes(),
            );
        }
    } else if let Some(filename) = &part.filename {
        headers.extend_from_slice(
            format!("Content-Disposition: attachment;\r\n\tfilename=\"{}\"\r\n", filename).as_bytes(),
        );
    }
    headers.extend_from_slice(b"\r\n");
    headers
}

fn cache_object_type_for_mime_part(part: &crate::domain::MimePart) -> &'static str {
    if matches!(part.disposition.as_deref(), Some("attachment")) || part.filename.is_some() {
        "Attachment"
    } else {
        "MimePart"
    }
}

fn apply_partial(bytes: &[u8], partial: Option<(usize, Option<usize>)>) -> Vec<u8> {
    let Some((offset, count)) = partial else {
        return bytes.to_vec();
    };
    if offset >= bytes.len() {
        return Vec::new();
    }
    let end = match count {
        Some(count) => offset.saturating_add(count).min(bytes.len()),
        None => bytes.len(),
    };
    bytes[offset..end].to_vec()
}

async fn load_raw_fetch_bytes(
    services: &AppServices,
    account_id: i64,
    mailbox_name: &str,
    view: &crate::db::repository::MailboxMessageView,
    section: &RawFetchSection,
    partial: Option<(usize, Option<usize>)>,
    metrics: &AppMetrics,
) -> Result<Option<Vec<u8>>> {
    let store = services.object_store.as_ref();
    match section {
        RawFetchSection::Whole(FetchBodySection::Full) => {
            let key = &view.rfc822_blob_key;
            if let Some((offset, count)) = partial {
                let end = count.map(|count| offset.saturating_add(count));
                let bytes = store.get_range(key, offset, end).await?;
                if let Some(bytes) = bytes.as_ref() {
                    metrics.record_cache_hit();
                    metrics.record_object_store_bytes_read(bytes.len() as u64);
                    if let Some(repo) = &services.repository {
                        let _ = repo.touch_cache_object(account_id, key).await;
                    }
                } else if let Some(raw) =
                    rehydrate_missing_raw_blob(services, account_id, mailbox_name, view).await?
                {
                    metrics.record_cache_miss();
                    metrics.record_object_store_bytes_written(raw.len() as u64);
                    metrics.record_object_store_bytes_read(raw.len() as u64);
                    let bytes = raw_fetch_bytes(&raw, &FetchBodySection::Full);
                    return Ok(Some(apply_partial(&bytes, partial)));
                } else {
                    metrics.record_cache_miss();
                }
                return Ok(bytes);
            }

            let (raw, cache_hit) = match store.get(key).await? {
                Some(raw) => (raw, true),
                None => {
                    let Some(raw) =
                        rehydrate_missing_raw_blob(services, account_id, mailbox_name, view)
                            .await?
                    else {
                        metrics.record_cache_miss();
                        return Ok(None);
                    };
                    (raw, false)
                }
            };
            if cache_hit {
                metrics.record_cache_hit();
            } else {
                metrics.record_cache_miss();
            }
            metrics.record_object_store_bytes_read(raw.len() as u64);
            if cache_hit && let Some(repo) = &services.repository {
                let _ = repo.touch_cache_object(account_id, key).await;
            }
            return Ok(Some(raw_fetch_bytes(&raw, &FetchBodySection::Full)));
        }
        RawFetchSection::Whole(section) => {
            let key = &view.rfc822_blob_key;
            let (raw, cache_hit) = match store.get(key).await? {
                Some(raw) => (raw, true),
                None => {
                    let Some(raw) =
                        rehydrate_missing_raw_blob(services, account_id, mailbox_name, view)
                            .await?
                    else {
                        metrics.record_cache_miss();
                        return Ok(None);
                    };
                    (raw, false)
                }
            };
            if cache_hit {
                metrics.record_cache_hit();
            } else {
                metrics.record_cache_miss();
            }
            metrics.record_object_store_bytes_read(raw.len() as u64);
            if cache_hit && let Some(repo) = &services.repository {
                let _ = repo.touch_cache_object(account_id, key).await;
            }
            let bytes = raw_fetch_bytes(&raw, section);
            return Ok(Some(if partial.is_some() {
                apply_partial(&bytes, partial)
            } else {
                bytes
            }));
        }
        RawFetchSection::Part { path, section } => {
            let Some(repo) = &services.repository else {
                metrics.record_cache_miss();
                return Ok(None);
            };
            let stored_path = format!("1.{path}");
            let Some(part) = repo
                .find_mime_part_by_message_and_path(account_id, view.message_id, &stored_path)
                .await?
            else {
                metrics.record_cache_miss();
                return Ok(None);
            };
            let key = &part.blob_key;
            if let Some((offset, count)) = partial {
                if matches!(section, FetchBodySection::Full) {
                    let end = count.map(|count| offset.saturating_add(count));
                    let bytes = store.get_range(key, offset, end).await?;
                    if let Some(bytes) = bytes.as_ref() {
                        metrics.record_cache_hit();
                        metrics.record_object_store_bytes_read(bytes.len() as u64);
                        if let Some(repo) = &services.repository {
                            let _ = repo.touch_cache_object(account_id, key).await;
                        }
                    } else {
                        metrics.record_cache_miss();
                    }
                    return Ok(bytes);
                }
            }
            let raw = if let Some(raw) = store.get(key).await? {
                metrics.record_cache_hit();
                metrics.record_object_store_bytes_read(raw.len() as u64);
                raw
            } else {
                metrics.record_cache_miss();
                let raw_rfc822 = match store.get(&view.rfc822_blob_key).await? {
                    Some(raw) => {
                        metrics.record_cache_hit();
                        metrics.record_object_store_bytes_read(raw.len() as u64);
                        Some(raw)
                    }
                    None => {
                        rehydrate_missing_raw_blob(services, account_id, mailbox_name, view).await?
                    }
                };
                let Some(raw_rfc822) = raw_rfc822 else {
                    return Ok(None);
                };
                let Some(bytes) = crate::mime::extract_part_bytes(&raw_rfc822, &stored_path)? else {
                    return Ok(None);
                };
                let metadata = store.put(key, &bytes).await?;
                metrics.record_object_store_bytes_written(metadata.size_octets);
                if let Some(repo) = &services.repository {
                    let object_type = cache_object_type_for_mime_part(&part);
                    if repo
                        .find_cache_object_by_account_type_and_blob_key(
                            account_id,
                            object_type,
                            key,
                        )
                        .await?
                        .is_none()
                    {
                        let _ = repo
                            .upsert_cache_object(NewCacheObject {
                                account_id: Some(account_id),
                                object_type,
                                blob_key: key,
                                sha256: &metadata.sha256,
                                size_octets: metadata.size_octets as i64,
                                ref_count: 1,
                                last_accessed_at: Some(chrono::Utc::now()),
                            })
                            .await?;
                    } else {
                        let _ = repo.touch_cache_object(account_id, key).await?;
                    }
                }
                bytes
            };
            if let Some(repo) = &services.repository {
                let _ = repo.touch_cache_object(account_id, key).await;
            }
            let bytes = mime_part_fetch_bytes(&raw, &part, section);
            return Ok(Some(if partial.is_some() {
                apply_partial(&bytes, partial)
            } else {
                bytes
            }));
        }
    }
}

async fn rehydrate_missing_raw_blob(
    services: &AppServices,
    account_id: i64,
    mailbox_name: &str,
    view: &crate::db::repository::MailboxMessageView,
) -> Result<Option<Vec<u8>>> {
    let Some(upstream_uid) = view.upstream_uid else {
        return Ok(None);
    };
    let Some(repo) = &services.repository else {
        return Ok(None);
    };
    let Some(account) = repo.find_account_by_id_any_state(account_id).await? else {
        return Ok(None);
    };
    let Some(upstream_config) = repo.upstream_account_config(&account.email_address).await? else {
        return Ok(None);
    };

    let mut upstream = crate::upstream::UpstreamClient::connect(&upstream_config)
        .await?
        .with_account_connection_limit(
            account_id,
            crate::config::upstream_connection_limit_per_account(),
        )
        .await?;
    upstream
        .authenticate_with_method(
            upstream_config.auth_method,
            &upstream_config.username,
            &upstream_config.secret,
        )
        .await?;
    upstream.select(mailbox_name).await?;
    let raw = upstream.uid_fetch_rfc822(upstream_uid as u64).await?;
    let metadata = services
        .object_store
        .put(&view.rfc822_blob_key, &raw)
        .await?;
    if let Some(repo) = &services.repository {
        if repo
            .find_cache_object_by_account_type_and_blob_key(account_id, "rfc822", &metadata.key)
            .await?
            .is_none()
        {
            let _ = repo
                .upsert_cache_object(NewCacheObject {
                    account_id: Some(account_id),
                    object_type: "rfc822",
                    blob_key: &metadata.key,
                    sha256: &metadata.sha256,
                    size_octets: metadata.size_octets as i64,
                    ref_count: 1,
                    last_accessed_at: Some(chrono::Utc::now()),
                })
                .await?;
        } else {
            let _ = repo.touch_cache_object(account_id, &metadata.key).await?;
        }
    }
    services
        .metrics
        .record_object_store_bytes_written(raw.len() as u64);
    Ok(Some(raw))
}

fn fetch_metadata_part(
    view: &crate::db::repository::MailboxMessageView,
    item: &str,
) -> Option<String> {
    match item {
        "FLAGS" => Some(format!("FLAGS ({})", view.flags.join(" "))),
        "UID" => Some(format!("UID {}", view.local_uid)),
        "RFC822.SIZE" => Some(format!("RFC822.SIZE {}", view.size_octets)),
        "INTERNALDATE" => {
            let date = view
                .internal_date
                .unwrap_or(view.created_at)
                .format("%d-%b-%Y %H:%M:%S %z")
                .to_string();
            Some(format!("INTERNALDATE {}", quote_imap_string(&date)))
        }
        "ENVELOPE" => Some(format!("ENVELOPE {}", encode_envelope(&view.envelope_json))),
        "BODYSTRUCTURE" => Some(format!(
            "BODYSTRUCTURE {}",
            encode_bodystructure(&view.bodystructure_json)
        )),
        _ => None,
    }
}

async fn write_raw_fetch_response<W>(
    writer: &mut W,
    services: &AppServices,
    session: &mut ImapSession,
    command: &ParsedCommand,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    let Some(account_id) = session
        .authenticated
        .as_ref()
        .and_then(|ctx| ctx.account_id)
    else {
        return Ok(false);
    };
    let Some(selected_mailbox) = session.selected_mailbox_name_ref() else {
        return Ok(false);
    };
    let Some(repo) = &services.repository else {
        return Ok(false);
    };
    let Some(mailbox) = repo.find_mailbox(account_id, selected_mailbox).await? else {
        return Ok(false);
    };

    let is_uid = command.name.eq_ignore_ascii_case("UID");
    let (set_index, items_index) = if is_uid {
        (1usize, 2usize)
    } else {
        (0usize, 1usize)
    };
    let Some(set) = command.args.get(set_index) else {
        return Ok(false);
    };
    let items = parse_fetch_items(&command.args[items_index..]);
    let Some(raw_index) = items
        .iter()
        .position(|item| parse_raw_fetch_request(item).is_some())
    else {
        return Ok(false);
    };
    let views = if is_uid {
        resolve_uid_views(repo.as_ref(), mailbox.id, set)
            .await?
            .into_iter()
            .map(|view| (view.local_uid, view))
            .collect::<Vec<_>>()
    } else {
        resolve_sequence_views(repo.as_ref(), mailbox.id, set).await?
    };

    let metadata_before = &items[..raw_index];
    let metadata_after = &items[raw_index + 1..];
    let raw_item = parse_raw_fetch_request(&items[raw_index]).expect("checked above");

    for (sequence_number, view) in views {
        let Some(raw_bytes) = load_raw_fetch_bytes(
            services,
            account_id,
            selected_mailbox,
            &view,
            &raw_item.section,
            raw_item.partial,
            &services.metrics,
        )
        .await?
        else {
            return Err(Error::Storage(format!(
                "missing raw RFC822 blob: {}",
                view.rfc822_blob_key
            )));
        };
        if !raw_item.peek
            && !view
                .flags
                .iter()
                .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
        {
            let mut seen_flags = view.flags.clone();
            seen_flags.push("\\Seen".to_string());
            let seen_flags = dedupe_flags(&seen_flags);
            let _ = repo
                .update_mailbox_message_flags(mailbox.id, view.local_uid, seen_flags.clone())
                .await?;
            if let Some(engine) = &services.mutation_engine {
                engine
                    .queue_flag_update(account_id, mailbox.id, None, view.local_uid, seen_flags)
                    .await?;
            }
        }
        let selected = raw_bytes;
        let before_parts = metadata_before
            .iter()
            .filter_map(|item| fetch_metadata_part(&view, item))
            .collect::<Vec<_>>();
        let after_parts = metadata_after
            .iter()
            .filter_map(|item| fetch_metadata_part(&view, item))
            .collect::<Vec<_>>();

        let mut prefix = format!("* {sequence_number} FETCH (");
        if !before_parts.is_empty() {
            prefix.push_str(&before_parts.join(" "));
            prefix.push(' ');
        }
        prefix.push_str(&format!("{} {{{}}}\r\n", raw_item.label, selected.len()));
        writer.write_all(prefix.as_bytes()).await?;
        writer.write_all(&selected).await?;
        services
            .metrics
            .record_downstream_bytes(selected.len() as u64);
        if after_parts.is_empty() {
            writer.write_all(b")\r\n").await?;
        } else {
            writer
                .write_all(format!(" {} )\r\n", after_parts.join(" ")).as_bytes())
                .await?;
        }
    }

    Ok(true)
}

fn format_imap_date(value: chrono::DateTime<chrono::Utc>) -> String {
    value.format("%d-%b-%Y %H:%M:%S %z").to_string()
}

fn parse_imap_date_time(value: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_str(value, "%d-%b-%Y %H:%M:%S %z")
        .map(|parsed| parsed.with_timezone(&chrono::Utc))
        .map_err(|err| Error::Parse(format!("invalid IMAP date-time {value:?}: {err}")))
}

fn parse_append_metadata(
    args: &[String],
    body_index: usize,
) -> Result<(Vec<String>, Option<chrono::DateTime<chrono::Utc>>)> {
    let extras = args.get(1..body_index).unwrap_or(&[]);
    match extras.len() {
        0 => Ok((Vec::new(), None)),
        1 => {
            let token = &extras[0];
            if token.starts_with('(') {
                Ok((parse_flag_list(token), None))
            } else {
                Ok((Vec::new(), Some(parse_imap_date_time(token)?)))
            }
        }
        2 => {
            let first = &extras[0];
            let second = &extras[1];
            match (first.starts_with('('), second.starts_with('(')) {
                (true, false) => Ok((parse_flag_list(first), Some(parse_imap_date_time(second)?))),
                (false, true) => Ok((parse_flag_list(second), Some(parse_imap_date_time(first)?))),
                _ => Err(Error::Parse(
                    "APPEND accepts at most one flag list and one date-time".to_string(),
                )),
            }
        }
        _ => Err(Error::Parse(
            "APPEND accepts at most one flag list and one date-time".to_string(),
        )),
    }
}

fn nstring(value: Option<&str>) -> String {
    value
        .map(quote_imap_string)
        .unwrap_or_else(|| "NIL".to_string())
}

fn encode_imap_address_list(value: Option<&serde_json::Value>) -> String {
    let Some(value) = value else {
        return "NIL".to_string();
    };
    let Some(items) = value.as_array() else {
        return "NIL".to_string();
    };
    if items.is_empty() {
        return "NIL".to_string();
    }

    let mut encoded = Vec::new();
    for item in items {
        let kind = item
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("mailbox");
        if kind != "mailbox" {
            continue;
        }
        let display_name = item.get("display_name").and_then(|v| v.as_str());
        let address = item.get("address").and_then(|v| v.as_str()).unwrap_or("");
        let (local_part, domain_part) = match address.split_once('@') {
            Some((local, domain)) => (Some(local), Some(domain)),
            None => (Some(address), None),
        };
        encoded.push(format!(
            "({} NIL {} {})",
            nstring(display_name),
            nstring(local_part),
            nstring(domain_part)
        ));
    }

    if encoded.is_empty() {
        "NIL".to_string()
    } else {
        format!("({})", encoded.join(" "))
    }
}

fn encode_envelope(value: &serde_json::Value) -> String {
    let date = value.get("date").and_then(|v| v.as_i64()).and_then(|ts| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0).map(format_imap_date)
    });
    let subject = value.get("subject").and_then(|v| v.as_str());
    let from = encode_imap_address_list(value.get("from"));
    let reply_to = encode_imap_address_list(value.get("reply_to"));
    let to = encode_imap_address_list(value.get("to"));
    let cc = encode_imap_address_list(value.get("cc"));
    let bcc = encode_imap_address_list(value.get("bcc"));
    let message_id = value.get("message_id").and_then(|v| v.as_str());

    format!(
        "({} {} {} {} {} {} {} {} NIL {})",
        date.as_deref()
            .map(quote_imap_string)
            .unwrap_or_else(|| "NIL".to_string()),
        nstring(subject),
        from,
        from,
        reply_to,
        to,
        cc,
        bcc,
        nstring(message_id)
    )
}

fn encode_param_list(params: Option<&serde_json::Value>) -> String {
    let Some(serde_json::Value::Object(map)) = params else {
        return "NIL".to_string();
    };
    if map.is_empty() {
        return "NIL".to_string();
    }
    let mut parts = Vec::new();
    for (key, value) in map {
        if let Some(text) = value.as_str() {
            parts.push(quote_imap_string(key));
            parts.push(quote_imap_string(text));
        }
    }
    if parts.is_empty() {
        "NIL".to_string()
    } else {
        format!("({})", parts.join(" "))
    }
}

fn encode_bodystructure(value: &serde_json::Value) -> String {
    match value.get("type").and_then(|v| v.as_str()) {
        Some("multipart") => {
            let parts = value
                .get("parts")
                .and_then(|v| v.as_array())
                .map(|parts| parts.iter().map(encode_bodystructure).collect::<Vec<_>>())
                .unwrap_or_default();
            let subtype = value
                .get("subtype")
                .and_then(|v| v.as_str())
                .unwrap_or("mixed");
            let params = encode_param_list(value.get("params"));
            format!(
                "({} {} {})",
                parts.join(" "),
                quote_imap_string(subtype),
                params
            )
        }
        Some("message") if value.get("subtype").and_then(|v| v.as_str()) == Some("rfc822") => {
            let params = encode_param_list(value.get("params"));
            let envelope = value
                .get("envelope")
                .map(encode_envelope)
                .unwrap_or_else(|| "NIL".to_string());
            let bodystructure = value
                .get("bodystructure")
                .map(encode_bodystructure)
                .unwrap_or_else(|| "NIL".to_string());
            let encoding = value
                .get("transfer_encoding")
                .and_then(|v| v.as_str())
                .unwrap_or("7BIT");
            let size = value.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
            let lines = value.get("lines").and_then(|v| v.as_i64()).unwrap_or(0);
            format!(
                "(\"message\" \"rfc822\" {} NIL NIL {} {} {} {} {})",
                params,
                quote_imap_string(encoding),
                size,
                envelope,
                bodystructure,
                lines
            )
        }
        _ => {
            let type_name = value
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("application");
            let subtype = value
                .get("subtype")
                .and_then(|v| v.as_str())
                .unwrap_or("octet-stream");
            let charset = value.get("charset").and_then(|v| v.as_str());
            let params = if let Some(charset) = charset {
                format!(
                    "({})",
                    ["CHARSET", charset]
                        .iter()
                        .map(|item| quote_imap_string(item))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            } else {
                encode_param_list(value.get("params"))
            };
            let encoding = value
                .get("transfer_encoding")
                .and_then(|v| v.as_str())
                .unwrap_or("7BIT");
            let size = value.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
            if type_name.eq_ignore_ascii_case("text") {
                format!(
                    "({} {} {} NIL NIL {} {} 0 NIL NIL NIL)",
                    quote_imap_string(type_name),
                    quote_imap_string(subtype),
                    params,
                    quote_imap_string(encoding),
                    size
                )
            } else {
                format!(
                    "({} {} {} NIL NIL {} {} NIL NIL NIL)",
                    quote_imap_string(type_name),
                    quote_imap_string(subtype),
                    params,
                    quote_imap_string(encoding),
                    size
                )
            }
        }
    }
}

fn format_fetch_response(
    sequence_number: i64,
    view: &crate::db::repository::MailboxMessageView,
    items: &[String],
) -> String {
    let mut parts = Vec::new();
    let wants_uid = items.iter().any(|item| item == "UID");
    let wants_flags = items.iter().any(|item| item == "FLAGS");
    let wants_size = items
        .iter()
        .any(|item| item == "RFC822.SIZE" || item == "RFC822");
    let wants_internal_date = items.iter().any(|item| item == "INTERNALDATE");
    let wants_envelope = items.iter().any(|item| item == "ENVELOPE");
    let wants_bodystructure = items.iter().any(|item| item == "BODYSTRUCTURE");
    let wants_modseq = items.iter().any(|item| item == "MODSEQ");

    if wants_flags {
        parts.push(format!("FLAGS ({})", view.flags.join(" ")));
    }
    if wants_uid {
        parts.push(format!("UID {}", view.local_uid));
    }
    if wants_size {
        parts.push(format!("RFC822.SIZE {}", view.size_octets));
    }
    if wants_internal_date {
        let date = view
            .internal_date
            .unwrap_or(view.created_at)
            .format("%d-%b-%Y %H:%M:%S %z")
            .to_string();
        parts.push(format!("INTERNALDATE {}", quote_imap_string(&date)));
    }
    if wants_envelope {
        parts.push(format!("ENVELOPE {}", encode_envelope(&view.envelope_json)));
    }
    if wants_bodystructure {
        parts.push(format!(
            "BODYSTRUCTURE {}",
            encode_bodystructure(&view.bodystructure_json)
        ));
    }
    if wants_modseq {
        parts.push(format!("MODSEQ ({})", view.modseq.unwrap_or(0)));
    }

    format!("* {sequence_number} FETCH ({})", parts.join(" "))
}

async fn resolve_sequence_views(
    repo: &crate::db::repository::PostgresRepository,
    mailbox_id: i64,
    set: &str,
) -> Result<Vec<(i64, crate::db::repository::MailboxMessageView)>> {
    let messages = repo.list_mailbox_message_views(mailbox_id).await?;
    let sequence_numbers = parse_number_set(set, messages.len() as i64);
    let mut out = Vec::new();
    for sequence in sequence_numbers {
        if let Some(message) = messages.get(sequence.saturating_sub(1) as usize) {
            out.push((sequence, message.clone()));
        }
    }
    Ok(out)
}

async fn resolve_uid_views(
    repo: &crate::db::repository::PostgresRepository,
    mailbox_id: i64,
    set: &str,
) -> Result<Vec<crate::db::repository::MailboxMessageView>> {
    let messages = repo.list_mailbox_message_views(mailbox_id).await?;
    let max_uid = messages
        .iter()
        .map(|message| message.local_uid)
        .max()
        .unwrap_or(0);
    let uids = parse_number_set(set, max_uid);
    Ok(messages
        .into_iter()
        .filter(|message| uids.contains(&message.local_uid))
        .collect())
}

fn flags_contain_deleted(flags: &[String]) -> bool {
    flags
        .iter()
        .any(|flag| flag.eq_ignore_ascii_case("\\Deleted"))
}

async fn resolve_sequence_targets(
    repo: &crate::db::repository::PostgresRepository,
    mailbox_id: i64,
    set: &str,
) -> Result<Vec<(usize, crate::domain::MailboxMessage)>> {
    let messages = repo.list_mailbox_messages(mailbox_id).await?;
    let sequence_numbers = parse_number_set(set, messages.len() as i64);
    let mut out = Vec::new();
    for sequence in sequence_numbers {
        if let Some(message) = messages.get(sequence.saturating_sub(1) as usize) {
            out.push((sequence as usize, message.clone()));
        }
    }
    Ok(out)
}

async fn sequence_number_for_local_uid(
    repo: &crate::db::repository::PostgresRepository,
    mailbox_id: i64,
    local_uid: i64,
) -> Result<Option<usize>> {
    Ok(repo
        .list_mailbox_messages(mailbox_id)
        .await?
        .iter()
        .position(|message| message.local_uid == local_uid)
        .map(|index| index + 1))
}

async fn resolve_uid_targets(
    repo: &crate::db::repository::PostgresRepository,
    mailbox_id: i64,
    set: &str,
) -> Result<Vec<crate::domain::MailboxMessage>> {
    let messages = repo.list_mailbox_messages(mailbox_id).await?;
    let uids = parse_number_set(
        set,
        messages
            .iter()
            .map(|message| message.local_uid)
            .max()
            .unwrap_or(0),
    );
    Ok(messages
        .into_iter()
        .filter(|message| uids.contains(&message.local_uid))
        .collect())
}

async fn execute_search(
    repo: Option<&Arc<crate::db::repository::PostgresRepository>>,
    search: Option<&Arc<dyn crate::search::SearchBackend>>,
    account_id: Option<i64>,
    mailbox_name: &str,
    query: &SearchQuery,
    uid_results: bool,
) -> Result<Vec<u64>> {
    let Some(repo) = repo else {
        if let Some(search) = search {
            return search.search(mailbox_name, query.clone()).await;
        }
        return Ok(Vec::new());
    };

    let Some(account_id) = account_id else {
        return Ok(Vec::new());
    };
    let Some(mailbox) = repo.find_mailbox(account_id, mailbox_name).await? else {
        return Ok(Vec::new());
    };
    let views = repo.list_mailbox_message_views(mailbox.id).await?;
    let view_map = views
        .iter()
        .cloned()
        .map(|view| (view.local_uid as u64, view))
        .collect::<std::collections::BTreeMap<_, _>>();
    let recent_uids = if query.recent_only || query.old_only {
        recent_mailbox_uids(&views, mailbox.recent_count)
    } else {
        std::collections::BTreeSet::new()
    };
    let candidate_uids = if let Some(search) = search {
        if query.expr.is_none() && (query.query_string.is_some() || query.uid_filter.is_some()) {
            search.search(mailbox_name, query.clone()).await?
        } else {
            view_map.keys().copied().collect::<Vec<_>>()
        }
    } else {
        view_map.keys().copied().collect::<Vec<_>>()
    };

    let apply_text_fallback = search.is_none();
    let mut filtered = candidate_uids
        .into_iter()
        .filter_map(|uid| {
            let view = view_map.get(&uid)?;
            if query.recent_only && !recent_uids.contains(&uid) {
                return None;
            }
            if query.old_only && recent_uids.contains(&uid) {
                return None;
            }
            if matches_search_view(view, query)
                && (!apply_text_fallback
                    || matches_search_text_fallback(view, query.query_string.as_deref()))
            {
                Some(if uid_results {
                    uid
                } else {
                    sequence_number_for_view(&views, uid).unwrap_or(uid)
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    filtered.sort_unstable();
    filtered.dedup();
    Ok(filtered)
}

fn recent_mailbox_uids(
    views: &[crate::db::repository::MailboxMessageView],
    recent_count: i64,
) -> std::collections::BTreeSet<u64> {
    if recent_count <= 0 {
        return std::collections::BTreeSet::new();
    }
    let mut uids = views.iter().map(|view| view.local_uid as u64).collect::<Vec<_>>();
    uids.sort_unstable();
    uids.into_iter()
        .rev()
        .take(recent_count as usize)
        .collect()
}

async fn execute_sort(
    repo: Option<&Arc<crate::db::repository::PostgresRepository>>,
    search: Option<&Arc<dyn crate::search::SearchBackend>>,
    account_id: Option<i64>,
    mailbox_name: &str,
    query: &SearchQuery,
    sort_keys: &[SortKey],
    reverse: bool,
    uid_results: bool,
) -> Result<Vec<u64>> {
    let Some(repo) = repo else {
        if let Some(search) = search {
            let mut uids = search.search(mailbox_name, query.clone()).await?;
            uids.sort_unstable();
            return Ok(uids);
        }
        return Ok(Vec::new());
    };

    let Some(account_id) = account_id else {
        return Ok(Vec::new());
    };
    let Some(mailbox) = repo.find_mailbox(account_id, mailbox_name).await? else {
        return Ok(Vec::new());
    };
    let views = repo.list_mailbox_message_views(mailbox.id).await?;
    let view_map = views
        .iter()
        .cloned()
        .map(|view| (view.local_uid as u64, view))
        .collect::<std::collections::BTreeMap<_, _>>();

    let candidate_uids = execute_search(
        Some(repo),
        search,
        Some(account_id),
        mailbox_name,
        query,
        true,
    )
    .await?
    .into_iter()
    .collect::<Vec<_>>();

    let mut rows = candidate_uids
        .into_iter()
        .filter_map(|uid| view_map.get(&uid).cloned())
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        let ordering = compare_sort_rows(left, right, sort_keys);
        if reverse {
            ordering.reverse()
        } else {
            ordering
        }
    });
    if uid_results {
        Ok(rows.into_iter().map(|view| view.local_uid as u64).collect())
    } else {
        Ok(rows
            .into_iter()
            .map(|view| {
                sequence_number_for_view(&views, view.local_uid as u64)
                    .unwrap_or(view.local_uid as u64)
            })
            .collect())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThreadAlgorithm {
    OrderedSubject,
    References,
}

fn parse_thread_request(args: &[String]) -> Result<Option<(ThreadAlgorithm, SearchQuery)>> {
    if args.len() < 3 {
        return Ok(None);
    }
    let algorithm = match args[0].to_ascii_uppercase().as_str() {
        "ORDEREDSUBJECT" => ThreadAlgorithm::OrderedSubject,
        "REFERENCES" => ThreadAlgorithm::References,
        other => return Err(Error::Parse(format!("unsupported THREAD algorithm: {other}"))),
    };
    let _charset = &args[1];
    let query = SearchQuery::from_imap_args(&args[2..])?;
    Ok(Some((algorithm, query)))
}

async fn execute_thread(
    services: &AppServices,
    account_id: Option<i64>,
    mailbox_name: &str,
    query: &SearchQuery,
    algorithm: ThreadAlgorithm,
    uid_results: bool,
) -> Result<Vec<String>> {
    let Some(repo) = &services.repository else {
        return Ok(Vec::new());
    };
    let Some(account_id) = account_id else {
        return Ok(Vec::new());
    };
    let Some(mailbox) = repo.find_mailbox(account_id, mailbox_name).await? else {
        return Ok(Vec::new());
    };
    let views = repo.list_mailbox_message_views(mailbox.id).await?;
    let view_map = views
        .iter()
        .cloned()
        .map(|view| (view.local_uid as u64, view))
        .collect::<std::collections::BTreeMap<_, _>>();
    let candidate_uids = execute_search(
        services.repository.as_ref(),
        services.search.as_ref(),
        Some(account_id),
        mailbox_name,
        query,
        true,
    )
    .await?;

    let selected_views = candidate_uids
        .into_iter()
        .filter_map(|uid| view_map.get(&uid).cloned())
        .collect::<Vec<_>>();
    if selected_views.is_empty() {
        return Ok(Vec::new());
    }

    match algorithm {
        ThreadAlgorithm::OrderedSubject => {
            let forest = thread_ordered_subject(selected_views);
            Ok(render_thread_forest(&forest, uid_results, &views))
        }
        ThreadAlgorithm::References => {
            let mut threaded = Vec::new();
            for view in selected_views {
                let raw = load_raw_fetch_bytes(
                    services,
                    account_id,
                    mailbox_name,
                    &view,
                    &RawFetchSection::Whole(FetchBodySection::Full),
                    None,
                    &services.metrics,
                )
                .await?
                .ok_or_else(|| Error::Storage("missing raw message for threading".to_string()))?;
                let headers = extract_thread_headers(&raw)?;
                threaded.push(ThreadMessage {
                    uid: view.local_uid as u64,
                    subject_key: normalize_thread_subject(&view.subject),
                    sort_date: sort_date_key(&view),
                    sort_uid: view.local_uid as u64,
                    message_id: headers.message_id,
                    references: headers.references,
                    in_reply_to: headers.in_reply_to,
                });
            }
            let forest = thread_references(threaded);
            Ok(render_thread_forest(&forest, uid_results, &views))
        }
    }
}

#[derive(Debug, Clone)]
struct ThreadMessage {
    uid: u64,
    subject_key: String,
    sort_date: i64,
    sort_uid: u64,
    message_id: Option<String>,
    references: Vec<String>,
    in_reply_to: Vec<String>,
}

#[derive(Debug, Clone)]
struct ThreadNode {
    uid: u64,
    sort_subject: String,
    sort_date: i64,
    sort_uid: u64,
    children: Vec<ThreadNode>,
}

fn thread_ordered_subject(mut messages: Vec<crate::db::repository::MailboxMessageView>) -> Vec<ThreadNode> {
    messages.sort_by(|left, right| {
        normalize_thread_subject(&left.subject)
            .cmp(&normalize_thread_subject(&right.subject))
            .then_with(|| sort_date_key(left).cmp(&sort_date_key(right)))
            .then_with(|| left.local_uid.cmp(&right.local_uid))
    });

    let mut groups: Vec<Vec<crate::db::repository::MailboxMessageView>> = Vec::new();
    for view in messages {
        let subject_key = normalize_thread_subject(&view.subject);
        if let Some(last_group) = groups.last_mut() {
            if normalize_thread_subject(&last_group[0].subject) == subject_key {
                last_group.push(view);
                continue;
            }
        }
        groups.push(vec![view]);
    }

    groups.sort_by(|left, right| {
        normalize_thread_subject(&left[0].subject)
            .cmp(&normalize_thread_subject(&right[0].subject))
            .then_with(|| sort_date_key(&left[0]).cmp(&sort_date_key(&right[0])))
            .then_with(|| left[0].local_uid.cmp(&right[0].local_uid))
    });

    groups
        .into_iter()
        .map(|mut group| {
            group.sort_by(|left, right| {
                sort_date_key(left)
                    .cmp(&sort_date_key(right))
                    .then_with(|| left.local_uid.cmp(&right.local_uid))
            });
            let mut iter = group.into_iter();
            let root = iter.next().unwrap();
            ThreadNode {
                uid: root.local_uid as u64,
                sort_subject: normalize_thread_subject(&root.subject),
                sort_date: sort_date_key(&root),
                sort_uid: root.local_uid as u64,
                children: iter
                    .map(|view| ThreadNode {
                        uid: view.local_uid as u64,
                        sort_subject: normalize_thread_subject(&view.subject),
                        sort_date: sort_date_key(&view),
                        sort_uid: view.local_uid as u64,
                        children: Vec::new(),
                    })
                    .collect(),
            }
        })
        .collect()
}

fn thread_references(messages: Vec<ThreadMessage>) -> Vec<ThreadNode> {
    let mut node_by_id = std::collections::BTreeMap::<String, ThreadNode>::new();
    let mut parent_by_id = std::collections::BTreeMap::<String, String>::new();
    let mut child_ids_by_parent = std::collections::BTreeMap::<String, Vec<String>>::new();

    for message in &messages {
        if let Some(message_id) = &message.message_id {
            node_by_id.insert(
                message_id.clone(),
                ThreadNode {
                    uid: message.uid,
                    sort_subject: message.subject_key.clone(),
                    sort_date: message.sort_date,
                    sort_uid: message.sort_uid,
                    children: Vec::new(),
                },
            );
        }
    }

    for message in &messages {
        let Some(message_id) = message.message_id.as_ref() else {
            continue;
        };
        let parent = message
            .references
            .last()
            .cloned()
            .or_else(|| message.in_reply_to.last().cloned());
        let Some(parent) = parent else {
            continue;
        };
        if parent != *message_id && node_by_id.contains_key(&parent) {
            parent_by_id.insert(message_id.clone(), parent.clone());
            child_ids_by_parent
                .entry(parent)
                .or_default()
                .push(message_id.clone());
        }
    }

    let mut roots = Vec::new();
    for message in messages {
        let Some(message_id) = message.message_id else {
            roots.push(ThreadNode {
                uid: message.uid,
                sort_subject: message.subject_key,
                sort_date: message.sort_date,
                sort_uid: message.sort_uid,
                children: Vec::new(),
            });
            continue;
        };
        if !parent_by_id.contains_key(&message_id) {
            roots.push(build_thread_node(
                &message_id,
                &node_by_id,
                &child_ids_by_parent,
                &mut std::collections::BTreeSet::new(),
            ));
        }
    }

    if roots.is_empty() && !node_by_id.is_empty() {
        roots = node_by_id
            .keys()
            .cloned()
            .map(|message_id| {
                build_thread_node(
                    &message_id,
                    &node_by_id,
                    &child_ids_by_parent,
                    &mut std::collections::BTreeSet::new(),
                )
            })
            .collect();
    }

    sort_thread_nodes(&mut roots);
    roots
}

fn build_thread_node(
    message_id: &str,
    node_by_id: &std::collections::BTreeMap<String, ThreadNode>,
    child_ids_by_parent: &std::collections::BTreeMap<String, Vec<String>>,
    visited: &mut std::collections::BTreeSet<String>,
) -> ThreadNode {
    if !visited.insert(message_id.to_string()) {
        return node_by_id
            .get(message_id)
            .expect("thread node exists")
            .clone();
    }
    let mut node = node_by_id
        .get(message_id)
        .expect("thread node exists")
        .clone();
    if let Some(child_ids) = child_ids_by_parent.get(message_id) {
        node.children = child_ids
            .iter()
            .map(|child_id| {
                build_thread_node(child_id, node_by_id, child_ids_by_parent, visited)
            })
            .collect();
    }
    visited.remove(message_id);
    node
}

fn sort_thread_nodes(nodes: &mut [ThreadNode]) {
    nodes.sort_by(|left, right| {
        left.sort_date
            .cmp(&right.sort_date)
            .then_with(|| left.sort_subject.cmp(&right.sort_subject))
            .then_with(|| left.sort_uid.cmp(&right.sort_uid))
    });
    for node in nodes {
        sort_thread_nodes(&mut node.children);
    }
}

fn render_thread_forest(
    forest: &[ThreadNode],
    uid_results: bool,
    views: &[crate::db::repository::MailboxMessageView],
) -> Vec<String> {
    forest
        .iter()
        .map(|node| render_thread_node(node, uid_results, views))
        .collect()
}

fn render_thread_node(
    node: &ThreadNode,
    uid_results: bool,
    views: &[crate::db::repository::MailboxMessageView],
) -> String {
    let label = thread_label(node.uid, uid_results, views);
    if node.children.is_empty() {
        label
    } else {
        let children = node
            .children
            .iter()
            .map(|child| render_thread_node(child, uid_results, views))
            .collect::<Vec<_>>()
            .join(" ");
        format!("({label} {children})")
    }
}

fn thread_label(
    uid: u64,
    uid_results: bool,
    views: &[crate::db::repository::MailboxMessageView],
) -> String {
    if uid_results {
        uid.to_string()
    } else {
        sequence_number_for_view(views, uid)
            .unwrap_or(uid)
            .to_string()
    }
}

fn normalize_thread_subject(subject: &Option<String>) -> String {
    let mut value = subject.as_deref().unwrap_or("").trim().to_string();
    loop {
        let Some(candidate) = strip_thread_subject_prefix(&value) else {
            break;
        };
        if candidate == value {
            break;
        }
        value = candidate.trim_start().to_string();
    }
    value.to_ascii_lowercase()
}

fn strip_thread_subject_prefix(value: &str) -> Option<&str> {
    let lower = value.to_ascii_lowercase();
    for prefix in ["re:", "fwd:", "fw:"] {
        if let Some(stripped) = lower.strip_prefix(prefix) {
            let offset = value.len() - stripped.len();
            return Some(value[offset..].trim_start());
        }
    }
    None
}

struct ThreadHeaders {
    message_id: Option<String>,
    references: Vec<String>,
    in_reply_to: Vec<String>,
}

fn extract_thread_headers(raw: &[u8]) -> Result<ThreadHeaders> {
    let parsed = mailparse::parse_mail(raw)
        .map_err(|e| Error::Parse(format!("failed to parse RFC822 message for threading: {e}")))?;
    Ok(ThreadHeaders {
        message_id: normalize_message_id(parsed.headers.get_first_value("Message-ID")),
        references: normalize_message_id_list(parsed.headers.get_first_value("References")),
        in_reply_to: normalize_message_id_list(parsed.headers.get_first_value("In-Reply-To")),
    })
}

fn normalize_message_id(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim().trim_matches('<').trim_matches('>').trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_ascii_lowercase())
        }
    })
}

fn normalize_message_id_list(value: Option<String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split_whitespace()
                .filter_map(|token| normalize_message_id(Some(token.to_string())))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Date,
    Subject,
    From,
    To,
    Cc,
    Size,
    Arrival,
    Uid,
}

fn parse_sort_request(args: &[String]) -> Result<Option<(Vec<SortKey>, bool, SearchQuery)>> {
    if args.len() < 3 {
        return Ok(None);
    }
    let sort_tokens = args[0]
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .split_whitespace()
        .collect::<Vec<_>>();
    if sort_tokens.is_empty() {
        return Err(Error::Parse(
            "SORT requires at least one sort key".to_string(),
        ));
    }
    let mut sort_keys = Vec::new();
    let mut reverse = false;
    for token in sort_tokens {
        match token.to_ascii_uppercase().as_str() {
            "DATE" => sort_keys.push(SortKey::Date),
            "SUBJECT" => sort_keys.push(SortKey::Subject),
            "FROM" => sort_keys.push(SortKey::From),
            "TO" => sort_keys.push(SortKey::To),
            "CC" => sort_keys.push(SortKey::Cc),
            "SIZE" => sort_keys.push(SortKey::Size),
            "ARRIVAL" => sort_keys.push(SortKey::Arrival),
            "UID" => sort_keys.push(SortKey::Uid),
            "REVERSE" => reverse = true,
            other => return Err(Error::Parse(format!("unsupported SORT key: {other}"))),
        }
    }
    let query = SearchQuery::from_imap_args(&args[2..])?;
    Ok(Some((sort_keys, reverse, query)))
}

fn parse_search_request(args: &[String]) -> Result<(SearchQuery, Option<SearchReturnOptions>)> {
    let mut index = 0usize;
    let mut return_options = None;
    while index < args.len() {
        if args[index].eq_ignore_ascii_case("RETURN") {
            let Some(options) = args.get(index + 1) else {
                return Err(Error::Parse("RETURN requires options".to_string()));
            };
            return_options = Some(parse_search_return_options(options)?);
            index += 2;
            continue;
        }
        if args[index].eq_ignore_ascii_case("CHARSET") {
            let Some(charset) = args.get(index + 1) else {
                return Err(Error::Parse("CHARSET requires a value".to_string()));
            };
            let supported = matches!(charset.to_ascii_uppercase().as_str(), "UTF-8" | "US-ASCII");
            if !supported {
                return Err(Error::ImapCommand(format!(
                    "BADCHARSET unsupported SEARCH charset: {charset}"
                )));
            }
            index += 2;
            continue;
        }
        break;
    }
    Ok((SearchQuery::from_imap_args(&args[index..])?, return_options))
}

fn parse_list_request(args: &[String]) -> Result<(&str, Option<Vec<String>>)> {
    let pattern = args
        .iter()
        .take_while(|arg| !arg.eq_ignore_ascii_case("RETURN"))
        .nth(1)
        .or_else(|| args.first())
        .map(|value| value.as_str())
        .unwrap_or("*");
    let Some(return_index) = args.iter().position(|arg| arg.eq_ignore_ascii_case("RETURN")) else {
        return Ok((pattern, None));
    };
    let Some(options) = args.get(return_index + 1..) else {
        return Err(Error::Parse("RETURN requires options".to_string()));
    };
    let return_clause = options.join(" ");
    let Some(status_pos) = return_clause.to_ascii_uppercase().find("STATUS") else {
        return Ok((pattern, None));
    };
    let status_clause = &return_clause[status_pos + "STATUS".len()..];
    let Some(open_paren) = status_clause.find('(') else {
        return Err(Error::Parse("STATUS return option requires items".to_string()));
    };
    let mut depth = 0usize;
    let mut close_paren = None;
    for (offset, ch) in status_clause[open_paren..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    close_paren = Some(open_paren + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close_paren) = close_paren else {
        return Err(Error::Parse("STATUS return option requires items".to_string()));
    };
    let status_items = status_clause[open_paren..=close_paren].to_string();
    Ok((pattern, Some(parse_status_items(&[status_items])?)))
}

#[derive(Debug, Clone, Copy, Default)]
struct SearchReturnOptions {
    count: bool,
    min: bool,
    max: bool,
    all: bool,
}

fn parse_search_return_options(value: &str) -> Result<SearchReturnOptions> {
    let trimmed = value.trim();
    let trimmed = trimmed.strip_prefix('(').unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix(')').unwrap_or(trimmed);
    let mut options = SearchReturnOptions::default();
    for token in trimmed.split_whitespace() {
        match token.to_ascii_uppercase().as_str() {
            "COUNT" => options.count = true,
            "MIN" => options.min = true,
            "MAX" => options.max = true,
            "ALL" => options.all = true,
            other => {
                return Err(Error::Parse(format!(
                    "unsupported ESEARCH return option: {other}"
                )));
            }
        }
    }
    Ok(options)
}

fn format_esearch_summary(results: &[u64], options: SearchReturnOptions) -> String {
    let mut parts = Vec::new();
    if options.count {
        parts.push(format!(" COUNT {}", results.len()));
    }
    if options.min {
        if let Some(min) = results.iter().min() {
            parts.push(format!(" MIN {min}"));
        }
    }
    if options.max {
        if let Some(max) = results.iter().max() {
            parts.push(format!(" MAX {max}"));
        }
    }
    if options.all {
        parts.push(format!(" ALL {}", format_number_set(results)));
    }
    parts.join("")
}

fn compare_sort_rows(
    left: &crate::db::repository::MailboxMessageView,
    right: &crate::db::repository::MailboxMessageView,
    sort_keys: &[SortKey],
) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    for key in sort_keys {
        let ordering = match key {
            SortKey::Date => sort_date_key(left).cmp(&sort_date_key(right)),
            SortKey::Subject => sort_text_key(&left.subject).cmp(&sort_text_key(&right.subject)),
            SortKey::From => sort_address_key(&left.envelope_json, "from")
                .cmp(&sort_address_key(&right.envelope_json, "from")),
            SortKey::To => sort_address_key(&left.envelope_json, "to")
                .cmp(&sort_address_key(&right.envelope_json, "to")),
            SortKey::Cc => sort_address_key(&left.envelope_json, "cc")
                .cmp(&sort_address_key(&right.envelope_json, "cc")),
            SortKey::Size => left.size_octets.cmp(&right.size_octets),
            SortKey::Arrival => left.created_at.cmp(&right.created_at),
            SortKey::Uid => left.local_uid.cmp(&right.local_uid),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.local_uid.cmp(&right.local_uid)
}

fn sort_date_key(view: &crate::db::repository::MailboxMessageView) -> i64 {
    view.sent_date
        .or(view.internal_date)
        .or(Some(view.created_at))
        .map(|dt| dt.timestamp())
        .unwrap_or_default()
}

fn sort_text_key(value: &Option<String>) -> String {
    value
        .as_ref()
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default()
}

fn sort_address_key(value: &serde_json::Value, field: &str) -> String {
    value
        .get(field)
        .and_then(|value| value.as_array())
        .and_then(|items| {
            items.iter().find_map(|item| {
                item.get("address")
                    .and_then(|address| address.as_str())
                    .map(|address| address.to_ascii_lowercase())
            })
        })
        .unwrap_or_default()
}

fn sequence_number_for_view(
    views: &[crate::db::repository::MailboxMessageView],
    uid: u64,
) -> Option<u64> {
    views
        .iter()
        .position(|view| view.local_uid as u64 == uid)
        .map(|index| index as u64 + 1)
}

fn matches_search_view(
    view: &crate::db::repository::MailboxMessageView,
    query: &SearchQuery,
) -> bool {
    if !matches_search_leaf(view, query) {
        return false;
    }
    query
        .expr
        .as_deref()
        .is_none_or(|expr| matches_search_expr(view, expr))
}

fn matches_search_expr(
    view: &crate::db::repository::MailboxMessageView,
    expr: &SearchExpr,
) -> bool {
    match expr {
        SearchExpr::Leaf(query) => matches_search_leaf(view, query),
        SearchExpr::And(children) => {
            children.iter().all(|child| matches_search_expr(view, child))
        }
        SearchExpr::Or(left, right) => {
            matches_search_expr(view, left) || matches_search_expr(view, right)
        }
        SearchExpr::Not(inner) => !matches_search_expr(view, inner),
    }
}

fn matches_search_leaf(
    view: &crate::db::repository::MailboxMessageView,
    query: &SearchQuery,
) -> bool {
    if query
        .uid_filter
        .as_ref()
        .is_some_and(|set| !set.contains(view.local_uid as u64))
    {
        return false;
    }
    if !query
        .required_flags
        .iter()
        .all(|flag| contains_case_insensitive(&view.flags, flag))
    {
        return false;
    }
    if query
        .forbidden_flags
        .iter()
        .any(|flag| contains_case_insensitive(&view.flags, flag))
    {
        return false;
    }
    if !query
        .required_keywords
        .iter()
        .all(|keyword| contains_case_insensitive(&view.keywords, keyword))
    {
        return false;
    }
    if query
        .forbidden_keywords
        .iter()
        .any(|keyword| contains_case_insensitive(&view.keywords, keyword))
    {
        return false;
    }
    if !matches_header_filters(view, &query.header_filters) {
        return false;
    }
    if let Some(larger_than) = query.larger_than
        && view.size_octets as u64 <= larger_than
    {
        return false;
    }
    if let Some(smaller_than) = query.smaller_than
        && view.size_octets as u64 >= smaller_than
    {
        return false;
    }

    let internal_date = view.internal_date.unwrap_or(view.created_at).date_naive();
    if let Some(before) = query.internal_date_before
        && internal_date >= before
    {
        return false;
    }
    if let Some(on) = query.internal_date_on
        && internal_date != on
    {
        return false;
    }
    if let Some(since) = query.internal_date_since
        && internal_date < since
    {
        return false;
    }

    let sent_date = view
        .sent_date
        .unwrap_or(view.internal_date.unwrap_or(view.created_at))
        .date_naive();
    if let Some(before) = query.sent_date_before
        && sent_date >= before
    {
        return false;
    }
    if let Some(on) = query.sent_date_on
        && sent_date != on
    {
        return false;
    }
    if let Some(since) = query.sent_date_since
        && sent_date < since
    {
        return false;
    }

    true
}

fn matches_header_filters(
    view: &crate::db::repository::MailboxMessageView,
    header_filters: &[(String, String)],
) -> bool {
    header_filters.iter().all(|(field, needle)| {
        let value = match field.as_str() {
            "subject" => view.subject.clone().map(serde_json::Value::String),
            "from" => view.envelope_json.get("from").cloned(),
            "to" => view.envelope_json.get("to").cloned(),
            "cc" => view.envelope_json.get("cc").cloned(),
            "bcc" => view.envelope_json.get("bcc").cloned(),
            "reply-to" | "reply_to" => view.envelope_json.get("reply_to").cloned(),
            "message-id" | "message_id" => view.envelope_json.get("message_id").cloned(),
            "date" => view.envelope_json.get("date").cloned(),
            other => view.envelope_json.get(other).cloned(),
        };
        value
            .as_ref()
            .is_some_and(|value| contains_case_insensitive_json(value, needle))
    })
}

fn contains_case_insensitive_json(value: &serde_json::Value, needle: &str) -> bool {
    let haystack = serde_json::to_string(value)
        .unwrap_or_default()
        .to_ascii_lowercase();
    haystack.contains(&needle.to_ascii_lowercase())
}

fn matches_search_text_fallback(
    view: &crate::db::repository::MailboxMessageView,
    query_string: Option<&str>,
) -> bool {
    let Some(query_string) = query_string else {
        return true;
    };
    let normalized = query_string.trim();
    if normalized.is_empty() {
        return true;
    }
    let haystack = [
        view.subject.as_deref().unwrap_or_default(),
        view.text_preview.as_deref().unwrap_or_default(),
        &serde_json::to_string(&view.envelope_json).unwrap_or_default(),
        &serde_json::to_string(&view.bodystructure_json).unwrap_or_default(),
    ]
    .join(" ")
    .to_ascii_lowercase();

    if let Some((left, right)) = split_top_level_bool(normalized, "OR") {
        return matches_search_text_fallback(view, Some(&left))
            || matches_search_text_fallback(view, Some(&right));
    }
    if let Some(inner) = normalized.strip_prefix("NOT ") {
        return !matches_search_text_fallback(view, Some(inner.trim()));
    }

    let terms = extract_search_terms(normalized);
    if terms.is_empty() {
        return true;
    }

    terms.into_iter().all(|term| haystack.contains(&term))
}

fn split_top_level_bool(expr: &str, operator: &str) -> Option<(String, String)> {
    let mut depth = 0usize;
    let bytes = expr.as_bytes();
    let needle = operator.as_bytes();
    let mut index = 0usize;

    while index + needle.len() <= bytes.len() {
        match bytes[index] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ => {}
        }

        if depth == 0 && bytes[index..].len() >= needle.len() {
            let candidate = &expr[index..index + needle.len()];
            let left_ok = index == 0 || bytes[index.saturating_sub(1)].is_ascii_whitespace();
            let right_index = index + needle.len();
            let right_ok = right_index >= bytes.len() || bytes[right_index].is_ascii_whitespace();
            if candidate.eq_ignore_ascii_case(operator) && left_ok && right_ok {
                let left = expr[..index].trim().trim_matches('(').trim().to_string();
                let right = expr[right_index..]
                    .trim()
                    .trim_matches(')')
                    .trim()
                    .to_string();
                return Some((left, right));
            }
        }

        index += 1;
    }

    None
}

fn extract_search_terms(expr: &str) -> Vec<String> {
    expr.split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(|term| term.trim().to_ascii_lowercase())
        .filter(|term| {
            !term.is_empty()
                && !matches!(
                    term.as_str(),
                    "subject" | "body" | "from" | "to" | "cc" | "text" | "all"
                )
        })
        .collect()
}

fn contains_case_insensitive(values: &[String], needle: &str) -> bool {
    values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(needle))
}

async fn read_command_with_literal<S>(
    stream: &mut S,
    line: &str,
) -> Result<Option<(ParsedCommand, Option<Vec<u8>>)>>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let Some(command) = parse_command(line)? else {
        return Ok(None);
    };

    let literal = match command
        .args
        .last()
        .and_then(|value| parse_literal_marker(value))
    {
        Some((length, non_sync)) => {
            if !non_sync {
                stream.write_all(b"+ Ready for literal data\r\n").await?;
                stream.flush().await?;
            }
            let mut bytes = vec![0u8; length];
            stream.read_exact(&mut bytes).await?;
            Some(bytes)
        }
        None => None,
    };

    Ok(Some((command, literal)))
}

fn canonical_mailbox_name(name: &str) -> String {
    if name.eq_ignore_ascii_case("INBOX") {
        "inbox".to_string()
    } else {
        name.to_ascii_lowercase()
    }
}

fn quote_imap_string(value: &str) -> String {
    let escaped = value.replace('\\', r"\\").replace('"', r#"\""#);
    format!("\"{escaped}\"")
}

fn mailbox_list_line(prefix: &str, mailbox: &Mailbox) -> String {
    let mut attributes = mailbox.attributes.clone();
    if !attributes.iter().any(|value| {
        value.eq_ignore_ascii_case("\\haschildren") || value.eq_ignore_ascii_case("\\hasnochildren")
    }) {
        attributes.push("\\HasNoChildren".to_string());
    }
    if let Some(special_use) = &mailbox.special_use {
        if !attributes
            .iter()
            .any(|value| value.eq_ignore_ascii_case(special_use))
        {
            attributes.push(special_use.clone());
        }
    }
    let delimiter = mailbox.delimiter.as_deref().unwrap_or("/");
    format!(
        "* {prefix} ({}) {} {}",
        attributes.join(" "),
        quote_imap_string(delimiter),
        quote_imap_string(&mailbox.name),
    )
}

fn imap_list_pattern_matches(pattern: &str, name: &str, delimiter: &str) -> bool {
    let pattern: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let name: Vec<char> = name.to_ascii_lowercase().chars().collect();
    let delimiter = delimiter.chars().next().unwrap_or('/');

    fn matches(pattern: &[char], pi: usize, name: &[char], ni: usize, delimiter: char) -> bool {
        if pi == pattern.len() {
            return ni == name.len();
        }

        match pattern[pi] {
            '*' => (ni..=name.len()).any(|next| matches(pattern, pi + 1, name, next, delimiter)),
            '%' => {
                let mut next = ni;
                loop {
                    if matches(pattern, pi + 1, name, next, delimiter) {
                        return true;
                    }
                    if next == name.len() || name[next] == delimiter {
                        return false;
                    }
                    next += 1;
                }
            }
            pattern_char => {
                if ni >= name.len() {
                    return false;
                }
                if pattern_char == name[ni] {
                    matches(pattern, pi + 1, name, ni + 1, delimiter)
                } else {
                    false
                }
            }
        }
    }

    matches(&pattern, 0, &name, 0, delimiter)
}

pub fn tls_acceptor(config: &Config) -> Result<Option<TlsAcceptor>> {
    crate::security::ensure_rustls_crypto_provider();
    let Some(cert_path) = config.imap_tls_cert_path.as_ref() else {
        return Ok(None);
    };
    let Some(key_path) = config.imap_tls_key_path.as_ref() else {
        return Ok(None);
    };
    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Config(format!("failed to build TLS config: {e}")))?;
    Ok(Some(TlsAcceptor::from(Arc::new(tls_config))))
}

fn load_certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("failed to read TLS certificate chain: {e}")))?;
    Ok(certs)
}

fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("failed to read PKCS#8 private key: {e}")))?;
    if let Some(key) = keys.pop() {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    let mut reader = BufReader::new(File::open(path)?);
    let mut keys = rustls_pemfile::rsa_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("failed to read RSA private key: {e}")))?;
    if let Some(key) = keys.pop() {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

    Err(Error::Config("no supported private key found".to_string()))
}

pub async fn serve_plaintext(
    listener: TcpListener,
    services: Arc<AppServices>,
    starttls_acceptor: Option<TlsAcceptor>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let services = Arc::clone(&services);
        let starttls_acceptor = starttls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(
                ImapTransport::Plain(stream),
                services,
                starttls_acceptor,
                Some(peer.to_string()),
            )
            .await
            {
                tracing::warn!(%peer, error = %err, "plaintext IMAP client ended with error");
            }
        });
    }
}

pub async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    services: Arc<AppServices>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let services = Arc::clone(&services);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(stream) => {
                    if let Err(err) = handle_connection(
                        ImapTransport::Tls(stream),
                        services,
                        None,
                        Some(peer.to_string()),
                    )
                    .await
                    {
                        tracing::warn!(%peer, error = %err, "TLS IMAP client ended with error");
                    }
                }
                Err(err) => tracing::warn!(%peer, error = %err, "TLS handshake failed"),
            }
        });
    }
}

async fn handle_connection(
    transport: ImapTransport,
    services: Arc<AppServices>,
    starttls_acceptor: Option<TlsAcceptor>,
    peer_addr: Option<String>,
) -> Result<()> {
    let _connection_guard = crate::metrics::ConnectionGuard::new(Arc::clone(&services.metrics));
    let mut stream = TokioBufStream::new(transport);
    let mut session = ImapSession::new();
    session.set_connection_context(Uuid::new_v4().to_string(), peer_addr);
    session.set_starttls_available(starttls_acceptor.is_some());
    if matches!(stream.get_ref(), ImapTransport::Tls(_)) {
        session.set_tls_active(true);
    }
    stream.write_all(b"* OK IMAP cache proxy ready\r\n").await?;
    stream.flush().await?;

    let result: Result<()> = async {
        loop {
            let mut line = String::new();
            let bytes = stream.read_line(&mut line).await?;
            if bytes == 0 {
                break;
            }
            let Some((command, literal)) = read_command_with_literal(&mut stream, &line).await?
            else {
                continue;
            };
            let command_name = command.name.to_ascii_uppercase();
            let command_tag = command.tag.clone();
            let started = Instant::now();
            if command_name == "STARTTLS" {
                if let Some(acceptor) = starttls_acceptor.as_ref() {
                    if !session.tls_active
                        && session.starttls_available
                        && matches!(session.state, State::NotAuthenticated)
                        && matches!(stream.get_ref(), ImapTransport::Plain(_))
                    {
                        stream
                            .write_all(
                                format!("{} OK Begin TLS negotiation now\r\n", command.tag)
                                    .as_bytes(),
                            )
                            .await?;
                        stream.flush().await?;
                        let transport = stream.into_inner();
                        let transport = transport.upgrade_to_tls(acceptor).await?;
                        stream = TokioBufStream::new(transport);
                        session.set_tls_active(true);
                        session.set_starttls_available(false);
                        record_command_observation(
                            &session.metrics,
                            &services.metrics,
                            &command_name,
                            started,
                            false,
                        );
                        continue;
                    }
                    stream
                        .write_all(
                            format!(
                                "{} NO [BADSTATE] STARTTLS is not available\r\n",
                                command.tag
                            )
                            .as_bytes(),
                        )
                        .await?;
                    stream.flush().await?;
                    record_command_observation(
                        &session.metrics,
                        &services.metrics,
                        &command_name,
                        started,
                        true,
                    );
                    continue;
                }
                stream
                    .write_all(
                        format!(
                            "{} NO [UNIMPLEMENTED] STARTTLS is not enabled\r\n",
                            command.tag
                        )
                        .as_bytes(),
                    )
                    .await?;
                stream.flush().await?;
                record_command_observation(
                    &session.metrics,
                    &services.metrics,
                    &command_name,
                    started,
                    true,
                );
                continue;
            }
            if command_name == "AUTHENTICATE" {
                handle_authenticate_command(&mut stream, &services, &mut session, &command).await?;
                stream.flush().await?;
                let errored = !matches!(
                    session.state,
                    State::Authenticated | State::SelectedMailbox { .. }
                );
                record_command_observation(
                    &session.metrics,
                    &services.metrics,
                    &command_name,
                    started,
                    errored,
                );
                if matches!(session.state, State::Logout) {
                    break;
                }
                continue;
            }
            if command_name == "IDLE" {
                session.metrics.record_command(&command_name);
                services.metrics.record_command(&command_name);
                handle_idle_command(&mut stream, &services, &mut session, &command.tag).await?;
                record_command_observation(
                    &session.metrics,
                    &services.metrics,
                    &command_name,
                    started,
                    false,
                );
                continue;
            }
            if (command_name == "FETCH" || command_name == "UID")
                && write_raw_fetch_response(&mut stream, &services, &mut session, &command).await?
            {
                session.metrics.record_command(&command_name);
                services.metrics.record_command(&command_name);
                stream
                    .write_all(format!("{} OK FETCH completed\r\n", command.tag).as_bytes())
                    .await?;
                stream.flush().await?;
                record_command_observation(
                    &session.metrics,
                    &services.metrics,
                    &command_name,
                    started,
                    false,
                );
                continue;
            }
            let responses = match session
                .handle_parsed_command(&services, command.clone(), literal)
                .await
            {
                Ok(responses) => responses,
                Err(Error::Parse(message)) => {
                    vec![format!("{} BAD {}", command.tag, message)]
                }
                Err(Error::ImapCommand(message)) => {
                    if let Some(rest) = message.strip_prefix("BADCHARSET ") {
                        vec![format!("{} NO [BADCHARSET] {}", command.tag, rest)]
                    } else {
                        vec![format!("{} BAD {}", command.tag, message)]
                    }
                }
                Err(err) => return Err(err),
            };
            let errored = responses.iter().any(|response| {
                response.starts_with(&format!("{} ", command_tag))
                    && (response.contains(" NO ") || response.contains(" BAD "))
            });
            for response in responses {
                stream.write_all(response.as_bytes()).await?;
                stream.write_all(b"\r\n").await?;
            }
            stream.flush().await?;
            record_command_observation(
                &session.metrics,
                &services.metrics,
                &command_name,
                started,
                errored,
            );
            if matches!(session.state, State::Logout) {
                break;
            }
        }
        Ok(())
    }
    .await;
    session.record_disconnected(&services).await;
    if session.auth_counted {
        session.metrics.dec_authenticated_sessions();
        services.metrics.dec_authenticated_sessions();
    }
    result
}

async fn handle_authenticate_command<S>(
    stream: &mut S,
    services: &AppServices,
    session: &mut ImapSession,
    command: &ParsedCommand,
) -> Result<()>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let tag = command.tag.as_str();
    let name = command.name.to_ascii_uppercase();
    session.metrics.record_command(&name);
    services.metrics.record_command(&name);

    if !matches!(session.state, State::NotAuthenticated) {
        stream
            .write_all(
                format!(
                    "{tag} NO [BADSTATE] AUTHENTICATE requires a not-authenticated session\r\n"
                )
                .as_bytes(),
            )
            .await?;
        stream.flush().await?;
        return Ok(());
    }

    let Some(mechanism) = command.args.first() else {
        stream
            .write_all(format!("{tag} BAD AUTHENTICATE requires a mechanism\r\n").as_bytes())
            .await?;
        stream.flush().await?;
        return Ok(());
    };

    let mechanism_upper = mechanism.to_ascii_uppercase();
    if mechanism_upper != "PLAIN" && mechanism_upper != "XOAUTH2" {
        stream
            .write_all(
                format!(
                    "{tag} NO [UNIMPLEMENTED] AUTHENTICATE {mechanism} is not yet implemented\r\n"
                )
                .as_bytes(),
            )
            .await?;
        stream.flush().await?;
        return Ok(());
    }

    if command.args.len() > 2 {
        stream
            .write_all(
                format!("{tag} BAD AUTHENTICATE accepts at most one initial response\r\n")
                    .as_bytes(),
            )
            .await?;
        stream.flush().await?;
        return Ok(());
    }

    let auth_blob = if let Some(initial_response) = command.args.get(1) {
        if initial_response == "=" {
            Vec::new()
        } else {
            decode_sasl_response(initial_response)?
        }
    } else {
        stream.write_all(b"+ \r\n").await?;
        stream.flush().await?;
        let mut response_line = String::new();
        let bytes = stream.read_line(&mut response_line).await?;
        if bytes == 0 {
            stream
                .write_all(format!("{tag} BAD AUTHENTICATE canceled\r\n").as_bytes())
                .await?;
            stream.flush().await?;
            return Ok(());
        }
        let response = response_line.trim_end_matches(['\r', '\n']);
        if response == "*" {
            stream
                .write_all(format!("{tag} BAD AUTHENTICATE canceled\r\n").as_bytes())
                .await?;
            stream.flush().await?;
            return Ok(());
        }
        decode_sasl_response(response)?
    };

    let (authcid, password) = if mechanism_upper == "XOAUTH2" {
        parse_sasl_xoauth2_auth(&auth_blob)?
    } else {
        parse_sasl_plain_auth(&auth_blob)?
    };
    match services
        .authenticator
        .authenticate(authcid, password)
        .await?
    {
        Some(ctx) => {
            session.activate_authenticated_session(services, ctx).await;
            stream
                .write_all(format!("{tag} OK AUTHENTICATE completed\r\n").as_bytes())
                .await?;
        }
        None => {
            stream
                .write_all(
                    format!("{tag} NO [AUTHENTICATIONFAILED] invalid credentials\r\n").as_bytes(),
                )
                .await?;
        }
    }

    stream.flush().await?;
    Ok(())
}

fn record_command_observation(
    session_metrics: &Arc<AppMetrics>,
    services_metrics: &Arc<AppMetrics>,
    command_name: &str,
    started: Instant,
    errored: bool,
) {
    let duration = started.elapsed();
    session_metrics.record_command_duration(command_name, duration);
    services_metrics.record_command_duration(command_name, duration);
    if errored {
        session_metrics.record_command_error(command_name);
        services_metrics.record_command_error(command_name);
    }
}

fn decode_sasl_response(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|err| Error::Parse(format!("invalid base64 SASL response: {err}")))
}

fn parse_sasl_plain_auth(auth_blob: &[u8]) -> Result<(&str, &str)> {
    let mut parts = auth_blob.split(|byte| *byte == 0);
    let _authzid = parts.next().unwrap_or_default();
    let Some(authcid) = parts.next() else {
        return Err(Error::Parse(
            "AUTHENTICATE PLAIN response missing authcid".to_string(),
        ));
    };
    let Some(password) = parts.next() else {
        return Err(Error::Parse(
            "AUTHENTICATE PLAIN response missing password".to_string(),
        ));
    };

    Ok((
        std::str::from_utf8(authcid)?,
        std::str::from_utf8(password)?,
    ))
}

fn parse_sasl_xoauth2_auth(auth_blob: &[u8]) -> Result<(&str, &str)> {
    let decoded = std::str::from_utf8(auth_blob)?;
    let mut username = None;
    let mut bearer = None;

    for segment in decoded.split('\x01') {
        if let Some(value) = segment.strip_prefix("user=") {
            username = Some(value);
        } else if let Some(value) = segment.strip_prefix("auth=Bearer ") {
            bearer = Some(value);
        }
    }

    let Some(username) = username else {
        return Err(Error::Parse(
            "AUTHENTICATE XOAUTH2 response missing user".to_string(),
        ));
    };
    let Some(bearer) = bearer else {
        return Err(Error::Parse(
            "AUTHENTICATE XOAUTH2 response missing bearer token".to_string(),
        ));
    };

    Ok((username, bearer))
}

async fn handle_idle_command<S>(
    stream: &mut S,
    services: &AppServices,
    session: &mut ImapSession,
    tag: &str,
) -> Result<()>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    handle_idle_command_with_timeout(
        stream,
        services,
        session,
        tag,
        Duration::from_secs(crate::config::idle_timeout_seconds()),
    )
    .await
}

async fn handle_idle_command_with_timeout<S>(
    stream: &mut S,
    services: &AppServices,
    session: &mut ImapSession,
    tag: &str,
    idle_timeout: Duration,
) -> Result<()>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    stream.write_all(b"+ idling\r\n").await?;
    stream.flush().await?;
    let mut events = services.events.subscribe();
    let idle_timeout = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_timeout);

    loop {
        let mut line = String::new();
        tokio::select! {
            read = stream.read_line(&mut line) => {
                let bytes = read?;
                if bytes == 0 {
                    break;
                }
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.eq_ignore_ascii_case("DONE") {
                    stream.write_all(format!("{tag} OK IDLE terminated\r\n").as_bytes()).await?;
                    stream.flush().await?;
                    break;
                }
            }
            _ = &mut idle_timeout => {
                stream.write_all(b"* BYE IDLE timeout\r\n").await?;
                stream.flush().await?;
                break;
            }
            event = events.recv() => {
                match event {
                    Ok(event) => {
                        if let Some(response) = idle_notification_for_event(services, session, &event).await? {
                            stream.write_all(response.as_bytes()).await?;
                            stream.write_all(b"\r\n").await?;
                            stream.flush().await?;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    Ok(())
}

async fn idle_notification_for_event(
    services: &AppServices,
    session: &mut ImapSession,
    event: &crate::notifications::MutationEvent,
) -> Result<Option<String>> {
    let Some(snapshot) = &mut session.selected_mailbox_snapshot else {
        return Ok(None);
    };
    if event.account_id != Some(snapshot.account_id)
        || event.mailbox_id != Some(snapshot.mailbox_id)
    {
        return Ok(None);
    }
    let Some(repo) = &services.repository else {
        return Ok(None);
    };
    if event.detail.contains("delete_mailbox_message") {
        if let Some(sequence_number) = event.sequence_number {
            let exists_count = repo.list_mailbox_messages(snapshot.mailbox_id).await?.len() as i64;
            snapshot.exists_count = exists_count;
            return Ok(Some(format!("* {sequence_number} EXPUNGE")));
        }
    }
    if event.detail.contains("update_mailbox_message_flags") || event.detail.contains("store_flags")
    {
        if let Some(local_uid) = event.local_uid {
            let sequence_number = repo
                .list_mailbox_messages(snapshot.mailbox_id)
                .await?
                .iter()
                .position(|message| message.local_uid == local_uid)
                .map(|index| index as i64 + 1);
            if let Some(sequence_number) = sequence_number {
                snapshot.exists_count =
                    repo.list_mailbox_messages(snapshot.mailbox_id).await?.len() as i64;
                return Ok(Some(format!(
                    "* {sequence_number} FETCH (FLAGS ({}))",
                    event.flags.join(" ")
                )));
            }
        }
    }

    let exists_count = repo.list_mailbox_messages(snapshot.mailbox_id).await?.len() as i64;
    let previous_exists = snapshot.exists_count;
    if exists_count > previous_exists {
        snapshot.exists_count = exists_count;
        return Ok(Some(format!("* {exists_count} EXISTS")));
    }
    if exists_count < previous_exists {
        snapshot.exists_count = exists_count;
        return Ok(Some(format!(
            "* {} EXPUNGE",
            previous_exists - exists_count
        )));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AppServices,
        auth::{AuthContext, DenyAllAuthenticator},
        db,
        db::repository::{
            NewMailAccount, NewMailbox, NewMailboxMessage, NewMessage, NewUser, PostgresRepository,
        },
        domain::{UpstreamAuthMethod, UpstreamTlsMode},
        notifications::{HubMutationEventSink, MailboxEventHub},
        security,
        storage::memory::MemoryObjectStore,
        storage::{self, ObjectStore, ObjectType, content_addressed_key},
    };
    use async_trait::async_trait;
    use serde_json::json;
    use sha2::Digest;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::BufReader as TokioBufReader;
    use tokio::io::{
        AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream as TokioBufStream, duplex,
    };
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_rustls::{
        TlsConnector,
        rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
    };

    async fn connect_pool() -> Result<sqlx::PgPool> {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://imap_cache:imap_cache_password@127.0.0.1:5432/imap_cache".to_string()
        });
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await?;
        db::run_migrations(&pool).await?;
        Ok(pool)
    }

    #[derive(Default)]
    struct TrackingObjectStore {
        bytes: Vec<u8>,
        get_calls: AtomicUsize,
        range_calls: AtomicUsize,
    }

    #[async_trait]
    impl ObjectStore for TrackingObjectStore {
        async fn put(
            &self,
            key: &str,
            bytes: &[u8],
        ) -> crate::error::Result<crate::storage::ObjectMetadata> {
            Ok(crate::storage::ObjectMetadata {
                key: key.to_string(),
                sha256: hex::encode(sha2::Sha256::digest(bytes)),
                size_octets: bytes.len() as u64,
            })
        }

        async fn get(&self, _key: &str) -> crate::error::Result<Option<Vec<u8>>> {
            self.get_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(self.bytes.clone()))
        }

        async fn get_range(
            &self,
            _key: &str,
            start: usize,
            end: Option<usize>,
        ) -> crate::error::Result<Option<Vec<u8>>> {
            self.range_calls.fetch_add(1, Ordering::SeqCst);
            if start >= self.bytes.len() {
                return Ok(Some(Vec::new()));
            }
            let end = end.unwrap_or(self.bytes.len()).min(self.bytes.len());
            Ok(Some(self.bytes[start..end].to_vec()))
        }

        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }

        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(true)
        }
    }

    async fn start_fake_upstream_server(
        raw: Vec<u8>,
    ) -> Result<(String, u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let fetch_count = Arc::new(AtomicUsize::new(0));
        let fetch_count_for_task = Arc::clone(&fetch_count);

        let handle = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = TokioBufReader::new(socket);
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
                let tag = line
                    .split_whitespace()
                    .next()
                    .unwrap_or("A0000")
                    .to_string();

                if line.contains("LOGIN") {
                    reader
                        .get_mut()
                        .write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                        .await
                        .unwrap();
                } else if line.contains("SELECT") {
                    reader
                        .get_mut()
                        .write_all(
                            format!(
                                "* FLAGS (\\Seen)\r\n* 1 EXISTS\r\n{tag} OK [READ-WRITE] SELECT completed\r\n"
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                } else if line.contains("UID FETCH") {
                    fetch_count_for_task.fetch_add(1, Ordering::SeqCst);
                    let header = format!("* 1 FETCH (UID 7 BODY[] {{{}}}\r\n", raw.len());
                    reader.get_mut().write_all(header.as_bytes()).await.unwrap();
                    reader.get_mut().write_all(&raw).await.unwrap();
                    reader
                        .get_mut()
                        .write_all(format!("\r\n)\r\n{tag} OK FETCH completed\r\n").as_bytes())
                        .await
                        .unwrap();
                } else if line.contains("LOGOUT") {
                    reader
                        .get_mut()
                        .write_all(
                            format!("* BYE logging out\r\n{tag} OK LOGOUT completed\r\n")
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                    break;
                } else {
                    reader
                        .get_mut()
                        .write_all(format!("{tag} OK completed\r\n").as_bytes())
                        .await
                        .unwrap();
                }
            }
        });

        Ok((addr.ip().to_string(), addr.port(), fetch_count, handle))
    }

    #[tokio::test]
    async fn reads_append_literal_after_continuation() -> Result<()> {
        let (client, server) = duplex(128);
        let mut server_stream = TokioBufStream::new(server);

        let client_task = tokio::spawn(async move {
            let (client_read, mut client_write) = tokio::io::split(client);
            let mut client_reader = TokioBufReader::new(client_read);

            client_write
                .write_all(b"A1 APPEND INBOX {5}\r\n")
                .await
                .unwrap();
            client_write.flush().await.unwrap();

            let mut continuation = String::new();
            client_reader.read_line(&mut continuation).await.unwrap();
            assert!(continuation.starts_with("+ "));

            client_write.write_all(b"hello").await.unwrap();
            client_write.flush().await.unwrap();
        });

        let mut line = String::new();
        server_stream.read_line(&mut line).await?;
        let parsed = read_command_with_literal(&mut server_stream, &line)
            .await?
            .expect("expected command");
        assert_eq!(parsed.0.name, "APPEND");
        assert_eq!(parsed.1.as_deref(), Some(b"hello".as_ref()));

        client_task.await.unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn plaintext_listener_upgrades_to_tls_via_starttls() -> Result<()> {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|err| Error::Config(format!("failed to generate test certificate: {err}")))?;
        let tempdir = tempfile::tempdir()?;
        let cert_path = tempdir.path().join("imap.crt");
        let key_path = tempdir.path().join("imap.key");
        std::fs::write(&cert_path, certified.cert.pem())?;
        std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

        let config = crate::config::Config {
            imap_tls_cert_path: Some(cert_path.clone()),
            imap_tls_key_path: Some(key_path.clone()),
            ..crate::config::Config::default()
        };
        let acceptor = tls_acceptor(&config)?.expect("test TLS acceptor");

        let services = Arc::new(AppServices {
            authenticator: Arc::new(crate::auth::StaticAuthenticator::new(
                "user@example.test".to_string(),
                security::hash_password("secret-password")?,
            )),
            repository: None,
            object_store: Arc::new(crate::storage::memory::MemoryObjectStore::new()),
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        });

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn({
            let services = Arc::clone(&services);
            async move { serve_plaintext(listener, services, Some(acceptor)).await }
        });

        let client = tokio::net::TcpStream::connect(addr).await?;
        let mut client_stream = TokioBufStream::new(client);

        let mut greeting = String::new();
        client_stream.read_line(&mut greeting).await?;
        assert!(greeting.starts_with("* OK"));

        client_stream.write_all(b"A1 CAPABILITY\r\n").await?;
        client_stream.flush().await?;
        let mut capability_lines = Vec::new();
        loop {
            let mut line = String::new();
            client_stream.read_line(&mut line).await?;
            let done = line.starts_with("A1 OK");
            capability_lines.push(line);
            if done {
                break;
            }
        }
        assert!(
            capability_lines
                .iter()
                .any(|line| line.contains("STARTTLS"))
        );

        client_stream.write_all(b"A2 STARTTLS\r\n").await?;
        client_stream.flush().await?;
        let mut starttls_response = String::new();
        client_stream.read_line(&mut starttls_response).await?;
        assert!(starttls_response.starts_with("A2 OK"));

        let plain_stream = client_stream.into_inner();
        let mut roots = RootCertStore::empty();
        let mut cert_reader = std::io::BufReader::new(std::fs::File::open(&cert_path)?);
        let certs =
            rustls_pemfile::certs(&mut cert_reader).collect::<std::result::Result<Vec<_>, _>>()?;
        for cert in certs {
            roots
                .add(cert)
                .map_err(|err| Error::Config(format!("failed to add root certificate: {err}")))?;
        }
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("localhost")
            .map_err(|err| Error::Config(format!("invalid TLS server name: {err}")))?;
        let tls_stream = connector.connect(server_name, plain_stream).await?;
        let mut tls_stream = TokioBufStream::new(tls_stream);

        tls_stream.write_all(b"A3 CAPABILITY\r\n").await?;
        tls_stream.flush().await?;
        let mut tls_capability_lines = Vec::new();
        loop {
            let mut line = String::new();
            tls_stream.read_line(&mut line).await?;
            let done = line.starts_with("A3 OK");
            tls_capability_lines.push(line);
            if done {
                break;
            }
        }
        assert!(
            !tls_capability_lines
                .iter()
                .any(|line| line.contains("STARTTLS"))
        );

        tls_stream
            .write_all(b"A4 LOGIN \"user@example.test\" \"secret-password\"\r\n")
            .await?;
        tls_stream.flush().await?;
        let mut login_lines = Vec::new();
        loop {
            let mut line = String::new();
            tls_stream.read_line(&mut line).await?;
            let done = line.starts_with("A4 OK");
            login_lines.push(line);
            if done {
                break;
            }
        }
        assert!(login_lines.iter().any(|line| line.starts_with("A4 OK")));

        tls_stream.write_all(b"A5 LOGOUT\r\n").await?;
        tls_stream.flush().await?;
        let mut bye = String::new();
        tls_stream.read_line(&mut bye).await?;
        assert!(bye.starts_with("* BYE"));

        server.abort();
        let _ = server.await;
        Ok(())
    }

    #[tokio::test]
    async fn authenticates_plain_with_initial_response() -> Result<()> {
        let password_hash = security::hash_password("secret-password")?;
        let services = AppServices {
            authenticator: Arc::new(crate::auth::StaticAuthenticator::new(
                "user@example.test".to_string(),
                password_hash,
            )),
            repository: None,
            object_store: Arc::new(crate::storage::memory::MemoryObjectStore::new()),
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };

        let mut session = ImapSession::new();
        let payload = base64::engine::general_purpose::STANDARD
            .encode(b"\0user@example.test\0secret-password");
        let command = ParsedCommand {
            tag: "A1".to_string(),
            name: "AUTHENTICATE".to_string(),
            args: vec!["PLAIN".to_string(), payload],
        };

        let (client, server) = duplex(128);
        let mut server_stream = TokioBufStream::new(server);
        handle_authenticate_command(&mut server_stream, &services, &mut session, &command).await?;
        drop(server_stream);

        let mut output = Vec::new();
        let mut client_reader = TokioBufReader::new(client);
        client_reader.read_to_end(&mut output).await?;
        let text = String::from_utf8(output)?;
        assert!(text.contains("A1 OK AUTHENTICATE completed"));
        assert_eq!(session.state, State::Authenticated);
        assert_eq!(
            session
                .authenticated
                .as_ref()
                .map(|ctx| ctx.username.as_str()),
            Some("user@example.test")
        );
        assert!(session.capabilities().contains(&"AUTH=XOAUTH2"));
        Ok(())
    }

    #[tokio::test]
    async fn authenticates_xoauth2_with_initial_response() -> Result<()> {
        let password_hash = security::hash_password("secret-token")?;
        let services = AppServices {
            authenticator: Arc::new(crate::auth::StaticAuthenticator::new(
                "user@example.test".to_string(),
                password_hash,
            )),
            repository: None,
            object_store: Arc::new(crate::storage::memory::MemoryObjectStore::new()),
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };

        let mut session = ImapSession::new();
        let payload = base64::engine::general_purpose::STANDARD
            .encode(b"user=user@example.test\x01auth=Bearer secret-token\x01\x01");
        let command = ParsedCommand {
            tag: "A1".to_string(),
            name: "AUTHENTICATE".to_string(),
            args: vec!["XOAUTH2".to_string(), payload],
        };

        let (client, server) = duplex(128);
        let mut server_stream = TokioBufStream::new(server);
        handle_authenticate_command(&mut server_stream, &services, &mut session, &command).await?;
        drop(server_stream);

        let mut output = Vec::new();
        let mut client_reader = TokioBufReader::new(client);
        client_reader.read_to_end(&mut output).await?;
        let text = String::from_utf8(output)?;
        assert!(text.contains("A1 OK AUTHENTICATE completed"));
        assert_eq!(session.state, State::Authenticated);
        assert_eq!(
            session
                .authenticated
                .as_ref()
                .map(|ctx| ctx.username.as_str()),
            Some("user@example.test")
        );
        Ok(())
    }

    #[tokio::test]
    async fn authenticates_plain_via_continuation_and_rejects_bad_password() -> Result<()> {
        let password_hash = security::hash_password("secret-password")?;
        let services = AppServices {
            authenticator: Arc::new(crate::auth::StaticAuthenticator::new(
                "user@example.test".to_string(),
                password_hash,
            )),
            repository: None,
            object_store: Arc::new(crate::storage::memory::MemoryObjectStore::new()),
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };

        let mut session = ImapSession::new();
        let command = ParsedCommand {
            tag: "A2".to_string(),
            name: "AUTHENTICATE".to_string(),
            args: vec!["PLAIN".to_string()],
        };

        let (client, server) = duplex(128);
        let mut server_stream = TokioBufStream::new(server);
        let client_task = tokio::spawn(async move {
            let (client_read, mut client_write) = tokio::io::split(client);
            let mut client_reader = TokioBufReader::new(client_read);

            let mut challenge = String::new();
            client_reader.read_line(&mut challenge).await.unwrap();
            assert!(challenge.starts_with("+"));

            let payload = base64::engine::general_purpose::STANDARD
                .encode(b"\0user@example.test\0wrong-password");
            client_write
                .write_all(format!("{payload}\r\n").as_bytes())
                .await
                .unwrap();
            client_write.flush().await.unwrap();

            let mut response = String::new();
            client_reader.read_line(&mut response).await.unwrap();
            assert!(response.contains("A2 NO [AUTHENTICATIONFAILED] invalid credentials"));
        });

        handle_authenticate_command(&mut server_stream, &services, &mut session, &command).await?;

        client_task.await.unwrap();
        assert_eq!(session.state, State::NotAuthenticated);
        assert!(session.authenticated.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn partial_raw_fetch_uses_range_reads_for_full_body() -> Result<()> {
        let store = Arc::new(TrackingObjectStore {
            bytes: b"From: A\r\n\r\nhello world".to_vec(),
            ..Default::default()
        });
        let services = AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: None,
            object_store: store.clone(),
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };
        let view = crate::db::repository::MailboxMessageView {
            id: 1,
            mailbox_id: 1,
            message_id: 1,
            local_uid: 1,
            upstream_uid: Some(11),
            modseq: None,
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            rfc822_blob_key: "Rfc822/abc".to_string(),
            rfc822_sha256: "sha256-test".to_string(),
            message_id_header: None,
            subject: None,
            envelope_json: json!({}),
            bodystructure_json: json!({}),
            internal_date: None,
            sent_date: None,
            size_octets: 22,
            text_preview: None,
        };
        let metrics = crate::metrics::AppMetrics::new();
        let selected = load_raw_fetch_bytes(
            &services,
            1,
            "INBOX",
            &view,
            &RawFetchSection::Whole(FetchBodySection::Full),
            Some((11, Some(5))),
            &metrics,
        )
        .await?
        .unwrap();

        assert_eq!(selected, b"hello");
        assert_eq!(store.range_calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.get_calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn body_fetch_marks_seen_but_peek_does_not() -> Result<()> {
        let pool = connect_pool().await?;
        let repo = Arc::new(PostgresRepository::new(
            pool,
            security::SecretBox::from_passphrase("test-master-key"),
        ));
        let store = Arc::new(MemoryObjectStore::new());

        let username = format!("peek-fetch-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Peek Fetch",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(1),
                uidnext: Some(1),
                highestmodseq: Some(0),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;

        let raw = concat!(
            "From: Alice <alice@example.test>\r\n",
            "Subject: Peek test\r\n",
            "\r\n",
            "peek body\r\n",
        );
        let blob_key = storage::content_addressed_key(storage::ObjectType::Rfc822, raw.as_bytes());
        store.put(&blob_key, raw.as_bytes()).await?;
        let message = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: &blob_key,
                rfc822_sha256: &hex::encode(sha2::Sha256::digest(raw.as_bytes())),
                message_id_header: Some("<peek@example.test>"),
                subject: Some("Peek test"),
                from_json: json!([{"kind": "mailbox", "display_name": "Alice", "address": "alice@example.test"}]),
                to_json: json!([]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({"subject": "Peek test"}),
                bodystructure_json: json!({
                    "type": "text",
                    "subtype": "plain",
                    "charset": "utf-8",
                    "params": {"charset": "utf-8"},
                    "transfer_encoding": "7BIT",
                    "size": 9
                }),
                internal_date: None,
                sent_date: None,
                size_octets: raw.len() as i64,
                text_preview: Some("peek body"),
            })
            .await?;
        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message.id,
            local_uid: 1,
            upstream_uid: Some(11),
            modseq: Some(1),
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;
        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message.id,
            local_uid: 2,
            upstream_uid: Some(12),
            modseq: Some(1),
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;

        let services = AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: Some(Arc::clone(&repo)),
            object_store: store,
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };
        let mut session = ImapSession::new();
        session.authenticated = Some(AuthContext {
            user_id: user.id,
            account_id: Some(account.id),
            username: username.clone(),
        });
        session.state = State::SelectedMailbox {
            read_only: false,
            mailbox: "INBOX".to_string(),
        };

        let command = parse_command("A1 FETCH 1 (BODY[])\r\n")?.expect("command");
        let (mut client, mut server) = duplex(4096);
        let handled =
            write_raw_fetch_response(&mut server, &services, &mut session, &command).await?;
        assert!(handled);
        server
            .write_all(format!("{} OK FETCH completed\r\n", command.tag).as_bytes())
            .await?;
        drop(server);
        let mut output = Vec::new();
        client.read_to_end(&mut output).await?;
        let body_fetch = String::from_utf8_lossy(&output);
        assert!(body_fetch.contains("* 1 FETCH (BODY[] {"));
        let flags_after_body = repo
            .list_mailbox_messages(mailbox.id)
            .await?
            .into_iter()
            .find(|message| message.local_uid == 1)
            .unwrap();
        assert!(
            flags_after_body
                .flags
                .iter()
                .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
        );

        let command = parse_command("A2 FETCH 2 (BODY.PEEK[])\r\n")?.expect("command");
        let (mut client, mut server) = duplex(4096);
        let handled =
            write_raw_fetch_response(&mut server, &services, &mut session, &command).await?;
        assert!(handled);
        server
            .write_all(format!("{} OK FETCH completed\r\n", command.tag).as_bytes())
            .await?;
        drop(server);
        let mut output = Vec::new();
        client.read_to_end(&mut output).await?;
        let peek_fetch = String::from_utf8_lossy(&output);
        assert!(peek_fetch.contains("* 2 FETCH (BODY.PEEK[] {"));
        let flags_after_peek = repo
            .list_mailbox_messages(mailbox.id)
            .await?
            .into_iter()
            .find(|message| message.local_uid == 2)
            .unwrap();
        assert!(
            !flags_after_peek
                .flags
                .iter()
                .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
        );

        Ok(())
    }

    #[tokio::test]
    async fn writes_raw_fetch_literal_response_bytes() -> Result<()> {
        let pool = connect_pool().await?;
        let repo = Arc::new(PostgresRepository::new(
            pool,
            security::SecretBox::from_passphrase("test-master-key"),
        ));
        let store = Arc::new(MemoryObjectStore::new());

        let username = format!("raw-fetch-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Raw Fetch",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(1),
                uidnext: Some(1),
                highestmodseq: Some(0),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;

        let raw = concat!(
            "From: Alice <alice@example.test>\r\n",
            "Subject: Raw fetch\r\n",
            "Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Hello world from raw fetch.\r\n"
        );
        let blob_key = storage::content_addressed_key(storage::ObjectType::Rfc822, raw.as_bytes());
        store.put(&blob_key, raw.as_bytes()).await?;
        let message = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: &blob_key,
                rfc822_sha256: &hex::encode(sha2::Sha256::digest(raw.as_bytes())),
                message_id_header: Some("<raw@example.test>"),
                subject: Some("Raw fetch"),
                from_json: json!([{"kind": "mailbox", "display_name": "Alice", "address": "alice@example.test"}]),
                to_json: json!([]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({
                    "date": 1704110400i64,
                    "subject": "Raw fetch",
                    "message_id": "<raw@example.test>",
                    "from": [{"kind": "mailbox", "display_name": "Alice", "address": "alice@example.test"}],
                    "reply_to": [],
                    "to": [],
                    "cc": [],
                    "bcc": []
                }),
                bodystructure_json: json!({
                    "type": "text",
                    "subtype": "plain",
                    "charset": "utf-8",
                    "params": {"charset": "utf-8"},
                    "transfer_encoding": "7BIT",
                    "size": 28
                }),
                internal_date: None,
                sent_date: None,
                size_octets: raw.len() as i64,
                text_preview: Some("Hello world from raw fetch."),
            })
            .await?;
        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message.id,
            local_uid: 1,
            upstream_uid: Some(11),
            modseq: Some(1),
            flags: vec!["\\Seen".to_string()],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;

        let services = AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: Some(Arc::clone(&repo)),
            object_store: store,
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };
        let mut session = ImapSession::new();
        session.authenticated = Some(AuthContext {
            user_id: user.id,
            account_id: Some(account.id),
            username: username.clone(),
        });
        session.state = State::SelectedMailbox {
            read_only: false,
            mailbox: "INBOX".to_string(),
        };

        let command =
            parse_command("A1 FETCH 1 (FLAGS BODY[]<0.5> RFC822.SIZE)\r\n")?.expect("command");
        let (mut client, mut server) = duplex(4096);
        let handled =
            write_raw_fetch_response(&mut server, &services, &mut session, &command).await?;
        assert!(handled);
        server
            .write_all(format!("{} OK FETCH completed\r\n", command.tag).as_bytes())
            .await?;
        drop(server);

        let mut output = Vec::new();
        client.read_to_end(&mut output).await?;
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("* 1 FETCH (FLAGS (\\Seen) BODY[]<0.5> {5}"));
        assert!(text.contains("From:"));
        assert!(text.contains(&format!("RFC822.SIZE {}", raw.len())));
        assert!(text.ends_with("A1 OK FETCH completed\r\n"));
        Ok(())
    }

    #[tokio::test]
    async fn missing_raw_fetch_blob_is_rehydrated_from_upstream() -> Result<()> {
        let token = uuid::Uuid::new_v4();
        let raw = format!(
            concat!(
                "From: Alice <alice@example.test>\r\n",
                "To: Bob <bob@example.test>\r\n",
                "Subject: Rehydrate test {token}\r\n",
                "Message-ID: <rehydrate-{token}@example.test>\r\n",
                "MIME-Version: 1.0\r\n",
                "Content-Type: text/plain; charset=utf-8\r\n",
                "\r\n",
                "Recovered from upstream {token}.\r\n",
            ),
            token = token
        )
        .into_bytes();
        let (upstream_host, upstream_port, fetch_count, upstream_server) =
            start_fake_upstream_server(raw.clone()).await?;

        let pool = connect_pool().await?;
        let repo = Arc::new(PostgresRepository::new(
            pool,
            security::SecretBox::from_passphrase("test-master-key"),
        ));
        let object_store: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());

        let username = format!("rehydrate-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Rehydrate Test",
                email_address: &username,
                upstream_host: &upstream_host,
                upstream_port: i32::from(upstream_port),
                upstream_tls_mode: UpstreamTlsMode::Plain,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-password",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(1),
                uidnext: Some(1),
                highestmodseq: Some(0),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;

        let ingestor =
            crate::sync::MessageIngestor::new(Arc::clone(&repo), Arc::clone(&object_store), None);
        let ingested = ingestor
            .ingest_raw_message(
                account.id,
                mailbox.id,
                "INBOX",
                1,
                Some(7),
                None,
                &raw,
                vec![],
            )
            .await?;
        object_store.delete(&ingested.blob_key).await?;
        assert!(!object_store.exists(&ingested.blob_key).await?);

        let services = AppServices {
            authenticator: Arc::new(crate::auth::PostgresAuthenticator::new(Arc::clone(&repo))),
            repository: Some(Arc::clone(&repo)),
            object_store: object_store.clone(),
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };
        let mut session = ImapSession::new();
        session
            .handle(
                &services,
                &format!("A1 LOGIN \"{username}\" \"secret-password\"\r\n"),
            )
            .await?;
        session.handle(&services, "A2 SELECT INBOX\r\n").await?;

        let command = parse_command("A3 FETCH 1 (BODY[])\r\n")?.expect("command");
        let (mut client, mut server) = duplex(4096);
        let handled =
            write_raw_fetch_response(&mut server, &services, &mut session, &command).await?;
        assert!(handled);
        server
            .write_all(format!("{} OK FETCH completed\r\n", command.tag).as_bytes())
            .await?;
        drop(server);

        let mut output = Vec::new();
        client.read_to_end(&mut output).await?;
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("* 1 FETCH (BODY[] {"));
        assert!(text.contains("Subject: Rehydrate test"));
        assert!(text.contains("Recovered from upstream"));
        assert!(text.ends_with("A3 OK FETCH completed\r\n"));
        assert!(object_store.exists(&ingested.blob_key).await?);
        let raw_cache = repo
            .find_cache_object_by_account_type_and_blob_key(account.id, "rfc822", &ingested.blob_key)
            .await?
            .expect("raw cache object");
        assert_eq!(raw_cache.ref_count, 1);
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);

        upstream_server.await.unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn missing_mime_part_blob_is_rebuilt_from_raw_message() -> Result<()> {
        let token = uuid::Uuid::new_v4();
        let raw = format!(
            concat!(
                "From: Alice <alice@example.test>\r\n",
                "To: Bob <bob@example.test>\r\n",
                "Subject: MIME part rehydrate {token}\r\n",
                "Message-ID: <mime-part-rehydrate-{token}@example.test>\r\n",
                "MIME-Version: 1.0\r\n",
                "Content-Type: multipart/mixed; boundary=\"outer\"\r\n",
                "\r\n",
                "--outer\r\n",
                "Content-Type: multipart/alternative; boundary=\"inner\"\r\n",
                "\r\n",
                "--inner\r\n",
                "Content-Type: text/plain; charset=utf-8\r\n",
                "\r\n",
                "Nested body text {token}.\r\n",
                "--inner\r\n",
                "Content-Type: text/html; charset=utf-8\r\n",
                "\r\n",
                "<p>Nested body text {token}.</p>\r\n",
                "--inner--\r\n",
                "--outer\r\n",
                "Content-Type: application/octet-stream\r\n",
                "Content-Disposition: attachment; filename=\"file.bin\"\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "Zm9v\r\n",
                "--outer--\r\n",
            ),
            token = token
        )
        .into_bytes();
        let parsed = crate::mime::parse_message(&raw)?;
        let expected_part = parsed
            .mime_parts
            .iter()
            .find(|part| part.part_path == "1.1.1")
            .cloned()
            .ok_or_else(|| Error::Storage("missing expected MIME part".to_string()))?;

        let pool = connect_pool().await?;
        let repo = Arc::new(PostgresRepository::new(
            pool,
            security::SecretBox::from_passphrase("test-master-key"),
        ));
        let object_store: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());

        let username = format!("mime-part-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "MIME Part Rehydrate",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-password",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(1),
                uidnext: Some(1),
                highestmodseq: Some(0),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;

        let ingestor =
            crate::sync::MessageIngestor::new(Arc::clone(&repo), Arc::clone(&object_store), None);
        let ingested = ingestor
            .ingest_raw_message(
                account.id,
                mailbox.id,
                "INBOX",
                1,
                Some(7),
                None,
                &raw,
                vec![],
            )
            .await?;
        let part = repo
            .find_mime_part_by_message_and_path(account.id, ingested.message_id, "1.1.1")
            .await?
            .ok_or_else(|| Error::Storage("missing MIME part record".to_string()))?;
        let object_type = cache_object_type_for_mime_part(&part);
        object_store.delete(&part.blob_key).await?;
        sqlx::query(
            "DELETE FROM cache_objects WHERE account_id = $1 AND object_type = $2 AND blob_key = $3",
        )
        .bind(account.id)
        .bind(object_type)
        .bind(&part.blob_key)
        .execute(repo.pool())
        .await?;
        assert!(!object_store.exists(&part.blob_key).await?);
        assert!(object_store.exists(&ingested.blob_key).await?);
        assert!(
            repo.find_cache_object_by_account_type_and_blob_key(account.id, object_type, &part.blob_key)
                .await?
                .is_none()
        );

        let services = AppServices {
            authenticator: Arc::new(crate::auth::PostgresAuthenticator::new(Arc::clone(&repo))),
            repository: Some(Arc::clone(&repo)),
            object_store: object_store.clone(),
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };
        let mut session = ImapSession::new();
        session
            .handle(
                &services,
                &format!("A1 LOGIN \"{username}\" \"secret-password\"\r\n"),
            )
            .await?;
        session.handle(&services, "A2 SELECT INBOX\r\n").await?;

        let command = parse_command("A3 FETCH 1 (BODY[1.1.TEXT])\r\n")?.expect("command");
        let (mut client, mut server) = duplex(4096);
        let handled =
            write_raw_fetch_response(&mut server, &services, &mut session, &command).await?;
        assert!(handled);
        server
            .write_all(format!("{} OK FETCH completed\r\n", command.tag).as_bytes())
            .await?;
        drop(server);

        let mut output = Vec::new();
        client.read_to_end(&mut output).await?;
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("* 1 FETCH (BODY[1.1.TEXT] {"));
        assert!(text.contains("Nested body text"));
        assert!(text.ends_with("A3 OK FETCH completed\r\n"));
        assert!(object_store.exists(&part.blob_key).await?);
        assert_eq!(object_store.get(&part.blob_key).await?.as_deref(), Some(&expected_part.raw_bytes[..]));
        assert!(
            repo.find_cache_object_by_account_type_and_blob_key(account.id, object_type, &part.blob_key)
                .await?
                .is_some()
        );

        Ok(())
    }

    #[tokio::test]
    async fn failed_raw_fetch_does_not_mark_message_seen() -> Result<()> {
        let pool = connect_pool().await?;
        let repo = Arc::new(PostgresRepository::new(
            pool,
            security::SecretBox::from_passphrase("test-master-key"),
        ));
        let object_store: Arc<dyn ObjectStore> = Arc::new(MemoryObjectStore::new());

        let username = format!("failed-fetch-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Failed Fetch Test",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-password",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(1),
                uidnext: Some(1),
                highestmodseq: Some(0),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;

        let raw = concat!(
            "From: Alice <alice@example.test>\r\n",
            "To: Bob <bob@example.test>\r\n",
            "Subject: Failed fetch\r\n",
            "Message-ID: <failed-fetch@example.test>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "This body will be missing.\r\n",
        );
        let ingestor =
            crate::sync::MessageIngestor::new(Arc::clone(&repo), Arc::clone(&object_store), None);
        let ingested = ingestor
            .ingest_raw_message(
                account.id,
                mailbox.id,
                "INBOX",
                1,
                None,
                None,
                raw.as_bytes(),
                vec![],
            )
            .await?;
        object_store.delete(&ingested.blob_key).await?;
        assert!(!object_store.exists(&ingested.blob_key).await?);

        let services = AppServices {
            authenticator: Arc::new(crate::auth::PostgresAuthenticator::new(Arc::clone(&repo))),
            repository: Some(Arc::clone(&repo)),
            object_store: object_store.clone(),
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };
        let mut session = ImapSession::new();
        session
            .handle(
                &services,
                &format!("A1 LOGIN \"{username}\" \"secret-password\"\r\n"),
            )
            .await?;
        session.handle(&services, "A2 SELECT INBOX\r\n").await?;

        let command = parse_command("A3 FETCH 1 (BODY[])\r\n")?.expect("command");
        let (_client, mut server) = duplex(4096);
        let result = write_raw_fetch_response(&mut server, &services, &mut session, &command).await;
        assert!(result.is_err());
        drop(server);

        let flags = repo.list_mailbox_messages(mailbox.id).await?[0].flags.clone();
        assert!(
            !flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\Seen")),
            "failed fetch should not mark the message seen"
        );

        Ok(())
    }

    #[tokio::test]
    async fn writes_header_fields_fetch_literal_response_bytes() -> Result<()> {
        let pool = connect_pool().await?;
        let repo = Arc::new(PostgresRepository::new(
            pool,
            security::SecretBox::from_passphrase("test-master-key"),
        ));
        let store = Arc::new(MemoryObjectStore::new());

        let username = format!("header-fetch-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Header Fetch",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(1),
                uidnext: Some(1),
                highestmodseq: Some(0),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;

        let raw = concat!(
            "From: Alice <alice@example.test>\r\n",
            "Subject: Header slice\r\n",
            "Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n",
            "X-Trace: keep-me\r\n",
            "\r\n",
            "Body text.\r\n"
        );
        let blob_key = storage::content_addressed_key(storage::ObjectType::Rfc822, raw.as_bytes());
        store.put(&blob_key, raw.as_bytes()).await?;
        let message = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: &blob_key,
                rfc822_sha256: &hex::encode(sha2::Sha256::digest(raw.as_bytes())),
                message_id_header: Some("<headers@example.test>"),
                subject: Some("Header slice"),
                from_json: json!([{"kind": "mailbox", "display_name": "Alice", "address": "alice@example.test"}]),
                to_json: json!([]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({
                    "date": 1704110400i64,
                    "subject": "Header slice",
                    "message_id": "<headers@example.test>",
                    "from": [{"kind": "mailbox", "display_name": "Alice", "address": "alice@example.test"}],
                    "reply_to": [],
                    "to": [],
                    "cc": [],
                    "bcc": []
                }),
                bodystructure_json: json!({
                    "type": "text",
                    "subtype": "plain",
                    "charset": "utf-8",
                    "params": {"charset": "utf-8"},
                    "transfer_encoding": "7BIT",
                    "size": 11
                }),
                internal_date: None,
                sent_date: None,
                size_octets: raw.len() as i64,
                text_preview: Some("Body text."),
            })
            .await?;
        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message.id,
            local_uid: 1,
            upstream_uid: Some(11),
            modseq: Some(1),
            flags: vec!["\\Seen".to_string()],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;

        let services = AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: Some(Arc::clone(&repo)),
            object_store: store,
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };
        let mut session = ImapSession::new();
        session.authenticated = Some(AuthContext {
            user_id: user.id,
            account_id: Some(account.id),
            username: username.clone(),
        });
        session.state = State::SelectedMailbox {
            read_only: false,
            mailbox: "INBOX".to_string(),
        };

        let command =
            parse_command("A1 FETCH 1 (FLAGS BODY[HEADER.FIELDS (Subject From)] RFC822.SIZE)\r\n")?
                .expect("command");
        let (mut client, mut server) = duplex(4096);
        let handled =
            write_raw_fetch_response(&mut server, &services, &mut session, &command).await?;
        assert!(handled);
        server
            .write_all(format!("{} OK FETCH completed\r\n", command.tag).as_bytes())
            .await?;
        drop(server);

        let mut output = Vec::new();
        client.read_to_end(&mut output).await?;
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("* 1 FETCH (FLAGS (\\Seen) BODY[HEADER.FIELDS (SUBJECT FROM)] {"));
        assert!(text.contains("From: Alice <alice@example.test>\r\nSubject: Header slice\r\n\r\n"));
        assert!(!text.contains("X-Trace: keep-me"));
        assert!(text.contains(&format!("RFC822.SIZE {}", raw.len())));
        assert!(text.ends_with("A1 OK FETCH completed\r\n"));
        Ok(())
    }

    #[tokio::test]
    async fn writes_header_fields_not_fetch_literal_response_bytes() -> Result<()> {
        let pool = connect_pool().await?;
        let repo = Arc::new(PostgresRepository::new(
            pool,
            security::SecretBox::from_passphrase("test-master-key"),
        ));
        let store = Arc::new(MemoryObjectStore::new());

        let username = format!("header-not-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Header Not Fetch",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(1),
                uidnext: Some(1),
                highestmodseq: Some(0),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;

        let raw = concat!(
            "From: Alice <alice@example.test>\r\n",
            "Subject: Header not slice\r\n",
            "Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n",
            "X-Trace: keep-me\r\n",
            "\r\n",
            "Body text.\r\n"
        );
        let blob_key = storage::content_addressed_key(storage::ObjectType::Rfc822, raw.as_bytes());
        store.put(&blob_key, raw.as_bytes()).await?;
        let message = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: &blob_key,
                rfc822_sha256: &hex::encode(sha2::Sha256::digest(raw.as_bytes())),
                message_id_header: Some("<headers-not@example.test>"),
                subject: Some("Header not slice"),
                from_json: json!([{"kind": "mailbox", "display_name": "Alice", "address": "alice@example.test"}]),
                to_json: json!([]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({
                    "date": 1704110400i64,
                    "subject": "Header not slice",
                    "message_id": "<headers-not@example.test>",
                    "from": [{"kind": "mailbox", "display_name": "Alice", "address": "alice@example.test"}],
                    "reply_to": [],
                    "to": [],
                    "cc": [],
                    "bcc": []
                }),
                bodystructure_json: json!({
                    "type": "text",
                    "subtype": "plain",
                    "charset": "utf-8",
                    "params": {"charset": "utf-8"},
                    "transfer_encoding": "7BIT",
                    "size": 11
                }),
                internal_date: None,
                sent_date: None,
                size_octets: raw.len() as i64,
                text_preview: Some("Body text."),
            })
            .await?;
        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message.id,
            local_uid: 1,
            upstream_uid: Some(11),
            modseq: Some(1),
            flags: vec!["\\Seen".to_string()],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;

        let services = AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: Some(Arc::clone(&repo)),
            object_store: store,
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };
        let mut session = ImapSession::new();
        session.authenticated = Some(AuthContext {
            user_id: user.id,
            account_id: Some(account.id),
            username: username.clone(),
        });
        session.state = State::SelectedMailbox {
            read_only: false,
            mailbox: "INBOX".to_string(),
        };

        let command =
            parse_command("A1 FETCH 1 (BODY[HEADER.FIELDS.NOT (X-Trace)] RFC822.SIZE)\r\n")?
                .expect("command");
        let (mut client, mut server) = duplex(4096);
        let handled =
            write_raw_fetch_response(&mut server, &services, &mut session, &command).await?;
        assert!(handled);
        server
            .write_all(format!("{} OK FETCH completed\r\n", command.tag).as_bytes())
            .await?;
        drop(server);

        let mut output = Vec::new();
        client.read_to_end(&mut output).await?;
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("* 1 FETCH (BODY[HEADER.FIELDS.NOT (X-TRACE)] {"));
        assert!(text.contains("From: Alice <alice@example.test>\r\nSubject: Header not slice\r\nDate: Mon, 1 Jan 2024 12:00:00 +0000\r\n\r\n"));
        assert!(!text.contains("X-Trace: keep-me"));
        assert!(text.contains(&format!("RFC822.SIZE {}", raw.len())));
        assert!(text.ends_with("A1 OK FETCH completed\r\n"));
        Ok(())
    }

    #[tokio::test]
    async fn login_commands_are_rate_limited_after_repeated_failures() -> Result<()> {
        let password_hash = security::hash_password("secret-password")?;
        let services = AppServices {
            authenticator: Arc::new(crate::auth::StaticAuthenticator::new(
                "user@example.test".to_string(),
                password_hash,
            )),
            repository: None,
            object_store: Arc::new(crate::storage::memory::MemoryObjectStore::new()),
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(crate::notifications::MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };

        let mut session = ImapSession::new();
        for tag in 1..=5 {
            let response = session
                .handle(
                    &services,
                    &format!("A{tag} LOGIN \"user@example.test\" \"wrong-password\"\r\n"),
                )
                .await?;
            assert!(
                response
                    .iter()
                    .any(|line| line.contains("AUTHENTICATIONFAILED"))
            );
        }

        let blocked = session
            .handle(
                &services,
                "A6 LOGIN \"user@example.test\" \"secret-password\"\r\n",
            )
            .await?;
        assert!(
            blocked
                .iter()
                .any(|line| line.contains("AUTHENTICATIONFAILED")),
            "login should remain blocked after repeated failures"
        );
        assert_eq!(session.state, State::NotAuthenticated);
        Ok(())
    }

    #[tokio::test]
    async fn idle_wakes_for_mailbox_updates() -> Result<()> {
        let pool = connect_pool().await?;
        let events = Arc::new(MailboxEventHub::new(16));
        let repo = Arc::new(
            PostgresRepository::new(
                pool,
                security::SecretBox::from_passphrase("test-master-key"),
            )
            .with_event_sink(Arc::new(HubMutationEventSink::new(Arc::clone(&events)))),
        );
        let store = Arc::new(MemoryObjectStore::new());

        let username = format!("idle-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Idle Test",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(42),
                uidnext: Some(7),
                highestmodseq: Some(9),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;
        let message = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: "blob-idle",
                rfc822_sha256: "sha-idle",
                message_id_header: Some("<idle@example.test>"),
                subject: Some("Idle Test"),
                from_json: json!([{"kind":"mailbox","display_name":"Idle","address":"idle@example.test"}]),
                to_json: json!([]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({
                    "date": 1704110400i64,
                    "subject": "Idle Test",
                    "message_id": "<idle@example.test>",
                    "from": [{"kind": "mailbox", "display_name": "Idle", "address": "idle@example.test"}],
                    "reply_to": [],
                    "to": [],
                    "cc": [],
                    "bcc": []
                }),
                bodystructure_json: json!({
                    "type": "text",
                    "subtype": "plain",
                    "charset": "utf-8",
                    "params": {"charset": "utf-8"},
                    "transfer_encoding": "7BIT",
                    "size": 11
                }),
                internal_date: None,
                sent_date: None,
                size_octets: 64,
                text_preview: Some("Idle body"),
            })
            .await?;
        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message.id,
            local_uid: 1,
            upstream_uid: Some(11),
            modseq: Some(1),
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;
        repo.refresh_mailbox_counts(mailbox.id).await?;

        let services = Arc::new(AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: Some(Arc::clone(&repo)),
            object_store: store,
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events,
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        });
        let mut session = ImapSession::new();
        session.authenticated = Some(AuthContext {
            user_id: user.id,
            account_id: Some(account.id),
            username: username.clone(),
        });
        let select = session.handle(&services, "A1 SELECT INBOX\r\n").await?;
        assert!(select.iter().any(|line| line.starts_with("A1 OK")));

        let (client, server) = duplex(1024);
        let mut server_stream = TokioBufStream::new(server);

        let (ready_tx, ready_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let services_for_idle = Arc::clone(&services);
        let idle_task = tokio::spawn(async move {
            handle_idle_command(&mut server_stream, &services_for_idle, &mut session, "A2").await
        });

        let client_task = tokio::spawn(async move {
            let (client_read, mut client_write) = tokio::io::split(client);
            let mut client_reader = TokioBufReader::new(client_read);

            let mut first = String::new();
            client_reader.read_line(&mut first).await.unwrap();
            assert!(first.starts_with("+ idling"));
            ready_tx.send(()).unwrap();

            release_rx.await.unwrap();
            client_write.write_all(b"DONE\r\n").await.unwrap();
            client_write.flush().await.unwrap();

            let mut lines = Vec::new();
            loop {
                let mut line = String::new();
                let bytes = client_reader.read_line(&mut line).await.unwrap();
                if bytes == 0 {
                    break;
                }
                lines.push(line);
                if lines.iter().any(|line| line.starts_with("A2 OK")) {
                    break;
                }
            }

            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("* 1 FETCH (FLAGS (\\Seen))"))
            );
            assert!(
                lines
                    .iter()
                    .any(|line| line.starts_with("A2 OK IDLE terminated"))
            );
        });

        ready_rx.await.unwrap();
        repo.update_mailbox_message_flags(mailbox.id, 1, vec!["\\Seen".to_string()])
            .await?;
        let _ = release_tx.send(());

        client_task.await.unwrap();
        idle_task.await.unwrap()?;
        Ok(())
    }

    #[tokio::test]
    async fn idle_wakes_for_client_append() -> Result<()> {
        let pool = connect_pool().await?;
        let events = Arc::new(MailboxEventHub::new(16));
        let repo = Arc::new(
            PostgresRepository::new(
                pool,
                security::SecretBox::from_passphrase("test-master-key"),
            )
            .with_event_sink(Arc::new(HubMutationEventSink::new(Arc::clone(&events)))),
        );
        let store = Arc::new(MemoryObjectStore::new());

        let username = format!("idle-append-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Idle Append Test",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(42),
                uidnext: Some(7),
                highestmodseq: Some(9),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;
        repo.refresh_mailbox_counts(mailbox.id).await?;

        let services = Arc::new(AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: Some(Arc::clone(&repo)),
            object_store: store,
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events,
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        });
        let mut idle_session = ImapSession::new();
        idle_session.authenticated = Some(AuthContext {
            user_id: user.id,
            account_id: Some(account.id),
            username: username.clone(),
        });
        let select = idle_session
            .handle(&services, "A1 SELECT INBOX\r\n")
            .await?;
        assert!(select.iter().any(|line| line.starts_with("A1 OK")));

        let mut append_session = ImapSession::new();
        append_session.authenticated = Some(AuthContext {
            user_id: user.id,
            account_id: Some(account.id),
            username: username.clone(),
        });
        append_session.state = State::Authenticated;

        let (client, server) = duplex(1024);
        let mut server_stream = TokioBufStream::new(server);

        let (ready_tx, ready_rx) = oneshot::channel();
        let (seen_tx, seen_rx) = oneshot::channel();
        let services_for_idle = Arc::clone(&services);
        let idle_task = tokio::spawn(async move {
            handle_idle_command_with_timeout(
                &mut server_stream,
                &services_for_idle,
                &mut idle_session,
                "A2",
                Duration::from_secs(30),
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            let (client_read, mut client_write) = tokio::io::split(client);
            let mut client_reader = TokioBufReader::new(client_read);
            let mut seen_tx = Some(seen_tx);

            let mut first = String::new();
            client_reader.read_line(&mut first).await.unwrap();
            assert!(first.starts_with("+ idling"));
            ready_tx.send(()).unwrap();

            let mut saw_exists = false;
            loop {
                let mut line = String::new();
                let bytes = client_reader.read_line(&mut line).await.unwrap();
                if bytes == 0 {
                    break;
                }
                if line.contains("* 1 EXISTS") {
                    saw_exists = true;
                    if let Some(tx) = seen_tx.take() {
                        let _ = tx.send(());
                    }
                    client_write.write_all(b"DONE\r\n").await.unwrap();
                    client_write.flush().await.unwrap();
                }
                if line.starts_with("A2 OK") {
                    break;
                }
            }

            assert!(saw_exists, "IDLE should wake on client APPEND");
        });

        ready_rx.await.unwrap();
        let append = append_session
            .handle(
                &services,
                "A3 APPEND INBOX (\\Seen) \"12-Feb-2024 10:00:00 +0000\" \"From: Alice <alice@example.com>\\r\\nSubject: idle append\\r\\n\\r\\nbody\\r\\n\"\r\n",
            )
            .await?;
        assert!(append.iter().any(|line| line.contains("APPEND completed")));
        seen_rx.await.unwrap();

        client_task.await.unwrap();
        idle_task.await.unwrap()?;
        Ok(())
    }

    #[tokio::test]
    async fn idle_wakes_for_client_expunge() -> Result<()> {
        let pool = connect_pool().await?;
        let events = Arc::new(MailboxEventHub::new(16));
        let repo = Arc::new(
            PostgresRepository::new(
                pool,
                security::SecretBox::from_passphrase("test-master-key"),
            )
            .with_event_sink(Arc::new(HubMutationEventSink::new(Arc::clone(&events)))),
        );
        let store = Arc::new(MemoryObjectStore::new());

        let username = format!("idle-expunge-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Idle Expunge Test",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(42),
                uidnext: Some(7),
                highestmodseq: Some(9),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;
        repo.refresh_mailbox_counts(mailbox.id).await?;

        let services = Arc::new(AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: Some(Arc::clone(&repo)),
            object_store: store,
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events,
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        });
        let mut session = ImapSession::new();
        session.authenticated = Some(AuthContext {
            user_id: user.id,
            account_id: Some(account.id),
            username: username.clone(),
        });
        let select = session.handle(&services, "A1 SELECT INBOX\r\n").await?;
        assert!(select.iter().any(|line| line.starts_with("A1 OK")));

        let event = crate::notifications::MutationEvent::message_changed_with_context(
            Some(account.id),
            Some(mailbox.id),
            Some(1),
            Some(1),
            Some(1),
            Vec::new(),
            "delete_mailbox_message:1",
        );
        let notification = idle_notification_for_event(&services, &mut session, &event).await?;
        assert_eq!(notification.as_deref(), Some("* 1 EXPUNGE"));
        Ok(())
    }

    #[tokio::test]
    async fn idle_notifies_on_flag_update() -> Result<()> {
        let pool = connect_pool().await?;
        let events = Arc::new(MailboxEventHub::new(16));
        let repo = Arc::new(
            PostgresRepository::new(
                pool,
                security::SecretBox::from_passphrase("test-master-key"),
            )
            .with_event_sink(Arc::new(HubMutationEventSink::new(Arc::clone(&events)))),
        );
        let store = Arc::new(MemoryObjectStore::new());

        let username = format!("idle-flags-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Idle Flags Test",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(42),
                uidnext: Some(7),
                highestmodseq: Some(9),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;
        let message = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: "rfc822/idle-flags",
                rfc822_sha256: "sha256-idle-flags",
                message_id_header: Some("<idle-flags@example.test>"),
                subject: Some("Idle Flags Test"),
                from_json: json!([{"address": "alice@example.test"}]),
                to_json: json!([{"address": "bob@example.test"}]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({"subject": "Idle Flags Test"}),
                bodystructure_json: json!({"type": "text"}),
                internal_date: None,
                sent_date: None,
                size_octets: 32,
                text_preview: Some("flags body"),
            })
            .await?;
        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message.id,
            local_uid: 1,
            upstream_uid: Some(401),
            modseq: Some(1),
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;

        let services = AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: Some(Arc::clone(&repo)),
            object_store: store,
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events,
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        };
        let mut session = ImapSession::new();
        session.authenticated = Some(AuthContext {
            user_id: user.id,
            account_id: Some(account.id),
            username: username.clone(),
        });
        let select = session.handle(&services, "A1 SELECT INBOX\r\n").await?;
        assert!(select.iter().any(|line| line.starts_with("A1 OK")));

        let event = crate::notifications::MutationEvent::message_changed_with_context(
            Some(account.id),
            Some(mailbox.id),
            Some(message.id),
            Some(1),
            Some(1),
            vec!["\\Seen".to_string()],
            "update_mailbox_message_flags",
        );
        let notification = idle_notification_for_event(&services, &mut session, &event).await?;
        assert_eq!(notification.as_deref(), Some("* 1 FETCH (FLAGS (\\Seen))"));
        Ok(())
    }

    #[tokio::test]
    async fn idle_times_out_after_inactivity() -> Result<()> {
        let services = Arc::new(AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: None,
            object_store: Arc::new(crate::storage::memory::MemoryObjectStore::new()),
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events: Arc::new(MailboxEventHub::new(16)),
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        });
        let mut session = ImapSession::new();

        let (client, server) = duplex(1024);
        let mut server_stream = TokioBufStream::new(server);

        let idle_task = tokio::spawn(async move {
            handle_idle_command_with_timeout(
                &mut server_stream,
                &services,
                &mut session,
                "A9",
                Duration::from_millis(20),
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            let (client_read, mut client_write) = tokio::io::split(client);
            let mut client_reader = TokioBufReader::new(client_read);

            let mut first = String::new();
            client_reader.read_line(&mut first).await.unwrap();
            assert!(first.starts_with("+ idling"));
            client_write.flush().await.unwrap();

            let mut second = String::new();
            client_reader.read_line(&mut second).await.unwrap();
            assert!(second.starts_with("* BYE IDLE timeout"));
        });

        client_task.await.unwrap();
        idle_task.await.unwrap()?;
        Ok(())
    }

    #[tokio::test]
    async fn threads_ordered_subject_and_uid_thread() -> Result<()> {
        let pool = connect_pool().await?;
        let events = Arc::new(MailboxEventHub::new(16));
        let repo = Arc::new(
            PostgresRepository::new(
                pool,
                security::SecretBox::from_passphrase("test-master-key"),
            )
            .with_event_sink(Arc::new(HubMutationEventSink::new(Arc::clone(&events)))),
        );
        let store = Arc::new(MemoryObjectStore::new());

        let username = format!("threading-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Threading Test",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(42),
                uidnext: Some(25),
                highestmodseq: Some(9),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;

        let message_one = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: "rfc822/thread-1",
                rfc822_sha256: "sha256-thread-1",
                message_id_header: Some("<thread-1@example.test>"),
                subject: Some("Project Thread"),
                from_json: json!([]),
                to_json: json!([]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({
                    "date": 1700000000i64,
                    "subject": "Project Thread",
                    "message_id": "<thread-1@example.test>",
                    "from": [],
                    "reply_to": [],
                    "to": [],
                    "cc": [],
                    "bcc": []
                }),
                bodystructure_json: json!({"type": "text"}),
                internal_date: None,
                sent_date: None,
                size_octets: 64,
                text_preview: Some("one"),
            })
            .await?;
        let message_two = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: "rfc822/thread-2",
                rfc822_sha256: "sha256-thread-2",
                message_id_header: Some("<thread-2@example.test>"),
                subject: Some("Re: Project Thread"),
                from_json: json!([]),
                to_json: json!([]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({
                    "date": 1700000600i64,
                    "subject": "Re: Project Thread",
                    "message_id": "<thread-2@example.test>",
                    "from": [],
                    "reply_to": [],
                    "to": [],
                    "cc": [],
                    "bcc": []
                }),
                bodystructure_json: json!({"type": "text"}),
                internal_date: None,
                sent_date: None,
                size_octets: 64,
                text_preview: Some("two"),
            })
            .await?;
        let message_three = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: "rfc822/thread-3",
                rfc822_sha256: "sha256-thread-3",
                message_id_header: Some("<thread-3@example.test>"),
                subject: Some("Standalone Topic"),
                from_json: json!([]),
                to_json: json!([]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({
                    "date": 1700001200i64,
                    "subject": "Standalone Topic",
                    "message_id": "<thread-3@example.test>",
                    "from": [],
                    "reply_to": [],
                    "to": [],
                    "cc": [],
                    "bcc": []
                }),
                bodystructure_json: json!({"type": "text"}),
                internal_date: None,
                sent_date: None,
                size_octets: 64,
                text_preview: Some("three"),
            })
            .await?;

        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message_one.id,
            local_uid: 10,
            upstream_uid: Some(110),
            modseq: Some(1),
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;
        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message_two.id,
            local_uid: 11,
            upstream_uid: Some(111),
            modseq: Some(1),
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;
        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message_three.id,
            local_uid: 20,
            upstream_uid: Some(120),
            modseq: Some(1),
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;
        repo.refresh_mailbox_counts(mailbox.id).await?;

        let services = Arc::new(AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: Some(Arc::clone(&repo)),
            object_store: store,
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events,
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        });
        let mut session = ImapSession::new();
        session.authenticated = Some(AuthContext {
            user_id: user.id,
            account_id: Some(account.id),
            username: username.clone(),
        });
        let select = session.handle(&services, "A1 SELECT INBOX\r\n").await?;
        assert!(select.iter().any(|line| line.starts_with("A1 OK")));

        let thread = session
            .handle(&services, "A2 THREAD ORDEREDSUBJECT UTF-8 ALL\r\n")
            .await?;
        assert!(thread.iter().any(|line| line == "* THREAD (1 2) 3"), "{thread:?}");
        assert!(thread.iter().any(|line| line == "A2 OK THREAD completed"));

        let uid_thread = session
            .handle(&services, "A3 UID THREAD ORDEREDSUBJECT UTF-8 ALL\r\n")
            .await?;
        assert!(
            uid_thread.iter().any(|line| line == "* THREAD (10 11) 20"),
            "{uid_thread:?}"
        );
        assert!(uid_thread.iter().any(|line| line == "A3 OK UID THREAD completed"));
        Ok(())
    }

    #[tokio::test]
    async fn threads_references_use_message_ancestry() -> Result<()> {
        let pool = connect_pool().await?;
        let events = Arc::new(MailboxEventHub::new(16));
        let repo = Arc::new(
            PostgresRepository::new(
                pool,
                security::SecretBox::from_passphrase("test-master-key"),
            )
            .with_event_sink(Arc::new(HubMutationEventSink::new(Arc::clone(&events)))),
        );
        let store = Arc::new(MemoryObjectStore::new());

        let username = format!("threading-refs-{}@example.test", uuid::Uuid::new_v4());
        let user = repo
            .create_user(NewUser {
                username_email: &username,
                password_hash: &security::hash_password("secret-password")?,
            })
            .await?;
        let account = repo
            .create_mail_account(NewMailAccount {
                user_id: user.id,
                display_name: "Threading References Test",
                email_address: &username,
                upstream_host: "imap.example.test",
                upstream_port: 993,
                upstream_tls_mode: UpstreamTlsMode::Tls,
                upstream_auth_method: UpstreamAuthMethod::Login,
                upstream_username: "upstream-user",
                upstream_secret: "upstream-secret",
            })
            .await?;
        let mailbox = repo
            .upsert_mailbox(NewMailbox {
                account_id: account.id,
                name: "INBOX",
                canonical_name: "inbox",
                delimiter: Some("/"),
                attributes: vec!["\\HasNoChildren".to_string()],
                subscribed: true,
                special_use: Some("\\Inbox"),
                uidvalidity: Some(42),
                uidnext: Some(25),
                highestmodseq: Some(9),
                exists_count: 0,
                recent_count: 0,
                unseen_count: 0,
            })
            .await?;

        let raw_one = concat!(
            "From: Alice <alice@example.test>\r\n",
            "To: Bob <bob@example.test>\r\n",
            "Subject: Project Alpha\r\n",
            "Message-ID: <thread-ref-1@example.test>\r\n",
            "\r\n",
            "one\r\n",
        );
        let raw_two = concat!(
            "From: Bob <bob@example.test>\r\n",
            "To: Alice <alice@example.test>\r\n",
            "Subject: Different Subject\r\n",
            "Message-ID: <thread-ref-2@example.test>\r\n",
            "In-Reply-To: <thread-ref-1@example.test>\r\n",
            "References: <thread-ref-1@example.test>\r\n",
            "\r\n",
            "two\r\n",
        );
        let raw_three = concat!(
            "From: Carol <carol@example.test>\r\n",
            "To: Alice <alice@example.test>\r\n",
            "Subject: Standalone Topic\r\n",
            "Message-ID: <thread-ref-3@example.test>\r\n",
            "\r\n",
            "three\r\n",
        );

        let key_one = content_addressed_key(ObjectType::Rfc822, raw_one.as_bytes());
        let key_two = content_addressed_key(ObjectType::Rfc822, raw_two.as_bytes());
        let key_three = content_addressed_key(ObjectType::Rfc822, raw_three.as_bytes());
        store.put(&key_one, raw_one.as_bytes()).await?;
        store.put(&key_two, raw_two.as_bytes()).await?;
        store.put(&key_three, raw_three.as_bytes()).await?;

        let message_one = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: &key_one,
                rfc822_sha256: "sha256-thread-ref-1",
                message_id_header: Some("<thread-ref-1@example.test>"),
                subject: Some("Project Alpha"),
                from_json: json!([]),
                to_json: json!([]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({"subject": "Project Alpha"}),
                bodystructure_json: json!({"type": "text"}),
                internal_date: None,
                sent_date: None,
                size_octets: 64,
                text_preview: Some("one"),
            })
            .await?;
        let message_two = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: &key_two,
                rfc822_sha256: "sha256-thread-ref-2",
                message_id_header: Some("<thread-ref-2@example.test>"),
                subject: Some("Different Subject"),
                from_json: json!([]),
                to_json: json!([]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({"subject": "Different Subject"}),
                bodystructure_json: json!({"type": "text"}),
                internal_date: None,
                sent_date: None,
                size_octets: 64,
                text_preview: Some("two"),
            })
            .await?;
        let message_three = repo
            .upsert_message(NewMessage {
                account_id: account.id,
                rfc822_blob_key: &key_three,
                rfc822_sha256: "sha256-thread-ref-3",
                message_id_header: Some("<thread-ref-3@example.test>"),
                subject: Some("Standalone Topic"),
                from_json: json!([]),
                to_json: json!([]),
                cc_json: json!([]),
                bcc_json: json!([]),
                reply_to_json: json!([]),
                envelope_json: json!({"subject": "Standalone Topic"}),
                bodystructure_json: json!({"type": "text"}),
                internal_date: None,
                sent_date: None,
                size_octets: 64,
                text_preview: Some("three"),
            })
            .await?;

        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message_one.id,
            local_uid: 10,
            upstream_uid: Some(110),
            modseq: Some(1),
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;
        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message_two.id,
            local_uid: 11,
            upstream_uid: Some(111),
            modseq: Some(1),
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;
        repo.upsert_mailbox_message(NewMailboxMessage {
            mailbox_id: mailbox.id,
            message_id: message_three.id,
            local_uid: 20,
            upstream_uid: Some(120),
            modseq: Some(1),
            flags: vec![],
            keywords: vec![],
            is_expunged: false,
            expunged_at: None,
        })
        .await?;
        repo.refresh_mailbox_counts(mailbox.id).await?;

        let services = Arc::new(AppServices {
            authenticator: Arc::new(DenyAllAuthenticator),
            repository: Some(Arc::clone(&repo)),
            object_store: store,
            search: None,
            sync_engine: None,
            mutation_engine: None,
            events,
            metrics: Arc::new(crate::metrics::AppMetrics::new()),
        });
        let mut session = ImapSession::new();
        session.authenticated = Some(AuthContext {
            user_id: user.id,
            account_id: Some(account.id),
            username: username.clone(),
        });
        let select = session.handle(&services, "A1 SELECT INBOX\r\n").await?;
        assert!(select.iter().any(|line| line.starts_with("A1 OK")));
        assert!(session.capabilities().contains(&"THREAD=REFERENCES"));
        assert!(session.capabilities().contains(&"THREAD=ORDEREDSUBJECT"));

        let thread = session
            .handle(&services, "A2 THREAD REFERENCES UTF-8 ALL\r\n")
            .await?;
        assert!(thread.iter().any(|line| line == "* THREAD (1 2) 3"), "{thread:?}");
        assert!(thread.iter().any(|line| line == "A2 OK THREAD completed"));

        let uid_thread = session
            .handle(&services, "A3 UID THREAD REFERENCES UTF-8 ALL\r\n")
            .await?;
        assert!(
            uid_thread.iter().any(|line| line == "* THREAD (10 11) 20"),
            "{uid_thread:?}"
        );
        assert!(uid_thread.iter().any(|line| line == "A3 OK UID THREAD completed"));
        Ok(())
    }
}
