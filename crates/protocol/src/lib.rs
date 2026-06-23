use imap_cache_core::{
    domain::Mailbox,
    error::{Error, Result},
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    NotAuthenticated,
    Authenticated,
    SelectedMailbox { read_only: bool, mailbox: String },
    Logout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    pub tag: String,
    pub name: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMode {
    Replace,
    Add,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchBodySection {
    Full,
    Header,
    Text,
    Mime,
    HeaderFields { names: Vec<String>, not: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawFetchSection {
    Whole(FetchBodySection),
    Part {
        path: String,
        section: FetchBodySection,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFetchRequest {
    pub label: String,
    pub section: RawFetchSection,
    pub partial: Option<(usize, Option<usize>)>,
    pub peek: bool,
}

pub fn ok(tag: &str, text: &str) -> String {
    format!("{tag} OK {text}")
}

pub fn bad(tag: &str, text: &str) -> String {
    format!("{tag} BAD {text}")
}

pub fn no(tag: &str, code: &str, text: &str) -> String {
    format!("{tag} NO [{code}] {text}")
}

pub fn parse_command(line: &str) -> Result<Option<ParsedCommand>> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return Ok(None);
    }

    let mut tokens = tokenize(line)?;
    if tokens.len() < 2 {
        return Err(Error::Parse(format!("expected tag and command: {line}")));
    }
    let tag = tokens.remove(0);
    let name = tokens.remove(0);
    Ok(Some(ParsedCommand {
        tag,
        name,
        args: tokens,
    }))
}

pub fn parse_flag_list(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    let trimmed = trimmed.strip_prefix('(').unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix(')').unwrap_or(trimmed);
    trimmed
        .split_whitespace()
        .map(|flag| flag.trim().to_string())
        .filter(|flag| !flag.is_empty())
        .collect()
}

pub fn parse_literal_marker(value: &str) -> Option<(usize, bool)> {
    let trimmed = value.trim();
    if !(trimmed.starts_with('{') && trimmed.ends_with('}')) {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let non_sync = inner.ends_with('+');
    let length_text = if non_sync {
        &inner[..inner.len().saturating_sub(1)]
    } else {
        inner
    };
    let length = length_text.parse::<usize>().ok()?;
    Some((length, non_sync))
}

pub fn parse_number_set(value: &str, max_value: i64) -> Vec<i64> {
    let mut out = Vec::new();
    for part in value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let expand = |token: &str| -> Option<i64> {
            if token == "*" {
                Some(max_value)
            } else {
                token.parse::<i64>().ok()
            }
        };
        if let Some((start, end)) = part.split_once(':') {
            let Some(start) = expand(start.trim()) else {
                continue;
            };
            let Some(end) = expand(end.trim()) else {
                continue;
            };
            let (lo, hi) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };
            out.extend(lo..=hi);
        } else if let Some(value) = expand(part) {
            out.push(value);
        }
    }
    out.sort_unstable();
    out.dedup();
    out.retain(|value| *value > 0);
    out
}

pub fn parse_store_request(args: &[String]) -> Result<(String, StoreMode, bool, Vec<String>)> {
    let Some(sequence_set) = args.first().cloned() else {
        return Err(Error::Parse("STORE requires a message set".to_string()));
    };
    if args.len() == 1 {
        return Err(Error::Parse("STORE requires a flag list".to_string()));
    }

    let mut index = 1;
    let mut store_mode = StoreMode::Replace;
    let mut silent = false;

    if let Some((mode, is_silent)) = parse_store_item(&args[index]) {
        store_mode = mode;
        silent = is_silent;
        index += 1;
    }

    let Some(flags_value) = args.get(index) else {
        return Err(Error::Parse("STORE requires a flag list".to_string()));
    };
    Ok((sequence_set, store_mode, silent, parse_flag_list(flags_value)))
}

pub fn parse_status_items(args: &[String]) -> Result<Vec<String>> {
    let Some(items_value) = args.first() else {
        return Err(Error::Parse(
            "STATUS requires a status item list".to_string(),
        ));
    };
    let trimmed = items_value.trim();
    let trimmed = trimmed.strip_prefix('(').unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix(')').unwrap_or(trimmed);
    let mut items = Vec::new();
    for item in trimmed.split_whitespace() {
        let upper = item.trim().to_ascii_uppercase();
        match upper.as_str() {
            "MESSAGES" | "RECENT" | "UIDNEXT" | "UIDVALIDITY" | "UNSEEN" | "HIGHESTMODSEQ" => {
                if !items.iter().any(|existing| existing == &upper) {
                    items.push(upper);
                }
            }
            other => {
                return Err(Error::Parse(format!(
                    "STATUS does not support item {other}"
                )));
            }
        }
    }
    if items.is_empty() {
        return Err(Error::Parse(
            "STATUS requires at least one item".to_string(),
        ));
    }
    Ok(items)
}

pub fn format_status_response(mailbox: &Mailbox, requested_items: &[String]) -> String {
    let mut items = Vec::new();
    for item in requested_items {
        match item.as_str() {
            "MESSAGES" => items.push(format!("MESSAGES {}", mailbox.exists_count)),
            "RECENT" => items.push(format!("RECENT {}", mailbox.recent_count)),
            "UNSEEN" => items.push(format!("UNSEEN {}", mailbox.unseen_count)),
            "UIDNEXT" => items.push(format!("UIDNEXT {}", mailbox.uidnext.unwrap_or(1))),
            "UIDVALIDITY" => {
                items.push(format!("UIDVALIDITY {}", mailbox.uidvalidity.unwrap_or(1)))
            }
            "HIGHESTMODSEQ" => {
                items.push(format!("HIGHESTMODSEQ {}", mailbox.highestmodseq.unwrap_or(0)))
            }
            _ => {}
        }
    }
    format!("* STATUS {} ({})", quote_imap_string(&mailbox.name), items.join(" "))
}

pub fn format_status_response_with_defaults(mailbox_name: &str, requested_items: &[String]) -> String {
    let mailbox = Mailbox {
        id: 0,
        account_id: 0,
        name: mailbox_name.to_string(),
        canonical_name: mailbox_name.to_ascii_lowercase(),
        delimiter: Some("/".to_string()),
        attributes: vec![],
        subscribed: false,
        special_use: None,
        uidvalidity: Some(1),
        uidnext: Some(1),
        highestmodseq: None,
        exists_count: 0,
        recent_count: 0,
        unseen_count: 0,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    format_status_response(&mailbox, requested_items)
}

pub fn format_number_set(values: &[u64]) -> String {
    if values.is_empty() {
        return String::new();
    }
    let mut values = values.to_vec();
    values.sort_unstable();
    values.dedup();
    let mut parts = Vec::new();
    let mut start = values[0];
    let mut end = values[0];
    for value in values.into_iter().skip(1) {
        if value == end + 1 {
            end = value;
            continue;
        }
        parts.push(format_range(start, end));
        start = value;
        end = value;
    }
    parts.push(format_range(start, end));
    parts.join(",")
}

pub fn parse_fetch_items(args: &[String]) -> Vec<String> {
    let joined = args.join(" ");
    let trimmed = joined.trim();
    let trimmed = trimmed.strip_prefix('(').unwrap_or(trimmed);
    let trimmed = trimmed.strip_suffix(')').unwrap_or(trimmed);

    let mut items = Vec::new();
    let mut current = String::new();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut in_quotes = false;

    for ch in trimmed.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            '(' if !in_quotes => {
                paren_depth += 1;
                current.push(ch);
            }
            ')' if !in_quotes => {
                paren_depth = paren_depth.saturating_sub(1);
                current.push(ch);
            }
            '[' if !in_quotes => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' if !in_quotes => {
                bracket_depth = bracket_depth.saturating_sub(1);
                current.push(ch);
            }
            ch if ch.is_whitespace() && !in_quotes && paren_depth == 0 && bracket_depth == 0 => {
                if !current.trim().is_empty() {
                    items.push(current.trim().to_ascii_uppercase());
                    current.clear();
                }
            }
            other => current.push(other),
        }
    }

    if !current.trim().is_empty() {
        items.push(current.trim().to_ascii_uppercase());
    }

    if items.is_empty() {
        vec![
            "FLAGS".to_string(),
            "UID".to_string(),
            "RFC822.SIZE".to_string(),
            "ENVELOPE".to_string(),
            "BODYSTRUCTURE".to_string(),
        ]
    } else {
        items
    }
}

pub fn parse_raw_fetch_request(item: &str) -> Option<RawFetchRequest> {
    let label = item.to_string();
    let peek = item.starts_with("BODY.PEEK[") || item == "BODY.PEEK[]";
    let normalized = if peek {
        item.replacen("BODY.PEEK[", "BODY[", 1)
    } else {
        item.to_string()
    };
    let item = normalized.as_str();
    let (item, partial) = if let Some(start) = item.rfind('<') {
        if item.ends_with('>') {
            let marker = &item[start + 1..item.len() - 1];
            let mut parts = marker.split('.');
            let offset = parts.next()?.parse::<usize>().ok()?;
            let count = parts.next().and_then(|value| value.parse::<usize>().ok());
            (&item[..start], Some((offset, count)))
        } else {
            (item, None)
        }
    } else {
        (item, None)
    };

    if item == "RFC822" {
        return Some(RawFetchRequest {
            label,
            section: RawFetchSection::Whole(FetchBodySection::Full),
            partial,
            peek: false,
        });
    }
    if item == "RFC822.HEADER" {
        return Some(RawFetchRequest {
            label,
            section: RawFetchSection::Whole(FetchBodySection::Header),
            partial,
            peek: false,
        });
    }
    if item == "RFC822.TEXT" {
        return Some(RawFetchRequest {
            label,
            section: RawFetchSection::Whole(FetchBodySection::Text),
            partial,
            peek: false,
        });
    }
    if item == "BODY[]" || item == "BODY.PEEK[]" {
        return Some(RawFetchRequest {
            label,
            section: RawFetchSection::Whole(FetchBodySection::Full),
            partial,
            peek,
        });
    }
    if item == "BODY[HEADER]" {
        return Some(RawFetchRequest {
            label,
            section: RawFetchSection::Whole(FetchBodySection::Header),
            partial,
            peek,
        });
    }
    if item == "BODY[TEXT]" {
        return Some(RawFetchRequest {
            label,
            section: RawFetchSection::Whole(FetchBodySection::Text),
            partial,
            peek,
        });
    }
    if item == "BODY[MIME]" {
        return Some(RawFetchRequest {
            label,
            section: RawFetchSection::Whole(FetchBodySection::Mime),
            partial,
            peek,
        });
    }
    if let Some(inner) = item
        .strip_prefix("BODY[HEADER.FIELDS (")
        .and_then(|value| value.strip_suffix(")]"))
    {
        let names = inner
            .split_whitespace()
            .map(|name| name.trim().to_string())
            .collect::<Vec<_>>();
        return Some(RawFetchRequest {
            label,
            section: RawFetchSection::Whole(FetchBodySection::HeaderFields {
                names,
                not: false,
            }),
            partial,
            peek,
        });
    }
    if let Some(inner) = item
        .strip_prefix("BODY[HEADER.FIELDS.NOT (")
        .and_then(|value| value.strip_suffix(")]"))
    {
        let names = inner
            .split_whitespace()
            .map(|name| name.trim().to_string())
            .collect::<Vec<_>>();
        return Some(RawFetchRequest {
            label,
            section: RawFetchSection::Whole(FetchBodySection::HeaderFields {
                names,
                not: true,
            }),
            partial,
            peek,
        });
    }
    if let Some((path, section)) = parse_body_part_fetch_request(item) {
        return Some(RawFetchRequest {
            label,
            section: RawFetchSection::Part { path, section },
            partial,
            peek,
        });
    }
    None
}

fn parse_store_item(item: &str) -> Option<(StoreMode, bool)> {
    let upper = item.trim().to_ascii_uppercase();
    let silent = upper.ends_with(".SILENT");
    let base = upper.strip_suffix(".SILENT").unwrap_or(&upper);
    let mode = match base {
        "FLAGS" => StoreMode::Replace,
        "+FLAGS" => StoreMode::Add,
        "-FLAGS" => StoreMode::Remove,
        _ => return None,
    };
    Some((mode, silent))
}

fn parse_body_part_fetch_request(item: &str) -> Option<(String, FetchBodySection)> {
    let inner = item.strip_prefix("BODY[")?.strip_suffix(']')?;
    if inner.is_empty() {
        return Some(("1".to_string(), FetchBodySection::Full));
    }

    let section_markers = [
        (".HEADER.FIELDS.NOT (", true, true),
        (".HEADER.FIELDS (", true, false),
        (".HEADER", false, false),
        (".TEXT", false, false),
        (".MIME", false, false),
    ];

    for (marker, is_header_fields, is_not) in section_markers {
        if let Some(index) = inner.find(marker) {
            let path = inner[..index].to_string();
            let suffix = &inner[index + 1..];
            if is_header_fields {
                let names = suffix
                    .strip_prefix("HEADER.FIELDS.NOT (")
                    .or_else(|| suffix.strip_prefix("HEADER.FIELDS ("))?
                    .strip_suffix(')')?
                    .split_whitespace()
                    .map(|name| name.trim().to_string())
                    .collect::<Vec<_>>();
                return Some((
                    path,
                    FetchBodySection::HeaderFields {
                        names,
                        not: is_not,
                    },
                ));
            }
            let section = match suffix {
                "HEADER" => FetchBodySection::Header,
                "TEXT" => FetchBodySection::Text,
                "MIME" => FetchBodySection::Mime,
                _ => continue,
            };
            return Some((path, section));
        }
    }

    if inner.chars().all(|ch| ch.is_ascii_digit() || ch == '.') {
        return Some((inner.to_string(), FetchBodySection::Full));
    }

    None
}

fn tokenize(input: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.peek().copied() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }

        if ch == '"' {
            chars.next();
            let mut token = String::new();
            while let Some(next) = chars.next() {
                match next {
                    '"' => break,
                    '\\' => {
                        if let Some(escaped) = chars.next() {
                            token.push(escaped);
                        }
                    }
                    other => token.push(other),
                }
            }
            out.push(token);
            continue;
        }

        let mut token = String::new();
        let mut paren_depth = 0usize;
        let mut bracket_depth = 0usize;
        while let Some(next) = chars.peek().copied() {
            let should_break = next.is_whitespace() && paren_depth == 0 && bracket_depth == 0;
            if should_break {
                break;
            }
            let next = chars.next().expect("peeked value must exist");
            match next {
                '(' => paren_depth += 1,
                ')' => paren_depth = paren_depth.saturating_sub(1),
                '[' => bracket_depth += 1,
                ']' => bracket_depth = bracket_depth.saturating_sub(1),
                _ => {}
            }
            token.push(next);
        }
        if token.is_empty() {
            return Err(Error::Parse(format!("failed to tokenize IMAP command: {input}")));
        }
        out.push(token);
    }

    Ok(out)
}

fn quote_imap_string(value: &str) -> String {
    let escaped = value.replace('\\', r"\\").replace('"', r#"\""#);
    format!("\"{escaped}\"")
}

fn format_range(start: u64, end: u64) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}:{end}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imap_cache_core::domain::Mailbox;

    fn mailbox(highestmodseq: Option<i64>) -> Mailbox {
        let now = chrono::Utc::now();
        Mailbox {
            id: 1,
            account_id: 1,
            name: "INBOX".to_string(),
            canonical_name: "inbox".to_string(),
            delimiter: Some("/".to_string()),
            attributes: vec![],
            subscribed: true,
            special_use: Some("\\Inbox".to_string()),
            uidvalidity: Some(1),
            uidnext: Some(2),
            highestmodseq,
            exists_count: 4,
            recent_count: 1,
            unseen_count: 2,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn parse_status_items_accepts_highestmodseq() {
        let items = parse_status_items(&["(MESSAGES HIGHESTMODSEQ UIDNEXT)".to_string()]).unwrap();
        assert_eq!(items, vec!["MESSAGES", "HIGHESTMODSEQ", "UIDNEXT"]);
    }

    #[test]
    fn format_status_response_includes_highestmodseq() {
        let response = format_status_response(
            &mailbox(Some(17)),
            &["MESSAGES".to_string(), "HIGHESTMODSEQ".to_string()],
        );
        assert_eq!(response, r#"* STATUS "INBOX" (MESSAGES 4 HIGHESTMODSEQ 17)"#);
    }

    #[test]
    fn format_status_response_defaults_missing_highestmodseq_to_zero() {
        let response = format_status_response(&mailbox(None), &["HIGHESTMODSEQ".to_string()]);
        assert_eq!(response, r#"* STATUS "INBOX" (HIGHESTMODSEQ 0)"#);
    }
}
