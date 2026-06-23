use imap_cache_core::error::{Error, Result};
use imap_cache_mime::ParsedMessage;
use async_trait::async_trait;
use chrono::NaiveDate;
use serde_json::Value;
use sha2::Digest;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tantivy::{
    Index, ReloadPolicy, Term,
    collector::TopDocs,
    directory::MmapDirectory,
    doc,
    query::{AllQuery, QueryParser},
    schema::{FAST, Field, STORED, Schema, TEXT, TantivyDocument, Value as TantivyValue},
};

#[derive(Debug, Clone)]
pub struct SearchDocument {
    pub uid: u64,
    pub subject: Option<String>,
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub message_id: Option<String>,
    pub reply_to: Vec<String>,
    pub body: String,
}

impl SearchDocument {
    pub fn from_parsed_message(uid: u64, parsed: &ParsedMessage) -> Self {
        Self {
            uid,
            subject: parsed.subject.clone(),
            from: addresses_from_value(&parsed.from_json),
            to: addresses_from_value(&parsed.to_json),
            cc: addresses_from_value(&parsed.cc_json),
            bcc: addresses_from_value(&parsed.bcc_json),
            message_id: parsed.message_id_header.clone(),
            reply_to: addresses_from_value(&parsed.reply_to_json),
            body: parsed.text_preview.clone().unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub match_all: bool,
    pub expr: Option<Box<SearchExpr>>,
    pub query_string: Option<String>,
    pub uid_filter: Option<UidSet>,
    pub recent_only: bool,
    pub old_only: bool,
    pub header_filters: Vec<(String, String)>,
    pub required_flags: Vec<String>,
    pub forbidden_flags: Vec<String>,
    pub required_keywords: Vec<String>,
    pub forbidden_keywords: Vec<String>,
    pub larger_than: Option<u64>,
    pub smaller_than: Option<u64>,
    pub internal_date_before: Option<NaiveDate>,
    pub internal_date_on: Option<NaiveDate>,
    pub internal_date_since: Option<NaiveDate>,
    pub sent_date_before: Option<NaiveDate>,
    pub sent_date_on: Option<NaiveDate>,
    pub sent_date_since: Option<NaiveDate>,
}

#[derive(Debug, Clone)]
pub enum SearchExpr {
    Leaf(SearchQuery),
    And(Vec<SearchExpr>),
    Or(Box<SearchExpr>, Box<SearchExpr>),
    Not(Box<SearchExpr>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UidSet {
    ranges: Vec<(u64, u64)>,
}

impl UidSet {
    pub fn contains(&self, uid: u64) -> bool {
        self.ranges
            .iter()
            .any(|(start, end)| uid >= *start && uid <= *end)
    }

    pub fn push(&mut self, start: u64, end: u64) {
        self.ranges.push((start.min(end), start.max(end)));
    }
}

impl SearchQuery {
    pub fn all() -> Self {
        Self {
            match_all: true,
            expr: None,
            query_string: None,
            uid_filter: None,
            recent_only: false,
            old_only: false,
            header_filters: Vec::new(),
            required_flags: Vec::new(),
            forbidden_flags: Vec::new(),
            required_keywords: Vec::new(),
            forbidden_keywords: Vec::new(),
            larger_than: None,
            smaller_than: None,
            internal_date_before: None,
            internal_date_on: None,
            internal_date_since: None,
            sent_date_before: None,
            sent_date_on: None,
            sent_date_since: None,
        }
    }

    pub fn from_imap_args(args: &[String]) -> Result<Self> {
        if args.is_empty() {
            return Ok(Self::all());
        }

        let mut parser = ImapSearchParser::new(args);
        parser.parse()
    }
}

#[async_trait]
pub trait SearchBackend: Send + Sync {
    async fn index_message(&self, mailbox: &str, document: SearchDocument) -> Result<()>;
    async fn search(&self, mailbox: &str, query: SearchQuery) -> Result<Vec<u64>>;
}

#[derive(Clone, Default)]
pub struct TantivySearchEngine {
    mailbox_root: Option<PathBuf>,
    mailboxes: Arc<Mutex<HashMap<String, MailboxIndex>>>,
}

impl TantivySearchEngine {
    pub fn memory() -> Result<Self> {
        Ok(Self::default())
    }

    pub fn persistent(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| {
            Error::Storage(format!(
                "failed to create search index directory {}: {e}",
                root.display()
            ))
        })?;
        Ok(Self {
            mailbox_root: Some(root),
            mailboxes: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn mailbox_index(&self, mailbox: &str) -> Result<MailboxIndexGuard<'_>> {
        let mailbox_root = self.mailbox_root.clone();
        let mut mailboxes = self
            .mailboxes
            .lock()
            .map_err(|_| Error::Storage("search index mutex poisoned".to_string()))?;
        if !mailboxes.contains_key(mailbox) {
            let index = match mailbox_root {
                Some(root) => {
                    MailboxIndex::open_or_create(&root.join(mailbox_directory_name(mailbox)))?
                }
                None => MailboxIndex::new_in_memory()?,
            };
            mailboxes.insert(mailbox.to_string(), index);
        }
        Ok(MailboxIndexGuard {
            mailbox: mailbox.to_string(),
            mailboxes,
        })
    }
}

struct MailboxIndexGuard<'a> {
    mailbox: String,
    mailboxes: std::sync::MutexGuard<'a, HashMap<String, MailboxIndex>>,
}

impl<'a> std::ops::Deref for MailboxIndexGuard<'a> {
    type Target = MailboxIndex;

    fn deref(&self) -> &Self::Target {
        self.mailboxes
            .get(&self.mailbox)
            .expect("mailbox index missing")
    }
}

impl<'a> std::ops::DerefMut for MailboxIndexGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.mailboxes
            .get_mut(&self.mailbox)
            .expect("mailbox index missing")
    }
}

struct MailboxIndex {
    index: Index,
    writer: tantivy::IndexWriter,
    reader: tantivy::IndexReader,
    uid_field: Field,
    subject_field: Field,
    from_field: Field,
    to_field: Field,
    cc_field: Field,
    bcc_field: Field,
    message_id_field: Field,
    reply_to_field: Field,
    body_field: Field,
    searchable_fields: Vec<Field>,
}

impl MailboxIndex {
    fn schema() -> (Schema, Field, Field, Field, Field, Field, Field, Field, Field, Field) {
        let mut builder = Schema::builder();
        let uid_field = builder.add_u64_field("uid", STORED | FAST);
        let subject_field = builder.add_text_field("subject", TEXT | STORED);
        let from_field = builder.add_text_field("from", TEXT | STORED);
        let to_field = builder.add_text_field("to", TEXT | STORED);
        let cc_field = builder.add_text_field("cc", TEXT | STORED);
        let bcc_field = builder.add_text_field("bcc", TEXT | STORED);
        let message_id_field = builder.add_text_field("message_id", TEXT | STORED);
        let reply_to_field = builder.add_text_field("reply_to", TEXT | STORED);
        let body_field = builder.add_text_field("body", TEXT | STORED);
        (
            builder.build(),
            uid_field,
            subject_field,
            from_field,
            to_field,
            cc_field,
            bcc_field,
            message_id_field,
            reply_to_field,
            body_field,
        )
    }

    fn new_in_memory() -> Result<Self> {
        let (
            schema,
            uid_field,
            subject_field,
            from_field,
            to_field,
            cc_field,
            bcc_field,
            message_id_field,
            reply_to_field,
            body_field,
        ) = Self::schema();
        let index = Index::create_in_ram(schema);
        Self::from_index(
            index,
            uid_field,
            subject_field,
            from_field,
            to_field,
            cc_field,
            bcc_field,
            message_id_field,
            reply_to_field,
            body_field,
        )
    }

    fn open_or_create(path: &Path) -> Result<Self> {
        fs::create_dir_all(path).map_err(|e| {
            Error::Storage(format!(
                "failed to create search mailbox directory {}: {e}",
                path.display()
            ))
        })?;
        let (
            schema,
            uid_field,
            subject_field,
            from_field,
            to_field,
            cc_field,
            bcc_field,
            message_id_field,
            reply_to_field,
            body_field,
        ) = Self::schema();
        let directory = MmapDirectory::open(path).map_err(|e| {
            Error::Storage(format!(
                "failed to open search directory {}: {e}",
                path.display()
            ))
        })?;
        let index = Index::open_or_create(directory, schema).map_err(|e| {
            Error::Storage(format!(
                "failed to open search index at {}: {e}",
                path.display()
            ))
        })?;
        Self::from_index(
            index,
            uid_field,
            subject_field,
            from_field,
            to_field,
            cc_field,
            bcc_field,
            message_id_field,
            reply_to_field,
            body_field,
        )
    }

    fn from_index(
        index: Index,
        uid_field: Field,
        subject_field: Field,
        from_field: Field,
        to_field: Field,
        cc_field: Field,
        bcc_field: Field,
        message_id_field: Field,
        reply_to_field: Field,
        body_field: Field,
    ) -> Result<Self> {
        let writer = index
            .writer(50_000_000)
            .map_err(|e| Error::Storage(format!("failed to create search writer: {e}")))?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()
            .map_err(|e| Error::Storage(format!("failed to create search reader: {e}")))?;
        Ok(Self {
            index,
            writer,
            reader,
            uid_field,
            subject_field,
            from_field,
            to_field,
            cc_field,
            bcc_field,
            message_id_field,
            reply_to_field,
            body_field,
            searchable_fields: vec![
                subject_field,
                from_field,
                to_field,
                cc_field,
                bcc_field,
                message_id_field,
                reply_to_field,
                body_field,
            ],
        })
    }

    fn index_message(&mut self, document: SearchDocument) -> Result<()> {
        self.writer
            .delete_term(Term::from_field_u64(self.uid_field, document.uid));
        let doc = doc!(
            self.uid_field => document.uid,
            self.subject_field => document.subject.unwrap_or_default(),
            self.from_field => document.from.join(" "),
            self.to_field => document.to.join(" "),
            self.cc_field => document.cc.join(" "),
            self.bcc_field => document.bcc.join(" "),
            self.message_id_field => document.message_id.unwrap_or_default(),
            self.reply_to_field => document.reply_to.join(" "),
            self.body_field => document.body,
        );
        self.writer
            .add_document(doc)
            .map_err(|e| Error::Storage(format!("failed to add search document: {e}")))?;
        self.writer
            .commit()
            .map_err(|e| Error::Storage(format!("failed to commit search index: {e}")))?;
        self.reader
            .reload()
            .map_err(|e| Error::Storage(format!("failed to reload search index: {e}")))?;
        Ok(())
    }

    fn search(&self, query: SearchQuery) -> Result<Vec<u64>> {
        let searcher = self.reader.searcher();
        let mut uids = if let Some(expr) = query.expr.as_deref() {
            let mut base_query = query.clone();
            base_query.expr = None;
            let base = self.search_flat(&searcher, &base_query)?;
            let expr_uids = self.search_expr_uids(&searcher, expr)?;
            let base = base.into_iter().collect::<std::collections::BTreeSet<_>>();
            expr_uids
                .into_iter()
                .filter(|uid| base.contains(uid))
                .collect::<Vec<_>>()
        } else {
            self.search_flat(&searcher, &query)?
        };
        uids.sort_unstable();
        uids.dedup();
        Ok(uids)
    }
}

impl MailboxIndex {
    fn search_flat(
        &self,
        searcher: &tantivy::Searcher,
        query: &SearchQuery,
    ) -> Result<Vec<u64>> {
        let tantivy_query: Box<dyn tantivy::query::Query> = if query.match_all
            || query
                .query_string
                .as_ref()
                .is_none_or(|value| value.is_empty())
        {
            Box::new(AllQuery)
        } else if let Some(query_string) = query.query_string.as_deref() {
            let parser = QueryParser::for_index(&self.index, self.searchable_fields.clone());
            let trimmed = query_string.trim();
            if let Some(inner) = trimmed
                .strip_prefix("NOT ")
                .or_else(|| trimmed.strip_prefix("NOT("))
            {
                let inner = strip_outer_parens(inner.trim());
                let excluded = collect_query_uids(
                    searcher,
                    parser
                        .parse_query(inner)
                        .map_err(|e| Error::Parse(format!("failed to parse search query: {e}")))?,
                    query.uid_filter.as_ref(),
                    self.uid_field,
                )?;
                let all = collect_query_uids(
                    searcher,
                    Box::new(AllQuery),
                    query.uid_filter.as_ref(),
                    self.uid_field,
                )?;
                let excluded = excluded
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>();
                return Ok(all
                    .into_iter()
                    .filter(|uid| !excluded.contains(uid))
                    .collect());
            }
            let query_string = normalize_boolean_query(query_string);
            Box::new(
                parser
                    .parse_query(&query_string)
                    .map_err(|e| Error::Parse(format!("failed to parse search query: {e}")))?,
            )
        } else {
            Box::new(AllQuery)
        };

        let top_docs = searcher
            .search(&*tantivy_query, &TopDocs::with_limit(1000))
            .map_err(|e| Error::Storage(format!("search failed: {e}")))?;

        let mut uids = Vec::new();
        for (_, doc_address) in top_docs {
            let doc: TantivyDocument = searcher
                .doc(doc_address)
                .map_err(|e| Error::Storage(format!("failed to read search result: {e}")))?;
            if let Some(uid) = doc
                .get_first(self.uid_field)
                .and_then(|value| TantivyValue::as_u64(&value))
            {
                if query
                    .uid_filter
                    .as_ref()
                    .map(|set| set.contains(uid))
                    .unwrap_or(true)
                {
                    uids.push(uid);
                }
            }
        }
        uids.sort_unstable();
        Ok(uids)
    }

    fn search_expr_uids(
        &self,
        searcher: &tantivy::Searcher,
        expr: &SearchExpr,
    ) -> Result<Vec<u64>> {
        match expr {
            SearchExpr::Leaf(query) => self.search_flat(searcher, query),
            SearchExpr::And(children) => {
                let mut iter = children.iter();
                let Some(first) = iter.next() else {
                    return Ok(Vec::new());
                };
                let mut acc = self
                    .search_expr_uids(searcher, first)?
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>();
                for child in iter {
                    let child_uids = self
                        .search_expr_uids(searcher, child)?
                        .into_iter()
                        .collect::<std::collections::BTreeSet<_>>();
                    acc = acc
                        .into_iter()
                        .filter(|uid| child_uids.contains(uid))
                        .collect();
                }
                Ok(acc.into_iter().collect())
            }
            SearchExpr::Or(left, right) => {
                let mut acc = self.search_expr_uids(searcher, left)?;
                acc.extend(self.search_expr_uids(searcher, right)?);
                acc.sort_unstable();
                acc.dedup();
                Ok(acc)
            }
            SearchExpr::Not(inner) => {
                let all = self.search_flat(searcher, &SearchQuery::all())?;
                let excluded = self
                    .search_expr_uids(searcher, inner)?
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>();
                Ok(all.into_iter().filter(|uid| !excluded.contains(uid)).collect())
            }
        }
    }
}

#[async_trait]
impl SearchBackend for TantivySearchEngine {
    async fn index_message(&self, mailbox: &str, document: SearchDocument) -> Result<()> {
        let mut guard = self.mailbox_index(mailbox)?;
        guard.index_message(document)
    }

    async fn search(&self, mailbox: &str, query: SearchQuery) -> Result<Vec<u64>> {
        let guard = self.mailbox_index(mailbox)?;
        guard.search(query)
    }
}

fn normalize_boolean_query(query_string: &str) -> String {
    let trimmed = query_string.trim();
    trimmed.to_string()
}

fn strip_outer_parens(value: &str) -> &str {
    let mut trimmed = value.trim();
    while trimmed.starts_with('(') && trimmed.ends_with(')') && trimmed.len() > 1 {
        trimmed = trimmed[1..trimmed.len() - 1].trim();
    }
    trimmed
}

fn collect_query_uids(
    searcher: &tantivy::Searcher,
    tantivy_query: Box<dyn tantivy::query::Query>,
    uid_filter: Option<&UidSet>,
    uid_field: Field,
) -> Result<Vec<u64>> {
    let top_docs = searcher
        .search(&*tantivy_query, &TopDocs::with_limit(1000))
        .map_err(|e| Error::Storage(format!("search failed: {e}")))?;
    let mut uids = Vec::new();
    for (_, doc_address) in top_docs {
        let doc: TantivyDocument = searcher
            .doc(doc_address)
            .map_err(|e| Error::Storage(format!("failed to read search result: {e}")))?;
        if let Some(uid) = doc
            .get_first(uid_field)
            .and_then(|value| TantivyValue::as_u64(&value))
            && uid_filter.map(|set| set.contains(uid)).unwrap_or(true)
        {
            uids.push(uid);
        }
    }
    uids.sort_unstable();
    Ok(uids)
}

fn mailbox_directory_name(mailbox: &str) -> String {
    hex::encode(sha2::Sha256::digest(mailbox.as_bytes()))
}

fn addresses_from_value(value: &Value) -> Vec<String> {
    let mut addresses = Vec::new();
    collect_addresses(value, &mut addresses);
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

fn collect_addresses(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_addresses(item, out);
            }
        }
        Value::Object(map) => {
            if let Some(address) = map.get("address").and_then(Value::as_str) {
                out.push(address.to_string());
            }
            if let Some(members) = map.get("members") {
                collect_addresses(members, out);
            }
        }
        _ => {}
    }
}

struct ImapSearchParser<'a> {
    tokens: &'a [String],
    index: usize,
}

impl<'a> ImapSearchParser<'a> {
    fn new(tokens: &'a [String]) -> Self {
        Self { tokens, index: 0 }
    }

    fn parse(&mut self) -> Result<SearchQuery> {
        let mut flat = SearchQuery::all();
        flat.match_all = false;
        let mut expr_terms = Vec::new();
        let mut saw_term = false;
        while self.index < self.tokens.len() {
            saw_term = true;
            match self.parse_term()? {
                SearchExpr::Leaf(fragment) => {
                    let fragment = fragment;
                    if !is_identity_query(&fragment) {
                        merge_query_fields(&mut flat, &fragment);
                    }
                }
                other => expr_terms.push(other),
            }
        }

        if !saw_term {
            return Ok(SearchQuery::all());
        }

        if expr_terms.is_empty() {
            if is_identity_query(&flat) {
                return Ok(SearchQuery::all());
            }
            return Ok(flat);
        }

        let expr = match expr_terms.len() {
            0 => unreachable!(),
            1 => expr_terms.pop().unwrap(),
            _ => SearchExpr::And(expr_terms),
        };
        flat.expr = Some(Box::new(expr));
        flat.match_all = false;
        Ok(flat)
    }

    fn parse_term(&mut self) -> Result<SearchExpr> {
        let token = self
            .next_token()
            .ok_or_else(|| Error::Parse("unexpected end of SEARCH criteria".to_string()))?;
        if token.eq_ignore_ascii_case("NOT") {
            let inner = self.parse_term()?;
            return Ok(SearchExpr::Not(Box::new(inner)));
        }
        if token.eq_ignore_ascii_case("OR") {
            let left = self.parse_term()?;
            let right = self.parse_term()?;
            return Ok(SearchExpr::Or(Box::new(left), Box::new(right)));
        }
        if token.eq_ignore_ascii_case("UID") {
            let value = self
                .next_token()
                .ok_or_else(|| Error::Parse("UID requires a sequence set".to_string()))?;
            let mut query = SearchQuery::all();
            query.uid_filter = Some(parse_uid_set(&value)?);
            query.match_all = false;
            return Ok(SearchExpr::Leaf(query));
        }

        let mut query = SearchQuery::all();
        let (field_query, match_all) = match token.to_ascii_uppercase().as_str() {
            "ALL" => (None, true),
            "SUBJECT" => (
                Some(format!("subject:{}", quote_query(self.expect_term()?))),
                false,
            ),
            "FROM" => (
                Some(format!("from:{}", quote_query(self.expect_term()?))),
                false,
            ),
            "TO" => (
                Some(format!("to:{}", quote_query(self.expect_term()?))),
                false,
            ),
            "CC" => (
                Some(format!("cc:{}", quote_query(self.expect_term()?))),
                false,
            ),
            "BCC" => (
                Some(format!("bcc:{}", quote_query(self.expect_term()?))),
                false,
            ),
            "HEADER" => {
                let field = self.expect_term()?;
                let value = self.expect_term()?;
                let field_lower = field.to_ascii_lowercase();
                query.header_filters.push((field_lower.clone(), value.clone()));
                (
                    header_query_string(&field_lower, &value),
                    false,
                )
            }
            "RECENT" => {
                query.recent_only = true;
                (None, false)
            }
            "NEW" => {
                query.recent_only = true;
                query.forbidden_flags.push("\\Seen".to_string());
                (None, false)
            }
            "OLD" => {
                query.old_only = true;
                (None, false)
            }
            "BODY" | "TEXT" => {
                let term = quote_query(self.expect_term()?);
                (
                    Some(format!(
                        "body:{term} OR subject:{term} OR from:{term} OR to:{term} OR cc:{term} OR bcc:{term}"
                    )),
                    false,
                )
            }
            "SEEN" => {
                query.required_flags.push("\\Seen".to_string());
                (None, false)
            }
            "UNSEEN" => {
                query.forbidden_flags.push("\\Seen".to_string());
                (None, false)
            }
            "ANSWERED" => {
                query.required_flags.push("\\Answered".to_string());
                (None, false)
            }
            "UNANSWERED" => {
                query.forbidden_flags.push("\\Answered".to_string());
                (None, false)
            }
            "FLAGGED" => {
                query.required_flags.push("\\Flagged".to_string());
                (None, false)
            }
            "UNFLAGGED" => {
                query.forbidden_flags.push("\\Flagged".to_string());
                (None, false)
            }
            "DELETED" => {
                query.required_flags.push("\\Deleted".to_string());
                (None, false)
            }
            "UNDELETED" => {
                query.forbidden_flags.push("\\Deleted".to_string());
                (None, false)
            }
            "KEYWORD" => {
                query.required_keywords.push(self.expect_term()?);
                (None, false)
            }
            "UNKEYWORD" => {
                query.forbidden_keywords.push(self.expect_term()?);
                (None, false)
            }
            "LARGER" => {
                let value = self
                    .expect_term()?
                    .parse::<u64>()
                    .map_err(|_| Error::Parse("LARGER requires a numeric size".to_string()))?;
                query.larger_than = Some(value);
                (None, false)
            }
            "SMALLER" => {
                let value = self
                    .expect_term()?
                    .parse::<u64>()
                    .map_err(|_| Error::Parse("SMALLER requires a numeric size".to_string()))?;
                query.smaller_than = Some(value);
                (None, false)
            }
            "BEFORE" => {
                query.internal_date_before = Some(parse_imap_date(&self.expect_term()?)?);
                (None, false)
            }
            "SINCE" => {
                query.internal_date_since = Some(parse_imap_date(&self.expect_term()?)?);
                (None, false)
            }
            "ON" => {
                query.internal_date_on = Some(parse_imap_date(&self.expect_term()?)?);
                (None, false)
            }
            "SENTBEFORE" => {
                query.sent_date_before = Some(parse_imap_date(&self.expect_term()?)?);
                (None, false)
            }
            "SENTSINCE" => {
                query.sent_date_since = Some(parse_imap_date(&self.expect_term()?)?);
                (None, false)
            }
            "SENTON" => {
                query.sent_date_on = Some(parse_imap_date(&self.expect_term()?)?);
                (None, false)
            }
            other => (Some(other.to_string()), false),
        };

        query.match_all = match_all;
        query.query_string = field_query;
        Ok(SearchExpr::Leaf(query))
    }

    fn expect_term(&mut self) -> Result<String> {
        self.next_token()
            .ok_or_else(|| Error::Parse("missing SEARCH term".to_string()))
    }

    fn next_token(&mut self) -> Option<String> {
        let token = self.tokens.get(self.index).cloned();
        self.index += usize::from(token.is_some());
        token
    }
}

fn is_identity_query(query: &SearchQuery) -> bool {
    query.expr.is_none()
        && query.query_string.is_none()
        && query.uid_filter.is_none()
        && query.required_flags.is_empty()
        && query.forbidden_flags.is_empty()
        && query.required_keywords.is_empty()
        && query.forbidden_keywords.is_empty()
        && query.header_filters.is_empty()
        && !query.recent_only
        && !query.old_only
        && query.larger_than.is_none()
        && query.smaller_than.is_none()
        && query.internal_date_before.is_none()
        && query.internal_date_on.is_none()
        && query.internal_date_since.is_none()
        && query.sent_date_before.is_none()
        && query.sent_date_on.is_none()
        && query.sent_date_since.is_none()
}

fn merge_query_fields(acc: &mut SearchQuery, fragment: &SearchQuery) {
    acc.match_all = false;
    acc.required_flags
        .extend(fragment.required_flags.iter().cloned());
    acc.forbidden_flags
        .extend(fragment.forbidden_flags.iter().cloned());
    acc.required_keywords
        .extend(fragment.required_keywords.iter().cloned());
    acc.forbidden_keywords
        .extend(fragment.forbidden_keywords.iter().cloned());
    acc.header_filters
        .extend(fragment.header_filters.iter().cloned());
    acc.recent_only |= fragment.recent_only;
    acc.old_only |= fragment.old_only;
    acc.larger_than = match (acc.larger_than, fragment.larger_than) {
        (Some(existing), Some(next)) => Some(existing.max(next)),
        (None, Some(next)) => Some(next),
        (existing, None) => existing,
    };
    acc.smaller_than = match (acc.smaller_than, fragment.smaller_than) {
        (Some(existing), Some(next)) => Some(existing.min(next)),
        (None, Some(next)) => Some(next),
        (existing, None) => existing,
    };
    acc.internal_date_before = match (acc.internal_date_before, fragment.internal_date_before) {
        (Some(existing), Some(next)) => Some(existing.min(next)),
        (None, Some(next)) => Some(next),
        (existing, None) => existing,
    };
    acc.internal_date_on = acc.internal_date_on.or(fragment.internal_date_on);
    acc.internal_date_since = match (acc.internal_date_since, fragment.internal_date_since) {
        (Some(existing), Some(next)) => Some(existing.max(next)),
        (None, Some(next)) => Some(next),
        (existing, None) => existing,
    };
    acc.sent_date_before = match (acc.sent_date_before, fragment.sent_date_before) {
        (Some(existing), Some(next)) => Some(existing.min(next)),
        (None, Some(next)) => Some(next),
        (existing, None) => existing,
    };
    acc.sent_date_on = acc.sent_date_on.or(fragment.sent_date_on);
    acc.sent_date_since = match (acc.sent_date_since, fragment.sent_date_since) {
        (Some(existing), Some(next)) => Some(existing.max(next)),
        (None, Some(next)) => Some(next),
        (existing, None) => existing,
    };

    if let Some(fragment_query) = fragment.query_string.as_ref() {
        acc.query_string = match acc.query_string.take() {
            Some(existing) => Some(format!("{existing} {fragment_query}")),
            None => Some(fragment_query.clone()),
        };
    }

    acc.uid_filter = match (acc.uid_filter.take(), fragment.uid_filter.clone()) {
        (Some(existing), Some(next)) => union_uid_sets(Some(existing), next),
        (None, Some(next)) => Some(next),
        (existing, None) => existing,
    };
}

fn parse_imap_date(value: &str) -> Result<NaiveDate> {
    NaiveDate::parse_from_str(value, "%d-%b-%Y")
        .map_err(|_| Error::Parse(format!("invalid IMAP date: {value}")))
}

fn quote_query(term: String) -> String {
    if term
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, ':' | '"' | '(' | ')' | '\\'))
    {
        format!("\"{}\"", term.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        term
    }
}

fn header_query_string(field: &str, value: &str) -> Option<String> {
    let query_field = match field {
        "subject" => "subject",
        "from" => "from",
        "to" => "to",
        "cc" => "cc",
        "bcc" => "bcc",
        "message-id" | "message_id" => "message_id",
        "reply-to" | "reply_to" => "reply_to",
        _ => return None,
    };
    Some(format!("{query_field}:{}", quote_query(value.to_string())))
}

fn parse_uid_set(value: &str) -> Result<UidSet> {
    let mut set = UidSet::default();
    for part in value.split(',') {
        if let Some((start, end)) = part.split_once(':') {
            let start = parse_uid_bound(start)?;
            let end = parse_uid_bound(end)?;
            set.push(start.unwrap_or(1), end.unwrap_or(u64::MAX));
        } else {
            let uid = parse_uid_bound(part)?;
            let uid = uid.ok_or_else(|| Error::Parse("UID must be numeric".to_string()))?;
            set.push(uid, uid);
        }
    }
    Ok(set)
}

fn parse_uid_bound(value: &str) -> Result<Option<u64>> {
    if value == "*" {
        Ok(None)
    } else {
        value
            .parse::<u64>()
            .map(Some)
            .map_err(|_| Error::Parse(format!("invalid UID bound: {value}")))
    }
}

fn union_uid_sets(acc: Option<UidSet>, set: UidSet) -> Option<UidSet> {
    Some(match acc {
        Some(mut acc) => {
            acc.ranges.extend(set.ranges);
            acc
        }
        None => set,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use imap_cache_mime::parse_message;
    use tempfile::tempdir;

    #[test]
    fn parses_simple_search_query() {
        let query = SearchQuery::from_imap_args(&[
            "SUBJECT".into(),
            "hello".into(),
            "UID".into(),
            "1:3".into(),
        ])
        .unwrap();
        assert!(!query.match_all);
        assert_eq!(query.uid_filter.unwrap().contains(2), true);
        assert!(query.query_string.unwrap().contains("subject:hello"));
    }

    #[test]
    fn all_does_not_override_other_search_terms() {
        let query = SearchQuery::from_imap_args(&["ALL".into(), "SEEN".into()]).unwrap();
        assert!(!query.match_all);
        assert!(query.required_flags.iter().any(|flag| flag == "\\Seen"));
    }

    #[test]
    fn parses_bcc_search_query() {
        let query = SearchQuery::from_imap_args(&["BCC".into(), "hidden@example.com".into()])
            .unwrap();
        assert_eq!(query.query_string.as_deref(), Some("bcc:hidden@example.com"));
    }

    #[test]
    fn parses_recency_search_queries() {
        let recent = SearchQuery::from_imap_args(&["RECENT".into()]).unwrap();
        assert!(recent.recent_only);
        let new = SearchQuery::from_imap_args(&["NEW".into()]).unwrap();
        assert!(new.recent_only);
        assert!(new.forbidden_flags.iter().any(|flag| flag == "\\Seen"));
        let old = SearchQuery::from_imap_args(&["OLD".into()]).unwrap();
        assert!(old.old_only);
    }

    #[test]
    fn parses_boolean_search_queries() {
        let or_query = SearchQuery::from_imap_args(&[
            "OR".into(),
            "SEEN".into(),
            "UNSEEN".into(),
        ])
        .unwrap();
        assert!(matches!(or_query.expr.as_deref(), Some(SearchExpr::Or(_, _))));

        let not_query = SearchQuery::from_imap_args(&["NOT".into(), "SEEN".into()]).unwrap();
        assert!(matches!(not_query.expr.as_deref(), Some(SearchExpr::Not(_))));
    }

    #[test]
    fn parses_header_search_query() {
        let query = SearchQuery::from_imap_args(&[
            "HEADER".into(),
            "Message-ID".into(),
            "abc@example.test".into(),
        ])
        .unwrap();
        assert_eq!(
            query.header_filters,
            vec![("message-id".to_string(), "abc@example.test".to_string())]
        );
        assert_eq!(
            query.query_string.as_deref(),
            Some("message_id:abc@example.test")
        );
    }

    #[tokio::test]
    async fn indexes_and_searches_documents() {
        let engine = TantivySearchEngine::memory().unwrap();
        let raw = concat!(
            "From: Alice <alice@example.com>\r\n",
            "To: Bob <bob@example.com>\r\n",
            "Message-ID: <msg-7@example.com>\r\n",
            "Reply-To: Replies <reply@example.com>\r\n",
            "Bcc: Hidden <hidden@example.com>\r\n",
            "Subject: Search Target\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=\"utf-8\"\r\n",
            "\r\n",
            "Hello searchable world.\r\n",
        );
        let parsed = parse_message(raw.as_bytes()).unwrap();
        engine
            .index_message("INBOX", SearchDocument::from_parsed_message(7, &parsed))
            .await
            .unwrap();

        let query = SearchQuery::from_imap_args(&["TEXT".into(), "searchable".into()]).unwrap();
        let results = engine.search("INBOX", query).await.unwrap();
        assert_eq!(results, vec![7]);

        let bcc_query = SearchQuery::from_imap_args(&["BCC".into(), "hidden@example.com".into()])
            .unwrap();
        let bcc_results = engine.search("INBOX", bcc_query).await.unwrap();
        assert_eq!(bcc_results, vec![7]);

        let message_id_query = SearchQuery::from_imap_args(&[
            "HEADER".into(),
            "Message-ID".into(),
            "msg-7@example.com".into(),
        ])
        .unwrap();
        let message_id_results = engine.search("INBOX", message_id_query).await.unwrap();
        assert_eq!(message_id_results, vec![7]);
    }

    #[tokio::test]
    async fn reopens_persistent_indexes() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("search");
        let raw = concat!(
            "From: Alice <alice@example.com>\r\n",
            "To: Bob <bob@example.com>\r\n",
            "Subject: Persistent Target\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=\"utf-8\"\r\n",
            "\r\n",
            "Searchable body survives restarts.\r\n",
        );
        let parsed = parse_message(raw.as_bytes()).unwrap();

        {
            let engine = TantivySearchEngine::persistent(&root).unwrap();
            engine
                .index_message("INBOX", SearchDocument::from_parsed_message(42, &parsed))
                .await
                .unwrap();
        }

        let engine = TantivySearchEngine::persistent(&root).unwrap();
        let query = SearchQuery::from_imap_args(&["TEXT".into(), "survives".into()]).unwrap();
        let results = engine.search("INBOX", query).await.unwrap();
        assert_eq!(results, vec![42]);
    }
}
