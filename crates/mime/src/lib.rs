use imap_cache_core::error::{Error, Result};
use imap_cache_storage::{content_addressed_key, ObjectType};
use mailparse::{
    DispositionType, MailAddr, MailHeaderMap, ParsedMail, addrparse, dateparse, parse_mail,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedMessage {
    pub raw_sha256: String,
    pub size_octets: usize,
    pub message_id_header: Option<String>,
    pub subject: Option<String>,
    pub from_json: Value,
    pub to_json: Value,
    pub cc_json: Value,
    pub bcc_json: Value,
    pub reply_to_json: Value,
    pub envelope_json: Value,
    pub bodystructure_json: Value,
    pub text_preview: Option<String>,
    pub mime_parts: Vec<MimePartRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MimePartRecord {
    pub part_path: String,
    pub content_type: String,
    pub charset: Option<String>,
    pub disposition: Option<String>,
    pub filename: Option<String>,
    pub content_id: Option<String>,
    pub size_octets: usize,
    pub blob_key: String,
    pub sha256: String,
    pub transfer_encoding: Option<String>,
    pub metadata_json: Value,
    #[serde(skip)]
    pub raw_bytes: Vec<u8>,
}

pub fn parse_message(raw: &[u8]) -> Result<ParsedMessage> {
    let parsed = parse_mail(raw)
        .map_err(|e| Error::Parse(format!("failed to parse RFC822 message: {e}")))?;
    let raw_sha256 = hex::encode(Sha256::digest(raw));

    let from_json = address_header_json(&parsed, "From");
    let to_json = address_header_json(&parsed, "To");
    let cc_json = address_header_json(&parsed, "Cc");
    let bcc_json = address_header_json(&parsed, "Bcc");
    let reply_to_json = address_header_json(&parsed, "Reply-To");
    let subject = parsed.headers.get_first_value("Subject");
    let message_id_header = parsed.headers.get_first_value("Message-ID");
    let envelope_json = build_envelope(
        &parsed,
        &from_json,
        &to_json,
        &cc_json,
        &bcc_json,
        &reply_to_json,
        subject.clone(),
        message_id_header.clone(),
    );

    let mut mime_parts = Vec::new();
    let mut preview = None;
    let bodystructure_json = build_part_tree(&parsed, "1", &mut mime_parts, &mut preview)?;

    Ok(ParsedMessage {
        raw_sha256,
        size_octets: raw.len(),
        message_id_header,
        subject,
        from_json,
        to_json,
        cc_json,
        bcc_json,
        reply_to_json,
        envelope_json,
        bodystructure_json,
        text_preview: preview,
        mime_parts,
    })
}

pub fn extract_part_bytes(raw: &[u8], part_path: &str) -> Result<Option<Vec<u8>>> {
    let parsed = parse_message(raw)?;
    Ok(parsed
        .mime_parts
        .into_iter()
        .find(|part| part.part_path == part_path)
        .map(|part| part.raw_bytes))
}

fn build_envelope(
    parsed: &ParsedMail<'_>,
    from_json: &Value,
    to_json: &Value,
    cc_json: &Value,
    bcc_json: &Value,
    reply_to_json: &Value,
    subject: Option<String>,
    message_id_header: Option<String>,
) -> Value {
    let date = parsed
        .headers
        .get_first_value("Date")
        .and_then(|value| dateparse(&value).ok());

    json!({
        "date": date,
        "subject": subject,
        "message_id": message_id_header,
        "from": from_json,
        "to": to_json,
        "cc": cc_json,
        "bcc": bcc_json,
        "reply_to": reply_to_json,
    })
}

fn build_part_tree(
    part: &ParsedMail<'_>,
    path: &str,
    mime_parts: &mut Vec<MimePartRecord>,
    preview: &mut Option<String>,
) -> Result<Value> {
    if part.ctype.mimetype.eq_ignore_ascii_case("message/rfc822") {
        return build_message_rfc822_part(part, path, mime_parts, preview);
    }
    if part.subparts.is_empty() {
        build_leaf_part(part, path, mime_parts, preview)
    } else {
        let mut children = Vec::with_capacity(part.subparts.len());
        for (idx, child) in part.subparts.iter().enumerate() {
            let child_path = if path.is_empty() {
                (idx + 1).to_string()
            } else {
                format!("{path}.{}", idx + 1)
            };
            children.push(build_part_tree(child, &child_path, mime_parts, preview)?);
        }

        let mut params = Map::new();
        for (key, value) in &part.ctype.params {
            params.insert(key.clone(), Value::String(value.clone()));
        }

        let subtype = part
            .ctype
            .mimetype
            .split_once('/')
            .map(|(_, subtype)| subtype.to_string())
            .unwrap_or_else(|| part.ctype.mimetype.clone());

        Ok(json!({
            "path": path,
            "type": "multipart",
            "subtype": subtype,
            "params": params,
            "parts": children,
        }))
    }
}

fn build_message_rfc822_part(
    part: &ParsedMail<'_>,
    path: &str,
    mime_parts: &mut Vec<MimePartRecord>,
    preview: &mut Option<String>,
) -> Result<Value> {
    let disposition = part.get_content_disposition();
    let disposition_text = match disposition.disposition {
        DispositionType::Inline => Some("inline".to_string()),
        DispositionType::Attachment => Some("attachment".to_string()),
        DispositionType::FormData => Some("form-data".to_string()),
        DispositionType::Extension(value) => Some(value),
    };
    let filename = disposition
        .params
        .get("filename")
        .cloned()
        .or_else(|| part.ctype.params.get("name").cloned());
    let content_id = part
        .headers
        .get_first_value("Content-ID")
        .map(|value| value.trim().trim_matches('<').trim_matches('>').to_string());
    let transfer_encoding = part.headers.get_first_value("Content-Transfer-Encoding");
    let raw_bytes = part
        .get_body_raw()
        .map_err(|e| Error::Parse(format!("failed to decode MIME part {path}: {e}")))?;
    let nested = parse_mail(&raw_bytes)
        .map_err(|e| Error::Parse(format!("failed to parse embedded message {path}: {e}")))?;
    let size_octets = raw_bytes.len();

    if preview.is_none() {
        let nested_preview = extract_preview_from_message(&nested);
        if let Some(snippet) = nested_preview {
            *preview = Some(snippet);
        }
    }

    let mut params = Map::new();
    for (key, value) in &part.ctype.params {
        params.insert(key.clone(), Value::String(value.clone()));
    }

    let mut metadata = Map::new();
    metadata.insert("path".to_string(), Value::String(path.to_string()));
    metadata.insert(
        "content_type".to_string(),
        Value::String(part.ctype.mimetype.clone()),
    );
    if let Some(value) = part.headers.get_first_value("Content-Description") {
        metadata.insert("description".to_string(), Value::String(value));
    }

    let object_type =
        if matches!(disposition_text.as_deref(), Some("attachment")) || filename.is_some() {
            ObjectType::Attachment
        } else {
            ObjectType::MimePart
        };
    let blob_key = content_addressed_key(object_type, &raw_bytes);
    let sha256 = hex::encode(Sha256::digest(&raw_bytes));

    mime_parts.push(MimePartRecord {
        part_path: path.to_string(),
        content_type: part.ctype.mimetype.clone(),
        charset: Some(part.ctype.charset.clone()).filter(|value| !value.is_empty()),
        disposition: disposition_text.clone(),
        filename: filename.clone(),
        content_id: content_id.clone(),
        size_octets,
        blob_key,
        sha256,
        transfer_encoding: transfer_encoding.clone(),
        metadata_json: Value::Object(metadata),
        raw_bytes: raw_bytes.clone(),
    });

    let nested_from = address_header_json(&nested, "From");
    let nested_to = address_header_json(&nested, "To");
    let nested_cc = address_header_json(&nested, "Cc");
    let nested_bcc = address_header_json(&nested, "Bcc");
    let nested_reply_to = address_header_json(&nested, "Reply-To");
    let nested_subject = nested.headers.get_first_value("Subject");
    let nested_message_id_header = nested.headers.get_first_value("Message-ID");
    let nested_envelope = build_envelope(
        &nested,
        &nested_from,
        &nested_to,
        &nested_cc,
        &nested_bcc,
        &nested_reply_to,
        nested_subject,
        nested_message_id_header,
    );
    let nested_bodystructure = build_part_tree(&nested, &format!("{path}.1"), mime_parts, preview)?;
    let lines = raw_bytes.iter().filter(|byte| **byte == b'\n').count() as usize;
    let mut result = Map::new();
    result.insert("path".to_string(), Value::String(path.to_string()));
    result.insert("type".to_string(), Value::String("message".to_string()));
    result.insert("subtype".to_string(), Value::String("rfc822".to_string()));
    result.insert("params".to_string(), Value::Object(params));
    result.insert("envelope".to_string(), nested_envelope);
    result.insert("bodystructure".to_string(), nested_bodystructure);
    result.insert("lines".to_string(), Value::from(lines as u64));
    result.insert("size".to_string(), Value::from(size_octets as u64));
    if let Some(value) = content_id {
        result.insert("content_id".to_string(), Value::String(value));
    }
    if let Some(value) = transfer_encoding {
        result.insert("transfer_encoding".to_string(), Value::String(value));
    }
    Ok(Value::Object(result))
}

fn build_leaf_part(
    part: &ParsedMail<'_>,
    path: &str,
    mime_parts: &mut Vec<MimePartRecord>,
    preview: &mut Option<String>,
) -> Result<Value> {
    let disposition = part.get_content_disposition();
    let disposition_text = match disposition.disposition {
        DispositionType::Inline => Some("inline".to_string()),
        DispositionType::Attachment => Some("attachment".to_string()),
        DispositionType::FormData => Some("form-data".to_string()),
        DispositionType::Extension(value) => Some(value),
    };
    let filename = disposition
        .params
        .get("filename")
        .cloned()
        .or_else(|| part.ctype.params.get("name").cloned());
    let content_id = part
        .headers
        .get_first_value("Content-ID")
        .map(|value| value.trim().trim_matches('<').trim_matches('>').to_string());
    let transfer_encoding = part.headers.get_first_value("Content-Transfer-Encoding");
    let raw_bytes = part
        .get_body_raw()
        .map_err(|e| Error::Parse(format!("failed to decode MIME part {path}: {e}")))?;
    let size_octets = raw_bytes.len();
    let body = part.get_body().unwrap_or_default();

    if preview.is_none()
        && is_preview_candidate(part, disposition_text.as_deref(), filename.as_deref())
    {
        let snippet = body.trim().chars().take(512).collect::<String>();
        if !snippet.is_empty() {
            *preview = Some(snippet);
        }
    }

    let mut params = Map::new();
    for (key, value) in &part.ctype.params {
        params.insert(key.clone(), Value::String(value.clone()));
    }

    let mut metadata = Map::new();
    metadata.insert("path".to_string(), Value::String(path.to_string()));
    metadata.insert(
        "content_type".to_string(),
        Value::String(part.ctype.mimetype.clone()),
    );
    if let Some(value) = part.headers.get_first_value("Content-Description") {
        metadata.insert("description".to_string(), Value::String(value));
    }

    let object_type =
        if matches!(disposition_text.as_deref(), Some("attachment")) || filename.is_some() {
            ObjectType::Attachment
        } else {
            ObjectType::MimePart
        };
    let blob_key = content_addressed_key(object_type, &raw_bytes);
    let sha256 = hex::encode(Sha256::digest(&raw_bytes));

    let record = MimePartRecord {
        part_path: path.to_string(),
        content_type: part.ctype.mimetype.clone(),
        charset: Some(part.ctype.charset.clone()).filter(|value| !value.is_empty()),
        disposition: disposition_text.clone(),
        filename: filename.clone(),
        content_id: content_id.clone(),
        size_octets,
        blob_key,
        sha256,
        transfer_encoding: transfer_encoding.clone(),
        metadata_json: Value::Object(metadata.clone()),
        raw_bytes,
    };
    mime_parts.push(record);

    let subtype = part
        .ctype
        .mimetype
        .split_once('/')
        .map(|(_, subtype)| subtype.to_string())
        .unwrap_or_else(|| part.ctype.mimetype.clone());

    Ok(json!({
        "path": path,
        "type": part.ctype.mimetype.split('/').next().unwrap_or("application"),
        "subtype": subtype,
        "charset": part.ctype.params.get("charset"),
        "params": params,
        "disposition": disposition_text,
        "filename": filename,
        "content_id": content_id,
        "transfer_encoding": transfer_encoding,
        "size": size_octets,
    }))
}

fn extract_preview_from_message(parsed: &ParsedMail<'_>) -> Option<String> {
    if parsed.ctype.mimetype.starts_with("text/") {
        let body = parsed.get_body().unwrap_or_default();
        let snippet = body.trim().chars().take(512).collect::<String>();
        if !snippet.is_empty() {
            return Some(snippet);
        }
    }
    for part in &parsed.subparts {
        if let Some(snippet) = extract_preview_from_message(part) {
            return Some(snippet);
        }
    }
    None
}

fn is_preview_candidate(
    part: &ParsedMail<'_>,
    disposition: Option<&str>,
    filename: Option<&str>,
) -> bool {
    if !part.ctype.mimetype.starts_with("text/") {
        return false;
    }
    if matches!(disposition, Some("attachment")) || filename.is_some() {
        return false;
    }
    true
}

fn address_header_json(parsed: &ParsedMail<'_>, header: &str) -> Value {
    match parsed.headers.get_first_value(header) {
        Some(value) => match addrparse(&value) {
            Ok(list) => Value::Array(list.iter().cloned().map(address_json).collect()),
            Err(_) => Value::Null,
        },
        None => Value::Null,
    }
}

fn address_json(addr: MailAddr) -> Value {
    match addr {
        MailAddr::Single(single) => json!({
            "kind": "mailbox",
            "display_name": single.display_name,
            "address": single.addr,
        }),
        MailAddr::Group(group) => json!({
            "kind": "group",
            "group_name": group.group_name,
            "members": group.addrs.into_iter().map(|member| json!({
                "display_name": member.display_name,
                "address": member.addr,
            })).collect::<Vec<_>>(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(
        "From: Alice <alice@example.com>\r\n",
        "To: Bob <bob@example.com>\r\n",
        "Subject: MIME Test\r\n",
        "Message-ID: <example-1@example.com>\r\n",
        "Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"outer\"\r\n",
        "\r\n",
        "--outer\r\n",
        "Content-Type: multipart/alternative; boundary=\"inner\"\r\n",
        "\r\n",
        "--inner\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "Hello plain world.\r\n",
        "--inner\r\n",
        "Content-Type: text/html; charset=\"utf-8\"\r\n",
        "\r\n",
        "<html><body>Hello <b>HTML</b>.</body></html>\r\n",
        "--inner--\r\n",
        "--outer\r\n",
        "Content-Type: application/pdf\r\n",
        "Content-Disposition: attachment; filename=\"file.pdf\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "Zm9v\r\n",
        "--outer--\r\n"
    );

    const ENCAPSULATED_SAMPLE: &str = concat!(
        "From: Outer <outer@example.com>\r\n",
        "To: Recipient <recipient@example.com>\r\n",
        "Subject: Encapsulated MIME Test\r\n",
        "Message-ID: <outer@example.com>\r\n",
        "Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: message/rfc822\r\n",
        "\r\n",
        "From: Nested <nested@example.com>\r\n",
        "To: Recipient <recipient@example.com>\r\n",
        "Subject: Nested Message\r\n",
        "Message-ID: <nested@example.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"inner\"\r\n",
        "\r\n",
        "--inner\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "Nested body.\r\n",
        "--inner\r\n",
        "Content-Type: application/pdf\r\n",
        "Content-Disposition: attachment; filename=\"nested.pdf\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "Zm9v\r\n",
        "--inner--\r\n"
    );

    #[test]
    fn parses_multipart_message_and_extracts_preview() {
        let parsed = parse_message(SAMPLE.as_bytes()).unwrap();
        assert_eq!(parsed.subject.as_deref(), Some("MIME Test"));
        assert_eq!(parsed.mime_parts.len(), 3);
        assert!(
            parsed
                .text_preview
                .as_deref()
                .unwrap_or("")
                .contains("Hello plain world.")
        );
        assert_eq!(parsed.bodystructure_json["type"], "multipart");
    }

    #[test]
    fn captures_addresses_and_sha256() {
        let parsed = parse_message(SAMPLE.as_bytes()).unwrap();
        assert_eq!(parsed.from_json[0]["address"], "alice@example.com");
        assert_eq!(parsed.to_json[0]["address"], "bob@example.com");
        assert_eq!(parsed.raw_sha256.len(), 64);
    }

    #[test]
    fn parses_message_rfc822_and_nested_parts() {
        let parsed = parse_message(ENCAPSULATED_SAMPLE.as_bytes()).unwrap();
        assert_eq!(parsed.bodystructure_json["type"], "message");
        assert_eq!(parsed.bodystructure_json["subtype"], "rfc822");
        assert_eq!(
            parsed.bodystructure_json["bodystructure"]["type"],
            "multipart"
        );
        assert_eq!(parsed.mime_parts.len(), 3);
        assert_eq!(parsed.mime_parts[0].content_type, "message/rfc822");
        assert!(
            parsed
                .mime_parts
                .iter()
                .any(|part| part.part_path.starts_with("1.1"))
        );
        assert!(
            parsed
                .text_preview
                .as_deref()
                .unwrap_or("")
                .contains("Nested body.")
        );
    }
}
