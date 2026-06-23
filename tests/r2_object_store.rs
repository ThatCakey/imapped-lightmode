use imap_cache_rs::storage::{
    ObjectStore, ObjectType, content_addressed_key,
    r2::{R2Config, S3ObjectStore},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

#[derive(Default)]
struct MockS3State {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

#[tokio::test]
async fn s3_object_store_round_trips_objects() -> anyhow::Result<()> {
    let state = Arc::new(MockS3State::default());
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server_state = Arc::clone(&state);
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let state = Arc::clone(&server_state);
            tokio::spawn(async move {
                let _ = handle_mock_s3_connection(stream, state).await;
            });
        }
    });

    let config = R2Config {
        endpoint: format!("http://{addr}"),
        bucket: "test-bucket".to_string(),
        access_key_id: "test-access-key".to_string(),
        secret_access_key: "test-secret-key".to_string(),
        region: "auto".to_string(),
    };
    let store = S3ObjectStore::from_config(&config).await?;
    let key = content_addressed_key(ObjectType::Rfc822, b"hello-r2");

    let meta = store.put(&key, b"hello-r2").await?;
    assert_eq!(meta.key, key);
    assert!(store.exists(&key).await?);
    assert_eq!(store.get(&key).await?.unwrap(), b"hello-r2");
    assert_eq!(store.get_range(&key, 1, Some(4)).await?.unwrap(), b"ell");

    state
        .objects
        .lock()
        .unwrap()
        .insert(format!("test-bucket/{key}"), b"corrupted".to_vec());
    let err = store.get(&key).await.unwrap_err();
    assert!(err.to_string().contains("content hash mismatch"));

    store.delete(&key).await?;
    assert!(!store.exists(&key).await?);

    let error_key = "force-error";
    let err = store.exists(error_key).await.unwrap_err();
    assert!(err.to_string().contains("S3 head_object failed"));
    let err = store.get(error_key).await.unwrap_err();
    assert!(err.to_string().contains("S3 head_object failed"));

    server.abort();
    Ok(())
}

async fn handle_mock_s3_connection(
    stream: TcpStream,
    state: Arc<MockS3State>,
) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream);

    loop {
        let mut request_line = String::new();
        let bytes = reader.read_line(&mut request_line).await?;
        if bytes == 0 {
            break;
        }
        if request_line.trim().is_empty() {
            continue;
        }

        let mut headers = HashMap::new();
        loop {
            let mut header_line = String::new();
            reader.read_line(&mut header_line).await?;
            let trimmed = header_line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }

        let content_length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).await?;
        }

        let parts = request_line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }
        let method = parts[0];
        let path = parts[1]
            .split('?')
            .next()
            .unwrap_or(parts[1])
            .trim_start_matches('/');
        let (bucket, key) = path
            .split_once('/')
            .map(|(bucket, key)| (bucket.to_string(), key.to_string()))
            .unwrap_or_else(|| (path.to_string(), String::new()));
        let object_id = format!("{bucket}/{key}");

        let (status_line, response_body) = {
            let mut objects = state.objects.lock().unwrap();
            match method {
                "PUT" => {
                    objects.insert(object_id, body);
                    ("HTTP/1.1 200 OK", Vec::new())
                }
                "HEAD" => match objects.get(&object_id).cloned() {
                    _ if key == "force-error" => {
                        ("HTTP/1.1 500 Internal Server Error", Vec::new())
                    }
                    Some(bytes) => {
                        let content_length = headers
                            .get("range")
                            .and_then(|range| parse_range(range, bytes.len()))
                            .map(|(start, end)| end.saturating_sub(start))
                            .unwrap_or(bytes.len());
                        (
                            "HTTP/1.1 200 OK",
                            format!(
                                "Content-Length: {}\r\nETag: \"mock-etag\"\r\nConnection: keep-alive\r\n\r\n",
                                content_length
                            )
                            .into_bytes(),
                        )
                    }
                    None => ("HTTP/1.1 404 Not Found", Vec::new()),
                },
                "GET" => match objects.get(&object_id) {
                    _ if key == "force-error" => {
                        ("HTTP/1.1 500 Internal Server Error", Vec::new())
                    }
                    Some(bytes) => {
                        if let Some(range) = headers.get("range") {
                            if let Some((start, end)) = parse_range(range, bytes.len()) {
                                ("HTTP/1.1 206 Partial Content", bytes[start..end].to_vec())
                            } else {
                                ("HTTP/1.1 416 Range Not Satisfiable", Vec::new())
                            }
                        } else {
                            ("HTTP/1.1 200 OK", bytes.clone())
                        }
                    }
                    None => ("HTTP/1.1 404 Not Found", Vec::new()),
                },
                "DELETE" => {
                    objects.remove(&object_id);
                    ("HTTP/1.1 204 No Content", Vec::new())
                }
                _ => ("HTTP/1.1 405 Method Not Allowed", Vec::new()),
            }
        };

        let response = format!(
            "{status_line}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            response_body.len()
        );
        reader.get_mut().write_all(response.as_bytes()).await?;
        if !response_body.is_empty() {
            reader.get_mut().write_all(&response_body).await?;
        }
        reader.get_mut().flush().await?;
    }

    Ok(())
}

fn parse_range(range: &str, len: usize) -> Option<(usize, usize)> {
    let range = range.strip_prefix("bytes=")?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse::<usize>().ok()?;
    let end = if end.is_empty() {
        len
    } else {
        end.parse::<usize>().ok()?.saturating_add(1)
    };
    if start >= len {
        return None;
    }
    Some((start, end.min(len)))
}
