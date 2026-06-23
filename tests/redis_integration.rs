use futures::StreamExt;
use imap_cache_rs::{
    auth::bootstrap_authenticator,
    config::Config,
    coordination::{RedisSyncLockManager, SyncLockManager},
    metrics::AppMetrics,
    notifications::{
        MailboxEventHub, MutationEvent, MutationEventSink, RedisMutationEventRelay,
        RedisMutationEventSink,
    },
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, tcp::OwnedWriteHalf},
    sync::{Mutex, Notify, broadcast},
};

#[derive(Clone)]
struct FakeRedisServer {
    addr: SocketAddr,
    state: Arc<FakeRedisState>,
}

struct FakeRedisState {
    kv: Mutex<HashMap<String, StoredValue>>,
    mutation_channel: broadcast::Sender<Vec<u8>>,
    subscriber_count: AtomicUsize,
    subscriber_ready: Notify,
}

#[derive(Clone)]
struct StoredValue {
    value: String,
    expires_at: Option<Instant>,
}

impl FakeRedisServer {
    async fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (mutation_channel, _) = broadcast::channel(32);
        let state = Arc::new(FakeRedisState {
            kv: Mutex::new(HashMap::new()),
            mutation_channel,
            subscriber_count: AtomicUsize::new(0),
            subscriber_ready: Notify::new(),
        });

        let server_state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let connection_state = Arc::clone(&server_state);
                tokio::spawn(async move {
                    let _ = handle_connection(stream, connection_state).await;
                });
            }
        });

        Ok(Self { addr, state })
    }

    fn url(&self) -> String {
        format!("redis://{}", self.addr)
    }

    async fn wait_for_subscriber(&self) {
        while self.state.subscriber_count.load(Ordering::SeqCst) == 0 {
            self.state.subscriber_ready.notified().await;
        }
    }

    async fn wait_for_subscribers(&self, expected: usize) {
        while self.state.subscriber_count.load(Ordering::SeqCst) < expected {
            self.state.subscriber_ready.notified().await;
        }
    }
}

async fn handle_connection(stream: TcpStream, state: Arc<FakeRedisState>) -> anyhow::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    while let Some(command) = read_command(&mut reader).await? {
        if command.is_empty() {
            continue;
        }
        let verb = String::from_utf8_lossy(&command[0]).to_ascii_uppercase();
        match verb.as_str() {
            "CLIENT" => {
                write_ok(&mut write_half).await?;
            }
            "SCRIPT" => {
                let subcommand = command
                    .get(1)
                    .ok_or_else(|| anyhow::anyhow!("missing script subcommand"))?;
                if subcommand.eq_ignore_ascii_case(b"LOAD") {
                    write_bulk_string(&mut write_half, b"0123456789abcdef0123456789abcdef01234567")
                        .await?;
                } else {
                    write_ok(&mut write_half).await?;
                }
            }
            "SUBSCRIBE" => {
                let channel = command
                    .get(1)
                    .ok_or_else(|| anyhow::anyhow!("missing channel"))?
                    .clone();
                let channel_name = String::from_utf8(channel.clone())?;
                let mut rx = state.mutation_channel.subscribe();
                state.subscriber_count.fetch_add(1, Ordering::SeqCst);
                state.subscriber_ready.notify_waiters();
                write_subscribe_ack(&mut write_half, &channel_name, 1).await?;
                tokio::spawn(async move {
                    while let Ok(payload) = rx.recv().await {
                        if write_pubsub_message(&mut write_half, &channel_name, &payload)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    state.subscriber_count.fetch_sub(1, Ordering::SeqCst);
                });
                return Ok(());
            }
            "PUBLISH" => {
                let payload = command
                    .get(2)
                    .ok_or_else(|| anyhow::anyhow!("missing publish payload"))?
                    .clone();
                let _ = state.mutation_channel.send(payload);
                let count = state.subscriber_count.load(Ordering::SeqCst) as i64;
                write_integer(&mut write_half, count).await?;
            }
            "SET" => {
                let reply = handle_set(&state, &command).await?;
                match reply {
                    RedisReply::Ok => write_ok(&mut write_half).await?,
                    RedisReply::Nil => write_nil(&mut write_half).await?,
                }
            }
            "GET" => {
                let value = handle_get(&state, &command).await?;
                match value {
                    Some(value) => write_bulk_string(&mut write_half, value.as_bytes()).await?,
                    None => write_nil(&mut write_half).await?,
                }
            }
            "EXISTS" => {
                let exists = handle_exists(&state, &command).await?;
                write_integer(&mut write_half, i64::from(exists)).await?;
            }
            "DEL" => {
                let deleted = handle_del(&state, &command).await?;
                write_integer(&mut write_half, deleted as i64).await?;
            }
            "INCR" => {
                let value = handle_incr(&state, &command).await?;
                write_integer(&mut write_half, value).await?;
            }
            "EXPIRE" => {
                let updated = handle_expire(&state, &command).await?;
                write_integer(&mut write_half, i64::from(updated)).await?;
            }
            "EVAL" => {
                let reply = handle_eval(&state, &command, true).await?;
                write_integer(&mut write_half, reply).await?;
            }
            "EVALSHA" => {
                let reply = handle_eval(&state, &command, false).await?;
                write_integer(&mut write_half, reply).await?;
            }
            "PING" => {
                write_ok(&mut write_half).await?;
            }
            _ => {
                write_ok(&mut write_half).await?;
            }
        }
    }

    Ok(())
}

enum RedisReply {
    Ok,
    Nil,
}

async fn handle_set(
    state: &Arc<FakeRedisState>,
    command: &[Vec<u8>],
) -> anyhow::Result<RedisReply> {
    let key = String::from_utf8(
        command
            .get(1)
            .ok_or_else(|| anyhow::anyhow!("missing key"))?
            .clone(),
    )?;
    let value = String::from_utf8(
        command
            .get(2)
            .ok_or_else(|| anyhow::anyhow!("missing value"))?
            .clone(),
    )?;
    let mut nx = false;
    let mut px = None;
    let mut index = 3;
    while index < command.len() {
        let option = String::from_utf8_lossy(&command[index]).to_ascii_uppercase();
        match option.as_str() {
            "NX" => {
                nx = true;
                index += 1;
            }
            "PX" => {
                let ttl = command
                    .get(index + 1)
                    .ok_or_else(|| anyhow::anyhow!("missing PX ttl"))?;
                px = Some(String::from_utf8(ttl.clone())?.parse::<u64>()?);
                index += 2;
            }
            _ => {
                index += 1;
            }
        }
    }

    let mut kv = state.kv.lock().await;
    cleanup_expired(&mut kv);
    if nx && kv.contains_key(&key) {
        return Ok(RedisReply::Nil);
    }

    kv.insert(
        key,
        StoredValue {
            value,
            expires_at: px.map(|ttl| Instant::now() + Duration::from_millis(ttl)),
        },
    );
    Ok(RedisReply::Ok)
}

async fn handle_get(
    state: &Arc<FakeRedisState>,
    command: &[Vec<u8>],
) -> anyhow::Result<Option<String>> {
    let key = String::from_utf8(
        command
            .get(1)
            .ok_or_else(|| anyhow::anyhow!("missing key"))?
            .clone(),
    )?;
    let mut kv = state.kv.lock().await;
    cleanup_expired(&mut kv);
    Ok(kv.get(&key).map(|entry| entry.value.clone()))
}

async fn handle_exists(state: &Arc<FakeRedisState>, command: &[Vec<u8>]) -> anyhow::Result<bool> {
    let key = String::from_utf8(
        command
            .get(1)
            .ok_or_else(|| anyhow::anyhow!("missing key"))?
            .clone(),
    )?;
    let mut kv = state.kv.lock().await;
    cleanup_expired(&mut kv);
    Ok(kv.contains_key(&key))
}

async fn handle_del(state: &Arc<FakeRedisState>, command: &[Vec<u8>]) -> anyhow::Result<usize> {
    let key = String::from_utf8(
        command
            .get(1)
            .ok_or_else(|| anyhow::anyhow!("missing key"))?
            .clone(),
    )?;
    let mut kv = state.kv.lock().await;
    cleanup_expired(&mut kv);
    Ok(kv.remove(&key).is_some() as usize)
}

async fn handle_incr(state: &Arc<FakeRedisState>, command: &[Vec<u8>]) -> anyhow::Result<i64> {
    let key = String::from_utf8(
        command
            .get(1)
            .ok_or_else(|| anyhow::anyhow!("missing key"))?
            .clone(),
    )?;
    let mut kv = state.kv.lock().await;
    cleanup_expired(&mut kv);
    let next = kv
        .get(&key)
        .and_then(|entry| entry.value.parse::<i64>().ok())
        .unwrap_or(0)
        + 1;
    kv.insert(
        key,
        StoredValue {
            value: next.to_string(),
            expires_at: None,
        },
    );
    Ok(next)
}

async fn handle_expire(state: &Arc<FakeRedisState>, command: &[Vec<u8>]) -> anyhow::Result<bool> {
    let key = String::from_utf8(
        command
            .get(1)
            .ok_or_else(|| anyhow::anyhow!("missing key"))?
            .clone(),
    )?;
    let ttl = String::from_utf8(
        command
            .get(2)
            .ok_or_else(|| anyhow::anyhow!("missing ttl"))?
            .clone(),
    )?
    .parse::<u64>()?;
    let mut kv = state.kv.lock().await;
    cleanup_expired(&mut kv);
    if let Some(entry) = kv.get_mut(&key) {
        entry.expires_at = Some(Instant::now() + Duration::from_secs(ttl));
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn handle_eval(
    state: &Arc<FakeRedisState>,
    command: &[Vec<u8>],
    has_script_body: bool,
) -> anyhow::Result<i64> {
    let script = if has_script_body {
        Some(String::from_utf8(
            command
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("missing script"))?
                .clone(),
        )?)
    } else {
        None
    };
    let numkeys = String::from_utf8(
        command
            .get(2)
            .ok_or_else(|| anyhow::anyhow!("missing numkeys"))?
            .clone(),
    )?
    .parse::<usize>()?;
    let keys = &command[3..3 + numkeys];
    let argv = &command[3 + numkeys..];

    if script
        .as_deref()
        .is_some_and(|script| script.contains(r#"redis.call("GET", KEYS[1]) == ARGV[1]"#))
        || (!has_script_body && numkeys == 1 && argv.len() == 1)
    {
        let key = String::from_utf8(keys[0].clone())?;
        let token = String::from_utf8(argv[0].clone())?;
        let mut kv = state.kv.lock().await;
        cleanup_expired(&mut kv);
        if kv.get(&key).map(|entry| entry.value.as_str()) == Some(token.as_str()) {
            kv.remove(&key);
            return Ok(1);
        }
        return Ok(0);
    }

    if script
        .as_deref()
        .is_some_and(|script| script.contains(r#"redis.call("INCR", KEYS[2])"#))
        || (!has_script_body && numkeys == 2 && argv.len() == 2)
    {
        let blocked_key = String::from_utf8(keys[0].clone())?;
        let failures_key = String::from_utf8(keys[1].clone())?;
        let lockout_seconds = String::from_utf8(argv[0].clone())?.parse::<u64>()?;
        let max_failures = String::from_utf8(argv[1].clone())?.parse::<u32>()?;
        let mut kv = state.kv.lock().await;
        cleanup_expired(&mut kv);
        if kv.contains_key(&blocked_key) {
            return Ok(-1);
        }
        let failures = kv
            .get(&failures_key)
            .and_then(|entry| entry.value.parse::<u32>().ok())
            .unwrap_or(0)
            + 1;
        if failures == 1 {
            let expires_at = Some(Instant::now() + Duration::from_secs(lockout_seconds));
            kv.insert(
                failures_key.clone(),
                StoredValue {
                    value: failures.to_string(),
                    expires_at,
                },
            );
        } else {
            let expires_at = kv.get(&failures_key).and_then(|entry| entry.expires_at);
            kv.insert(
                failures_key.clone(),
                StoredValue {
                    value: failures.to_string(),
                    expires_at,
                },
            );
        }
        if failures >= max_failures {
            kv.insert(
                blocked_key,
                StoredValue {
                    value: "1".to_string(),
                    expires_at: Some(Instant::now() + Duration::from_secs(lockout_seconds)),
                },
            );
            kv.remove(&failures_key);
            return Ok(1);
        }
        return Ok(failures as i64);
    }

    Ok(0)
}

fn cleanup_expired(kv: &mut HashMap<String, StoredValue>) {
    let now = Instant::now();
    kv.retain(|_, entry| entry.expires_at.is_none_or(|expires_at| expires_at > now));
}

async fn read_command(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> anyhow::Result<Option<Vec<Vec<u8>>>> {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).await?;
    if bytes == 0 {
        return Ok(None);
    }
    if !line.starts_with('*') {
        return Err(anyhow::anyhow!("expected RESP array"));
    }
    let count = line[1..].trim_end_matches(['\r', '\n']).parse::<usize>()?;
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        line.clear();
        reader.read_line(&mut line).await?;
        if !line.starts_with('$') {
            return Err(anyhow::anyhow!("expected RESP bulk string"));
        }
        let len = line[1..].trim_end_matches(['\r', '\n']).parse::<usize>()?;
        let mut buf = vec![0; len];
        reader.read_exact(&mut buf).await?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        args.push(buf);
    }
    Ok(Some(args))
}

async fn write_ok(write: &mut OwnedWriteHalf) -> anyhow::Result<()> {
    write.write_all(b"+OK\r\n").await?;
    Ok(())
}

async fn write_nil(write: &mut OwnedWriteHalf) -> anyhow::Result<()> {
    write.write_all(b"$-1\r\n").await?;
    Ok(())
}

async fn write_integer(write: &mut OwnedWriteHalf, value: i64) -> anyhow::Result<()> {
    write.write_all(format!(":{value}\r\n").as_bytes()).await?;
    Ok(())
}

async fn write_bulk_string(write: &mut OwnedWriteHalf, bytes: &[u8]) -> anyhow::Result<()> {
    write
        .write_all(format!("${}\r\n", bytes.len()).as_bytes())
        .await?;
    write.write_all(bytes).await?;
    write.write_all(b"\r\n").await?;
    Ok(())
}

async fn write_subscribe_ack(
    write: &mut OwnedWriteHalf,
    channel: &str,
    count: i64,
) -> anyhow::Result<()> {
    write
        .write_all(
            format!(
                "*3\r\n$9\r\nsubscribe\r\n${}\r\n{}\r\n:{}\r\n",
                channel.len(),
                channel,
                count
            )
            .as_bytes(),
        )
        .await?;
    Ok(())
}

async fn write_pubsub_message(
    write: &mut OwnedWriteHalf,
    channel: &str,
    payload: &[u8],
) -> anyhow::Result<()> {
    write
        .write_all(
            format!(
                "*3\r\n$7\r\nmessage\r\n${}\r\n{}\r\n${}\r\n",
                channel.len(),
                channel,
                payload.len()
            )
            .as_bytes(),
        )
        .await?;
    write.write_all(payload).await?;
    write.write_all(b"\r\n").await?;
    Ok(())
}

#[tokio::test]
async fn redis_mutation_events_flow_through_pubsub_relay() -> anyhow::Result<()> {
    let server = FakeRedisServer::start().await?;
    let hub = Arc::new(MailboxEventHub::new(16));
    let metrics = Arc::new(AppMetrics::new());
    let notification_metrics: Arc<dyn imap_cache_rs::notifications::NotificationMetrics> =
        metrics.clone();
    let relay = RedisMutationEventRelay::new(&server.url(), Arc::clone(&hub))?
        .with_metrics(Arc::clone(&notification_metrics));
    let relay_task = tokio::spawn(async move { relay.run().await });

    tokio::time::timeout(Duration::from_secs(5), server.wait_for_subscriber()).await?;
    let sink = RedisMutationEventSink::new(&server.url())?.with_metrics(notification_metrics);
    let mut receiver = hub.subscribe();
    let event = MutationEvent::mailbox_changed(Some(7), Some(11), "refresh_mailbox_counts");

    sink.publish(event.clone()).await?;
    let received = tokio::time::timeout(Duration::from_secs(2), receiver.recv()).await??;
    assert_eq!(received, event);
    assert_eq!(metrics.redis_pubsub_events_published(), 1);
    assert_eq!(metrics.redis_pubsub_events_relayed(), 1);

    relay_task.abort();
    Ok(())
}

#[tokio::test]
async fn redis_mutation_events_fan_out_to_multiple_hubs() -> anyhow::Result<()> {
    let server = FakeRedisServer::start().await?;
    let hub_a = Arc::new(MailboxEventHub::new(16));
    let hub_b = Arc::new(MailboxEventHub::new(16));
    let relay_a = RedisMutationEventRelay::new(&server.url(), Arc::clone(&hub_a))?;
    let relay_b = RedisMutationEventRelay::new(&server.url(), Arc::clone(&hub_b))?;
    let relay_a_task = tokio::spawn(async move { relay_a.run().await });
    let relay_b_task = tokio::spawn(async move { relay_b.run().await });

    tokio::time::timeout(Duration::from_secs(5), server.wait_for_subscribers(2)).await?;

    let sink = RedisMutationEventSink::new(&server.url())?;
    let event = MutationEvent::mailbox_changed(Some(7), Some(11), "refresh_mailbox_counts");
    let mut receiver_a = hub_a.subscribe();
    let mut receiver_b = hub_b.subscribe();

    sink.publish(event.clone()).await?;
    let received_a = tokio::time::timeout(Duration::from_secs(2), receiver_a.recv()).await??;
    let received_b = tokio::time::timeout(Duration::from_secs(2), receiver_b.recv()).await??;
    assert_eq!(received_a, event);
    assert_eq!(received_b, event);

    relay_a_task.abort();
    relay_b_task.abort();
    Ok(())
}

#[tokio::test]
async fn redis_pubsub_stream_receives_messages_from_fake_server() -> anyhow::Result<()> {
    let server = FakeRedisServer::start().await?;
    let client = redis::Client::open(server.url())?;
    let mut pubsub = client.get_async_pubsub().await?;
    pubsub.subscribe("imap:mutations").await?;
    let mut messages = pubsub.on_message();

    let sink = RedisMutationEventSink::new(&server.url())?;
    let event = MutationEvent::mailbox_changed(Some(7), Some(11), "refresh_mailbox_counts");
    sink.publish(event.clone()).await?;

    let message = tokio::time::timeout(Duration::from_secs(2), messages.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("pubsub stream ended unexpectedly"))?;
    let payload_bytes = message.get_payload_bytes();
    let payload = std::str::from_utf8(payload_bytes)?;
    let parsed: MutationEvent = serde_json::from_str(payload)?;
    assert_eq!(parsed, event);
    Ok(())
}

#[tokio::test]
async fn redis_sync_lock_manager_acquires_and_releases_locks() -> anyhow::Result<()> {
    let server = FakeRedisServer::start().await?;
    let manager = RedisSyncLockManager::new(&server.url())?;

    let lock = manager
        .acquire("sync:account:1", Duration::from_secs(60))
        .await?
        .expect("first lock should be granted");
    assert!(
        manager
            .acquire("sync:account:1", Duration::from_secs(60))
            .await?
            .is_none()
    );

    drop(lock);
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(
        manager
            .acquire("sync:account:1", Duration::from_secs(60))
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn redis_bootstrap_authenticator_blocks_after_repeated_failures() -> anyhow::Result<()> {
    let server = FakeRedisServer::start().await?;
    let config = Config {
        redis_url: Some(server.url()),
        bootstrap_imap_username: Some("user@example.test".to_string()),
        bootstrap_imap_password: Some("secret-password".to_string()),
        ..Config::default()
    };
    let authenticator = bootstrap_authenticator(&config, None)?;

    for _ in 0..5 {
        assert!(
            authenticator
                .authenticate("user@example.test", "wrong-password")
                .await?
                .is_none()
        );
    }

    assert!(
        authenticator
            .authenticate("user@example.test", "secret-password")
            .await?
            .is_none(),
        "redis-backed throttling should block the correct password after repeated failures"
    );
    Ok(())
}
