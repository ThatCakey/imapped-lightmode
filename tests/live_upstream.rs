use imap_cache_rs::{
    domain::{UpstreamAuthMethod, UpstreamTlsMode},
    upstream::{UpstreamAccountConfig, UpstreamClient},
};
use imap_cache_test_support::{
    live_test_guard as support_live_test_guard,
    load_testing_credentials as load_live_testing_credentials,
};
use std::time::Duration;

fn testing_upstream_config() -> anyhow::Result<UpstreamAccountConfig> {
    let creds = load_live_testing_credentials()?;
    Ok(UpstreamAccountConfig {
        host: creds.imap_host,
        port: creds.imap_port,
        tls_mode: UpstreamTlsMode::Tls,
        auth_method: UpstreamAuthMethod::Login,
        username: creds.username,
        secret: creds.password,
    })
}

fn load_testing_credentials() -> anyhow::Result<UpstreamAccountConfig> {
    testing_upstream_config()
}

async fn create_mailbox(client: &mut UpstreamClient, mailbox: &str) -> anyhow::Result<()> {
    let response = client
        .send_command("CREATE", &[format!("\"{}\"", mailbox)])
        .await?;
    if response.tagged.starts_with("NO ") || response.tagged.starts_with("BAD ") {
        return Err(anyhow::anyhow!("CREATE failed: {}", response.tagged));
    }
    Ok(())
}

async fn delete_mailbox(client: &mut UpstreamClient, mailbox: &str) -> anyhow::Result<()> {
    let response = client
        .send_command("DELETE", &[format!("\"{}\"", mailbox)])
        .await?;
    if response.tagged.starts_with("NO ") || response.tagged.starts_with("BAD ") {
        return Err(anyhow::anyhow!("DELETE failed: {}", response.tagged));
    }
    Ok(())
}

#[tokio::test]
async fn real_upstream_tls_login_and_capability() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = load_testing_credentials()?;
    let mut client =
        tokio::time::timeout(Duration::from_secs(20), UpstreamClient::connect(&config)).await??;

    let caps = tokio::time::timeout(Duration::from_secs(20), client.capability()).await??;
    assert!(!caps.is_empty(), "real server returned no capabilities");

    tokio::time::timeout(
        Duration::from_secs(20),
        client.authenticate_with_method(config.auth_method, &config.username, &config.secret),
    )
    .await??;
    let mailboxes =
        tokio::time::timeout(Duration::from_secs(20), client.list_mailboxes()).await??;
    assert!(
        mailboxes
            .iter()
            .any(|mailbox| mailbox.eq_ignore_ascii_case("INBOX")),
        "real server did not list INBOX"
    );
    tokio::time::timeout(Duration::from_secs(20), client.noop()).await??;
    tokio::time::timeout(Duration::from_secs(20), client.logout()).await??;
    Ok(())
}

#[tokio::test]
async fn real_upstream_copy_round_trip_with_cleanup() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = testing_upstream_config()?;
    let source_mailbox = format!("imap-cache-rs-src-{}", uuid::Uuid::new_v4());
    let destination_mailbox = format!("imap-cache-rs-dst-{}", uuid::Uuid::new_v4());
    let unique_subject = format!("imap-cache-rs-copy-{}", uuid::Uuid::new_v4());
    let raw = format!(
        concat!(
            "From: Live Test <live-test@example.test>\r\n",
            "To: Live Test <live-test@example.test>\r\n",
            "Subject: {subject}\r\n",
            "Message-ID: <{subject}@example.test>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Live copy body for {subject}\r\n",
        ),
        subject = unique_subject
    );

    let mut client =
        tokio::time::timeout(Duration::from_secs(20), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(Duration::from_secs(20), client.authenticate_with_method(
        config.auth_method,
        &config.username,
        &config.secret,
    ))
    .await??;

    let created_source = tokio::time::timeout(
        Duration::from_secs(20),
        create_mailbox(&mut client, &source_mailbox),
    )
    .await;
    if let Err(err) = &created_source {
        let _ = tokio::time::timeout(
            Duration::from_secs(20),
            client.logout(),
        )
        .await;
        return Err(anyhow::anyhow!(err.to_string()));
    }
    created_source??;

    let created_destination = tokio::time::timeout(
        Duration::from_secs(20),
        create_mailbox(&mut client, &destination_mailbox),
    )
    .await;
    if let Err(err) = &created_destination {
        let _ = tokio::time::timeout(
            Duration::from_secs(20),
            delete_mailbox(&mut client, &source_mailbox),
        )
        .await;
        let _ = tokio::time::timeout(Duration::from_secs(20), client.logout()).await;
        return Err(anyhow::anyhow!(err.to_string()));
    }
    created_destination??;

    let appended_uid = tokio::time::timeout(
        Duration::from_secs(20),
        client.append_with_internal_date(
            &source_mailbox,
            &[String::from("\\Seen")],
            Some(chrono::Utc::now()),
            raw.as_bytes(),
        ),
    )
    .await??;
    let appended_uid = appended_uid.ok_or_else(|| anyhow::anyhow!("missing APPENDUID"))?;

    tokio::time::timeout(
        Duration::from_secs(20),
        client.select_mailbox(&source_mailbox),
    )
    .await??;
    let source_uids =
        tokio::time::timeout(Duration::from_secs(20), client.uid_search_all()).await??;
    assert!(source_uids.contains(&appended_uid));

    let copied_uid = tokio::time::timeout(
        Duration::from_secs(20),
        client.uid_copy_message(appended_uid, &destination_mailbox),
    )
    .await??;

    tokio::time::timeout(
        Duration::from_secs(20),
        client.select_mailbox(&destination_mailbox),
    )
    .await??;
    let destination_uids =
        tokio::time::timeout(Duration::from_secs(20), client.uid_search_all()).await??;
    assert!(destination_uids.contains(&copied_uid));
    let copied_raw =
        tokio::time::timeout(Duration::from_secs(20), client.uid_fetch_rfc822(copied_uid)).await??;
    assert_eq!(copied_raw, raw.as_bytes());

    tokio::time::timeout(
        Duration::from_secs(20),
        client.uid_store_flags(copied_uid, &[String::from("\\Deleted")]),
    )
    .await??;
    tokio::time::timeout(Duration::from_secs(20), client.expunge_selected()).await??;

    tokio::time::timeout(
        Duration::from_secs(20),
        client.select_mailbox(&source_mailbox),
    )
    .await??;
    tokio::time::timeout(
        Duration::from_secs(20),
        client.uid_store_flags(appended_uid, &[String::from("\\Deleted")]),
    )
    .await??;
    tokio::time::timeout(Duration::from_secs(20), client.expunge_selected()).await??;

    tokio::time::timeout(
        Duration::from_secs(20),
        delete_mailbox(&mut client, &destination_mailbox),
    )
    .await??;
    tokio::time::timeout(Duration::from_secs(20), delete_mailbox(&mut client, &source_mailbox))
        .await??;
    tokio::time::timeout(Duration::from_secs(20), client.logout()).await??;

    Ok(())
}

#[tokio::test]
async fn real_upstream_move_round_trip_with_cleanup() -> anyhow::Result<()> {
    let _live_guard = support_live_test_guard().await;
    let config = testing_upstream_config()?;
    let source_mailbox = format!("imap-cache-rs-move-src-{}", uuid::Uuid::new_v4());
    let destination_mailbox = format!("imap-cache-rs-move-dst-{}", uuid::Uuid::new_v4());
    let unique_subject = format!("imap-cache-rs-move-{}", uuid::Uuid::new_v4());
    let raw = format!(
        concat!(
            "From: Live Test <live-test@example.test>\r\n",
            "To: Live Test <live-test@example.test>\r\n",
            "Subject: {subject}\r\n",
            "Message-ID: <{subject}@example.test>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Live move body for {subject}\r\n",
        ),
        subject = unique_subject
    );

    let mut client =
        tokio::time::timeout(Duration::from_secs(20), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(
        Duration::from_secs(20),
        client.authenticate_with_method(
            config.auth_method,
            &config.username,
            &config.secret,
        ),
    )
    .await??;

    let result: anyhow::Result<()> = async {
        create_mailbox(&mut client, &source_mailbox).await?;
        create_mailbox(&mut client, &destination_mailbox).await?;

        let appended_uid = client
            .append_with_internal_date(
                &source_mailbox,
                &[String::from("\\Seen")],
                Some(chrono::Utc::now()),
                raw.as_bytes(),
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing APPENDUID"))?;

        client.select_mailbox(&source_mailbox).await?;
        let source_before = client.uid_search_all().await?;
        assert_eq!(source_before, vec![appended_uid]);

        let moved_uid = client
            .uid_move_message(appended_uid, &destination_mailbox)
            .await?;

        client.select_mailbox(&source_mailbox).await?;
        let source_after = client.uid_search_all().await?;
        assert!(
            source_after.is_empty(),
            "source mailbox should be empty after MOVE"
        );

        client.select_mailbox(&destination_mailbox).await?;
        let destination_uids = client.uid_search_all().await?;
        assert_eq!(destination_uids, vec![moved_uid]);
        let moved_raw = client.uid_fetch_rfc822(moved_uid).await?;
        assert_eq!(moved_raw, raw.as_bytes());

        Ok(())
    }
    .await;

    let _ = tokio::time::timeout(
        Duration::from_secs(20),
        delete_mailbox(&mut client, &destination_mailbox),
    )
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(20), delete_mailbox(&mut client, &source_mailbox))
        .await;
    let _ = tokio::time::timeout(Duration::from_secs(20), client.logout()).await;

    result
}

#[tokio::test]
async fn real_upstream_append_search_and_fetch_round_trip() -> anyhow::Result<()> {
    let config = testing_upstream_config()?;
    let mailbox = format!("imap-cache-rs-search-{}", uuid::Uuid::new_v4());
    let unique_subject = format!("imap-cache-rs-search-{}", uuid::Uuid::new_v4());
    let raw = format!(
        concat!(
            "From: Live Test <live-test@example.test>\r\n",
            "To: Live Test <live-test@example.test>\r\n",
            "Subject: {subject}\r\n",
            "Message-ID: <{subject}@example.test>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Live search body for {subject}\r\n",
        ),
        subject = unique_subject
    );

    let mut client =
        tokio::time::timeout(Duration::from_secs(20), UpstreamClient::connect(&config)).await??;
    tokio::time::timeout(
        Duration::from_secs(20),
        client.authenticate_with_method(
            config.auth_method,
            &config.username,
            &config.secret,
        ),
    )
    .await??;

    let result: anyhow::Result<()> = async {
        create_mailbox(&mut client, &mailbox).await?;
        let appended_uid = client
            .append_with_internal_date(
                &mailbox,
                &[String::from("\\Seen")],
                Some(chrono::Utc::now()),
                raw.as_bytes(),
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing APPENDUID"))?;

        client.select_mailbox(&mailbox).await?;
        let selection = client.select_mailbox(&mailbox).await?;
        assert_eq!(selection.exists, Some(1));
        assert!(client.uid_search_all().await?.contains(&appended_uid));
        let fetched = client.uid_fetch_rfc822(appended_uid).await?;
        assert_eq!(fetched, raw.as_bytes());

        client
            .uid_store_flags(appended_uid, &[String::from("\\Deleted")])
            .await?;
        client.expunge_selected().await?;
        Ok(())
    }
    .await;

    let _ = tokio::time::timeout(Duration::from_secs(20), delete_mailbox(&mut client, &mailbox))
        .await;
    let _ = tokio::time::timeout(Duration::from_secs(20), client.logout()).await;

    result
}
