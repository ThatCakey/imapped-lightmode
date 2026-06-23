use imap_cache_rs::mime::parse_message;

#[test]
fn sample_message_parses_into_parts_and_preview() {
    let raw = concat!(
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

    let parsed = parse_message(raw.as_bytes()).unwrap();
    assert_eq!(parsed.mime_parts.len(), 3);
    assert!(parsed.text_preview.unwrap().contains("Hello plain world."));
    assert_eq!(
        parsed.bodystructure_json["parts"].as_array().unwrap().len(),
        2
    );
}
