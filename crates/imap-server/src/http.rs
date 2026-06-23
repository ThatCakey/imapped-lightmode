use crate::{AppServices, error::Result};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub async fn serve(listener: TcpListener, services: Arc<AppServices>) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let services = Arc::clone(&services);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, services).await {
                tracing::warn!(%peer, error = %err, "HTTP client ended with error");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, services: Arc<AppServices>) -> Result<()> {
    let mut buffer = [0u8; 4096];
    let bytes = stream.read(&mut buffer).await?;
    if bytes == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buffer[..bytes]);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or_default();
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    let (status_line, content_type, body) = match path {
        "/metrics" => (
            "HTTP/1.1 200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            services.metrics.render(services.repository.clone()).await?,
        ),
        "/health" => (
            "HTTP/1.1 200 OK",
            "text/plain; charset=utf-8",
            "ok".to_string(),
        ),
        _ => (
            "HTTP/1.1 404 Not Found",
            "text/plain; charset=utf-8",
            "not found".to_string(),
        ),
    };

    let response = format!(
        "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}
