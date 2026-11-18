//! One loopback HTTP server for every test that needs an API to talk to.
//!
//! It reads each request in full, records it, and answers with whatever the
//! test's responder returns. The helpers below cover the common shapes.

use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// One request the fake API received.
#[derive(Debug, Clone)]
pub(crate) struct Received {
    /// `POST /authenticate HTTP/1.1`.
    pub request_line: String,
    /// The header line as sent, lowercased name included, or empty.
    pub authorization: String,
    pub body: String,
}

pub(crate) type Seen = Arc<Mutex<Vec<Received>>>;

/// Picks the reply to a request: a status line such as `"200 OK"`, and a body.
pub(crate) type Responder = Arc<dyn Fn(&Received) -> (String, String) + Send + Sync>;

/// A loopback API that answers every request through `respond`, until the
/// test ends, and records what it received.
pub(crate) async fn api_with(respond: Responder) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let base = format!("http://{}", listener.local_addr().expect("local addr"));
    let seen: Seen = Arc::default();
    let recorded = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let recorded = recorded.clone();
            let respond = respond.clone();
            tokio::spawn(async move {
                let request = read_request(&mut socket).await;
                recorded.lock().unwrap().push(request.clone());
                let (status, body) = respond(&request);
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (base, seen)
}

/// A loopback API that answers every request with `status` and `body`.
/// `on_request` runs before the reply goes out, so a test can change the
/// agent's state while a request is in flight.
pub(crate) async fn api(
    status: impl Into<String>,
    body: String,
    on_request: Arc<dyn Fn() + Send + Sync>,
) -> (String, Seen) {
    let status = status.into();
    api_with(Arc::new(move |_: &Received| {
        on_request();
        (status.clone(), body.clone())
    }))
    .await
}

/// An `on_request` that does nothing.
pub(crate) fn nothing() -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(|| {})
}

/// A base URL nothing listens on: the port was bound, read, and released.
pub(crate) async fn api_that_is_down() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    format!("http://{}", listener.local_addr().expect("local addr"))
}

/// Read the head, then as much body as `Content-Length` says.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Received {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = socket.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf);
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end]
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + length {
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    Received {
        request_line: head.lines().next().unwrap_or("").to_string(),
        authorization: head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
            .unwrap_or("")
            .to_string(),
        body: body.to_string(),
    }
}
