//! Browser sign-in over a loopback port.
//!
//! The agent has no window, so it cannot show a code and it cannot host a
//! sign-in form. It borrows the browser, which is what makes Google,
//! Microsoft, and password sign-in all work here without this process
//! knowing anything about them.
//!
//! What changed is how the token comes back. It used to arrive on a
//! `klaayguard://` URL, a scheme RFC 8252 §7.1 names as claimable by any
//! local program, carrying the token in its query. Now the agent listens on
//! `127.0.0.1`, tells the server only which port and the SHA-256 of a secret
//! it keeps, and the browser is redirected to that port with a one-time
//! code. Two things follow:
//!
//! - Nobody remote can receive a redirect to this machine's loopback
//!   address, so the token binds to the machine that asked for it. No
//!   `state` nonce to check, and no confused deputy to worry about.
//! - A local program that does read the code still cannot spend it. The
//!   verifier never leaves this process (RFC 7636).

use base64::Engine;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::Duration;

/// How long the listener waits for the browser before giving up. The server
/// expires the request in five minutes; this is the local backstop.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(360);

/// A sign-in that has been registered with the server and is waiting for the
/// browser to come back.
pub struct Pending {
    /// The id the browser carries. Not a secret: it selects a row and
    /// nothing else.
    pub request_id: String,
    /// The secret that claims the token. Never leaves this process.
    pub verifier: String,
    pub listener: TcpListener,
}

/// The browser can only deliver the code to this machine, so a remote attacker
/// never receives it. Named so a test can assert the address this code binds,
/// not one the test binds itself.
fn bind_loopback() -> std::io::Result<TcpListener> {
    TcpListener::bind("127.0.0.1:0")
}

/// Binds a loopback port and registers the sign-in. Binds first, because the
/// server has to be told the real port and the OS only names it once the
/// socket exists.
pub async fn start(api_base_url: &str) -> Result<Pending, String> {
    let listener = bind_loopback().map_err(|e| format!("could not bind loopback: {e}"))?;
    listener
        .set_nonblocking(false)
        .map_err(|e| format!("could not configure loopback: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("could not read loopback port: {e}"))?
        .port();

    let verifier = random_secret().ok_or("no OS randomness for the sign-in secret")?;
    let body = serde_json::json!({
        "data": {
            "type": "cli_auth_requests",
            "attributes": {
                "kind": "loopback",
                "client": "klaayguard",
                "code_challenge": challenge_for(&verifier),
                "redirect_port": port,
            }
        }
    });

    let response = reqwest::Client::new()
        .post(format!("{}/cli_auth_requests", api_base_url))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("could not reach the server: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("server refused the sign-in: {}", response.status()));
    }
    let parsed: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("could not read the server's reply: {e}"))?;
    let request_id = parsed
        .pointer("/data/attributes/request_id")
        .and_then(|v| v.as_str())
        .ok_or("the server named no request to approve")?
        .to_string();

    Ok(Pending {
        request_id,
        verifier,
        listener,
    })
}

/// Serves exactly one request, answers with a page telling the person they
/// can close the tab, and returns the code the browser carried. No HTTP
/// server dependency: one request line is all this has to understand.
pub fn wait_for_code(listener: TcpListener) -> Option<String> {
    let stream = listener.incoming().next()?.ok()?;
    let _ = stream.set_read_timeout(Some(LISTEN_TIMEOUT));
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;

    let code = code_from_request_line(&request_line);
    let page = match &code {
        Some(_) => "<!doctype html><meta charset=utf-8><title>Signed in</title><p>KlaayGuard is signed in. You can close this window.",
        None => "<!doctype html><meta charset=utf-8><title>Sign-in failed</title><p>That reply carried no sign-in code. Open KlaayGuard from the tray and try again.",
    };
    let stream = reader.get_mut();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.flush();
    code
}

/// Exchanges the one-time code and the verifier for the token. The server
/// checks the verifier against the challenge registered in `start`, so a
/// code alone - read from the loopback reply by another local program, say -
/// buys nothing.
pub async fn claim(api_base_url: &str, code: &str, verifier: &str) -> Result<String, String> {
    let body = serde_json::json!({
        "data": {
            "type": "cli_auth_requests",
            "attributes": { "code": code, "code_verifier": verifier }
        }
    });
    let response = reqwest::Client::new()
        .post(format!("{}/cli_auth_requests/claim", api_base_url))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("could not reach the server: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("the sign-in was refused: {}", response.status()));
    }
    let parsed: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("could not read the server's reply: {e}"))?;
    parsed
        .pointer("/data/attributes/token")
        .and_then(|v| v.as_str())
        .map(|t| t.to_string())
        .ok_or_else(|| "the sign-in completed but carried no token".to_string())
}

/// 32 random bytes, base64url-encoded - the PKCE verifier.
fn random_secret() -> Option<String> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

/// S256, the only challenge method this flow offers. The server stores this
/// and can prove nothing from it, because a hash cannot be run backwards.
fn challenge_for(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Pulls `code` out of `GET /?code=… HTTP/1.1`.
fn code_from_request_line(line: &str) -> Option<String> {
    let target = line.split_whitespace().nth(1)?;
    let query = target.split_once('?')?.1;
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "code")
        .map(|(_, value)| value.to_string())
        .filter(|code| !code.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7636's own S256 example. This is the one value the server checks
    // the verifier against, so it is worth pinning to the spec rather than
    // to whatever this code happens to produce.
    #[test]
    fn challenge_is_the_rfc_7636_s256_example() {
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn secret_is_43_base64url_chars() {
        let secret = random_secret().expect("OS randomness");
        assert_eq!(secret.len(), 43);
        assert!(secret
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn two_secrets_differ() {
        assert_ne!(random_secret(), random_secret());
    }

    #[test]
    fn code_comes_out_of_the_request_line() {
        assert_eq!(
            code_from_request_line("GET /?code=abc123 HTTP/1.1\r\n"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn code_is_found_among_other_parameters() {
        assert_eq!(
            code_from_request_line("GET /?other=x&code=abc123&more=y HTTP/1.1\r\n"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn a_reply_with_no_code_yields_none() {
        assert!(code_from_request_line("GET / HTTP/1.1\r\n").is_none());
        assert!(code_from_request_line("GET /?code= HTTP/1.1\r\n").is_none());
        assert!(code_from_request_line("nonsense\r\n").is_none());
    }

    // The whole point of the port: the browser can only deliver the code to
    // this machine, so a remote attacker never receives it. This calls the
    // function `start` uses, so widening that address fails here.
    #[test]
    fn the_listener_binds_loopback_only() {
        let listener = bind_loopback().expect("bind");
        let addr = listener.local_addr().expect("addr");
        assert!(addr.ip().is_loopback());
        assert!(addr.port() >= 1024);
    }
}
