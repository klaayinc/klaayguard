//! Renew the device token before it expires (PROD-4397).
//!
//! Kiln gives a KlaayGuard token three months, and nothing used to renew it. On
//! the day it expired the agent got a 401, signed out, and the device went
//! silent until somebody signed in again.
//!
//! The agent now reads the token's own `exp`. Once fewer than 14 days are left
//! it presents the token to `POST /authenticate`, whose upgrade mode answers
//! with a fresh three-month token for the same person, client and account. It
//! stores the new token and uses it from the next request on.
//!
//! A renewal that fails, for any reason, keeps the token the agent has. A
//! token with days left still works, so dropping it would sign out a device
//! that was fine. The agent asks again a few hours later. Signing out stays
//! where it was: the collection cycle, on a 401 from the data endpoints.
//!
//! A 201 is a point of no return. Kiln revokes the token it replaces when that
//! token names an account (kiln #6080), so the new token must be held and
//! stored before anything else uses one.

use serde_json::{json, Value};
use std::time::{Duration, Instant};

use base64::Engine;

/// Renew once the token has fewer than this many seconds left. Fourteen days
/// leaves room for a laptop that sits closed for a week or two.
pub const RENEW_WITHIN_SECS: u64 = 14 * 24 * 60 * 60;

/// The least time between two renewal requests. A device whose renewal fails
/// (some SSO accounts answer 403 for weeks) asks four times a day rather than
/// on every 15-minute cycle. `/authenticate` allows five requests a minute, and
/// an office of agents shares one address.
pub const RETRY_AFTER_SECS: u64 = 6 * 60 * 60;

/// What the agent reads from its own token. The signature is not checked: the
/// agent holds no key, and it only decides when to ask. The server checks the
/// token it is shown.
#[derive(Debug, Clone, PartialEq)]
pub struct Claims {
    /// Seconds since the Unix epoch. `None` when the token carries no `exp`.
    pub exp: Option<i64>,
    /// The account the token names, as text. `None` for an account-less token.
    pub account_id: Option<String>,
}

/// Read the claims from a JWT's payload. `None` when the token is not a JWT
/// this code can read.
pub fn claims(token: &str) -> Option<Claims> {
    let mut parts = token.split('.');
    let (_header, payload, _signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    // JWTs drop the padding; tolerate a token that kept it.
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let body: Value = serde_json::from_slice(&bytes).ok()?;
    let body = body.as_object()?;
    let account_id = match body.get("account_id") {
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    Some(Claims {
        exp: body.get("exp").and_then(Value::as_i64),
        account_id,
    })
}

/// Whether a token that expires at `exp` is due for renewal at `now_unix`.
pub fn renewal_due(exp: i64, now_unix: i64, within_secs: u64) -> bool {
    let within = i64::try_from(within_secs).unwrap_or(i64::MAX);
    exp.saturating_sub(now_unix) < within
}

/// Why a renewal request produced no new token.
#[derive(Debug, PartialEq)]
pub enum Failure {
    /// The request did not complete: no connection, a timeout, a reset.
    Network(String),
    /// The server answered with something other than 201.
    Status(u16),
    /// A 201 whose body carries no token this agent can use.
    Malformed(&'static str),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Network(e) => write!(f, "network: {e}"),
            Failure::Status(s) => write!(f, "status {s}"),
            Failure::Malformed(why) => write!(f, "malformed reply: {why}"),
        }
    }
}

/// The body of an upgrade request. It carries no credentials: a body with an
/// email or an SSO credential is a sign-in, and kiln would not take the
/// upgrade path. It names the token's own account when the token names one.
/// Without it kiln resolves a person in several accounts to no account, and
/// the renewed token would lose its `account_id`.
pub fn request_body(account_id: Option<&str>) -> Value {
    let mut data = json!({ "type": "authentication", "attributes": {} });
    if let Some(id) = account_id {
        data["relationships"] = json!({ "account": { "data": { "type": "accounts", "id": id } } });
    }
    json!({ "data": data })
}

/// Ask the API for a token to replace `token`. Returns the new token, after
/// checking that it outlives the one it replaces.
pub async fn request_renewal(
    client: &reqwest::Client,
    api_base_url: &str,
    token: &str,
    current: &Claims,
) -> Result<String, Failure> {
    let response = client
        .post(format!("{api_base_url}/authenticate"))
        .bearer_auth(token)
        .json(&request_body(current.account_id.as_deref()))
        .send()
        .await
        .map_err(|e| Failure::Network(e.without_url().to_string()))?;
    if response.status() != reqwest::StatusCode::CREATED {
        return Err(Failure::Status(response.status().as_u16()));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|_| Failure::Malformed("body is not JSON"))?;
    let new = body
        .pointer("/data/attributes/token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .ok_or(Failure::Malformed("no token in the reply"))?;
    // A token that does not outlive the old one renews nothing, and one the
    // agent cannot read it could never renew again.
    let new_exp = claims(new)
        .and_then(|c| c.exp)
        .ok_or(Failure::Malformed("the new token carries no exp"))?;
    if current.exp.is_some_and(|old| new_exp <= old) {
        return Err(Failure::Malformed("the new token expires no later"));
    }
    Ok(new.to_string())
}

/// When the next renewal request may go out, and a renewed token the
/// credential store has not yet accepted.
#[derive(Debug)]
pub struct Schedule {
    pub within_secs: u64,
    pub retry_after: Duration,
    pub next_try_at: Option<Instant>,
    /// A renewed token the store refused. The agent holds it in memory, and
    /// the old one in the store may already be revoked, so the save is tried
    /// again on every tick until it lands.
    pub unsaved: Option<String>,
}

impl Schedule {
    pub fn new(within_secs: u64, retry_after: Duration) -> Self {
        Self {
            within_secs,
            retry_after,
            next_try_at: None,
            unsaved: None,
        }
    }

    /// Whether a request may go out at `now`.
    pub fn may_try(&self, now: Instant) -> bool {
        self.next_try_at.is_none_or(|at| now >= at)
    }

    /// Record a request at `now`, whatever its outcome. The next one waits
    /// `retry_after`. A success waits too: a clock running weeks fast would
    /// otherwise find every new token due and renew on every tick.
    pub fn record_try(&mut self, now: Instant) {
        self.next_try_at = Some(now + self.retry_after);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const DAY: i64 = 24 * 60 * 60;
    const NOW: i64 = 1_795_000_000; // 2026-11-17

    /// A token with `payload` as its claims. The header and signature are
    /// placeholders: the agent reads neither.
    pub(crate) fn jwt(payload: Value) -> String {
        let enc = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        format!(
            "{}.{}.c2ln",
            enc(br#"{"alg":"HS256"}"#),
            enc(payload.to_string().as_bytes())
        )
    }

    /// One request the fake API received.
    #[derive(Debug, Clone)]
    pub(crate) struct Received {
        pub request_line: String,
        pub authorization: String,
        pub body: String,
    }

    pub(crate) type Seen = Arc<Mutex<Vec<Received>>>;

    /// A loopback API that answers every request with `status` and `body`, and
    /// records what it received. `on_request` runs before the reply goes out,
    /// so a test can change the agent's state while a request is in flight.
    pub(crate) async fn api(
        status: &'static str,
        body: String,
        on_request: Arc<dyn Fn() + Send + Sync>,
    ) -> (String, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let seen: Seen = Arc::default();
        let recorded = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let recorded = recorded.clone();
                let body = body.clone();
                let on_request = on_request.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    // Read the head, then as much body as Content-Length says.
                    loop {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf).into_owned();
                        if let Some(end) = text.find("\r\n\r\n") {
                            let length = text[..end]
                                .lines()
                                .find_map(|l| {
                                    let l = l.to_ascii_lowercase();
                                    l.strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            if buf.len() >= end + 4 + length {
                                break;
                            }
                        }
                    }
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    let (head, req_body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                    let authorization = head
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                        .unwrap_or("")
                        .to_string();
                    recorded.lock().unwrap().push(Received {
                        request_line: head.lines().next().unwrap_or("").to_string(),
                        authorization,
                        body: req_body.to_string(),
                    });
                    on_request();
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

    pub(crate) fn nothing() -> Arc<dyn Fn() + Send + Sync> {
        Arc::new(|| {})
    }

    /// The body kiln's `AuthenticateController#jsonapi_json` sends with a 201.
    pub(crate) fn issued(token: &str) -> String {
        json!({
            "data": {
                "type": "authorization_token",
                "id": "8c1d",
                "attributes": { "token": token, "is_new_user": false },
                "relationships": { "user": { "data": { "type": "users", "id": 7 } } }
            }
        })
        .to_string()
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap()
    }

    fn scoped(exp: i64) -> Claims {
        Claims {
            exp: Some(exp),
            account_id: Some("473".into()),
        }
    }

    // --- Reading the token --------------------------------------------------

    #[test]
    fn reads_exp_and_a_numeric_account() {
        let token =
            jwt(json!({ "user_id": 7, "account_id": 473, "exp": NOW, "client": "klaayguard" }));
        assert_eq!(
            claims(&token),
            Some(Claims {
                exp: Some(NOW),
                account_id: Some("473".into())
            })
        );
    }

    #[test]
    fn reads_an_account_less_token() {
        let token = jwt(json!({ "user_id": 7, "accounts": "employed", "exp": NOW }));
        assert_eq!(
            claims(&token),
            Some(Claims {
                exp: Some(NOW),
                account_id: None
            })
        );
    }

    #[test]
    fn reads_a_string_account_and_a_padded_payload() {
        let payload = json!({ "account_id": "473", "exp": NOW }).to_string();
        let padded = base64::engine::general_purpose::URL_SAFE.encode(payload.as_bytes());
        let token = format!("e30.{padded}.c2ln");
        assert_eq!(
            claims(&token).and_then(|c| c.account_id),
            Some("473".to_string())
        );
    }

    #[test]
    fn a_token_without_exp_reads_as_none() {
        let token = jwt(json!({ "user_id": 7 }));
        assert_eq!(claims(&token).map(|c| c.exp), Some(None));
    }

    #[test]
    fn junk_is_not_a_token() {
        assert_eq!(claims(""), None);
        assert_eq!(claims("not-a-jwt"), None);
        assert_eq!(claims("a.!!!.c"), None);
        assert_eq!(claims(&format!("a.{}.c", "bm90IGpzb24")), None); // "not json"
    }

    // --- When to renew ------------------------------------------------------

    #[test]
    fn renews_inside_the_last_14_days_only() {
        let within = RENEW_WITHIN_SECS;
        assert!(!renewal_due(NOW + 90 * DAY, NOW, within));
        assert!(!renewal_due(NOW + 14 * DAY, NOW, within));
        assert!(renewal_due(NOW + 14 * DAY - 1, NOW, within));
        assert!(renewal_due(NOW + DAY, NOW, within));
        // An expired token is still asked about: the server decides.
        assert!(renewal_due(NOW - DAY, NOW, within));
    }

    #[test]
    fn the_first_try_goes_at_once_and_the_next_waits() {
        let mut schedule = Schedule::new(RENEW_WITHIN_SECS, Duration::from_secs(RETRY_AFTER_SECS));
        let t0 = Instant::now();
        assert!(schedule.may_try(t0));
        schedule.record_try(t0);
        assert!(!schedule.may_try(t0 + Duration::from_secs(RETRY_AFTER_SECS - 1)));
        assert!(schedule.may_try(t0 + Duration::from_secs(RETRY_AFTER_SECS)));
    }

    // --- The request --------------------------------------------------------

    #[test]
    fn the_body_names_the_tokens_account() {
        assert_eq!(
            request_body(Some("473")),
            json!({
                "data": {
                    "type": "authentication",
                    "attributes": {},
                    "relationships": { "account": { "data": { "type": "accounts", "id": "473" } } }
                }
            })
        );
    }

    #[test]
    fn the_body_of_an_account_less_token_names_no_account_and_no_credentials() {
        let body = request_body(None);
        assert_eq!(
            body,
            json!({ "data": { "type": "authentication", "attributes": {} } })
        );
    }

    #[tokio::test]
    async fn a_201_returns_the_new_token() {
        let new = jwt(json!({ "exp": NOW + 90 * DAY, "account_id": 473 }));
        let (base, seen) = api("201 Created", issued(&new), nothing()).await;
        let old = jwt(json!({ "exp": NOW + DAY, "account_id": 473 }));

        let got = request_renewal(&client(), &base, &old, &scoped(NOW + DAY)).await;

        assert_eq!(got, Ok(new));
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].request_line, "POST /authenticate HTTP/1.1");
        assert_eq!(
            seen[0].authorization,
            format!("authorization: Bearer {old}")
        );
        let sent: Value = serde_json::from_str(&seen[0].body).unwrap();
        assert_eq!(sent, request_body(Some("473")));
    }

    #[tokio::test]
    async fn a_401_is_a_failure_not_a_sign_out() {
        let (base, _) = api("401 Unauthorized", "{}".into(), nothing()).await;
        let got = request_renewal(&client(), &base, "old", &scoped(NOW + DAY)).await;
        assert_eq!(got, Err(Failure::Status(401)));
    }

    #[tokio::test]
    async fn a_403_sso_required_is_a_failure() {
        let body = r#"{"errors":[{"status":"403","code":"sso_required"}]}"#;
        let (base, _) = api("403 Forbidden", body.into(), nothing()).await;
        let got = request_renewal(&client(), &base, "old", &scoped(NOW + DAY)).await;
        assert_eq!(got, Err(Failure::Status(403)));
    }

    #[tokio::test]
    async fn a_rate_limit_or_a_server_error_is_a_failure() {
        for status in ["429 Too Many Requests", "500 Internal Server Error"] {
            let (base, _) = api(status, "{}".into(), nothing()).await;
            let got = request_renewal(&client(), &base, "old", &scoped(NOW + DAY)).await;
            assert!(
                matches!(got, Err(Failure::Status(429 | 500))),
                "{status}: {got:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_unreachable_server_is_a_failure() {
        // Bind, learn the port, then close it: nothing listens there.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let got = request_renewal(
            &client(),
            &format!("http://127.0.0.1:{port}"),
            "old",
            &scoped(NOW + DAY),
        )
        .await;
        assert!(matches!(got, Err(Failure::Network(_))), "{got:?}");
    }

    #[tokio::test]
    async fn a_201_without_a_token_is_a_failure() {
        let (base, _) = api("201 Created", r#"{"data":{}}"#.into(), nothing()).await;
        let got = request_renewal(&client(), &base, "old", &scoped(NOW + DAY)).await;
        assert!(matches!(got, Err(Failure::Malformed(_))), "{got:?}");
    }

    #[tokio::test]
    async fn a_201_whose_token_does_not_outlive_the_old_one_is_a_failure() {
        let same = jwt(json!({ "exp": NOW + DAY }));
        let (base, _) = api("201 Created", issued(&same), nothing()).await;
        let got = request_renewal(&client(), &base, "old", &scoped(NOW + DAY)).await;
        assert!(matches!(got, Err(Failure::Malformed(_))), "{got:?}");

        let unreadable = "not-a-jwt";
        let (base, _) = api("201 Created", issued(unreadable), nothing()).await;
        let got = request_renewal(&client(), &base, "old", &scoped(NOW + DAY)).await;
        assert!(matches!(got, Err(Failure::Malformed(_))), "{got:?}");
    }
}
