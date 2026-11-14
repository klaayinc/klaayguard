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
//! that was fine. Signing out stays where it was: the collection cycle, on a
//! 401 from the data endpoints.
//!
//! A 201 is a point of no return. Kiln revokes the token it replaces when that
//! token names an account (kiln #6080). So the agent takes any token a 201
//! carries, even one that looks wrong to it, and reports what looks wrong. The
//! old token would fail at the next cycle anyway.

use serde_json::{json, Value};

use base64::Engine;

/// Renew once the token has fewer than this many seconds left. Fourteen days
/// leaves room for a laptop that sits closed for a week or two.
pub const RENEW_WITHIN_SECS: u64 = 14 * 24 * 60 * 60;

/// The least time between two renewal requests the server answered. A device
/// whose renewal is refused (some SSO accounts answer 403 for weeks) asks four
/// times a day rather than on every 15-minute cycle. `/authenticate` allows five
/// requests a minute, and an office of agents shares one address. A request
/// that never reached the server waits only for the next cycle.
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

/// A JWT's payload as JSON. `None` when the token is not a JWT this code can
/// read.
pub fn payload(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let (_header, payload, _signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    // JWTs drop the padding; tolerate a token that kept it.
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Read the claims from a JWT's payload. `None` when the token is not a JWT
/// this code can read.
pub fn claims(token: &str) -> Option<Claims> {
    let body = payload(token)?;
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
    /// A 201 whose body carries no token at all.
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

/// A token the server issued, and whatever about it looks wrong to the agent.
/// The agent takes it either way: the server may already have revoked the old
/// one.
#[derive(Debug, PartialEq)]
pub struct Issued {
    pub token: String,
    pub anomalies: Vec<&'static str>,
}

/// What looks wrong about `new`, the token issued to replace one with
/// `current` claims. Empty when nothing does.
pub fn anomalies(current: &Claims, new: &str) -> Vec<&'static str> {
    let Some(issued) = claims(new) else {
        return vec!["the new token is unreadable"];
    };
    let mut found = Vec::new();
    match (issued.exp, current.exp) {
        (None, _) => found.push("the new token carries no exp"),
        (Some(new_exp), Some(old_exp)) if new_exp <= old_exp => {
            found.push("the new token expires no later")
        }
        _ => {}
    }
    // An account-less token may gain an account (kiln picks a person's only
    // one). A token that named an account must keep it.
    if current.account_id.is_some() && issued.account_id != current.account_id {
        found.push("the new token names another account");
    }
    found
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

/// Ask the API for a token to replace `token`.
pub async fn request_renewal(
    client: &reqwest::Client,
    api_base_url: &str,
    token: &str,
    current: &Claims,
) -> Result<Issued, Failure> {
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
    Ok(Issued {
        token: new.to_string(),
        anomalies: anomalies(current, new),
    })
}

/// How the background save of a renewed token went.
#[derive(Debug)]
pub struct SaveResult {
    pub token: String,
    pub outcome: Result<crate::keychain::CredentialStore, String>,
}

/// When the next renewal request may go out, and a renewed token the
/// credential store has not yet accepted.
///
/// Times are wall-clock seconds, the clock `exp` is read against. A monotonic
/// clock stops while the machine sleeps, so "6 hours" would mean 6 hours awake:
/// days, on a laptop that is open two hours a day.
#[derive(Debug)]
pub struct Schedule {
    pub within_secs: u64,
    pub retry_after_secs: u64,
    pub next_try_at: Option<i64>,
    /// A renewed token the store refused. The agent holds it in memory, and
    /// the old one in the store may already be revoked, so the save is tried
    /// again on every tick until it lands.
    pub unsaved: Option<String>,
    /// The save of a renewed token, while it runs beside the loop.
    pub pending_save: Option<tokio::task::JoinHandle<SaveResult>>,
    /// The unsaved token whose refusal was already reported.
    pub reported_unsaved: Option<String>,
    /// How many refused saves were reported. Read by the tests.
    pub save_failure_reports: u32,
}

impl Schedule {
    pub fn new(within_secs: u64, retry_after_secs: u64) -> Self {
        Self {
            within_secs,
            retry_after_secs,
            next_try_at: None,
            unsaved: None,
            pending_save: None,
            reported_unsaved: None,
            save_failure_reports: 0,
        }
    }

    fn retry_after(&self) -> i64 {
        i64::try_from(self.retry_after_secs).unwrap_or(i64::MAX)
    }

    /// Whether a request may go out at `now_unix`. A wait longer than a whole
    /// retry period means the clock was set back since: try now rather than
    /// wait out the jump.
    pub fn may_try(&self, now_unix: i64) -> bool {
        match self.next_try_at {
            None => true,
            Some(at) => now_unix >= at || at.saturating_sub(now_unix) > self.retry_after(),
        }
    }

    /// Record a request the server answered, whatever the answer. The next one
    /// waits `retry_after_secs`. A success waits too: a clock running weeks
    /// fast would otherwise find every new token due and renew on every tick.
    pub fn record_answered(&mut self, now_unix: i64) {
        self.next_try_at = Some(now_unix.saturating_add(self.retry_after()));
    }

    /// Record a request that never reached the server. A laptop that wakes
    /// before its network is up must not spend six hours on that.
    pub fn record_unanswered(&mut self) {
        self.next_try_at = None;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_api::{api, api_that_is_down, nothing};
    use std::time::Duration;

    const DAY: i64 = 24 * 60 * 60;
    const NOW: i64 = 1_795_000_000; // 2026-11-17
    const RETRY: u64 = RETRY_AFTER_SECS;

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
        crate::http_client(Some(Duration::from_secs(10)))
    }

    fn scoped(exp: i64) -> Claims {
        Claims {
            exp: Some(exp),
            account_id: Some("42".into()),
        }
    }

    // --- Reading the token --------------------------------------------------

    #[test]
    fn reads_exp_and_a_numeric_account() {
        let token =
            jwt(json!({ "user_id": 7, "account_id": 42, "exp": NOW, "client": "klaayguard" }));
        assert_eq!(
            claims(&token),
            Some(Claims {
                exp: Some(NOW),
                account_id: Some("42".into())
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
        let payload = json!({ "account_id": "42", "exp": NOW }).to_string();
        let padded = base64::engine::general_purpose::URL_SAFE.encode(payload.as_bytes());
        let token = format!("e30.{padded}.c2ln");
        assert_eq!(
            claims(&token).and_then(|c| c.account_id),
            Some("42".to_string())
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
    fn an_answered_try_waits_six_hours_of_wall_clock() {
        let mut schedule = Schedule::new(RENEW_WITHIN_SECS, RETRY);
        assert!(schedule.may_try(NOW));
        schedule.record_answered(NOW);
        assert!(!schedule.may_try(NOW + RETRY as i64 - 1));
        // Seconds of wall clock, so hours asleep count.
        assert!(schedule.may_try(NOW + RETRY as i64));
    }

    #[test]
    fn an_unanswered_try_waits_for_nothing() {
        let mut schedule = Schedule::new(RENEW_WITHIN_SECS, RETRY);
        schedule.record_answered(NOW);
        schedule.record_unanswered();
        assert!(schedule.may_try(NOW + 1));
    }

    #[test]
    fn a_clock_set_back_does_not_park_the_schedule() {
        let mut schedule = Schedule::new(RENEW_WITHIN_SECS, RETRY);
        schedule.record_answered(NOW);
        // The clock jumps back a day: the wait would be 30 hours.
        assert!(schedule.may_try(NOW - DAY));
    }

    // --- What looks wrong about a new token --------------------------------

    #[test]
    fn a_new_token_like_the_old_one_raises_nothing() {
        let new = jwt(json!({ "exp": NOW + 90 * DAY, "account_id": 42 }));
        assert!(anomalies(&scoped(NOW + DAY), &new).is_empty());
    }

    #[test]
    fn an_account_less_token_may_gain_an_account() {
        let current = Claims {
            exp: Some(NOW + DAY),
            account_id: None,
        };
        let new = jwt(json!({ "exp": NOW + 90 * DAY, "account_id": 42 }));
        assert!(anomalies(&current, &new).is_empty());
    }

    #[test]
    fn a_token_that_named_an_account_must_keep_it() {
        let other = jwt(json!({ "exp": NOW + 90 * DAY, "account_id": 43 }));
        let none = jwt(json!({ "exp": NOW + 90 * DAY }));
        let flagged = vec!["the new token names another account"];
        assert_eq!(anomalies(&scoped(NOW + DAY), &other), flagged);
        assert_eq!(anomalies(&scoped(NOW + DAY), &none), flagged);
    }

    #[test]
    fn an_unreadable_or_shorter_token_is_flagged() {
        assert_eq!(
            anomalies(&scoped(NOW + DAY), "opaque"),
            vec!["the new token is unreadable"]
        );
        let same = jwt(json!({ "exp": NOW + DAY, "account_id": 42 }));
        assert_eq!(
            anomalies(&scoped(NOW + DAY), &same),
            vec!["the new token expires no later"]
        );
        let no_exp = jwt(json!({ "account_id": 42 }));
        assert_eq!(
            anomalies(&scoped(NOW + DAY), &no_exp),
            vec!["the new token carries no exp"]
        );
    }

    // --- The request --------------------------------------------------------

    #[test]
    fn the_body_names_the_tokens_account() {
        assert_eq!(
            request_body(Some("42")),
            json!({
                "data": {
                    "type": "authentication",
                    "attributes": {},
                    "relationships": { "account": { "data": { "type": "accounts", "id": "42" } } }
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
        let new = jwt(json!({ "exp": NOW + 90 * DAY, "account_id": 42 }));
        let (base, seen) = api("201 Created", issued(&new), nothing()).await;
        let old = jwt(json!({ "exp": NOW + DAY, "account_id": 42 }));

        let got = request_renewal(&client(), &base, &old, &scoped(NOW + DAY)).await;

        assert_eq!(
            got,
            Ok(Issued {
                token: new,
                anomalies: vec![]
            })
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].request_line, "POST /authenticate HTTP/1.1");
        assert_eq!(
            seen[0].authorization,
            format!("authorization: Bearer {old}")
        );
        let sent: Value = serde_json::from_str(&seen[0].body).unwrap();
        assert_eq!(sent, request_body(Some("42")));
    }

    // The server may already have revoked the old token. A token it issued
    // that looks wrong is still the only one that can work.
    #[tokio::test]
    async fn a_201_whose_token_looks_wrong_is_still_returned() {
        let (base, _) = api("201 Created", issued("opaque"), nothing()).await;
        let got = request_renewal(&client(), &base, "old", &scoped(NOW + DAY)).await;
        assert_eq!(
            got,
            Ok(Issued {
                token: "opaque".into(),
                anomalies: vec!["the new token is unreadable"]
            })
        );
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
        let base = api_that_is_down().await;
        let got = request_renewal(&client(), &base, "old", &scoped(NOW + DAY)).await;
        assert!(matches!(got, Err(Failure::Network(_))), "{got:?}");
    }

    #[tokio::test]
    async fn a_201_without_a_token_is_a_failure() {
        let (base, _) = api("201 Created", r#"{"data":{}}"#.into(), nothing()).await;
        let got = request_renewal(&client(), &base, "old", &scoped(NOW + DAY)).await;
        assert!(matches!(got, Err(Failure::Malformed(_))), "{got:?}");
    }
}
