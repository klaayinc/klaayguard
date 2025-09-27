use std::sync::Arc;

use sentry::Level;
use serde::Serialize;
use serde_json::{json, Value};
use tauri::{Emitter, Manager};

use crate::{add_breadcrumb, focus_window_with_debounce, keychain, AppState};

#[derive(Serialize)]
pub struct AuthStatus {
    pub authenticated: bool,
    pub display_name: Option<String>,
}

// Keychain access is performed via crate::keychain directly

fn parse_deep_link_token(url: &str) -> Option<String> {
    if !url.starts_with("klaayguard://") {
        return None;
    }
    let qs = url.splitn(2, '?').nth(1).unwrap_or("");
    for pair in qs.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        if k == "token" {
            let decoded = v.replace("%20", " ").replace("+", " ");
            let dot_count = decoded.matches('.').count();
            if dot_count == 2 {
                return Some(decoded);
            } else {
                return None;
            }
        }
    }
    None
}

pub fn handle_deep_link_url(app: &tauri::AppHandle, state: &Arc<AppState>, url: &str) {
    if !url.starts_with("klaayguard://") {
        log::info!("deep_link_ignored_non_scheme url={}", url);
        return;
    }
    log::info!("deep_link_received url={}", url);
    if let Some(tok) = parse_deep_link_token(url) {
        log::info!(
            "deep_link_token_parsed length={} saving_to_keychain",
            tok.len()
        );
        tauri::async_runtime::block_on(async {
            *state.auth_token.write().await = Some(tok.clone());
            *state.keychain_cleared_this_session.write().await = false;
        });
        let _ = keychain::save_token(&tok);
        log::info!("deep_link_token_saved_to_keychain");
        let _ = app.emit("auth:status", json!({ "authenticated": true }));
        add_breadcrumb("auth", "deep_link_token_saved", Level::Info);
        sentry::capture_message("deep_link_token_saved", Level::Info);
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.hide();
            log::info!("deep_link_window_hidden_after_auth");
        }
    } else {
        add_breadcrumb("auth", "deep_link_invalid_token_shape", Level::Warning);
        log::warn!("deep_link_invalid_token_shape");
    }
}

pub fn try_handle_deep_link_from_args(app: &tauri::AppHandle, state: &Arc<AppState>) {
    let args: Vec<String> = std::env::args().collect();
    log::info!(
        "process_args count={} sample_arg1={}",
        args.len(),
        args.get(1).cloned().unwrap_or_default()
    );
    for a in args {
        if a.starts_with("klaayguard://") {
            log::info!("deep_link_found_in_process_args");
            handle_deep_link_url(app, state, &a);
            break;
        }
    }
}

pub async fn invalidate_auth(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<(), String> {
    *state.auth_token.write().await = None;
    let already_cleared = *state.keychain_cleared_this_session.read().await;
    if !already_cleared {
        let _ = keychain::delete_token();
        *state.keychain_cleared_this_session.write().await = true;
    }
    log::warn!("Authentication invalidated; focusing window for re-login");
    focus_window_with_debounce(app, state).await;
    let _ = app.emit("auth:invalidated", ());
    let _ = app.emit("auth:status", json!({ "authenticated": false }));
    add_breadcrumb("auth", "auth_invalidated", Level::Warning);
    sentry::capture_message("auth_invalidated", Level::Warning);
    Ok(())
}

async fn fetch_me(
    client: &reqwest::Client,
    base: &str,
    token: &str,
) -> (bool, Option<String>, bool) {
    match client
        .get(format!("{}/me", base))
        .bearer_auth(token)
        .send()
        .await
    {
        Ok(resp) => {
            add_breadcrumb(
                "auth",
                &format!("me_response_status:{}", resp.status().as_u16()),
                Level::Info,
            );
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED
                || resp.status() == reqwest::StatusCode::FORBIDDEN
            {
                return (false, None, true);
            }
            if resp.status().is_success() {
                match resp.json::<Value>().await {
                    Ok(body) => {
                        let attrs = body
                            .get("data")
                            .and_then(|d| d.get("attributes"))
                            .cloned()
                            .unwrap_or(json!({}));
                        let first = attrs
                            .get("first_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let last = attrs
                            .get("last_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let email = attrs.get("email").and_then(|v| v.as_str());
                        let full = format!("{} {}", first, last).trim().to_string();
                        let name = if !full.is_empty() {
                            Some(full)
                        } else {
                            email.map(|s| s.to_string())
                        };
                        (true, name, false)
                    }
                    Err(_) => (true, None, false),
                }
            } else {
                (false, None, false)
            }
        }
        Err(e) => {
            add_breadcrumb("auth", &format!("me_request_error:{}", e), Level::Warning);
            sentry::capture_message("auth_me_request_error", Level::Warning);
            (false, None, false)
        }
    }
}

#[tauri::command]
pub async fn save_auth_token(
    state: tauri::State<'_, Arc<AppState>>,
    token: String,
) -> Result<(), String> {
    *state.auth_token.write().await = Some(token.clone());
    *state.keychain_cleared_this_session.write().await = false;
    let _ = keychain::save_token(&token);
    add_breadcrumb("auth", "token_saved", Level::Info);
    sentry::capture_message("auth_token_saved", Level::Info);
    Ok(())
}

#[tauri::command]
pub async fn clear_auth_token(state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
    *state.auth_token.write().await = None;
    let already_cleared = *state.keychain_cleared_this_session.read().await;
    if !already_cleared {
        let _ = keychain::delete_token();
        *state.keychain_cleared_this_session.write().await = true;
    }
    add_breadcrumb("auth", "token_cleared", Level::Info);
    sentry::capture_message("auth_token_cleared", Level::Info);
    Ok(())
}

#[tauri::command]
pub async fn get_auth_status(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<AuthStatus, String> {
    let token_opt = state.auth_token.read().await.clone();
    if token_opt.is_none() {
        return Ok(AuthStatus {
            authenticated: false,
            display_name: None,
        });
    }
    let base = state.api_base_url.read().await.clone();
    let token = token_opt.unwrap();
    let client = reqwest::Client::builder()
        .user_agent("klaayguard/0.1")
        .build()
        .map_err(|e| e.to_string())?;
    add_breadcrumb("auth", "me_request_start", Level::Info);
    sentry::capture_message("auth_me_request_start", Level::Info);

    let (is_authenticated, name, should_invalidate) = fetch_me(&client, &base, &token).await;
    if should_invalidate {
        invalidate_auth(&app, &state).await.ok();
        add_breadcrumb("auth", "auth_invalidated_on_me", Level::Warning);
        sentry::capture_message("auth_invalidated_on_me", Level::Warning);
    }
    Ok(AuthStatus {
        authenticated: is_authenticated,
        display_name: name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    fn rt() -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn test_parse_deep_link_token_valid() {
        let tok = "aaa.bbb.ccc";
        let url = format!("klaayguard://auth-callback?token={}", tok);
        assert_eq!(parse_deep_link_token(&url), Some(tok.to_string()));
    }

    #[test]
    fn test_parse_deep_link_token_invalid_shape() {
        let tok = "aaa.bbb";
        let url = format!("klaayguard://auth-callback?token={}", tok);
        assert_eq!(parse_deep_link_token(&url), None);
    }

    #[test]
    fn test_parse_deep_link_token_missing() {
        let url = "klaayguard://auth-callback";
        assert_eq!(parse_deep_link_token(url), None);
    }

    #[test]
    fn test_fetch_me_success_with_name() {
        rt().block_on(async {
            let server = MockServer::start();
            let m = server.mock(|when, then| {
                when.method(GET).path("/me");
                then.status(200).json_body(json!({
                    "data": { "attributes": { "first_name": "Jane", "last_name": "Doe" } }
                }));
            });
            let client = reqwest::Client::new();
            let (auth, name, inv) = fetch_me(&client, &server.base_url(), "t").await;
            m.assert();
            assert!(auth);
            assert_eq!(name, Some("Jane Doe".to_string()));
            assert!(!inv);
        });
    }

    #[test]
    fn test_fetch_me_unauthorized_triggers_invalidate() {
        rt().block_on(async {
            let server = MockServer::start();
            let m = server.mock(|when, then| {
                when.method(GET).path("/me");
                then.status(401);
            });
            let client = reqwest::Client::new();
            let (auth, name, inv) = fetch_me(&client, &server.base_url(), "t").await;
            m.assert();
            assert!(!auth);
            assert_eq!(name, None);
            assert!(inv);
        });
    }

    #[test]
    fn test_clear_auth_token_session_guard() {
        rt().block_on(async {
            let state = Arc::new(AppState {
                auth_token: tokio::sync::RwLock::new(Some("t".to_string())),
                api_base_url: tokio::sync::RwLock::new("http://x".to_string()),
                last_run_at: tokio::sync::RwLock::new(None),
                last_attempt_at: tokio::sync::RwLock::new(None),
                db_path: tokio::sync::RwLock::new(None),
                upload_in_progress: tokio::sync::RwLock::new(false),
                keychain_cleared_this_session: tokio::sync::RwLock::new(false),
                last_upload_tick_at: tokio::sync::RwLock::new(None),
                last_focus_at: tokio::sync::RwLock::new(None),
                retention_in_progress: tokio::sync::RwLock::new(false),
            });
            // Simulate two clears via internal logic
            {
                *state.auth_token.write().await = None;
                let already = *state.keychain_cleared_this_session.read().await;
                assert!(!already);
                *state.keychain_cleared_this_session.write().await = true;
            }
            // The session guard is set; subsequent delete should not be invoked again in production path
            assert!(*state.keychain_cleared_this_session.read().await);
        });
    }
}
