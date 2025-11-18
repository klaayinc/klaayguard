//! KlaayGuard - Security Monitoring Application
//!
//! System tray-only application for continuous security monitoring.
//! - Runs in background with system tray icon
//! - Collects system data hourly via osquery
//! - Immediately sends data to API (no local persistence)
//! - Shows status via tray icon tooltip

mod keychain;
use sentry::{self, Level};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tauri::{Emitter, Manager};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_shell::ShellExt;
use tokio::sync::RwLock;

/// Shared application state
pub struct AppState {
    pub auth_token: RwLock<Option<String>>,
    pub api_base_url: RwLock<String>,
    pub last_send_status: RwLock<Option<bool>>, // true = success, false = failure
    pub last_send_at: RwLock<Option<chrono::DateTime<chrono::Utc>>>,
    pub keychain_cleared_this_session: RwLock<bool>,
}

fn add_breadcrumb(category: &str, message: &str, level: Level) {
    let mut data = std::collections::BTreeMap::new();
    data.insert(
        "ts".to_string(),
        serde_json::json!(chrono::Utc::now().to_rfc3339()),
    );
    sentry::add_breadcrumb(sentry::Breadcrumb {
        ty: "default".to_string(),
        category: Some(category.to_string()),
        message: Some(message.to_string()),
        level,
        data,
        ..Default::default()
    });
}

/// Handle deep link authentication callback (klaayguard://auth-callback?token=JWT)
async fn handle_deep_link_url_async(app: &tauri::AppHandle, state: &Arc<AppState>, url: &str) {
    if !url.starts_with("klaayguard://") {
        log::info!("deep_link_ignored_non_scheme url={}", url);
        return;
    }
    log::info!("deep_link_received url={}", url);
    
    let token_opt = {
        let qs = url.splitn(2, '?').nth(1).unwrap_or("");
        let mut out: Option<String> = None;
        for pair in qs.split('&') {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            if k == "token" {
                let decoded = v.replace("%20", " ").replace("+", " ");
                out = Some(decoded);
                break;
            }
        }
        out
    };

    if let Some(tok) = token_opt {
        let dot_count = tok.matches('.').count();
        if dot_count != 2 {
            add_breadcrumb("auth", "deep_link_invalid_token_shape", Level::Warning);
            log::warn!("deep_link_invalid_token_shape dot_count={}", dot_count);
            return;
        }
        
        log::info!("deep_link_token_parsed length={} saving_to_keychain", tok.len());
        *state.auth_token.write().await = Some(tok.clone());
        *state.keychain_cleared_this_session.write().await = false;
        let _ = keychain::save_token(&tok);
        log::info!("deep_link_token_saved_to_keychain");
        let _ = app.emit("auth:status", json!({ "authenticated": true }));
        add_breadcrumb("auth", "deep_link_token_saved", Level::Info);
        sentry::capture_message("deep_link_token_saved", Level::Info);
    } else {
        log::warn!("deep_link_missing_token_param");
    }
}

/// Scan process args for deep link
async fn try_handle_deep_link_from_args_async(app: &tauri::AppHandle, state: &Arc<AppState>) {
    let args: Vec<String> = std::env::args().collect();
    log::info!("process_args count={} sample_arg1={}", args.len(), args.get(1).cloned().unwrap_or_default());
    for a in args {
        if a.starts_with("klaayguard://") {
            log::info!("deep_link_found_in_process_args");
            handle_deep_link_url_async(app, state, &a).await;
            break;
        }
    }
}

#[tauri::command]
async fn set_api_base_url(state: tauri::State<'_, Arc<AppState>>, base: String) -> Result<(), String> {
    *state.api_base_url.write().await = base;
    Ok(())
}

#[tauri::command]
async fn save_auth_token(state: tauri::State<'_, Arc<AppState>>, token: String) -> Result<(), String> {
    *state.auth_token.write().await = Some(token.clone());
    *state.keychain_cleared_this_session.write().await = false;
    let _ = keychain::save_token(&token);
    add_breadcrumb("auth", "token_saved", Level::Info);
    sentry::capture_message("auth_token_saved", Level::Info);
    Ok(())
}

#[tauri::command]
async fn clear_auth_token(state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
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
async fn get_device_serial_number(app: tauri::AppHandle) -> Result<String, String> {
    let tables = vec!["hardware_info".to_string()];
    let query_result = execute_query(app, tables).await?;

    let serial = query_result
        .get("hardware_info")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|obj| {
            obj.get("serial_number")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    obj.get("hardware_serial")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                })
                .or_else(|| {
                    obj.get("hardware_uuid")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                })
        })
        .ok_or_else(|| "Couldn't find hardware serial number".to_string())?;

    Ok(serial.to_string())
}

#[derive(serde::Serialize)]
struct AuthStatus {
    authenticated: bool,
    display_name: Option<String>,
}

#[tauri::command]
async fn get_app_version() -> Result<String, String> {
    let version = env!("CARGO_PKG_VERSION").to_string();
    log::info!("📱 Frontend requested app version: {}", version);
    Ok(version)
}

#[tauri::command]
async fn get_auth_status(
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

    let (is_authenticated, name): (bool, Option<String>) = match client
        .get(format!("{}/me", base))
        .bearer_auth(&token)
        .send()
        .await
    {
        Ok(resp) => {
            add_breadcrumb("auth", &format!("me_response_status:{}", resp.status().as_u16()), Level::Info);
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED
                || resp.status() == reqwest::StatusCode::FORBIDDEN
            {
                invalidate_auth(&app, &state).await.ok();
                add_breadcrumb("auth", "auth_invalidated_on_me", Level::Warning);
                sentry::capture_message("auth_invalidated_on_me", Level::Warning);
                (false, None)
            } else if resp.status().is_success() {
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
                        (true, name)
                    }
                    Err(_) => (true, None),
                }
            } else {
                (false, None)
            }
        }
        Err(e) => {
            add_breadcrumb("auth", &format!("me_request_error:{}", e), Level::Warning);
            sentry::capture_message("auth_me_request_error", Level::Warning);
            (false, None)
        }
    };

    Ok(AuthStatus {
        authenticated: is_authenticated,
        display_name: name,
    })
}

#[tauri::command]
async fn execute_query(
    app: tauri::AppHandle,
    table_names: Vec<String>,
) -> Result<HashMap<String, Value>, String> {
    let mut all_results = HashMap::new();

    for table_name in table_names {
        let cmd = app
            .shell()
            .sidecar("osqueryi")
            .unwrap()
            .args(["--json", &format!("SELECT * FROM {}", table_name)]);

        let output = cmd.output().await.map_err(|e| e.to_string())?;

        if !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            let stderr_lc = stderr_str.to_ascii_lowercase();
            if stderr_lc.contains("no such table")
                || stderr_lc.contains("no such column")
                || stderr_lc.contains("no such module")
            {
                all_results.insert(table_name, serde_json::json!([]));
                continue;
            }
            return Err(format!(
                "table {} failed (exit code {:?}): {}",
                table_name,
                output.status.code(),
                stderr_str
            ));
        }

        let stdout_str = String::from_utf8(output.stdout)
            .map_err(|e| format!("Invalid UTF-8 output for table {}: {}", table_name, e))?;

        let parsed_result: Value = serde_json::from_str(&stdout_str).map_err(|e| {
            format!("Failed to parse JSON for table {} (content: '{}'): {}", table_name, stdout_str.trim(), e)
        })?;

        all_results.insert(table_name, parsed_result);
    }

    Ok(all_results)
}

async fn execute_sql_batch(
    app: tauri::AppHandle,
    queries: Vec<(String, String)>,
) -> Result<HashMap<String, Value>, String> {
    let mut all_results: HashMap<String, Value> = HashMap::new();

    for (logical_id, sql) in queries {
        let cmd = app
            .shell()
            .sidecar("osqueryi")
            .unwrap()
            .args(["--json", sql.as_str()]);

        let output = cmd.output().await.map_err(|e| e.to_string())?;

        if !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            let stderr_lc = stderr_str.to_ascii_lowercase();
            if stderr_lc.contains("no such table")
                || stderr_lc.contains("no such column")
                || stderr_lc.contains("no such module")
            {
                all_results.insert(logical_id, serde_json::json!([]));
                continue;
            }
            return Err(format!(
                "sql for '{}' failed (exit code {:?}): {}",
                logical_id,
                output.status.code(),
                stderr_str
            ));
        }

        let stdout_str = String::from_utf8(output.stdout)
            .map_err(|e| format!("Invalid UTF-8 output for {}: {}", logical_id, e))?;

        let parsed_result: Value = serde_json::from_str(&stdout_str).map_err(|e| {
            format!("Failed to parse JSON for {} (content: '{}'): {}", logical_id, stdout_str.trim(), e)
        })?;

        all_results.insert(logical_id, parsed_result);
    }

    Ok(all_results)
}

async fn invalidate_auth(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<(), String> {
    *state.auth_token.write().await = None;
    let already_cleared = *state.keychain_cleared_this_session.read().await;
    if !already_cleared {
        let _ = keychain::delete_token();
        *state.keychain_cleared_this_session.write().await = true;
    }
    log::warn!("Authentication invalidated");
    
    // Show notification instead of focusing window
    let _ = app.notification()
        .builder()
        .title("KlaayGuard")
        .body("Authentication required. Please sign in.")
        .show();
    
    let _ = app.emit("auth:invalidated", ());
    let _ = app.emit("auth:status", json!({ "authenticated": false }));
    add_breadcrumb("auth", "auth_invalidated", Level::Warning);
    sentry::capture_message("auth_invalidated", Level::Warning);
    Ok(())
}

fn collection_interval_seconds() -> u64 {
    std::env::var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600) // Changed from 900 to 3600 (1 hour)
}

async fn get_device_serial_number_internal(app: &tauri::AppHandle) -> Result<String, String> {
    let tables = vec!["hardware_info".to_string()];
    let result = execute_query(app.clone(), tables).await?;
    let serial = result
        .get("hardware_info")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|obj| {
            obj.get("serial_number")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    obj.get("hardware_serial")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                })
                .or_else(|| {
                    obj.get("hardware_uuid")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                })
        })
        .ok_or_else(|| "Couldn't find hardware serial number".to_string())?;
    Ok(serial.to_string())
}

async fn update_tray_status(app: &tauri::AppHandle, state: &Arc<AppState>, success: bool) {
    let (tooltip, notification_msg) = if success {
        let timestamp = state.last_send_at.read().await.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());
        let tooltip = if let Some(ts) = timestamp {
            format!("✓ Last send: {} (Success)", ts)
        } else {
            "✓ Last send: Success".to_string()
        };
        (tooltip, None)
    } else {
        ("✗ Last send: Failed".to_string(), Some("Data send failed. Will retry in 1 hour."))
    };
    
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(tooltip));
    }
    
    // Show notification on failure
    if let Some(msg) = notification_msg {
        let _ = app.notification()
            .builder()
            .title("KlaayGuard")
            .body(msg)
            .show();
    }
    
    *state.last_send_status.write().await = Some(success);
    *state.last_send_at.write().await = Some(chrono::Utc::now());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonApiResource {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "type")]
    r#type: String,
    attributes: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonApiPayload {
    data: Vec<JsonApiResource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jsonapi: Option<serde_json::Value>,
}

async fn run_cycle(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    client: &reqwest_middleware::ClientWithMiddleware,
) -> Result<(), String> {
    let token = match state.auth_token.read().await.clone() {
        Some(t) => t,
        None => return Ok(()),
    };

    let base = state.api_base_url.read().await.clone();

    // 1) GET /klaayguard/config (retries handled by middleware)
    add_breadcrumb("collection", "config_fetch_start", Level::Info);
    sentry::capture_message("collection_config_fetch_start", Level::Info);
    
    let cfg_resp = client
            .get(format!("{}/klaayguard/config", base))
            .bearer_auth(&token)
            .send()
            .await
        .map_err(|e| e.to_string())?;

    add_breadcrumb("collection", &format!("config_status:{}", cfg_resp.status().as_u16()), Level::Info);

    if cfg_resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || cfg_resp.status() == reqwest::StatusCode::FORBIDDEN
    {
        invalidate_auth(app, state).await?;
        sentry::capture_message("collection_auth_invalidated_on_config", Level::Warning);
        return Ok(());
    }
    if !cfg_resp.status().is_success() {
        sentry::capture_message("collection_error_config_non_success", Level::Warning);
        update_tray_status(app, state, false).await;
        return Ok(());
    }

    let cfg_json: Value = cfg_resp.json().await.map_err(|e| e.to_string())?;
    
    let queries: Vec<(String, String)> = cfg_json
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let id = item.get("id").and_then(|v| v.as_str())?;
                    let sql = item
                        .get("sql")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("SELECT * FROM {}", id));
                    Some((id.to_string(), sql))
                })
                .collect()
        })
        .unwrap_or_default();

    if queries.is_empty() {
        log::warn!("No queries in config");
        return Ok(());
    }

    // 2) Execute osquery
    add_breadcrumb("collection", "osquery_start", Level::Info);
    sentry::capture_message("collection_osquery_start", Level::Info);
    let results = execute_sql_batch(app.clone(), queries).await?;

    // 3) Immediately POST to API (retries handled by middleware)
    let device_serial = get_device_serial_number_internal(app).await
        .unwrap_or_else(|_| "unknown".to_string());
    
    let mut items: Vec<JsonApiResource> = Vec::new();
    for (table_name, value) in results.iter() {
        if let Some(arr) = value.as_array() {
            for row in arr {
                items.push(JsonApiResource {
                    id: None,
                    r#type: table_name.clone(),
                    attributes: row.clone(),
                });
            }
        }
    }
    
    let payload = JsonApiPayload {
        data: items,
        meta: Some(json!({ "device_uuid": device_serial })),
        jsonapi: Some(json!({ "version": "1.0" })),
    };
    
    let body_json = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    
    let post_result = client
        .post(format!("{}/klaayguard/data", base))
        .bearer_auth(&token)
        .header(reqwest::header::CONTENT_TYPE, "application/vnd.api+json")
        .header(reqwest::header::ACCEPT, "application/vnd.api+json")
        .body(body_json)
        .send()
            .await;
    
    // 4) Update status
    match post_result {
        Ok(resp) if resp.status().is_success() || resp.status() == reqwest::StatusCode::ACCEPTED => {
            log::info!("Data send successful");
            add_breadcrumb("collection", "post_success", Level::Info);
            update_tray_status(app, state, true).await;
        }
        Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED || resp.status() == reqwest::StatusCode::FORBIDDEN => {
            add_breadcrumb("collection", "auth_invalidated_on_post", Level::Warning);
            invalidate_auth(app, state).await?;
        }
        Ok(resp) => {
            log::error!("Data send failed: status {}", resp.status().as_u16());
            add_breadcrumb("collection", &format!("post_failed:{}", resp.status().as_u16()), Level::Error);
            update_tray_status(app, state, false).await;
        }
        Err(e) => {
            log::error!("Data send error: {}", e);
            add_breadcrumb("collection", &format!("post_error:{}", e), Level::Error);
            update_tray_status(app, state, false).await;
        }
    }

    Ok(())
}

fn spawn_background_loop(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        use reqwest_middleware::ClientBuilder;
        use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
        
        let retry_policy = ExponentialBackoff::builder()
            .retry_bounds(Duration::from_secs(60), Duration::from_secs(600))
            .build_with_max_retries(3);
        
        let client = ClientBuilder::new(reqwest::Client::builder()
            .user_agent("klaayguard/0.1")
            .build()
            .expect("reqwest client"))
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        // Wait for token
    loop {
            if state.auth_token.read().await.is_some() {
            break;
        }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }

        // Run immediately
        if let Err(e) = run_cycle(&app, &state, &client).await {
            log::error!("initial cycle error: {}", e);
        }

        let mut interval = tokio::time::interval(Duration::from_secs(collection_interval_seconds()));
        loop {
            interval.tick().await;
            if let Err(e) = run_cycle(&app, &state, &client).await {
                log::error!("cycle error: {}", e);
            }
        }
    });
}

#[derive(Serialize)]
struct ArchStatus {
    mismatch: bool,
    built: String,
    host: String,
}

#[tauri::command]
async fn get_arch_status() -> Result<ArchStatus, String> {
    let mismatch = std::env::var("KLAAY_ARCH_MISMATCH").ok().as_deref() == Some("1");
    let built = std::env::var("KLAAY_ARCH_BUILT").unwrap_or_else(|_| std::env::consts::ARCH.to_string());
    let host = std::env::var("KLAAY_ARCH_HOST").unwrap_or_else(|_| "unknown".to_string());
    Ok(ArchStatus {
        mismatch,
        built,
        host,
    })
}

#[derive(serde::Deserialize)]
struct ReleaseAsset {
    id: u64,
    name: String,
    #[serde(rename = "original_name")]
    _original_name: Option<String>,
    #[serde(rename = "content_type")]
    _content_type: Option<String>,
    #[serde(rename = "size")]
    _size: Option<u64>,
    #[serde(rename = "digest")]
    _digest: Option<String>,
    #[serde(rename = "sha256")]
    _sha256: Option<String>,
    #[serde(rename = "browser_download_url")]
    _browser_download_url: Option<String>,
    #[serde(rename = "api_asset_url")]
    _api_asset_url: Option<String>,
}

#[derive(serde::Deserialize)]
struct ReleaseInfo {
    #[serde(rename = "name")]
    _name: Option<String>,
    version: String,
    assets: Vec<ReleaseAsset>,
}

fn get_api_base_url() -> String {
    std::env::var("VITE_API_BASE_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_API_BASE_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://api.klaay.com".to_string())
}

async fn check_for_updates_internal(api_base: &str) -> Result<Option<String>, String> {
    let current_version = env!("CARGO_PKG_VERSION");
    log::info!("🔍 Starting update check - current version: {}", current_version);
    log::info!("🌐 Checking for updates from API: {}/klaayguard/updates/latest", api_base);

    let client = reqwest::Client::new();
    let response = client
        .get(&format!("{}/klaayguard/updates/latest", api_base))
        .send()
        .await
        .map_err(|e| {
            log::error!("❌ Failed to check for updates: {}", e);
            format!("Failed to check for updates: {}", e)
        })?;

    log::info!("📡 API response status: {}", response.status());

    if !response.status().is_success() {
        let error_msg = format!("Update check failed with status: {}", response.status());
        log::error!("❌ {}", error_msg);
        return Err(error_msg);
    }

    let release: ReleaseInfo = response.json().await.map_err(|e| {
        log::error!("❌ Failed to parse release info: {}", e);
        format!("Failed to parse release info: {}", e)
    })?;

    log::info!("📦 Found release: {} with {} assets", release.version, release.assets.len());

    let normalized_current = current_version.trim_start_matches('v');
    let normalized_release = release.version.trim_start_matches('v');

    let current_semver = semver::Version::parse(normalized_current).map_err(|e| {
        log::error!("❌ Failed to parse current version '{}': {}", normalized_current, e);
        format!("Invalid current version format: {}", normalized_current)
    })?;

    let release_semver = semver::Version::parse(normalized_release).map_err(|e| {
        log::error!("❌ Failed to parse release version '{}': {}", normalized_release, e);
        format!("Invalid release version format: {}", normalized_release)
    })?;

    if release_semver > current_semver {
        log::info!("🆚 Version comparison: {} < {} (update available)", current_version, release.version);
        
        if let Some(dmg_asset) = release.assets.iter().find(|asset| {
            asset.name.ends_with(".dmg")
                || asset.name.contains("MacOS")
                || asset._original_name.as_ref().map_or(false, |orig| orig.ends_with(".dmg"))
        }) {
            log::info!("✅ Found DMG asset: {} (ID: {})", dmg_asset.name, dmg_asset.id);
            log::info!("🚀 Update available: {} -> {}", current_version, release.version);
            return Ok(Some(dmg_asset.id.to_string()));
        } else {
            log::warn!("⚠️  No DMG asset found in release assets");
        }
    } else {
        log::info!("✅ No update needed - already at latest version: {}", current_version);
    }

    Ok(None)
}

#[tauri::command]
async fn check_for_updates_command() -> Result<Option<String>, String> {
    let api_base = get_api_base_url();
    log::info!("🌐 Manual update check using API base URL: {}", api_base);
    check_for_updates_internal(&api_base).await
}

async fn download_and_install_update_internal(
    api_base: &str,
    asset_id: &str,
    app: &tauri::AppHandle,
) -> Result<(), String> {
    log::info!("📥 Starting download and install process for asset ID: {}", asset_id);

    let client = reqwest::Client::new();
    let download_url = format!("{}/klaayguard/download/{}", api_base, asset_id);
    log::info!("🌐 Download URL: {}", download_url);

    let response = client.get(&download_url).send().await.map_err(|e| {
        log::error!("❌ Failed to download update: {}", e);
        format!("Failed to download update: {}", e)
    })?;

    log::info!("📡 Download response status: {}", response.status());

    if !response.status().is_success() {
        let error_msg = format!("Download failed with status: {}", response.status());
        log::error!("❌ {}", error_msg);
        return Err(error_msg);
    }

    let downloads_dir = dirs::download_dir().ok_or_else(|| {
        log::error!("❌ Could not find downloads directory");
        "Could not find downloads directory"
    })?;
    let dmg_path = downloads_dir.join("KlaayGuard-update.dmg");

    log::info!("💾 Downloading to: {:?}", dmg_path);

    let mut file = std::fs::File::create(&dmg_path).map_err(|e| {
        log::error!("❌ Failed to create update file: {}", e);
        format!("Failed to create update file: {}", e)
    })?;

    let bytes = response.bytes().await.map_err(|e| {
        log::error!("❌ Download error: {}", e);
        format!("Download error: {}", e)
    })?;

    log::info!("📊 Downloaded {} bytes", bytes.len());

    std::io::Write::write_all(&mut file, &bytes).map_err(|e| {
        log::error!("❌ Write error: {}", e);
        format!("Write error: {}", e)
    })?;

    log::info!("✅ Update downloaded successfully to: {:?}", dmg_path);
    log::info!("🔄 Starting application replacement process...");
    replace_application(&dmg_path, app).await?;

    Ok(())
}

#[tauri::command]
async fn download_and_install_update(asset_id: String, app: tauri::AppHandle) -> Result<(), String> {
    let api_base = get_api_base_url();
    log::info!("🌐 Manual update download using API base URL: {}", api_base);
    download_and_install_update_internal(&api_base, &asset_id, &app).await
}

async fn replace_application(dmg_path: &std::path::Path, app: &tauri::AppHandle) -> Result<(), String> {
    log::info!("💿 Mounting DMG: {:?}", dmg_path);

    let mount_output = std::process::Command::new("hdiutil")
        .args(&["attach", dmg_path.to_str().unwrap()])
        .output()
        .map_err(|e| {
            log::error!("❌ Failed to mount DMG: {}", e);
            format!("Failed to mount DMG: {}", e)
        })?;

    if !mount_output.status.success() {
        let error_msg = "Failed to mount DMG".to_string();
        log::error!("❌ {} - hdiutil output: {}", error_msg, String::from_utf8_lossy(&mount_output.stderr));
        return Err(error_msg);
    }

    let mount_output_str = String::from_utf8_lossy(&mount_output.stdout);
    log::info!("📋 hdiutil output: {}", mount_output_str);

    let mount_point = mount_output_str
        .lines()
        .find(|line| line.contains("/Volumes/"))
        .ok_or_else(|| {
            log::error!("❌ Could not find mount point in hdiutil output");
            "Could not find mount point"
        })?
        .split('\t')
        .last()
        .ok_or_else(|| {
            log::error!("❌ Could not parse mount point from line");
            "Could not parse mount point"
        })?;

    log::info!("📍 Mount point: {}", mount_point);

    let source_app = std::path::Path::new(mount_point).join("KlaayGuard.app");
    let target_app = std::path::Path::new("/Applications/KlaayGuard.app");

    log::info!("📂 Source app: {:?}", source_app);
    log::info!("📂 Target app: {:?}", target_app);

    if !source_app.exists() {
        let error_msg = format!("Source app not found at: {:?}", source_app);
        log::error!("❌ {}", error_msg);
        return Err(error_msg);
    }

    if target_app.exists() {
        log::info!("🗑️  Removing old app from: {:?}", target_app);
        std::fs::remove_dir_all(target_app).map_err(|e| {
            log::error!("❌ Failed to remove old app: {}", e);
            format!("Failed to remove old app: {}", e)
        })?;
        log::info!("✅ Old app removed successfully");
    } else {
        log::info!("ℹ️  No existing app found at target location");
    }

    log::info!("📋 Copying new app from {:?} to {:?}", source_app, target_app);
    let copy_result = std::process::Command::new("cp")
        .args(&["-R", source_app.to_str().unwrap(), target_app.to_str().unwrap()])
        .status()
        .map_err(|e| {
            log::error!("❌ Failed to copy new app: {}", e);
            format!("Failed to copy new app: {}", e)
        })?;

    if !copy_result.success() {
        let error_msg = "Failed to copy new app - cp command failed".to_string();
        log::error!("❌ {}", error_msg);
        return Err(error_msg);
    }

    log::info!("✅ New app copied successfully");

    log::info!("💿 Unmounting DMG from: {}", mount_point);
    let unmount_result = std::process::Command::new("hdiutil")
        .args(&["detach", mount_point])
        .status()
        .map_err(|e| {
            log::error!("❌ Failed to unmount DMG: {}", e);
            format!("Failed to unmount DMG: {}", e)
        })?;

    if !unmount_result.success() {
        log::warn!("⚠️  DMG unmount failed, but continuing...");
    } else {
        log::info!("✅ DMG unmounted successfully");
    }

    log::info!("🗑️  Removing temporary DMG file: {:?}", dmg_path);
    if let Err(e) = std::fs::remove_file(dmg_path) {
        log::warn!("⚠️  Failed to remove DMG file: {}", e);
    } else {
        log::info!("✅ Temporary DMG file removed");
    }

    log::info!("🎉 Application updated successfully! Restarting...");
    app.restart();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let api_base = std::env::var("VITE_API_BASE_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_API_BASE_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://api.klaay.com".to_string());
    
    if let Ok(earthenware) = std::env::var("VITE_EARTHENWARE_URL") {
        add_breadcrumb("startup", &format!("endpoints api:{} earthenware:{}", api_base, earthenware), Level::Info);
    } else {
        add_breadcrumb("startup", &format!("endpoints api:{} earthenware:<unset>", api_base), Level::Info);
    }
    
    let state = Arc::new(AppState {
        auth_token: RwLock::new(None),
        api_base_url: RwLock::new(api_base),
        last_send_status: RwLock::new(None),
        last_send_at: RwLock::new(None),
        keychain_cleared_this_session: RwLock::new(false),
    });

    let app = tauri::Builder::default()
        .manage(state.clone())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_log::Builder::new().level(log::LevelFilter::Info).build())
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            let st = app.state::<Arc<AppState>>().inner().clone();
            let app_handle = app.clone();
            log::info!("single_instance_args count={} sample_arg0={}", args.len(), args.get(0).cloned().unwrap_or_default());
            for a in args {
                if a.starts_with("klaayguard://") {
                    log::info!("single_instance_deep_link_received");
                    let a_owned = a.clone();
                    tauri::async_runtime::spawn(async move {
                        handle_deep_link_url_async(&app_handle, &st, &a_owned).await;
                    });
                    break;
                }
            }
        }))
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, None::<Vec<&str>>))
        .setup(|app| {
            #[cfg(target_os = "macos")]
            {
                app.set_activation_policy(tauri::ActivationPolicy::Accessory);
                log::info!("KlaayGuard configured as background service - hidden from dock");
            }

            // Check arch mismatch
            #[cfg(target_os = "macos")]
            {
            if std::env::var("KLAAY_ARCH_MISMATCH").ok().as_deref() == Some("1") {
                    let built = std::env::var("KLAAY_ARCH_BUILT").unwrap_or_else(|_| std::env::consts::ARCH.to_string());
                    let host = std::env::var("KLAAY_ARCH_HOST").unwrap_or_else(|_| "unknown".to_string());
                    let _ = app.notification()
                        .builder()
                        .title("KlaayGuard - Architecture Mismatch")
                        .body(format!("App built for {} but running on {} hardware. Please install the correct build.", built, host))
                        .show();
                    sentry::capture_message(&format!("arch_mismatch: built={} host={}", built, host), Level::Error);
                return Ok(());
                }
            }

            // Auto-update check
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                log::info!("🚀 Starting automatic update check on app startup");
                let api_base = get_api_base_url();
                log::info!("🌐 Using API base URL: {}", api_base);
                if let Ok(Some(asset_id)) = check_for_updates_internal(&api_base).await {
                    log::info!("🔄 Update available, starting download and install process...");
                    if let Err(e) = download_and_install_update_internal(&api_base, &asset_id, &app_handle).await {
                        log::error!("💥 Auto-update failed: {}", e);
                    }
                } else {
                    log::info!("✅ No updates available - app is up to date");
                }
            });

            let state_for_loop = app.state::<Arc<AppState>>().inner().clone();
            let app_handle_for_init = app.handle().clone();
            let state_for_init = state_for_loop.clone();
            
            // Load token from keychain and handle deep link in async task
            tauri::async_runtime::spawn(async move {
                if let Ok(Some(tok)) = keychain::load_token() {
                    *state_for_init.auth_token.write().await = Some(tok);
                    let _ = app_handle_for_init.emit("auth:status", json!({ "authenticated": true }));
                } else {
                    let _ = app_handle_for_init.emit("auth:status", json!({ "authenticated": false }));
                }

                // Handle deep link
                try_handle_deep_link_from_args_async(&app_handle_for_init, &state_for_init).await;
            });

            // Create tray menu
            let login_i = tauri::menu::MenuItem::with_id(app, "login", "Login", true, None::<&str>)
                .map_err(|e| {
                    log::error!("Failed to create 'Login' menu item: {}", e);
                    e
                })?;
            let menu = tauri::menu::Menu::with_items(app, &[&login_i]).map_err(|e| {
                log::error!("Failed to create system tray menu: {}", e);
                e
            })?;

            // Create tray icon
            tauri::tray::TrayIconBuilder::new()
                .on_menu_event(|_app, event| match event.id.as_ref() {
                    "login" => {
                        log::info!("Login requested from system tray");
                        let earthenware_url = std::env::var("VITE_EARTHENWARE_URL")
                            .unwrap_or_else(|_| "https://app.klaay.com".to_string());
                        let login_url = format!("{}/login?app=klaayguard", earthenware_url);
                        let _ = tauri_plugin_opener::open_url(login_url, None::<&str>);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| match event {
                    tauri::tray::TrayIconEvent::Enter { .. } => {
                        let _ = tray.set_tooltip(Some("KlaayGuard - Security Monitoring".to_string()));
                    }
                    tauri::tray::TrayIconEvent::Leave { .. } => {
                        let _ = tray.set_tooltip(Some("".to_string()));
                    }
                    _ => {}
                })
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .icon_as_template(true)
                .show_menu_on_left_click(false)
                .build(app)
                .map_err(|e| {
                    log::error!("Failed to create system tray icon: {}", e);
                    e
                })?;

            // Spawn background loop
            spawn_background_loop(app.handle().clone(), state_for_loop);

            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            execute_query,
            get_device_serial_number,
            save_auth_token,
            clear_auth_token,
            set_api_base_url,
            get_auth_status,
            get_app_version,
            get_arch_status,
            check_for_updates_command,
            download_and_install_update
        ])
        .build(tauri::generate_context!())
        .expect("error building tauri application");

    app.run(|_app_handle, event| match event {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        tauri::RunEvent::Opened { urls } => {
            if !urls.is_empty() {
                let st = _app_handle.state::<Arc<AppState>>().inner().clone();
                let app_handle = _app_handle.clone();
                for u in urls {
                    let s = u.to_string();
                    log::info!("run_event_opened url={}", s);
                    let st_clone = st.clone();
                    let app_handle_clone = app_handle.clone();
                    tauri::async_runtime::spawn(async move {
                        handle_deep_link_url_async(&app_handle_clone, &st_clone, &s).await;
                    });
                }
            }
        }
        _ => {}
    });
}
