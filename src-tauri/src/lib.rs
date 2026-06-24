//! KlaayGuard - Security Monitoring Application
//!
//! This application provides continuous security monitoring on edge devices.
//! Key security features:
//! - Runs as background service (hidden from dock on macOS)
//! - No quit option in system tray to prevent easy termination
//! - Automatic updates for security patches
//! - System tray interface for minimal user interaction
//!
//! Security Design:
//! - App cannot be easily terminated by end users
//! - Background operation ensures continuous monitoring
//! - System tray provides controlled access to app functionality

mod keychain;
use sentry::{self, Level};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tauri::{Emitter, Manager};
// removed autostart plugin; using manual LaunchAgent management
use tauri_plugin_shell::ShellExt;
// use tauri_plugin_log::LogTarget; // use defaults
use tokio::sync::RwLock;

// Re-introduced minimal osquery commands used by the UI.

/// Shared application state for background operations
pub struct AppState {
    pub auth_token: RwLock<Option<String>>,
    pub api_base_url: RwLock<String>,
    pub last_run_at: RwLock<Option<std::time::Instant>>,
    pub last_attempt_at: RwLock<Option<std::time::Instant>>,
    // Prevent repeated Keychain delete prompts by ensuring we only delete once per session
    pub keychain_cleared_this_session: RwLock<bool>,
    pub last_focus_at: RwLock<Option<std::time::Instant>>, // debounce for focus-on-failure
}

// Keychain access is centralized in src-tauri/src/keychain.rs

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

/// Extract and shape-validate the JWT from a `klaayguard://...?token=...` deep link.
/// Returns None for a non-klaayguard URL, a missing token, or one that isn't three
/// dot-separated segments.
fn parse_deep_link_token(url: &str) -> Option<String> {
    if !url.starts_with("klaayguard://") {
        return None;
    }
    let qs = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let token = qs.split('&').find_map(|pair| {
        let mut it = pair.splitn(2, '=');
        match (it.next(), it.next()) {
            (Some("token"), Some(v)) => Some(v.replace("%20", " ").replace('+', " ")),
            _ => None,
        }
    })?;
    (token.matches('.').count() == 2).then_some(token)
}

/// Turn the /klaayguard/config payload into (logical_id, sql) pairs. An item with an
/// explicit `sql` uses it; otherwise it defaults to `SELECT * FROM <id>`.
fn parse_config_queries(cfg: &Value) -> Vec<(String, String)> {
    cfg.get("data")
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
        .unwrap_or_default()
}

/// Flatten osquery results into JSON:API resources, stamping each row with collected_at.
fn build_payload_items(results: &HashMap<String, Value>, collected_at: &str) -> Vec<JsonApiResource> {
    let mut items = Vec::new();
    for (table, value) in results.iter() {
        let Some(arr) = value.as_array() else { continue };
        for row in arr {
            let mut attributes = row.clone();
            if let Some(obj) = attributes.as_object_mut() {
                obj.insert("collected_at".to_string(), json!(collected_at));
            }
            items.push(JsonApiResource {
                id: None,
                r#type: table.clone(),
                attributes,
            });
        }
    }
    items
}

/// Persist a JWT delivered via a klaayguard:// deep link.
fn handle_deep_link_url(app: &tauri::AppHandle, state: &Arc<AppState>, url: &str) {
    let Some(tok) = parse_deep_link_token(url) else {
        log::info!("deep_link_ignored url={}", url);
        return;
    };
    log::info!("deep_link_token_parsed length={} saving_to_keychain", tok.len());
    tauri::async_runtime::block_on(async {
        *state.auth_token.write().await = Some(tok.clone());
        *state.keychain_cleared_this_session.write().await = false;
    });
    let _ = keychain::save_token(&tok);
    let _ = app.emit("auth:status", json!({ "authenticated": true }));
    add_breadcrumb("auth", "deep_link_token_saved", Level::Info);
    sentry::capture_message("deep_link_token_saved", Level::Info);
}

/// Scan process args for a klaayguard deep link and handle it
fn try_handle_deep_link_from_args(app: &tauri::AppHandle, state: &Arc<AppState>) {
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

/// Executes a batch of SQL statements against osquery and returns results keyed by logical id
/// The vector contains pairs of (logical_id, sql_to_execute).
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

        // osquery failing to spawn at all is a systemic problem — surface it.
        let output = cmd.output().await.map_err(|e| e.to_string())?;

        // A single failed or unparseable query must not sink the cycle: record an
        // empty result for it and keep collecting (and sending) the others.
        if !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            add_breadcrumb(
                "collection",
                &format!("osquery_query_skipped '{}': {}", logical_id, stderr_str.trim()),
                Level::Warning,
            );
            all_results.insert(logical_id, serde_json::json!([]));
            continue;
        }

        let parsed = String::from_utf8(output.stdout)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
        match parsed {
            Some(v) => {
                all_results.insert(logical_id, v);
            }
            None => {
                add_breadcrumb(
                    "collection",
                    &format!("osquery_parse_skipped '{}'", logical_id),
                    Level::Warning,
                );
                all_results.insert(logical_id, serde_json::json!([]));
            }
        }
    }

    Ok(all_results)
}

async fn invalidate_auth(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<(), String> {
    *state.auth_token.write().await = None;
    // Delete the token at most once per session to reduce prompts
    let already_cleared = *state.keychain_cleared_this_session.read().await;
    if !already_cleared {
        let _ = keychain::delete_token();
        *state.keychain_cleared_this_session.write().await = true;
    }
    // Log locally and notify the user that re-login is needed (no window now).
    log::warn!("Authentication invalidated; notifying user to re-sign-in");
    notify_signin_needed(state).await;
    let _ = app.emit("auth:invalidated", ());
    let _ = app.emit("auth:status", json!({ "authenticated": false }));
    add_breadcrumb("auth", "auth_invalidated", Level::Warning);
    sentry::capture_message("auth_invalidated", Level::Warning);
    Ok(())
}

fn focus_debounce_seconds() -> u64 {
    std::env::var("KLAAYGUARD_FAILURE_FOCUS_DEBOUNCE_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60)
}

fn collection_interval_seconds() -> u64 {
    std::env::var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(900)
}

/// Debounced native notification telling the user to sign in again. Replaces the
/// old "focus the window" nudge now that the app is tray-only.
async fn notify_signin_needed(state: &Arc<AppState>) {
    let now = std::time::Instant::now();
    let debounce = std::time::Duration::from_secs(focus_debounce_seconds());
    let should = match *state.last_focus_at.read().await {
        Some(prev) => now.duration_since(prev) >= debounce,
        None => true,
    };
    if !should {
        return;
    }
    *state.last_focus_at.write().await = Some(now);
    log::warn!("sign-in required; notifying user (debounced)");
    add_breadcrumb("ui", "signin_required_notification", Level::Info);
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("osascript")
            .args([
                "-e",
                "display notification \"Open KlaayGuard in the menu bar to sign in.\" with title \"KlaayGuard\"",
            ])
            .spawn();
    }
}

async fn emit_error_and_focus(
    app: &tauri::AppHandle,
    _state: &Arc<AppState>,
    event: &str,
    payload: serde_json::Value,
) {
    // Emit to UI listeners
    let _ = app.emit(event, payload.clone());
    // Report to Sentry as an error-level event with context
    let serialized = payload.to_string();
    // Also log locally to KlaayGuard.log
    log::error!("error_event:{}, payload:{}", event, serialized);
    sentry::capture_message(
        &format!("error_event:{}, payload:{}", event, serialized),
        Level::Error,
    );
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

/// Pull a stable device identifier from osquery `system_info` rows. osquery has no
/// `hardware_info` table; the serial lives in `system_info.hardware_serial`, with
/// `uuid` as a fallback.
fn extract_serial(rows: &Value) -> Option<String> {
    let obj = rows.as_array()?.first()?;
    ["hardware_serial", "serial_number", "uuid", "hardware_uuid"]
        .iter()
        .find_map(|k| {
            obj.get(*k)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
        .map(|s| s.to_string())
}

async fn get_device_serial_number_internal(app: &tauri::AppHandle) -> Result<String, String> {
    let result = execute_sql_batch(
        app.clone(),
        vec![("system_info".to_string(), "SELECT * FROM system_info".to_string())],
    )
    .await?;
    extract_serial(result.get("system_info").unwrap_or(&Value::Null))
        .ok_or_else(|| "Couldn't find hardware serial number".to_string())
}

async fn run_cycle(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    client: &reqwest::Client,
) -> Result<(), String> {
    let token = match state.auth_token.read().await.clone() {
        Some(t) => t,
        None => return Ok(()),
    };

    let base = state.api_base_url.read().await.clone();

    // Mark an attempt start and notify UI listeners
    *state.last_attempt_at.write().await = Some(std::time::Instant::now());
    let _ = app.emit("collection:attempt", ());

    // 1) GET /klaayguard/config
    add_breadcrumb("collection", "config_fetch_start", Level::Info);
    sentry::capture_message("collection_config_fetch_start", Level::Info);
    let is_transient_status = |code: u16| -> bool { code == 429 || (500..=599).contains(&code) };
    let retry_delays = [60u64, 120u64];
    let mut attempt = 0usize;
    let cfg_resp = loop {
        match client
            .get(format!("{}/klaayguard/config", base))
            .bearer_auth(&token)
            .send()
            .await
        {
            Ok(resp) => {
                add_breadcrumb(
                    "collection",
                    &format!("config_status:{}", resp.status().as_u16()),
                    Level::Info,
                );
                if !resp.status().is_success()
                    && is_transient_status(resp.status().as_u16())
                    && attempt < retry_delays.len()
                {
                    let delay = retry_delays[attempt];
                    add_breadcrumb(
                        "collection",
                        &format!("transient_retry_in_s:{}", delay),
                        Level::Warning,
                    );
                    sentry::capture_message("collection_transient_retry", Level::Warning);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    attempt += 1;
                    continue;
                }
                break resp;
            }
            Err(e) => {
                add_breadcrumb(
                    "collection",
                    &format!("config_network_error:{}", e),
                    Level::Warning,
                );
                sentry::capture_message("collection_config_network_error", Level::Warning);
                if attempt < retry_delays.len() {
                    let delay = retry_delays[attempt];
                    add_breadcrumb(
                        "collection",
                        &format!("retry_in_s:{}", delay),
                        Level::Warning,
                    );
                    sentry::capture_message("collection_retry", Level::Warning);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    attempt += 1;
                    continue;
                } else {
                    return Err(e.to_string());
                }
            }
        }
    };

    if cfg_resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || cfg_resp.status() == reqwest::StatusCode::FORBIDDEN
    {
        invalidate_auth(app, state).await?;
        let _ = app.emit(
            "collection:error",
            json!({ "stage": "config", "status": cfg_resp.status().as_u16() }),
        );
        sentry::capture_message("collection_auth_invalidated_on_config", Level::Warning);
        return Ok(());
    }
    if !cfg_resp.status().is_success() {
        emit_error_and_focus(
            app,
            state,
            "collection:error",
            json!({ "stage": "config", "status": cfg_resp.status().as_u16() }),
        )
        .await;
        sentry::capture_message("collection_error_config_non_transient", Level::Warning);
        return Ok(());
    }

    let cfg_json: Value = cfg_resp.json().await.map_err(|e| e.to_string())?;
    let queries = parse_config_queries(&cfg_json);

    if queries.is_empty() {
        emit_error_and_focus(
            app,
            state,
            "collection:error",
            json!({ "stage": "config", "reason": "no_tables" }),
        )
        .await;
        return Ok(());
    }

    // 2) osquery
    add_breadcrumb("collection", "osquery_start", Level::Info);
    sentry::capture_message("collection_osquery_start", Level::Info);
    let results = execute_sql_batch(app.clone(), queries).await?;
    *state.last_run_at.write().await = Some(std::time::Instant::now());

    // 3) Build the JSON:API payload from the freshly collected rows
    let collected_at = chrono::Utc::now().to_rfc3339();
    let device_serial = get_device_serial_number_internal(app)
        .await
        .unwrap_or_else(|_| "unknown".to_string());
    let items = build_payload_items(&results, &collected_at);
    let row_count = items.len();
    if row_count == 0 {
        let _ = app.emit("collection:success", json!({ "sent_rows": 0 }));
        return Ok(());
    }
    let payload = JsonApiPayload {
        data: items,
        meta: Some(json!({ "device_uuid": device_serial })),
        jsonapi: Some(json!({ "version": "1.0" })),
    };

    // 4) POST straight to /klaayguard/data, reusing the transient-retry ladder
    let mut post_attempt = 0usize;
    loop {
        let body_json = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        match client
            .post(format!("{}/klaayguard/data", base))
            .bearer_auth(&token)
            .header(reqwest::header::CONTENT_TYPE, "application/vnd.api+json")
            .header(reqwest::header::ACCEPT, "application/vnd.api+json")
            .body(body_json)
            .send()
            .await
        {
            Ok(resp) => {
                add_breadcrumb(
                    "collection",
                    &format!("post_status:{}", resp.status().as_u16()),
                    Level::Info,
                );
                if resp.status() == reqwest::StatusCode::UNAUTHORIZED
                    || resp.status() == reqwest::StatusCode::FORBIDDEN
                {
                    invalidate_auth(app, state).await?;
                    let _ = app.emit(
                        "collection:error",
                        json!({ "stage": "post", "status": resp.status().as_u16() }),
                    );
                    return Ok(());
                }
                if resp.status().is_success() || resp.status() == reqwest::StatusCode::ACCEPTED {
                    let _ = app.emit("collection:success", json!({ "sent_rows": row_count }));
                    log::info!("collection_success sent_rows={}", row_count);
                    add_breadcrumb(
                        "collection",
                        &format!("success_count:{}", row_count),
                        Level::Info,
                    );
                    return Ok(());
                } else if is_transient_status(resp.status().as_u16())
                    && post_attempt < retry_delays.len()
                {
                    let delay = retry_delays[post_attempt];
                    sentry::capture_message("collection_post_transient_retry", Level::Warning);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    post_attempt += 1;
                    continue;
                } else {
                    emit_error_and_focus(
                        app,
                        state,
                        "collection:error",
                        json!({ "stage": "post", "status": resp.status().as_u16() }),
                    )
                    .await;
                    return Ok(());
                }
            }
            Err(e) => {
                if post_attempt < retry_delays.len() {
                    let delay = retry_delays[post_attempt];
                    sentry::capture_message("collection_post_retry", Level::Warning);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    post_attempt += 1;
                    continue;
                } else {
                    emit_error_and_focus(
                        app,
                        state,
                        "collection:error",
                        json!({ "stage": "post", "error": e.to_string() }),
                    )
                    .await;
                    return Ok(());
                }
            }
        }
    }
}

fn spawn_background_loop(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let client = reqwest::Client::builder()
            .user_agent("klaayguard/0.1")
            .build()
            .expect("reqwest client");

        // wait for token once
        loop {
            if state.auth_token.read().await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }

        // interval's first tick fires immediately, giving the initial collection.
        // Skip (don't burst) ticks missed while the machine was asleep.
        let mut interval =
            tokio::time::interval(Duration::from_secs(collection_interval_seconds()));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(e) = run_cycle(&app, &state, &client).await {
                log::error!("cycle error: {}", e);
                emit_error_and_focus(
                    &app,
                    &state,
                    "collection:error",
                    json!({ "stage": "internal", "error": e }),
                )
                .await;
            }
        }
    });
}

/// Installs a launch agent for automatic startup on macOS.
///
/// This function creates a launchd plist file in the user's LaunchAgents directory
/// and loads it to ensure the app starts automatically on login. This is a mandatory
/// security feature that cannot be disabled by users.
async fn install_launch_agent() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        use std::fs;
        let home_dir = dirs::home_dir().ok_or("Could not find home directory")?;
        let launch_agents_dir = home_dir.join("Library/LaunchAgents");
        let label = "com.klaay.klaayguard";
        let plist_path = launch_agents_dir.join(format!("{}.plist", label));
        let uid = nix::unistd::getuid().as_raw();
        let domain = format!("gui/{}", uid);

        fs::create_dir_all(&launch_agents_dir)
            .map_err(|e| format!("Failed to create LaunchAgents directory: {}", e))?;

        // Resolve executable path (prefer installed app)
        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get current executable path: {}", e))?;
        let app_bundle_path = std::path::Path::new("/Applications/KlaayGuard.app");
        let installed_exists = app_bundle_path.exists();

        // Render plist
        let app_path: String = if installed_exists {
            "/Applications/KlaayGuard.app".to_string()
        } else {
            current_exe
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "/Applications/KlaayGuard.app".to_string())
        };
        // Determine API base for env injection in LaunchAgent
        let api_base_for_plist: String = std::env::var("VITE_API_BASE_URL")
            .ok()
            .or_else(|| option_env!("APP_DEFAULT_API_BASE_URL").map(|s| s.to_string()))
            .unwrap_or_else(|| "https://api.klaay.com".to_string());

        let log_dir = home_dir.join("Library/Logs/KlaayGuard");
        fs::create_dir_all(&log_dir)
            .map_err(|e| format!("Failed to create log directory: {}", e))?;

        let plist_content = include_str!("../resources/com.klaay.klaayguard.plist")
            .replace("__LABEL__", label)
            .replace("__OPEN_PATH__", "/usr/bin/open")
            .replace("__APP_PATH__", &app_path)
            .replace("__VITE_API_BASE_URL__", &api_base_for_plist)
            .replace("__LOG_DIR__", &log_dir.to_string_lossy());

        let mut needs_reload = true;
        if let Ok(existing) = fs::read_to_string(&plist_path) {
            if existing == plist_content {
                let output = std::process::Command::new("launchctl")
                    .args(&["print", &format!("{}/{}", domain, label)])
                    .output()
                    .map_err(|e| format!("Failed to check launch agent status: {}", e))?;
                if output.status.success() {
                    return Ok("Launch agent already installed and running".to_string());
                }
                needs_reload = false;
            }
        }

        fs::write(&plist_path, plist_content)
            .map_err(|e| format!("Failed to write plist file: {}", e))?;

        if installed_exists {
            if needs_reload {
                let _ = std::process::Command::new("launchctl")
                    .args(&["bootout", &format!("{}/{}", domain, label)])
                    .output();
            }

            let output = std::process::Command::new("launchctl")
                .args(&["bootstrap", &domain, plist_path.to_str().unwrap()])
                .output()
                .map_err(|e| format!("Failed to bootstrap launch agent: {}", e))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("EEXIST") && !stderr.contains("already loaded") {
                    return Err(format!("Failed to bootstrap launch agent: {}", stderr));
                }
            }

            let _ = std::process::Command::new("launchctl")
                .args(&["enable", &format!("{}/{}", domain, label)])
                .output();
            let _ = std::process::Command::new("launchctl")
                .args(&["kickstart", "-k", &format!("{}/{}", domain, label)])
                .output();
        } else {
            // Not installed under /Applications; skip bootstrap to avoid immediate launch errors in dev.
            // launchd will load the agent at next login.
        }

        Ok("Launch agent installed successfully".to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("Launch agent installation is only supported on macOS".to_string())
    }
}

#[derive(serde::Deserialize)]
struct ReleaseAsset {
    id: u64,
    // Human-facing label, e.g. "MacOS (Apple silicon)". Does NOT encode arch reliably.
    name: String,
    // The real artifact filename, e.g. "KlaayGuard_0.1.12_macOS_arm64_production.dmg".
    original_name: Option<String>,
    // Expected hash of the asset bytes (bare hex or "sha256:" prefixed).
    sha256: Option<String>,
}

/// The update asset chosen for this host: which one to download and its expected hash.
struct SelectedUpdate {
    asset_id: String,
    sha256: Option<String>,
}

/// macOS artifact tags for the current host: (filename infix, friendly-name infix).
fn host_arch_tags() -> Option<(&'static str, &'static str)> {
    match std::env::consts::ARCH {
        "aarch64" => Some(("macOS_arm64", "Apple silicon")),
        "x86_64" => Some(("macOS_x64", "Intel")),
        _ => None,
    }
}

/// Pick the DMG asset matching this host's architecture. Prefers the real
/// artifact filename (`original_name`); falls back to the friendly label only
/// when it is absent. Returns None rather than guess the wrong architecture.
fn select_dmg_asset<'a>(
    assets: &'a [ReleaseAsset],
    arch_tag: &str,
    arch_label: &str,
) -> Option<&'a ReleaseAsset> {
    assets.iter().find(|asset| match asset.original_name.as_deref() {
        Some(orig) => orig.ends_with(".dmg") && orig.contains(arch_tag),
        None => asset.name.contains(arch_label),
    })
}

/// Whether `bytes` hashes to `expected` (bare hex or "sha256:"-prefixed).
fn sha256_matches(bytes: &[u8], expected: &str) -> bool {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual: String = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect();
    actual.eq_ignore_ascii_case(expected.trim_start_matches("sha256:"))
}

#[derive(serde::Deserialize)]
struct ReleaseInfo {
    #[serde(rename = "name")]
    _name: Option<String>,
    version: String, // This is the tag_name from GitHub
    assets: Vec<ReleaseAsset>,
}

fn get_api_base_url() -> String {
    // Use the same logic as the main app startup
    std::env::var("VITE_API_BASE_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_API_BASE_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://api.klaay.com".to_string())
}

fn get_earthenware_url() -> String {
    std::env::var("VITE_EARTHENWARE_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_EARTHENWARE_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://app.klaay.com".to_string())
}

/// Open the browser to the Earthenware sign-in page; it deep-links back via
/// `klaayguard://auth-callback?token=…`. Invoked from the tray "Sign in" item.
/// Open an Earthenware path in the default browser.
fn open_earthenware(app: &tauri::AppHandle, path: &str) {
    let url = format!("{}{}", get_earthenware_url(), path);
    log::info!("opening url={}", url);
    if let Err(e) = app.shell().open(url.clone(), None) {
        log::error!("failed to open url {}: {}", url, e);
    }
}

/// Open the Earthenware sign-in page; it deep-links back via klaayguard://.
fn open_sign_in(app: &tauri::AppHandle) {
    open_earthenware(app, "/login?app=klaayguard");
}

/// Handle to the single tray item whose text + enabled state reflect auth state.
struct TrayMenu {
    item: tauri::menu::MenuItem<tauri::Wry>,
}

/// Format seconds-until-next-fetch as a short countdown string.
fn fmt_countdown(secs: i64) -> String {
    if secs <= 0 {
        return "Fetching now…".to_string();
    }
    let (m, s) = (secs / 60, secs % 60);
    if m > 0 {
        format!("Next fetch in {}m {:02}s", m, s)
    } else {
        format!("Next fetch in {}s", s)
    }
}

/// Refresh the single tray item: a clickable "Sign in" when signed out, or a greyed
/// countdown to the next fetch when signed in. Menu mutation runs on the main thread.
async fn refresh_tray(app: &tauri::AppHandle, state: &Arc<AppState>) {
    let (text, enabled) = if state.auth_token.read().await.is_some() {
        let interval = collection_interval_seconds() as i64;
        let remaining = match *state.last_attempt_at.read().await {
            Some(t) => (interval - t.elapsed().as_secs() as i64).max(0),
            None => 0,
        };
        (fmt_countdown(remaining), false)
    } else {
        ("Sign in".to_string(), true)
    };
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(tray) = handle.try_state::<TrayMenu>() {
            let _ = tray.item.set_text(&text);
            let _ = tray.item.set_enabled(enabled);
        }
    });
}

/// Tick the tray countdown once a second so it's current whenever the menu opens.
fn spawn_tray_clock(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(1));
        loop {
            iv.tick().await;
            refresh_tray(&app, &state).await;
        }
    });
}

async fn check_for_updates_internal(api_base: &str) -> Result<Option<SelectedUpdate>, String> {
    let current_version = env!("CARGO_PKG_VERSION");
    log::info!(
        "🔍 Starting update check - current version: {}",
        current_version
    );
    log::info!(
        "🌐 Checking for updates from API: {}/klaayguard/updates/latest",
        api_base
    );

    let client = reqwest::Client::new();

    // Get latest release info
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

    log::info!(
        "📦 Found release: {} with {} assets",
        release.version,
        release.assets.len()
    );
    for (i, asset) in release.assets.iter().enumerate() {
        log::info!("  Asset {}: {} (ID: {})", i + 1, asset.name, asset.id);
        if let Some(orig_name) = &asset.original_name {
            log::info!("    Original name: {}", orig_name);
        }
    }

    // Normalize versions by removing 'v' prefix for comparison
    let normalized_current = current_version.trim_start_matches('v');
    let normalized_release = release.version.trim_start_matches('v');

    // Parse versions as semantic versions for proper comparison
    let current_semver = match semver::Version::parse(normalized_current) {
        Ok(v) => v,
        Err(e) => {
            log::error!(
                "❌ Failed to parse current version '{}': {}",
                normalized_current,
                e
            );
            return Err(format!(
                "Invalid current version format: {}",
                normalized_current
            ));
        }
    };

    let release_semver = match semver::Version::parse(normalized_release) {
        Ok(v) => v,
        Err(e) => {
            log::error!(
                "❌ Failed to parse release version '{}': {}",
                normalized_release,
                e
            );
            return Err(format!(
                "Invalid release version format: {}",
                normalized_release
            ));
        }
    };

    // Only suggest update if release version is newer
    if release_semver > current_semver {
        log::info!(
            "🆚 Version comparison: {} < {} (update available)",
            current_version,
            release.version
        );

        // The manifest returns every macOS build (arm64 + x64); the human-facing
        // `name` does not distinguish them, so match on `original_name` (the real
        // artifact filename) against THIS host's architecture. Picking the wrong
        // arch would install an app the arch-mismatch gate then refuses to launch.
        let Some((arch_tag, arch_label)) = host_arch_tags() else {
            log::warn!(
                "⚠️  No macOS update artifact for architecture: {}",
                std::env::consts::ARCH
            );
            return Ok(None);
        };

        if let Some(dmg_asset) = select_dmg_asset(&release.assets, arch_tag, arch_label) {
            log::info!(
                "✅ Selected {} update: {} (ID: {})",
                arch_tag,
                dmg_asset.original_name.as_deref().unwrap_or(&dmg_asset.name),
                dmg_asset.id
            );
            log::info!(
                "🚀 Update available: {} -> {}",
                current_version,
                release.version
            );
            return Ok(Some(SelectedUpdate {
                asset_id: dmg_asset.id.to_string(),
                sha256: dmg_asset.sha256.clone(),
            }));
        } else {
            log::warn!(
                "⚠️  No {} DMG asset found in release assets",
                arch_tag
            );
        }
    } else if release_semver < current_semver {
        log::info!(
            "✅ No update needed - current version {} is newer than release {}",
            current_version,
            release.version
        );
    } else {
        log::info!(
            "✅ No update needed - already at latest version: {}",
            current_version
        );
    }

    Ok(None)
}

async fn download_and_install_update_internal(
    api_base: &str,
    asset_id: &str,
    expected_sha256: Option<&str>,
    app: &tauri::AppHandle,
) -> Result<(), String> {
    log::info!(
        "📥 Starting download and install process for asset ID: {}",
        asset_id
    );

    let client = reqwest::Client::new();

    // Download the DMG
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

    // Get the download path
    let downloads_dir = dirs::download_dir().ok_or_else(|| {
        log::error!("❌ Could not find downloads directory");
        "Could not find downloads directory"
    })?;
    let dmg_path = downloads_dir.join("KlaayGuard-update.dmg");

    log::info!("💾 Downloading to: {:?}", dmg_path);

    // Save the DMG file
    let mut file = std::fs::File::create(&dmg_path).map_err(|e| {
        log::error!("❌ Failed to create update file: {}", e);
        format!("Failed to create update file: {}", e)
    })?;

    let bytes = response.bytes().await.map_err(|e| {
        log::error!("❌ Download error: {}", e);
        format!("Download error: {}", e)
    })?;

    log::info!("📊 Downloaded {} bytes", bytes.len());

    // Verify integrity before we mount and swap a running security agent.
    match expected_sha256 {
        Some(expected) if !sha256_matches(&bytes, expected) => {
            let msg = format!("Update checksum mismatch for expected {}", expected);
            log::error!("❌ {}", msg);
            sentry::capture_message(&msg, Level::Error);
            return Err(msg);
        }
        Some(expected) => log::info!("🔐 Update checksum verified against {}", expected),
        None => log::warn!("⚠️  No checksum provided for update asset; skipping verification"),
    }

    std::io::Write::write_all(&mut file, &bytes).map_err(|e| {
        log::error!("❌ Write error: {}", e);
        format!("Write error: {}", e)
    })?;

    log::info!("✅ Update downloaded successfully to: {:?}", dmg_path);

    // Mount the DMG and replace the app
    log::info!("🔄 Starting application replacement process...");
    replace_application(&dmg_path, app).await?;

    Ok(())
}

async fn replace_application(
    dmg_path: &std::path::Path,
    app: &tauri::AppHandle,
) -> Result<(), String> {
    log::info!("💿 Mounting DMG: {:?}", dmg_path);

    // Mount the DMG
    let mount_output = std::process::Command::new("hdiutil")
        .args(&["attach", dmg_path.to_str().unwrap()])
        .output()
        .map_err(|e| {
            log::error!("❌ Failed to mount DMG: {}", e);
            format!("Failed to mount DMG: {}", e)
        })?;

    if !mount_output.status.success() {
        let error_msg = "Failed to mount DMG".to_string();
        log::error!(
            "❌ {} - hdiutil output: {}",
            error_msg,
            String::from_utf8_lossy(&mount_output.stderr)
        );
        return Err(error_msg);
    }

    // Extract mount point from hdiutil output
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

    // Check if source app exists
    if !source_app.exists() {
        let error_msg = format!("Source app not found at: {:?}", source_app);
        log::error!("❌ {}", error_msg);
        return Err(error_msg);
    }

    // Remove old app and copy new one
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

    log::info!(
        "📋 Copying new app from {:?} to {:?}",
        source_app,
        target_app
    );
    let copy_result = std::process::Command::new("cp")
        .args(&[
            "-R",
            source_app.to_str().unwrap(),
            target_app.to_str().unwrap(),
        ])
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

    // Unmount the DMG
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

    // Remove the DMG file
    log::info!("🗑️  Removing temporary DMG file: {:?}", dmg_path);
    if let Err(e) = std::fs::remove_file(dmg_path) {
        log::warn!("⚠️  Failed to remove DMG file: {}", e);
        // Don't fail the whole process for this
    } else {
        log::info!("✅ Temporary DMG file removed");
    }

    log::info!("🎉 Application updated successfully! Restarting...");

    // Restart the application
    app.restart();
}
/// Main entry point for the KlaayGuard security monitoring application.
///
/// This function initializes the Tauri application with security-focused configuration:
/// - Hides the app from the dock on macOS for background operation
/// - Creates a system tray with limited options (no quit functionality)
/// - Sets up automatic updates for security patches
/// - Configures window behavior to prevent accidental closure
///
/// Security Features:
/// - Background operation prevents easy termination
/// - System tray provides controlled access
/// - Automatic updates ensure latest security patches
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Prefer runtime env; fall back to compile-time embedded default; then hard-coded prod
    let api_base = std::env::var("VITE_API_BASE_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_API_BASE_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://api.klaay.com".to_string());
    if let Ok(earthenware) = std::env::var("VITE_EARTHENWARE_URL") {
        add_breadcrumb(
            "startup",
            &format!("endpoints api:{} earthenware:{}", api_base, earthenware),
            Level::Info,
        );
        // naive mismatch hint: localhost vs non-localhost
        let api_is_local = api_base.contains("localhost") || api_base.contains("127.0.0.1");
        let ew_is_local = earthenware.contains("localhost") || earthenware.contains("127.0.0.1");
        if api_is_local ^ ew_is_local {
            add_breadcrumb(
                "startup",
                "endpoint_mismatch_local_vs_remote",
                Level::Warning,
            );
        }
    } else {
        add_breadcrumb(
            "startup",
            &format!("endpoints api:{} earthenware:<unset>", api_base),
            Level::Info,
        );
    }
    let state = Arc::new(AppState {
        auth_token: RwLock::new(None),
        api_base_url: RwLock::new(api_base),
        last_run_at: RwLock::new(None),
        last_attempt_at: RwLock::new(None),
        keychain_cleared_this_session: RwLock::new(false),
        last_focus_at: RwLock::new(None),
    });

    let app = tauri::Builder::default()
        .manage(state.clone())
        .plugin(tauri_plugin_shell::init())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // Handle deep link if present in args (secondary launches)
            let st = app.state::<Arc<AppState>>().inner().clone();
            log::info!(
                "single_instance_args count={} sample_arg0={}",
                args.len(),
                args.get(0).cloned().unwrap_or_default()
            );
            for a in args {
                if a.starts_with("klaayguard://") {
                    log::info!("single_instance_deep_link_received");
                    handle_deep_link_url(&app, &st, &a);
                    break;
                }
            }
            log::info!("single_instance: secondary launch routed to primary instance");
        }))
        .setup(|app| {
            // Tray-only background service: hide from dock, no window.
            #[cfg(target_os = "macos")]
            {
                app.set_activation_policy(tauri::ActivationPolicy::Accessory);
                log::info!("KlaayGuard configured as background service - tray only, hidden from dock");
            }

            // Architecture mismatch: warn the user natively and do NOT start the
            // collection loop (the binary can't run correctly on this hardware).
            if std::env::var("KLAAY_ARCH_MISMATCH").ok().as_deref() == Some("1") {
                let built = std::env::var("KLAAY_ARCH_BUILT")
                    .unwrap_or_else(|_| std::env::consts::ARCH.to_string());
                let host =
                    std::env::var("KLAAY_ARCH_HOST").unwrap_or_else(|_| "unknown".to_string());
                log::error!("arch_mismatch built={} host={}", built, host);
                #[cfg(target_os = "macos")]
                {
                    let script = format!(
                        "display dialog \"KlaayGuard was built for {} but this Mac is {}. Please reinstall the correct build.\" buttons {{\"OK\"}} with icon stop with title \"KlaayGuard\"",
                        built, host
                    );
                    let _ = std::process::Command::new("osascript")
                        .args(["-e", &script])
                        .spawn();
                }
                return Ok(());
            }

            // Check if we're already running as a regular process to prevent duplicates
            // Duplicate instance prevention handled by single-instance plugin; remove manual pgrep/exit logic

            // Check for updates on startup and install automatically
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                log::info!("🚀 Starting automatic update check on app startup");
                let api_base = get_api_base_url();
                log::info!("🌐 Using API base URL: {}", api_base);
                if let Ok(Some(update)) = check_for_updates_internal(&api_base).await {
                    log::info!("🔄 Update available, starting download and install process...");
                    if let Err(e) = download_and_install_update_internal(
                        &api_base,
                        &update.asset_id,
                        update.sha256.as_deref(),
                        &app_handle,
                    )
                    .await
                    {
                        log::error!("💥 Auto-update failed: {}", e);
                    }
                } else {
                    log::info!("✅ No updates available - app is up to date");
                }
            });

            // Install and kickstart LaunchAgent with KeepAlive
            #[cfg(target_os = "macos")]
            {
                tauri::async_runtime::spawn(async {
                    if let Err(e) = install_launch_agent().await {
                        log::error!("LaunchAgent install failed: {}", e);
                        sentry::capture_message(
                            &format!("launch_agent_install_failed:{}", e),
                            Level::Error,
                        );
                    }
                });
            }
            // Load any saved token; if absent, nudge the user to sign in via the tray.
            let state_for_loop = app.state::<Arc<AppState>>().inner().clone();
            let authed = if let Ok(Some(tok)) = keychain::load_token() {
                tauri::async_runtime::block_on(async {
                    *state_for_loop.auth_token.write().await = Some(tok);
                });
                true
            } else {
                false
            };
            if authed {
                log::info!("KlaayGuard started - authenticated, collecting in background");
            } else {
                log::info!("KlaayGuard started - sign-in required");
                let st = state_for_loop.clone();
                tauri::async_runtime::spawn(async move { notify_signin_needed(&st).await });
            }

            // Handle deep link if app was launched by klaayguard:// URL (first instance)
            try_handle_deep_link_from_args(&app.handle(), &state_for_loop);

            // Tray menu: live auth/countdown item, an Employee Hub link, and a version
            // line. No quit, no sign-out. Only the auth item updates at runtime.
            let item = tauri::menu::MenuItem::with_id(
                app,
                "auth_action",
                if authed { "Signed in" } else { "Sign in" },
                !authed,
                None::<&str>,
            )?;
            let hub_i = tauri::menu::MenuItem::with_id(
                app,
                "employee_hub",
                "Employee Hub",
                true,
                None::<&str>,
            )?;
            let version_i = tauri::menu::MenuItem::with_id(
                app,
                "version",
                format!("Version {}", env!("CARGO_PKG_VERSION")),
                false,
                None::<&str>,
            )?;
            let sep = tauri::menu::PredefinedMenuItem::separator(app)?;
            app.manage(TrayMenu { item: item.clone() });
            let menu = tauri::menu::Menu::with_items(
                app,
                &[
                    &item as &dyn tauri::menu::IsMenuItem<tauri::Wry>,
                    &hub_i,
                    &sep,
                    &version_i,
                ],
            )?;
            tauri::tray::TrayIconBuilder::new()
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "auth_action" => open_sign_in(app),
                    "employee_hub" => open_earthenware(app, "/employee-hub"),
                    _ => {}
                })
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("KlaayGuard")
                .menu(&menu)
                .build(app)?;
            // Spawn the single collect-and-send loop + the tray countdown clock.
            let state_for_loop = app.state::<Arc<AppState>>().inner().clone();
            let app_handle = app.handle().clone();
            spawn_tray_clock(app_handle.clone(), state_for_loop.clone());
            spawn_background_loop(app_handle, state_for_loop);

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error building tauri application");

    app.run(|_app_handle, event| match event {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        tauri::RunEvent::Opened { urls } => {
            // macOS open-url events deliver here; handle klaayguard:// URLs at runtime
            if !urls.is_empty() {
                let st = _app_handle.state::<Arc<AppState>>().inner().clone();
                for u in urls {
                    let s = u.to_string();
                    log::info!("run_event_opened url={}", s);
                    handle_deep_link_url(&_app_handle, &st, &s);
                }
            }
        }
        _ => {}
    });
}

#[cfg(test)]
mod update_selection_tests {
    use super::*;

    // Mirrors the real /klaayguard/updates/latest manifest: both macOS arches
    // plus Linux artifacts in one release.
    fn manifest() -> Vec<ReleaseAsset> {
        serde_json::from_str(
            r#"[
              {"id":1,"name":"Linux (Debian/Ubuntu .deb)","original_name":"KlaayGuard_0.1.12_Linux_x86_64_production.deb","sha256":"aa"},
              {"id":2,"name":"MacOS (Apple silicon)","original_name":"KlaayGuard_0.1.12_macOS_arm64_production.dmg","sha256":"bb"},
              {"id":3,"name":"MacOS (Intel)","original_name":"KlaayGuard_0.1.12_macOS_x64_production.dmg","sha256":"cc"}
            ]"#,
        )
        .unwrap()
    }

    #[test]
    fn selects_arm64_dmg_for_apple_silicon() {
        let assets = manifest();
        let sel = select_dmg_asset(&assets, "macOS_arm64", "Apple silicon").unwrap();
        assert_eq!(sel.id, 2);
        assert_eq!(
            sel.original_name.as_deref(),
            Some("KlaayGuard_0.1.12_macOS_arm64_production.dmg")
        );
    }

    #[test]
    fn selects_x64_dmg_for_intel() {
        let assets = manifest();
        let sel = select_dmg_asset(&assets, "macOS_x64", "Intel").unwrap();
        assert_eq!(sel.id, 3);
    }

    #[test]
    fn never_selects_a_non_dmg_or_wrong_arch() {
        // The pre-fix bug returned the first ".dmg"/"MacOS" match; assert each
        // arch resolves to its OWN dmg and never a Linux artifact.
        let assets = manifest();
        for (tag, label, want) in [
            ("macOS_arm64", "Apple silicon", 2u64),
            ("macOS_x64", "Intel", 3u64),
        ] {
            let sel = select_dmg_asset(&assets, tag, label).unwrap();
            assert_eq!(sel.id, want);
            assert!(sel.original_name.as_deref().unwrap().ends_with(".dmg"));
        }
    }

    #[test]
    fn falls_back_to_friendly_label_without_original_name() {
        let assets: Vec<ReleaseAsset> =
            serde_json::from_str(r#"[{"id":9,"name":"MacOS (Intel)","sha256":null}]"#).unwrap();
        assert_eq!(select_dmg_asset(&assets, "macOS_x64", "Intel").unwrap().id, 9);
        assert!(select_dmg_asset(&assets, "macOS_arm64", "Apple silicon").is_none());
    }

    #[test]
    fn checksum_accepts_match_and_rejects_mismatch() {
        // sha256("") well-known digest, bare and "sha256:"-prefixed.
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(sha256_matches(b"", expected));
        assert!(sha256_matches(b"", &format!("sha256:{}", expected)));
        assert!(!sha256_matches(b"tampered", expected));
    }
}

#[cfg(test)]
mod happy_path_tests {
    use super::*;

    #[test]
    fn deep_link_token_extracted_and_shape_validated() {
        assert_eq!(
            parse_deep_link_token("klaayguard://auth-callback?token=aaa.bbb.ccc"),
            Some("aaa.bbb.ccc".to_string())
        );
        // token among other params
        assert_eq!(
            parse_deep_link_token("klaayguard://x?foo=1&token=aaa.bbb.ccc&bar=2"),
            Some("aaa.bbb.ccc".to_string())
        );
    }

    #[test]
    fn deep_link_token_rejected_when_invalid() {
        assert_eq!(parse_deep_link_token("https://evil?token=aaa.bbb.ccc"), None); // wrong scheme
        assert_eq!(parse_deep_link_token("klaayguard://x?foo=1"), None); // no token
        assert_eq!(parse_deep_link_token("klaayguard://x?token=not-a-jwt"), None); // wrong shape
    }

    #[test]
    fn config_queries_use_explicit_sql_or_default_select() {
        let cfg = json!({"data": [
            {"type": "osquery-table", "id": "system_info"},
            {"type": "osquery-table", "id": "users", "sql": "SELECT username FROM users"}
        ]});
        let q = parse_config_queries(&cfg);
        assert_eq!(q.len(), 2);
        assert!(q.contains(&("system_info".to_string(), "SELECT * FROM system_info".to_string())));
        assert!(q.contains(&("users".to_string(), "SELECT username FROM users".to_string())));
    }

    #[test]
    fn config_queries_empty_when_no_data() {
        assert!(parse_config_queries(&json!({})).is_empty());
        assert!(parse_config_queries(&json!({"data": []})).is_empty());
    }

    #[test]
    fn payload_items_flatten_rows_and_stamp_collected_at() {
        let mut results = HashMap::new();
        results.insert("users".to_string(), json!([{"username": "a"}, {"username": "b"}]));
        let items = build_payload_items(&results, "2026-06-22T00:00:00Z");
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|i| i.r#type == "users"));
        assert_eq!(items[0].attributes["collected_at"], json!("2026-06-22T00:00:00Z"));
        assert!(items[0].attributes.get("username").is_some());
    }

    #[test]
    fn payload_items_empty_for_no_rows() {
        let results: HashMap<String, Value> = HashMap::new();
        assert!(build_payload_items(&results, "T").is_empty());
    }

    #[test]
    fn serial_extracted_from_system_info_hardware_serial() {
        // Shaped like real osquery system_info: serial is `hardware_serial`, not `serial_number`.
        let rows = json!([{"hardware_serial": "G97L3X4KYV", "uuid": "9082C1CD", "computer_name": "Athene"}]);
        assert_eq!(extract_serial(&rows), Some("G97L3X4KYV".to_string()));
    }

    #[test]
    fn serial_falls_back_to_uuid_then_none() {
        let only_uuid = json!([{"uuid": "9082C1CD"}]);
        assert_eq!(extract_serial(&only_uuid), Some("9082C1CD".to_string()));
        assert_eq!(extract_serial(&json!([])), None);
        assert_eq!(extract_serial(&Value::Null), None);
    }
}
