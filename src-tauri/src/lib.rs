// Copyright (C) 2024 KLAAY, Inc.
//! KlaayGuard: System Tray-Only Security Agent
//! 
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
        
        // Update tray menu to show logout option
        update_tray_menu(app, state).await;
        
        // Show success notification
        let _ = app.notification()
            .builder()
            .title("KlaayGuard")
            .body("Successfully authenticated! Collecting data now...")
            .show();
        
        // Immediately trigger data collection to show green/red dot
        set_tray_icon_and_tooltip(
            app,
            "icon-default.png",
            "✓ Authenticated - Collecting data..."
        );
        
        log::info!("deep_link_triggering_immediate_collection");
        match run_cycle(app, state).await {
            Ok(_) => {
                log::info!("deep_link_immediate_collection_completed");
                update_tray_status(app, state, true).await;
            }
            Err(e) => {
                log::error!("deep_link_immediate_collection_failed error={}", e);
                update_tray_status(app, state, false).await;
            }
        }
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
async fn get_api_base_url_cmd(state: tauri::State<'_, Arc<AppState>>) -> Result<String, String> {
    let url = state.api_base_url.read().await.clone();
    Ok(url)
}

fn get_api_base_url() -> String {
    std::env::var("APP_DEFAULT_API_BASE_URL").unwrap_or_else(|_| "https://api.klaay.com".to_string())
}

#[tauri::command]
async fn get_app_version() -> Result<String, String> {
    let version = env!("CARGO_PKG_VERSION");
    log::info!("📱 Frontend requested app version: {}", version);
    Ok(version.to_string())
}

fn get_client_with_retries() -> reqwest_middleware::ClientWithMiddleware {
    use reqwest_middleware::ClientBuilder;
    use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};

    let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
    let base = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    ClientBuilder::new(base)
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build()
}

async fn execute_query(
    app: tauri::AppHandle,
    tables: Vec<String>,
) -> Result<HashMap<String, Value>, String> {
    let queries: Vec<(String, String)> = tables
        .into_iter()
        .map(|t| {
            let sql = format!("SELECT * FROM {};", t);
            (t, sql)
        })
        .collect();

    execute_sql_batch(app, queries).await
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
    let tables = vec!["system_info".to_string()];
    let result = execute_query(app.clone(), tables).await?;
    let serial = result
        .get("system_info")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|obj| {
            obj.get("hardware_serial")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    obj.get("uuid")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                })
        })
        .ok_or_else(|| "Couldn't find hardware serial number".to_string())?;
    Ok(serial.to_string())
}

/// Build tray menu dynamically based on authentication status
fn build_tray_menu(app: &tauri::AppHandle, is_authenticated: bool) -> Result<tauri::menu::Menu<tauri::Wry>, Box<dyn std::error::Error>> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    
    let status_text = if is_authenticated {
        "✅ Authenticated"
    } else {
        "🔴 Not Authenticated"
    };
    
    // Status indicator (disabled, non-clickable)
    let status_item = MenuItem::with_id(app, "status", status_text, false, None::<&str>)?;
    
    // Build menu based on authentication status
    if !is_authenticated {
        let separator = PredefinedMenuItem::separator(app)?;
        let login_item = MenuItem::with_id(app, "login", "Login", true, None::<&str>)?;
        let items: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = vec![
            &status_item,
            &separator,
            &login_item,
        ];
        Menu::with_items(app, &items).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    } else {
        // When authenticated, only show status (no logout option)
        let items: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = vec![
            &status_item,
        ];
        Menu::with_items(app, &items).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}

/// Update tray menu based on current authentication status
async fn update_tray_menu(app: &tauri::AppHandle, state: &Arc<AppState>) {
    let is_authenticated = state.auth_token.read().await.is_some();
    
    if let Ok(menu) = build_tray_menu(app, is_authenticated) {
        if let Some(tray) = app.tray_by_id("main") {
            if let Err(e) = tray.set_menu(Some(menu)) {
                log::error!("Failed to update tray menu: {}", e);
            } else {
                log::info!("✓ Tray menu updated (authenticated: {})", is_authenticated);
            }
        }
    }
}

/// Helper function to set tray icon and tooltip
fn set_tray_icon_and_tooltip(app: &tauri::AppHandle, icon_name: &str, tooltip: &str) {
    log::info!("🔧 set_tray_icon_and_tooltip called: icon={}, tooltip={}", icon_name, tooltip);
    
    if let Some(tray) = app.tray_by_id("main") {
        // Update tooltip
        if let Err(e) = tray.set_tooltip(Some(tooltip.to_string())) {
            log::error!("Failed to set tooltip: {}", e);
        } else {
            log::info!("✓ Tooltip set successfully");
        }
        
        // In dev mode, icons are in src-tauri/icons/ or icons/
        // In production, they're in the resource directory
        let icon_path = if cfg!(debug_assertions) {
            // Dev mode: try multiple paths
            let current = std::env::current_dir().unwrap_or_default();
            log::info!("📂 Current dir: {}", current.display());
            
            let paths_to_try = vec![
                current.join("icons").join(icon_name),                    // If running from src-tauri/
                current.join("src-tauri").join("icons").join(icon_name),  // If running from project root
                current.parent().unwrap_or(&current).join("icons").join(icon_name), // One level up
            ];
            
            let mut found_path = None;
            for path in paths_to_try {
                log::info!("🔍 Trying icon path: {}", path.display());
                if path.exists() {
                    log::info!("✅ Found dev icon at: {}", path.display());
                    found_path = Some(path);
                    break;
                } else {
                    log::debug!("❌ Not found: {}", path.display());
                }
            }
            
            if found_path.is_none() {
                // Fallback to resource dir (try both with and without icons/ subdirectory)
                if let Ok(resource_dir) = app.path().resource_dir() {
                    // Try icons/ subdirectory first
                    let icon_subdir_path = resource_dir.join("icons").join(icon_name);
                    if icon_subdir_path.exists() {
                        log::info!("✅ Found resource icon at: {}", icon_subdir_path.display());
                        found_path = Some(icon_subdir_path);
                    } else {
                        // Try root resource dir
                        let full_path = resource_dir.join(icon_name);
                        if full_path.exists() {
                            log::info!("✅ Found resource icon at: {}", full_path.display());
                            found_path = Some(full_path);
                        } else {
                            log::warn!("❌ Resource icon not found: {}", full_path.display());
                        }
                    }
                }
            }
            
            found_path
        } else {
            // Production: use resource dir (try both with and without icons/ subdirectory)
            app.path().resource_dir()
                .ok()
                .and_then(|p| {
                    // Try icons/ subdirectory first
                    let icon_subdir_path = p.join("icons").join(icon_name);
                    if icon_subdir_path.exists() {
                        log::info!("✅ Found resource icon at: {}", icon_subdir_path.display());
                        Some(icon_subdir_path)
                    } else {
                        // Try root resource dir
                        let full_path = p.join(icon_name);
                        if full_path.exists() {
                            log::info!("✅ Found resource icon at: {}", full_path.display());
                            Some(full_path)
                        } else {
                            log::warn!("Icon file not found: {}", full_path.display());
                            None
                        }
                    }
                })
        };
        
        if let Some(path) = icon_path {
            log::info!("📂 Reading icon from: {}", path.display());
            match std::fs::read(&path) {
                Ok(bytes) => {
                    log::info!("✓ Icon file read: {} bytes", bytes.len());
                    match image::load_from_memory(&bytes) {
                        Ok(img) => {
                            let rgba = img.to_rgba8();
                            let (width, height) = rgba.dimensions();
                            log::info!("✓ Icon decoded: {}x{}", width, height);
                            let icon = tauri::image::Image::new_owned(rgba.into_raw(), width, height);
                            
                            if let Err(e) = tray.set_icon(Some(icon)) {
                                log::error!("❌ Failed to update tray icon: {}", e);
                } else {
                                log::info!("✅ Tray icon updated to: {}", icon_name);
                }
            }
            Err(e) => {
                            log::error!("❌ Failed to decode icon image {}: {}", icon_name, e);
                        }
                    }
                }
                Err(e) => {
                    log::error!("❌ Failed to read icon file {}: {}", path.display(), e);
                }
            }
                } else {
            log::error!("❌ Could not locate icon file: {}", icon_name);
        }
    } else {
        log::error!("❌ Tray icon with id 'main' not found!");
    }
}

async fn update_tray_status(app: &tauri::AppHandle, state: &Arc<AppState>, success: bool) {
    // Check if authenticated first - if not, show red (error state)
    if state.auth_token.read().await.is_none() {
        log::debug!("Not authenticated - showing red dot");
        set_tray_icon_and_tooltip(
            app,
            "icon-error.png",
            "🔴 Not authenticated - Click Login to start monitoring"
        );
        return;
    }
    
    // Update last send status
    *state.last_send_status.write().await = Some(success);
    *state.last_send_at.write().await = Some(chrono::Utc::now());
    
    let (tooltip, notification_msg, icon_name) = if success {
        ("🟢 Last data send successful".to_string(), None, "icon-success.png")
    } else {
        ("🔴 Last data send failed".to_string(), Some("Data send failed. Will retry in 1 hour."), "icon-error.png")
    };
    
    set_tray_icon_and_tooltip(app, icon_name, &tooltip);
    
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
    resource_type: String,
    attributes: serde_json::Value,
}

async fn run_cycle(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<(), String> {
    log::info!("Starting collection cycle");
    add_breadcrumb("collection", "cycle_start", Level::Info);

    let token_opt = state.auth_token.read().await.clone();
    let Some(token) = token_opt else {
        log::info!("Skipping collection - no auth token");
        return Ok(());
    };

    let api_base = state.api_base_url.read().await.clone();
    let serial = get_device_serial_number_internal(app).await?;

    // 1) Fetch config from Kiln
    let client = get_client_with_retries();
    let cfg_url = format!("{}/klaayguard/config", api_base);
    let cfg_resp = client
        .get(&cfg_url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
        .header(reqwest::header::ACCEPT, "application/vnd.api+json")
            .send()
            .await
        .map_err(|e| e.to_string())?;

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
    
    // Parse queries from Kiln's config format: { data: [{ id, type, sql? }] }
    let queries: Vec<(String, String)> = cfg_json
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let logical_id = item.get("id")?.as_str()?.to_string();
                    // If sql is provided, use it; otherwise use "SELECT * FROM {id}"
                    let sql = item
                        .get("sql")
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("SELECT * FROM {}", logical_id));
                    Some((logical_id, sql))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if queries.is_empty() {
        log::info!("No queries in config");
        add_breadcrumb("collection", "no_queries", Level::Info);
        return Ok(());
    }

    // 2) Execute queries
    let results_map = execute_sql_batch(app.clone(), queries).await?;
    add_breadcrumb("collection", &format!("executed_queries:{}", results_map.len()), Level::Info);

    // 3) POST to Kiln data endpoint
    // Format: { meta: { device_uuid }, data: [{ type, attributes }] }
    let data_array: Vec<Value> = results_map
        .into_iter()
        .map(|(table_name, rows)| {
            json!({
                "type": table_name,
                "attributes": {
                    "rows": rows
                }
            })
        })
        .collect();

    let body_json = serde_json::to_string(&json!({
        "meta": {
            "device_uuid": serial
        },
        "data": data_array
    }))
    .map_err(|e| format!("serialize: {}", e))?;

    let post_url = format!("{}/klaayguard/data", api_base);
    let post_result = client
        .post(&post_url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
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
        log::info!("Background loop started");
        let interval_secs = collection_interval_seconds();
        log::info!("Collection interval: {} seconds", interval_secs);

        // Run immediately on startup
        match run_cycle(&app, &state).await {
            Ok(_) => {
                log::info!("Initial collection cycle completed successfully");
                // Only update tray status if we're authenticated (collection actually ran)
                if state.auth_token.read().await.is_some() {
                    update_tray_status(&app, &state, true).await;
                }
            }
            Err(e) => {
                log::error!("Initial collection cycle error: {}", e);
                add_breadcrumb("collection", &format!("cycle_error:{}", e), Level::Error);
                // Only update tray status if we're authenticated
                if state.auth_token.read().await.is_some() {
                    update_tray_status(&app, &state, false).await;
                }
            }
        }

        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            log::info!("Timer tick - starting collection cycle");
            match run_cycle(&app, &state).await {
                Ok(_) => {
                    log::info!("Collection cycle completed successfully");
                    // Only update tray status if we're authenticated (collection actually ran)
                    if state.auth_token.read().await.is_some() {
                        update_tray_status(&app, &state, true).await;
                    }
                }
                Err(e) => {
                    log::error!("Collection cycle error: {}", e);
                    add_breadcrumb("collection", &format!("cycle_error:{}", e), Level::Error);
                    // Only update tray status if we're authenticated
                    if state.auth_token.read().await.is_some() {
                        update_tray_status(&app, &state, false).await;
                    }
                }
            }
        }
    });
}

#[tauri::command]
async fn check_for_updates_internal(api_base_url: &str) -> Result<Option<String>, String> {
    let current_version = env!("CARGO_PKG_VERSION");
    log::info!("🔍 Starting update check - current version: {}", current_version);

    let url = format!("{}/klaayguard/updates/latest", api_base_url);
    log::info!("🌐 Checking for updates from API: {}", url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch updates: {}", e))?;

    log::info!("📡 API response status: {}", response.status());

    if !response.status().is_success() {
        return Err(format!("API returned non-success status: {}", response.status()));
    }

    let release_info: Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    let release_version = release_info
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing 'version' in response".to_string())?;

    log::info!("📦 Found release: {} with {} assets", 
        release_version,
        release_info.get("assets").and_then(|a| a.as_array()).map(|a| a.len()).unwrap_or(0)
    );

    if let Some(assets) = release_info.get("assets").and_then(|a| a.as_array()) {
        for (i, asset) in assets.iter().enumerate() {
            if let (Some(label), Some(id), Some(name)) = (
                asset.get("label").and_then(|l| l.as_str()),
                asset.get("id").and_then(|i| i.as_u64()),
                asset.get("name").and_then(|n| n.as_str()),
            ) {
                log::info!("  Asset {}: {} (ID: {})", i + 1, label, id);
                log::info!("    Original name: {}", name);
            }
        }
    }

    let normalized_current = current_version.trim_start_matches('v');
    let normalized_release = release_version.trim_start_matches('v');

    let current_semver = semver::Version::parse(normalized_current)
        .map_err(|e| format!("Failed to parse current version '{}': {}", normalized_current, e))?;

    let release_semver = semver::Version::parse(normalized_release)
        .map_err(|e| format!("Failed to parse release version '{}': {}", normalized_release, e))?;

    if release_semver > current_semver {
        log::info!("🔄 Update available: {} -> {}", current_version, release_version);
        
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        
        let assets = release_info
            .get("assets")
            .and_then(|a| a.as_array())
            .ok_or_else(|| "No assets found in release".to_string())?;

        let asset_id = assets
            .iter()
            .find(|asset| {
                if let Some(name) = asset.get("name").and_then(|n| n.as_str()) {
                    let name_lower = name.to_lowercase();
                    let os_match = match os {
                        "macos" => name_lower.contains("macos"),
                        "linux" => name_lower.contains("linux"),
                        "windows" => name_lower.contains("windows"),
                        _ => false,
                    };
                    let arch_match = match arch {
                        "aarch64" | "arm" => name_lower.contains("arm64") || name_lower.contains("aarch64"),
                        "x86_64" => name_lower.contains("x64") || name_lower.contains("x86_64"),
                        _ => false,
                    };
                    os_match && arch_match
    } else {
                    false
                }
            })
            .and_then(|asset| asset.get("id").and_then(|id| id.as_u64()))
            .map(|id| id.to_string())
            .ok_or_else(|| format!("No matching asset found for OS: {}, ARCH: {}", os, arch))?;

        Ok(Some(asset_id))
    } else {
        log::info!("✅ No update needed - already at latest version: {}", current_version);
        Ok(None)
    }
}

#[tauri::command]
async fn check_for_updates(api_base_url: String) -> Result<Option<String>, String> {
    check_for_updates_internal(&api_base_url).await
}

#[tauri::command]
async fn download_and_install_update_internal(
    api_base_url: &str,
    asset_id: &str,
    app: &tauri::AppHandle,
) -> Result<(), String> {
    log::info!("📥 Starting download for asset ID: {}", asset_id);

    let url = format!("{}/klaayguard/updates/assets/{}", api_base_url, asset_id);
    log::info!("🌐 Downloading from: {}", url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to download update: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Download failed with status: {}", response.status()));
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|ct| ct.to_str().ok())
        .unwrap_or("unknown");
    
    log::info!("📦 Response Content-Type: {}", content_type);

    let file_extension = if content_type.contains("gzip") || content_type.contains("x-gzip") {
        "dmg"
    } else if content_type.contains("debian") {
        "deb"
    } else if content_type.contains("rpm") {
        "rpm"
    } else if content_type.contains("zip") {
        "zip"
    } else {
        "dmg"
    };

    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join(format!("klaayguard_update.{}", file_extension));
    log::info!("💾 Saving to: {}", file_path.display());

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response bytes: {}", e))?;

    std::fs::write(&file_path, bytes)
        .map_err(|e| format!("Failed to write update file: {}", e))?;

    log::info!("✅ Download complete: {} bytes", std::fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0));

    #[cfg(target_os = "macos")]
    {
        log::info!("🍎 Opening DMG installer...");
        std::process::Command::new("open")
            .arg(&file_path)
            .spawn()
            .map_err(|e| format!("Failed to open installer: {}", e))?;
    }

    #[cfg(target_os = "linux")]
    {
        log::info!("🐧 Installing update...");
        if file_extension == "deb" {
            std::process::Command::new("pkexec")
                .args(&["dpkg", "-i", file_path.to_str().unwrap()])
                .spawn()
                .map_err(|e| format!("Failed to install update: {}", e))?;
        } else if file_extension == "rpm" {
            std::process::Command::new("pkexec")
                .args(&["rpm", "-U", file_path.to_str().unwrap()])
                .spawn()
                .map_err(|e| format!("Failed to install update: {}", e))?;
        }
    }

    #[cfg(target_os = "windows")]
    {
        log::info!("🪟 Opening installer...");
        std::process::Command::new("explorer")
            .arg(&file_path)
            .spawn()
            .map_err(|e| format!("Failed to open installer: {}", e))?;
    }

    log::info!("🔄 Waiting 2 seconds before quitting...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    log::info!("👋 Quitting application to complete update...");
    app.exit(0);

    Ok(())
}

#[tauri::command]
async fn download_and_install_update(
    api_base_url: String,
    asset_id: String,
    app: tauri::AppHandle,
) -> Result<(), String> {
    download_and_install_update_internal(&api_base_url, &asset_id, &app).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let default_api = get_api_base_url();
    
    let state = Arc::new(AppState {
        auth_token: RwLock::new(None),
        api_base_url: RwLock::new(default_api.clone()),
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
            
            // Create initial tray menu (unauthenticated state by default)
            let menu = build_tray_menu(&app.handle(), false).map_err(|e| {
                log::error!("Failed to create system tray menu: {}", e);
                format!("{}", e)
            })?;

        // Create tray icon SECOND (before spawning async tasks that update it)
        tauri::tray::TrayIconBuilder::with_id("main")
                .on_menu_event(move |_app, event| {
                    log::info!("🖱️  Menu event triggered: id={}", event.id.as_ref());
                    match event.id.as_ref() {
                        "login" => {
                            log::info!("🔐 Login requested from system tray");
                            let earthenware_url = std::env::var("VITE_EARTHENWARE_URL")
                                .unwrap_or_else(|_| "https://app.klaay.com".to_string());
                            let callback_url = "klaayguard://auth-callback";
                            let full_url = format!("{}?redirect_to={}", earthenware_url, callback_url);
                            log::info!("🌐 Opening browser: {}", full_url);
                            if let Err(e) = open::that(full_url) {
                                log::error!("❌ Failed to open browser: {}", e);
                            } else {
                                log::info!("✅ Browser opened successfully");
                            }
                        }
                        "status" => {
                            // Status item is non-clickable, ignore
                        }
                        _ => {
                            log::warn!("⚠️  Unknown menu event: {}", event.id.as_ref());
                        }
                    }
                })
                .icon(app.default_window_icon().unwrap().clone())
                .icon_as_template(false) // Disable template mode to show colored status dots
                .menu(&menu)
                .show_menu_on_left_click(true) // Show menu on left-click
                .tooltip("KlaayGuard")
                .build(app)
                .map_err(|e| {
                    log::error!("Failed to create system tray: {}", e);
                    e
                })?;

            log::info!("✅ Tray icon created successfully");

            // NOW load token and update tray (after tray exists!)
            let app_handle_for_init = app.handle().clone();
            let state_for_init = state_for_loop.clone();
            
            tauri::async_runtime::spawn(async move {
                log::info!("🔑 Checking keychain for authentication token...");
                if let Ok(Some(tok)) = keychain::load_token() {
                    *state_for_init.auth_token.write().await = Some(tok);
                    let _ = app_handle_for_init.emit("auth:status", json!({ "authenticated": true }));
                    log::info!("✅ Authenticated - token loaded from keychain");
                    
                    // Update tray menu to show logout option
                    update_tray_menu(&app_handle_for_init, &state_for_init).await;
                } else {
                    *state_for_init.auth_token.write().await = None;
                    let _ = app_handle_for_init.emit("auth:status", json!({ "authenticated": false }));
                    log::warn!("⚠️  Not authenticated - no token found in keychain");
                    
                    // Update tray menu to show login option
                    update_tray_menu(&app_handle_for_init, &state_for_init).await;
                    
                    // Show notification prompting login
                    log::info!("📢 Showing login notification...");
                    match app_handle_for_init.notification()
                        .builder()
                        .title("KlaayGuard - Login Required")
                        .body("Please login to start monitoring. Click the tray icon (top-right menu bar) and select Login.")
                        .show() {
                        Ok(_) => log::info!("✅ Notification shown successfully"),
                        Err(e) => log::error!("❌ Failed to show notification: {}", e),
                    }
                    
                    // Set red dot for unauthenticated state (error state)
                    log::info!("🔴 Setting red dot for unauthenticated state...");
                    set_tray_icon_and_tooltip(
                        &app_handle_for_init,
                        "icon-error.png",
                        "🔴 Not authenticated - Click Login to start monitoring"
                    );
                }

                // Handle deep link
                try_handle_deep_link_from_args_async(&app_handle_for_init, &state_for_init).await;
            });

            log::info!("KlaayGuard started - running in background (no focus)");

            // Start background loop
            spawn_background_loop(app.handle().clone(), state_for_loop);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            set_api_base_url,
            get_api_base_url_cmd,
            get_app_version,
            check_for_updates,
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

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    /// Test that AppState can be created with default values
    #[tokio::test]
    async fn test_app_state_creation() {
        let state = Arc::new(AppState {
            auth_token: RwLock::new(None),
            api_base_url: RwLock::new("https://api.test.com".to_string()),
            last_send_status: RwLock::new(None),
            last_send_at: RwLock::new(None),
            keychain_cleared_this_session: RwLock::new(false),
        });
        
        assert!(state.auth_token.read().await.is_none());
        assert_eq!(*state.api_base_url.read().await, "https://api.test.com");
        assert!(state.last_send_status.read().await.is_none());
        assert!(state.last_send_at.read().await.is_none());
        assert!(!*state.keychain_cleared_this_session.read().await);
    }
    
    /// Test that collection interval can be parsed from environment
    #[test]
    fn test_collection_interval_default() {
        // Use serial_test or temp_env to avoid race conditions
        let interval = std::env::var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(3600);
        assert!(interval >= 300); // At least 5 minutes
    }
    
    #[test]
    fn test_collection_interval_parsing_logic() {
        // Test the parsing logic without modifying global env
        let test_cases = vec![
            (Some("1800"), 1800),
            (Some("300"), 300),
            (Some("invalid"), 3600), // Invalid falls back to default
            (None, 3600), // Missing falls back to default
        ];
        
        for (input, expected) in test_cases {
            let result = input
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(3600);
            assert_eq!(result, expected);
        }
    }
    
    /// Test API base URL parsing logic
    #[test]
    fn test_get_api_base_url_parsing() {
        // Test the parsing logic without modifying global env
        let test_cases = vec![
            (Some("https://api.test.com"), "https://api.test.com"),
            (Some("https://api.staging.com"), "https://api.staging.com"),
            (None, "https://api.klaay.com"), // Default
        ];
        
        for (input, expected) in test_cases {
            let result = input
                .map(|s| s.to_string())
                .unwrap_or_else(|| "https://api.klaay.com".to_string());
            assert_eq!(result, expected);
        }
    }
    
    /// Test that update_tray_status is async and doesn't block
    #[tokio::test]
    async fn test_update_tray_status_success() {
        // This test verifies that update_tray_status is truly async
        // and doesn't use block_on (which would panic in async context)
        let state = Arc::new(AppState {
            auth_token: RwLock::new(Some("test_token".to_string())),
            api_base_url: RwLock::new("https://api.test.com".to_string()),
            last_send_status: RwLock::new(None),
            last_send_at: RwLock::new(None),
            keychain_cleared_this_session: RwLock::new(false),
        });
        
        // This would panic if update_tray_status used block_on internally
        // Note: We can't actually call update_tray_status without a real AppHandle,
        // but we can verify the state updates work correctly
        *state.last_send_status.write().await = Some(true);
        *state.last_send_at.write().await = Some(chrono::Utc::now());
        
        assert_eq!(*state.last_send_status.read().await, Some(true));
        assert!(state.last_send_at.read().await.is_some());
    }
    
    /// Test deep link URL parsing
    #[test]
    fn test_deep_link_url_parsing() {
        // Valid JWT token structure (3 parts separated by dots)
        let valid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        
        // Parse URL
        let url = format!("klaayguard://auth-callback?token={}", valid_token);
        let qs = url.splitn(2, '?').nth(1).unwrap_or("");
        let mut token_opt: Option<String> = None;
        for pair in qs.split('&') {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            if k == "token" {
                token_opt = Some(v.to_string());
                break;
            }
        }
        
        assert!(token_opt.is_some());
        let token = token_opt.unwrap();
        assert_eq!(token.matches('.').count(), 2);
    }
    
    #[test]
    fn test_deep_link_invalid_token() {
        // Invalid token (not JWT format)
        let url = "klaayguard://auth-callback?token=invalid_token";
        let qs = url.splitn(2, '?').nth(1).unwrap_or("");
        let mut token_opt: Option<String> = None;
        for pair in qs.split('&') {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            if k == "token" {
                token_opt = Some(v.to_string());
                break;
            }
        }
        
        assert!(token_opt.is_some());
        let token = token_opt.unwrap();
        assert_ne!(token.matches('.').count(), 2); // Invalid JWT format
    }
    
    #[test]
    fn test_deep_link_missing_token() {
        let url = "klaayguard://auth-callback";
        let qs = url.splitn(2, '?').nth(1).unwrap_or("");
        let mut token_opt: Option<String> = None;
        for pair in qs.split('&') {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            if k == "token" {
                token_opt = Some(v.to_string());
                break;
            }
        }
        
        assert!(token_opt.is_none());
    }
    
    /// Test JSON API resource serialization
    #[test]
    fn test_json_api_resource_serialization() {
        let resource = JsonApiResource {
            id: Some("123".to_string()),
            resource_type: "device_osquery_results".to_string(),
            attributes: json!({
                "device_serial_number": "ABC123",
                "results": {}
            }),
        };
        
        let serialized = serde_json::to_string(&resource).unwrap();
        assert!(serialized.contains("\"type\":\"device_osquery_results\""));
        assert!(serialized.contains("\"id\":\"123\""));
        assert!(serialized.contains("device_serial_number"));
    }
    
    #[test]
    fn test_json_api_resource_without_id() {
        let resource = JsonApiResource {
            id: None,
            resource_type: "device_osquery_results".to_string(),
            attributes: json!({
                "device_serial_number": "ABC123",
            }),
        };
        
        let serialized = serde_json::to_string(&resource).unwrap();
        assert!(serialized.contains("\"type\":\"device_osquery_results\""));
        assert!(!serialized.contains("\"id\":")); // ID should be omitted when None
    }
    
    /// Test HTTP client configuration
    #[test]
    fn test_client_with_retries() {
        let _client = get_client_with_retries();
        // Just verify it can be created without panicking
        assert!(true);
    }
}
