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

mod auth;
mod background;
mod collection;
mod database;
mod keychain;
mod system;
mod updates;
mod upload;
use crate::auth::AuthStatus;
// rusqlite imports kept for legacy compat in this file
use crate::system::launch_agent::install_launch_agent;
use sentry::{self, Level};
use serde::Serialize;
use serde_json::{json, Value};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tauri::{Emitter, Manager};
// removed autostart plugin; using manual LaunchAgent management
// use tauri_plugin_shell::ShellExt; // not used in this file
// use tauri_plugin_log::LogTarget; // use defaults
use tokio::sync::RwLock;
// use uuid::Uuid; // only used in removed helpers
// use system::launch_agent via full path where needed

// Re-introduced minimal osquery commands used by the UI.

/// Shared application state for background operations
pub struct AppState {
    pub auth_token: RwLock<Option<String>>,
    pub api_base_url: RwLock<String>,
    pub last_run_at: RwLock<Option<std::time::Instant>>,
    pub last_attempt_at: RwLock<Option<std::time::Instant>>,
    pub db_path: RwLock<Option<String>>, // file-backed SQLite path
    pub upload_in_progress: RwLock<bool>,
    // Prevent repeated Keychain delete prompts by ensuring we only delete once per session
    pub keychain_cleared_this_session: RwLock<bool>,
    pub last_upload_tick_at: RwLock<Option<std::time::Instant>>, // wake-gap detection for uploader
    pub last_focus_at: RwLock<Option<std::time::Instant>>,       // debounce for focus-on-failure
    pub retention_in_progress: RwLock<bool>,
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

// deep link handling moved to auth module

#[tauri::command]
async fn set_api_base_url(
    state: tauri::State<'_, Arc<AppState>>,
    base: String,
) -> Result<(), String> {
    *state.api_base_url.write().await = base;
    Ok(())
}

// save_auth_token moved to auth module
// clear_auth_token moved to auth module
// get_auth_status moved to auth module

#[tauri::command]
async fn get_app_version() -> Result<String, String> {
    let version = env!("CARGO_PKG_VERSION").to_string();
    log::info!("📱 Frontend requested app version: {}", version);
    Ok(version)
}

// moved to collection::execute_query

/// Executes a batch of SQL statements against osquery and returns results keyed by logical id
/// The vector contains pairs of (logical_id, sql_to_execute).
// moved to collection::execute_sql_batch

// invalidate_auth moved to auth module

fn wake_gap_seconds() -> u64 {
    background::config::wake_gap_seconds()
}

fn focus_debounce_seconds() -> u64 {
    std::env::var("KLAAYGUARD_FAILURE_FOCUS_DEBOUNCE_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60)
}

// retention interval resolved where needed in background::retention

fn collection_interval_seconds() -> u64 {
    background::config::collection_interval_seconds()
}

async fn focus_window_with_debounce(app: &tauri::AppHandle, state: &Arc<AppState>) {
    let now = std::time::Instant::now();
    let debounce = std::time::Duration::from_secs(focus_debounce_seconds());
    let should_focus = {
        let last = *state.last_focus_at.read().await;
        match last {
            Some(prev) => now.duration_since(prev) >= debounce,
            None => true,
        }
    };
    if should_focus {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.show();
            let _ = window.set_focus();
            *state.last_focus_at.write().await = Some(now);
        }
    }
}

pub(crate) async fn emit_error_and_focus(
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

// moved to upload::types::UploadRow

// moved to upload::types::JsonApiResource

// moved to upload::types::JsonApiPayload

// Remove unused helper: get_db_path_cached
/* async fn get_db_path_cached(
    app: &tauri::AppHandle,
    _state: &Arc<AppState>,
) -> Result<PathBuf, String> {
    Ok(database::resolve_path(app)?)
} */

// moved to upload::store::get_last_upload_at

// moved to upload::store::select_pending_rows

// moved to upload::store::build_in_clause_params

// moved to upload::store::mark_rows_handled_and_advance_watermark

/* async fn get_device_serial_number_internal(app: &tauri::AppHandle) -> Result<String, String> {
    crate::collection::get_device_serial_number_internal(app).await
} */

// moved to upload::run_upload_cycle

// moved to upload::spawn_upload_loop

/* async fn run_cycle(
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
        auth::invalidate_auth(app, state).await?;
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
    // Build query list. If item has an explicit `sql`, use it; otherwise default to SELECT * FROM <id>.
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
    let results = crate::collection::execute_sql_batch(app.clone(), queries).await?;

    // 3) Persist results to SQLite (Loop A)
    let run_id = Uuid::new_v4().to_string();
    let inserted = persist_results_to_sqlite(app, state, &run_id, &results).await?;
    *state.last_run_at.write().await = Some(std::time::Instant::now());
    let _ = app.emit(
        "collection:success",
        json!({ "inserted_rows": inserted, "run_id": run_id }),
    );
    log::info!(
        "collection_success inserted_rows={} run_id={}",
        inserted,
        run_id
    );
    add_breadcrumb(
        "collection",
        &format!("persisted_rows:{} run_id:{}", inserted, run_id),
        Level::Info,
    );
    sentry::capture_message("collection_persisted", Level::Info);

    // Trigger uploader immediately after successful collection to restart retry loop (B)
    if let Err(e) = crate::upload::run_upload_cycle(app, state, client).await {
        log::error!("upload cycle (post-collection) error: {}", e);
        emit_error_and_focus(
            app,
            state,
            "upload:error",
            json!({ "stage": "internal", "error": e, "post_collection": true }),
        )
        .await;
    }

    Ok(())
} */

/* // deprecated by collection::spawn_collection_loop
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

        // run immediately
        if let Err(e) = run_cycle(&app, &state, &client).await {
            log::error!("initial cycle error: {}", e);
            emit_error_and_focus(
                &app,
                &state,
                "collection:error",
                json!({ "stage": "internal", "error": e }),
            )
            .await;
        }

        let mut interval =
            tokio::time::interval(Duration::from_secs(collection_interval_seconds()));
        loop {
            interval.tick().await;
            // detect potential wake by long elapsed since last attempt
            let woke = {
                let last = *state.last_attempt_at.read().await;
                if let Some(prev) = last {
                    prev.elapsed() >= std::time::Duration::from_secs(wake_gap_seconds())
                } else {
                    false
                }
            };
            if woke {
                let _ = app.emit("system:wake_detected", json!({ "loop": "collection" }));
                add_breadcrumb("system", "wake_detected_collection", Level::Info);
                sentry::capture_message("wake_detected_collection", Level::Info);
            }
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
} */

pub(crate) fn get_sqlite_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    database::resolve_path(app)
}

fn init_sqlite(app: &tauri::AppHandle) -> Result<(), String> {
    database::initialize(app).map(|_| ())
}

// helper moved to background::retention

/* async fn prune_time_based(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<usize, String> {
    database::prune_time_based(
        app,
        state,
        database::config::retention_days(),
        database::config::prune_batch_rows(),
    )
    .await
} */

/* async fn prune_size_based(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<usize, String> {
    database::prune_size_based(
        app,
        state,
        database::config::max_db_mb(),
        database::config::prune_batch_rows(),
    )
    .await
} */

// retention loop moved to crate::background::retention

async fn persist_results_to_sqlite(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    run_id: &str,
    results: &HashMap<String, Value>,
) -> Result<usize, String> {
    database::persist_results(app, state, run_id, results).await
}

/// Installs a launch agent for automatic startup on macOS.
///
/// This function creates a launchd plist file in the user's LaunchAgents directory
/// and loads it to ensure the app starts automatically on login. This is a mandatory
/// security feature that cannot be disabled by users.
// moved into system::launch_agent

#[derive(Serialize)]
struct ArchStatus {
    mismatch: bool,
    built: String,
    host: String,
}

#[tauri::command]
async fn get_arch_status() -> Result<ArchStatus, String> {
    let mismatch = std::env::var("KLAAY_ARCH_MISMATCH").ok().as_deref() == Some("1");
    let built =
        std::env::var("KLAAY_ARCH_BUILT").unwrap_or_else(|_| std::env::consts::ARCH.to_string());
    let host = std::env::var("KLAAY_ARCH_HOST").unwrap_or_else(|_| "unknown".to_string());
    Ok(ArchStatus {
        mismatch,
        built,
        host,
    })
}

#[derive(Serialize)]
struct RuntimeStatusLoops {
    collection_seconds_since_last_run: Option<u64>,
    collection_seconds_until_next_due: Option<i64>,
    upload_seconds_since_last_tick: Option<u64>,
}

#[derive(Serialize)]
struct RuntimeStatusAutostart {
    platform: String,
    strategy: String,
    installed: bool,
    label: Option<String>,
}

#[derive(Serialize)]
struct RuntimeStatus {
    autostart: RuntimeStatusAutostart,
    loops: RuntimeStatusLoops,
    auth: AuthStatus,
}

#[tauri::command]
async fn get_runtime_status(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<RuntimeStatus, String> {
    // Loops status
    let collection_seconds_since_last_run = {
        let last = *state.last_run_at.read().await;
        last.map(|t| t.elapsed().as_secs())
    };
    let collection_seconds_until_next_due = {
        if state.auth_token.read().await.is_none() {
            Some(-1)
        } else {
            let last = *state.last_attempt_at.read().await;
            let interval = std::time::Duration::from_secs(collection_interval_seconds());
            if let Some(last) = last {
                let elapsed = last.elapsed();
                if elapsed >= interval {
                    Some(0)
                } else {
                    Some((interval - elapsed).as_secs() as i64)
                }
            } else {
                Some(0)
            }
        }
    };
    let upload_seconds_since_last_tick = {
        let last = *state.last_upload_tick_at.read().await;
        last.map(|t| t.elapsed().as_secs())
    };

    // Auth
    let auth = if state.auth_token.read().await.is_some() {
        AuthStatus {
            authenticated: true,
            display_name: None,
        }
    } else {
        AuthStatus {
            authenticated: false,
            display_name: None,
        }
    };

    // Autostart (platform-specific)
    #[cfg(target_os = "macos")]
    let autostart = {
        let label = "com.klaay.klaayguard".to_string();
        let uid = nix::unistd::getuid().as_raw();
        let domain = format!("gui/{}", uid);
        let installed = std::process::Command::new("launchctl")
            .args(&["print", &format!("{}/{}", domain, &label)])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        RuntimeStatusAutostart {
            platform: "macos".to_string(),
            strategy: "launchagent".to_string(),
            installed,
            label: Some(label),
        }
    };

    #[cfg(not(target_os = "macos"))]
    let autostart = RuntimeStatusAutostart {
        platform: std::env::consts::OS.to_string(),
        strategy: "none".to_string(),
        installed: false,
        label: None,
    };

    Ok(RuntimeStatus {
        autostart,
        loops: RuntimeStatusLoops {
            collection_seconds_since_last_run,
            collection_seconds_until_next_due,
            upload_seconds_since_last_tick,
        },
        auth,
    })
}

// release DTOs and API helper moved to updates module

// moved to updates::check
/* async fn check_for_updates_internal(api_base: &str) -> Result<Option<String>, String> {
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
        if let Some(orig_name) = &asset._original_name {
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

        // Find the DMG asset for macOS
        // Check both the user-friendly name and original name for DMG files
        if let Some(dmg_asset) = release.assets.iter().find(|asset| {
            asset.name.ends_with(".dmg")
                || asset.name.contains("MacOS")
                || asset
                    ._original_name
                    .as_ref()
                    .map_or(false, |orig| orig.ends_with(".dmg"))
        }) {
            log::info!(
                "✅ Found DMG asset: {} (ID: {})",
                dmg_asset.name,
                dmg_asset.id
            );
            log::info!(
                "🚀 Update available: {} -> {}",
                current_version,
                release.version
            );
            return Ok(Some(dmg_asset.id.to_string()));
        } else {
            log::warn!("⚠️  No DMG asset found in release assets");
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
} */

// re-exported from updates module

/* async fn download_and_install_update_internal(
    api_base: &str,
    asset_id: &str,
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

    std::io::Write::write_all(&mut file, &bytes).map_err(|e| {
        log::error!("❌ Write error: {}", e);
        format!("Write error: {}", e)
    })?;

    log::info!("✅ Update downloaded successfully to: {:?}", dmg_path);

    // Mount the DMG and replace the app
    log::info!("🔄 Starting application replacement process...");
    replace_application(&dmg_path, app).await?;

    Ok(())
} */

// re-exported from updates module

// moved to updates::install
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
        db_path: RwLock::new(None),
        upload_in_progress: RwLock::new(false),
        keychain_cleared_this_session: RwLock::new(false),
        last_upload_tick_at: RwLock::new(None),
        last_focus_at: RwLock::new(None),
        retention_in_progress: RwLock::new(false),
    });

    let app = tauri::Builder::default()
        .manage(state.clone())
        .plugin(tauri_plugin_os::init())
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
                    crate::auth::handle_deep_link_url(&app, &st, &a);
                    break;
                }
            }
            // Only focus if sign-in is required
            let needs_login =
                tauri::async_runtime::block_on(async { st.auth_token.read().await.is_none() });
            if let Some(window) = app.get_webview_window("main") {
                if needs_login {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            log::info!("single_instance: secondary launch routed to primary instance");
        }))
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            let _handle2 = app.handle().clone();

            // Hide the app from the dock on macOS for security monitoring
            #[cfg(target_os = "macos")]
            {
                app.set_activation_policy(tauri::ActivationPolicy::Accessory);
                log::info!("KlaayGuard configured as background service - hidden from dock");
            }

            // Ensure no window is created before activation policy; create programmatically now
            if app.get_webview_window("main").is_none() {
                if let Err(e) = tauri::webview::WebviewWindowBuilder::new(
                    app,
                    "main",
                    tauri::WebviewUrl::default(),
                )
                .title("KlaayGuard")
                .visible(false)
                .inner_size(520.0, 680.0)
                .min_inner_size(480.0, 600.0)
                .center()
                .build()
                {
                    log::error!("Failed to create main window: {}", e);
                }
            }

            // Emit arch mismatch to UI if flagged by main.rs
            if std::env::var("KLAAY_ARCH_MISMATCH").ok().as_deref() == Some("1") {
                let built = std::env::var("KLAAY_ARCH_BUILT")
                    .unwrap_or_else(|_| std::env::consts::ARCH.to_string());
                let host =
                    std::env::var("KLAAY_ARCH_HOST").unwrap_or_else(|_| "unknown".to_string());
                let _ = app.emit(
                    "arch:mismatch",
                    serde_json::json!({ "built": built, "host": host }),
                );
                // Show window to present error page
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
                // Do not start background loops; return early
                return Ok(());
            }

            // Check if we're already running as a regular process to prevent duplicates
            // Duplicate instance prevention handled by single-instance plugin; remove manual pgrep/exit logic

            // Check for updates on startup and install automatically
            let app_handle = app.handle().clone();
            crate::updates::bootstrap::bootstrap_on_startup(app_handle);

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
            let window = app.get_webview_window("main").unwrap();
            let window_ = window.clone();

            // Load token from keychain at startup and emit status BEFORE deciding focus
            let state_for_loop = app.state::<Arc<AppState>>().inner().clone();
            if let Ok(Some(tok)) = keychain::load_token() {
                tauri::async_runtime::block_on(async {
                    *state_for_loop.auth_token.write().await = Some(tok);
                });
                let _ = app.emit("auth:status", json!({ "authenticated": true }));
            } else {
                let _ = app.emit("auth:status", json!({ "authenticated": false }));
            }

            // Only take focus on startup if sign-in is required
            {
                let needs_login = tauri::async_runtime::block_on(async {
                    state_for_loop.auth_token.read().await.is_none()
                });
                if needs_login {
                    window.show().unwrap();
                    window.set_focus().unwrap();
                    log::info!("KlaayGuard started - login screen displayed");
                } else {
                    log::info!("KlaayGuard started - running in background (no focus)");
                }
            }

            // Handle deep link if app was launched by klaayguard:// URL (first instance)
            crate::auth::try_handle_deep_link_from_args(&app.handle(), &state_for_loop);

            window.on_window_event(move |event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    window_.hide().unwrap();
                    api.prevent_close();
                }
            });

            // Register system tray via system module
            crate::system::tray::register_tray(
                &app.handle(),
                &crate::system::Callbacks::new(
                    |app| {
                        log::info!("Show window requested from system tray");
                        let needs_login = {
                            let st = app.state::<Arc<AppState>>().inner().clone();
                            tauri::async_runtime::block_on(async {
                                st.auth_token.read().await.is_none()
                            })
                        };
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            if needs_login {
                                let _ = window.set_focus();
                            }
                        }
                    },
                    |app| {
                        log::info!("Hide window requested from system tray");
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.hide();
                        }
                    },
                ),
            )
            .map_err(|e| {
                log::error!("Failed to register system tray: {}", e);
                e
            })?;
            // Spawn background monitoring loop
            let state_for_loop = app.state::<Arc<AppState>>().inner().clone();
            let app_handle = app.handle().clone();

            // (duplicate initial keychain load removed)

            // Initialize SQLite (file-backed) path and schema
            if let Err(e) = init_sqlite(&app.handle()) {
                log::error!("Failed to initialize SQLite: {}", e);
                sentry::capture_message(&format!("sqlite_init_failed:{}", e), Level::Error);
            } else {
                if let Some(p) = get_sqlite_path(&app.handle()).ok() {
                    tauri::async_runtime::block_on(async {
                        *state_for_loop.db_path.write().await =
                            Some(p.to_string_lossy().to_string());
                    });
                }
            }

            // Start background tasks (collection, upload, retention)
            let _bg = crate::background::BackgroundTasksManager::start(app_handle, state_for_loop);

            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            crate::collection::execute_query,
            crate::collection::get_device_serial_number,
            crate::auth::save_auth_token,
            crate::auth::clear_auth_token,
            set_api_base_url,
            crate::collection::get_next_run_in_seconds,
            crate::auth::get_auth_status,
            get_app_version,
            crate::system::launch_agent::install_launch_agent,
            crate::system::launch_agent::uninstall_launch_agent,
            get_arch_status,
            get_runtime_status,
            crate::updates::commands::check_for_updates_command,
            crate::updates::commands::download_and_install_update
        ])
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
                    crate::auth::handle_deep_link_url(&_app_handle, &st, &s);
                }
            }
        }
        _ => {}
    });
}
