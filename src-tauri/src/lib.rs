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
mod collection;
mod keychain;
mod upload;
use crate::auth::AuthStatus;
use rusqlite::{params, Connection};
use sentry::{self, Level};
use serde::Serialize;
use serde_json::{json, Value};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};
use tauri::{Emitter, Manager};
// removed autostart plugin; using manual LaunchAgent management
// use tauri_plugin_shell::ShellExt; // not used in this file
// use tauri_plugin_log::LogTarget; // use defaults
use tokio::sync::RwLock;
use uuid::Uuid;

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

/// Returns seconds until next scheduled run (120s default interval).
/// -1 indicates not signed in (no token yet). 0 means due now or overdue.
// moved to collection::get_next_run_in_seconds

// moved to collection::get_device_serial_number

// AuthStatus moved to auth module

#[tauri::command]
async fn get_app_version() -> Result<String, String> {
    let version = env!("CARGO_PKG_VERSION").to_string();
    log::info!("📱 Frontend requested app version: {}", version);
    Ok(version)
}

// get_auth_status moved to auth module

// moved to collection::execute_query

/// Executes a batch of SQL statements against osquery and returns results keyed by logical id
/// The vector contains pairs of (logical_id, sql_to_execute).
// moved to collection::execute_sql_batch

// invalidate_auth moved to auth module

fn wake_gap_seconds() -> u64 {
    std::env::var("KLAAYGUARD_WAKE_GAP_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300)
}

fn focus_debounce_seconds() -> u64 {
    std::env::var("KLAAYGUARD_FAILURE_FOCUS_DEBOUNCE_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60)
}

fn retention_days() -> i64 {
    std::env::var("KLAAYGUARD_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(30)
}

fn retention_interval_seconds() -> u64 {
    std::env::var("KLAAYGUARD_RETENTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(24 * 60 * 60)
}

fn collection_interval_seconds() -> u64 {
    std::env::var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(900)
}

fn prune_batch_rows() -> i64 {
    std::env::var("KLAAYGUARD_PRUNE_BATCH_ROWS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(5000)
}

fn max_db_mb() -> u64 {
    std::env::var("KLAAYGUARD_MAX_DB_MB")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(200)
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
        }
        // Log locally when focusing for user-required action (e.g., sign-in)
        log::warn!("Focusing main window for user action (debounced)");
        *state.last_focus_at.write().await = Some(now);
        let _ = app.emit(
            "focus:on_failure",
            json!({ "at": chrono::Utc::now().to_rfc3339() }),
        );
        add_breadcrumb("ui", "focus_on_failure", Level::Info);
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

async fn get_db_path_cached(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
) -> Result<PathBuf, String> {
    let current = state.db_path.read().await.clone();
    if let Some(p) = current {
        Ok(PathBuf::from(p))
    } else {
        get_sqlite_path(app)
    }
}

// moved to upload::store::get_last_upload_at

// moved to upload::store::select_pending_rows

// moved to upload::store::build_in_clause_params

// moved to upload::store::mark_rows_handled_and_advance_watermark

#[allow(dead_code)]
async fn get_device_serial_number_internal(app: &tauri::AppHandle) -> Result<String, String> {
    crate::collection::get_device_serial_number_internal(app).await
}

// moved to upload::run_upload_cycle

// moved to upload::spawn_upload_loop

#[allow(dead_code)]
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
}

#[allow(dead_code)]
// deprecated by collection::spawn_collection_loop
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
}

pub(crate) fn get_sqlite_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    // Mode selection: default file for development, memory for production unless overridden
    let mode = std::env::var("KLAAYGUARD_DB_MODE").unwrap_or_else(|_| "file".to_string());
    if mode.eq_ignore_ascii_case("memory") {
        // Indicate memory by returning a special :memory: path
        return Ok(PathBuf::from(":memory:"));
    }
    let mut base = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("app_data_dir error: {}", e))?;
    let file_override = std::env::var("KLAAYGUARD_DB_PATH").ok();
    if let Some(p) = file_override {
        return Ok(PathBuf::from(p));
    }
    base.push("klaayguard.db");
    Ok(base)
}

fn init_sqlite(app: &tauri::AppHandle) -> Result<(), String> {
    let db_path = get_sqlite_path(app)?;
    if db_path != PathBuf::from(":memory:") {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create_dir_all for db parent failed: {}", e))?;
        }
    }
    let conn = if db_path == PathBuf::from(":memory:") {
        Connection::open_in_memory().map_err(|e| e.to_string())?
    } else {
        Connection::open(&db_path).map_err(|e| e.to_string())?
    };
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS results (
          id INTEGER PRIMARY KEY,
          table_name TEXT NOT NULL,
          json TEXT NOT NULL,
          run_id TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          handled INTEGER DEFAULT 0,
          handled_at DATETIME NULL
        );
        CREATE TABLE IF NOT EXISTS metadata (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_results_pending ON results(handled, created_at, id);
        CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
        CREATE INDEX IF NOT EXISTS idx_results_handled_at ON results(handled, handled_at);
        "#,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

async fn get_db_size_mb(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<u64, String> {
    let db_path = get_db_path_cached(app, state).await?;
    if db_path == PathBuf::from(":memory:") {
        // Estimate using page_count * page_size
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        let page_count: i64 = conn
            .query_row("PRAGMA page_count;", [], |r| r.get(0))
            .unwrap_or(0);
        let page_size: i64 = conn
            .query_row("PRAGMA page_size;", [], |r| r.get(0))
            .unwrap_or(4096);
        let bytes = page_count.saturating_mul(page_size) as u64;
        Ok(bytes / (1024 * 1024))
    } else {
        let meta = std::fs::metadata(&db_path).map_err(|e| e.to_string())?;
        Ok(meta.len() / (1024 * 1024))
    }
}

async fn prune_time_based(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<usize, String> {
    let db_path = get_db_path_cached(app, state).await?;
    let conn = if db_path == PathBuf::from(":memory:") {
        Connection::open_in_memory().map_err(|e| e.to_string())?
    } else {
        Connection::open(&db_path).map_err(|e| e.to_string())?
    };
    let last_upload = crate::upload::store::get_last_upload_at(app, state).await?;
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(retention_days() as i64))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let mut total_deleted: usize = 0;
    loop {
        let deleted = conn
            .execute(
                "DELETE FROM results WHERE id IN (
                   SELECT id FROM results
                   WHERE handled=1
                     AND datetime(created_at) <= datetime(?1)
                     AND datetime(created_at) <= datetime(?2)
                   ORDER BY datetime(created_at) ASC, id ASC
                   LIMIT ?3
                 )",
                params![last_upload.as_str(), cutoff.as_str(), prune_batch_rows()],
            )
            .map_err(|e| e.to_string())?;
        total_deleted += deleted as usize;
        if deleted == 0 {
            break;
        }
    }
    Ok(total_deleted)
}

async fn prune_size_based(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<usize, String> {
    let db_path = get_db_path_cached(app, state).await?;
    if db_path == PathBuf::from(":memory:") {
        // No file to size-bound in memory mode; skip
        return Ok(0);
    }
    let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
    let last_upload = crate::upload::store::get_last_upload_at(app, state).await?;
    let mut total_deleted: usize = 0;
    let cap = max_db_mb();
    loop {
        let size_now = get_db_size_mb(app, state).await?;
        if size_now <= cap {
            break;
        }
        let deleted = conn
            .execute(
                "DELETE FROM results WHERE id IN (
                   SELECT id FROM results
                   WHERE handled=1
                     AND datetime(created_at) <= datetime(?1)
                   ORDER BY datetime(created_at) ASC, id ASC
                   LIMIT ?2
                 )",
                params![last_upload.as_str(), prune_batch_rows()],
            )
            .map_err(|e| e.to_string())?;
        total_deleted += deleted as usize;
        if deleted == 0 {
            break;
        }
    }
    Ok(total_deleted)
}

async fn run_retention_cycle(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<(), String> {
    // Prevent overlap
    if *state.retention_in_progress.read().await {
        return Ok(());
    }
    *state.retention_in_progress.write().await = true;
    let before = get_db_size_mb(app, state).await.unwrap_or(0);
    add_breadcrumb("retention", &format!("start_db_mb:{}", before), Level::Info);
    let time_deleted = prune_time_based(app, state).await.unwrap_or(0);
    let mut after = get_db_size_mb(app, state).await.unwrap_or(before);
    let mut size_deleted = 0usize;
    if after > max_db_mb() {
        size_deleted = prune_size_based(app, state).await.unwrap_or(0);
        after = get_db_size_mb(app, state).await.unwrap_or(after);
    }
    // Optimize lightweight
    let _ = {
        let db_path = get_db_path_cached(app, state).await?;
        let conn = if db_path == PathBuf::from(":memory:") {
            Connection::open_in_memory().map_err(|e| e.to_string())?
        } else {
            Connection::open(&db_path).map_err(|e| e.to_string())?
        };
        conn.execute_batch("PRAGMA optimize;").ok();
        Ok::<(), String>(())
    };
    let _ = app.emit(
        "retention:run",
        json!({
            "deleted_time_based": time_deleted,
            "deleted_size_based": size_deleted,
            "db_mb_before": before,
            "db_mb_after": after,
        }),
    );
    add_breadcrumb(
        "retention",
        &format!(
            "done time_deleted:{} size_deleted:{} db_mb:{}->{}",
            time_deleted, size_deleted, before, after
        ),
        Level::Info,
    );
    *state.retention_in_progress.write().await = false;
    Ok(())
}

fn spawn_retention_loop(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        // Wait for DB path to be initialized
        loop {
            if state.db_path.read().await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        // Run immediately once
        if let Err(e) = run_retention_cycle(&app, &state).await {
            log::error!("retention initial run error: {}", e);
            let _ = app.emit(
                "retention:error",
                json!({ "stage": "initial", "error": e.to_string() }),
            );
        }
        let interval_secs = retention_interval_seconds();
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            if let Err(e) = run_retention_cycle(&app, &state).await {
                log::error!("retention run error: {}", e);
                let _ = app.emit(
                    "retention:error",
                    json!({ "stage": "interval", "error": e.to_string() }),
                );
            }
        }
    });
}

async fn persist_results_to_sqlite(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    run_id: &str,
    results: &HashMap<String, Value>,
) -> Result<usize, String> {
    let db_path = {
        let current = state.db_path.read().await.clone();
        if let Some(p) = current {
            PathBuf::from(p)
        } else {
            get_sqlite_path(app)?
        }
    };
    let mut conn = if db_path == PathBuf::from(":memory:") {
        Connection::open_in_memory().map_err(|e| e.to_string())?
    } else {
        Connection::open(&db_path).map_err(|e| e.to_string())?
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut inserted = 0usize;
    {
        let mut stmt = tx
            .prepare("INSERT INTO results (table_name, json, run_id) VALUES (?1, ?2, ?3)")
            .map_err(|e| e.to_string())?;
        for (table, value) in results.iter() {
            if let Some(arr) = value.as_array() {
                for row in arr {
                    let row_str = serde_json::to_string(row).map_err(|e| e.to_string())?;
                    stmt.execute(params![table.as_str(), row_str.as_str(), run_id])
                        .map_err(|e| e.to_string())?;
                    inserted += 1;
                }
            }
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(inserted)
}

/// Installs a launch agent for automatic startup on macOS.
///
/// This function creates a launchd plist file in the user's LaunchAgents directory
/// and loads it to ensure the app starts automatically on login. This is a mandatory
/// security feature that cannot be disabled by users.
#[tauri::command]
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

#[tauri::command]
async fn uninstall_launch_agent() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        use std::fs;
        let home_dir = dirs::home_dir().ok_or("Could not find home directory")?;
        let launch_agents_dir = home_dir.join("Library/LaunchAgents");
        let label = "com.klaay.klaayguard";
        let plist_path = launch_agents_dir.join(format!("{}.plist", label));
        let uid = nix::unistd::getuid().as_raw();
        let domain = format!("gui/{}", uid);

        // Try to bootout if loaded
        let _ = std::process::Command::new("launchctl")
            .args(&["bootout", &format!("{}/{}", domain, label)])
            .output();

        // Remove plist file
        if plist_path.exists() {
            if let Err(e) = fs::remove_file(&plist_path) {
                return Err(format!("Failed to remove launch agent plist: {}", e));
            }
        }

        Ok("LaunchAgent uninstalled".to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("Launch agent uninstallation is only supported on macOS".to_string())
    }
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

#[derive(serde::Deserialize)]
struct ReleaseAsset {
    id: u64,
    name: String,
    // Include other fields for deserialization but mark as unused
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

async fn check_for_updates_internal(api_base: &str) -> Result<Option<String>, String> {
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
}

#[tauri::command]
async fn download_and_install_update(
    asset_id: String,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let api_base = get_api_base_url();
    log::info!("🌐 Manual update download using API base URL: {}", api_base);
    download_and_install_update_internal(&api_base, &asset_id, &app).await
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
            tauri::async_runtime::spawn(async move {
                log::info!("🚀 Starting automatic update check on app startup");
                let api_base = get_api_base_url();
                log::info!("🌐 Using API base URL: {}", api_base);
                if let Ok(Some(asset_id)) = check_for_updates_internal(&api_base).await {
                    log::info!("🔄 Update available, starting download and install process...");
                    if let Err(e) =
                        download_and_install_update_internal(&api_base, &asset_id, &app_handle)
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

            // Create tray menu with security-focused options (no quit option)
            let show_i = tauri::menu::MenuItem::with_id(app, "show", "Show", true, None::<&str>)
                .map_err(|e| {
                    log::error!("Failed to create 'Show' menu item: {}", e);
                    e
                })?;
            let hide_i = tauri::menu::MenuItem::with_id(app, "hide", "Hide", true, None::<&str>)
                .map_err(|e| {
                    log::error!("Failed to create 'Hide' menu item: {}", e);
                    e
                })?;
            let menu = tauri::menu::Menu::with_items(app, &[&show_i, &hide_i]).map_err(|e| {
                log::error!("Failed to create system tray menu: {}", e);
                e
            })?;

            // Create tray icon with security monitoring tooltip
            tauri::tray::TrayIconBuilder::new()
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        log::info!("Show window requested from system tray");
                        // Show window; only force focus if sign-in is required
                        let needs_login = {
                            let st = app.state::<Arc<AppState>>().inner().clone();
                            tauri::async_runtime::block_on(async {
                                st.auth_token.read().await.is_none()
                            })
                        };
                        if let Some(window) = app.get_webview_window("main") {
                            if let Err(e) = window.show() {
                                log::error!("Failed to show window: {}", e);
                            } else {
                                log::info!("Window shown successfully");
                            }
                            if needs_login {
                                if let Err(e) = window.set_focus() {
                                    log::error!("Failed to focus window: {}", e);
                                }
                            }
                        }
                    }
                    "hide" => {
                        log::info!("Hide window requested from system tray");
                        if let Some(window) = app.get_webview_window("main") {
                            if let Err(e) = window.hide() {
                                log::error!("Failed to hide window: {}", e);
                            } else {
                                log::info!("Window hidden successfully");
                            }
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| match event {
                    tauri::tray::TrayIconEvent::Enter { .. } => {
                        if let Err(e) =
                            tray.set_tooltip(Some("KlaayGuard - Security Monitoring".to_string()))
                        {
                            log::error!("Failed to set tooltip: {}", e);
                        }
                    }
                    tauri::tray::TrayIconEvent::Leave { .. } => {
                        if let Err(e) = tray.set_tooltip(Some("".to_string())) {
                            log::error!("Failed to clear tooltip: {}", e);
                        }
                    }
                    _ => {}
                })
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .build(app)
                .map_err(|e| {
                    log::error!("Failed to create system tray icon: {}", e);
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

            // Spawn collection loop (Loop A)
            crate::collection::spawn_collection_loop(app_handle.clone(), state_for_loop.clone());
            // Spawn uploader loop (Loop B)
            crate::upload::spawn_upload_loop(app_handle.clone(), state_for_loop.clone());
            // Spawn retention loop (maintenance)
            spawn_retention_loop(app_handle, state_for_loop);

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
            install_launch_agent,
            uninstall_launch_agent,
            get_arch_status,
            get_runtime_status,
            check_for_updates_command,
            download_and_install_update
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
