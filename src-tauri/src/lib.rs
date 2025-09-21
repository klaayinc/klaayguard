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

use keyring::Entry;
use rusqlite::{params, Connection, ToSql};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, fs, path::PathBuf, sync::Arc, time::Duration};
use tauri::{Emitter, Manager};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_updater::UpdaterExt;
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
}

const KEYCHAIN_SERVICE: &str = "com.klaay.klaayguard";
const KEYCHAIN_ACCOUNT: &str = "auth_token";

fn keyring_entry() -> Result<Entry, String> {
    Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .map_err(|e| format!("keychain new entry error: {}", e))
}

fn save_token_to_keychain(token: &str) -> Result<(), String> {
    keyring_entry()?
        .set_password(token)
        .map_err(|e| format!("keychain set_password error: {}", e))
}

fn load_token_from_keychain() -> Result<Option<String>, String> {
    match keyring_entry()?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("keychain get_password error: {}", e)),
    }
}

fn delete_token_from_keychain() -> Result<(), String> {
    match keyring_entry()?.delete_password() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("keychain delete_password error: {}", e)),
    }
}

#[tauri::command]
async fn set_api_base_url(
    state: tauri::State<'_, Arc<AppState>>,
    base: String,
) -> Result<(), String> {
    *state.api_base_url.write().await = base;
    Ok(())
}

#[tauri::command]
async fn save_auth_token(
    state: tauri::State<'_, Arc<AppState>>,
    token: String,
) -> Result<(), String> {
    *state.auth_token.write().await = Some(token.clone());
    // Reset the session guard; we have a fresh token now
    *state.keychain_cleared_this_session.write().await = false;
    let _ = save_token_to_keychain(&token);
    Ok(())
}

#[tauri::command]
async fn clear_auth_token(state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
    *state.auth_token.write().await = None;
    // Allow a single delete per session to avoid repeated Keychain prompts
    let already_cleared = *state.keychain_cleared_this_session.read().await;
    if !already_cleared {
        let _ = delete_token_from_keychain();
        *state.keychain_cleared_this_session.write().await = true;
    }
    Ok(())
}

/// Returns seconds until next scheduled run (900s interval).
/// -1 indicates not signed in (no token yet). 0 means due now or overdue.
#[tauri::command]
async fn get_next_run_in_seconds(state: tauri::State<'_, Arc<AppState>>) -> Result<i64, String> {
    if state.auth_token.read().await.is_none() {
        return Ok(-1);
    }
    // Use last attempt time so countdown advances even if last run failed
    let last = *state.last_attempt_at.read().await;
    let interval = std::time::Duration::from_secs(15 * 60);
    if let Some(last) = last {
        let elapsed = last.elapsed();
        if elapsed >= interval {
            Ok(0)
        } else {
            Ok((interval - elapsed).as_secs() as i64)
        }
    } else {
        // first run should happen immediately after login/token
        Ok(0)
    }
}

#[tauri::command]
async fn get_device_uuid(app: tauri::AppHandle) -> Result<String, String> {
    let tables = vec!["system_info".to_string()];
    let query_result = execute_query(app, tables).await?;

    let uuid = query_result
        .get("system_info")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|obj| obj.get("uuid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Couldn't find device uuid".to_string())?;

    Ok(uuid.to_string())
}

#[derive(serde::Serialize)]
struct AuthStatus {
    authenticated: bool,
    display_name: Option<String>,
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
    let name = match client
        .get(format!("{}/me", base))
        .bearer_auth(&token)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED
                || resp.status() == reqwest::StatusCode::FORBIDDEN
            {
                // Invalidate and prompt login
                invalidate_auth(&app, &state).await.ok();
                None
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
                        if !full.is_empty() {
                            Some(full)
                        } else {
                            email.map(|s| s.to_string())
                        }
                    }
                    Err(_) => None,
                }
            } else {
                None
            }
        }
        Err(_) => None,
    };
    Ok(AuthStatus {
        authenticated: true,
        display_name: name,
    })
}

#[tauri::command]
async fn execute_query(
    app: tauri::AppHandle,
    table_names: Vec<String>,
) -> Result<HashMap<String, Value>, String> {
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

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
            // Gracefully handle missing/unsupported tables by recording an empty result set
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
            format!(
                "Failed to parse JSON for table {} (content: '{}'): {}",
                table_name,
                stdout_str.trim(),
                e
            )
        })?;

        all_results.insert(table_name, parsed_result);
    }

    Ok(all_results)
}

async fn invalidate_auth(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<(), String> {
    *state.auth_token.write().await = None;
    // Delete the token at most once per session to reduce prompts
    let already_cleared = *state.keychain_cleared_this_session.read().await;
    if !already_cleared {
        let _ = delete_token_from_keychain();
        *state.keychain_cleared_this_session.write().await = true;
    }
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
    let _ = app.emit("auth:invalidated", ());
    let _ = app.emit("auth:status", json!({ "authenticated": false }));
    Ok(())
}

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
        *state.last_focus_at.write().await = Some(now);
        let _ = app.emit(
            "focus:on_failure",
            json!({ "at": chrono::Utc::now().to_rfc3339() }),
        );
    }
}

async fn emit_error_and_focus(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    event: &str,
    payload: serde_json::Value,
) {
    let _ = app.emit(event, payload);
    focus_window_with_debounce(app, state).await;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadRow {
    id: i64,
    table_name: String,
    json: String,
    run_id: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadRowPayload {
    id: i64,
    table_name: String,
    json: Value,
    run_id: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadPayload {
    device_id: String,
    batch_id: String,
    rows: Vec<UploadRowPayload>,
}

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

async fn get_last_upload_at(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
) -> Result<String, String> {
    let db_path = get_db_path_cached(app, state).await?;
    let conn = if db_path == PathBuf::from(":memory:") {
        Connection::open_in_memory().map_err(|e| e.to_string())?
    } else {
        Connection::open(&db_path).map_err(|e| e.to_string())?
    };
    let mut stmt = conn
        .prepare("SELECT value FROM metadata WHERE key='last_upload_at' LIMIT 1")
        .map_err(|e| e.to_string())?;
    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
    if let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let v: String = row.get(0).map_err(|e| e.to_string())?;
        Ok(v)
    } else {
        // Epoch-like timestamp in SQLite default format to match created_at
        Ok("1970-01-01 00:00:00".to_string())
    }
}

async fn select_pending_rows(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    max_rows: usize,
) -> Result<Vec<UploadRow>, String> {
    let db_path = get_db_path_cached(app, state).await?;
    let conn = if db_path == PathBuf::from(":memory:") {
        Connection::open_in_memory().map_err(|e| e.to_string())?
    } else {
        Connection::open(&db_path).map_err(|e| e.to_string())?
    };
    let watermark = get_last_upload_at(app, state).await?;
    let mut stmt = conn
        .prepare(
            "SELECT id, table_name, json, run_id, created_at \
             FROM results \
             WHERE handled=0 AND created_at > ?1 \
             ORDER BY datetime(created_at) ASC, id ASC \
             LIMIT ?2",
        )
        .map_err(|e| e.to_string())?;
    let mut rows = stmt
        .query(params![&watermark, max_rows as i64])
        .map_err(|e| e.to_string())?;
    let mut out: Vec<UploadRow> = Vec::new();
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        out.push(UploadRow {
            id: row.get(0).map_err(|e| e.to_string())?,
            table_name: row.get(1).map_err(|e| e.to_string())?,
            json: row.get(2).map_err(|e| e.to_string())?,
            run_id: row.get(3).map_err(|e| e.to_string())?,
            created_at: row.get(4).map_err(|e| e.to_string())?,
        });
    }
    Ok(out)
}

fn build_in_clause_params(ids: &[i64]) -> (String, Vec<Box<dyn ToSql>>) {
    // Produce placeholders like ?, ?, ? and corresponding params
    let mut placeholders = String::new();
    let mut params_vec: Vec<Box<dyn ToSql>> = Vec::new();
    for (idx, id) in ids.iter().enumerate() {
        if idx > 0 {
            placeholders.push_str(",");
        }
        placeholders.push_str("?");
        params_vec.push(Box::new(*id));
    }
    (placeholders, params_vec)
}

async fn mark_rows_handled_and_advance_watermark(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    ids: &[i64],
) -> Result<(), String> {
    if ids.is_empty() {
        return Ok(());
    }
    let db_path = get_db_path_cached(app, state).await?;
    let mut conn = if db_path == PathBuf::from(":memory:") {
        Connection::open_in_memory().map_err(|e| e.to_string())?
    } else {
        Connection::open(&db_path).map_err(|e| e.to_string())?
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    // UPDATE handled flag
    let (ph, params_vec) = build_in_clause_params(ids);
    let update_sql = format!(
        "UPDATE results SET handled=1, handled_at=CURRENT_TIMESTAMP WHERE id IN ({})",
        ph
    );
    {
        let mut stmt = tx.prepare(&update_sql).map_err(|e| e.to_string())?;
        let params_slice: Vec<&dyn ToSql> = params_vec.iter().map(|b| &**b as &dyn ToSql).collect();
        stmt.execute(rusqlite::params_from_iter(params_slice))
            .map_err(|e| e.to_string())?;
    }
    // MAX(created_at) for watermark
    let select_sql = format!("SELECT MAX(created_at) FROM results WHERE id IN ({})", ph);
    let max_created_at: Option<String> = {
        let mut stmt = tx.prepare(&select_sql).map_err(|e| e.to_string())?;
        let params_slice: Vec<&dyn ToSql> = params_vec.iter().map(|b| &**b as &dyn ToSql).collect();
        let mut rows = stmt
            .query(rusqlite::params_from_iter(params_slice))
            .map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            row.get(0).ok()
        } else {
            None
        }
    };
    if let Some(max_ts) = max_created_at {
        tx.execute(
            "INSERT INTO metadata(key, value) VALUES('last_upload_at', ?1) \
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![&max_ts],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(())
}

async fn get_device_uuid_internal(app: &tauri::AppHandle) -> Result<String, String> {
    let tables = vec!["system_info".to_string()];
    let result = execute_query(app.clone(), tables).await?;
    let uuid = result
        .get("system_info")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|obj| obj.get("uuid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Couldn't find device uuid".to_string())?;
    Ok(uuid.to_string())
}

async fn run_upload_cycle(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    client: &reqwest::Client,
) -> Result<(), String> {
    // prevent overlap
    {
        let uploading = *state.upload_in_progress.read().await;
        if uploading {
            return Ok(());
        }
    }
    *state.upload_in_progress.write().await = true;
    let token = match state.auth_token.read().await.clone() {
        Some(t) => t,
        None => {
            *state.upload_in_progress.write().await = false;
            return Ok(());
        }
    };
    let base = state.api_base_url.read().await.clone();
    // Select pending rows
    let max_rows: usize = std::env::var("KLAAYGUARD_UPLOAD_MAX_ROWS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1000);
    let rows = select_pending_rows(app, state, max_rows).await?;
    if rows.is_empty() {
        *state.upload_in_progress.write().await = false;
        return Ok(());
    }
    let device_id = get_device_uuid_internal(app)
        .await
        .unwrap_or_else(|_| "unknown".to_string());
    let batch_id = Uuid::new_v4().to_string();
    let mut payload_rows: Vec<UploadRowPayload> = Vec::with_capacity(rows.len());
    let mut ids: Vec<i64> = Vec::with_capacity(rows.len());
    for r in rows {
        ids.push(r.id);
        let parsed_json: Value = serde_json::from_str(&r.json).unwrap_or(json!({"_raw": r.json}));
        payload_rows.push(UploadRowPayload {
            id: r.id,
            table_name: r.table_name,
            json: parsed_json,
            run_id: r.run_id,
            created_at: r.created_at,
        });
    }
    let payload = UploadPayload {
        device_id,
        batch_id,
        rows: payload_rows,
    };
    let resp = client
        .post(format!("{}/klaayguard/data", base))
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || resp.status() == reqwest::StatusCode::FORBIDDEN
    {
        invalidate_auth(app, state).await?;
        let _ = app.emit(
            "upload:error",
            json!({ "stage": "post", "status": resp.status().as_u16() }),
        );
        *state.upload_in_progress.write().await = false;
        return Ok(());
    }
    if resp.status().is_success() || resp.status() == reqwest::StatusCode::ACCEPTED {
        // Mark handled and advance watermark
        mark_rows_handled_and_advance_watermark(app, state, &ids).await?;
        let _ = app.emit("upload:success", json!({ "count": ids.len() }));
    } else {
        emit_error_and_focus(
            app,
            state,
            "upload:error",
            json!({ "stage": "post", "status": resp.status().as_u16() }),
        )
        .await;
    }
    *state.upload_in_progress.write().await = false;
    Ok(())
}

fn spawn_upload_loop(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let client = reqwest::Client::builder()
            .user_agent("klaayguard/0.1")
            .build()
            .expect("reqwest client (uploader)");
        // wait for token once
        loop {
            if state.auth_token.read().await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        // immediate drain
        if let Err(e) = run_upload_cycle(&app, &state, &client).await {
            eprintln!("initial upload cycle error: {}", e);
            emit_error_and_focus(
                &app,
                &state,
                "upload:error",
                json!({ "stage": "internal", "error": e }),
            )
            .await;
        }
        // interval loop (15 minutes)
        let interval_secs: u64 = std::env::var("KLAAYGUARD_UPLOAD_INTERVAL_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(15 * 60);
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        // initialize last upload tick to now
        *state.last_upload_tick_at.write().await = Some(std::time::Instant::now());
        loop {
            interval.tick().await;
            let now = std::time::Instant::now();
            let woke = {
                let last = *state.last_upload_tick_at.read().await;
                if let Some(prev) = last {
                    let elapsed = now.duration_since(prev);
                    let threshold = std::time::Duration::from_secs(wake_gap_seconds());
                    elapsed >= threshold
                } else {
                    false
                }
            };
            if let Err(e) = run_upload_cycle(&app, &state, &client).await {
                eprintln!("upload cycle error: {}", e);
                emit_error_and_focus(
                    &app,
                    &state,
                    "upload:error",
                    json!({ "stage": "internal", "error": e }),
                )
                .await;
            }
            if woke {
                let _ = app.emit("system:wake_detected", json!({ "loop": "upload" }));
                // immediate extra drain to catch up after wake
                if let Err(e) = run_upload_cycle(&app, &state, &client).await {
                    eprintln!("upload cycle (post-wake) error: {}", e);
                    emit_error_and_focus(
                        &app,
                        &state,
                        "upload:error",
                        json!({ "stage": "internal", "error": e, "post_wake": true }),
                    )
                    .await;
                }
            }
            *state.last_upload_tick_at.write().await = Some(now);
        }
    });
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
    let cfg_resp = client
        .get(format!("{}/klaayguard/config", base))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if cfg_resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || cfg_resp.status() == reqwest::StatusCode::FORBIDDEN
    {
        invalidate_auth(app, state).await?;
        let _ = app.emit(
            "collection:error",
            json!({ "stage": "config", "status": cfg_resp.status().as_u16() }),
        );
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
        return Ok(());
    }

    let cfg_json: Value = cfg_resp.json().await.map_err(|e| e.to_string())?;
    let tables: Vec<String> = cfg_json
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    item.get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    if tables.is_empty() {
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
    let results = execute_query(app.clone(), tables).await?;

    // 3) Persist results to SQLite (Loop A)
    let run_id = Uuid::new_v4().to_string();
    let inserted = persist_results_to_sqlite(app, state, &run_id, &results).await?;
    *state.last_run_at.write().await = Some(std::time::Instant::now());
    let _ = app.emit(
        "collection:success",
        json!({ "inserted_rows": inserted, "run_id": run_id }),
    );

    Ok(())
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

        // run immediately
        if let Err(e) = run_cycle(&app, &state, &client).await {
            eprintln!("initial cycle error: {}", e);
            emit_error_and_focus(
                &app,
                &state,
                "collection:error",
                json!({ "stage": "internal", "error": e }),
            )
            .await;
        }

        let mut interval = tokio::time::interval(Duration::from_secs(15 * 60));
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
            }
            if let Err(e) = run_cycle(&app, &state, &client).await {
                eprintln!("cycle error: {}", e);
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

fn get_sqlite_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
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
        "#,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
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
        let home_dir = dirs::home_dir().ok_or("Could not find home directory")?;
        let launch_agents_dir = home_dir.join("Library/LaunchAgents");
        let label = "com.klaay.klaayguard";
        let plist_path = launch_agents_dir.join(format!("{}.plist", label));

        // Determine user launchctl domain
        let uid = nix::unistd::getuid().as_raw();
        let domain = format!("gui/{}", uid);

        // Check if launch agent is already loaded using modern launchctl
        let output = std::process::Command::new("launchctl")
            .args(&["print", &format!("{}/{}", domain, label)])
            .output()
            .map_err(|e| format!("Failed to check launch agent status: {}", e))?;

        if output.status.success() {
            return Ok("Launch agent already installed and running".to_string());
        }

        // Create LaunchAgents directory if it doesn't exist
        fs::create_dir_all(&launch_agents_dir)
            .map_err(|e| format!("Failed to create LaunchAgents directory: {}", e))?;

        // Clean up legacy label/file if present
        let legacy_plist = launch_agents_dir.join("KlaayGuard.plist");
        if legacy_plist.exists() {
            let _ = std::process::Command::new("launchctl")
                .args(&["bootout", &format!("{}/{}", domain, "KlaayGuard")])
                .output();
            let _ = fs::remove_file(&legacy_plist);
        }

        // Get the current executable path (used as fallback when the app is not installed in /Applications)
        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get current executable path: {}", e))?;

        // Determine preferred executable path: prefer installed app in /Applications
        let installed_path =
            std::path::Path::new("/Applications/KlaayGuard.app/Contents/MacOS/KlaayGuard");
        let preferred_exec = if installed_path.exists() {
            installed_path.to_path_buf()
        } else {
            current_exe.clone()
        };

        // Read the plist template and replace placeholders
        let plist_content = include_str!("../resources/com.klaay.klaayguard.plist");
        let plist_content = plist_content
            .replace("__LABEL__", label)
            .replace("__EXECUTABLE__", &preferred_exec.to_string_lossy());

        // Write the plist file
        fs::write(&plist_path, plist_content)
            .map_err(|e| format!("Failed to write plist file: {}", e))?;

        // Bootstrap (load) the launch agent using modern launchctl domain
        let output = std::process::Command::new("launchctl")
            .args(&["bootstrap", &domain, plist_path.to_str().unwrap()])
            .output()
            .map_err(|e| format!("Failed to bootstrap launch agent: {}", e))?;

        // If already bootstrapped, continue; else require success
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Error code 9 or message indicating already bootstrapped can be ignored
            if !stderr.contains("EEXIST") && !stderr.contains("already loaded") {
                return Err(format!("Failed to bootstrap launch agent: {}", stderr));
            }
        }

        // Enable the service
        let _ = std::process::Command::new("launchctl")
            .args(&["enable", &format!("{}/{}", domain, label)])
            .output();

        // Kickstart the service immediately
        let _ = std::process::Command::new("launchctl")
            .args(&["kickstart", "-k", &format!("{}/{}", domain, label)])
            .output();

        Ok("Launch agent installed successfully".to_string())
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err("Launch agent installation is only supported on macOS".to_string())
    }
}

/// Handles automatic updates for security patches and bug fixes.
///
/// This function checks for available updates and automatically downloads and installs them.
/// The app will restart after a successful update to ensure the latest security patches
/// are active.
async fn update(app: tauri::AppHandle) -> tauri_plugin_updater::Result<()> {
    if let Some(update) = app.updater()?.check().await? {
        let mut downloaded = 0;

        // alternatively we could also call update.download() and update.install() separately
        update
            .download_and_install(
                |chunk_length, content_length| {
                    downloaded += chunk_length;
                    println!("downloaded {downloaded} from {content_length:?}");
                },
                || {
                    println!("download finished");
                },
            )
            .await?;

        println!("update installed");
        app.restart();
    }

    Ok(())
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
    });

    let app = tauri::Builder::default()
        .manage(state.clone())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let handle2 = app.handle().clone();

            // Hide the app from the dock on macOS for security monitoring
            #[cfg(target_os = "macos")]
            {
                app.set_activation_policy(tauri::ActivationPolicy::Accessory);
                log::info!("KlaayGuard configured as background service - hidden from dock");
            }

            // Check if we're already running as a regular process to prevent duplicates
            #[cfg(target_os = "macos")]
            {
                let current_pid = std::process::id();
                let output = std::process::Command::new("pgrep")
                    .args(&["-f", "KlaayGuard"])
                    .output();

                if let Ok(output) = output {
                    if output.status.success() {
                        let other_count = String::from_utf8_lossy(&output.stdout)
                            .lines()
                            .filter_map(|line| line.trim().parse::<u32>().ok())
                            .filter(|pid| *pid != current_pid)
                            .count();

                        // If another KlaayGuard process is running (excluding this one), exit this instance
                        if other_count > 0 {
                            std::process::exit(0);
                        }
                    }
                }
            }

            tauri::async_runtime::spawn(async move {
                update(handle2).await.unwrap_or_else(|e| {
                    eprintln!("Failed to check for updates: {}", e);
                });
            });

            // Automatically install launch agent on macOS
            #[cfg(target_os = "macos")]
            {
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = install_launch_agent().await {
                        eprintln!("Failed to install launch agent: {}", e);
                    }
                });
            }
            let window = app.get_webview_window("main").unwrap();
            let window_ = window.clone();

            // Show the window on startup to display the login screen
            window.show().unwrap();
            window.set_focus().unwrap();
            log::info!("KlaayGuard started - login screen displayed");

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
                        if let Some(window) = app.get_webview_window("main") {
                            if let Err(e) = window.show() {
                                log::error!("Failed to show window: {}", e);
                            } else {
                                log::info!("Window shown successfully");
                            }
                            if let Err(e) = window.set_focus() {
                                log::error!("Failed to focus window: {}", e);
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

            // Load token from keychain at startup and emit status
            if let Ok(Some(tok)) = load_token_from_keychain() {
                tauri::async_runtime::block_on(async {
                    *state_for_loop.auth_token.write().await = Some(tok);
                });
                let _ = app.emit("auth:status", json!({ "authenticated": true }));
            } else {
                let _ = app.emit("auth:status", json!({ "authenticated": false }));
            }

            // Initialize SQLite (file-backed) path and schema
            if let Err(e) = init_sqlite(&app.handle()) {
                eprintln!("Failed to initialize SQLite: {}", e);
            } else {
                if let Some(p) = get_sqlite_path(&app.handle()).ok() {
                    tauri::async_runtime::block_on(async {
                        *state_for_loop.db_path.write().await =
                            Some(p.to_string_lossy().to_string());
                    });
                }
            }

            spawn_background_loop(app_handle.clone(), state_for_loop.clone());
            // Spawn uploader loop (Loop B)
            spawn_upload_loop(app_handle, state_for_loop);

            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            execute_query,
            get_device_uuid,
            save_auth_token,
            clear_auth_token,
            set_api_base_url,
            get_next_run_in_seconds,
            get_auth_status
        ])
        .build(tauri::generate_context!())
        .expect("error building tauri application");

    app.run(|_app_handle, _event| {});
}
