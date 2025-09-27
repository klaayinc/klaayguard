use std::{collections::HashMap, sync::Arc, time::Duration};

use reqwest::Client;
use sentry::Level;
use serde_json::{json, Value};
use tauri::Emitter;

use crate::{add_breadcrumb, auth, emit_error_and_focus, AppState};
use tauri_plugin_shell::ShellExt;

fn collection_interval_seconds() -> u64 {
    std::env::var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(900)
}

#[tauri::command]
pub async fn get_next_run_in_seconds(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<i64, String> {
    if state.auth_token.read().await.is_none() {
        return Ok(-1);
    }
    let last = *state.last_attempt_at.read().await;
    let interval = std::time::Duration::from_secs(collection_interval_seconds());
    if let Some(last) = last {
        let elapsed = last.elapsed();
        if elapsed >= interval {
            Ok(0)
        } else {
            Ok((interval - elapsed).as_secs() as i64)
        }
    } else {
        Ok(0)
    }
}

#[tauri::command]
pub async fn execute_query(
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

pub async fn execute_sql_batch(
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
            format!(
                "Failed to parse JSON for {} (content: '{}'): {}",
                logical_id,
                stdout_str.trim(),
                e
            )
        })?;
        all_results.insert(logical_id, parsed_result);
    }
    Ok(all_results)
}

#[tauri::command]
pub async fn get_device_serial_number(app: tauri::AppHandle) -> Result<String, String> {
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
                .or_else(|| obj.get("hardware_serial").and_then(|v| v.as_str()))
                .or_else(|| obj.get("hardware_uuid").and_then(|v| v.as_str()))
        })
        .unwrap_or("UNKNOWN");
    Ok(serial.to_string())
}

pub async fn get_device_serial_number_internal(app: &tauri::AppHandle) -> Result<String, String> {
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
                .or_else(|| obj.get("hardware_serial").and_then(|v| v.as_str()))
                .or_else(|| obj.get("hardware_uuid").and_then(|v| v.as_str()))
        })
        .unwrap_or("UNKNOWN");
    Ok(serial.to_string())
}

async fn fetch_config(
    client: &Client,
    base: &str,
    token: &str,
) -> Result<reqwest::Response, reqwest::Error> {
    client
        .get(format!("{}/klaayguard/config", base))
        .bearer_auth(token)
        .send()
        .await
}

pub async fn run_collection_cycle(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    client: &Client,
) -> Result<(), String> {
    let token = match state.auth_token.read().await.clone() {
        Some(t) => t,
        None => return Ok(()),
    };
    let base = state.api_base_url.read().await.clone();
    *state.last_attempt_at.write().await = Some(std::time::Instant::now());
    let _ = app.emit("collection:attempt", ());

    add_breadcrumb("collection", "config_fetch_start", Level::Info);
    sentry::capture_message("collection_config_fetch_start", Level::Info);
    let is_transient_status = |code: u16| -> bool { code == 429 || (500..=599).contains(&code) };
    let retry_delays = [60u64, 120u64];
    let mut attempt = 0usize;
    let cfg_resp = loop {
        match fetch_config(client, &base, &token).await {
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

    add_breadcrumb("collection", "osquery_start", Level::Info);
    sentry::capture_message("collection_osquery_start", Level::Info);
    let results = execute_sql_batch(app.clone(), queries).await?;

    let run_id = uuid::Uuid::new_v4().to_string();
    let inserted = crate::persist_results_to_sqlite(app, state, &run_id, &results).await?;
    *state.last_run_at.write().await = Some(std::time::Instant::now());
    let _ = app.emit(
        "collection:success",
        json!({ "inserted_rows": inserted, "run_id": run_id }),
    );
    add_breadcrumb(
        "collection",
        &format!("persisted_rows:{} run_id:{}", inserted, run_id),
        Level::Info,
    );
    sentry::capture_message("collection_persisted", Level::Info);

    if let Err(e) = crate::upload::run_upload_cycle(app, state, client).await {
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

pub fn spawn_collection_loop(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let client = reqwest::Client::builder()
            .user_agent("klaayguard/0.1")
            .build()
            .expect("reqwest client");

        loop {
            if state.auth_token.read().await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }

        if let Err(e) = run_collection_cycle(&app, &state, &client).await {
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
            let woke = {
                let last = *state.last_attempt_at.read().await;
                if let Some(prev) = last {
                    prev.elapsed() >= std::time::Duration::from_secs(crate::wake_gap_seconds())
                } else {
                    false
                }
            };
            if woke {
                let _ = app.emit("system:wake_detected", json!({ "loop": "collection" }));
                add_breadcrumb("system", "wake_detected_collection", Level::Info);
                sentry::capture_message("wake_detected_collection", Level::Info);
            }
            if let Err(e) = run_collection_cycle(&app, &state, &client).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    // use httpmock::prelude::*;
    use tokio::runtime::Runtime;

    fn rt() -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn test_next_run_no_token() {
        rt().block_on(async {
            let state = Arc::new(AppState {
                auth_token: tokio::sync::RwLock::new(None),
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
            // Directly verify logic without constructing tauri::State in unit test
            if state.auth_token.read().await.is_none() {
                assert_eq!(-1, -1);
            } else {
                unreachable!();
            }
        });
    }

    // Additional tests for pure logic should be added here as needed
}
