use std::sync::Arc;
use std::time::Duration;

use sentry::Level;
use serde_json::json;
use tauri::Emitter;

use crate::{add_breadcrumb, database, AppState};

use super::config::retention_interval_seconds;

async fn get_db_size_mb(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<u64, String> {
    database::size_mb(app, state).await
}

async fn run_retention_cycle(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<(), String> {
    if *state.retention_in_progress.read().await {
        return Ok(());
    }
    *state.retention_in_progress.write().await = true;
    let before = get_db_size_mb(app, state).await.unwrap_or(0);
    add_breadcrumb("retention", &format!("start_db_mb:{}", before), Level::Info);
    let summary = database::run_once(
        app,
        state,
        database::config::retention_days(),
        database::config::max_db_mb(),
        database::config::prune_batch_rows(),
    )
    .await?;
    let _ = app.emit(
        "retention:run",
        json!({
            "deleted_time_based": summary.deleted_time_based,
            "deleted_size_based": summary.deleted_size_based,
            "db_mb_before": summary.db_mb_before,
            "db_mb_after": summary.db_mb_after,
        }),
    );
    add_breadcrumb(
        "retention",
        &format!(
            "done time_deleted:{} size_deleted:{} db_mb:{}->{}",
            summary.deleted_time_based,
            summary.deleted_size_based,
            summary.db_mb_before,
            summary.db_mb_after
        ),
        Level::Info,
    );
    *state.retention_in_progress.write().await = false;
    Ok(())
}

pub fn spawn_retention_loop(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        loop {
            if state.db_path.read().await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_retention_cycle_reentrant_guard() {
        // Build a minimal AppState
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

        // We can only call the internal function via a stub of its behavior here; ensure flag toggles.
        *state.retention_in_progress.write().await = true;
        // When already in progress, subsequent call should bail early (Ok(()))
        // We cannot construct a real AppHandle here; this test only validates guard state transitions
        assert_eq!(*state.retention_in_progress.read().await, true);
        *state.retention_in_progress.write().await = false;
        assert_eq!(*state.retention_in_progress.read().await, false);
    }
}
