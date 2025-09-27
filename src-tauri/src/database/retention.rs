use std::{path::PathBuf, sync::Arc};
use rusqlite::{params, Connection};
use serde::Serialize;

use crate::AppState;
use super::{connection::open_from_path, path::resolve_path, upload::get_last_upload_at};

pub async fn size_mb(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<u64, String> {
    let db_path = {
        let current = state.db_path.read().await.clone();
        if let Some(p) = current { PathBuf::from(p) } else { resolve_path(app)? }
    };
    if db_path == PathBuf::from(":memory:") {
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

pub async fn prune_time_based(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    retention_days: i64,
    prune_batch_rows: i64,
) -> Result<usize, String> {
    let db_path = {
        let current = state.db_path.read().await.clone();
        if let Some(p) = current { PathBuf::from(p) } else { resolve_path(app)? }
    };
    let conn = open_from_path(&db_path)?;
    let last_upload = get_last_upload_at(app, state).await?;
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(retention_days as i64))
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
                params![last_upload.as_str(), cutoff.as_str(), prune_batch_rows],
            )
            .map_err(|e| e.to_string())?;
        total_deleted += deleted as usize;
        if deleted == 0 { break; }
    }
    Ok(total_deleted)
}

pub async fn prune_size_based(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    max_db_mb: u64,
    prune_batch_rows: i64,
) -> Result<usize, String> {
    let db_path = {
        let current = state.db_path.read().await.clone();
        if let Some(p) = current { PathBuf::from(p) } else { resolve_path(app)? }
    };
    if db_path == PathBuf::from(":memory:") { return Ok(0); }
    let conn = open_from_path(&db_path)?;
    let last_upload = get_last_upload_at(app, state).await?;
    let mut total_deleted: usize = 0;
    loop {
        let size_now = size_mb(app, state).await?;
        if size_now <= max_db_mb { break; }
        let deleted = conn
            .execute(
                "DELETE FROM results WHERE id IN (
                   SELECT id FROM results
                   WHERE handled=1
                     AND datetime(created_at) <= datetime(?1)
                   ORDER BY datetime(created_at) ASC, id ASC
                   LIMIT ?2
                 )",
                params![last_upload.as_str(), prune_batch_rows],
            )
            .map_err(|e| e.to_string())?;
        total_deleted += deleted as usize;
        if deleted == 0 { break; }
    }
    Ok(total_deleted)
}

#[derive(Serialize, Debug, Clone, Copy)]
pub struct RunSummary {
    pub deleted_time_based: usize,
    pub deleted_size_based: usize,
    pub db_mb_before: u64,
    pub db_mb_after: u64,
}

pub async fn run_once(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    retention_days: i64,
    max_db_mb: u64,
    prune_batch_rows: i64,
) -> Result<RunSummary, String> {
    let before = size_mb(app, state).await.unwrap_or(0);
    let time_deleted = prune_time_based(app, state, retention_days, prune_batch_rows).await.unwrap_or(0);
    let mut after = size_mb(app, state).await.unwrap_or(before);
    let mut size_deleted = 0usize;
    if after > max_db_mb {
        size_deleted = prune_size_based(app, state, max_db_mb, prune_batch_rows).await.unwrap_or(0);
        after = size_mb(app, state).await.unwrap_or(after);
    }
    // light optimize
    let _ = {
        let db_path = {
            let current = state.db_path.read().await.clone();
            if let Some(p) = current { PathBuf::from(p) } else { resolve_path(app)? }
        };
        let conn = open_from_path(&db_path)?;
        conn.execute_batch("PRAGMA optimize;").ok();
        Ok::<(), String>(())
    };

    Ok(RunSummary { deleted_time_based: time_deleted, deleted_size_based: size_deleted, db_mb_before: before, db_mb_after: after })
}


