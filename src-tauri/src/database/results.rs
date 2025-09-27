use std::{collections::HashMap, path::PathBuf, sync::Arc};
use rusqlite::params;
use serde_json::Value;

use crate::AppState;
use super::{connection::open_from_path, path::resolve_path};

pub async fn persist_results(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    run_id: &str,
    results: &HashMap<String, Value>,
) -> Result<usize, String> {
    let db_path = {
        let current = state.db_path.read().await.clone();
        if let Some(p) = current { PathBuf::from(p) } else { resolve_path(app)? }
    };
    let mut conn = open_from_path(&db_path)?;
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

#[cfg(test)]
pub fn persist_results_at_path(
    db_path: &PathBuf,
    run_id: &str,
    results: &HashMap<String, Value>,
) -> Result<usize, String> {
    let mut conn = open_from_path(db_path)?;
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


