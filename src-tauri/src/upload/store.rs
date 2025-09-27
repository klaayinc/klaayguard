use std::{path::PathBuf, sync::Arc};

use rusqlite::{params, Connection, ToSql};

use crate::AppState;

use super::types::UploadRow;

async fn get_db_path_cached(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
) -> Result<PathBuf, String> {
    let current = state.db_path.read().await.clone();
    if let Some(p) = current {
        Ok(PathBuf::from(p))
    } else {
        super::super::get_sqlite_path(app)
    }
}

pub async fn get_last_upload_at(
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
        Ok("1970-01-01 00:00:00".to_string())
    }
}

pub async fn select_pending_rows(
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

fn build_in_clause_params(ids: &[i64]) -> (String, Vec<Box<dyn ToSql>>)
{
    let mut placeholders = String::new();
    let mut params_vec: Vec<Box<dyn ToSql>> = Vec::new();
    for (idx, id) in ids.iter().enumerate() {
        if idx > 0 { placeholders.push_str(","); }
        placeholders.push_str("?");
        params_vec.push(Box::new(*id));
    }
    (placeholders, params_vec)
}

pub async fn mark_rows_handled_and_advance_watermark(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    ids: &[i64],
) -> Result<(), String> {
    if ids.is_empty() { return Ok(()); }
    let db_path = get_db_path_cached(app, state).await?;
    let mut conn = if db_path == PathBuf::from(":memory:") {
        Connection::open_in_memory().map_err(|e| e.to_string())?
    } else {
        Connection::open(&db_path).map_err(|e| e.to_string())?
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
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


