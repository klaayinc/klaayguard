use rusqlite::Connection;
use std::path::PathBuf;

use super::path::resolve_path;

pub fn initialize(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let db_path = resolve_path(app)?;
    initialize_at_path(&db_path)?;
    Ok(db_path)
}

pub fn initialize_at_path(db_path: &PathBuf) -> Result<(), String> {
    if *db_path != PathBuf::from(":memory:") {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create_dir_all for db parent failed: {}", e))?;
        }
    }
    let conn = if *db_path == PathBuf::from(":memory:") {
        Connection::open_in_memory().map_err(|e| e.to_string())?
    } else {
        Connection::open(db_path).map_err(|e| e.to_string())?
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
