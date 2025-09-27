use std::{path::PathBuf, sync::Arc};
use rusqlite::Connection;

use crate::AppState;
use super::path::resolve_path;

pub async fn open_from_state(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
) -> Result<Connection, String> {
    let path = {
        let current = state.db_path.read().await.clone();
        if let Some(p) = current { PathBuf::from(p) } else { resolve_path(app)? }
    };
    open_from_path(&path)
}

pub fn open_from_path(path: &PathBuf) -> Result<Connection, String> {
    if *path == PathBuf::from(":memory:") {
        Connection::open_in_memory().map_err(|e| e.to_string())
    } else {
        Connection::open(path).map_err(|e| e.to_string())
    }
}


