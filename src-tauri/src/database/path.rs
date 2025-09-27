use std::path::PathBuf;
use tauri::Manager;

pub fn resolve_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let mode = std::env::var("KLAAYGUARD_DB_MODE").unwrap_or_else(|_| "file".to_string());
    if mode.eq_ignore_ascii_case("memory") {
        return Ok(PathBuf::from(":memory:"));
    }
    let mut base = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("app_data_dir error: {}", e))?;
    if let Ok(p) = std::env::var("KLAAYGUARD_DB_PATH") {
        return Ok(PathBuf::from(p));
    }
    base.push("klaayguard.db");
    Ok(base)
}
