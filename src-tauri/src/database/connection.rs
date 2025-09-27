use rusqlite::Connection;
use std::path::PathBuf;

// removed unused import of resolve_path

// Removed unused open_from_state (callers resolve path via state or use open_from_path)

pub fn open_from_path(path: &PathBuf) -> Result<Connection, String> {
    if *path == PathBuf::from(":memory:") {
        Connection::open_in_memory().map_err(|e| e.to_string())
    } else {
        Connection::open(path).map_err(|e| e.to_string())
    }
}
