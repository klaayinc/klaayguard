use rusqlite::Connection;
use std::path::PathBuf;

pub fn open_from_path(path: &PathBuf) -> Result<Connection, String> {
    if *path == PathBuf::from(":memory:") {
        Connection::open_in_memory().map_err(|e| e.to_string())
    } else {
        Connection::open(path).map_err(|e| e.to_string())
    }
}
