mod config;
mod connection;
mod init;
mod path;
mod results;
mod retention;
mod upload;

pub use init::initialize;
pub use path::resolve_path;
pub use results::persist_results;
pub use retention::{prune_size_based, prune_time_based, run_once, size_mb};
pub use upload::{
    get_last_upload_at, mark_rows_handled_and_advance_watermark, select_pending_rows,
};

#[cfg(test)]
mod tests {
    use super::init::initialize_at_path;
    use super::*;
    use crate::AppState;
    use serde_json::json;
    use std::{collections::HashMap, sync::Arc};
    use tokio::runtime::Runtime;

    fn rt() -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn persist_select_and_mark_flow() {
        rt().block_on(async {
            // No app handle required in this test

            let mut path = std::env::temp_dir();
            let fname = format!("klaayguard_test_{}.db", uuid::Uuid::new_v4());
            path.push(fname);
            initialize_at_path(&path).expect("init db");

            let _state = Arc::new(AppState {
                auth_token: tokio::sync::RwLock::new(None),
                api_base_url: tokio::sync::RwLock::new("http://localhost".to_string()),
                last_run_at: tokio::sync::RwLock::new(None),
                last_attempt_at: tokio::sync::RwLock::new(None),
                db_path: tokio::sync::RwLock::new(Some(path.to_string_lossy().to_string())),
                upload_in_progress: tokio::sync::RwLock::new(false),
                keychain_cleared_this_session: tokio::sync::RwLock::new(false),
                last_upload_tick_at: tokio::sync::RwLock::new(None),
                last_focus_at: tokio::sync::RwLock::new(None),
                retention_in_progress: tokio::sync::RwLock::new(false),
            });

            let mut results: HashMap<String, serde_json::Value> = HashMap::new();
            results.insert("events".to_string(), json!([{ "a": 1 }, { "a": 2 }]));
            results.insert("facts".to_string(), json!([{ "b": "x" }]));
            let run_id = uuid::Uuid::new_v4().to_string();
            // Call test-only persist at path directly to avoid app/state plumbing in unit test
            let inserted = results::persist_results_at_path(&path, &run_id, &results).unwrap();
            assert_eq!(inserted, 3);

            let rows = upload::select_pending_rows_at_path(&path, 10).unwrap();
            assert_eq!(rows.len(), 3);
            let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();

            upload::mark_rows_handled_and_advance_watermark_at_path(&path, &ids).unwrap();

            let rows2 = upload::select_pending_rows_at_path(&path, 10).unwrap();
            assert!(rows2.is_empty());
        });
    }
}
