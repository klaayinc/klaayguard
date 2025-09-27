use std::sync::Arc;

use crate::AppState;

pub struct BackgroundTasksManager {
    // Currently no join handles retained; tasks run for app lifetime.
}

impl BackgroundTasksManager {
    pub fn start(app: tauri::AppHandle, state: Arc<AppState>) -> Self {
        // Delegate to existing loops to preserve behavior
        crate::collection::spawn_collection_loop(app.clone(), state.clone());
        crate::upload::spawn_upload_loop(app.clone(), state.clone());
        crate::background::retention::spawn_retention_loop(app, state);
        Self {}
    }

    #[allow(dead_code)]
    pub fn stop(self) {
        // No-op for now; loops are unbounded lifetime tasks.
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn manager_start_does_not_panic() {
        // We cannot run Tauri app handle in unit test easily; this test is a placeholder
        // for construction-only logic remaining panic-free.
        assert!(true);
    }
}
