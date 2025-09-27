use std::sync::Arc;

use super::types::UploadRow;
use crate::AppState;

// Removed redundant wrapper; use crate::database::get_last_upload_at directly

pub async fn select_pending_rows(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    max_rows: usize,
) -> Result<Vec<UploadRow>, String> {
    crate::database::select_pending_rows(app, state, max_rows).await
}

pub async fn mark_rows_handled_and_advance_watermark(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    ids: &[i64],
) -> Result<(), String> {
    crate::database::mark_rows_handled_and_advance_watermark(app, state, ids).await
}
