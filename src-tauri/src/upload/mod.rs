use std::{sync::Arc, time::Duration};

use reqwest::StatusCode;
use sentry::Level;
use serde_json::{json, Value};
use tauri::Emitter;

use crate::{add_breadcrumb, auth, AppState};

mod client;
mod r#loop;
pub mod store;
mod types;

pub use r#loop::spawn_upload_loop;
pub use types::{JsonApiPayload, JsonApiResource};

/// Runs a single upload cycle: selects pending rows, builds payload, sends to server, and updates watermark.
pub async fn run_upload_cycle(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    client: &reqwest::Client,
) -> Result<(), String> {
    // prevent overlap
    {
        let uploading = *state.upload_in_progress.read().await;
        if uploading {
            return Ok(());
        }
    }
    *state.upload_in_progress.write().await = true;

    let token = match state.auth_token.read().await.clone() {
        Some(t) => t,
        None => {
            *state.upload_in_progress.write().await = false;
            return Ok(());
        }
    };
    let base = state.api_base_url.read().await.clone();

    // Select pending rows
    let max_rows: usize = std::env::var("KLAAYGUARD_UPLOAD_MAX_ROWS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1000);
    let rows = store::select_pending_rows(app, state, max_rows).await?;
    if rows.is_empty() {
        *state.upload_in_progress.write().await = false;
        return Ok(());
    }
    add_breadcrumb(
        "upload",
        &format!("pending_rows:{}", rows.len()),
        Level::Info,
    );
    sentry::capture_message("upload_pending_rows", Level::Info);

    let device_serial = crate::collection::get_device_serial_number_internal(app)
        .await
        .unwrap_or_else(|_| "unknown".to_string());

    let mut items: Vec<JsonApiResource> = Vec::with_capacity(rows.len());
    let mut ids: Vec<i64> = Vec::with_capacity(rows.len());
    for r in rows {
        ids.push(r.id);
        let mut parsed_json: Value =
            serde_json::from_str(&r.json).unwrap_or(json!({"_raw": r.json}));

        // Add the collected_at timestamp to the attributes
        if let Some(attributes) = parsed_json.as_object_mut() {
            attributes.insert("collected_at".to_string(), json!(r.created_at));
        } else {
            parsed_json = json!({
                "_raw": r.json,
                "collected_at": r.created_at
            });
        }

        items.push(JsonApiResource {
            id: None,
            r#type: r.table_name,
            attributes: parsed_json,
        });
    }
    let payload = JsonApiPayload {
        data: items,
        meta: Some(json!({ "device_uuid": device_serial })),
        jsonapi: Some(json!({ "version": "1.0" })),
    };

    let retry_delays = [60u64, 120u64];
    let mut attempt: usize = 0;

    loop {
        // Serialize payload first to avoid reqwest::RequestBuilder.json() overwriting Content-Type
        let body_json = serde_json::to_vec(&payload).unwrap_or_else(|e| {
            add_breadcrumb("upload", &format!("serialize_error:{}", e), Level::Error);
            // Fallback to empty object; server will 400 and we will surface the error
            b"{}".to_vec()
        });

        match client::send_payload(client, &base, &token, body_json).await {
            Ok(status) => {
                add_breadcrumb(
                    "upload",
                    &format!("post_status:{}", status.as_u16()),
                    Level::Info,
                );

                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    add_breadcrumb("upload", "auth_invalidated_on_post", Level::Warning);
                    auth::invalidate_auth(app, state).await?;
                    let _ = app.emit(
                        "upload:error",
                        json!({ "stage": "post", "status": status.as_u16() }),
                    );
                    *state.upload_in_progress.write().await = false;
                    return Ok(());
                }

                if status.is_success() || status == StatusCode::ACCEPTED {
                    store::mark_rows_handled_and_advance_watermark(app, state, &ids).await?;
                    let _ = app.emit("upload:success", json!({ "count": ids.len() }));
                    log::info!("upload_success submitted_count={}", ids.len());
                    add_breadcrumb(
                        "upload",
                        &format!("success_count:{}", ids.len()),
                        Level::Info,
                    );
                    break;
                }

                if (status.as_u16() == 429 || (500..=599).contains(&status.as_u16()))
                    && attempt < retry_delays.len()
                {
                    let delay = retry_delays[attempt];
                    add_breadcrumb(
                        "upload",
                        &format!("transient_status_retry_in_s:{}", delay),
                        Level::Warning,
                    );
                    sentry::capture_message("upload_transient_status_retry", Level::Warning);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    attempt += 1;
                    continue;
                } else {
                    crate::emit_error_and_focus(
                        app,
                        state,
                        "upload:error",
                        json!({ "stage": "post", "status": status.as_u16() }),
                    )
                    .await;
                    sentry::capture_message("upload_error_non_transient", Level::Warning);
                    break;
                }
            }
            Err(e) => {
                add_breadcrumb("upload", &format!("network_error:{}", e), Level::Warning);
                sentry::capture_message("upload_network_error", Level::Warning);
                if attempt < retry_delays.len() {
                    let delay = retry_delays[attempt];
                    add_breadcrumb("upload", &format!("retry_in_s:{}", delay), Level::Warning);
                    sentry::capture_message("upload_retry", Level::Warning);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    attempt += 1;
                    continue;
                } else {
                    crate::emit_error_and_focus(
                        app,
                        state,
                        "upload:error",
                        json!({ "stage": "network", "error": e.to_string() }),
                    )
                    .await;
                    sentry::capture_message("upload_error_network_final", Level::Warning);
                    break;
                }
            }
        }
    }

    *state.upload_in_progress.write().await = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use tokio::runtime::Runtime;

    fn rt() -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn client_sends_payload_and_handles_status() {
        rt().block_on(async {
            let server = MockServer::start();
            let m = server.mock(|when, then| {
                when.method(POST)
                    .path("/klaayguard/data")
                    .header("content-type", "application/vnd.api+json")
                    .header("accept", "application/vnd.api+json");
                then.status(202);
            });
            let client = reqwest::Client::new();
            let status = crate::upload::client::send_payload(
                &client,
                &server.base_url(),
                "t",
                b"{}".to_vec(),
            )
            .await
            .unwrap();
            m.assert();
            assert_eq!(status, StatusCode::ACCEPTED);
        });
    }
}
