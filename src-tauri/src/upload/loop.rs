use std::{sync::Arc, time::Duration};

use sentry::Level;
use tauri::Emitter;

use crate::{add_breadcrumb, AppState};

use super::run_upload_cycle;

fn wake_gap_seconds() -> u64 {
    std::env::var("KLAAYGUARD_WAKE_GAP_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300)
}

pub fn spawn_upload_loop(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let client = reqwest::Client::builder()
            .user_agent("klaayguard/0.1")
            .build()
            .expect("reqwest client (uploader)");
        // wait for token once
        loop {
            if state.auth_token.read().await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        // immediate drain
        if let Err(e) = run_upload_cycle(&app, &state, &client).await {
            log::error!("initial upload cycle error: {}", e);
            crate::emit_error_and_focus(
                &app,
                &state,
                "upload:error",
                serde_json::json!({ "stage": "internal", "error": e }),
            )
            .await;
        }
        // interval loop (default 15 minutes)
        let interval_secs: u64 = std::env::var("KLAAYGUARD_UPLOAD_INTERVAL_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(900);
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        // initialize last upload tick to now
        *state.last_upload_tick_at.write().await = Some(std::time::Instant::now());
        loop {
            interval.tick().await;
            let now = std::time::Instant::now();
            let woke = {
                let last = *state.last_upload_tick_at.read().await;
                if let Some(prev) = last {
                    let elapsed = now.duration_since(prev);
                    let threshold = std::time::Duration::from_secs(wake_gap_seconds());
                    elapsed >= threshold
                } else {
                    false
                }
            };
            if let Err(e) = run_upload_cycle(&app, &state, &client).await {
                log::error!("upload cycle error: {}", e);
                crate::emit_error_and_focus(
                    &app,
                    &state,
                    "upload:error",
                    serde_json::json!({ "stage": "internal", "error": e }),
                )
                .await;
            }
            if woke {
                let _ = app.emit("system:wake_detected", serde_json::json!({ "loop": "upload" }));
                add_breadcrumb("system", "wake_detected_upload", Level::Info);
                sentry::capture_message("wake_detected_upload", Level::Info);
                // immediate extra drain to catch up after wake
                if let Err(e) = run_upload_cycle(&app, &state, &client).await {
                    log::error!("upload cycle (post-wake) error: {}", e);
                    crate::emit_error_and_focus(
                        &app,
                        &state,
                        "upload:error",
                        serde_json::json!({ "stage": "internal", "error": e, "post_wake": true }),
                    )
                    .await;
                    sentry::capture_message("upload_error_post_wake", Level::Warning);
                }
            }
            *state.last_upload_tick_at.write().await = Some(now);
        }
    });
}


