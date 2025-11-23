// Copyright (C) 2024 KLAAY, Inc.
//! Unified status management for KlaayGuard
//! 
//! This module provides a single source of truth for application status,
//! using reactive watch channels to ensure all UI components stay in sync.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_store::StoreExt;

/// Represents the current operational status of the agent
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentStatus {
    /// No authentication token present
    Unauthenticated,
    /// Currently validating authentication token
    Authenticating,
    /// Ready and operating normally
    Ready {
        /// Timestamp of last successful data send
        last_success: Option<DateTime<Utc>>,
    },
    /// Data send failed
    SendFailed {
        /// Error message describing the failure
        error: String,
        /// Timestamp of the failed attempt
        last_attempt: DateTime<Utc>,
    },
}

/// Complete snapshot of application status for UI consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusSnapshot {
    /// Current agent status
    pub status: AgentStatus,
    /// API base URL being used
    pub api_base_url: String,
    /// Timestamp when this status was set
    pub updated_at: DateTime<Utc>,
}

impl StatusSnapshot {
    /// Create a new snapshot with the current timestamp
    pub fn new(status: AgentStatus, api_base_url: String) -> Self {
        Self {
            status,
            api_base_url,
            updated_at: Utc::now(),
        }
    }

    /// Determine if the agent is authenticated and operational
    pub fn is_operational(&self) -> bool {
        matches!(self.status, AgentStatus::Ready { .. })
    }

    /// Get the icon name for the tray based on status
    pub fn tray_icon(&self) -> &'static str {
        match &self.status {
            AgentStatus::Unauthenticated => "icon-error.png",
            AgentStatus::Authenticating => "icon-default.png",
            AgentStatus::Ready { .. } => "icon-success.png",
            AgentStatus::SendFailed { .. } => "icon-error.png",
        }
    }

    /// Get the tooltip text for the tray icon
    pub fn tray_tooltip(&self) -> String {
        match &self.status {
            AgentStatus::Unauthenticated => {
                "🔴 Not authenticated - Click Login to start monitoring".to_string()
            }
            AgentStatus::Authenticating => {
                "🟡 Authenticating...".to_string()
            }
            AgentStatus::Ready { last_success } => {
                if let Some(success_time) = last_success {
                    format!("🟢 Last data send successful ({})", 
                        success_time.format("%H:%M:%S"))
                } else {
                    "🟢 KlaayGuard is running".to_string()
                }
            }
            AgentStatus::SendFailed { error, last_attempt } => {
                format!("🔴 Last data send failed at {}: {}", 
                    last_attempt.format("%H:%M:%S"), error)
            }
        }
    }

    /// Get the status text for the context menu
    pub fn menu_status_text(&self) -> String {
        match &self.status {
            AgentStatus::Unauthenticated => "🔴 Not Authenticated".to_string(),
            AgentStatus::Authenticating => "🟡 Authenticating...".to_string(),
            AgentStatus::Ready { last_success } => {
                if last_success.is_some() {
                    "🟢 KlaayGuard is running".to_string()
                } else {
                    "🟡 KlaayGuard is starting...".to_string()
                }
            }
            AgentStatus::SendFailed { .. } => "🔴 Data send failed".to_string(),
        }
    }
}

/// Status controller for managing and broadcasting status changes
pub struct StatusController;

impl StatusController {
    /// Set a new status and notify all observers
    pub async fn set_status(
        app: &AppHandle,
        state: &Arc<super::AppState>,
        new_status: AgentStatus,
    ) -> Result<(), String> {
        let api_base = state.api_base_url.read().await.clone();
        let snapshot = StatusSnapshot::new(new_status, api_base);
        
        // Update the latest snapshot
        *state.status_snapshot.write().await = Some(snapshot.clone());
        
        // Persist to store
        if let Err(e) = Self::persist_status(app, &snapshot).await {
            log::warn!("Failed to persist status to store: {}", e);
        }
        
        // Update the watch channel
        if let Some(sender) = state.status_sender.read().await.as_ref() {
            sender.send(snapshot.clone()).map_err(|e| {
                format!("Failed to broadcast status update: {}", e)
            })?;
        }
        
        // Emit Tauri event for frontend
        let _ = app.emit("app:status", &snapshot);
        
        // Handle side effects based on status
        match &snapshot.status {
            AgentStatus::Unauthenticated => {
                Self::handle_unauthenticated(app, state).await?;
            }
            AgentStatus::Authenticating => {
                // No special side effects needed
            }
            AgentStatus::Ready { .. } => {
                // Status observer will update UI reactively
            }
            AgentStatus::SendFailed { error, .. } => {
                Self::handle_send_failed(app, error).await;
            }
        }
        
        Ok(())
    }

    /// Handle transition to unauthenticated state
    async fn handle_unauthenticated(
        app: &AppHandle,
        state: &Arc<super::AppState>,
    ) -> Result<(), String> {
        // Clear token from memory
        *state.auth_token.write().await = None;
        
        // Clear keychain if not already cleared this session
        let already_cleared = *state.keychain_cleared_this_session.read().await;
        if !already_cleared {
            let _ = super::keychain::delete_token();
            *state.keychain_cleared_this_session.write().await = true;
        }
        
        log::warn!("Authentication invalidated");
        
        // Emit auth events
        let _ = app.emit("auth:invalidated", ());
        let _ = app.emit("auth:status", serde_json::json!({ "authenticated": false }));
        
        // Open browser for login
        // Check runtime env var first, fall back to compile-time default
        let earthenware_url = std::env::var("VITE_EARTHENWARE_URL")
            .unwrap_or_else(|_| env!("APP_DEFAULT_EARTHENWARE_URL").to_string());
        let callback_url = "klaayguard://auth-callback";
        let full_url = format!("{}/login?app=klaayguard&redirect_to={}", earthenware_url, callback_url);
        log::info!("🌐 Opening browser for re-authentication: {}", full_url);
        if let Err(e) = open::that(&full_url) {
            log::error!("❌ Failed to open browser: {}", e);
        }
        
        // Show notification
        let _ = app.notification()
            .builder()
            .title("KlaayGuard - Authentication Required")
            .body("Your session has expired. Please sign in again.")
            .show();
        
        super::add_breadcrumb("auth", "auth_invalidated", sentry::Level::Warning);
        sentry::capture_message("auth_invalidated", sentry::Level::Warning);
        
        Ok(())
    }

    /// Handle send failure
    async fn handle_send_failed(app: &AppHandle, error: &str) {
        let _ = app.notification()
            .builder()
            .title("KlaayGuard")
            .body(&format!("Data send failed: {}. Will retry in 1 hour.", error))
            .show();
    }

    /// Persist status snapshot to store
    async fn persist_status(app: &AppHandle, snapshot: &StatusSnapshot) -> Result<(), String> {
        // Store persistence is optional - if store plugin is not available, just log and continue
        match app.path().app_data_dir() {
            Ok(app_data_dir) => {
                let path = app_data_dir.join("status.json");
                match app.store(path) {
                    Ok(store) => {
                        let value = serde_json::to_value(snapshot)
                            .map_err(|e| format!("Failed to serialize status: {}", e))?;
                        store.set("status".to_string(), value);
                        store.save()
                            .map_err(|e| format!("Failed to save store: {}", e))?;
                        Ok(())
                    }
                    Err(e) => {
                        log::debug!("Store not available, skipping persistence: {}", e);
                        Ok(())
                    }
                }
            }
            Err(e) => {
                log::debug!("App data dir not available, skipping persistence: {}", e);
                Ok(())
            }
        }
    }

    /// Load persisted status snapshot from store
    pub async fn load_persisted_status(app: &AppHandle) -> Option<StatusSnapshot> {
        // Store loading is optional - if store plugin is not available, return None
        let app_data_dir = app.path().app_data_dir().ok()?;
        let path = app_data_dir.join("status.json");
        let store = app.store(path).ok()?;
        
        store.get("status")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_snapshot_creation() {
        let snapshot = StatusSnapshot::new(
            AgentStatus::Unauthenticated,
            "https://api.test.com".to_string(),
        );
        
        assert_eq!(snapshot.api_base_url, "https://api.test.com");
        assert!(!snapshot.is_operational());
        assert_eq!(snapshot.tray_icon(), "icon-error.png");
        assert!(snapshot.tray_tooltip().contains("Not authenticated"));
        assert!(snapshot.menu_status_text().contains("Not Authenticated"));
    }

    #[test]
    fn test_status_snapshot_ready_with_success() {
        let now = Utc::now();
        let snapshot = StatusSnapshot::new(
            AgentStatus::Ready {
                last_success: Some(now),
            },
            "https://api.test.com".to_string(),
        );
        
        assert!(snapshot.is_operational());
        assert_eq!(snapshot.tray_icon(), "icon-success.png");
        assert!(snapshot.tray_tooltip().contains("Last data send successful"));
        assert!(snapshot.menu_status_text().contains("KlaayGuard is running"));
    }

    #[test]
    fn test_status_snapshot_ready_without_success() {
        let snapshot = StatusSnapshot::new(
            AgentStatus::Ready {
                last_success: None,
            },
            "https://api.test.com".to_string(),
        );
        
        assert!(snapshot.is_operational());
        assert_eq!(snapshot.tray_icon(), "icon-success.png");
        assert_eq!(snapshot.tray_tooltip(), "🟢 KlaayGuard is running");
        assert!(snapshot.menu_status_text().contains("starting"));
    }

    #[test]
    fn test_status_snapshot_send_failed() {
        let now = Utc::now();
        let snapshot = StatusSnapshot::new(
            AgentStatus::SendFailed {
                error: "HTTP 500".to_string(),
                last_attempt: now,
            },
            "https://api.test.com".to_string(),
        );
        
        assert!(!snapshot.is_operational());
        assert_eq!(snapshot.tray_icon(), "icon-error.png");
        assert!(snapshot.tray_tooltip().contains("Last data send failed"));
        assert!(snapshot.tray_tooltip().contains("HTTP 500"));
        assert!(snapshot.menu_status_text().contains("Data send failed"));
    }

    #[test]
    fn test_status_snapshot_authenticating() {
        let snapshot = StatusSnapshot::new(
            AgentStatus::Authenticating,
            "https://api.test.com".to_string(),
        );
        
        assert!(!snapshot.is_operational());
        assert_eq!(snapshot.tray_icon(), "icon-default.png");
        assert!(snapshot.tray_tooltip().contains("Authenticating"));
        assert!(snapshot.menu_status_text().contains("Authenticating"));
    }

    #[test]
    fn test_status_enum_serialization() {
        let status = AgentStatus::Ready {
            last_success: Some(Utc::now()),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("Ready"));
        
        let deserialized: AgentStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, AgentStatus::Ready { .. }));
    }

    #[test]
    fn test_status_snapshot_serialization() {
        let snapshot = StatusSnapshot::new(
            AgentStatus::Unauthenticated,
            "https://api.test.com".to_string(),
        );
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("Unauthenticated"));
        assert!(json.contains("api.test.com"));
        
        let deserialized: StatusSnapshot = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized.status, AgentStatus::Unauthenticated));
        assert_eq!(deserialized.api_base_url, "https://api.test.com");
    }
}
