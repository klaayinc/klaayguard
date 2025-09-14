use anyhow::Result;
use chrono::Utc;
use log::{error, info, warn};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tauri::AppHandle;
use tauri_plugin_shell::ShellExt;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration as TokioDuration};

use crate::database::Database;
use crate::wake_timer::WakeTimer;

pub struct MonitoringService {
    app_handle: AppHandle,
    database: Arc<Database>,
    pub device_uuid: Arc<Mutex<Option<String>>>,
    api_base_url: String,
    auth_token: Arc<Mutex<Option<String>>>,
    pub is_running: Arc<Mutex<bool>>,
    wake_timer: Arc<Mutex<Option<WakeTimer>>>,
}

impl MonitoringService {
    pub async fn new(app_handle: AppHandle, api_base_url: String) -> Self {
        Self {
            database: Arc::new(
                Database::new(&app_handle)
                    .await
                    .expect("Failed to initialize database"),
            ),
            device_uuid: Arc::new(Mutex::new(None)),
            auth_token: Arc::new(Mutex::new(None)),
            is_running: Arc::new(Mutex::new(false)),
            wake_timer: Arc::new(Mutex::new(None)),
            app_handle,
            api_base_url,
        }
    }

    // Simple constructor for immediate initialization
    pub fn new_simple(app_handle: AppHandle, api_base_url: String) -> Self {
        Self {
            database: Arc::new(Database::new_simple(&app_handle)),
            device_uuid: Arc::new(Mutex::new(None)),
            auth_token: Arc::new(Mutex::new(None)),
            is_running: Arc::new(Mutex::new(false)),
            wake_timer: Arc::new(Mutex::new(None)),
            app_handle,
            api_base_url,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let mut is_running = self.is_running.lock().await;
        if *is_running {
            return Ok(());
        }
        *is_running = true;
        drop(is_running);

        info!("Starting monitoring service");

        // Initialize device UUID
        self.initialize_device_uuid().await?;

        // Start the monitoring loop
        let service = self.clone();
        tokio::spawn(async move {
            service.monitoring_loop().await;
        });

        // Start the sync loop for queued data
        let service = self.clone();
        tokio::spawn(async move {
            service.sync_loop().await;
        });

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut is_running = self.is_running.lock().await;
        *is_running = false;
        info!("Stopping monitoring service");
        Ok(())
    }

    pub async fn set_auth_token(&self, token: String) {
        let mut auth_token = self.auth_token.lock().await;
        *auth_token = Some(token);
    }

    async fn initialize_device_uuid(&self) -> Result<()> {
        let tables = vec!["system_info".to_string()];
        let query_result = self.execute_query(tables).await?;

        let uuid = query_result
            .get("system_info")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|obj| obj.get("uuid"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Couldn't find device uuid"))?;

        let mut device_uuid = self.device_uuid.lock().await;
        *device_uuid = Some(uuid.to_string());

        info!("Device UUID initialized: {}", uuid);
        Ok(())
    }

    async fn monitoring_loop(&self) {
        let mut interval = interval(TokioDuration::from_secs(15 * 60)); // 15 minutes

        loop {
            interval.tick().await;

            let is_running = *self.is_running.lock().await;
            if !is_running {
                break;
            }

            if let Err(e) = self.collect_and_queue_data().await {
                error!("Failed to collect and queue data: {}", e);
            }
        }
    }

    async fn sync_loop(&self) {
        let mut interval = interval(TokioDuration::from_secs(60)); // Check every minute

        loop {
            interval.tick().await;

            let is_running = *self.is_running.lock().await;
            if !is_running {
                break;
            }

            if let Err(e) = self.process_queued_data().await {
                error!("Failed to process queued data: {}", e);
            }
        }
    }

    async fn collect_and_queue_data(&self) -> Result<()> {
        let device_uuid = {
            let uuid = self.device_uuid.lock().await;
            uuid.clone()
                .ok_or_else(|| anyhow::anyhow!("Device UUID not initialized"))?
        };

        // Fetch configuration from API
        let config = self.fetch_configuration().await?;

        if let Some(config) = config {
            // Execute queries for all configured tables
            if let Some(data_array) = config.get("data").and_then(|v| v.as_array()) {
                let table_names: Vec<String> = data_array
                    .iter()
                    .filter_map(|item| item.get("id").and_then(|v| v.as_str()))
                    .map(|s| s.to_string())
                    .collect();

                let query_result = self.execute_query(table_names).await?;

                // Queue the data for later sync
                self.database
                    .queue_data(
                        &device_uuid,
                        serde_json::Value::Object(query_result.into_iter().collect()),
                    )
                    .await?;
                info!("Data collected and queued for device: {}", device_uuid);
            }
        }

        Ok(())
    }

    async fn process_queued_data(&self) -> Result<()> {
        let device_uuid = {
            let uuid = self.device_uuid.lock().await;
            uuid.clone()
                .ok_or_else(|| anyhow::anyhow!("Device UUID not initialized"))?
        };

        let pending_data = self.database.get_pending_data(10).await?; // Process up to 10 items at a time

        for queued_item in pending_data {
            match self.send_data_to_api(&queued_item.data, &device_uuid).await {
                Ok(_) => {
                    self.database.mark_data_sent(queued_item.id).await?;
                    self.database.update_sync_status(&device_uuid, true).await?;
                    info!("Successfully sent queued data for device: {}", device_uuid);
                }
                Err(e) => {
                    self.database.mark_data_failed(queued_item.id).await?;
                    self.database
                        .update_sync_status(&device_uuid, false)
                        .await?;
                    warn!(
                        "Failed to send queued data for device {}: {}",
                        device_uuid, e
                    );
                }
            }
        }

        Ok(())
    }

    async fn fetch_configuration(&self) -> Result<Option<serde_json::Value>> {
        let auth_token = {
            let token = self.auth_token.lock().await;
            token.clone()
        };

        let Some(token) = auth_token else {
            return Ok(None);
        };

        let client = reqwest::Client::new();
        let response = client
            .get(&format!("{}/klaayguard/config", self.api_base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if response.status().is_success() {
            let config: serde_json::Value = response.json().await?;
            Ok(Some(config))
        } else {
            warn!("Failed to fetch configuration: {}", response.status());
            Ok(None)
        }
    }

    async fn send_data_to_api(&self, data: &Value, device_uuid: &str) -> Result<()> {
        let auth_token = {
            let token = self.auth_token.lock().await;
            token.clone()
        };

        let Some(token) = auth_token else {
            return Err(anyhow::anyhow!("No auth token available"));
        };

        let payload = serde_json::json!({
            "device_uuid": device_uuid,
            "data": data,
            "timestamp": Utc::now()
        });

        let client = reqwest::Client::new();
        let response = client
            .post(&format!("{}/klaayguard/data", self.api_base_url))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "API request failed with status: {}",
                response.status()
            ));
        }

        Ok(())
    }

    async fn execute_query(&self, table_names: Vec<String>) -> Result<HashMap<String, Value>> {
        let mut all_results = HashMap::new();

        for table_name in table_names {
            let cmd = self
                .app_handle
                .shell()
                .sidecar("osqueryi")
                .unwrap()
                .args(&["--json", &format!("SELECT * FROM {}", table_name)]);

            let output = cmd
                .output()
                .await
                .map_err(|e| anyhow::anyhow!("Command execution failed: {}", e))?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "osquery command failed with exit code {:?}: {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            let stdout_str = String::from_utf8(output.stdout).map_err(|e| {
                anyhow::anyhow!("Invalid UTF-8 output for table {}: {}", table_name, e)
            })?;

            let parsed_result: Value = serde_json::from_str(&stdout_str).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to parse JSON for table {} (content: '{}'): {}",
                    table_name,
                    stdout_str.trim(),
                    e
                )
            })?;

            all_results.insert(table_name, parsed_result);
        }

        Ok(all_results)
    }

    pub async fn handle_system_wake(&self) -> Result<()> {
        info!("System wake detected, processing missed data");

        // Process any queued data immediately
        if let Err(e) = self.process_queued_data().await {
            error!("Failed to process queued data after wake: {}", e);
        }

        // Collect fresh data
        if let Err(e) = self.collect_and_queue_data().await {
            error!("Failed to collect fresh data after wake: {}", e);
        }

        Ok(())
    }

    pub async fn handle_system_sleep(&self) -> Result<()> {
        info!("System sleep detected, ensuring data is queued and wake timer is set");

        // Collect and queue any pending data before sleep
        if let Err(e) = self.collect_and_queue_data().await {
            error!("Failed to collect data before sleep: {}", e);
        }

        // Schedule wake timer for next monitoring interval
        let mut wake_timer = self.wake_timer.lock().await;
        *wake_timer = Some(WakeTimer::new());

        if let Some(timer) = wake_timer.as_mut() {
            if let Err(e) = timer.schedule_wake(15).await {
                // 15 minutes
                warn!("Failed to schedule wake timer: {}", e);
            }
        }

        Ok(())
    }

    pub async fn get_sync_info(&self) -> Result<serde_json::Value> {
        let device_uuid = {
            let uuid = self.device_uuid.lock().await;
            uuid.clone().unwrap_or_else(|| "unknown".to_string())
        };

        // Get sync status from database with proper error handling
        let sync_status = match self.database.get_sync_status(&device_uuid).await {
            Ok(status) => status,
            Err(e) => {
                error!("Failed to get sync status from database: {}", e);
                None
            }
        };

        // Calculate next osquery time (15 minutes from now)
        let next_osquery = Utc::now() + chrono::Duration::minutes(15);

        let info = serde_json::json!({
            "last_sync_time": sync_status.as_ref().map(|s| s.last_successful_sync.to_rfc3339()).unwrap_or_else(|| "Never".to_string()),
            "last_attempt_time": sync_status.as_ref().map(|s| s.last_attempt.to_rfc3339()).unwrap_or_else(|| "Never".to_string()),
            "consecutive_failures": sync_status.as_ref().map(|s| s.consecutive_failures).unwrap_or(0),
            "last_osquery_time": Utc::now().to_rfc3339(), // This would be tracked in a real implementation
            "next_osquery_time": next_osquery.to_rfc3339(),
            "monitoring_active": *self.is_running.lock().await,
            "device_uuid": device_uuid
        });

        Ok(info)
    }
}

impl Clone for MonitoringService {
    fn clone(&self) -> Self {
        Self {
            app_handle: self.app_handle.clone(),
            database: self.database.clone(),
            device_uuid: self.device_uuid.clone(),
            api_base_url: self.api_base_url.clone(),
            auth_token: self.auth_token.clone(),
            is_running: self.is_running.clone(),
            wake_timer: self.wake_timer.clone(),
        }
    }
}
