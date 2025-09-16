//! KlaayGuard - Security Monitoring Application
//!
//! This application provides continuous security monitoring on edge devices.
//! Key security features:
//! - Runs as background service (hidden from dock on macOS)
//! - No quit option in system tray to prevent easy termination
//! - Automatic updates for security patches
//! - System tray interface for minimal user interaction
//!
//! Security Design:
//! - App cannot be easily terminated by end users
//! - Background operation ensures continuous monitoring
//! - System tray provides controlled access to app functionality

use chrono::Utc;
use serde_json::Value;
use std::{collections::HashMap, fs, sync::Arc};
use tauri::{Manager, State};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_updater::UpdaterExt;

mod database;
mod monitoring;
mod wake_timer;

use monitoring::MonitoringService;

/// Retrieves the device UUID for security monitoring identification.
///
/// This function queries the system_info table using osquery to get a unique
/// device identifier. The UUID is used for tracking and reporting security events
/// to the central monitoring system.
///
/// Note: Will return a different ID every call if you don't have a hardware ID until
/// a build with https://github.com/osquery/osquery/pull/8616 is released
#[tauri::command]
async fn get_device_uuid(app: tauri::AppHandle) -> Result<String, String> {
    let tables = vec!["system_info".to_string()];
    let query_result = execute_query(app, tables).await?;

    // Navigate the nested structure:
    // 1. Get "system_info" array
    // 2. Get first item in array
    // 3. Get "uuid" from that item
    let uuid = query_result
        .get("system_info")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|obj| obj.get("uuid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Couldn't find device uuid".to_string())?;

    Ok(uuid.to_string())
}

/// Executes osquery commands to gather system information for security monitoring.
///
/// This function runs osquery queries against specified tables and returns the results
/// as JSON. It's used by the security monitoring system to collect data about the
/// current state of the device.
///
/// # Arguments
/// * `app` - Tauri app handle for accessing shell functionality
/// * `table_names` - Vector of osquery table names to query
///
/// # Returns
/// * `Ok(HashMap<String, Value>)` - Query results keyed by table name
/// * `Err(String)` - Error message if query execution fails
#[tauri::command]
async fn set_auth_token(
    monitoring_service: State<'_, Arc<MonitoringService>>,
    token: String,
) -> Result<(), String> {
    monitoring_service.set_auth_token(token).await;
    Ok(())
}

#[tauri::command]
async fn start_monitoring(
    monitoring_service: State<'_, Arc<MonitoringService>>,
) -> Result<(), String> {
    monitoring_service
        .start()
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn stop_monitoring(
    monitoring_service: State<'_, Arc<MonitoringService>>,
) -> Result<(), String> {
    monitoring_service.stop().await.map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn get_monitoring_status(
    monitoring_service: State<'_, Arc<MonitoringService>>,
) -> Result<String, String> {
    let is_running = *monitoring_service.is_running.lock().await;
    Ok(if is_running {
        "Monitoring service is running".to_string()
    } else {
        "Monitoring service is stopped".to_string()
    })
}

#[tauri::command]
async fn get_sync_info(
    monitoring_service: State<'_, Arc<MonitoringService>>,
) -> Result<serde_json::Value, String> {
    // Get sync information from the monitoring service
    let info = monitoring_service
        .get_sync_info()
        .await
        .map_err(|e| e.to_string())?;
    Ok(info)
}

#[tauri::command]
async fn get_collection_status(
    monitoring_service: State<'_, Arc<MonitoringService>>,
) -> Result<serde_json::Value, String> {
    // Get detailed collection status from the monitoring service
    let is_running = *monitoring_service.is_running.lock().await;
    let device_uuid = {
        let uuid = monitoring_service.device_uuid.lock().await;
        uuid.clone().unwrap_or_else(|| "unknown".to_string())
    };

    let status = serde_json::json!({
        "is_running": is_running,
        "device_uuid": device_uuid,
        "last_collection": Utc::now().to_rfc3339(), // This would be tracked in a real implementation
        "next_collection": (Utc::now() + chrono::Duration::minutes(15)).to_rfc3339(),
        "collection_interval_minutes": 15,
        "status": if is_running { "active" } else { "inactive" }
    });

    Ok(status)
}

#[tauri::command]
async fn execute_query(
    app: tauri::AppHandle,
    table_names: Vec<String>,
) -> Result<HashMap<String, Value>, String> {
    use serde_json::Value;
    use std::collections::HashMap;

    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    let mut all_results = HashMap::new();

    for table_name in table_names {
        // Configure the command
        let cmd = app
            .shell()
            .sidecar("osqueryi")
            .unwrap()
            .args(["--json", &format!("SELECT * FROM {}", table_name)]);

        let output = cmd.output().await.map_err(|e| e.to_string())?;

        if !output.status.success() {
            return Err(format!(
                "exit code {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let stdout_str = String::from_utf8(output.stdout)
            .map_err(|e| format!("Invalid UTF-8 output for table {}: {}", table_name, e))?;

        let parsed_result: Value = serde_json::from_str(&stdout_str).map_err(|e| {
            format!(
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

/// Installs a launch agent for automatic startup on macOS.
///
/// This function creates a launchd plist file in the user's LaunchAgents directory
/// and loads it to ensure the app starts automatically on login. This is a mandatory
/// security feature that cannot be disabled by users.
#[tauri::command]
async fn install_launch_agent() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let home_dir = dirs::home_dir().ok_or("Could not find home directory")?;
        let launch_agents_dir = home_dir.join("Library/LaunchAgents");
        let plist_path = launch_agents_dir.join("KlaayGuard.plist");

        // Check if launch agent is already loaded
        let output = std::process::Command::new("launchctl")
            .args(&["list", "KlaayGuard"])
            .output()
            .map_err(|e| format!("Failed to check launch agent status: {}", e))?;

        if output.status.success() {
            // Launch agent is already loaded, no need to install again
            return Ok("Launch agent already installed and running".to_string());
        }

        // Create LaunchAgents directory if it doesn't exist
        fs::create_dir_all(&launch_agents_dir)
            .map_err(|e| format!("Failed to create LaunchAgents directory: {}", e))?;

        // Get the current executable path
        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get current executable path: {}", e))?;

        // Read the plist template and replace the executable path
        let plist_content = include_str!("../resources/com.klaay.app.plist");
        let plist_content = plist_content.replace(
            "/Applications/KlaayGuard.app/Contents/MacOS/KlaayGuard",
            &current_exe.to_string_lossy(),
        );

        // Write the plist file
        fs::write(&plist_path, plist_content)
            .map_err(|e| format!("Failed to write plist file: {}", e))?;

        // Load the launch agent
        let output = std::process::Command::new("launchctl")
            .args(&["load", plist_path.to_str().unwrap()])
            .output()
            .map_err(|e| format!("Failed to load launch agent: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Failed to load launch agent: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok("Launch agent installed successfully".to_string())
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err("Launch agent installation is only supported on macOS".to_string())
    }
}

/// Handles automatic updates for security patches and bug fixes.
///
/// This function checks for available updates and automatically downloads and installs them.
/// The app will restart after a successful update to ensure the latest security patches
/// are active.
async fn update(app: tauri::AppHandle) -> tauri_plugin_updater::Result<()> {
    if let Some(update) = app.updater()?.check().await? {
        let mut downloaded = 0;

        // alternatively we could also call update.download() and update.install() separately
        update
            .download_and_install(
                |chunk_length, content_length| {
                    downloaded += chunk_length;
                    println!("downloaded {downloaded} from {content_length:?}");
                },
                || {
                    println!("download finished");
                },
            )
            .await?;

        println!("update installed");
        app.restart();
    }

    Ok(())
}

/// Main entry point for the KlaayGuard security monitoring application.
///
/// This function initializes the Tauri application with security-focused configuration:
/// - Hides the app from the dock on macOS for background operation
/// - Creates a system tray with limited options (no quit functionality)
/// - Sets up automatic updates for security patches
/// - Configures window behavior to prevent accidental closure
///
/// Security Features:
/// - Background operation prevents easy termination
/// - System tray provides controlled access
/// - Automatic updates ensure latest security patches
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let handle = app.handle().clone();
            let handle2 = app.handle().clone();

            // Hide the app from the dock on macOS for security monitoring
            #[cfg(target_os = "macos")]
            {
                app.set_activation_policy(tauri::ActivationPolicy::Accessory);
                log::info!("KlaayGuard configured as background service - hidden from dock");
            }

            // Check if we're already running as a regular process to prevent duplicates
            #[cfg(target_os = "macos")]
            {
                let output = std::process::Command::new("pgrep")
                    .args(&["-f", "KlaayGuard"])
                    .output();

                if let Ok(output) = output {
                    if output.status.success() {
                        let pid_count = String::from_utf8_lossy(&output.stdout)
                            .lines()
                            .filter(|line| !line.trim().is_empty())
                            .count();

                        // If there's already a KlaayGuard process running, exit this instance
                        if pid_count > 0 {
                            std::process::exit(0);
                        }
                    }
                }
            }

            // Initialize monitoring service immediately
            let api_base_url = std::env::var("VITE_API_BASE_URL")
                .unwrap_or_else(|_| "https://api.klaay.dev".to_string());

            // Create monitoring service immediately
            let monitoring_service =
                Arc::new(MonitoringService::new_simple(handle.clone(), api_base_url));
            app.manage(monitoring_service.clone());

            // Start monitoring service in background
            tauri::async_runtime::spawn(async move {
                if let Err(e) = monitoring_service.start().await {
                    eprintln!("Failed to start monitoring service: {}", e);
                }
            });

            tauri::async_runtime::spawn(async move {
                update(handle2).await.unwrap_or_else(|e| {
                    eprintln!("Failed to check for updates: {}", e);
                });
            });

            // Automatically install launch agent on macOS
            #[cfg(target_os = "macos")]
            {
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = install_launch_agent().await {
                        eprintln!("Failed to install launch agent: {}", e);
                    }
                });
            }
            let window = app.get_webview_window("main").unwrap();
            let window_ = window.clone();

            // Show the window on startup to display the login screen
            window.show().unwrap();
            window.set_focus().unwrap();
            log::info!("KlaayGuard started - login screen displayed");

            window.on_window_event(move |event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    window_.hide().unwrap();
                    api.prevent_close();
                }
            });

            // Create tray menu with security-focused options (no quit option)
            let show_i = tauri::menu::MenuItem::with_id(app, "show", "Show", true, None::<&str>)
                .map_err(|e| {
                    log::error!("Failed to create 'Show' menu item: {}", e);
                    e
                })?;
            let hide_i = tauri::menu::MenuItem::with_id(app, "hide", "Hide", true, None::<&str>)
                .map_err(|e| {
                    log::error!("Failed to create 'Hide' menu item: {}", e);
                    e
                })?;
            let menu = tauri::menu::Menu::with_items(app, &[&show_i, &hide_i]).map_err(|e| {
                log::error!("Failed to create system tray menu: {}", e);
                e
            })?;

            // Create tray icon with security monitoring tooltip
            tauri::tray::TrayIconBuilder::new()
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        log::info!("Show window requested from system tray");
                        if let Some(window) = app.get_webview_window("main") {
                            if let Err(e) = window.show() {
                                log::error!("Failed to show window: {}", e);
                            } else {
                                log::info!("Window shown successfully");
                            }
                            if let Err(e) = window.set_focus() {
                                log::error!("Failed to focus window: {}", e);
                            }
                        }
                    }
                    "hide" => {
                        log::info!("Hide window requested from system tray");
                        if let Some(window) = app.get_webview_window("main") {
                            if let Err(e) = window.hide() {
                                log::error!("Failed to hide window: {}", e);
                            } else {
                                log::info!("Window hidden successfully");
                            }
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| match event {
                    tauri::tray::TrayIconEvent::Enter { .. } => {
                        if let Err(e) =
                            tray.set_tooltip(Some("KlaayGuard - Security Monitoring".to_string()))
                        {
                            log::error!("Failed to set tooltip: {}", e);
                        }
                    }
                    tauri::tray::TrayIconEvent::Leave { .. } => {
                        if let Err(e) = tray.set_tooltip(Some("".to_string())) {
                            log::error!("Failed to clear tooltip: {}", e);
                        }
                    }
                    _ => {}
                })
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .build(app)
                .map_err(|e| {
                    log::error!("Failed to create system tray icon: {}", e);
                    e
                })?;
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            execute_query,
            get_device_uuid,
            set_auth_token,
            start_monitoring,
            stop_monitoring,
            get_monitoring_status,
            get_sync_info,
            get_collection_status
        ])
        .build(tauri::generate_context!())
        .expect("error building tauri application");

    app.run(|_app_handle, _event| {});
}
