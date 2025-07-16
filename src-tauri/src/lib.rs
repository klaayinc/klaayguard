mod osquery;
use osquery::install;
use serde_json::Value;
use std::collections::HashMap;
use tauri::Manager;
use tauri_plugin_updater::UpdaterExt;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
struct InstallationStatus {
    installed: bool,
    platform: String,
}

impl Default for InstallationStatus {
    fn default() -> Self {
        Self {
            installed: false,
            platform: std::env::consts::OS.to_string(),
        }
    }
}

// will return a different id every call if you don't have a hardware id until
// a build with https://github.com/osquery/osquery/pull/8616 is released
#[tauri::command]
async fn get_device_uuid() -> Result<String, String> {
    let tables = vec!("system_info".to_string());
    let query_result = execute_query(tables).await?;
    
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

#[tauri::command]
async fn execute_query(table_names: Vec<String>) -> Result<HashMap<String, Value>, String> {
    use serde_json::Value;
    use std::collections::HashMap;
    use std::process::{Command, Stdio};

    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    let mut all_results = HashMap::new();

    for table_name in table_names {
        // Configure the command
        let mut cmd = Command::new("osqueryi");

        cmd.args(&["--json", &format!("SELECT * FROM {}", table_name)])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Windows-specific: Hide console window
        #[cfg(windows)]
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW

        // Execute the command
        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run osquery: {}", e))?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "Osquery failed for table {}: {}",
                table_name,
                error_msg.trim()
            ));
        }

        // Handle output
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

#[tauri::command]
async fn check_osquery() -> Result<bool, String> {
    Ok(install::is_osquery_installed())
}

#[tauri::command]
async fn install_osquery() -> Result<(), String> {
    install::install_osquery().map_err(|e| e.to_string())
}

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

fn install_osquery_with_progress<R: tauri::Runtime>(_app: &tauri::AppHandle<R>) -> Result<(), String> {
    // For now, just call the regular install function
    // Progress events can be added later when we figure out the correct Tauri 2.0 API
    match install::install_osquery() {
        Ok(_) => {
            Ok(())
        },
        Err(e) => {
            Err(e.to_string())
        }
    }
}

#[tauri::command]
async fn auto_install_osquery<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> Result<(), String> {
    let result = install_osquery_with_progress(&app);
    if result.is_ok() {
        // Mark installation as complete (simplified approach)
        Ok(())
    } else {
        result
    }
}

#[tauri::command]
async fn is_first_launch() -> Result<bool, String> {
    // Simplified approach: just check if osquery is installed
    // If not installed, consider it first launch
    Ok(!install::is_osquery_installed())
}

#[tauri::command]
async fn mark_first_launch_complete() -> Result<(), String> {
    // Simplified approach: just return success
    // The actual installation status is checked by is_osquery_installed()
    Ok(())
}

#[tauri::command]
async fn get_installation_status() -> Result<InstallationStatus, String> {
    let status = InstallationStatus {
        installed: install::is_osquery_installed(),
        platform: std::env::consts::OS.to_string(),
    };
    Ok(status)
}

#[tauri::command]
async fn record_installation_error(_error_message: String) -> Result<(), String> {
    // Simplified approach: just return success
    // Error tracking can be implemented later if needed
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                update(handle).await.unwrap_or_else(|e| {
                    eprintln!("Failed to check for updates: {}", e);
                });
            });
            let window = app.get_webview_window("main").unwrap();
            let window_ = window.clone();
            window.on_window_event(move |event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    window_.hide().unwrap();
                    api.prevent_close();
                }
            });
            
            // Create tray menu
            let quit_i = tauri::menu::MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let show_i = tauri::menu::MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
            let hide_i = tauri::menu::MenuItem::with_id(app, "hide", "Hide", true, None::<&str>)?;
            let menu = tauri::menu::Menu::with_items(app, &[&quit_i, &show_i, &hide_i])?;
            
            // Create tray icon
            tauri::tray::TrayIconBuilder::new()
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "hide" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.hide();
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| match event {
                    tauri::tray::TrayIconEvent::Enter { .. } => {
                        tray.set_tooltip(Some("Klaay Guard".to_string())).unwrap();
                    }
                    tauri::tray::TrayIconEvent::Leave { .. } => {
                        tray.set_tooltip(Some("")).unwrap();
                    }
                    _ => {}
                })
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .build(app)?;
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            execute_query,
            install_osquery,
            check_osquery,
            get_device_uuid,
            is_first_launch,
            mark_first_launch_complete,
            auto_install_osquery,
            get_installation_status,
            record_installation_error,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
