use serde_json::Value;
use std::collections::HashMap;
use tauri::Manager;
use tauri_plugin_shell::ShellExt;
use tauri_plugin_updater::UpdaterExt;

// will return a different id every call if you don't have a hardware id until
// a build with https://github.com/osquery/osquery/pull/8616 is released
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
            .args(&["--json", &format!("SELECT * FROM {}", table_name)]);

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let handle = app.handle().clone();

            tauri::async_runtime::spawn(async move {
                update(handle).await.unwrap_or_else(|e| {
                    eprintln!("Failed to check for updates: {}", e);
                });
            });

            // Autostart is handled automatically by the plugin configuration
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
        .invoke_handler(tauri::generate_handler![execute_query, get_device_uuid])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
