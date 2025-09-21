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

use serde_json::{json, Value};
use std::{collections::HashMap, fs, sync::Arc, time::Duration};
use tauri::{Emitter, Manager};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_updater::UpdaterExt;
use tokio::sync::RwLock;

// Re-introduced minimal osquery commands used by the UI.

/// Shared application state for background operations
pub struct AppState {
    pub auth_token: RwLock<Option<String>>,
    pub api_base_url: RwLock<String>,
    pub last_run_at: RwLock<Option<std::time::Instant>>,
    pub last_attempt_at: RwLock<Option<std::time::Instant>>,
}

#[tauri::command]
async fn set_api_base_url(
    state: tauri::State<'_, Arc<AppState>>,
    base: String,
) -> Result<(), String> {
    *state.api_base_url.write().await = base;
    Ok(())
}

#[tauri::command]
async fn save_auth_token(
    state: tauri::State<'_, Arc<AppState>>,
    token: String,
) -> Result<(), String> {
    *state.auth_token.write().await = Some(token);
    Ok(())
}

#[tauri::command]
async fn clear_auth_token(state: tauri::State<'_, Arc<AppState>>) -> Result<(), String> {
    *state.auth_token.write().await = None;
    Ok(())
}

/// Returns seconds until next scheduled run (900s interval).
/// -1 indicates not signed in (no token yet). 0 means due now or overdue.
#[tauri::command]
async fn get_next_run_in_seconds(state: tauri::State<'_, Arc<AppState>>) -> Result<i64, String> {
    if state.auth_token.read().await.is_none() {
        return Ok(-1);
    }
    // Use last attempt time so countdown advances even if last run failed
    let last = *state.last_attempt_at.read().await;
    let interval = std::time::Duration::from_secs(15 * 60);
    if let Some(last) = last {
        let elapsed = last.elapsed();
        if elapsed >= interval {
            Ok(0)
        } else {
            Ok((interval - elapsed).as_secs() as i64)
        }
    } else {
        // first run should happen immediately after login/token
        Ok(0)
    }
}

#[tauri::command]
async fn get_device_uuid(app: tauri::AppHandle) -> Result<String, String> {
    let tables = vec!["system_info".to_string()];
    let query_result = execute_query(app, tables).await?;

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
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    let mut all_results = HashMap::new();

    for table_name in table_names {
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

async fn invalidate_auth(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<(), String> {
    *state.auth_token.write().await = None;
    let _ = app.emit("auth:invalidated", ());
    Ok(())
}

async fn run_cycle(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    client: &reqwest::Client,
) -> Result<(), String> {
    let token = match state.auth_token.read().await.clone() {
        Some(t) => t,
        None => return Ok(()),
    };

    let base = state.api_base_url.read().await.clone();

    // Mark an attempt start and notify UI listeners
    *state.last_attempt_at.write().await = Some(std::time::Instant::now());
    let _ = app.emit("collection:attempt", ());

    // 1) GET /klaayguard/config
    let cfg_resp = client
        .get(format!("{}/klaayguard/config", base))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if cfg_resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        invalidate_auth(app, state).await?;
        let _ = app.emit(
            "collection:error",
            json!({ "stage": "config", "status": 401 }),
        );
        return Ok(());
    }
    if !cfg_resp.status().is_success() {
        let _ = app.emit(
            "collection:error",
            json!({
                "stage": "config",
                "status": cfg_resp.status().as_u16()
            }),
        );
        return Ok(());
    }

    let cfg_json: Value = cfg_resp.json().await.map_err(|e| e.to_string())?;
    let tables: Vec<String> = cfg_json
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    item.get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    if tables.is_empty() {
        let _ = app.emit(
            "collection:error",
            json!({ "stage": "config", "reason": "no_tables" }),
        );
        return Ok(());
    }

    // 2) osquery
    let results = execute_query(app.clone(), tables).await?;

    // 3) device uuid
    let device_uuid = get_device_uuid(app.clone())
        .await
        .unwrap_or_else(|_| "unknown".to_string());

    // 4) format payload like UI
    let mut formatted: Vec<Value> = Vec::new();
    for (table_name, entries) in results {
        if let Some(arr) = entries.as_array() {
            for entry in arr {
                formatted.push(json!({
                    "type": table_name,
                    "attributes": entry
                }));
            }
        }
    }

    let body = json!({
        "device_uuid": device_uuid,
        "data": formatted
    });

    // POST /klaayguard/data
    let post_resp = client
        .post(format!("{}/klaayguard/data", base))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if post_resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        invalidate_auth(app, state).await?;
        let _ = app.emit(
            "collection:error",
            json!({ "stage": "post", "status": 401 }),
        );
        return Ok(());
    }

    if post_resp.status().is_success() {
        *state.last_run_at.write().await = Some(std::time::Instant::now());
        let _ = app.emit("collection:success", ());
    } else {
        let _ = app.emit(
            "collection:error",
            json!({
                "stage": "post",
                "status": post_resp.status().as_u16()
            }),
        );
    }

    Ok(())
}

fn spawn_background_loop(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let client = reqwest::Client::builder()
            .user_agent("klaayguard/0.1")
            .build()
            .expect("reqwest client");

        // wait for token once
        loop {
            if state.auth_token.read().await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }

        // run immediately
        if let Err(e) = run_cycle(&app, &state, &client).await {
            eprintln!("initial cycle error: {}", e);
        }

        let mut interval = tokio::time::interval(Duration::from_secs(15 * 60));
        loop {
            interval.tick().await;
            if let Err(e) = run_cycle(&app, &state, &client).await {
                eprintln!("cycle error: {}", e);
            }
        }
    });
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
        let label = "com.klaay.klaayguard";
        let plist_path = launch_agents_dir.join(format!("{}.plist", label));

        // Determine user launchctl domain
        let uid = nix::unistd::getuid().as_raw();
        let domain = format!("gui/{}", uid);

        // Check if launch agent is already loaded using modern launchctl
        let output = std::process::Command::new("launchctl")
            .args(&["print", &format!("{}/{}", domain, label)])
            .output()
            .map_err(|e| format!("Failed to check launch agent status: {}", e))?;

        if output.status.success() {
            return Ok("Launch agent already installed and running".to_string());
        }

        // Create LaunchAgents directory if it doesn't exist
        fs::create_dir_all(&launch_agents_dir)
            .map_err(|e| format!("Failed to create LaunchAgents directory: {}", e))?;

        // Clean up legacy label/file if present
        let legacy_plist = launch_agents_dir.join("KlaayGuard.plist");
        if legacy_plist.exists() {
            let _ = std::process::Command::new("launchctl")
                .args(&["bootout", &format!("{}/{}", domain, "KlaayGuard")])
                .output();
            let _ = fs::remove_file(&legacy_plist);
        }

        // Get the current executable path (used as fallback when the app is not installed in /Applications)
        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get current executable path: {}", e))?;

        // Determine preferred executable path: prefer installed app in /Applications
        let installed_path =
            std::path::Path::new("/Applications/KlaayGuard.app/Contents/MacOS/KlaayGuard");
        let preferred_exec = if installed_path.exists() {
            installed_path.to_path_buf()
        } else {
            current_exe.clone()
        };

        // Read the plist template and replace placeholders
        let plist_content = include_str!("../resources/com.klaay.klaayguard.plist");
        let plist_content = plist_content
            .replace("__LABEL__", label)
            .replace("__EXECUTABLE__", &preferred_exec.to_string_lossy());

        // Write the plist file
        fs::write(&plist_path, plist_content)
            .map_err(|e| format!("Failed to write plist file: {}", e))?;

        // Bootstrap (load) the launch agent using modern launchctl domain
        let output = std::process::Command::new("launchctl")
            .args(&["bootstrap", &domain, plist_path.to_str().unwrap()])
            .output()
            .map_err(|e| format!("Failed to bootstrap launch agent: {}", e))?;

        // If already bootstrapped, continue; else require success
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Error code 9 or message indicating already bootstrapped can be ignored
            if !stderr.contains("EEXIST") && !stderr.contains("already loaded") {
                return Err(format!("Failed to bootstrap launch agent: {}", stderr));
            }
        }

        // Enable the service
        let _ = std::process::Command::new("launchctl")
            .args(&["enable", &format!("{}/{}", domain, label)])
            .output();

        // Kickstart the service immediately
        let _ = std::process::Command::new("launchctl")
            .args(&["kickstart", "-k", &format!("{}/{}", domain, label)])
            .output();

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
    // Prefer runtime env; fall back to compile-time embedded default; then hard-coded prod
    let api_base = std::env::var("VITE_API_BASE_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_API_BASE_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://api.klaay.com".to_string());
    let state = Arc::new(AppState {
        auth_token: RwLock::new(None),
        api_base_url: RwLock::new(api_base),
        last_run_at: RwLock::new(None),
        last_attempt_at: RwLock::new(None),
    });

    let app = tauri::Builder::default()
        .manage(state.clone())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
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
                let current_pid = std::process::id();
                let output = std::process::Command::new("pgrep")
                    .args(&["-f", "KlaayGuard"])
                    .output();

                if let Ok(output) = output {
                    if output.status.success() {
                        let other_count = String::from_utf8_lossy(&output.stdout)
                            .lines()
                            .filter_map(|line| line.trim().parse::<u32>().ok())
                            .filter(|pid| *pid != current_pid)
                            .count();

                        // If another KlaayGuard process is running (excluding this one), exit this instance
                        if other_count > 0 {
                            std::process::exit(0);
                        }
                    }
                }
            }

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
            // Spawn background monitoring loop
            let state_for_loop = app.state::<Arc<AppState>>().inner().clone();
            let app_handle = app.handle().clone();
            spawn_background_loop(app_handle, state_for_loop);

            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            execute_query,
            get_device_uuid,
            save_auth_token,
            clear_auth_token,
            set_api_base_url,
            get_next_run_in_seconds
        ])
        .build(tauri::generate_context!())
        .expect("error building tauri application");

    app.run(|_app_handle, _event| {});
}
