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

use std::fs;
use tauri::Manager;
use tauri_plugin_updater::UpdaterExt;

// Removed osquery, monitoring, and database-related commands.

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
        .plugin(tauri_plugin_os::init())
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
        .invoke_handler(tauri::generate_handler![])
        .build(tauri::generate_context!())
        .expect("error building tauri application");

    app.run(|_app_handle, _event| {});
}
