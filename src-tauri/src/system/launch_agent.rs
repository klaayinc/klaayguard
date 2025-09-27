// no module-level imports needed

#[tauri::command]
pub async fn install_launch_agent() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        use std::fs;
        let home_dir = dirs::home_dir().ok_or("Could not find home directory")?;
        let launch_agents_dir = home_dir.join("Library/LaunchAgents");
        let label = "com.klaay.klaayguard";
        let plist_path = launch_agents_dir.join(format!("{}.plist", label));
        let uid = nix::unistd::getuid().as_raw();
        let domain = format!("gui/{}", uid);

        fs::create_dir_all(&launch_agents_dir)
            .map_err(|e| format!("Failed to create LaunchAgents directory: {}", e))?;

        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get current executable path: {}", e))?;
        let app_bundle_path = std::path::Path::new("/Applications/KlaayGuard.app");
        let installed_exists = app_bundle_path.exists();

        let app_path: String = if installed_exists {
            "/Applications/KlaayGuard.app".to_string()
        } else {
            current_exe
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "/Applications/KlaayGuard.app".to_string())
        };
        let api_base_for_plist: String = std::env::var("VITE_API_BASE_URL")
            .ok()
            .or_else(|| option_env!("APP_DEFAULT_API_BASE_URL").map(|s| s.to_string()))
            .unwrap_or_else(|| "https://api.klaay.com".to_string());

        let log_dir = home_dir.join("Library/Logs/KlaayGuard");
        fs::create_dir_all(&log_dir)
            .map_err(|e| format!("Failed to create log directory: {}", e))?;

        let plist_content = include_str!("../../resources/com.klaay.klaayguard.plist")
            .replace("__LABEL__", label)
            .replace("__OPEN_PATH__", "/usr/bin/open")
            .replace("__APP_PATH__", &app_path)
            .replace("__VITE_API_BASE_URL__", &api_base_for_plist)
            .replace("__LOG_DIR__", &log_dir.to_string_lossy());

        let mut needs_reload = true;
        if let Ok(existing) = fs::read_to_string(&plist_path) {
            if existing == plist_content {
                let output = std::process::Command::new("launchctl")
                    .args(&["print", &format!("{}/{}", domain, label)])
                    .output()
                    .map_err(|e| format!("Failed to check launch agent status: {}", e))?;
                if output.status.success() {
                    return Ok("Launch agent already installed and running".to_string());
                }
                needs_reload = false;
            }
        }

        fs::write(&plist_path, plist_content)
            .map_err(|e| format!("Failed to write plist file: {}", e))?;

        if installed_exists {
            if needs_reload {
                let _ = std::process::Command::new("launchctl")
                    .args(&["bootout", &format!("{}/{}", domain, label)])
                    .output();
            }

            let output = std::process::Command::new("launchctl")
                .args(&["bootstrap", &domain, plist_path.to_str().unwrap()])
                .output()
                .map_err(|e| format!("Failed to bootstrap launch agent: {}", e))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("EEXIST") && !stderr.contains("already loaded") {
                    return Err(format!("Failed to bootstrap launch agent: {}", stderr));
                }
            }

            let _ = std::process::Command::new("launchctl")
                .args(&["enable", &format!("{}/{}", domain, label)])
                .output();
            let _ = std::process::Command::new("launchctl")
                .args(&["kickstart", "-k", &format!("{}/{}", domain, label)])
                .output();
        }

        Ok("Launch agent installed successfully".to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("Launch agent installation is only supported on macOS".to_string())
    }
}

#[tauri::command]
pub async fn uninstall_launch_agent() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        use std::fs;
        let home_dir = dirs::home_dir().ok_or("Could not find home directory")?;
        let launch_agents_dir = home_dir.join("Library/LaunchAgents");
        let label = "com.klaay.klaayguard";
        let plist_path = launch_agents_dir.join(format!("{}.plist", label));
        let uid = nix::unistd::getuid().as_raw();
        let domain = format!("gui/{}", uid);

        let _ = std::process::Command::new("launchctl")
            .args(&["bootout", &format!("{}/{}", domain, label)])
            .output();

        if plist_path.exists() {
            if let Err(e) = fs::remove_file(&plist_path) {
                return Err(format!("Failed to remove launch agent plist: {}", e));
            }
        }

        Ok("LaunchAgent uninstalled".to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("Launch agent uninstallation is only supported on macOS".to_string())
    }
}


