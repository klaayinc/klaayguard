use crate::updates::adapters::{MacSystem, RealPaths, ReqwestHttpClient};
use crate::updates::check::check;
use crate::updates::download::download_dmg;
use crate::updates::install::install_from_dmg;
use crate::updates::get_api_base_url;

pub fn bootstrap_on_startup(app_handle: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        log::info!("🚀 Starting automatic update check on app startup");
        let api_base = get_api_base_url();
        log::info!("🌐 Using API base URL: {}", api_base);
        let client = match ReqwestHttpClient::new() {
            Ok(c) => c,
            Err(e) => {
                log::error!("update_http_client_init_failed: {}", e);
                return;
            }
        };
        match check(&api_base, &client).await {
            Ok(Some(asset_id)) => {
                log::info!("🔄 Update available, starting download and install process...");
                let paths = RealPaths;
                let system = MacSystem;
                match download_dmg(&api_base, &asset_id, &paths, &client).await {
                    Ok(dmg) => {
                        if let Err(e) = install_from_dmg(&dmg, &system, &app_handle).await {
                            log::error!("💥 Auto-update install failed: {}", e);
                        }
                    }
                    Err(e) => log::error!("💥 Auto-update download failed: {}", e),
                }
            }
            Ok(None) => log::info!("✅ No updates available - app is up to date"),
            Err(e) => log::error!("💥 Auto-update check failed: {}", e),
        }
    });
}


