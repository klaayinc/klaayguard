use crate::updates::adapters::{MacSystem, RealPaths, ReqwestHttpClient};
use crate::updates::check::check;
use crate::updates::download::download_dmg;
use crate::updates::install::install_from_dmg;
use crate::updates::types::UpdateError;
use crate::updates::get_api_base_url;

fn to_string_err(e: UpdateError) -> String { e.to_string() }

#[tauri::command]
pub async fn check_for_updates_command() -> Result<Option<String>, String> {
    let api_base = get_api_base_url();
    let client = ReqwestHttpClient::new().map_err(to_string_err)?;
    check(&api_base, &client).await.map_err(to_string_err)
}

#[tauri::command]
pub async fn download_and_install_update(
    asset_id: String,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let api_base = get_api_base_url();
    let client = ReqwestHttpClient::new().map_err(to_string_err)?;
    let paths = RealPaths;
    let system = MacSystem;
    let dmg = download_dmg(&api_base, &asset_id, &paths, &client)
        .await
        .map_err(to_string_err)?;
    install_from_dmg(&dmg, &system, &app).await.map_err(to_string_err)
}


