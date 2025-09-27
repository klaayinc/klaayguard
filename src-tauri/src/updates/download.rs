use crate::updates::adapters::{AppPaths, UpdateHttpClient};
use crate::updates::types::UpdateError;
use std::path::PathBuf;

pub async fn download_dmg(
    api_base: &str,
    asset_id: &str,
    paths: &impl AppPaths,
    client: &impl UpdateHttpClient,
) -> Result<PathBuf, UpdateError> {
    let url = format!("{}/klaayguard/download/{}", api_base, asset_id);
    log::info!("🌐 Download URL: {}", url);
    let bytes = client.get_bytes_blocking(&url)?;
    log::info!("📊 Downloaded {} bytes", bytes.len());

    let dmg_path = paths.downloads_dir()?.join("KlaayGuard-update.dmg");
    let mut f = std::fs::File::create(&dmg_path)?;
    std::io::Write::write_all(&mut f, &bytes)?;
    log::info!("✅ Update downloaded successfully to: {:?}", dmg_path);
    Ok(dmg_path)
}


