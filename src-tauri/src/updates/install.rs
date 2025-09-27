use crate::updates::adapters::SystemIntegration;
use crate::updates::types::UpdateError;
use std::path::Path;

pub async fn install_from_dmg(
    dmg_path: &Path,
    system: &impl SystemIntegration,
    app: &tauri::AppHandle,
) -> Result<(), UpdateError> {
    log::info!("🔄 Starting application replacement process...");
    let mount_point = system.mount_dmg(dmg_path)?;
    let res = system.replace_app_from_mount(&mount_point, app);
    let unmount_res = system.unmount(&mount_point);
    // Best-effort cleanup; do not fail if removal fails
    system.remove_file(dmg_path);
    if let Err(_e) = unmount_res {
        log::warn!("⚠️  DMG unmount failed");
    }
    res?;
    log::info!("🎉 Application updated successfully! Scheduling restart...");
    let app_ = app.clone();
    tauri::async_runtime::spawn(async move {
        // small delay to flush logs
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        app_.restart();
    });
    Ok(())
}
