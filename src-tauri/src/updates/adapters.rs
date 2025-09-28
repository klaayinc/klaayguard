use crate::updates::types::UpdateError;
use serde::de::DeserializeOwned;
use std::path::PathBuf;

#[async_trait::async_trait]
pub trait UpdateHttpClient {
    async fn get_json<T: DeserializeOwned + Send>(&self, url: &str) -> Result<T, UpdateError>;
    async fn get_bytes(&self, url: &str) -> Result<Vec<u8>, UpdateError>;
}

pub struct ReqwestHttpClient {
    client: reqwest::Client,
}

impl ReqwestHttpClient {
    pub fn new() -> Result<Self, UpdateError> {
        let client = reqwest::Client::builder()
            .user_agent("klaayguard/0.1")
            .build()
            .map_err(|e| UpdateError::Http(e.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl UpdateHttpClient for ReqwestHttpClient {
    async fn get_json<T: DeserializeOwned + Send>(&self, url: &str) -> Result<T, UpdateError> {
        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(UpdateError::Http(format!(
                "status {} from {}",
                resp.status(),
                url
            )));
        }
        match resp.json::<T>().await {
            Ok(v) => Ok(v),
            Err(e) => Err(UpdateError::InvalidResponse(e.to_string())),
        }
    }

    async fn get_bytes(&self, url: &str) -> Result<Vec<u8>, UpdateError> {
        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(UpdateError::Http(format!(
                "status {} from {}",
                resp.status(),
                url
            )));
        }
        let b = resp.bytes().await?;
        Ok(b.to_vec())
    }
}

pub trait AppPaths {
    fn downloads_dir(&self) -> Result<PathBuf, UpdateError>;
}

pub struct RealPaths;

impl AppPaths for RealPaths {
    fn downloads_dir(&self) -> Result<PathBuf, UpdateError> {
        dirs::download_dir().ok_or_else(|| UpdateError::Io("downloads_dir_not_found".into()))
    }
}

pub trait SystemIntegration {
    fn mount_dmg(&self, dmg_path: &std::path::Path) -> Result<String, UpdateError>;
    fn replace_app_from_mount(
        &self,
        mount_point: &str,
        app: &tauri::AppHandle,
    ) -> Result<(), UpdateError>;
    fn unmount(&self, mount_point: &str) -> Result<(), UpdateError>;
    fn remove_file(&self, p: &std::path::Path);
}

pub struct MacSystem;

impl SystemIntegration for MacSystem {
    fn mount_dmg(&self, dmg_path: &std::path::Path) -> Result<String, UpdateError> {
        let out = std::process::Command::new("hdiutil")
            .args(["attach", dmg_path.to_str().unwrap()])
            .output()
            .map_err(|e| UpdateError::System(e.to_string()))?;
        if !out.status.success() {
            return Err(UpdateError::System(format!(
                "mount_failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let s = String::from_utf8_lossy(&out.stdout);
        let mp = s
            .lines()
            .find(|l| l.contains("/Volumes/"))
            .and_then(|l| l.split('\t').last())
            .ok_or_else(|| UpdateError::System("mount_point_not_found".into()))?;
        Ok(mp.to_string())
    }

    fn replace_app_from_mount(
        &self,
        mount_point: &str,
        _app: &tauri::AppHandle,
    ) -> Result<(), UpdateError> {
        let source_app = std::path::Path::new(mount_point).join("KlaayGuard.app");
        let target_app = std::path::Path::new("/Applications/KlaayGuard.app");
        if !source_app.exists() {
            return Err(UpdateError::System(format!(
                "source_app_missing:{:?}",
                source_app
            )));
        }
        if target_app.exists() {
            std::fs::remove_dir_all(&target_app)
                .map_err(|e| UpdateError::System(format!("remove_old: {}", e)))?;
        }
        let status = std::process::Command::new("cp")
            .args([
                "-R",
                source_app.to_str().unwrap(),
                target_app.to_str().unwrap(),
            ])
            .status()
            .map_err(|e| UpdateError::System(format!("copy_error: {}", e)))?;
        if !status.success() {
            return Err(UpdateError::System("copy_failed".into()));
        }
        Ok(())
    }

    fn unmount(&self, mount_point: &str) -> Result<(), UpdateError> {
        let status = std::process::Command::new("hdiutil")
            .args(["detach", mount_point])
            .status()
            .map_err(|e| UpdateError::System(e.to_string()))?;
        if !status.success() {
            return Err(UpdateError::System("detach_failed".into()));
        }
        Ok(())
    }

    fn remove_file(&self, p: &std::path::Path) {
        let _ = std::fs::remove_file(p);
    }
}
