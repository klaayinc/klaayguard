use crate::updates::types::UpdateError;
use serde::de::DeserializeOwned;
use std::path::PathBuf;

pub trait UpdateHttpClient {
    fn get_json_blocking<T: DeserializeOwned>(&self, url: &str) -> Result<T, UpdateError>;
    fn get_bytes_blocking(&self, url: &str) -> Result<Vec<u8>, UpdateError>;
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

impl UpdateHttpClient for ReqwestHttpClient {
    fn get_json_blocking<T: DeserializeOwned>(&self, url: &str) -> Result<T, UpdateError> {
        let rt = tokio::runtime::Handle::try_current()
            .ok()
            .map(|h| h.clone());
        if let Some(handle) = rt {
            let fut = async {
                let resp = self.client.get(url).send().await?;
                if !resp.status().is_success() {
                    return Err(UpdateError::Http(format!(
                        "status {} from {}",
                        resp.status(), url
                    )));
                }
                let v = resp.json::<T>().await?;
                Ok::<T, UpdateError>(v)
            };
            handle.block_on(fut)
        } else {
            // Create a local runtime if we're not on Tokio
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| UpdateError::Http(e.to_string()))?;
            rt.block_on(async {
                let resp = self.client.get(url).send().await?;
                if !resp.status().is_success() {
                    return Err(UpdateError::Http(format!(
                        "status {} from {}",
                        resp.status(), url
                    )));
                }
                let v = resp.json::<T>().await?;
                Ok::<T, UpdateError>(v)
            })
        }
    }

    fn get_bytes_blocking(&self, url: &str) -> Result<Vec<u8>, UpdateError> {
        let rt = tokio::runtime::Handle::try_current()
            .ok()
            .map(|h| h.clone());
        if let Some(handle) = rt {
            let fut = async {
                let resp = self.client.get(url).send().await?;
                if !resp.status().is_success() {
                    return Err(UpdateError::Http(format!(
                        "status {} from {}",
                        resp.status(), url
                    )));
                }
                let b = resp.bytes().await?;
                Ok::<Vec<u8>, UpdateError>(b.to_vec())
            };
            handle.block_on(fut)
        } else {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| UpdateError::Http(e.to_string()))?;
            rt.block_on(async {
                let resp = self.client.get(url).send().await?;
                if !resp.status().is_success() {
                    return Err(UpdateError::Http(format!(
                        "status {} from {}",
                        resp.status(), url
                    )));
                }
                let b = resp.bytes().await?;
                Ok::<Vec<u8>, UpdateError>(b.to_vec())
            })
        }
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
            .args(["-R", source_app.to_str().unwrap(), target_app.to_str().unwrap()])
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
            return Err(UpdateError::System("detach_failed".into()))
        }
        Ok(())
    }

    fn remove_file(&self, p: &std::path::Path) {
        let _ = std::fs::remove_file(p);
    }
}


