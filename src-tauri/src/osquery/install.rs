// src-tauri/src/osquery/install.rs
use anyhow::{Result};
use runas::Command as SudoCommand;
use reqwest::blocking::get;
use std::fs::File;
use std::io::copy;
use std::io::Error;

#[cfg(target_os = "linux")]
use std::process::Stdio;


// Progress callback type
pub type ProgressCallback = dyn Fn(&str, &str);

#[cfg(target_os = "linux")]
enum LinuxPackageManager {
    Apt,
    Dnf,
    Zypper,
}

#[cfg(target_os = "linux")]
fn get_package_manager() -> Result<LinuxPackageManager> {
    use log::info;
    use std::process::Command;
    
    // debian based
    let apt_installed = Command::new("which")
        .arg("apt")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if apt_installed {
        info!("detected apt");
        return Ok(LinuxPackageManager::Apt);
    }

    // fedora based
    let dnf_installed= Command::new("which")
        .arg("dnf")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if dnf_installed {
        info!("detected dnf");
        return Ok(LinuxPackageManager::Dnf);
    }

    // suse based
    let zypper_installed= Command::new("which")
        .arg("zypper")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if zypper_installed {
        info!("detected zypper");
        return Ok(LinuxPackageManager::Zypper);
    }

    Err(anyhow::anyhow!("Couldn't find supported package manager"))
}

#[cfg(target_os = "linux")]
fn configure_osquery_repo(package_manager: &LinuxPackageManager) -> Result<()> {
    use std::process::Command;
    
    match package_manager {
        LinuxPackageManager::Apt => {
            Command::new("sudo")
                .args(&["mkdir", "-p", "/etc/apt/keyrings"])
                .status()
                .and_then(|s| {
                    if s.success() {
                        Command::new("sh")
                            .arg("-c")
                            .arg("curl -L https://pkg.osquery.io/deb/pubkey.gpg | sudo tee /etc/apt/keyrings/osquery.asc")
                            .status()
                    } else {
                        Ok(s)
                    }
                })
                .and_then(|s| {
                    if s.success() {
                        let content = "deb [arch=amd64 signed-by=/etc/apt/keyrings/osquery.asc] https://pkg.osquery.io/deb deb main";

                        let mut tee = Command::new("sudo")
                            .arg("tee")
                            .arg("/etc/apt/sources.list.d/osquery.list")
                            .stdin(Stdio::piped())
                            .stdout(Stdio::null())
                            .spawn()?;

                        if let Some(mut stdin) = tee.stdin.take() {
                            use std::io::Write;

                            stdin.write_all(content.as_bytes())?
                        }

                        let status = tee.wait()?;

                        Ok(status)
                    } else {
                        Ok(s)
                    }
                })
                .map_err(|e| anyhow::anyhow!("Failed to configure apt repo: {}", e))
                .and_then(|s| {
                    if s.success() {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!("Failed to configure apt repo"))
                    }
                })
        },
        LinuxPackageManager::Dnf => {
            Command::new("sh")
                .arg("-c")
                .arg("curl -L https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery")
                .status()
                .and_then(|s| {
                    if s.success() {
                        Command::new("sudo")
                            .args(&["yum-config-manager", "--add-repo", "https://pkg.osquery.io/rpm/osquery-s3-rpm.repo"])
                            .status()
                    } else {
                        Ok(s)
                    }
                })
                .and_then(|s| {
                    if s.success() {
            Command::new("sudo")
                            .args(&["yum-config-manager", "--enable", "osquery-s3-rpm-repo"])
                            .status()
                    } else {
                        Ok(s)
                    }
                })
                .map_err(|e| anyhow::anyhow!("Failed to configure yum/dnf repo: {}", e))
                .and_then(|s| {
                    if s.success() {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!("Failed to configure yum/dnf repo"))
                    }
                })
        },
        LinuxPackageManager::Zypper => {
            Command::new("sh")
                .arg("-c")
                .arg("curl -L https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery")
                .status()
                .and_then(|s| {
                    if s.success() {
                        Command::new("sudo")
                            .args(&["zypper", "ar", "-f", "https://pkg.osquery.io/rpm/osquery-s3-rpm.repo"])
                            .status()
                    } else {
                        Ok(s)
                    }
                })
                .and_then(|s| {
                    if s.success() {
            Command::new("sudo")
                            .args(&["zypper", "mr", "-e", "osquery-s3-rpm-repo"])
                .status()
        } else {
                        Ok(s)
                    }
                })
                .map_err(|e| anyhow::anyhow!("Failed to configure zypper repo: {}", e))
                .and_then(|s| {
                    if s.success() {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!("Failed to configure zypper repo"))
                    }
                })
        }
    }
}

pub fn is_osquery_installed() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        
        // Combine multiple flags for maximum suppression
        let flags = CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        
        std::process::Command::new("where")  // First check if osqueryi exists in PATH
            .arg("osqueryi")
            .creation_flags(flags)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("which")
            .arg("osqueryi")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

#[cfg(target_os = "windows")]
pub fn install_osquery_with_progress(progress: Option<&ProgressCallback>) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use log::{info, warn, error};
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    if let Some(cb) = progress { cb("checking", "Preparing osquery installation on Windows"); }
    info!("Preparing osquery installation on Windows");
    let choco_installed = Command::new("where")
        .arg("choco")
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    if !choco_installed {
        if let Some(cb) = progress { cb("downloading", "Chocolatey not found. Installing Chocolatey first..."); }
        warn!("Chocolatey not found. Installing Chocolatey first...");
        let status = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command",
                "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; \
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map_err(|e| {
                if let Some(cb) = progress {
                    cb("error", &format!("Network or permission error while installing Chocolatey: {}. Try running as administrator.", e));
                }
                anyhow::anyhow!("Network or permission error while installing Chocolatey: {}. Try running as administrator.", e)
            })?;
        if !status.success() {
            if let Some(cb) = progress { cb("error", "Chocolatey installation failed. Try running as administrator."); }
            return Err(anyhow::anyhow!("Chocolatey installation failed with status: {}. Try running as administrator.", status));
        }
        if let Some(cb) = progress { cb("configuring", "Waiting for Chocolatey to initialize..."); }
        info!("Waiting for Chocolatey to initialize...");
        std::thread::sleep(std::time::Duration::from_secs(5));
        info!("Refreshing environment variables...");
        let _ = Command::new("cmd")
            .args(&["/C", "refreshenv"])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }
    info!("Verifying Chocolatey installation...");
    let choco_version = Command::new("choco")
        .arg("--version")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| {
            if let Some(cb) = progress {
                cb("error", &format!("Failed to verify Chocolatey installation: {}. Try running as administrator.", e));
            }
            anyhow::anyhow!("Failed to verify Chocolatey installation: {}. Try running as administrator.", e)
        })?;
    if !choco_version.status.success() {
        if let Some(cb) = progress { cb("error", "Chocolatey verification failed. Try running as administrator."); }
        error!("Chocolatey verification failed. Output: {:?}", choco_version);
        return Err(anyhow::anyhow!("Chocolatey installation verification failed. Try running as administrator."));
    }
    info!("Chocolatey version: {}", String::from_utf8_lossy(&choco_version.stdout));
    if let Some(cb) = progress { cb("installing", "Installing osquery via Chocolatey"); }
    info!("Installing osquery via Chocolatey");
    let mut attempts = 0;
    let max_attempts = 3;
    let mut last_error = None;
    while attempts < max_attempts {
        attempts += 1;
        info!("Attempt {} of {} to install osquery", attempts, max_attempts);
        if let Some(cb) = progress { cb("installing", &format!("Attempt {} of {} to install osquery", attempts, max_attempts)); }
        let status = Command::new("choco")
            .args(&["install", "osquery", "-y", "--force", "--no-progress"])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
        match status {
            Ok(status) if status.success() => {
                if let Some(cb) = progress { cb("done", "osquery installation completed via Chocolatey"); }
                info!("osquery installation completed via Chocolatey");
                return Ok(());
            },
            Ok(status) => {
                last_error = Some(format!("Chocolatey exited with status: {}", status));
                warn!("Attempt {} failed: {}", attempts, last_error.as_ref().unwrap());
            },
            Err(e) => {
                last_error = Some(format!("Failed to execute choco command: {}. Try running as administrator.", e));
                warn!("Attempt {} failed: {}", attempts, last_error.as_ref().unwrap());
            }
        }
        if attempts < max_attempts {
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }
    if let Some(cb) = progress { cb("error", &format!("Failed to install osquery after multiple attempts. {}. Try running as administrator.", last_error.clone().unwrap_or_default())); }
    Err(anyhow::anyhow!(
        "Failed to install osquery after {} attempts. Last error: {}. Try running as administrator.",
        max_attempts,
        last_error.unwrap_or_else(|| "unknown error".to_string())
    ))
}

#[cfg(target_os = "macos")]
pub fn install_osquery_with_progress(progress: Option<&ProgressCallback>) -> Result<()> {
    let url = "https://pkg.osquery.io/darwin/osquery-5.17.0.pkg";
    let output_path = "/tmp/osquery-5.17.0.pkg";
    if let Some(cb) = progress { cb("downloading", "Downloading osquery package..."); }
    let mut response = get(url).map_err(|e| {
        if let Some(cb) = progress {
            cb("error", &format!("Network error while downloading osquery: {}. Check your internet connection.", e));
        }
        anyhow::anyhow!("Network error while downloading osquery: {}. Check your internet connection.", e)
    })?;
    if response.status().is_success() {
        if let Some(cb) = progress { cb("downloading", "Writing osquery package to disk..."); }
        let mut out = File::create(output_path).map_err(|e| {
            if let Some(cb) = progress {
                cb("error", &format!("Permission error writing to disk: {}. Try running as administrator.", e));
            }
            anyhow::anyhow!("Permission error writing to disk: {}. Try running as administrator.", e)
        })?;
        copy(&mut response, &mut out).map_err(|e| {
            if let Some(cb) = progress {
                cb("error", &format!("Disk write error: {}. Try running as administrator.", e));
            }
            anyhow::anyhow!("Disk write error: {}. Try running as administrator.", e)
        })?;
        if let Some(cb) = progress { cb("installing", "Installing osquery..."); }
        let status = SudoCommand::new("installer")
            .gui(true)
            .force_prompt(true)
            .arg("-pkg")
            .arg(output_path)
            .arg("-target")
            .arg("/")
            .status()
            .map_err(|e| {
                if let Some(cb) = progress {
                    cb("error", &format!("Permission error running installer: {}. Try running as administrator.", e));
                }
                anyhow::anyhow!("Permission error running installer: {}. Try running as administrator.", e)
            })?;
        if status.success() {
            if let Some(cb) = progress { cb("done", "osquery installation successful."); }
            std::fs::remove_file(output_path).ok();
            Ok(())
        } else {
            if let Some(cb) = progress { cb("error", "osquery installation failed. Try running as administrator."); }
            Err(anyhow::anyhow!("osquery installation failed. Try running as administrator."))
        }
    } else {
        if let Some(cb) = progress { cb("error", "Failed to download osquery package. Check your internet connection."); }
        Err(anyhow::anyhow!("Failed to download osquery package. Check your internet connection."))
    }
}

#[cfg(target_os = "linux")]
pub fn install_osquery_with_progress(progress: Option<&ProgressCallback>) -> Result<()> {
    use log::{info, warn};
    use std::process::Command;
    info!("Preparing osquery installation on Linux");
    if let Some(cb) = progress { cb("checking", "Preparing osquery installation on Linux"); }
    let package_manager = get_package_manager().map_err(|e| {
        if let Some(cb) = progress {
            cb("error", &format!("Could not detect supported package manager: {}. Please install apt, dnf, or zypper.", e));
        }
        anyhow::anyhow!("Could not detect supported package manager: {}. Please install apt, dnf, or zypper.", e)
    })?;
    if let Some(cb) = progress { cb("configuring", "Configuring osquery repository"); }
    configure_osquery_repo(&package_manager).map_err(|e| {
        if let Some(cb) = progress {
            cb("error", &format!("Failed to configure osquery repository: {}. Try running as root or with sudo.", e));
        }
        anyhow::anyhow!("Failed to configure osquery repository: {}. Try running as root or with sudo.", e)
    })?;
    let mut attempts = 0;
    let max_attempts = 3;
    let mut last_error = None;
    while attempts < max_attempts {
        attempts += 1;
        info!("Attempt {} of {} to install osquery", attempts, max_attempts);
        if let Some(cb) = progress { cb("installing", &format!("Attempt {} of {} to install osquery", attempts, max_attempts)); }
        let osquery_install_status = match package_manager {
            LinuxPackageManager::Apt => Command::new("sudo")
                .args(&["apt", "update"])
                .status()
                .and_then(|s| {
                    if s.success() {
                        let status = Command::new("sudo")
                        .args(&["apt", "install", "-y", "osquery"])
                        .status()?;

                        Ok(status)
                    } else {
                        Ok(s)
                    }
                }),
            LinuxPackageManager::Dnf => Command::new("sudo")
                .args(&["yum", "install", "-y", "osquery"])
                .status(),
            LinuxPackageManager::Zypper => Command::new("sudo")
                .args(&["zypper", "--non-interactive", "install", "osquery"])
                .status(),
        };
        match osquery_install_status {
            Ok(status) if status.success() => {
                if let Some(cb) = progress { cb("done", "osquery installation completed successfully"); }
                info!("osquery installation completed successfully");
                return Ok(());
            }
            Ok(status) => {
                last_error = Some(format!("Installation failed with status: {}", status));
                warn!("Attempt {} failed: {}", attempts, last_error.as_ref().unwrap());
            }
            Err(e) => {
                last_error = Some(format!("Failed to execute installation command: {}. Try running as root or with sudo.", e));
                warn!("Attempt {} failed: {}", attempts, last_error.as_ref().unwrap());
            }
        }
        if attempts < max_attempts {
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }
    if let Some(cb) = progress { cb("error", &format!("Failed to install osquery after multiple attempts. {}. Try running as root or with sudo.", last_error.clone().unwrap_or_default())); }
    Err(anyhow::anyhow!(
        "Failed to install osquery after {} attempts. Last error: {}. Try running as root or with sudo.",
        max_attempts,
        last_error.unwrap_or_else(|| "unknown error".to_string())
    ))
}

// Fallback for Tauri command
pub fn install_osquery() -> Result<()> {
    install_osquery_with_progress(None)
}
