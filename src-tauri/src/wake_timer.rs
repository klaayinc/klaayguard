use anyhow::Result;
use log::{info, warn};
use std::time::Duration;

#[cfg(target_os = "windows")]
use winapi::um::winbase::{SetWaitableTimer, CreateWaitableTimerW};
#[cfg(target_os = "windows")]
use winapi::um::processthreadsapi::GetCurrentProcess;
#[cfg(target_os = "windows")]
use winapi::um::winnt::HANDLE;
#[cfg(target_os = "windows")]
use std::ptr::null_mut;

#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "linux")]
use std::process::Command;

pub struct WakeTimer {
    #[cfg(target_os = "windows")]
    timer_handle: Option<HANDLE>,
}

impl WakeTimer {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "windows")]
            timer_handle: None,
        }
    }

    /// Schedule a wake timer for the next monitoring interval
    pub async fn schedule_wake(&mut self, interval_minutes: u64) -> Result<()> {
        let interval_duration = Duration::from_secs(interval_minutes * 60);
        
        #[cfg(target_os = "windows")]
        {
            self.schedule_windows_wake_timer(interval_duration).await?;
        }
        
        #[cfg(target_os = "macos")]
        {
            self.schedule_macos_wake_timer(interval_duration).await?;
        }
        
        #[cfg(target_os = "linux")]
        {
            self.schedule_linux_wake_timer(interval_duration).await?;
        }
        
        info!("Wake timer scheduled for {} minutes", interval_minutes);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn schedule_windows_wake_timer(&mut self, duration: Duration) -> Result<()> {
        use std::mem;
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        
        // Create a waitable timer
        let timer_name = OsString::from("KlaayGuardWakeTimer");
        let timer_name_wide: Vec<u16> = timer_name.encode_wide().chain(std::iter::once(0)).collect();
        
        let timer_handle = unsafe {
            CreateWaitableTimerW(
                null_mut(),
                0, // Manual reset
                0, // Not signaled initially
                timer_name_wide.as_ptr(),
            )
        };
        
        if timer_handle.is_null() {
            return Err(anyhow::anyhow!("Failed to create waitable timer"));
        }
        
        // Calculate the wake time
        let wake_time = std::time::SystemTime::now() + duration;
        let file_time = windows_file_time_from_system_time(wake_time);
        
        // Set the timer
        let result = unsafe {
            SetWaitableTimer(
                timer_handle,
                &file_time,
                0, // No periodic timer
                None,
                null_mut(),
                0,
            )
        };
        
        if result == 0 {
            return Err(anyhow::anyhow!("Failed to set waitable timer"));
        }
        
        self.timer_handle = Some(timer_handle);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn schedule_macos_wake_timer(&self, duration: Duration) -> Result<()> {
        let wake_time = std::time::SystemTime::now() + duration;
        let wake_timestamp = wake_time.duration_since(std::time::UNIX_EPOCH)?.as_secs();
        
        // Use pmset to schedule a wake event
        let output = Command::new("sudo")
            .args(&[
                "pmset",
                "schedule",
                "wake",
                &format!("{}", wake_timestamp),
                "KlaayGuard monitoring"
            ])
            .output()?;
        
        if !output.status.success() {
            warn!("Failed to schedule wake timer: {}", String::from_utf8_lossy(&output.stderr));
            return Err(anyhow::anyhow!("Failed to schedule wake timer"));
        }
        
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn schedule_linux_wake_timer(&self, duration: Duration) -> Result<()> {
        let wake_time = std::time::SystemTime::now() + duration;
        let wake_timestamp = wake_time.duration_since(std::time::UNIX_EPOCH)?.as_secs();
        
        // Try to use rtcwake if available
        let output = Command::new("rtcwake")
            .args(&[
                "-m", "no", // Don't actually suspend, just set wake time
                "-t", &format!("{}", wake_timestamp)
            ])
            .output();
        
        match output {
            Ok(output) if output.status.success() => {
                info!("Wake timer set using rtcwake");
                Ok(())
            }
            Ok(_) => {
                warn!("rtcwake failed, trying alternative method");
                self.schedule_linux_alternative_wake_timer(wake_timestamp).await
            }
            Err(_) => {
                warn!("rtcwake not available, trying alternative method");
                self.schedule_linux_alternative_wake_timer(wake_timestamp).await
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn schedule_linux_alternative_wake_timer(&self, wake_timestamp: u64) -> Result<()> {
        // Try using systemd timers as a fallback
        let output = Command::new("systemd-run")
            .args(&[
                "--on-calendar",
                &format!("@{}", wake_timestamp),
                "echo", "KlaayGuard wake event"
            ])
            .output()?;
        
        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to schedule wake timer with systemd"));
        }
        
        Ok(())
    }

    pub fn cancel_wake_timer(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            if let Some(handle) = self.timer_handle.take() {
                unsafe {
                    winapi::um::handleapi::CloseHandle(handle);
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            // Cancel pmset wake events
            let _ = Command::new("sudo")
                .args(&["pmset", "schedule", "cancel", "KlaayGuard monitoring"])
                .output();
        }
        
        #[cfg(target_os = "linux")]
        {
            // Cancel systemd timers
            let _ = Command::new("systemctl")
                .args(&["--user", "stop", "klaayguard-wake.timer"])
                .output();
        }
        
        info!("Wake timer cancelled");
        Ok(())
    }
}

impl Drop for WakeTimer {
    fn drop(&mut self) {
        let _ = self.cancel_wake_timer();
    }
}

#[cfg(target_os = "windows")]
fn windows_file_time_from_system_time(system_time: std::time::SystemTime) -> winapi::shared::minwindef::FILETIME {
    use winapi::shared::minwindef::FILETIME;
    use std::mem;
    
    let duration = system_time.duration_since(std::time::UNIX_EPOCH).unwrap();
    let windows_ticks = duration.as_nanos() / 100 + 116444736000000000; // Convert to Windows file time
    
    FILETIME {
        dwLowDateTime: (windows_ticks & 0xFFFFFFFF) as u32,
        dwHighDateTime: (windows_ticks >> 32) as u32,
    }
}
