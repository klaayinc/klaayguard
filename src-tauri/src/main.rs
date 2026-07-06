// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Early panic hook to write immediately to macOS user Logs folder
    {
        std::panic::set_hook(Box::new(|panic_info| {
            let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
            let msg = format!("[{}][panic] {}\n", ts, panic_info);
            let log_dir = dirs::home_dir()
                .map(|h| h.join("Library/Logs/com.klaay.app"))
                .unwrap_or(std::path::PathBuf::from("./"));
            let _ = std::fs::create_dir_all(&log_dir);
            let log_path = log_dir.join("KlaayGuard.log");
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .and_then(|mut f| std::io::Write::write_all(&mut f, msg.as_bytes()));
        }));
    }

    // Initialize Sentry for error tracking
    let _guard = sentry::init((
        std::env::var("VITE_SENTRY_DSN").unwrap_or_default(),
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: std::env::var("KLAAY_ENV").ok().map(|s| s.into()),
            send_default_pii: true,
            attach_stacktrace: true,
            ..Default::default()
        },
    ));
    sentry::configure_scope(|scope| {
        scope.set_tag("component", "tauri");
        scope.set_tag("os", std::env::consts::OS);
        scope.set_tag("arch", std::env::consts::ARCH);
        if let Ok(app_version) = std::env::var("TAURI_APP_VERSION") {
            scope.set_tag("app_version", app_version);
        }
    });

    // Architecture compatibility check (now that Sentry is initialized)
    #[cfg(target_os = "macos")]
    {
        let built_arch = std::env::consts::ARCH; // "aarch64" or "x86_64"
        let mut is_apple_silicon_hw = None;
        if let Ok(out) = std::process::Command::new("/usr/sbin/sysctl")
            .args(["-n", "hw.optional.arm64"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s == "1" || s.eq_ignore_ascii_case("true") {
                is_apple_silicon_hw = Some(true);
            } else if s == "0" || s.eq_ignore_ascii_case("false") {
                is_apple_silicon_hw = Some(false);
            }
        }
        if is_apple_silicon_hw.is_none() {
            if let Ok(out) = std::process::Command::new("/usr/bin/uname")
                .arg("-m")
                .output()
            {
                let m = String::from_utf8_lossy(&out.stdout).trim().to_string();
                is_apple_silicon_hw = Some(m == "arm64" || m == "aarch64");
            }
        }

        if let Some(is_arm_hw) = is_apple_silicon_hw {
            let mismatch = matches!(
                (is_arm_hw, built_arch),
                (true, "x86_64") | (false, "aarch64") | (false, "arm")
            );

            if mismatch {
                let human_built = if built_arch == "aarch64" {
                    "arm64"
                } else {
                    built_arch
                };
                let human_hw = if is_arm_hw {
                    "arm64 (Apple Silicon)"
                } else {
                    "x86_64 (Intel)"
                };
                let msg = format!(
                    "Architecture mismatch: app built for {} but running on {} hardware. Please install the {} build of KlaayGuard.",
                    human_built,
                    human_hw,
                    if is_arm_hw { "arm64" } else { "x86_64" }
                );

                let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
                let full = format!("[{}][arch][ERROR] {}\n", ts, &msg);
                let log_dir = dirs::home_dir()
                    .map(|h| h.join("Library/Logs/com.klaay.app"))
                    .unwrap_or(std::path::PathBuf::from("./"));
                let _ = std::fs::create_dir_all(&log_dir);
                let log_path = log_dir.join("KlaayGuard.log");
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)
                    .and_then(|mut f| std::io::Write::write_all(&mut f, full.as_bytes()));

                sentry::capture_message(&format!("arch_mismatch: {}", msg), sentry::Level::Error);
                eprintln!("{}", msg);
                // Signal the frontend; the window is created in lib.rs setup, so we also set env vars for later use.
                std::env::set_var("KLAAY_ARCH_MISMATCH", "1");
                std::env::set_var("KLAAY_ARCH_BUILT", human_built);
                std::env::set_var("KLAAY_ARCH_HOST", human_hw);
            }
        }
    }

    // Ensure Rust log crate is initialized early so tauri-plugin-log captures logs
    // The plugin installs a logger; we just ensure standard logging macros are used elsewhere
    log::set_max_level(log::LevelFilter::Info);

    // Early boot log write for visibility before Tauri is fully initialized
    {
        let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let msg = format!("[{}][startup] KlaayGuard launching...\n", ts);
        let log_dir = dirs::home_dir()
            .map(|h| h.join("Library/Logs/com.klaay.app"))
            .unwrap_or(std::path::PathBuf::from("./"));
        let _ = std::fs::create_dir_all(&log_dir);
        let log_path = log_dir.join("KlaayGuard.log");
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, msg.as_bytes()));
    }

    klaay_guard_lib::run()
}
