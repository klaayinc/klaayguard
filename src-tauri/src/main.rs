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
