// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
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

    klaay_guard_lib::run()
}
