// SPDX-License-Identifier: GPL-3.0-or-later
// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// True when this process cannot run on this hardware.
///
/// An x86_64 process on Apple silicon is not a mismatch: Rosetta runs it. The
/// universal app also runs its x86_64 slice there when a user sets Open using
/// Rosetta. Only an arm64 process on an Intel Mac cannot run.
#[cfg(target_os = "macos")]
fn arch_mismatch(is_arm_hw: bool, built_arch: &str) -> bool {
    matches!((is_arm_hw, built_arch), (false, "aarch64") | (false, "arm"))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::arch_mismatch;

    #[test]
    fn x86_64_slice_on_apple_silicon_is_not_a_mismatch() {
        // The universal app runs its x86_64 slice under Rosetta on Apple silicon.
        assert!(!arch_mismatch(true, "x86_64"));
    }

    #[test]
    fn arm64_slice_on_apple_silicon_is_not_a_mismatch() {
        assert!(!arch_mismatch(true, "aarch64"));
    }

    #[test]
    fn x86_64_slice_on_intel_is_not_a_mismatch() {
        assert!(!arch_mismatch(false, "x86_64"));
    }

    #[test]
    fn arm64_slice_on_intel_is_a_mismatch() {
        // An arm64 slice cannot run on an Intel Mac.
        assert!(arch_mismatch(false, "aarch64"));
        assert!(arch_mismatch(false, "arm"));
    }
}

fn main() {
    // Early panic hook: write to the platform log directory before Tauri and
    // its logger exist. Uses the same directory as tauri-plugin-log, so one
    // location holds every log.
    std::panic::set_hook(Box::new(|panic_info| {
        klaay_guard_lib::append_early_log(&format!("[panic] {}", panic_info));
    }));

    // Initialize Sentry for error tracking
    // Runtime env first, then the compile-time default from build.rs. Released
    // builds run under launchd without these variables, so without the baked-in
    // fallback Sentry never activates in production.
    //
    // `ClientOptions` is `#[non_exhaustive]`, so it is built with its setters
    // rather than a struct literal.
    let options = sentry::ClientOptions::new()
        .maybe_release(sentry::release_name!())
        // Do not attach client IP / user identifiers by default. This agent runs on
        // employee endpoints; crash telemetry should not carry PII unless we make a
        // deliberate, documented decision to collect a specific field.
        .send_default_pii(false)
        .attach_stacktrace(true);
    let options = match std::env::var("KLAAY_ENV")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_KLAAY_ENV").map(|s| s.to_string()))
    {
        Some(environment) => options.environment(environment),
        None => options,
    };
    let _guard = sentry::init((
        std::env::var("VITE_SENTRY_DSN")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| option_env!("APP_DEFAULT_SENTRY_DSN").map(|s| s.to_string()))
            .unwrap_or_default(),
        options,
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
            let mismatch = arch_mismatch(is_arm_hw, built_arch);

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

                klaay_guard_lib::append_early_log(&format!("[arch][ERROR] {}", msg));
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
    klaay_guard_lib::append_early_log("[startup] KlaayGuard launching...");

    klaay_guard_lib::run()
}
