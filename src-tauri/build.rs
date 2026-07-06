fn main() {
    // Re-run this script when any env that feeds the compiled-in defaults changes.
    // Without these, cargo caches build.rs output and a later build with a different
    // KLAAY_ENV/VITE_* silently keeps the previously-compiled environment.
    for var in [
        "KLAAY_ENV",
        "NODE_ENV",
        "VITE_API_BASE_URL",
        "VITE_EARTHENWARE_URL",
    ] {
        println!("cargo:rerun-if-env-changed={}", var);
    }

    // Determine environment for compile-time defaults
    let klaay_env = std::env::var("KLAAY_ENV")
        .ok()
        .or_else(|| std::env::var("NODE_ENV").ok())
        .unwrap_or_else(|| "production".to_string())
        .to_lowercase();

    // Debug output
    println!("cargo:warning=KLAAY_ENV: {}", klaay_env);
    println!(
        "cargo:warning=VITE_API_BASE_URL: {:?}",
        std::env::var("VITE_API_BASE_URL")
    );

    // Compute default API base if not explicitly provided
    let default_api = match klaay_env.as_str() {
        "staging" => "https://api.klaay.dev",
        "development" => "http://localhost:3000",
        _ => "https://api.klaay.com",
    };
    let api_base = std::env::var("VITE_API_BASE_URL").unwrap_or_else(|_| default_api.to_string());

    // Debug output
    println!("cargo:warning=default_api: {}", default_api);
    println!("cargo:warning=final api_base: {}", api_base);

    // Expose compile-time default for Rust side
    println!("cargo:rustc-env=APP_DEFAULT_API_BASE_URL={}", api_base);
    println!(
        "cargo:warning=Setting APP_DEFAULT_API_BASE_URL to: {}",
        api_base
    );

    // Earthenware (web app) base — needed by the tray "Sign in" action now that
    // the login UI lives in Rust, not a webview.
    let default_earthenware = match klaay_env.as_str() {
        "staging" => "https://app.klaay.dev",
        "development" => "http://localhost:5173",
        _ => "https://app.klaay.com",
    };
    let earthenware =
        std::env::var("VITE_EARTHENWARE_URL").unwrap_or_else(|_| default_earthenware.to_string());
    println!(
        "cargo:rustc-env=APP_DEFAULT_EARTHENWARE_URL={}",
        earthenware
    );

    let mut windows = tauri_build::WindowsAttributes::new();
    windows = windows.app_manifest(
        r#"
        <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
        <dependency>
            <dependentAssembly>
            <assemblyIdentity
                type="win32"
                name="Microsoft.Windows.Common-Controls"
                version="6.0.0.0"
                processorArchitecture="*"
                publicKeyToken="6595b64144ccf1df"
                language="*"
            />
            </dependentAssembly>
        </dependency>
        <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
            <security>
                <requestedPrivileges>
                    <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
                </requestedPrivileges>
            </security>
        </trustInfo>
        </assembly>
        "#,
    );
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("failed to run build script");
}
