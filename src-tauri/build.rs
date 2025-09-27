fn main() {
    // Determine environment for compile-time defaults
    let klaay_env = std::env::var("KLAAY_ENV")
        .ok()
        .or_else(|| std::env::var("NODE_ENV").ok())
        .unwrap_or_else(|| "production".to_string())
        .to_lowercase();

    // Debug output (avoid cargo:warning to keep builds clean)
    eprintln!("KLAAY_ENV: {}", klaay_env);
    eprintln!(
        "VITE_API_BASE_URL: {:?}",
        std::env::var("VITE_API_BASE_URL")
    );

    // Compute default API base if not explicitly provided
    let default_api = match klaay_env.as_str() {
        "staging" => "https://api.klaay.dev",
        "development" => "http://localhost:3000",
        _ => "https://api.klaay.com",
    };
    let api_base = std::env::var("VITE_API_BASE_URL").unwrap_or_else(|_| default_api.to_string());

    // Debug output (avoid cargo:warning to keep builds clean)
    eprintln!("default_api: {}", default_api);
    eprintln!("final api_base: {}", api_base);

    // Expose compile-time default for Rust side
    println!("cargo:rustc-env=APP_DEFAULT_API_BASE_URL={}", api_base);
    eprintln!("Setting APP_DEFAULT_API_BASE_URL to: {}", api_base);

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
