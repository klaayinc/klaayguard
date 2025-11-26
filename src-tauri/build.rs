fn main() {
    // Validate required environment variables
    let required_vars = vec![
        "VITE_API_BASE_URL",
        "VITE_EARTHENWARE_URL",
    ];

    let mut missing_vars = Vec::new();
    for var in &required_vars {
        if std::env::var(var).is_err() {
            missing_vars.push(*var);
        }
    }

    if !missing_vars.is_empty() {
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        eprintln!("❌ Build Error: Required environment variables are missing");
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        eprintln!("");
        eprintln!("Missing variables:");
        for var in &missing_vars {
            eprintln!("  - {}", var);
        }
        eprintln!("");
        eprintln!("Solution:");
        eprintln!("  1. Run: scripts/setup-env.sh");
        eprintln!("  2. Build using: bin/build <environment>");
        eprintln!("");
        eprintln!("See docs/ENVIRONMENT.md for details.");
        eprintln!("");
        panic!("Build failed: missing required environment variables");
    }

    // Get environment variables (already validated)
    let api_base = std::env::var("VITE_API_BASE_URL").unwrap();
    let earthenware_url = std::env::var("VITE_EARTHENWARE_URL").unwrap();
    let klaay_env = std::env::var("KLAAY_ENV").unwrap_or_else(|_| "production".to_string());

    // Debug output
    println!("cargo:warning=KLAAY_ENV: {}", klaay_env);
    println!("cargo:warning=VITE_API_BASE_URL: {}", api_base);
    println!("cargo:warning=VITE_EARTHENWARE_URL: {}", earthenware_url);

    // Expose compile-time defaults for Rust side
    println!("cargo:rustc-env=APP_DEFAULT_API_BASE_URL={}", api_base);
    println!("cargo:rustc-env=APP_DEFAULT_EARTHENWARE_URL={}", earthenware_url);

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
