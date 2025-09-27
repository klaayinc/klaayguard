pub mod adapters;
pub mod bootstrap;
pub mod check;
pub mod commands;
pub mod download;
pub mod install;
pub mod types;

// Shared helper for determining API base URL at runtime
pub(crate) fn get_api_base_url() -> String {
    std::env::var("VITE_API_BASE_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_API_BASE_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://api.klaay.com".to_string())
}


