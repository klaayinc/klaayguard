//! Keychain management for authentication tokens
//!
//! This module provides secure storage for authentication tokens using the system keychain.
//! Different environments (development, staging, production) use separate keychain services
//! to ensure tokens are isolated and don't leak between environments. This is critical for
//! security as it prevents accidentally using a production token in development or vice versa.

use keyring::Entry;

const KEYCHAIN_ACCOUNT: &str = "auth_token";

/// Get keychain service name based on environment
/// This ensures different environments (dev/staging/prod) don't share tokens
///
/// # Security
/// Using separate keychain services per environment prevents token leakage between
/// environments. For example, a development token cannot accidentally be used in production.
fn get_keychain_service() -> String {
    // Prefer explicit environment variable for environment detection
    let env = std::env::var("KLAAY_ENV").unwrap_or_else(|_| "production".to_string());
    match env.to_lowercase().as_str() {
        "development" | "dev" => "com.klaay.klaayguard.dev".to_string(),
        "staging" => "com.klaay.klaayguard.staging".to_string(),
        "production" | "prod" => "com.klaay.klaayguard".to_string(),
        _ => {
            // Fallback to previous logic if KLAAY_ENV is not recognized
            let api_url = std::env::var("VITE_API_BASE_URL")
                .or_else(|_| std::env::var("APP_DEFAULT_API_BASE_URL"))
                .unwrap_or_else(|_| env!("APP_DEFAULT_API_BASE_URL").to_string());
            if api_url.contains("localhost") {
                "com.klaay.klaayguard.dev".to_string()
            } else if api_url.contains("klaay.dev") {
                "com.klaay.klaayguard.staging".to_string()
            } else {
                "com.klaay.klaayguard".to_string()
            }
        }
    }
}

fn entry() -> Result<Entry, String> {
    let service = get_keychain_service();
    Entry::new(&service, KEYCHAIN_ACCOUNT).map_err(|e| format!("keychain new entry error: {}", e))
}

pub fn save_token(token: &str) -> Result<(), String> {
    entry()?
        .set_password(token)
        .map_err(|e| format!("keychain set_password error: {}", e))
}

pub fn load_token() -> Result<Option<String>, String> {
    match entry()?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("keychain get_password error: {}", e)),
    }
}

pub fn delete_token() -> Result<(), String> {
    match entry()?.delete_password() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("keychain delete_password error: {}", e)),
    }
}
