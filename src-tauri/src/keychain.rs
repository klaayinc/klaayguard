use keyring::Entry;

const KEYCHAIN_ACCOUNT: &str = "auth_token";

/// Get keychain service name based on API URL
/// This ensures different environments (dev/staging/prod) don't share tokens
fn get_keychain_service() -> &'static str {
    let api_url = env!("APP_DEFAULT_API_BASE_URL");
    
    // Match on API URL to determine environment
    if api_url.contains("localhost") {
        "com.klaay.klaayguard.dev"
    } else if api_url.contains("klaay.dev") {
        "com.klaay.klaayguard.staging"
    } else {
        "com.klaay.klaayguard"
    }
}

fn entry() -> Result<Entry, String> {
    let service = get_keychain_service();
    Entry::new(service, KEYCHAIN_ACCOUNT)
        .map_err(|e| format!("keychain new entry error: {}", e))
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
