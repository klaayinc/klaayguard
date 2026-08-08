use keyring::Entry;

const KEYCHAIN_SERVICE: &str = "com.klaay.klaayguard";
const KEYCHAIN_ACCOUNT: &str = "auth_token";
const DEVICE_ID_ACCOUNT: &str = "device_identity";

fn entry_for(account: &str) -> Result<Entry, String> {
    Entry::new(KEYCHAIN_SERVICE, account)
        .map_err(|e| format!("keychain new entry error: {}", e))
}

pub fn save_token(token: &str) -> Result<(), String> {
    log::info!("🔑 keychain access: set_password");
    entry_for(KEYCHAIN_ACCOUNT)?
        .set_password(token)
        .map_err(|e| format!("keychain set_password error: {}", e))
}

pub fn load_token() -> Result<Option<String>, String> {
    log::info!("🔑 keychain access: get_password");
    match entry_for(KEYCHAIN_ACCOUNT)?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("keychain get_password error: {}", e)),
    }
}

pub fn save_device_identity(id: &str) -> Result<(), String> {
    log::info!("🔑 keychain access: set device_identity");
    entry_for(DEVICE_ID_ACCOUNT)?
        .set_password(id)
        .map_err(|e| format!("keychain set device_identity error: {}", e))
}

pub fn load_device_identity() -> Result<Option<String>, String> {
    match entry_for(DEVICE_ID_ACCOUNT)?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("keychain get device_identity error: {}", e)),
    }
}
