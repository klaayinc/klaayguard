use keyring::Entry;

const KEYCHAIN_SERVICE: &str = "com.klaay.klaayguard";
const KEYCHAIN_ACCOUNT: &str = "auth_token";

fn entry() -> Result<Entry, String> {
    Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
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
