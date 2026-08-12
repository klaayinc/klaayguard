use keyring::Entry;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const KEYCHAIN_SERVICE: &str = "com.klaay.klaayguard";
const KEYCHAIN_ACCOUNT: &str = "auth_token";
const DEVICE_ID_ACCOUNT: &str = "device_identity";

/// Which store held the credential. The caller surfaces a notice to the user
/// when the OS Secret Service was unavailable and the file fallback was used.
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialStore {
    Keyring,
    File,
}

fn entry_for(account: &str) -> Result<Entry, String> {
    Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| format!("keychain new entry error: {}", e))
}

fn keyring_set(account: &str, value: &str) -> Result<(), String> {
    entry_for(account)?
        .set_password(value)
        .map_err(|e| format!("set_password error: {}", e))
}

fn keyring_get(account: &str) -> Result<Option<String>, String> {
    match entry_for(account)?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("get_password error: {}", e)),
    }
}

// --- File fallback ---------------------------------------------------------
//
// The keyring is the primary store. Many Linux desktops (XFCE, i3, sway) run no
// Secret Service daemon, so `set_password` fails there and the token would live
// in memory only — the user then signs in again on every reboot (PROD-4046).
//
// When the keyring is unavailable, save the credential to a user-only file, the
// same way the GitHub CLI does. The token is a short-lived bearer credential;
// file permissions (0600), not encryption, protect it. A key derived from the
// machine would add no real protection: it lives on the same disk and in the
// same backups as the file.

fn credential_file(account: &str) -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("com.klaay.app").join("credentials").join(account))
}

fn file_save_at(path: &Path, value: &str) -> Result<(), String> {
    let dir = path.parent().ok_or("credential path has no parent")?;
    fs::create_dir_all(dir).map_err(|e| format!("credential dir: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    // Write a fresh temp file with 0600, then rename over the target, so a crash
    // cannot leave a half-written or world-readable token.
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        let mut f = opts
            .open(&tmp)
            .map_err(|e| format!("credential create: {}", e))?;
        f.write_all(value.as_bytes())
            .map_err(|e| format!("credential write: {}", e))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("credential rename: {}", e))
}

fn file_load_at(path: &Path) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

fn file_delete_at(path: &Path) {
    let _ = fs::remove_file(path);
}

fn file_save(account: &str, value: &str) -> Result<(), String> {
    let path = credential_file(account).ok_or("no data dir for credential fallback")?;
    file_save_at(&path, value)
}

fn file_load(account: &str) -> Option<String> {
    credential_file(account).and_then(|p| file_load_at(&p))
}

fn file_delete(account: &str) {
    if let Some(p) = credential_file(account) {
        file_delete_at(&p);
    }
}

// --- Public API: keyring first, file fallback ------------------------------

pub fn save_token(token: &str) -> Result<CredentialStore, String> {
    match keyring_set(KEYCHAIN_ACCOUNT, token) {
        Ok(()) => {
            // The keyring works; drop any stale fallback copy so a plaintext
            // token does not linger after the store recovers.
            file_delete(KEYCHAIN_ACCOUNT);
            Ok(CredentialStore::Keyring)
        }
        Err(e) => {
            log::warn!("secret service unavailable ({}); saving token to file", e);
            file_save(KEYCHAIN_ACCOUNT, token)
                .map_err(|fe| format!("keyring failed ({}); file fallback failed ({})", e, fe))?;
            Ok(CredentialStore::File)
        }
    }
}

pub fn load_token() -> Result<Option<String>, String> {
    match keyring_get(KEYCHAIN_ACCOUNT) {
        Ok(Some(t)) => Ok(Some(t)),
        // Keyring empty: a fallback file may still hold the token.
        Ok(None) => Ok(file_load(KEYCHAIN_ACCOUNT)),
        Err(e) => {
            log::warn!(
                "secret service read failed ({}); reading token from file",
                e
            );
            Ok(file_load(KEYCHAIN_ACCOUNT))
        }
    }
}

pub fn save_device_identity(id: &str) -> Result<(), String> {
    match keyring_set(DEVICE_ID_ACCOUNT, id) {
        Ok(()) => {
            file_delete(DEVICE_ID_ACCOUNT);
            Ok(())
        }
        Err(e) => {
            log::warn!(
                "secret service unavailable ({}); saving device identity to file",
                e
            );
            file_save(DEVICE_ID_ACCOUNT, id)
                .map_err(|fe| format!("keyring failed ({}); file fallback failed ({})", e, fe))
        }
    }
}

pub fn load_device_identity() -> Result<Option<String>, String> {
    match keyring_get(DEVICE_ID_ACCOUNT) {
        Ok(Some(v)) => Ok(Some(v)),
        Ok(None) => Ok(file_load(DEVICE_ID_ACCOUNT)),
        Err(e) => {
            log::warn!(
                "secret service read failed ({}); reading device identity from file",
                e
            );
            Ok(file_load(DEVICE_ID_ACCOUNT))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn unique_path(name: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("klaayguard-cred-test-{}-{}", std::process::id(), n))
            .join(name)
    }

    #[test]
    fn file_store_round_trips_the_value() {
        let path = unique_path("auth_token");
        file_save_at(&path, "tok-123").unwrap();
        assert_eq!(file_load_at(&path), Some("tok-123".to_string()));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn file_store_missing_reads_as_none() {
        let path = unique_path("auth_token");
        assert_eq!(file_load_at(&path), None);
    }

    #[test]
    fn file_store_overwrites_then_deletes() {
        let path = unique_path("auth_token");
        file_save_at(&path, "one").unwrap();
        file_save_at(&path, "two").unwrap();
        assert_eq!(file_load_at(&path), Some("two".to_string()));
        file_delete_at(&path);
        assert_eq!(file_load_at(&path), None);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    // The fallback holds a real bearer token, so the file must be user-only.
    #[test]
    #[cfg(unix)]
    fn file_store_is_user_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = unique_path("auth_token");
        file_save_at(&path, "secret").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
