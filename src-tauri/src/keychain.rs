// SPDX-License-Identifier: GPL-3.0-or-later
use keyring::Entry;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const KEYCHAIN_SERVICE: &str = "com.klaay.klaayguard";
const KEYCHAIN_ACCOUNT: &str = "auth_token";
const DEVICE_ID_ACCOUNT: &str = "device_identity";

/// The one API base whose credential entry is shared by every installed
/// agent. Any other target gets its own entry — see `keychain_service_for`.
const PRODUCTION_API_BASE: &str = "https://api.klaay.com";

/// The credential entry this build uses, chosen by the server it talks to.
///
/// A build pointed at production keeps the entry the fleet already holds, so
/// an upgrade never signs anybody out. A build pointed anywhere else gets its
/// own: a developer running against localhost must not overwrite the token of
/// the agent installed on the same machine, and a staging agent must not
/// collide with a local one.
///
/// The suffix is a hash rather than the URL itself, because a service name
/// and a directory name cannot carry a scheme, a colon, or a slash.
fn keychain_service_for(api_base_url: &str) -> String {
    match target_suffix(api_base_url) {
        None => KEYCHAIN_SERVICE.to_string(),
        Some(suffix) => format!("{KEYCHAIN_SERVICE}.{suffix}"),
    }
}

/// `None` for production, so its names stay byte-identical to what already
/// exists on disk and in the keychain.
fn target_suffix(api_base_url: &str) -> Option<String> {
    let normalised = api_base_url.trim_end_matches('/');
    if normalised == PRODUCTION_API_BASE {
        return None;
    }
    let digest = Sha256::digest(normalised.as_bytes());
    Some(digest.iter().take(4).map(|b| format!("{b:02x}")).collect())
}

fn api_base() -> String {
    crate::get_api_base_url()
}

/// Which store held the credential. The caller surfaces a notice to the user
/// when the OS Secret Service was unavailable and the file fallback was used.
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialStore {
    Keyring,
    File,
}

fn entry_for(account: &str) -> Result<Entry, String> {
    Entry::new(&keychain_service_for(&api_base()), account)
        .map_err(|e| format!("keychain new entry error: {}", e))
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
    credential_file_in(&api_base(), account)
}

/// The fallback file needs the same split as the keychain entry, or a local
/// build overwrites the installed agent's token on any desktop without a
/// Secret Service daemon. Production keeps the existing path exactly.
fn credential_file_in(api_base_url: &str, account: &str) -> Option<PathBuf> {
    let dir = match target_suffix(api_base_url) {
        None => "credentials".to_string(),
        Some(suffix) => format!("credentials-{suffix}"),
    };
    dirs::data_local_dir().map(|d| d.join("com.klaay.app").join(dir).join(account))
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
        // Flush before the rename. On a first save the target does not exist
        // yet, so no rename-over-existing heuristic protects it, and a power
        // loss could leave an empty file that reads as "no token".
        f.sync_all()
            .map_err(|e| format!("credential sync: {}", e))?;
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

/// Load a credential: the fallback file first, then the keyring. A file is
/// written only when a keyring write failed, and a later successful keyring
/// write deletes it, so a present file always holds the newest value; reading
/// the keyring first would resurrect a stale entry (an invalidated token that
/// `invalidate_auth` deliberately leaves in place). A keyring read error with
/// no file is returned to the caller, so a locked or absent store is reported
/// instead of looking like "not signed in".
fn load(account: &str) -> Result<Option<String>, String> {
    if let Some(v) = file_load(account) {
        return Ok(Some(v));
    }
    keyring_get(account)
}

pub fn load_token() -> Result<Option<String>, String> {
    load(KEYCHAIN_ACCOUNT)
}

/// Remove the stored auth token from both stores. An explicit sign out must
/// leave no token behind. Clear the file fallback, then the keyring. A missing
/// entry is success. A refused keyring delete is a failure only when the token
/// is provably still stored: on a host with no usable keyring the token only
/// ever lived in the file, and that is gone.
pub fn delete_token() -> Result<(), String> {
    file_delete(KEYCHAIN_ACCOUNT);
    let Ok(entry) = entry_for(KEYCHAIN_ACCOUNT) else {
        return Ok(());
    };
    match entry.delete_password() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => match keyring_get(KEYCHAIN_ACCOUNT) {
            Ok(Some(_)) => Err(format!(
                "keyring delete failed ({}); the token is still stored",
                e
            )),
            _ => {
                log::warn!("sign out: keyring delete failed ({}); file cleared", e);
                Ok(())
            }
        },
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
    load(DEVICE_ID_ACCOUNT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // A build pointed at production keeps the entry every installed agent
    // already uses. Changing it would sign the fleet out on upgrade.
    #[test]
    fn production_keeps_the_installed_entry() {
        assert_eq!(
            keychain_service_for("https://api.klaay.com"),
            "com.klaay.klaayguard"
        );
        assert_eq!(
            keychain_service_for("https://api.klaay.com/"),
            "com.klaay.klaayguard"
        );
    }

    // A build pointed anywhere else must not share the production entry.
    // Without this, running a local build signs the real agent out and
    // replaces its token with one minted by a development server.
    #[test]
    fn any_other_target_gets_its_own_entry() {
        for base in [
            "http://localhost:61521",
            "http://127.0.0.1:3000",
            "https://api.staging.klaay.com",
        ] {
            let service = keychain_service_for(base);
            assert_ne!(
                service, "com.klaay.klaayguard",
                "{base} shared the production entry"
            );
            assert!(service.starts_with("com.klaay.klaayguard."), "{service}");
        }
    }

    // Two different non-production targets must not collide either, so a
    // staging agent and a local one can coexist on one machine.
    #[test]
    fn two_non_production_targets_do_not_collide() {
        assert_ne!(
            keychain_service_for("http://localhost:61521"),
            keychain_service_for("https://api.staging.klaay.com")
        );
    }

    // The file fallback needs the same split. Without it, a local build
    // overwrites the installed agent's token on any desktop with no Secret
    // Service daemon - the very case the fallback exists to serve.
    #[test]
    fn the_file_fallback_splits_the_same_way() {
        let prod = credential_file_in("https://api.klaay.com", "auth_token");
        let local = credential_file_in("http://localhost:61521", "auth_token");

        assert_ne!(prod, local);
        assert!(
            prod.as_ref()
                .unwrap()
                .to_string_lossy()
                .contains("/credentials/"),
            "production path changed: {prod:?}"
        );
    }

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
