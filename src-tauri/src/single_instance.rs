// SPDX-License-Identifier: GPL-3.0-or-later
//! One agent per machine, claimed with an atomic file lock.
//!
//! `tauri-plugin-single-instance` guards macOS with a socket in `/tmp`, and it
//! unlinks the path *before* it binds (`platform_impl/macos.rs:33-34`). Two
//! agents that start milliseconds apart therefore both find no socket, both
//! unlink, and both bind: each one believes it is alone, and neither can ever
//! see the other. That is PROD-4603 — two tray icons after a self-update, the
//! device double-reporting every 15 minutes.
//!
//! `flock(LOCK_EX | LOCK_NB)` is one syscall, so exactly one caller wins. The
//! kernel drops the lock when the holder dies, so there is no stale file to
//! clean up and no path where an exiting agent strips a live agent's claim.
//!
//! Windows (a named mutex) and Linux (a D-Bus name) are already atomic, so they
//! keep the plugin. This module serves macOS, and compiles under `test` so the
//! Linux CI runner exercises it.

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// What happened when this process tried to become the agent.
#[derive(Debug)]
pub(crate) enum Claim {
    /// This process owns the machine. Hold the file for the whole process
    /// lifetime: `flock` binds to the open file description, so dropping the
    /// `File` releases the lock without a sound.
    Held(File),
    /// Another agent owns it. This process must exit.
    Taken,
    /// The lock could not be evaluated. The caller runs anyway and reports it:
    /// for an always-on security agent, no agent is worse than two.
    Unavailable(String),
}

/// The lock file for a build that talks to `api_base_url`.
///
/// Keyed the same way as the credential store, so a developer build pointed at
/// localhost runs alongside the installed production agent — the behaviour the
/// plugin registration at `lib.rs` has always had.
///
/// Callers pass the *compile-time* API base, never the runtime one. The runtime
/// value comes from the LaunchAgent plist's `EnvironmentVariables`, which any
/// build can rewrite; keying on it would let a poisoned plist hand two agents
/// two different locks.
pub(crate) fn agent_lock_path(api_base_url: &str) -> Option<PathBuf> {
    let name = match crate::keychain::target_suffix(api_base_url) {
        None => "agent.lock".to_string(),
        Some(suffix) => format!("agent-{suffix}.lock"),
    };
    dirs::data_local_dir().map(|d| d.join("com.klaay.app").join(name))
}

/// Claim the lock, retrying briefly before conceding.
///
/// `launchctl kickstart -k` SIGKILLs the running agent and starts its
/// replacement at once, and the dead process releases its lock asynchronously.
/// A single failed attempt therefore means "my predecessor is dying", not
/// "another agent is healthy". Conceding immediately would turn a handover of a
/// few hundred milliseconds into a machine with no agent at all.
///
/// `attempts` and `backoff` are parameters so the retry rule is testable
/// without waiting on a real clock.
pub(crate) fn claim_agent_lock(path: &Path, attempts: u32, backoff: Duration) -> Claim {
    let attempts = attempts.max(1);
    for attempt in 0..attempts {
        match try_claim(path) {
            Ok(Some(file)) => return Claim::Held(file),
            Ok(None) => {
                if attempt + 1 < attempts && !backoff.is_zero() {
                    std::thread::sleep(backoff);
                }
            }
            // A lock that cannot be evaluated will not start working on the
            // next pass, so stop rather than sleep through the retries.
            Err(e) => return Claim::Unavailable(format!("{path:?}: {e}")),
        }
    }
    Claim::Taken
}

/// Whether `file` still names the inode that `path` resolves to.
///
/// `flock` locks an inode, not a name. An agent that opens the lock file and is
/// then overtaken — the path replaced before it locks — ends up holding an
/// orphaned inode nobody will look up again, and would run beside the agent
/// holding the live one. Checking after the lock closes that window.
///
/// It does not close everything. If the lock file is deleted while an agent
/// holds it, the next agent creates a fresh inode and legitimately locks that;
/// no file lock can prevent it, only a watchdog that re-checks and stands down.
/// The agent never deletes its own lock file, so this needs someone to remove
/// `~/Library/Application Support/com.klaay.app/` under a running agent, and
/// the next restart re-establishes a single lock.
fn same_inode(file: &File, path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let held = file.metadata()?;
    match std::fs::metadata(path) {
        Ok(on_disk) => Ok(held.dev() == on_disk.dev() && held.ino() == on_disk.ino()),
        // The name is gone, so the lock this process holds guards nothing that
        // a later agent would find. Treat it as lost.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// One attempt: `Ok(Some(file))` holds it, `Ok(None)` means someone else does
/// (or the file was replaced), `Err` means the lock could not be evaluated.
fn try_claim(path: &Path) -> std::io::Result<Option<File>> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Rust opens with O_CLOEXEC. Keep it that way: an fd that leaks across an
    // exec into the osquery sidecar would hold this lock after the agent dies,
    // and launchd could never start a replacement. Never use libc::open here.
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;

    if let Err(e) = nix::fcntl::flock(
        file.as_raw_fd(),
        nix::fcntl::FlockArg::LockExclusiveNonblock,
    ) {
        if e == nix::errno::Errno::EWOULDBLOCK {
            return Ok(None);
        }
        return Err(std::io::Error::from_raw_os_error(e as i32));
    }

    if !same_inode(&file, path)? {
        return Ok(None);
    }
    Ok(Some(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A private path per test, mirroring `keychain.rs`'s `unique_path`.
    fn unique_path(name: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("klaayguard-lock-test-{}-{}", std::process::id(), n))
            .join(name)
    }

    fn held(claim: Claim) -> File {
        match claim {
            Claim::Held(f) => f,
            other => panic!("expected the lock to be held, got {other:?}"),
        }
    }

    const NOW: Duration = Duration::from_millis(0);

    /// The defect this module exists to close: a second agent must not be able
    /// to claim a machine that already has one.
    #[test]
    fn a_second_claim_on_the_same_path_is_refused() {
        let path = unique_path("agent.lock");
        let first = held(claim_agent_lock(&path, 1, NOW));

        match claim_agent_lock(&path, 1, NOW) {
            Claim::Taken => {}
            other => panic!("a second agent claimed the same machine: {other:?}"),
        }

        drop(first);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// When the holder goes away the kernel releases the lock, so the next
    /// agent starts cleanly. This is what makes the relaunch after an update
    /// work without any cleanup step.
    #[test]
    fn the_lock_is_free_again_once_the_holder_drops_it() {
        let path = unique_path("agent.lock");
        drop(held(claim_agent_lock(&path, 1, NOW)));

        let second = held(claim_agent_lock(&path, 1, NOW));

        drop(second);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// The retry exists for the `kickstart -k` handover. Ask for several
    /// attempts while the lock is genuinely held: it must still concede rather
    /// than hang or claim.
    #[test]
    fn a_held_lock_is_conceded_after_the_attempts_run_out() {
        let path = unique_path("agent.lock");
        let first = held(claim_agent_lock(&path, 1, NOW));

        match claim_agent_lock(&path, 3, NOW) {
            Claim::Taken => {}
            other => panic!("expected the loser to concede, got {other:?}"),
        }

        drop(first);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// The race `same_inode` exists to close: one agent opens the lock file,
    /// and before it can lock the file the path is replaced. Its `flock` then
    /// succeeds on an orphaned inode nobody will ever look up again, so without
    /// this check it would run beside the agent holding the live one.
    #[test]
    fn a_lock_on_a_replaced_file_is_not_the_machines_lock() {
        let path = unique_path("agent.lock");
        let orphan = held(claim_agent_lock(&path, 1, NOW));

        // Another process replaces the path with a fresh inode.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"").unwrap();

        assert!(
            !same_inode(&orphan, &path).unwrap(),
            "a lock on a replaced file was mistaken for the machine's lock"
        );

        drop(orphan);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// The path vanishing is the same loss, and must read the same way.
    #[test]
    fn a_lock_on_a_deleted_file_is_not_the_machines_lock() {
        let path = unique_path("agent.lock");
        let orphan = held(claim_agent_lock(&path, 1, NOW));

        std::fs::remove_file(&path).unwrap();

        assert!(
            !same_inode(&orphan, &path).unwrap(),
            "a lock on a deleted file was mistaken for the machine's lock"
        );

        drop(orphan);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// A production build and a developer build must not fight over one lock.
    #[test]
    fn two_api_targets_do_not_share_a_lock() {
        let prod = agent_lock_path("https://api.klaay.com").expect("production path");
        let dev = agent_lock_path("http://localhost:3000").expect("dev path");
        assert_ne!(prod, dev);
    }

    /// Production keeps one name whatever the trailing slash, so two production
    /// agents always meet on the same lock.
    #[test]
    fn production_shares_one_lock_whatever_the_trailing_slash() {
        let bare = agent_lock_path("https://api.klaay.com").expect("bare");
        let slashed = agent_lock_path("https://api.klaay.com/").expect("slashed");
        assert_eq!(bare, slashed);
    }

    /// The lock belongs beside the agent's own data, not in world-writable
    /// `/tmp` where any account on the machine can create the path first.
    #[test]
    fn the_lock_lives_under_the_app_data_directory() {
        let path = agent_lock_path("https://api.klaay.com").expect("production path");
        assert!(
            path.to_string_lossy().contains("com.klaay.app"),
            "lock escaped the app data directory: {path:?}"
        );
        assert!(
            !path.starts_with("/tmp") && !path.starts_with("/private/tmp"),
            "lock sits in world-writable temp: {path:?}"
        );
    }
}
