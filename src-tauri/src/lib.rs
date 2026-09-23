// SPDX-License-Identifier: GPL-3.0-or-later
//! KlaayGuard - Security Monitoring Application
//!
//! This application provides continuous security monitoring on edge devices.
//! Key security features:
//! - Runs as background service (hidden from dock on macOS)
//! - No quit option in system tray to prevent easy termination
//! - Automatic updates for security patches
//! - System tray interface for minimal user interaction
//!
//! Security Design:
//! - App cannot be easily terminated by end users
//! - Background operation ensures continuous monitoring
//! - System tray provides controlled access to app functionality

mod keychain;
mod sign_in;
// macOS claims its single-instance lock here. `test` is in the gate so the
// Linux CI runner, which is the only one that runs `cargo test`, exercises it.
#[cfg(all(unix, any(target_os = "macos", test)))]
mod single_instance;
use sentry::{self, Level};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tauri::{Emitter, Manager};
use tauri_plugin_opener::OpenerExt;
use tauri_plugin_shell::ShellExt;
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};

/// Shared application state for background operations. The locks are
/// `std::sync`: every critical section is one clone, take, or assignment,
/// never held across an `.await`, so the main thread, plugin callbacks, and
/// tokio tasks all use the same plain API. (An async lock forced `block_on`
/// calls, which panic inside a tokio task.)
pub struct AppState {
    pub auth_token: RwLock<Option<String>>,
    pub api_base_url: String,
    pub last_attempt_at: RwLock<Option<Instant>>,
    pub last_focus_at: RwLock<Option<Instant>>, // debounce for the sign-in nudge
    /// The device identity, resolved once per process (persisted by keychain).
    pub device_identity: RwLock<Option<String>>,
    /// The signed-in person's name, or their email when the account carries no
    /// name. `None` until the API names them, and again after a sign out.
    pub user_label: RwLock<Option<String>>,
    /// Woken when a token is (re)acquired, so a collection runs at once.
    pub token_acquired: tokio::sync::Notify,
    /// Linux: whether the tray icon built, and whether a StatusNotifier host
    /// is on the bus to show it. Setup writes both; the sign-in nudge reads
    /// them to decide whether it must open the fallback window instead.
    pub tray_built: std::sync::atomic::AtomicBool,
    pub tray_watcher_present: std::sync::atomic::AtomicBool,
}

impl AppState {
    /// Take up a session: the token, and the name of whoever holds it. The two
    /// always move together. A token the API could not name carries no name, so
    /// the last holder never sits above this one.
    fn adopt_session(&self, token: String, label: Option<String>) {
        *lock_write(&self.auth_token) = Some(token);
        *lock_write(&self.user_label) = label;
    }

    /// Drop the session. Every path that stops using a token calls this, so the
    /// tray never names a person the agent no longer reports for.
    ///
    /// Keep the token first. `name_holder_of` reads the token, finds it still
    /// live, and writes the label; clearing the token first is what makes that
    /// read fail. Reverse these two lines and a `/me` reply in flight writes
    /// the name back over the sign out.
    fn clear_session(&self) {
        *lock_write(&self.auth_token) = None;
        *lock_write(&self.user_label) = None;
    }

    /// Name the holder of `token`, but only while that token is still the live
    /// one. A `/me` reply that lands after a sign out describes a session that
    /// has ended, and must not name it.
    /// Hold the token guard across the label write. Dropping it first leaves a
    /// gap in which `clear_session` runs to completion, and this line then
    /// writes the name back after the sign out cleared it — a tray that names a
    /// person beside a red dot, which nothing clears until the next sign in.
    ///
    /// The guard is a barrier over one ordering: `clear_session` clears
    /// `auth_token` before `user_label`. Swap those two lines and the bug is
    /// back, because neither of them holds its guard past its own semicolon —
    /// the sign out would clear the label first, this line would write it
    /// again, and the token would go last.
    fn name_holder_of(&self, token: Option<&str>, label: Option<String>) {
        let held_token = lock_read(&self.auth_token);
        if held_token.as_deref() != token {
            return;
        }
        *lock_write(&self.user_label) = label;
    }
}

/// Read an AppState lock. A poisoned lock cannot hold a half-updated value
/// here (each section is one assignment or clone), so recover the guard
/// instead of propagating another thread's panic.
fn lock_read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

/// Write an AppState lock; see `lock_read`.
fn lock_write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

// Keychain access is centralized in src-tauri/src/keychain.rs

fn add_breadcrumb(category: &str, message: &str, level: Level) {
    let mut data = std::collections::BTreeMap::new();
    data.insert(
        "ts".to_string(),
        serde_json::json!(chrono::Utc::now().to_rfc3339()),
    );
    sentry::add_breadcrumb(sentry::Breadcrumb {
        ty: "default".to_string(),
        category: Some(category.to_string()),
        message: Some(message.to_string()),
        level,
        data,
        ..Default::default()
    });
}

/// Lower-case hex of a byte slice.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Defense-in-depth against a compromised/MITM'd config endpoint: only accept a
/// single read-only osquery statement. osquery can still read arbitrary user-readable
/// files via tables like `file`/`hash`, so this does not make the SQL harmless — but it
/// refuses anything that isn't one plain `SELECT` (or a `WITH …` CTE), blocking stacked
/// statements (`SELECT 1; ATTACH …`), non-query verbs, and DML hidden behind a CTE.
/// The engine-level control is the `--disable_tables` list passed to the sidecar in
/// `execute_sql_batch`, which is what actually keeps a SELECT off the network.
fn is_read_only_query(sql: &str) -> bool {
    let trimmed = sql.trim().trim_end_matches(';').trim();
    // Any remaining ';' means a second statement was stacked on.
    if trimmed.contains(';') {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if !(lower.starts_with("select") || lower.starts_with("with")) {
        return false;
    }
    // SQLite accepts DML behind a CTE (`WITH t AS (...) DELETE FROM x`), so a
    // `with` prefix alone is not read-only. osquery's tables refuse writes
    // anyway; this keeps the guard honest about what it admits.
    !lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|tok| matches!(tok, "insert" | "update" | "delete" | "replace"))
}

/// Whether a config item's `platform` tag matches this host's OS. Mirrors
/// osquery query-pack semantics: absent / empty / "all" / "any" runs
/// everywhere; a comma-separated list runs where any entry matches; "posix"
/// runs on linux and macos; "ubuntu"/"centos" are linux; any other value must
/// equal the OS string (`std::env::consts::OS`: "linux" / "macos" /
/// "windows"). `os` is a parameter so tests pin every branch without
/// cross-compiling. Backward compatible: an item with no tag always runs.
fn platform_matches(tag: Option<&str>, os: &str) -> bool {
    let Some(tag) = tag else { return true };
    if tag.trim().is_empty() {
        return true;
    }
    tag.split(',')
        .map(|name| name.trim().to_ascii_lowercase())
        .any(|name| match name.as_str() {
            "" | "all" | "any" | "null" => true,
            "posix" => os == "linux" || os == "macos",
            "linux" | "ubuntu" | "centos" => os == "linux",
            // osquery names macOS "darwin"; Rust's OS string is "macos". Treat both
            // as the same platform so the Klaay API's "darwin" tag matches a macOS host.
            "darwin" | "macos" => os == "macos",
            other => other == os,
        })
}

/// One resolved collection item from /klaayguard/config, after platform filter.
#[derive(Debug, PartialEq)]
enum CollectionItem {
    /// Default: run this read-only SQL through the osquery sidecar.
    Osquery { id: String, sql: String },
    /// Native: resolve `check` with in-process Rust, no osquery. Used for facts
    /// osquery cannot supply unprivileged (Linux disk encryption, screen lock).
    Builtin { id: String, check: String },
}

/// Turn the /klaayguard/config payload into collection items for `os`. Items
/// whose `platform` tag does not match `os` are skipped. An item with
/// `type: "builtin"` (and a `check` name) resolves natively; otherwise it is
/// an osquery item — explicit `sql` or a default `SELECT * FROM <id>`, dropped
/// if it is not a single read-only query (see `is_read_only_query`).
fn parse_config_items(cfg: &Value, os: &str) -> Vec<CollectionItem> {
    cfg.get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let id = item.get("id").and_then(|v| v.as_str())?;
                    let platform = item.get("platform").and_then(|v| v.as_str());
                    if !platform_matches(platform, os) {
                        return None;
                    }
                    // kiln marks a native check with `type: "builtin"` (its
                    // config request spec pins the spelling). The agent once
                    // read a `source` key nothing ever sent, so every builtin
                    // ran as `SELECT * FROM <id>` through osquery and the
                    // native Linux checks never executed in the field.
                    let is_builtin = item.get("type").and_then(|v| v.as_str()) == Some("builtin");
                    if is_builtin {
                        return match item.get("check").and_then(|v| v.as_str()) {
                            Some(check) => Some(CollectionItem::Builtin {
                                id: id.to_string(),
                                check: check.to_string(),
                            }),
                            None => {
                                log::warn!("builtin config item missing 'check' id={}", id);
                                add_breadcrumb(
                                    "collection",
                                    &format!("builtin_check_missing id={}", id),
                                    Level::Warning,
                                );
                                None
                            }
                        };
                    }
                    let sql = item
                        .get("sql")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("SELECT * FROM {}", id));
                    if !is_read_only_query(&sql) {
                        log::warn!("rejecting non-read-only config query id={}", id);
                        add_breadcrumb(
                            "collection",
                            &format!("config_query_rejected id={}", id),
                            Level::Warning,
                        );
                        return None;
                    }
                    Some(CollectionItem::Osquery {
                        id: id.to_string(),
                        sql,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve a native (non-osquery) check by name, returning a JSON array of row
/// objects in the same shape osquery emits, so `build_payload_items` treats
/// native and osquery rows identically. An unknown or unsupported check yields
/// an empty array — an honest "no rows", never an error that aborts the cycle.
fn run_builtin_check(check: &str) -> Value {
    match check {
        #[cfg(target_os = "linux")]
        "disk_encryption" => collect_disk_encryption(),
        #[cfg(target_os = "linux")]
        "screenlock" => collect_screenlock(),
        #[cfg(target_os = "windows")]
        "screenlock" => collect_screenlock_windows(),
        #[cfg(target_os = "windows")]
        "disk_encryption" => collect_disk_encryption_windows(),
        #[cfg(target_os = "windows")]
        "password_policy" => collect_password_policy_windows(),
        other => {
            log::warn!("unknown or unsupported builtin check '{}'", other);
            add_breadcrumb(
                "collection",
                &format!("builtin_check_unsupported '{}'", other),
                Level::Warning,
            );
            json!([])
        }
    }
}

// ---------------------------------------------------------------------------
// Native Linux and Windows posture collectors (disk encryption, screen lock).
// osquery cannot supply these unprivileged: disk_encryption needs root and
// mis-reports LUKS, there is no Linux screenlock table, and the Windows
// registry table needs anchored keys. Pure parsers are unit-tested; thin IO
// wrappers are not. Every path degrades to "unknown", never a false "no",
// when a mechanism cannot be seen without root.
// ---------------------------------------------------------------------------

/// One block device flattened from `lsblk -J`, with encryption context.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone)]
struct FlatDev {
    // Every mountpoint of this device. A btrfs device is mounted at several
    // subvolumes at once, and `/` may be only one of them, so we must keep the
    // whole list — not just the first — or an encrypted root reads "unknown".
    mountpoints: Vec<String>,
    kind: String,          // lsblk TYPE: part, crypt, lvm, disk, ...
    on_crypt: bool,        // this device or an ancestor is a dm-crypt mapper
    parent_fstype: String, // the parent's FSTYPE (crypto_LUKS marks LUKS)
}

/// Flatten the `lsblk -J` block-device tree, propagating a dm-crypt ancestor
/// flag and each node's parent fstype down the children.
#[cfg(any(target_os = "linux", test))]
fn parse_lsblk(json: &str) -> Vec<FlatDev> {
    fn field(v: &Value, k: &str) -> String {
        // lsblk emits null for empty fields, and mountpoint may be `mountpoints`.
        v.get(k)
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default()
    }
    // All mountpoints: the singular `mountpoint` plus every entry of the
    // `mountpoints` array (newer util-linux), de-duplicated, nulls dropped.
    fn mountpoints_of(v: &Value) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Some(mp) = v.get("mountpoint").and_then(|x| x.as_str()) {
            if !mp.is_empty() {
                out.push(mp.to_string());
            }
        }
        if let Some(arr) = v.get("mountpoints").and_then(|x| x.as_array()) {
            for m in arr.iter().filter_map(|m| m.as_str()) {
                if !m.is_empty() && !out.iter().any(|x| x == m) {
                    out.push(m.to_string());
                }
            }
        }
        out
    }
    fn walk(node: &Value, parent_on_crypt: bool, parent_fstype: &str, out: &mut Vec<FlatDev>) {
        let kind = field(node, "type");
        let fstype = field(node, "fstype");
        let on_crypt = parent_on_crypt || kind == "crypt";
        out.push(FlatDev {
            mountpoints: mountpoints_of(node),
            kind: kind.clone(),
            on_crypt,
            parent_fstype: parent_fstype.to_string(),
        });
        if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
            for child in children {
                walk(child, on_crypt, &fstype, out);
            }
        }
    }
    let parsed: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(devs) = parsed.get("blockdevices").and_then(|d| d.as_array()) {
        for dev in devs {
            walk(dev, false, "", &mut out);
        }
    }
    out
}

/// One /proc/mounts entry.
#[cfg(any(target_os = "linux", test))]
struct MountEntry {
    mountpoint: String,
    fstype: String,
}

/// Parse /proc/mounts into (mountpoint, fstype) entries.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_mounts(text: &str) -> Vec<MountEntry> {
    // /proc/mounts octal-escapes spaces and a few other chars in the path
    // (space = \040). Decode so a mountpoint with a space still matches.
    fn unescape(s: &str) -> String {
        // Decode into bytes: an escape is one byte of a possibly multi-byte
        // UTF-8 sequence (\303\251 is "é"), so pushing it as a char would
        // produce Latin-1 garbage.
        let mut out: Vec<u8> = Vec::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let oct: String = chars.clone().take(3).collect();
                if oct.len() == 3 && oct.chars().all(|d| ('0'..='7').contains(&d)) {
                    if let Ok(code) = u8::from_str_radix(&oct, 8) {
                        for _ in 0..3 {
                            chars.next();
                        }
                        out.push(code);
                        continue;
                    }
                }
            }
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let _device = f.next()?;
            let mountpoint = f.next()?;
            let fstype = f.next()?;
            Some(MountEntry {
                mountpoint: unescape(mountpoint),
                fstype: fstype.to_string(),
            })
        })
        .collect()
}

/// Whether the filesystem type at `mount` names a built-in encryption layer.
#[cfg(any(target_os = "linux", test))]
fn encrypted_mount_mechanism(fstype: &str) -> Option<&'static str> {
    match fstype {
        "ecryptfs" => Some("ecryptfs"),
        _ => None,
    }
}

/// Build the `disk_encryption` rows for `/` (and, best effort, home) from lsblk
/// topology and /proc/mounts. Emits one evidence row per encrypted device or
/// mount, plus a `summary` row with tri-state root/home determinations. A
/// mechanism that cannot be confirmed unprivileged reports "unknown", never
/// "no".
#[cfg(any(target_os = "linux", test))]
fn build_disk_encryption_rows(
    lsblk_json: Option<&str>,
    proc_mounts: &str,
    home: Option<&str>,
) -> Value {
    let devs = lsblk_json.map(parse_lsblk).unwrap_or_default();
    let mounts = parse_proc_mounts(proc_mounts);
    let mut rows: Vec<Value> = Vec::new();
    let mut mechanisms: Vec<String> = Vec::new();

    // Evidence: dm-crypt mappers from lsblk.
    for d in devs.iter().filter(|d| d.kind == "crypt") {
        let mechanism = if d.parent_fstype == "crypto_LUKS" {
            "luks"
        } else {
            "dm-crypt"
        };
        if !mechanisms.iter().any(|m| m == mechanism) {
            mechanisms.push(mechanism.to_string());
        }
        rows.push(json!({
            "kind": "device", "mechanism": mechanism, "encrypted": "yes",
            "mountpoints": d.mountpoints, "source": "lsblk",
            "detail": format!("dm-crypt mapper (parent fstype {})", d.parent_fstype)
        }));
    }
    // Evidence: encryption-bearing mount types (ecryptfs) from /proc/mounts.
    for m in &mounts {
        if let Some(mechanism) = encrypted_mount_mechanism(&m.fstype) {
            if !mechanisms.iter().any(|x| x == mechanism) {
                mechanisms.push(mechanism.to_string());
            }
            rows.push(json!({
                "kind": "device", "mechanism": mechanism, "encrypted": "yes",
                "mountpoint": m.mountpoint, "source": "/proc/mounts",
                "detail": format!("{} mount", mechanism)
            }));
        }
    }

    // Determine whether a given mountpoint is on encrypted storage.
    let determine = |target: &str| -> &'static str {
        // ecryptfs / other encrypted mount types.
        if mounts
            .iter()
            .any(|m| m.mountpoint == target && encrypted_mount_mechanism(&m.fstype).is_some())
        {
            return "yes";
        }
        // ZFS: encryption is a dataset property we cannot read unprivileged.
        if mounts
            .iter()
            .any(|m| m.mountpoint == target && m.fstype == "zfs")
        {
            return "unknown";
        }
        // dm-crypt/LUKS via lsblk: the device mounted at target sits on crypt.
        // A btrfs device carries many mountpoints, so match any of them.
        match devs
            .iter()
            .find(|d| d.mountpoints.iter().any(|m| m == target))
        {
            Some(d) => {
                if d.on_crypt {
                    "yes"
                } else {
                    "no"
                }
            }
            // The mount was not resolvable from lsblk (e.g. lsblk missing or
            // fscrypt on a plain fs): do not claim "no".
            None => "unknown",
        }
    };

    // A home directory is rarely a mountpoint itself: classify the mount it
    // lives on, the longest mountpoint that is a path prefix of it.
    let mount_of = |path: &str| -> String {
        let p = std::path::Path::new(path);
        mounts
            .iter()
            .map(|m| m.mountpoint.as_str())
            .chain(
                devs.iter()
                    .flat_map(|d| d.mountpoints.iter().map(String::as_str)),
            )
            .filter(|mp| p.starts_with(mp))
            .max_by_key(|mp| mp.len())
            .unwrap_or(path)
            .to_string()
    };

    let root_encrypted = determine("/");
    let home_encrypted = match home {
        Some(h) if !h.is_empty() => {
            let mount = mount_of(h);
            // Home on the root filesystem shares its determination.
            if mount == "/" {
                root_encrypted
            } else {
                determine(&mount)
            }
        }
        _ => "unknown",
    };

    rows.push(json!({
        "kind": "summary",
        "root_encrypted": root_encrypted,
        "home_encrypted": home_encrypted,
        "mechanisms": mechanisms,
        "source": "aggregate"
    }));
    Value::Array(rows)
}

/// Collect Linux disk-encryption posture (unprivileged). Runs `lsblk -J` and
/// reads /proc/mounts, then builds the rows. Falls back to sysfs-free /proc if
/// lsblk is unavailable (root determination then degrades to "unknown").
#[cfg(target_os = "linux")]
fn collect_disk_encryption() -> Value {
    let mut lsblk_cmd = std::process::Command::new("lsblk");
    lsblk_cmd.args([
        "-J",
        "-o",
        "NAME,KNAME,TYPE,FSTYPE,MOUNTPOINT,MOUNTPOINTS,PKNAME",
    ]);
    apply_appimage_sanitization(&mut lsblk_cmd);
    let lsblk = lsblk_cmd
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok());
    let proc_mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let home = dirs::home_dir().map(|h| h.to_string_lossy().into_owned());
    build_disk_encryption_rows(lsblk.as_deref(), &proc_mounts, home.as_deref())
}

/// The desktop environments whose screen-lock policy we can read.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq)]
enum Desktop {
    Gnome,
    Kde,
    Hyprland,
    Cinnamon,
    Mate,
    Xfce,
    Unknown,
}

/// Classify `XDG_CURRENT_DESKTOP` (colon-separated, case-insensitive; handles
/// values like "ubuntu:GNOME").
#[cfg(any(target_os = "linux", test))]
fn detect_desktop(xdg_current_desktop: Option<&str>) -> Desktop {
    let value = xdg_current_desktop.unwrap_or("").to_ascii_lowercase();
    for seg in value.split(':').map(|s| s.trim()) {
        match seg {
            // "ubuntu:GNOME" is GNOME; a lone "ubuntu" is GNOME-based too.
            "gnome" | "unity" | "ubuntu" => return Desktop::Gnome,
            "kde" => return Desktop::Kde,
            "hyprland" => return Desktop::Hyprland,
            // Mint sets exactly "X-Cinnamon".
            "x-cinnamon" | "cinnamon" => return Desktop::Cinnamon,
            "mate" => return Desktop::Mate,
            // Xubuntu sets "xubuntu:XFCE"; a plain XFCE session sets "XFCE".
            "xfce" => return Desktop::Xfce,
            _ => {}
        }
    }
    Desktop::Unknown
}

/// Parse a `gsettings get ... <bool>` result ("true"/"false" with a newline).
#[cfg(any(target_os = "linux", test))]
fn parse_gsettings_bool(out: &str) -> Option<bool> {
    match out.trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Parse a `gsettings get ... <uint>` result (e.g. "uint32 300").
#[cfg(any(target_os = "linux", test))]
fn parse_gsettings_uint(out: &str) -> Option<u64> {
    out.trim()
        .rsplit(|c: char| c.is_whitespace())
        .next()
        .and_then(|n| n.parse::<u64>().ok())
}

/// Parse the `[Daemon]` section of kscreenlockerrc: (autolock, timeout in
/// seconds). The file stores minutes; since Plasma 6.3 as a double, so "0.5"
/// is thirty seconds and must not round to a minute.
#[cfg(any(target_os = "linux", test))]
fn parse_kscreenlockerrc(text: &str) -> (Option<bool>, Option<u64>) {
    let mut in_daemon = false;
    let mut autolock = None;
    let mut timeout_secs = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_daemon = line.eq_ignore_ascii_case("[daemon]");
            continue;
        }
        if !in_daemon {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k.trim().to_ascii_lowercase().as_str() {
                "autolock" => autolock = parse_gsettings_bool(&v.trim().to_ascii_lowercase()),
                "timeout" => {
                    timeout_secs = v
                        .trim()
                        .parse::<f64>()
                        .ok()
                        .filter(|m| m.is_finite() && *m >= 0.0)
                        .map(|m| (m * 60.0).round() as u64)
                }
                _ => {}
            }
        }
    }
    (autolock, timeout_secs)
}

/// Parse a hypridle config for the first lock listener's timeout (seconds). A
/// listener counts as a lock if its `on-timeout` runs hyprlock or
/// `loginctl lock-session`.
#[cfg(any(target_os = "linux", test))]
fn parse_hypridle_config(text: &str) -> Option<u64> {
    let mut depth = 0i32;
    let mut in_listener = false;
    let mut timeout: Option<u64> = None;
    let mut locks = false;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.contains("listener") && line.contains('{') {
            in_listener = true;
            depth = 1;
            timeout = None;
            locks = false;
            continue;
        }
        if in_listener {
            depth += line.matches('{').count() as i32;
            depth -= line.matches('}').count() as i32;
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "timeout" => timeout = v.trim().parse::<u64>().ok(),
                    "on-timeout" => {
                        // Any lock command counts: hyprlock, loginctl
                        // lock-session, or a custom wrapper like
                        // omarchy-system-lock. Exclude "unlock".
                        let v = v.to_ascii_lowercase();
                        if v.contains("lock") && !v.contains("unlock") {
                            locks = true;
                        }
                    }
                    _ => {}
                }
            }
            if depth <= 0 {
                in_listener = false;
                if locks {
                    if let Some(t) = timeout {
                        return Some(t);
                    }
                }
            }
        }
    }
    None
}

/// Assemble the single screenlock row. One shape for every platform: the
/// backend reads the same five fields whichever agent sent them.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn screenlock_row(
    de: &str,
    enabled: &str,
    delay_seconds: Option<u64>,
    source: &str,
    detail: &str,
) -> Value {
    json!([{
        "desktop_environment": de,
        "enabled": enabled,
        "delay_seconds": delay_seconds,
        "source": source,
        "detail": detail,
    }])
}

/// Screen-lock row for the gsettings desktops, GNOME and Cinnamon, which
/// share one schema shape. Lock engages only when it is enabled AND the idle
/// delay is non-zero (0 = never triggers). The time to a locked screen is
/// idle-delay plus lock-delay, both in seconds; reporting idle-delay alone
/// under-reports a user who set a one-hour lock delay.
#[cfg(any(target_os = "linux", test))]
fn screenlock_row_gsettings(
    de: &str,
    lock_enabled: Option<bool>,
    idle_delay: Option<u64>,
    lock_delay: Option<u64>,
) -> Value {
    let extra = lock_delay.unwrap_or(0);
    match (lock_enabled, idle_delay) {
        (Some(true), Some(d)) if d > 0 => screenlock_row(
            de,
            "yes",
            Some(d + extra),
            "gsettings",
            &format!("lock-enabled=true, idle-delay={}, lock-delay={}", d, extra),
        ),
        (Some(true), Some(0)) => screenlock_row(
            de,
            "no",
            Some(0),
            "gsettings",
            "lock enabled but idle-delay=0, so it never triggers",
        ),
        (Some(false), _) => screenlock_row(de, "no", idle_delay, "gsettings", "lock-enabled=false"),
        _ => screenlock_row(
            de,
            "unknown",
            idle_delay,
            "gsettings",
            "gsettings unavailable",
        ),
    }
}

#[cfg(any(target_os = "linux", test))]
fn screenlock_row_gnome(
    lock_enabled: Option<bool>,
    idle_delay: Option<u64>,
    lock_delay: Option<u64>,
) -> Value {
    screenlock_row_gsettings("gnome", lock_enabled, idle_delay, lock_delay)
}

/// MATE screen-lock row. Its units are MINUTES (org.mate.session idle-delay,
/// org.mate.screensaver lock-delay), unlike GNOME and Cinnamon, and the
/// saver must be both idle-activated and set to lock.
#[cfg(any(target_os = "linux", test))]
fn screenlock_row_mate(
    idle_activation: Option<bool>,
    lock_enabled: Option<bool>,
    idle_delay_min: Option<u64>,
    lock_delay_min: Option<u64>,
) -> Value {
    let extra = lock_delay_min.unwrap_or(0);
    let secs = idle_delay_min.map(|m| m * 60);
    match (idle_activation, lock_enabled, idle_delay_min) {
        (Some(true), Some(true), Some(d)) if d > 0 => screenlock_row(
            "mate",
            "yes",
            Some((d + extra) * 60),
            "gsettings",
            &format!(
                "idle-activation-enabled=true, lock-enabled=true, idle-delay={}min, lock-delay={}min",
                d, extra
            ),
        ),
        (Some(true), Some(true), Some(0)) => screenlock_row(
            "mate",
            "no",
            Some(0),
            "gsettings",
            "lock enabled but idle-delay=0, so it never triggers",
        ),
        (Some(false), _, _) => screenlock_row(
            "mate",
            "no",
            secs,
            "gsettings",
            "idle-activation-enabled=false",
        ),
        (_, Some(false), _) => screenlock_row("mate", "no", secs, "gsettings", "lock-enabled=false"),
        _ => screenlock_row("mate", "unknown", secs, "gsettings", "gsettings unavailable"),
    }
}

/// Plasma's shipped defaults (kscreenlockersettings.kcfg): Autolock=true,
/// Timeout=5 minutes. KConfig writes only values that differ from the
/// schema, so an untouched, compliant machine has no key at all.
#[cfg(any(target_os = "linux", test))]
const KDE_DEFAULT_TIMEOUT_SECS: u64 = 300;

/// KDE screenlock row from kscreenlockerrc. An absent key means the Plasma
/// default applies; it is not unknown. Reporting it as unknown left the
/// secure majority blank and only the users who turned the lock off visible.
#[cfg(any(target_os = "linux", test))]
fn screenlock_row_kde(autolock: Option<bool>, timeout_secs: Option<u64>) -> Value {
    let autolock_src = if autolock.is_some() {
        "file"
    } else {
        "Plasma default"
    };
    let timeout_src = if timeout_secs.is_some() {
        "file"
    } else {
        "Plasma default"
    };
    let timeout = timeout_secs.unwrap_or(KDE_DEFAULT_TIMEOUT_SECS);
    let detail = format!(
        "Autolock={} ({}), Timeout={}s ({})",
        autolock.unwrap_or(true),
        autolock_src,
        timeout,
        timeout_src
    );
    match (autolock.unwrap_or(true), timeout) {
        (true, 0) => screenlock_row(
            "kde",
            "no",
            Some(0),
            "kscreenlockerrc",
            &format!("{}; a zero timeout never triggers", detail),
        ),
        (true, t) => screenlock_row("kde", "yes", Some(t), "kscreenlockerrc", &detail),
        (false, t) => screenlock_row("kde", "no", Some(t), "kscreenlockerrc", &detail),
    }
}

/// Hyprland screenlock row from a hypridle timeout (seconds), or unknown.
#[cfg(any(target_os = "linux", test))]
fn screenlock_row_hyprland(lock_timeout: Option<u64>) -> Value {
    match lock_timeout {
        // Same rule as GNOME and Windows: a lock with a zero timeout never
        // fires, so it is not an enabled lock.
        Some(0) => screenlock_row(
            "hyprland",
            "no",
            Some(0),
            "hypridle",
            "lock listener has timeout 0",
        ),
        Some(t) => screenlock_row(
            "hyprland",
            "yes",
            Some(t),
            "hypridle",
            "lock listener present",
        ),
        None => screenlock_row(
            "hyprland",
            "unknown",
            None,
            "hypridle",
            "no hypridle lock listener found",
        ),
    }
}

/// Read the X screensaver blank delay (seconds) from `xset q` output. The
/// line reads "  timeout:  600    cycle:  600". light-locker locks when X
/// blanks, so this delay is the first half of its lock time.
#[cfg(any(target_os = "linux", test))]
fn parse_xset_timeout(text: &str) -> Option<u64> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("timeout:") {
            return rest.split_whitespace().next()?.parse::<u64>().ok();
        }
    }
    None
}

/// xfce4-screensaver's own schema defaults (src/gs-prefs.h). xfconf keeps
/// only values that differ from them, so an untouched machine answers
/// nothing at all and every default below applies. Every one of them locks.
#[cfg(any(target_os = "linux", test))]
mod xfce_defaults {
    pub const SAVER_ENABLED: bool = true;
    pub const IDLE_ACTIVATION_ENABLED: bool = true;
    pub const IDLE_DELAY_MIN: u64 = 5;
    pub const LOCK_ENABLED: bool = true;
    pub const LOCK_WITH_SAVER_ENABLED: bool = true;
    pub const LOCK_WITH_SAVER_DELAY_MIN: u64 = 0;
}

/// XFCE screen-lock row from the xfce4-screensaver xfconf channel, which
/// XFCE 4.16 and later ship. Four switches must all be on for an idle lock:
/// `gs_listener` starts the saver only when `/saver/enabled` and
/// `/saver/idle-activation/enabled` are true, and `add_lock_timer` schedules
/// the lock only when `/lock/enabled` and `/lock/saver-activation/enabled`
/// are true. Both delays are in MINUTES. An absent key means the shipped
/// default, not unknown: reporting unknown would leave every compliant
/// machine blank, the defect the KDE row already had.
#[cfg(any(target_os = "linux", test))]
fn screenlock_row_xfce_screensaver(
    saver_enabled: Option<bool>,
    idle_activation: Option<bool>,
    idle_delay_min: Option<u64>,
    lock_enabled: Option<bool>,
    lock_with_saver: Option<bool>,
    lock_delay_min: Option<u64>,
) -> Value {
    let saver = saver_enabled.unwrap_or(xfce_defaults::SAVER_ENABLED);
    let idle_act = idle_activation.unwrap_or(xfce_defaults::IDLE_ACTIVATION_ENABLED);
    let idle = idle_delay_min.unwrap_or(xfce_defaults::IDLE_DELAY_MIN);
    let lock = lock_enabled.unwrap_or(xfce_defaults::LOCK_ENABLED);
    let lock_saver = lock_with_saver.unwrap_or(xfce_defaults::LOCK_WITH_SAVER_ENABLED);
    let grace = lock_delay_min.unwrap_or(xfce_defaults::LOCK_WITH_SAVER_DELAY_MIN);
    let detail = format!(
        "saver={}, idle-activation={}, idle-delay={}min, lock={}, \
         lock-on-saver={}, lock-delay={}min",
        saver, idle_act, idle, lock, lock_saver, grace
    );
    let total = (idle + grace) * 60;
    if !saver || !idle_act || !lock || !lock_saver {
        return screenlock_row("xfce", "no", Some(total), "xfce4-screensaver", &detail);
    }
    if idle == 0 {
        return screenlock_row(
            "xfce",
            "no",
            Some(0),
            "xfce4-screensaver",
            &format!("{}; idle-delay=0, so it never triggers", detail),
        );
    }
    screenlock_row("xfce", "yes", Some(total), "xfce4-screensaver", &detail)
}

/// light-locker's own default when the flag is absent (src/gs-monitor.c).
#[cfg(any(target_os = "linux", test))]
const LIGHT_LOCKER_DEFAULT_LOCK_AFTER: u64 = 5;

/// Read light-locker's lock delay (SECONDS) from its autostart entry, or
/// None when the entry is disabled. light-locker keeps no settings file: it
/// takes `--lock-after-screensaver=S` on the command line, and
/// light-locker-settings writes that flag into the autostart entry.
#[cfg(any(target_os = "linux", test))]
fn parse_light_locker_autostart(text: &str) -> Option<u64> {
    let mut exec = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Hidden=") {
            if v.trim().eq_ignore_ascii_case("true") {
                return None;
            }
        }
        if let Some(v) = line.strip_prefix("Exec=") {
            exec = Some(v.trim().to_string());
        }
    }
    let exec = exec?;
    Some(
        exec.split_whitespace()
            .find_map(|a| a.strip_prefix("--lock-after-screensaver="))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(LIGHT_LOCKER_DEFAULT_LOCK_AFTER),
    )
}

/// XFCE screen-lock row for light-locker, the locker XFCE 4.12 to 4.14 ship
/// and Debian still installs. light-locker holds no idle timer of its own:
/// it locks `lock-after-screensaver` seconds after the X screensaver blanks.
/// A zero X timeout means X never blanks, so the lock never fires.
#[cfg(any(target_os = "linux", test))]
fn screenlock_row_light_locker(
    lock_after_screensaver: Option<u64>,
    blank_timeout: Option<u64>,
) -> Value {
    let detail = format!(
        "lock-after-screensaver={}, X blank timeout={}",
        fmt_opt(lock_after_screensaver),
        fmt_opt(blank_timeout)
    );
    match (lock_after_screensaver, blank_timeout) {
        (None, _) => screenlock_row(
            "xfce",
            "no",
            None,
            "light-locker",
            &format!("{}; the autostart entry is disabled", detail),
        ),
        (_, None) => screenlock_row(
            "xfce",
            "unknown",
            None,
            "light-locker",
            &format!("{}; xset gave no timeout", detail),
        ),
        (_, Some(0)) => screenlock_row(
            "xfce",
            "no",
            Some(0),
            "light-locker",
            &format!("{}; X never blanks, so the lock never fires", detail),
        ),
        (Some(after), Some(blank)) => {
            screenlock_row("xfce", "yes", Some(blank + after), "light-locker", &detail)
        }
    }
}

/// `gsettings get <schema> <key>` as the desktop sees it. gsettings is a GLib
/// program. From an AppImage it must not load the bundled libgio, whose
/// module directory holds no dconf backend: it then answers with schema
/// defaults, a false "yes".
#[cfg(target_os = "linux")]
fn gsettings_get(schema: &str, key: &str) -> Option<String> {
    let mut cmd = std::process::Command::new("gsettings");
    cmd.args(["get", schema, key]);
    apply_appimage_sanitization(&mut cmd);
    cmd.output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
}

#[cfg(target_os = "linux")]
fn gsettings_bool(schema: &str, key: &str) -> Option<bool> {
    gsettings_get(schema, key).and_then(|s| parse_gsettings_bool(&s))
}

#[cfg(target_os = "linux")]
fn gsettings_uint(schema: &str, key: &str) -> Option<u64> {
    gsettings_get(schema, key).and_then(|s| parse_gsettings_uint(&s))
}

/// `xfconf-query -c <channel> -p <property>` as the desktop sees it. It
/// prints "true"/"false" for bools and a bare number for ints, so the
/// gsettings parsers read both. An unset property exits non-zero, which the
/// success filter turns into None.
#[cfg(target_os = "linux")]
fn xfconf_get(channel: &str, property: &str) -> Option<String> {
    let mut cmd = std::process::Command::new("xfconf-query");
    cmd.args(["-c", channel, "-p", property]);
    apply_appimage_sanitization(&mut cmd);
    cmd.output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
}

#[cfg(target_os = "linux")]
fn xfconf_bool(channel: &str, property: &str) -> Option<bool> {
    xfconf_get(channel, property).and_then(|s| parse_gsettings_bool(&s))
}

#[cfg(target_os = "linux")]
fn xfconf_uint(channel: &str, property: &str) -> Option<u64> {
    xfconf_get(channel, property).and_then(|s| parse_gsettings_uint(&s))
}

/// The X screensaver blank delay in seconds, from `xset q`.
#[cfg(target_os = "linux")]
fn xset_blank_timeout() -> Option<u64> {
    let mut cmd = std::process::Command::new("xset");
    cmd.arg("q");
    apply_appimage_sanitization(&mut cmd);
    cmd.output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| parse_xset_timeout(&s))
}

/// Whether a program is on this session's PATH.
#[cfg(target_os = "linux")]
fn binary_on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
        .unwrap_or(false)
}

/// The first readable autostart entry for `file_name`: the user's copy in
/// ~/.config/autostart hides the system one in /etc/xdg/autostart.
#[cfg(target_os = "linux")]
fn read_autostart_entry(file_name: &str) -> Option<String> {
    dirs::config_dir()
        .map(|c| c.join("autostart").join(file_name))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .or_else(|| {
            std::fs::read_to_string(std::path::Path::new("/etc/xdg/autostart").join(file_name)).ok()
        })
}

/// XFCE screen-lock posture. XFCE ships two lockers and only one runs: XFCE
/// 4.16 and later use xfce4-screensaver, XFCE 4.12 to 4.14 use light-locker.
/// Dispatch on which binary is installed, never on which xfconf keys answer:
/// on an untouched machine xfce4-screensaver has written no key at all, so a
/// key probe would send every compliant desktop down the light-locker path.
#[cfg(target_os = "linux")]
fn collect_screenlock_xfce() -> Value {
    if binary_on_path("xfce4-screensaver") {
        return screenlock_row_xfce_screensaver(
            xfconf_bool("xfce4-screensaver", "/saver/enabled"),
            xfconf_bool("xfce4-screensaver", "/saver/idle-activation/enabled"),
            xfconf_uint("xfce4-screensaver", "/saver/idle-activation/delay"),
            xfconf_bool("xfce4-screensaver", "/lock/enabled"),
            xfconf_bool("xfce4-screensaver", "/lock/saver-activation/enabled"),
            xfconf_uint("xfce4-screensaver", "/lock/saver-activation/delay"),
        );
    }
    if binary_on_path("light-locker") {
        return screenlock_row_light_locker(
            read_autostart_entry("light-locker.desktop")
                .as_deref()
                .and_then(parse_light_locker_autostart),
            xset_blank_timeout(),
        );
    }
    screenlock_row(
        "xfce",
        "unknown",
        None,
        "none",
        "neither xfce4-screensaver nor light-locker is installed",
    )
}

/// Hyprland and sway run no XDG autostart: the entry is written, nothing
/// reads it, the agent starts once and the device goes quiet, which the
/// dashboard cannot tell from a laptop in a drawer. GNOME, KDE, Cinnamon and
/// MATE run the entries themselves; on the rest, an inactive
/// xdg-desktop-autostart.target means no session component will either.
#[cfg(target_os = "linux")]
fn warn_if_autostart_unserved() {
    let desktop = detect_desktop(std::env::var("XDG_CURRENT_DESKTOP").ok().as_deref());
    if !matches!(desktop, Desktop::Hyprland | Desktop::Unknown) {
        return;
    }
    let mut cmd = std::process::Command::new("systemctl");
    cmd.args(["--user", "is-active", "xdg-desktop-autostart.target"]);
    apply_appimage_sanitization(&mut cmd);
    let active = cmd
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false);
    if !active {
        log::warn!(
            "autostart: desktop {:?} runs no XDG autostart and xdg-desktop-autostart.target is inactive; \
             the agent will not start at next login unless the session runs ~/.config/autostart (uwsm, dex, exec-once)",
            desktop
        );
        sentry::capture_message("autostart_unserved", Level::Warning);
    }
}

/// Collect Linux screen-lock posture (unprivileged) for the current desktop.
/// Dispatch is on XDG_CURRENT_DESKTOP, never on which schemas exist: Mint
/// installs the Cinnamon schemas on its MATE and XFCE editions too, so a
/// Cinnamon query answers there with a meaningless "true".
#[cfg(target_os = "linux")]
fn collect_screenlock() -> Value {
    match detect_desktop(std::env::var("XDG_CURRENT_DESKTOP").ok().as_deref()) {
        Desktop::Gnome => screenlock_row_gnome(
            gsettings_bool("org.gnome.desktop.screensaver", "lock-enabled"),
            gsettings_uint("org.gnome.desktop.session", "idle-delay"),
            gsettings_uint("org.gnome.desktop.screensaver", "lock-delay"),
        ),
        Desktop::Cinnamon => screenlock_row_gsettings(
            "cinnamon",
            gsettings_bool("org.cinnamon.desktop.screensaver", "lock-enabled"),
            gsettings_uint("org.cinnamon.desktop.session", "idle-delay"),
            gsettings_uint("org.cinnamon.desktop.screensaver", "lock-delay"),
        ),
        Desktop::Mate => screenlock_row_mate(
            gsettings_bool("org.mate.screensaver", "idle-activation-enabled"),
            gsettings_bool("org.mate.screensaver", "lock-enabled"),
            gsettings_uint("org.mate.session", "idle-delay"),
            gsettings_uint("org.mate.screensaver", "lock-delay"),
        ),
        Desktop::Kde => {
            // Admin policy in /etc/xdg applies under the user's file.
            let read = |p: std::path::PathBuf| std::fs::read_to_string(p).unwrap_or_default();
            let (sys_autolock, sys_timeout) =
                parse_kscreenlockerrc(&read("/etc/xdg/kscreenlockerrc".into()));
            let (autolock, timeout_secs) = dirs::config_dir()
                .map(|c| parse_kscreenlockerrc(&read(c.join("kscreenlockerrc"))))
                .unwrap_or((None, None));
            screenlock_row_kde(autolock.or(sys_autolock), timeout_secs.or(sys_timeout))
        }
        Desktop::Hyprland => {
            let text = dirs::config_dir()
                .map(|c| c.join("hypr/hypridle.conf"))
                .and_then(|p| std::fs::read_to_string(p).ok())
                .unwrap_or_default();
            screenlock_row_hyprland(parse_hypridle_config(&text))
        }
        Desktop::Xfce => collect_screenlock_xfce(),
        Desktop::Unknown => screenlock_row(
            "unknown",
            "unknown",
            None,
            "none",
            "no recognized XDG_CURRENT_DESKTOP",
        ),
    }
}

/// Spawn flag for a child of this windowless process: no console window.
/// `/S`, not this flag, is what makes an installer silent; this only stops a
/// console flashing when the agent itself was started from one.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The BitLocker state of one volume as Explorer reads it: the shell property
/// `System.Volume.BitLockerProtection` (PKEY {2d15a9a1-a556-4189-91ad-027458f11a07} 1717).
/// Unlike `Win32_EncryptableVolume`, `manage-bde`, and `Get-BitLockerVolume`,
/// this needs no elevation; it is what draws the padlock in File Explorer.
/// Verified on Windows 11 22621 against Get-BitLockerVolume: 2 = fully
/// decrypted, 7 = encryption pending a restart, 3 = encrypting (protection
/// still off), 1 = fully encrypted and on, 5 = suspended (encrypted, key in
/// the clear). 4 and 6 follow the same numbering and are not yet observed.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq)]
enum BitLockerProtection {
    /// 1: fully encrypted and protection on.
    On,
    /// 2: not encrypted.
    Off,
    /// 3: encryption in progress.
    Encrypting,
    /// 4: decryption in progress.
    Decrypting,
    /// 5: encrypted but protection suspended; the key is in the clear.
    Suspended,
    /// 6: encrypted and locked (no key available in this session).
    Locked,
    /// 7: encryption chosen, waiting for the restart that starts it.
    PendingRestart,
    Other(i64),
}

#[cfg(any(target_os = "windows", test))]
fn parse_bitlocker_protection(raw: Option<&str>) -> Option<BitLockerProtection> {
    let n = raw?.trim().parse::<i64>().ok()?;
    Some(match n {
        1 => BitLockerProtection::On,
        2 => BitLockerProtection::Off,
        3 => BitLockerProtection::Encrypting,
        4 => BitLockerProtection::Decrypting,
        5 => BitLockerProtection::Suspended,
        6 => BitLockerProtection::Locked,
        7 => BitLockerProtection::PendingRestart,
        other => BitLockerProtection::Other(other),
    })
}

/// Windows disk-encryption summary row, in the shape the Linux builtin emits
/// so the backend reads one shape. Only a fully protected volume is "yes":
/// a suspended volume has its key in the clear, and a volume still
/// encrypting is not yet protected. An unreadable property is "unknown",
/// never a false "no"; `unreadable_reason` says why, so a fleet whose
/// application-control policy blocks the read is distinguishable from a
/// property that is genuinely missing.
#[cfg(any(target_os = "windows", test))]
fn windows_disk_encryption_rows(
    drive: &str,
    status: Option<BitLockerProtection>,
    unreadable_reason: &str,
) -> Value {
    let (root_encrypted, mechanism, detail) = match status {
        Some(BitLockerProtection::On) => ("yes", "bitlocker", "protection on".to_string()),
        Some(BitLockerProtection::Locked) => ("yes", "bitlocker", "encrypted, locked".to_string()),
        Some(BitLockerProtection::Off) => ("no", "none", "not encrypted".to_string()),
        Some(BitLockerProtection::Suspended) => (
            "no",
            "bitlocker",
            "protection suspended; key in the clear".to_string(),
        ),
        Some(BitLockerProtection::Encrypting) => {
            ("no", "bitlocker", "encryption in progress".to_string())
        }
        Some(BitLockerProtection::Decrypting) => {
            ("no", "bitlocker", "decryption in progress".to_string())
        }
        Some(BitLockerProtection::PendingRestart) => {
            ("no", "none", "encryption pending a restart".to_string())
        }
        Some(BitLockerProtection::Other(n)) => (
            "unknown",
            "bitlocker",
            format!("unrecognised BitLockerProtection value {}", n),
        ),
        None => (
            "unknown",
            "none",
            if unreadable_reason.is_empty() {
                "System.Volume.BitLockerProtection not readable".to_string()
            } else {
                format!(
                    "System.Volume.BitLockerProtection not readable: {}",
                    unreadable_reason
                )
            },
        ),
    };
    json!([
        {
            "kind": "volume",
            "name": drive,
            "root_encrypted": root_encrypted,
            "mechanism": mechanism,
            "detail": detail,
            "source": "shell_property"
        },
        {
            "kind": "summary",
            "root_encrypted": root_encrypted,
            "home_encrypted": root_encrypted,
            "mechanisms": if mechanism == "none" { json!([]) } else { json!([mechanism]) },
            "source": "aggregate"
        }
    ])
}

/// Read the shell property for the system drive through PowerShell. The
/// Shell COM object is the same path Explorer uses and needs no elevation.
/// A spawn every 15 minutes is cheap; a COM binding in Rust is not worth it.
/// Under AppLocker/WDAC PowerShell runs in ConstrainedLanguage mode, where
/// `New-Object -ComObject` is refused; that case exits 3 so the row can say
/// the policy, not the property, is what blocked the read.
#[cfg(target_os = "windows")]
fn read_bitlocker_protection(drive: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let script = format!(
        "if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {{ exit 3 }}; \
         (New-Object -ComObject Shell.Application).NameSpace('{}').Self.ExtendedProperty('System.Volume.BitLockerProtection')",
        drive
    );
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("powershell spawn failed: {}", e))?;
    if out.status.code() == Some(3) {
        return Err("blocked by application control (PowerShell ConstrainedLanguage)".to_string());
    }
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        log::warn!(
            "bitlocker property read failed ({}): {}",
            out.status,
            stderr
        );
        return Err(format!("powershell {}", out.status));
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        Err("empty property".to_string())
    } else {
        Ok(text)
    }
}

/// Collect Windows disk-encryption posture for the system drive, unprivileged.
#[cfg(target_os = "windows")]
fn collect_disk_encryption_windows() -> Value {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    match read_bitlocker_protection(&drive) {
        Ok(raw) => {
            windows_disk_encryption_rows(&drive, parse_bitlocker_protection(Some(raw.as_str())), "")
        }
        Err(reason) => {
            log::warn!("bitlocker: {}", reason);
            add_breadcrumb(
                "collection",
                &format!("bitlocker_unreadable: {}", reason),
                Level::Warning,
            );
            windows_disk_encryption_rows(&drive, None, &reason)
        }
    }
}

/// The local account password and lockout policy, as `NetUserModalsGet`
/// returns it (levels 0 and 3). Ages and durations are seconds; the API
/// uses u32::MAX (TIMEQ_FOREVER) for "never".
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq)]
struct PasswordPolicy {
    min_password_len: u32,
    max_password_age_secs: u32,
    min_password_age_secs: u32,
    password_history_len: u32,
    lockout_threshold: u32,
    lockout_duration_secs: u32,
    lockout_window_secs: u32,
}

#[cfg(any(target_os = "windows", test))]
const TIMEQ_FOREVER: u32 = u32::MAX;

/// Seconds to whole units of `unit_secs`, or None for "never" (TIMEQ_FOREVER).
#[cfg(any(target_os = "windows", test))]
fn policy_units(secs: u32, unit_secs: u64) -> Option<u64> {
    (secs != TIMEQ_FOREVER).then(|| u64::from(secs) / unit_secs)
}

#[cfg(any(target_os = "windows", test))]
fn policy_days(secs: u32) -> Option<u64> {
    policy_units(secs, 86_400)
}

#[cfg(any(target_os = "windows", test))]
fn policy_minutes(secs: u32) -> Option<u64> {
    policy_units(secs, 60)
}

/// One row describing the local password and lockout policy. A lockout
/// threshold of 0 means accounts never lock; a null maximum age means
/// passwords never expire. An unreadable policy is one "unknown" row, never a
/// row of zeros that reads as "no policy". `NetUserModalsGet(NULL, ..)` reads
/// the local SAM, which governs local accounts only; `scope` says whether the
/// machine is domain-joined (its users' passwords are ruled by the domain, not
/// these numbers) so the backend does not grade a domain user by local
/// defaults.
#[cfg(any(target_os = "windows", test))]
fn password_policy_rows(policy: Option<PasswordPolicy>, scope: &str) -> Value {
    match policy {
        Some(p) => json!([{
            "minimum_password_length": p.min_password_len,
            "maximum_password_age_days": policy_days(p.max_password_age_secs),
            "minimum_password_age_days": policy_days(p.min_password_age_secs),
            "password_history_size": p.password_history_len,
            "lockout_threshold": p.lockout_threshold,
            "lockout_duration_minutes": policy_minutes(p.lockout_duration_secs),
            "lockout_window_minutes": policy_minutes(p.lockout_window_secs),
            "policy_of": "local_accounts",
            "scope": scope,
            "status": "ok",
            "source": "NetUserModalsGet"
        }]),
        None => json!([{
            "status": "unknown",
            "scope": scope,
            "source": "NetUserModalsGet",
            "detail": "NetUserModalsGet failed"
        }]),
    }
}

/// Whether this machine is joined to an AD domain ("domain"), stands alone
/// ("local"), or cannot say. Entra-only joins report "local": telling them
/// apart needs NetGetAadJoinInformation and another windows-sys feature.
#[cfg(target_os = "windows")]
fn read_join_scope() -> &'static str {
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetGetJoinInformation, NetSetupDomainName, NetSetupUnjoined,
        NetSetupWorkgroupName, NETSETUP_JOIN_STATUS,
    };
    let mut name: windows_sys::core::PWSTR = std::ptr::null_mut();
    let mut status: NETSETUP_JOIN_STATUS = 0;
    // SAFETY: NetGetJoinInformation allocates the name buffer, which is never
    // read and is released with NetApiBufferFree; a non-zero return leaves
    // both out-parameters untouched.
    unsafe {
        if NetGetJoinInformation(std::ptr::null(), &mut name, &mut status) != 0 {
            return "unknown";
        }
        if !name.is_null() {
            NetApiBufferFree(name as *const std::ffi::c_void);
        }
    }
    // The windows-sys constants are not upper-case, so a match pattern on
    // them trips `non_upper_case_globals` under CI's -D warnings.
    if status == NetSetupDomainName {
        "domain"
    } else if status == NetSetupWorkgroupName || status == NetSetupUnjoined {
        "local"
    } else {
        "unknown"
    }
}

/// Read the local password and lockout policy. `NetUserModalsGet` levels 0
/// and 3 need no elevation. Every failure path returns None.
#[cfg(target_os = "windows")]
fn read_password_policy() -> Option<PasswordPolicy> {
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetUserModalsGet, USER_MODALS_INFO_0, USER_MODALS_INFO_3,
    };
    // SAFETY: NetUserModalsGet allocates the buffer; it is read once as the
    // struct the requested level documents, then released with
    // NetApiBufferFree. A non-zero status leaves the pointer untouched.
    unsafe {
        let mut p0: *mut u8 = std::ptr::null_mut();
        if NetUserModalsGet(std::ptr::null(), 0, &mut p0) != 0 || p0.is_null() {
            return None;
        }
        let m0 = *(p0 as *const USER_MODALS_INFO_0);
        NetApiBufferFree(p0 as *const std::ffi::c_void);

        let mut p3: *mut u8 = std::ptr::null_mut();
        if NetUserModalsGet(std::ptr::null(), 3, &mut p3) != 0 || p3.is_null() {
            return None;
        }
        let m3 = *(p3 as *const USER_MODALS_INFO_3);
        NetApiBufferFree(p3 as *const std::ffi::c_void);

        Some(PasswordPolicy {
            min_password_len: m0.usrmod0_min_passwd_len,
            max_password_age_secs: m0.usrmod0_max_passwd_age,
            min_password_age_secs: m0.usrmod0_min_passwd_age,
            password_history_len: m0.usrmod0_password_hist_len,
            lockout_threshold: m3.usrmod3_lockout_threshold,
            lockout_duration_secs: m3.usrmod3_lockout_duration,
            lockout_window_secs: m3.usrmod3_lockout_observation_window,
        })
    }
}

/// Collect the Windows password and lockout policy, unprivileged.
#[cfg(target_os = "windows")]
fn collect_password_policy_windows() -> Value {
    password_policy_rows(read_password_policy(), read_join_scope())
}

/// The screensaver values one registry key can carry, as raw REG_SZ text.
/// Windows stores them as text, not DWORDs. An absent value stays None so the
/// parser can tell "not set" from "set to zero".
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default, Clone, PartialEq)]
struct ScreenSaverValues {
    active: Option<String>,          // ScreenSaveActive     "1" / "0"
    secure: Option<String>,          // ScreenSaverIsSecure  "1" / "0"
    timeout_seconds: Option<String>, // ScreenSaveTimeOut    seconds as text
    exe: Option<String>,             // SCRNSAVE.EXE         the saver; absent = "(None)"
}

/// The power-configuration values behind the lock Windows 11 users actually
/// set: Settings -> Accounts -> Sign-in options writes none of the screensaver
/// values, so the screensaver keys alone cannot see it. These arrive already
/// parsed, because the power API hands back numbers rather than REG_SZ text.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default, Clone, PartialEq)]
struct SleepLockValues {
    /// CONSOLELOCK: "require a password on wakeup" for the active scheme.
    console_lock: Option<bool>,
    /// STANDBYIDLE on mains and on battery, in seconds. 0 means "never".
    /// Both are read and both must lock: a machine that sleeps on battery and
    /// never on mains sits unlocked whenever it is plugged in. Measured on a
    /// Windows 11 laptop, the two differ in practice.
    standby_ac_secs: Option<u64>,
    standby_dc_secs: Option<u64>,
    /// Whether the host has a battery at all. On a desktop the battery-side
    /// values are returned but never apply, so only the mains side is judged.
    has_battery: Option<bool>,
    /// Evidence only. The display-off timeouts say when the screen goes dark,
    /// which is not the same as locking: Windows locks on wake from sleep,
    /// not on an idle display. They are reported so the whole idle picture is
    /// visible behind the verdict, and they never decide it.
    display_off_ac_secs: Option<u64>,
    display_off_dc_secs: Option<u64>,
}

/// Every screen-lock source on a Windows host, as raw text. The IO wrapper
/// fills it; every decision below is pure and unit-tested on any host. The
/// screen-saver policies are user-scope only (ControlPanelDisplay.admx), so
/// there is no machine key to read: a value under HKLM\...\Control Panel\
/// Desktop is never applied by Windows and must not outrank the real ones.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default, Clone, PartialEq)]
struct WindowsScreenLockInputs {
    /// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    /// InactivityTimeoutSecs: the machine inactivity limit, in seconds.
    inactivity_timeout_secs: Option<String>,
    /// HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop
    user_policy: ScreenSaverValues,
    /// HKCU\Control Panel\Desktop
    user_preference: ScreenSaverValues,
    /// The active power scheme's lock-on-wake and sleep timeouts.
    sleep: SleepLockValues,
}

/// Parse a REG_SZ boolean ("1" or "0"). Anything else is unknown, never a
/// silent "no".
#[cfg(any(target_os = "windows", test))]
fn parse_reg_sz_bool(raw: Option<&str>) -> Option<bool> {
    match raw?.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// Parse a REG_SZ unsigned number ("600"). Empty or non-numeric is unknown.
#[cfg(any(target_os = "windows", test))]
fn parse_reg_sz_u64(raw: Option<&str>) -> Option<u64> {
    raw?.trim().parse::<u64>().ok()
}

/// One parsed value and the key that supplied it.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, PartialEq)]
struct Sourced<T> {
    value: Option<T>,
    source: &'static str,
}

/// Pick the first key, by policy precedence, that sets one value. Windows
/// applies policy PER VALUE, not per key: a policy that sets only
/// ScreenSaverIsSecure leaves the user's own timeout in effect. A first-key-
/// wins rule would report "unknown" on the most common managed setup.
#[cfg(any(target_os = "windows", test))]
fn first_set<'a, T>(
    ranked: &[(&'static str, &'a ScreenSaverValues)],
    field: fn(&'a ScreenSaverValues) -> Option<&'a str>,
    parse: fn(Option<&str>) -> Option<T>,
) -> Sourced<T> {
    for (source, values) in ranked {
        if let Some(raw) = field(values) {
            return Sourced {
                value: parse(Some(raw)),
                source,
            };
        }
    }
    Sourced {
        value: None,
        source: "none",
    }
}

/// One mechanism's answer: Some(true) locks, Some(false) does not, None could
/// not be read. The delay is the time to a locked screen when it locks, and
/// whatever the mechanism could still say about timing when it does not.
#[cfg(any(target_os = "windows", test))]
struct LockVerdict {
    locks: Option<bool>,
    delay_seconds: Option<u64>,
    source: &'static str,
    detail: String,
}

/// The sleep path: Windows 11 puts the lock people actually set under
/// Settings -> Accounts -> Sign-in options, which writes none of the
/// screensaver values. The machine sleeps after the standby idle timeout and
/// demands a password on wake, so lock engages only when the password is
/// required AND the machine actually sleeps.
///
/// Every power source that applies must lock, and the delay is the LONGEST of
/// them: the machine is on one source or the other, so the honest answer to
/// "how long can this sit unlocked" is the worst case. A timeout of 0 means
/// "never sleeps", so a machine that sleeps on battery and never on mains is
/// a definite "no" — it sits unlocked whenever it is plugged in. An
/// unreadable value leaves the path unknown rather than inventing an answer.
#[cfg(any(target_os = "windows", test))]
fn sleep_lock_verdict(sleep: &SleepLockValues) -> LockVerdict {
    let detail = format!(
        "ConsoleLock={} StandbyIdleAC={} StandbyIdleDC={} Battery={} DisplayOffAC={} DisplayOffDC={}",
        fmt_opt(sleep.console_lock),
        fmt_opt(sleep.standby_ac_secs),
        fmt_opt(sleep.standby_dc_secs),
        fmt_opt(sleep.has_battery),
        fmt_opt(sleep.display_off_ac_secs),
        fmt_opt(sleep.display_off_dc_secs),
    );
    let verdict = |locks, delay_seconds| LockVerdict {
        locks,
        delay_seconds,
        source: "sleep_policy",
        detail: detail.clone(),
    };
    // Nothing read at all: this path names no source, so a host where neither
    // mechanism is readable can still report "none".
    let unreadable = || LockVerdict {
        locks: None,
        delay_seconds: None,
        source: "none",
        detail: detail.clone(),
    };
    match sleep.console_lock {
        None => return unreadable(),
        // Windows wakes straight to the desktop, so sleeping never locks.
        Some(false) => return verdict(Some(false), None),
        Some(true) => {}
    }
    // On a desktop the battery-side timeout is returned but never applies.
    let mut applies = vec![sleep.standby_ac_secs];
    match sleep.has_battery {
        None => return unreadable(),
        Some(true) => applies.push(sleep.standby_dc_secs),
        Some(false) => {}
    }
    if applies.iter().any(|t| t.is_none()) {
        return unreadable();
    }
    let timeouts: Vec<u64> = applies.into_iter().flatten().collect();
    if timeouts.iter().any(|t| *t == 0) {
        return verdict(Some(false), Some(0));
    }
    verdict(Some(true), timeouts.into_iter().max())
}

/// The screensaver path: it must be active, must ask for a password, must
/// have a non-zero timeout, and a saver must be selected — Windows runs no
/// saver, and so never locks, when SCRNSAVE.EXE is unset, whatever the other
/// three say. Any definite failure is "no"; a missing value is unknown.
#[cfg(any(target_os = "windows", test))]
fn screensaver_lock_verdict(inputs: &WindowsScreenLockInputs) -> LockVerdict {
    let ranked = [
        ("user_policy", &inputs.user_policy),
        ("user", &inputs.user_preference),
    ];
    let active = first_set(&ranked, |v| v.active.as_deref(), parse_reg_sz_bool);
    let secure = first_set(&ranked, |v| v.secure.as_deref(), parse_reg_sz_bool);
    let timeout = first_set(&ranked, |v| v.timeout_seconds.as_deref(), parse_reg_sz_u64);
    let exe = first_set(&ranked, |v| v.exe.as_deref(), parse_reg_sz_path);
    let detail = format!(
        "ScreenSaveActive={}({}) ScreenSaverIsSecure={}({}) ScreenSaveTimeOut={}({}) SCRNSAVE.EXE={}({})",
        fmt_opt(active.value),
        active.source,
        fmt_opt(secure.value),
        secure.source,
        fmt_opt(timeout.value),
        timeout.source,
        fmt_opt(exe.value.clone()),
        exe.source
    );
    // The highest-ranking key that contributed anything names the source.
    let source = [active.source, secure.source, timeout.source, exe.source]
        .into_iter()
        .min_by_key(|s| match *s {
            "user_policy" => 0,
            "user" => 1,
            _ => 2,
        })
        .unwrap_or("none");
    let verdict = |locks, delay_seconds, detail: String| LockVerdict {
        locks,
        delay_seconds,
        source,
        detail,
    };
    if source == "none" {
        return LockVerdict {
            locks: None,
            delay_seconds: None,
            source: "none",
            detail: "no screen saver values found".to_string(),
        };
    }
    if active.value == Some(false) || secure.value == Some(false) {
        return verdict(Some(false), timeout.value, detail);
    }
    if timeout.value == Some(0) {
        // Mirrors the GNOME idle-delay=0 rule: a lock that never triggers is
        // not a lock.
        return verdict(Some(false), Some(0), detail);
    }
    match (active.value, secure.value, timeout.value) {
        (Some(true), Some(true), Some(t)) if exe.value.is_none() => verdict(
            Some(false),
            Some(t),
            format!(
                "{} (no screen saver selected, so none runs and nothing locks)",
                detail
            ),
        ),
        (Some(true), Some(true), Some(t)) => verdict(Some(true), Some(t), detail),
        _ => verdict(None, timeout.value, detail),
    }
}

/// Windows screenlock row. Decision order:
/// 1. A machine inactivity limit above zero locks the console whatever every
///    other mechanism says, so it answers "yes" outright.
/// 2. Otherwise the screensaver and the sleep path each answer, and the row
///    combines them: a machine locks if ANY mechanism locks it, reported at
///    the soonest delay, because that is when the screen is actually locked.
///    Failing that, an unreadable mechanism outranks a definite "no" — it
///    might be the one that locks — so "no" is reported only when every
///    mechanism was readable and none of them locks. The agent never reports
///    a lock missing on the strength of a value it could not see.
#[cfg(any(target_os = "windows", test))]
fn windows_screenlock_row(inputs: &WindowsScreenLockInputs) -> Value {
    if let Some(secs) = parse_reg_sz_u64(inputs.inactivity_timeout_secs.as_deref()) {
        if secs > 0 {
            return screenlock_row(
                "windows",
                "yes",
                Some(secs),
                "machine_inactivity_policy",
                &format!("InactivityTimeoutSecs={}", secs),
            );
        }
    }
    let saver = screensaver_lock_verdict(inputs);
    let sleep = sleep_lock_verdict(&inputs.sleep);
    let detail = format!("{} | {}", saver.detail, sleep.detail);
    let mechanisms = [&saver, &sleep];

    // The soonest lock wins: two mechanisms that both lock leave the screen
    // locked at the earlier of the two.
    let locking = mechanisms
        .iter()
        .filter(|m| m.locks == Some(true))
        .min_by_key(|m| m.delay_seconds.unwrap_or(u64::MAX));
    if let Some(m) = locking {
        return screenlock_row("windows", "yes", m.delay_seconds, m.source, &detail);
    }
    // A mechanism the agent could not read might be the one that locks, so it
    // outranks a definite "no" from the others: the row never reports a lock
    // missing on the strength of a value nobody could see.
    if mechanisms.iter().any(|m| m.locks.is_none()) {
        if saver.source == "none" && sleep.source == "none" {
            return screenlock_row(
                "windows",
                "unknown",
                None,
                "none",
                "no screen-lock policy, screen saver, or power values found",
            );
        }
        return screenlock_row(
            "windows",
            "unknown",
            saver.delay_seconds,
            saver.source,
            &detail,
        );
    }
    // Every mechanism was readable and none of them locks.
    let m = mechanisms
        .iter()
        .find(|m| m.locks == Some(false))
        .copied()
        .unwrap_or(&saver);
    screenlock_row("windows", "no", m.delay_seconds, m.source, &detail)
}

/// A GUID split into the parts the Win32 GUID struct wants. Kept free of any
/// windows-sys type so the parser is unit-tested on any host.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, PartialEq, Clone, Copy)]
struct GuidParts {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

/// Parse the registry's active power scheme, a GUID as text, optionally in
/// braces: "381b4222-f694-41f0-9685-ff5bb260df2e". Anything else is None, so
/// an unreadable scheme reports unknown rather than reading some other one.
#[cfg(any(target_os = "windows", test))]
fn parse_guid(raw: &str) -> Option<GuidParts> {
    let text = raw.trim().trim_start_matches('{').trim_end_matches('}');
    let fields: Vec<&str> = text.split('-').collect();
    if fields.len() != 5 {
        return None;
    }
    let lengths = [8, 4, 4, 4, 12];
    if fields.iter().zip(lengths).any(|(f, n)| f.len() != n) {
        return None;
    }
    if !fields.iter().all(|f| f.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }
    let mut d4 = [0u8; 8];
    // The last two fields run together as the eight trailing bytes.
    let tail: String = format!("{}{}", fields[3], fields[4]);
    for (i, byte) in d4.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&tail[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(GuidParts {
        d1: u32::from_str_radix(fields[0], 16).ok()?,
        d2: u16::from_str_radix(fields[1], 16).ok()?,
        d3: u16::from_str_radix(fields[2], 16).ok()?,
        d4,
    })
}

/// Parse a REG_SZ path (SCRNSAVE.EXE). Empty text means no saver.
#[cfg(any(target_os = "windows", test))]
fn parse_reg_sz_path(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(any(target_os = "windows", target_os = "linux", test))]
fn fmt_opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string())
        .unwrap_or_else(|| "unset".to_string())
}

/// Read one registry value as text. REG_SZ comes back as is; a REG_DWORD is
/// rendered as decimal, because some management tools write the inactivity
/// limit either way. A missing key, a missing value, or a wrong type all stay
/// None, so the parser reports "unknown" and never a false "no".
#[cfg(target_os = "windows")]
fn reg_value_text(root: winreg::HKEY, path: &str, name: &str) -> Option<String> {
    let key = winreg::RegKey::predef(root).open_subkey(path).ok()?;
    if let Ok(s) = key.get_value::<String, _>(name) {
        return Some(s);
    }
    key.get_value::<u32, _>(name).ok().map(|n| n.to_string())
}

#[cfg(target_os = "windows")]
fn read_screensaver_values(root: winreg::HKEY, path: &str) -> ScreenSaverValues {
    ScreenSaverValues {
        active: reg_value_text(root, path, "ScreenSaveActive"),
        secure: reg_value_text(root, path, "ScreenSaverIsSecure"),
        timeout_seconds: reg_value_text(root, path, "ScreenSaveTimeOut"),
        exe: reg_value_text(root, path, "SCRNSAVE.EXE"),
    }
}

/// The power settings behind "require a password on wakeup" and "put the
/// computer to sleep", as documented power-setting GUIDs. Stable since
/// Windows Vista; `powercfg /q SCHEME_CURRENT <subgroup> <setting>` prints
/// the same two.
#[cfg(target_os = "windows")]
const SUB_NONE: &str = "fea3413e-7e05-4911-9a71-700331f1c294";
#[cfg(target_os = "windows")]
const SETTING_CONSOLE_LOCK: &str = "0e796bdb-100d-47d6-a2d5-f7d2daa51f51";
#[cfg(target_os = "windows")]
const SUB_SLEEP: &str = "238c9fa8-0aad-41ed-83f4-97be242c8f20";
#[cfg(target_os = "windows")]
const SETTING_STANDBY_IDLE: &str = "29f6c1db-86da-48c5-9fdb-f2b67b1f44da";
#[cfg(target_os = "windows")]
const SUB_VIDEO: &str = "7516b95f-f776-4464-8c53-06167f40cc99";
#[cfg(target_os = "windows")]
const SETTING_VIDEO_IDLE: &str = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e";

/// Whether the host has a system battery. BATTERY_FLAG_NO_SYSTEM_BATTERY
/// (128) is the one bit that answers it; a failed call stays None so the
/// verdict degrades to unknown rather than judging a laptop as a desktop.
#[cfg(target_os = "windows")]
fn has_battery() -> Option<bool> {
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    let mut status: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: the pointer is to a live, fully initialised local.
    if unsafe { GetSystemPowerStatus(&mut status) } == 0 {
        return None;
    }
    Some(status.BatteryFlag & 128 == 0)
}

#[cfg(target_os = "windows")]
fn guid_from(text: &str) -> Option<windows_sys::core::GUID> {
    let parts = parse_guid(text)?;
    Some(windows_sys::core::GUID {
        data1: parts.d1,
        data2: parts.d2,
        data3: parts.d3,
        data4: parts.d4,
    })
}

/// Read one power value on the active scheme. The API resolves a scheme's
/// defaults, which a raw registry walk does not: an untouched setting has no
/// value under the scheme's own key and would read as unset.
#[cfg(target_os = "windows")]
fn power_value(
    scheme: &windows_sys::core::GUID,
    subgroup: &str,
    setting: &str,
    ac: bool,
) -> Option<u32> {
    use windows_sys::Win32::System::Power::{PowerReadACValueIndex, PowerReadDCValueIndex};
    let subgroup = guid_from(subgroup)?;
    let setting = guid_from(setting)?;
    let mut value: u32 = 0;
    // windows-sys types HKEY as an isize, not a pointer; 0 is the null root
    // key, which asks the API for the running configuration.
    let root = 0;
    // SAFETY: every pointer is to a live local, and the API writes only the
    // u32 it is handed. A non-zero return means it wrote nothing.
    let status = unsafe {
        if ac {
            PowerReadACValueIndex(root, scheme, &subgroup, &setting, &mut value)
        } else {
            PowerReadDCValueIndex(root, scheme, &subgroup, &setting, &mut value)
        }
    };
    (status == 0).then_some(value)
}

/// Read the sleep path: lock-on-wake and the sleep timeouts of the active
/// power scheme. Unprivileged. Every failure stays None, so an unreadable
/// power configuration reports unknown, never a false "no".
#[cfg(target_os = "windows")]
fn read_sleep_lock_values() -> SleepLockValues {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let active = reg_value_text(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes",
        "ActivePowerScheme",
    );
    let Some(scheme) = active.as_deref().and_then(guid_from) else {
        return SleepLockValues::default();
    };
    let standby = |ac| power_value(&scheme, SUB_SLEEP, SETTING_STANDBY_IDLE, ac).map(u64::from);
    let display_off = |ac| power_value(&scheme, SUB_VIDEO, SETTING_VIDEO_IDLE, ac).map(u64::from);
    SleepLockValues {
        // Lock-on-wake is a per-scheme setting, not per-power-source; both
        // sides carry the same value, so the mains one answers.
        console_lock: power_value(&scheme, SUB_NONE, SETTING_CONSOLE_LOCK, true).map(|v| v != 0),
        standby_ac_secs: standby(true),
        standby_dc_secs: standby(false),
        has_battery: has_battery(),
        display_off_ac_secs: display_off(true),
        display_off_dc_secs: display_off(false),
    }
}

/// Read every screen-lock source from the registry. All three keys are
/// readable without administrator rights. The build is x64, so no WOW64
/// redirection applies to HKLM\SOFTWARE.
#[cfg(target_os = "windows")]
fn read_windows_screenlock_inputs() -> WindowsScreenLockInputs {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    WindowsScreenLockInputs {
        inactivity_timeout_secs: reg_value_text(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "InactivityTimeoutSecs",
        ),
        user_policy: read_screensaver_values(
            HKEY_CURRENT_USER,
            r"Software\Policies\Microsoft\Windows\Control Panel\Desktop",
        ),
        user_preference: read_screensaver_values(HKEY_CURRENT_USER, r"Control Panel\Desktop"),
        sleep: read_sleep_lock_values(),
    }
}

/// Collect Windows screen-lock posture, unprivileged.
#[cfg(target_os = "windows")]
fn collect_screenlock_windows() -> Value {
    windows_screenlock_row(&read_windows_screenlock_inputs())
}

/// Flatten osquery results into JSON:API resources, stamping each row with collected_at.
fn build_payload_items(
    results: &HashMap<String, Value>,
    collected_at: &str,
) -> Vec<JsonApiResource> {
    let mut items = Vec::new();
    for (table, value) in results.iter() {
        let Some(arr) = value.as_array() else {
            continue;
        };
        for row in arr {
            let mut attributes = row.clone();
            if let Some(obj) = attributes.as_object_mut() {
                obj.insert("collected_at".to_string(), json!(collected_at));
            }
            items.push(JsonApiResource {
                id: None,
                r#type: table.clone(),
                attributes,
            });
        }
    }
    items
}

/// An HTTP client with the agent's User-Agent and connection deadlines. reqwest
/// sets none by default, and a peer that keeps the TCP connection alive but
/// never answers (a proxy that accepts and stalls) is the case nothing else
/// catches; the loops that await these requests would otherwise stop for good.
/// `overall` bounds the whole request for small exchanges; without it, the
/// read timeout bounds silence on a body stream, so a slow but live installer
/// download is not cut off.
fn http_client(overall: Option<Duration>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!("KlaayGuard/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(60));
    if let Some(t) = overall {
        builder = builder.timeout(t);
    }
    builder.build().expect("reqwest client")
}

/// What `GET /me` says about a token.
#[derive(Debug, PartialEq)]
enum Identity {
    /// The API positively rejects it (401/403).
    Rejected,
    /// The API accepts it. The label names the holder, when the reply carries
    /// a name or an email to name them by.
    Accepted(Option<String>),
    /// Nothing conclusive: a network error, a timeout, any other status. The
    /// callers read this as "not definitely invalid". A transient blip must
    /// never block a legitimate sign-in. The collection loop's own 401 handling
    /// stays the backstop for a token that later turns out bad.
    Unknown,
}

/// Ask the API who holds this token. One request answers both questions the
/// agent has: whether the token still works, and whose name to put in the tray.
async fn fetch_identity(base: &str, token: &str) -> Identity {
    let client = http_client(Some(Duration::from_secs(10)));
    let response = match client
        .get(format!("{}/me", base))
        .bearer_auth(token)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return Identity::Unknown,
    };
    if matches!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) {
        return Identity::Rejected;
    }
    if !response.status().is_success() {
        return Identity::Unknown;
    }
    match response.json::<Value>().await {
        Ok(body) => Identity::Accepted(identity_label(&body)),
        Err(_) => Identity::Unknown,
    }
}

/// How many characters of a name the tray shows. Nobody validates the length of
/// a name: the person types it, and the API stores what they type. A menu item
/// is one short line, so cut the rest.
const LABEL_MAX_CHARS: usize = 48;

/// Characters that paint no glyph and bind nothing to the character beside
/// them. A bidi control reverses the run after it, so a menu that honours one
/// paints "Emil<RLO>tuo ngiS" as "Emil Sign out". A zero-width space hides a
/// break, and a tag character paints nothing at all.
///
/// `is_control` misses every one: they are Unicode Cf, not Cc. So ask Unicode
/// for the category instead of listing the code points. A list of ranges
/// tracks the bug reports it was written from, and five rounds of this one
/// each added a range and still missed the next: `U+0890`, `U+08E2`,
/// `U+110BD`, `U+1BCA0`, `U+1D173` and `U+13430` are all Cf, all typeable into
/// a name field, and none was in the list.
///
/// Cf, not `Default_Ignorable_Code_Point`. The two disagree in both
/// directions. Default-ignorable misses the prepended concatenation marks
/// above, and it holds the variation selectors, which shape the character
/// beside them.
///
/// Two additions carry what the category cannot:
///
/// - Four fillers people actually use for a blank display name. They are Lo,
///   letters, so no rule about format characters reaches them.
/// - `U+2800` BRAILLE PATTERN BLANK, So, the empty cell of a braille font.
///
/// The joiners in `binds_without_painting` leave again. `U+200D` is Cf, and
/// cutting a name on it breaks a family emoji into four people.
fn paints_nothing(c: char) -> bool {
    if binds_without_painting(c) {
        return false;
    }
    c.general_category() == GeneralCategory::Format
        || matches!(
            c,
            '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' | '\u{2800}'
        )
}

/// Characters that paint no glyph of their own but shape the one beside them.
/// A word keeps them, because cutting one apart breaks a family emoji into
/// four people. A value made only of them still paints nothing, so it names
/// nobody.
fn binds_without_painting(c: char) -> bool {
    matches!(
        c,
        '\u{200D}' | '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}'
    )
}

/// One line of plain text, safe to hand a menu item. Control and format
/// characters become spaces, so a newline cannot paint a second line that
/// reads like another menu item, and a bidi override cannot reverse one. Runs
/// of space collapse to one.
fn one_line(value: &str) -> String {
    value
        .split(|c: char| c.is_control() || c.is_whitespace() || paints_nothing(c))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Cut a label to `LABEL_MAX_CHARS`, always on a character boundary, and mark
/// the cut. `chars` counts code points, so a name of emoji never splits one.
fn cap_label(label: String) -> String {
    if label.chars().count() <= LABEL_MAX_CHARS {
        return label;
    }
    let kept: String = label.chars().take(LABEL_MAX_CHARS - 1).collect();
    format!("{kept}…")
}

/// The line the tray shows for the signed-in person, read from a `/me` reply:
/// their name, or their email when the account carries no name. `None` when the
/// reply carries neither, so the menu drops the line instead of showing a blank
/// one.
fn identity_label(me: &Value) -> Option<String> {
    let attributes = me.pointer("/data/attributes")?;
    let field = |key: &str| {
        attributes
            .get(key)
            .and_then(|value| value.as_str())
            .map(one_line)
            .filter(|value| value.chars().any(|c| !binds_without_painting(c)))
    };
    let name = [field("first_name"), field("last_name")]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    if !name.is_empty() {
        return Some(cap_label(name));
    }
    field("email").map(cap_label)
}

/// Name the holder of the token this process already has. The sign-in path
/// learns the name from the check it already makes; a start with a stored token
/// makes no such check, so it asks here.
fn refresh_identity(state: &Arc<AppState>) {
    let state = state.clone();
    tauri::async_runtime::spawn(async move {
        let Some(token) = lock_read(&state.auth_token).clone() else {
            return;
        };
        if let Identity::Accepted(label) = fetch_identity(&state.api_base_url, &token).await {
            state.name_holder_of(Some(&token), label);
        }
    });
}

/// Name a session that `/me` could not name at sign-in. The collection loop
/// calls this once the token has just proved live, so a blip costs the name
/// until the next cycle, not until a restart. The first cycle runs the moment
/// a token arrives. A named session asks nothing.
fn name_unnamed_holder(state: &Arc<AppState>) {
    if lock_read(&state.user_label).is_none() {
        refresh_identity(state);
    }
}

/// Ask the API about a token that just arrived and, unless the API rejects
/// it, take it up as this process's session. A `/me` blip names nobody: the
/// token is adopted anyway, unnamed, so the previous holder's name never sits
/// above this session. The collection loop's own 401 handling stays the
/// backstop for a token that later turns out bad. Returns whether the token
/// was adopted.
async fn adopt_unless_rejected(state: &Arc<AppState>, tok: &str) -> bool {
    let label = match fetch_identity(&state.api_base_url, tok).await {
        Identity::Rejected => return false,
        Identity::Accepted(label) => label,
        Identity::Unknown => None,
    };
    state.adopt_session(tok.to_string(), label);
    state.token_acquired.notify_one();
    true
}

/// Store a token the loopback exchange just returned, once the API accepts
/// it. The token reached this process over `127.0.0.1` and was released only
/// against a verifier the browser never saw, so the binding is already settled
/// by the time this runs; the API check stays because a token this agent
/// cannot use is worth catching here rather than at the next collection.
fn adopt_token<R: tauri::Runtime>(app: &tauri::AppHandle<R>, state: &Arc<AppState>, tok: String) {
    let app = app.clone();
    let state = state.clone();
    tauri::async_runtime::spawn(async move {
        if !adopt_unless_rejected(&state, &tok).await {
            log::warn!("sign_in_token_rejected_by_api length={}", tok.len());
            add_breadcrumb("auth", "sign_in_token_rejected", Level::Warning);
            sentry::capture_message("sign_in_token_rejected", Level::Warning);
            let _ = app.emit("auth:status", json!({ "authenticated": false }));
            return;
        }

        // The keyring is the primary store. Without a Secret Service daemon
        // (common on Linux) the agent falls back to a user-only file so the
        // sign-in still survives a reboot. Tell the user the store is
        // degraded instead of failing silently. The keyring call blocks
        // (D-Bus, Keychain), so it stays off the async workers.
        let saved = tauri::async_runtime::spawn_blocking(move || keychain::save_token(&tok)).await;
        match saved {
            Ok(Ok(keychain::CredentialStore::Keyring)) => {}
            Ok(Ok(keychain::CredentialStore::File)) => {
                log::warn!("secure credential store unavailable; saved sign-in to a file");
                notify_user(
                    "KlaayGuard",
                    "No secure credential store found. Your sign-in is saved with reduced \
                     protection. Install a keyring (gnome-keyring or KWallet) for full \
                     protection.",
                );
                add_breadcrumb("auth", "token_saved_file_fallback", Level::Warning);
                sentry::capture_message("keychain_token_file_fallback", Level::Warning);
            }
            Ok(Err(e)) => {
                log::error!("keychain: token save failed: {}", e);
                sentry::capture_message(
                    &format!("keychain_token_save_failed: {}", e),
                    Level::Error,
                );
            }
            Err(e) => {
                log::error!("keychain: token save task failed: {}", e);
            }
        }
        let _ = app.emit("auth:status", json!({ "authenticated": true }));
        add_breadcrumb("auth", "sign_in_token_saved", Level::Info);
        sentry::capture_message("sign_in_token_saved", Level::Info);
    });
}

/// Executes a batch of SQL statements against osquery and returns results keyed by logical id
/// The vector contains pairs of (logical_id, sql_to_execute).
async fn execute_sql_batch<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    queries: Vec<(String, String)>,
) -> Result<HashMap<String, Value>, String> {
    let mut all_results: HashMap<String, Value> = HashMap::new();

    for (logical_id, sql) in queries {
        let cmd = app
            .shell()
            .sidecar("klaayguard-osqueryi")
            .map_err(|e| format!("klaayguard-osqueryi sidecar unavailable: {}", e))?
            .args([
                // The text guard in `is_read_only_query` cannot keep a SELECT
                // off the network: osquery's `curl` table performs an HTTP
                // request, `yara` fetches `sigurl`, and the carver uploads.
                // Turn those off in the engine, where the SQL text does not
                // matter, and keep extensions from adding new ones.
                "--disable_tables=curl,curl_certificate,yara,carves",
                "--disable_extensions=true",
                "--json",
                sql.as_str(),
            ]);

        // osquery failing to spawn at all is a systemic problem — surface it.
        let output = cmd.output().await.map_err(|e| e.to_string())?;

        // A single failed or unparseable query must not sink the cycle: record an
        // empty result for it and keep collecting (and sending) the others.
        if !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            // Log it too: Sentry only runs when a DSN was baked in at build
            // time, and a breadcrumb alone leaves a missing table
            // undiagnosable from the log file.
            log::warn!(
                "osquery query '{}' skipped: {}",
                logical_id,
                stderr_str.trim()
            );
            add_breadcrumb(
                "collection",
                &format!(
                    "osquery_query_skipped '{}': {}",
                    logical_id,
                    stderr_str.trim()
                ),
                Level::Warning,
            );
            all_results.insert(logical_id, serde_json::json!([]));
            continue;
        }

        // osquery copies column bytes verbatim, so one non-UTF-8 byte (a
        // process argv, a file name) must not blank the whole table: decode
        // lossily and let the row survive with U+FFFD in that field.
        let parsed = serde_json::from_str::<Value>(&String::from_utf8_lossy(&output.stdout)).ok();
        match parsed {
            Some(v) => {
                all_results.insert(logical_id, v);
            }
            None => {
                log::warn!("osquery query '{}' returned unparseable output", logical_id);
                add_breadcrumb(
                    "collection",
                    &format!("osquery_parse_skipped '{}'", logical_id),
                    Level::Warning,
                );
                all_results.insert(logical_id, serde_json::json!([]));
            }
        }
    }

    Ok(all_results)
}

fn invalidate_auth<R: tauri::Runtime>(app: &tauri::AppHandle<R>, state: &Arc<AppState>) {
    // Stop using the token, but DON'T delete it from the keychain: a keychain write
    // pops a second OS prompt on unsigned builds, and the stale token is harmless
    // (the next sign-in overwrites it, or shadows it through the file store, which
    // `keychain::load_token` reads first). Just clear it in memory and prompt re-login.
    // The name goes with it: the dot turns red, so the tray must stop naming
    // anybody.
    state.clear_session();
    log::warn!("Authentication invalidated; notifying user to re-sign-in");
    notify_signin_needed(app, state);
    let _ = app.emit("auth:invalidated", ());
    let _ = app.emit("auth:status", json!({ "authenticated": false }));
    add_breadcrumb("auth", "auth_invalidated", Level::Warning);
    sentry::capture_message("auth_invalidated", Level::Warning);
}

/// A positive number of seconds from an environment override, or `default`.
/// Zero is rejected: `tokio::time::interval` asserts on a zero period, which
/// would kill the loop that reads it.
fn env_seconds(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

fn focus_debounce_seconds() -> u64 {
    env_seconds("KLAAYGUARD_FAILURE_FOCUS_DEBOUNCE_SECONDS", 60)
}

fn collection_interval_seconds() -> u64 {
    env_seconds("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS", 900)
}

/// Debounced sign-in nudge: opens the login page in the browser and posts a native
/// notification. The debounce keeps repeated 401s from spamming browser tabs. A
/// no-op once a token is present: a cold start signs the user in from the
/// stored token while this is being decided.
fn notify_signin_needed<R: tauri::Runtime>(app: &tauri::AppHandle<R>, state: &Arc<AppState>) {
    if lock_read(&state.auth_token).is_some() {
        return;
    }
    let now = Instant::now();
    let debounce = Duration::from_secs(focus_debounce_seconds());
    let should = match *lock_read(&state.last_focus_at) {
        Some(prev) => now.duration_since(prev) >= debounce,
        None => true,
    };
    if !should {
        return;
    }
    *lock_write(&state.last_focus_at) = Some(now);
    log::warn!("sign-in required; opening login page (debounced)");
    add_breadcrumb("ui", "signin_required_notification", Level::Info);
    open_sign_in(app);
    notify_user("KlaayGuard", "Open KlaayGuard in the menu bar to sign in.");
    // Stock GNOME shows the tray to nobody. Without a tray the user has no
    // way back to sign-in after a token expires, so open the window here,
    // when it is needed, instead of at every login.
    #[cfg(target_os = "linux")]
    {
        use std::sync::atomic::Ordering;
        if fallback_window_needed(
            state.tray_built.load(Ordering::Relaxed),
            state.tray_watcher_present.load(Ordering::Relaxed),
            false,
        ) {
            open_fallback_window(app);
        }
    }
}

/// Emit a collection error to UI listeners, the log, and Sentry (error level).
fn emit_error<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    event: &str,
    payload: serde_json::Value,
) {
    let _ = app.emit(event, payload.clone());
    let serialized = payload.to_string();
    log::error!("error_event:{}, payload:{}", event, serialized);
    sentry::capture_message(
        &format!("error_event:{}, payload:{}", event, serialized),
        Level::Error,
    );
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonApiResource {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "type")]
    r#type: String,
    attributes: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonApiPayload {
    data: Vec<JsonApiResource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jsonapi: Option<serde_json::Value>,
}

/// The check-in `meta`: the device identity plus the agent version, so the
/// backend can record which build sent each check-in.
fn checkin_meta(device_uuid: &str) -> serde_json::Value {
    json!({
        "device_uuid": device_uuid,
        "app_version": env!("CARGO_PKG_VERSION"),
    })
}

/// Pull the hardware serial from osquery `system_info` rows. Do not fall back
/// to `uuid`: unprivileged osquery on Linux cannot read the DMI uuid and
/// invents a random one per process, which made a new device on each restart.
fn extract_serial(rows: &Value) -> Option<String> {
    let obj = rows.as_array()?.first()?;
    ["hardware_serial", "serial_number"]
        .iter()
        .find_map(|k| {
            obj.get(*k)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty() && !is_placeholder_serial(s))
        })
        .map(|s| s.to_string())
}

/// Whether a BIOS serial is one of the placeholders OEM boards, virtual
/// machines, and osquery itself ("-1" when WMI fails) hand out instead of a
/// real one. Adopting one as the device identity would merge every such
/// machine into one device.
fn is_placeholder_serial(raw: &str) -> bool {
    const PLACEHOLDERS: [&str; 22] = [
        "-1",
        "0",
        "none",
        "n/a",
        "null",
        "(null string)",
        "invalid",
        "default",
        "default string",
        "system serial number",
        "to be filled by o.e.m.",
        "not applicable",
        "not specified",
        "not available",
        "unknown",
        "serial number",
        "serialnumber",
        "oem",
        "empty",
        "123456789",
        "0123456789",
        "1234567890",
    ];
    let s = raw.trim().to_ascii_lowercase();
    let mut chars = s.chars();
    let first = chars.next();
    s.len() < 4
        || PLACEHOLDERS.contains(&s.as_str())
        || first.is_some_and(|f| chars.all(|c| c == f))
}

/// Which device identity to use and whether to store it.
enum IdentityDecision {
    /// A stored identity exists. Use it unchanged.
    Use(String),
    /// A new trusted identity. Use it and store it.
    Adopt(String),
    /// No trusted source exists. Make one random identity and store it.
    Generate,
}

/// A valid machine id is 32 hex characters, with optional whitespace around it.
fn normalize_machine_id(raw: &str) -> Option<String> {
    let t = raw.trim();
    (t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit())).then(|| t.to_ascii_lowercase())
}

/// App-scoped hash of the systemd machine id. The systemd manual says to not
/// send the raw id off the machine; the HMAC derives a stable, Klaay-specific
/// value from it. The key is compiled into the binary, so this is not a
/// secret — it stops other software from reusing our exact identifier, not a
/// determined attacker who reads the key.
fn hash_machine_id(machine_id: &str) -> String {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"com.klaay.klaayguard")
        .expect("HMAC accepts any key length");
    mac.update(machine_id.as_bytes());
    hex_lower(&mac.finalize().into_bytes())
}

/// Rank the identity sources: stored value, then hardware serial, then hashed
/// machine id, then a generated fallback. Identity is decided once; every
/// later run must reuse the stored value.
fn decide_device_identity(
    stored: Option<&str>,
    hardware_serial: Option<&str>,
    machine_id: Option<&str>,
) -> IdentityDecision {
    if let Some(s) = stored.filter(|s| !s.is_empty()) {
        return IdentityDecision::Use(s.to_string());
    }
    if let Some(s) = hardware_serial.filter(|s| !s.is_empty()) {
        return IdentityDecision::Adopt(s.to_string());
    }
    if let Some(id) = machine_id.and_then(normalize_machine_id) {
        return IdentityDecision::Adopt(hash_machine_id(&id));
    }
    IdentityDecision::Generate
}

/// Directory for the early boot and panic log. On Linux and Windows this
/// follows `data_local` (tauri-plugin-log resolves through the same
/// `dirs::data_local_dir()`, honoring XDG_DATA_HOME / LOCALAPPDATA). macOS
/// keeps the user Logs folder, which is not the data-local dir.
pub(crate) fn early_log_dir(
    home: &std::path::Path,
    data_local: &std::path::Path,
) -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Logs/com.klaay.app")
    } else {
        data_local.join("com.klaay.app/logs")
    }
}

/// Append one line to the early boot log. Used before and outside the Tauri
/// logger, for the panic hook and startup markers.
pub fn append_early_log(line: &str) {
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let msg = format!("[{}]{}\n", ts, line);
    let log_dir = match (dirs::home_dir(), dirs::data_local_dir()) {
        (Some(h), Some(d)) => early_log_dir(&h, &d),
        _ => std::path::PathBuf::from("./"),
    };
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir.join("KlaayGuard.log");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, msg.as_bytes()));
}

/// The native notification command for this platform, or None where the app
/// has no notification path.
fn notification_command(title: &str, body: &str) -> Option<(&'static str, Vec<String>)> {
    if cfg!(target_os = "macos") {
        // Pass text through argv, so a quote or backslash in the message
        // cannot break out of the AppleScript literal.
        Some((
            "osascript",
            vec![
                "-e".to_string(),
                "on run argv".to_string(),
                "-e".to_string(),
                "display notification (item 1 of argv) with title (item 2 of argv)".to_string(),
                "-e".to_string(),
                "end run".to_string(),
                body.to_string(),
                title.to_string(),
            ],
        ))
    } else if cfg!(target_os = "linux") {
        // `--` stops option parsing, so a title or body that starts with `-`
        // is treated as text, not a notify-send flag.
        Some((
            "notify-send",
            vec![
                "--app-name=KlaayGuard".to_string(),
                "--".to_string(),
                title.to_string(),
                body.to_string(),
            ],
        ))
    } else {
        None
    }
}

/// Spawn a fire-and-forget helper and reap it when it exits. std never waits
/// on a dropped `Child`, so without this every notify-send, browser, or
/// clipboard helper would stay a zombie for the life of the agent.
fn spawn_and_reap(cmd: &mut std::process::Command) -> std::io::Result<()> {
    let mut child = cmd.spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// Show a native notification. Failure is fine; this is best-effort UX.
fn notify_user(title: &str, body: &str) {
    if let Some((program, args)) = notification_command(title, body) {
        let mut cmd = std::process::Command::new(program);
        cmd.args(args);
        // notify-send is a system binary; from an AppImage it must not inherit
        // the bundled library paths, or it fails to start and the notification
        // never shows.
        #[cfg(target_os = "linux")]
        apply_appimage_sanitization(&mut cmd);
        let _ = spawn_and_reap(&mut cmd);
    }
}

/// Read the systemd machine id. The dbus path serves older systems.
fn read_machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
}

/// 32 hex characters from the OS CSPRNG, for hosts with no other identity.
fn generate_device_identity() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("getrandom failed: {}", e))?;
    Ok(hex_lower(&bytes))
}

/// Quote and escape a path for the Desktop Entry `Exec` field. The entry is
/// always double-quoted, so a path with spaces stays one argument; the
/// reserved characters `"`, `` ` ``, `$`, `\` are backslash-escaped, and a
/// literal `%` is doubled so it is not read as a field code.
#[cfg(any(target_os = "linux", test))]
fn desktop_exec_field(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 2);
    out.push('"');
    for c in path.chars() {
        match c {
            '"' | '`' | '$' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A fallback window is needed when the tray cannot serve as the UI.
///
/// A tray that failed to build leaves no UI at all, so the window opens
/// whatever the sign-in state. A tray that built but has no StatusNotifier
/// host to show it (stock GNOME without the AppIndicator extension) is the
/// normal case on Fedora, Debian and Arch: there the window is only worth
/// opening when the user must sign in. A signed-in agent needs no UI, and a
/// window at every login is noise.
#[cfg(any(target_os = "linux", test))]
fn fallback_window_needed(tray_built: bool, watcher_present: bool, signed_in: bool) -> bool {
    !tray_built || (!watcher_present && !signed_in)
}

/// Open the sign-in fallback window, once. A second call while the window
/// lives is a no-op, so startup and a later sign-out cannot stack windows.
#[cfg(target_os = "linux")]
fn open_fallback_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if app.get_webview_window("fallback").is_some() {
        return;
    }
    if let Err(e) = tauri::WebviewWindowBuilder::new(
        app,
        "fallback",
        tauri::WebviewUrl::App("fallback.html".into()),
    )
    .title("KlaayGuard")
    .inner_size(440.0, 340.0)
    .build()
    {
        log::error!("fallback window failed: {}", e);
        sentry::capture_message(&format!("fallback_window_failed: {}", e), Level::Error);
    }
}

/// Whether a StatusNotifier host listens on the session bus. Errors and a
/// slow bus both count as absent: a wedged bus must not hang startup, and if
/// D-Bus is broken the tray cannot show either, so the window is the only UI.
#[cfg(target_os = "linux")]
fn status_notifier_watcher_present() -> bool {
    // Probe on a worker thread with a hard deadline, so a stuck session bus
    // cannot block the setup thread forever.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let probe = || -> zbus::Result<bool> {
            let conn = zbus::blocking::Connection::session()?;
            let proxy = zbus::blocking::fdo::DBusProxy::new(&conn)?;
            let name = zbus::names::BusName::try_from("org.kde.StatusNotifierWatcher")?;
            Ok(proxy.name_has_owner(name)?)
        };
        let _ = tx.send(probe().unwrap_or(false));
    });
    match rx.recv_timeout(std::time::Duration::from_secs(3)) {
        Ok(present) => present,
        Err(_) => {
            log::warn!("StatusNotifierWatcher probe timed out; assuming no tray host");
            false
        }
    }
}

/// Open the sign-in page from the fallback window.
#[tauri::command]
fn fallback_sign_in(app: tauri::AppHandle) {
    open_sign_in(&app);
}

/// Open the employee hub from the fallback window.
#[tauri::command]
fn fallback_employee_hub(app: tauri::AppHandle) {
    open_frontend(&app, "/employee-hub");
}

/// Content of the Linux autostart entry.
#[cfg(any(target_os = "linux", test))]
fn autostart_entry(exec: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=KlaayGuard\n\
         Comment=KlaayGuard security agent\n\
         Exec={}\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n",
        desktop_exec_field(exec)
    )
}

/// The executable to autostart. Inside an AppImage, current_exe points at a
/// temporary mount that is gone after exit; the APPIMAGE variable holds the
/// real file.
#[cfg(any(target_os = "linux", test))]
fn autostart_exec(appimage_env: Option<&str>, current_exe: &str) -> String {
    appimage_env
        .filter(|s| !s.is_empty())
        .unwrap_or(current_exe)
        .to_string()
}

/// Location of the XDG autostart entry: `$XDG_CONFIG_HOME/autostart`, which
/// is what the session's autostart implementation reads, not a fixed
/// `~/.config`.
#[cfg(any(target_os = "linux", test))]
fn autostart_path(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("autostart/klaayguard.desktop")
}

/// Whether an APPIMAGE value names the image this process runs from. The
/// AppImage runtime exports APPIMAGE and APPDIR to every child, so a deb/rpm
/// agent started from an AppImage browser or terminal inherits a foreign
/// pair; only an executable inside APPDIR, the runtime's mount of that file,
/// is ours.
#[cfg(any(target_os = "linux", test))]
fn appimage_is_own(
    appimage: &std::path::Path,
    appdir: &std::path::Path,
    current_exe: &std::path::Path,
) -> bool {
    appimage.is_absolute() && appdir.is_absolute() && current_exe.starts_with(appdir)
}

/// The AppImage this process runs from, if any (see `appimage_is_own`).
#[cfg(target_os = "linux")]
fn own_appimage() -> Option<std::path::PathBuf> {
    let appimage = std::path::PathBuf::from(std::env::var_os("APPIMAGE")?);
    let appdir = std::path::PathBuf::from(std::env::var_os("APPDIR")?);
    let exe = std::env::current_exe().ok()?;
    (appimage_is_own(&appimage, &appdir, &exe) && appimage.is_file()).then_some(appimage)
}

/// Whether the user disabled autostart. The GNOME toggle writes
/// `X-GNOME-Autostart-enabled=false`; `Hidden=true` is the generic disable.
/// Honor either, so a rewrite does not turn autostart back on.
#[cfg(any(target_os = "linux", test))]
fn autostart_is_user_disabled(contents: &str) -> bool {
    contents.lines().any(|l| {
        let l = l.trim().replace(' ', "").to_ascii_lowercase();
        l == "x-gnome-autostart-enabled=false" || l == "hidden=true"
    })
}

/// Install or refresh the autostart entry so the agent starts at login,
/// matching the macOS LaunchAgent behavior. Idempotent, honors a user
/// disable, and writes atomically.
#[cfg(target_os = "linux")]
fn install_autostart_entry() -> Result<(), String> {
    let config_dir = dirs::config_dir().ok_or("no config directory")?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;

    // Trust APPIMAGE only for the image this process runs from; a stray value
    // inherited from another AppImage would persist its path under our name.
    let appimage = own_appimage().map(|p| p.to_string_lossy().into_owned());
    let entry = autostart_entry(&autostart_exec(appimage.as_deref(), &exe.to_string_lossy()));
    let path = autostart_path(&config_dir);

    if let Ok(existing) = std::fs::read_to_string(&path) {
        if autostart_is_user_disabled(&existing) {
            log::info!("autostart: user disabled the entry; leaving it");
            return Ok(());
        }
        if existing == entry {
            return Ok(());
        }
    }

    let dir = path
        .parent()
        .ok_or_else(|| "autostart path has no parent".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    // Write to a temp file in the same dir, then rename, so a crash mid-write
    // never leaves a truncated entry.
    let tmp = path.with_extension("desktop.tmp");
    std::fs::write(&tmp, &entry).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
}

/// Write (or repair) the HKCU Run value the installer created, so a value a
/// cleanup tool or policy removed comes back at the next launch, as the Linux
/// and macOS paths do. A user who turned KlaayGuard off in Task Manager >
/// Startup apps is honoured: Windows records that in StartupApproved and
/// ignores the Run value, which this never touches.
#[cfg(target_os = "windows")]
fn ensure_autostart_entry() -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let want = format!("\"{}\"", exe.to_string_lossy());
    let (key, _) = winreg::RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            KEY_READ | KEY_WRITE,
        )
        .map_err(|e| format!("open Run key: {}", e))?;
    if key.get_value::<String, _>("KlaayGuard").ok().as_deref() == Some(want.as_str()) {
        return Ok(());
    }
    key.set_value("KlaayGuard", &want)
        .map_err(|e| format!("write Run value: {}", e))
}

/// Resolve the stable device identity. The first run decides it and stores it
/// in the keychain; every later run returns the stored value, cached in memory
/// after the first successful read. `system_info` is the osquery rows this
/// cycle already collected, so the serial query is not run a second time.
async fn get_device_identity_internal<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    state: &Arc<AppState>,
    system_info: Option<&Value>,
) -> Result<String, String> {
    if let Some(cached) = lock_read(&state.device_identity).clone() {
        return Ok(cached);
    }
    // Fast path, and the rule the tests pin as IdentityDecision::Use.
    match keychain::load_device_identity() {
        Ok(Some(stored)) if !stored.is_empty() => {
            *lock_write(&state.device_identity) = Some(stored.clone());
            return Ok(stored);
        }
        Ok(_) => {}
        Err(e) => {
            // A broken credential store forces re-derivation every cycle.
            // Report it so a locked or absent Secret Service is visible.
            log::error!("keychain: device identity load failed: {}", e);
            sentry::capture_message(
                &format!("keychain_identity_load_failed: {}", e),
                Level::Error,
            );
        }
    }

    let hardware_serial = match system_info {
        Some(rows) => extract_serial(rows),
        None => match execute_sql_batch(
            app.clone(),
            vec![(
                "system_info".to_string(),
                "SELECT * FROM system_info".to_string(),
            )],
        )
        .await
        {
            Ok(result) => extract_serial(result.get("system_info").unwrap_or(&Value::Null)),
            Err(e) => {
                log::warn!("identity: system_info query failed: {}", e);
                None
            }
        },
    };

    let (identity, source) = match decide_device_identity(
        None,
        hardware_serial.as_deref(),
        read_machine_id().as_deref(),
    ) {
        IdentityDecision::Use(v) => (v, "stored"),
        IdentityDecision::Adopt(v) => (v, "adopted from host"),
        IdentityDecision::Generate => (generate_device_identity()?, "generated"),
    };

    match keychain::save_device_identity(&identity) {
        // Cache only what is persisted, so a failed save is retried next cycle.
        Ok(()) => *lock_write(&state.device_identity) = Some(identity.clone()),
        Err(e) => {
            // Report but still return the identity: one collection with an
            // unstored identity beats none.
            log::error!("identity: keychain save failed: {}", e);
            sentry::capture_message(&format!("device_identity_save_failed: {}", e), Level::Error);
        }
    }
    log::info!("identity: device identity {}", source);
    Ok(identity)
}

/// Send a request, retrying transient failures (network errors, 429, 5xx)
/// with the fixed delay ladder. Returns the last response, or the network
/// error once the ladder is exhausted. The builder must be cloneable (a bytes
/// body is), which every call here satisfies.
async fn send_with_retry(
    request: reqwest::RequestBuilder,
    label: &str,
) -> Result<reqwest::Response, String> {
    let is_transient_status = |code: u16| -> bool { code == 429 || (500..=599).contains(&code) };
    let retry_delays = [60u64, 120u64];
    let mut attempt = 0usize;
    loop {
        let Some(req) = request.try_clone() else {
            return Err(format!("{}: request is not retryable", label));
        };
        match req.send().await {
            Ok(resp) => {
                add_breadcrumb(
                    "collection",
                    &format!("{}_status:{}", label, resp.status().as_u16()),
                    Level::Info,
                );
                if !resp.status().is_success()
                    && is_transient_status(resp.status().as_u16())
                    && attempt < retry_delays.len()
                {
                    let delay = retry_delays[attempt];
                    add_breadcrumb(
                        "collection",
                        &format!("{}_transient_retry_in_s:{}", label, delay),
                        Level::Warning,
                    );
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    attempt += 1;
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                add_breadcrumb(
                    "collection",
                    &format!("{}_network_error:{}", label, e),
                    Level::Warning,
                );
                if attempt < retry_delays.len() {
                    let delay = retry_delays[attempt];
                    add_breadcrumb(
                        "collection",
                        &format!("{}_retry_in_s:{}", label, delay),
                        Level::Warning,
                    );
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    attempt += 1;
                    continue;
                }
                return Err(e.to_string());
            }
        }
    }
}

async fn run_cycle<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    state: &Arc<AppState>,
    client: &reqwest::Client,
) -> Result<(), String> {
    let token = match lock_read(&state.auth_token).clone() {
        Some(t) => t,
        None => return Ok(()),
    };

    let base = state.api_base_url.as_str();

    // Mark an attempt start and notify UI listeners
    *lock_write(&state.last_attempt_at) = Some(Instant::now());
    let _ = app.emit("collection:attempt", ());

    // 1) GET /klaayguard/config
    add_breadcrumb("collection", "config_fetch_start", Level::Info);
    let cfg_resp = match send_with_retry(
        client
            .get(format!("{}/klaayguard/config", base))
            .bearer_auth(&token),
        "config",
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            emit_error(
                app,
                "collection:error",
                json!({ "stage": "config", "error": e }),
            );
            return Ok(());
        }
    };

    if cfg_resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || cfg_resp.status() == reqwest::StatusCode::FORBIDDEN
    {
        invalidate_auth(app, state);
        let _ = app.emit(
            "collection:error",
            json!({ "stage": "config", "status": cfg_resp.status().as_u16() }),
        );
        sentry::capture_message("collection_auth_invalidated_on_config", Level::Warning);
        return Ok(());
    }
    if !cfg_resp.status().is_success() {
        emit_error(
            app,
            "collection:error",
            json!({ "stage": "config", "status": cfg_resp.status().as_u16() }),
        );
        return Ok(());
    }

    name_unnamed_holder(state);

    let cfg_json: Value = cfg_resp.json().await.map_err(|e| e.to_string())?;
    let items = parse_config_items(&cfg_json, std::env::consts::OS);

    if items.is_empty() {
        emit_error(
            app,
            "collection:error",
            json!({ "stage": "config", "reason": "no_tables" }),
        );
        return Ok(());
    }

    // Split osquery items from native (builtin) ones. osquery runs through the
    // sidecar; builtin checks resolve in-process. Both fill the same results
    // map keyed by logical id, so the payload builder is unchanged.
    let mut osquery_queries: Vec<(String, String)> = Vec::new();
    let mut builtin_checks: Vec<(String, String)> = Vec::new();
    for item in items {
        match item {
            CollectionItem::Osquery { id, sql } => osquery_queries.push((id, sql)),
            CollectionItem::Builtin { id, check } => builtin_checks.push((id, check)),
        }
    }

    // 2) Native checks first: they do not need osquery, so a sidecar that
    //    cannot spawn must not cost the posture they can still report.
    let mut results: HashMap<String, Value> = HashMap::new();
    for (id, check) in builtin_checks {
        results.insert(id, run_builtin_check(&check));
    }
    // 2b) osquery. A sidecar that fails to spawn at all is a systemic problem:
    //     report it, and still send whatever the native checks produced.
    add_breadcrumb("collection", "osquery_start", Level::Info);
    if !osquery_queries.is_empty() {
        match execute_sql_batch(app.clone(), osquery_queries).await {
            Ok(rows) => results.extend(rows),
            Err(e) => emit_error(
                app,
                "collection:error",
                json!({ "stage": "osquery", "error": e }),
            ),
        }
    }

    // 3) Build the JSON:API payload from the freshly collected rows
    let collected_at = chrono::Utc::now().to_rfc3339();
    let device_serial = get_device_identity_internal(app, state, results.get("system_info"))
        .await
        .unwrap_or_else(|_| "unknown".to_string());
    let items = build_payload_items(&results, &collected_at);
    let row_count = items.len();
    if row_count == 0 {
        let _ = app.emit("collection:success", json!({ "sent_rows": 0 }));
        return Ok(());
    }
    let payload = JsonApiPayload {
        data: items,
        meta: Some(checkin_meta(&device_serial)),
        jsonapi: Some(json!({ "version": "1.0" })),
    };

    // 4) POST straight to /klaayguard/data, with the same transient-retry ladder
    let body_json = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    let resp = match send_with_retry(
        client
            .post(format!("{}/klaayguard/data", base))
            .bearer_auth(&token)
            .header(reqwest::header::CONTENT_TYPE, "application/vnd.api+json")
            .header(reqwest::header::ACCEPT, "application/vnd.api+json")
            .body(body_json),
        "post",
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            emit_error(
                app,
                "collection:error",
                json!({ "stage": "post", "error": e }),
            );
            return Ok(());
        }
    };
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || resp.status() == reqwest::StatusCode::FORBIDDEN
    {
        invalidate_auth(app, state);
        let _ = app.emit(
            "collection:error",
            json!({ "stage": "post", "status": resp.status().as_u16() }),
        );
        return Ok(());
    }
    if resp.status().is_success() {
        let _ = app.emit("collection:success", json!({ "sent_rows": row_count }));
        log::info!("collection_success sent_rows={}", row_count);
        add_breadcrumb(
            "collection",
            &format!("success_count:{}", row_count),
            Level::Info,
        );
        return Ok(());
    }
    emit_error(
        app,
        "collection:error",
        json!({ "stage": "post", "status": resp.status().as_u16() }),
    );
    Ok(())
}

fn spawn_background_loop(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        // The config GET and data POST are small: give the whole request a
        // deadline, so a peer that accepts and then stalls cannot park this
        // loop for the life of the process.
        let client = http_client(Some(Duration::from_secs(60)));

        // wait for token once
        loop {
            if lock_read(&state.auth_token).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }

        // interval's first tick fires immediately, giving the initial collection.
        // Skip (don't burst) ticks missed while the machine was asleep. A token
        // acquired between ticks (a sign-in after a sign-out or a 401) collects
        // at once and restarts the interval from there, instead of waiting out
        // the rest of the period behind a tray that says "Fetching now…".
        let mut interval =
            tokio::time::interval(Duration::from_secs(collection_interval_seconds()));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = state.token_acquired.notified() => {
                    interval.reset();
                }
            }
            if let Err(e) = run_cycle(&app, &state, &client).await {
                log::error!("cycle error: {}", e);
                emit_error(
                    &app,
                    "collection:error",
                    json!({ "stage": "internal", "error": e }),
                );
            }
        }
    });
}

/// Minimal XML text/attribute escaping for values interpolated into the plist
/// template. Keeps a stray `&`/`<`/`>` (or an injected `</string>…`) in a path or URL
/// from corrupting — or injecting keys into — the generated launchd plist.
#[cfg(any(target_os = "macos", test))]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Whether this process may write the shared LaunchAgent.
///
/// Two rules, and both must hold.
///
/// The plist is one file with one label, shared by every build on the machine,
/// and it names both the app to launch and the API base to inject. Whoever
/// writes it decides both, so only a binary inside `installed_bundle` may. A
/// developer binary, a copy on a mounted disk image, or an old bundle in the
/// Trash would otherwise aim launchd at the installed app while handing it a
/// different server.
///
/// `installed` must also hold. With no app in `/Applications` the plist has
/// nothing to start, and any path it named would be gone by the next login.
/// Without this the guard binds nothing in that state, because the caller then
/// derives the app path from the running binary and every build matches itself.
#[cfg(any(target_os = "macos", test))]
fn may_write_launch_agent(
    current_exe: &std::path::Path,
    installed_bundle: &std::path::Path,
    installed: bool,
) -> bool {
    installed && current_exe.starts_with(installed_bundle)
}

/// The API base to write into the LaunchAgent.
///
/// Always the compiled value. The plist hands the agent `VITE_API_BASE_URL`, so
/// an agent that resolved this through `get_api_base_url` would write back
/// whatever the plist already held: one wrong value would survive every restart
/// and every update, because each run rewrites it and the content check finds
/// nothing to change.
///
/// This exists as its own function so a test can set that variable and prove the
/// choice ignores it. Inlining the call made the rule untestable.
#[cfg(any(target_os = "macos", test))]
fn plist_api_base() -> String {
    compiled_api_base_url().to_string()
}

/// Build the launchd plist. Pure, so every rule it encodes is testable without
/// touching `~/Library/LaunchAgents` or running `launchctl`.
///
/// `RunAtLoad` and `KeepAlive` are always true: the file is written only for an
/// app that is installed, so the job it describes always has something to run.
#[cfg(any(target_os = "macos", test))]
fn render_launch_agent_plist(label: &str, app_path: &str, log_dir: &str, api_base: &str) -> String {
    include_str!("../resources/com.klaay.klaayguard.plist")
        .replace("__LABEL__", label)
        .replace("__OPEN_PATH__", "/usr/bin/open")
        .replace("__RUN_AT_LOAD__", "<true/>")
        .replace("__KEEP_ALIVE__", "<true/>")
        .replace("__APP_PATH__", &xml_escape(app_path))
        .replace("__VITE_API_BASE_URL__", &xml_escape(api_base))
        .replace("__LOG_DIR__", &xml_escape(log_dir))
}

/// Installs a launch agent for automatic startup on macOS.
///
/// This function creates a launchd plist file in the user's LaunchAgents directory
/// and loads it to ensure the app starts automatically on login. This is a mandatory
/// security feature that cannot be disabled by users.
///
/// It writes nothing unless the running binary is the installed app under
/// `/Applications` — see `may_write_launch_agent`. A KeepAlive job pointing at a
/// path that is gone at next login makes launchd respawn every ThrottleInterval
/// seconds, forever, and a foreign writer can redirect the installed agent to
/// its own server.
#[cfg(target_os = "macos")]
async fn install_launch_agent() -> Result<String, String> {
    use std::fs;
    let home_dir = dirs::home_dir().ok_or("Could not find home directory")?;
    let launch_agents_dir = home_dir.join("Library/LaunchAgents");
    let label = "com.klaay.klaayguard";
    let plist_path = launch_agents_dir.join(format!("{}.plist", label));
    let uid = nix::unistd::getuid().as_raw();
    let domain = format!("gui/{}", uid);

    fs::create_dir_all(&launch_agents_dir)
        .map_err(|e| format!("Failed to create LaunchAgents directory: {}", e))?;

    // Resolve executable path (prefer installed app)
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Failed to get current executable path: {}", e))?;
    let app_bundle_path = std::path::Path::new("/Applications/KlaayGuard.app");
    let installed_exists = app_bundle_path.exists();

    if !may_write_launch_agent(&current_exe, app_bundle_path, installed_exists) {
        let msg = format!(
            "not writing the LaunchAgent: this build runs from {:?}, and the installed app is {}",
            current_exe,
            if installed_exists {
                "elsewhere"
            } else {
                "missing"
            }
        );
        log::info!("{}", msg);
        return Ok(msg);
    }
    let app_path = app_bundle_path.to_string_lossy().to_string();

    // The compiled server, never the injected one — see `plist_api_base`. It is
    // the same value the single-instance lock keys on; they must not drift.
    let api_base_for_plist = plist_api_base();

    let log_dir = home_dir.join("Library/Logs/KlaayGuard");
    fs::create_dir_all(&log_dir).map_err(|e| format!("Failed to create log directory: {}", e))?;

    let plist_content = render_launch_agent_plist(
        label,
        &app_path,
        &log_dir.to_string_lossy(),
        &api_base_for_plist,
    );

    let mut needs_reload = true;
    if let Ok(existing) = fs::read_to_string(&plist_path) {
        if existing == plist_content {
            let output = std::process::Command::new("launchctl")
                .args(["print", &format!("{}/{}", domain, label)])
                .output()
                .map_err(|e| format!("Failed to check launch agent status: {}", e))?;
            if output.status.success() {
                return Ok("Launch agent already installed and running".to_string());
            }
            needs_reload = false;
        }
    }

    fs::write(&plist_path, plist_content)
        .map_err(|e| format!("Failed to write plist file: {}", e))?;

    // No `installed_exists` check here. The guard above returns early unless the
    // app is installed, so by this point it always is.
    if needs_reload {
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &format!("{}/{}", domain, label)])
            .output();
    }

    // Enable the label BEFORE bootstrap. If it was left `disabled` in launchd's
    // override DB (e.g. by a prior `bootout`/`disable`), bootstrap fails with
    // "Input/output error" and RunAtLoad never fires at login. Enabling afterwards
    // can never recover, because bootstrap's failure returns early.
    let _ = std::process::Command::new("launchctl")
        .args(["enable", &format!("{}/{}", domain, label)])
        .output();

    let output = std::process::Command::new("launchctl")
        .args(["bootstrap", &domain, plist_path.to_str().unwrap()])
        .output()
        .map_err(|e| format!("Failed to bootstrap launch agent: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("EEXIST") && !stderr.contains("already loaded") {
            return Err(format!("Failed to bootstrap launch agent: {}", stderr));
        }
    }

    let _ = std::process::Command::new("launchctl")
        .args(["kickstart", "-k", &format!("{}/{}", domain, label)])
        .output();

    Ok("Launch agent installed successfully".to_string())
}

#[derive(serde::Deserialize)]
struct ReleaseAsset {
    id: u64,
    // Human-facing label, e.g. "MacOS (Apple silicon)". Does NOT encode arch reliably.
    name: String,
    // The real artifact filename, e.g. "KlaayGuard_0.1.12_macOS_arm64_production.dmg".
    original_name: Option<String>,
    // Expected hash of the asset bytes (bare hex or "sha256:" prefixed).
    sha256: Option<String>,
}

/// The update asset chosen for this host: which one to download and its expected hash.
struct SelectedUpdate {
    asset_id: String,
    sha256: Option<String>,
}

/// Pick the AppImage asset for this architecture. `original_name` is the
/// contract; the human label carries no architecture.
#[cfg(any(target_os = "linux", test))]
fn select_appimage_asset<'a>(assets: &'a [ReleaseAsset], arch: &str) -> Option<&'a ReleaseAsset> {
    let infix = format!("Linux_{}", arch);
    assets.iter().find(|asset| {
        asset
            .original_name
            .as_deref()
            .is_some_and(|n| n.ends_with(".AppImage") && n.contains(&infix))
    })
}

/// The release-artifact architecture tag for a Windows host. Windows and
/// macOS artifacts use the short tag ("x64", "arm64"); Linux ones use the
/// Rust arch string ("x86_64"). Passing std::env::consts::ARCH straight
/// through would never match "Windows_x64" and the agent would stop updating
/// in silence. An arch with no tag returns None rather than guess; a tagged
/// arch with no asset in the release logs that honestly.
#[cfg(any(target_os = "windows", test))]
fn windows_arch_tag(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("x64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

/// Pick the NSIS installer asset for this architecture. `original_name` is
/// the contract; the friendly label ("Windows Installer") carries neither the
/// architecture nor the file type. No label fallback: a label-only match
/// could hand back a `.deb`. The suffix test also rejects `.nsis.zip`,
/// `.exe.sig`, and `.msi`.
#[cfg(any(target_os = "windows", test))]
fn select_windows_installer_asset<'a>(
    assets: &'a [ReleaseAsset],
    arch_tag: &str,
) -> Option<&'a ReleaseAsset> {
    let infix = format!("Windows_{}", arch_tag);
    assets.iter().find(|asset| {
        asset
            .original_name
            .as_deref()
            .is_some_and(|n| n.ends_with(".exe") && n.contains(&infix))
    })
}

/// Where to stage a downloaded replacement (AppImage, .app bundle): the same
/// directory as the target, so the final rename stays on one filesystem and
/// is atomic.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn staged_sibling_path(target: &std::path::Path, pid: u32) -> std::path::PathBuf {
    let base = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "KlaayGuard".to_string());
    target.with_file_name(format!(".{}.update-{}", base, pid))
}

/// macOS artifact tags for the current host: (filename infix, friendly-name infix).
#[cfg(target_os = "macos")]
fn host_arch_tags() -> Option<(&'static str, &'static str)> {
    match std::env::consts::ARCH {
        "aarch64" => Some(("macOS_arm64", "Apple silicon")),
        "x86_64" => Some(("macOS_x64", "Intel")),
        _ => None,
    }
}

/// Pick the DMG asset matching this host's architecture. Prefers the real
/// artifact filename (`original_name`); falls back to the friendly label only
/// when it is absent. Returns None rather than guess the wrong architecture.
#[cfg(any(target_os = "macos", test))]
fn select_dmg_asset<'a>(
    assets: &'a [ReleaseAsset],
    arch_tag: &str,
    arch_label: &str,
) -> Option<&'a ReleaseAsset> {
    assets
        .iter()
        .find(|asset| match asset.original_name.as_deref() {
            Some(orig) => orig.ends_with(".dmg") && orig.contains(arch_tag),
            None => asset.name.contains(arch_label),
        })
}

/// Whether `bytes` hashes to `expected` (bare hex or "sha256:"-prefixed).
fn sha256_matches(bytes: &[u8], expected: &str) -> bool {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual = hex_lower(&hasher.finalize());
    actual.eq_ignore_ascii_case(expected.trim_start_matches("sha256:"))
}

/// Whether this platform refuses an update that carries no server checksum.
/// macOS has a second, independent gate after the hash (codesign team match
/// plus a Gatekeeper assessment), so it may proceed. Linux and Windows have
/// nothing after the hash, so unverifiable bytes must never run. `os` is a
/// parameter so tests pin every branch without cross-compiling.
fn update_requires_checksum(os: &str) -> bool {
    os != "macos"
}

#[derive(serde::Deserialize)]
struct ReleaseInfo {
    version: String, // This is the tag_name from GitHub
    assets: Vec<ReleaseAsset>,
}

fn get_api_base_url() -> String {
    // Use the same logic as the main app startup
    std::env::var("VITE_API_BASE_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_API_BASE_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://api.klaay.com".to_string())
}

fn get_frontend_url() -> String {
    std::env::var("VITE_FRONTEND_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_FRONTEND_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://app.klaay.com".to_string())
}

/// Environment variables that the AppImage runtime (AppRun) points at the
/// bundled libraries and GTK modules. A browser we spawn must not inherit the
/// AppImage values, or it loads the wrong libraries and fails to start.
#[cfg(target_os = "linux")]
const APPIMAGE_CHILD_ENV_VARS: [&str; 12] = [
    // Set by the AppImage runtime (AppRun).
    "PATH",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "XDG_DATA_DIRS",
    "GSETTINGS_SCHEMA_DIR",
    // Set by the linuxdeploy GTK hook.
    "GTK_PATH",
    "GTK_EXE_PREFIX",
    "GTK_DATA_PREFIX",
    "GTK_IM_MODULE_FILE",
    "GDK_PIXBUF_MODULE_FILE",
    "GIO_MODULE_DIR",
    "GIO_EXTRA_MODULES",
];

/// Remove the colon-separated entries that live under `appdir` (the AppImage
/// mount point). Returns the remaining entries, or None when nothing is left,
/// which tells the caller to unset the variable for the child process.
#[cfg(target_os = "linux")]
fn strip_appimage_paths(value: &str, appdir: &str) -> Option<String> {
    let appdir = appdir.trim_end_matches('/');
    let prefix = format!("{}/", appdir);
    let kept: Vec<&str> = value
        .split(':')
        .filter(|p| !p.is_empty() && *p != appdir && !p.starts_with(&prefix))
        .collect();
    (!kept.is_empty()).then(|| kept.join(":"))
}

/// Open a URL in the user's default browser.
///
/// Inside a Linux AppImage, `xdg-open` and the browser it launches inherit the
/// AppImage's `LD_LIBRARY_PATH` and GTK module variables, so the browser loads
/// the bundled libraries and fails to start — sign-in then never opens, with no
/// error. When we detect the AppImage (`APPDIR` is set), spawn `xdg-open`
/// ourselves with those variables stripped of AppImage paths. Off Linux, and on
/// Linux outside an AppImage, use the opener plugin unchanged.
/// Strip the AppImage-injected library paths from a spawned command. From an
/// AppImage a system binary (browser, xdg-open, notify-send) must not inherit
/// the bundled `LD_LIBRARY_PATH`/GTK paths, or it fails to start. A no-op when
/// not running from an AppImage.
#[cfg(target_os = "linux")]
fn apply_appimage_sanitization(cmd: &mut std::process::Command) {
    let Some(appdir) = std::env::var("APPDIR").ok().filter(|s| !s.is_empty()) else {
        return;
    };
    for var in APPIMAGE_CHILD_ENV_VARS {
        if let Ok(current) = std::env::var(var) {
            match strip_appimage_paths(&current, &appdir) {
                Some(kept) => {
                    cmd.env(var, kept);
                }
                None => {
                    cmd.env_remove(var);
                }
            }
        }
    }
}

/// The browser binary name from `xdg-settings get default-web-browser`, which
/// returns a desktop-file name like `chromium.desktop`.
#[cfg(target_os = "linux")]
fn browser_binary_from_setting(setting: &str) -> Option<String> {
    let name = setting.trim().strip_suffix(".desktop")?;
    (!name.is_empty()).then(|| name.to_string())
}

/// Ask the desktop for the default browser binary.
#[cfg(target_os = "linux")]
fn default_browser_binary() -> Option<String> {
    let mut cmd = std::process::Command::new("xdg-settings");
    cmd.args(["get", "default-web-browser"]);
    apply_appimage_sanitization(&mut cmd);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    browser_binary_from_setting(&String::from_utf8_lossy(&out.stdout))
}

/// Open the URL in a new browser window. A focusing compositor (Hyprland,
/// GNOME, KDE) raises a new window, unlike a background tab in a running
/// browser. Most browsers accept `--new-window`.
#[cfg(target_os = "linux")]
fn open_in_new_browser_window(url: &str) -> Result<(), String> {
    let browser = default_browser_binary().ok_or("no default browser")?;
    let mut cmd = std::process::Command::new(&browser);
    cmd.args(["--new-window", url]);
    apply_appimage_sanitization(&mut cmd);
    spawn_and_reap(&mut cmd).map_err(|e| format!("{}: {}", browser, e))
}

/// Copy text to the clipboard, best-effort. Tries Wayland (`wl-copy`) then X11
/// (`xclip`, `xsel`), so it works across desktops. Returns true if a tool ran.
#[cfg(target_os = "linux")]
fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    let attempts: [(&str, &[&str]); 3] = [
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ];
    for (bin, args) in attempts {
        let mut cmd = std::process::Command::new(bin);
        cmd.args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        apply_appimage_sanitization(&mut cmd);
        if let Ok(mut child) = cmd.spawn() {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            // Do not block here (wl-copy forks a resident server and its
            // parent exits at once); reap the child on a thread.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return true;
        }
    }
    false
}

/// Open a URL in the browser: a new window first (a focusing compositor raises
/// it), else `xdg-open` (a tab). No notification — the caller handles that.
#[cfg(target_os = "linux")]
fn open_url_in_browser(url: &str) -> Result<(), String> {
    if open_in_new_browser_window(url).is_ok() {
        return Ok(());
    }
    let mut cmd = std::process::Command::new("xdg-open");
    cmd.arg(url);
    apply_appimage_sanitization(&mut cmd);
    spawn_and_reap(&mut cmd).map_err(|e| format!("xdg-open: {}", e))
}

/// Whether `notify-send` can attach a clickable action (libnotify >= 0.8).
/// Older distros lack it, so we check once and fall back to a plain notice.
#[cfg(target_os = "linux")]
fn notify_send_supports_actions() -> bool {
    use std::sync::OnceLock;
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let mut cmd = std::process::Command::new("notify-send");
        cmd.arg("--help");
        apply_appimage_sanitization(&mut cmd);
        cmd.output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("--action"))
            .unwrap_or(false)
    })
}

/// Tell the user the browser is opening, and how to reach the page if the window
/// did not surface. The URL is in the body and on the clipboard. Where the
/// notification daemon supports actions, clicking the notification opens the URL.
#[cfg(target_os = "linux")]
fn notify_sign_in_link(url: &str, on_clipboard: bool) {
    let title = "KlaayGuard — sign in";
    let clip = if on_clipboard {
        " It is on your clipboard, or open it here:"
    } else {
        " Open it here:"
    };
    let body = format!("Opening your browser to sign in.{}\n{}", clip, url);

    if notify_send_supports_actions() {
        // notify-send --action implies --wait: it stays until the user acts,
        // then prints the action name. On click, open the URL. Run off-thread.
        let url = url.to_string();
        std::thread::spawn(move || {
            let mut cmd = std::process::Command::new("notify-send");
            cmd.args(["--app-name=KlaayGuard", "--action=default=Open sign-in"])
                .arg(title)
                .arg(&body)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null());
            apply_appimage_sanitization(&mut cmd);
            if let Ok(out) = cmd.output() {
                if String::from_utf8_lossy(&out.stdout).trim() == "default" {
                    let _ = open_url_in_browser(&url);
                }
            }
        });
    } else {
        notify_user(title, &body);
    }
}

/// Open a URL in the user's browser.
///
/// On Wayland an app cannot raise a window, and a URL opened in an
/// already-running browser lands as a background tab the user may never see. So
/// on Linux open a new browser window (a focusing compositor raises it); the
/// sign-in flow adds the clipboard copy and notification itself (see
/// `open_sign_in`). Off Linux, use the opener plugin unchanged.
fn open_external_url<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    url: &str,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if open_url_in_browser(url).is_ok() {
            return Ok(());
        }
        log::warn!("browser open failed; falling back to opener plugin");
    }
    app.opener()
        .open_url(url.to_string(), None::<&str>)
        .map_err(|e| e.to_string())
}

/// Open a Klaay Frontend path in the default browser.
fn open_frontend<R: tauri::Runtime>(app: &tauri::AppHandle<R>, path: &str) {
    let url = format!("{}{}", get_frontend_url(), path);
    log::info!("opening url={}", url);
    if let Err(e) = open_external_url(app, &url) {
        log::error!("failed to open url {}: {}", url, e);
    }
}

/// Open the Klaay sign-in page in the browser and wait on a loopback port
/// for the answer.
///
/// The agent has no window, so the browser does the whole sign-in - which is
/// why Google, Microsoft, and password all work here without this process
/// knowing about any of them. What comes back arrives on `127.0.0.1`, not on
/// a `klaayguard://` URL any local program could have claimed, and it is
/// released only against a verifier the browser never sees. So
/// the token binds to this machine, and there is no nonce for anyone to get
/// wrong.
fn open_sign_in<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let state = app.state::<Arc<AppState>>().inner().clone();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let pending = match sign_in::start(&state.api_base_url).await {
            Ok(pending) => pending,
            Err(e) => {
                log::error!("sign_in_start_failed: {}", e);
                sentry::capture_message(&format!("sign_in_start_failed: {}", e), Level::Error);
                notify_user(
                    "KlaayGuard",
                    "Could not start sign-in. Check your connection and try again from the tray.",
                );
                return;
            }
        };

        // The request id is not a secret: it selects a row and nothing more,
        // so it is safe in an address bar, a browser history, or a replay.
        let path = format!("/login?app=klaayguard&request={}", pending.request_id);
        #[cfg(target_os = "linux")]
        {
            // On Wayland the browser window may not surface: put the link on
            // the clipboard and in a notification (clickable where the daemon
            // supports it), for the sign-in flow only.
            let url = format!("{}{}", get_frontend_url(), path);
            let on_clipboard = copy_to_clipboard(&url);
            notify_sign_in_link(&url, on_clipboard);
        }
        open_frontend(&app, &path);

        // Blocking accept, so it belongs off the async workers.
        let sign_in::Pending {
            verifier, listener, ..
        } = pending;
        let code =
            match tauri::async_runtime::spawn_blocking(move || sign_in::wait_for_code(listener))
                .await
            {
                Ok(Some(code)) => code,
                Ok(None) => {
                    log::info!("sign_in_no_code: the browser never came back");
                    return;
                }
                Err(e) => {
                    log::error!("sign_in_listener_failed: {}", e);
                    return;
                }
            };

        match sign_in::claim(&state.api_base_url, &code, &verifier).await {
            Ok(token) => adopt_token(&app, &state, token),
            Err(e) => {
                log::error!("sign_in_claim_failed: {}", e);
                sentry::capture_message(&format!("sign_in_claim_failed: {}", e), Level::Error);
                let _ = app.emit("auth:status", json!({ "authenticated": false }));
            }
        }
    });
}

/// Handles + assets for keeping the tray in sync with auth state.
struct TrayMenu {
    item: tauri::menu::MenuItem<tauri::Wry>,
    /// The line naming the signed-in person, added at the top of the menu only
    /// once the API has named them.
    user: tauri::menu::MenuItem<tauri::Wry>,
    /// Whether `user` is in the menu right now.
    user_shown: std::sync::atomic::AtomicBool,
    /// The "Sign out" item, added to the menu only while signed in.
    sign_out: tauri::menu::MenuItem<tauri::Wry>,
    /// The tray menu itself, so "Sign out" can be added and removed at runtime.
    menu: tauri::menu::Menu<tauri::Wry>,
    tray: tauri::tray::TrayIcon<tauri::Wry>,
    green: tauri::image::Image<'static>,
    red: tauri::image::Image<'static>,
    last_signed_in: std::sync::atomic::AtomicBool,
}

/// Composite a filled status dot into the bottom-right of an RGBA icon. The base
/// icon is already decoded by Tauri, so no image-decode dependency is needed.
fn icon_with_dot(base: &tauri::image::Image, color: [u8; 4]) -> tauri::image::Image<'static> {
    let (w, h) = (base.width(), base.height());
    let mut rgba = base.rgba().to_vec();
    let r = ((w.min(h) as f32) * 0.30) as i32;
    let (cx, cy) = (w as i32 - r - 1, h as i32 - r - 1);
    for y in 0..h as i32 {
        for x in 0..w as i32 {
            let (dx, dy) = (x - cx, y - cy);
            if dx * dx + dy * dy <= r * r {
                let i = ((y as u32 * w + x as u32) * 4) as usize;
                rgba[i..i + 4].copy_from_slice(&color);
            }
        }
    }
    tauri::image::Image::new_owned(rgba, w, h)
}

/// Format seconds-until-next-fetch as a short countdown string.
fn fmt_countdown(secs: i64) -> String {
    if secs <= 0 {
        return "Fetching now…".to_string();
    }
    let (m, s) = (secs / 60, secs % 60);
    if m > 0 {
        format!("Next fetch in {}m {:02}s", m, s)
    } else {
        format!("Next fetch in {}s", s)
    }
}

/// Refresh the single tray item: a clickable "Sign in" when signed out, or a greyed
/// countdown to the next fetch when signed in. Menu mutation runs on the main thread.
fn refresh_tray<R: tauri::Runtime>(app: &tauri::AppHandle<R>, state: &Arc<AppState>) {
    let (text, enabled) = if lock_read(&state.auth_token).is_some() {
        let interval = collection_interval_seconds() as i64;
        let remaining = match *lock_read(&state.last_attempt_at) {
            Some(t) => (interval - t.elapsed().as_secs() as i64).max(0),
            None => 0,
        };
        (fmt_countdown(remaining), false)
    } else {
        ("Sign in".to_string(), true)
    };
    let signed_in = !enabled;
    let user_label = lock_read(&state.user_label).clone();
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(tray) = handle.try_state::<TrayMenu>() {
            let _ = tray.item.set_text(&text);
            let _ = tray.item.set_enabled(enabled);
            // The name line sits above every other item, and joins the menu
            // only once the API has named the person. Its text is set before
            // it joins, so the line never shows up blank.
            let show_user = user_label.is_some();
            if let Some(label) = &user_label {
                let _ = tray.user.set_text(label);
            }
            let was_shown = tray
                .user_shown
                .swap(show_user, std::sync::atomic::Ordering::Relaxed);
            if was_shown != show_user {
                let _ = if show_user {
                    tray.menu.prepend(&tray.user)
                } else {
                    tray.menu.remove(&tray.user)
                };
            }
            // On an auth-state flip, swap the status dot and add or remove the
            // "Sign out" item. "Sign out" shows only while signed in, appended
            // last so it sits at the very bottom of the menu.
            let prev = tray
                .last_signed_in
                .swap(signed_in, std::sync::atomic::Ordering::Relaxed);
            if prev != signed_in {
                let icon = if signed_in {
                    tray.green.clone()
                } else {
                    tray.red.clone()
                };
                let _ = tray.tray.set_icon(Some(icon));
                if signed_in {
                    let _ = tray.menu.append(&tray.sign_out);
                } else {
                    let _ = tray.menu.remove(&tray.sign_out);
                }
            }
        }
    });
}

/// The tray shows "Sign out" only while signed in, at the very bottom of the
/// menu. There is no confirm step: a click signs out and the status dot turns
/// red. Its position keeps it away from the other clickable items.
const SIGN_OUT_LABEL: &str = "Sign out";

/// Clear the session at the user's request: drop the in-memory token, delete it
/// from the OS credential store, and refresh the tray. refresh_tray then turns
/// the dot red and removes the "Sign out" item. An explicit sign out deletes
/// the stored token, unlike an invalidated one, so the next start does not
/// reuse it; if the store refuses, the next start WILL sign back in, so that is
/// reported, not shrugged off.
fn sign_out<R: tauri::Runtime>(app: &tauri::AppHandle<R>, state: &Arc<AppState>) {
    sign_out_with(app, state, keychain::delete_token);
}

/// The whole of a sign out, with the credential store's delete passed in. Only
/// the store is an argument: a test drives every other step, and must not
/// delete the entry the agent installed on the same machine signs in with.
fn sign_out_with<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    state: &Arc<AppState>,
    delete_stored_token: fn() -> Result<(), String>,
) {
    // Nobody is signed in, so the menu names nobody. refresh_tray drops the line.
    state.clear_session();
    match delete_stored_token() {
        Ok(()) => log::info!("user signed out from the tray"),
        Err(e) => {
            log::error!("sign out incomplete: {}", e);
            sentry::capture_message(&format!("sign_out_incomplete: {}", e), Level::Error);
            notify_user(
                "KlaayGuard",
                "Sign out could not remove the stored sign-in; it will be used again at the next start.",
            );
        }
    }
    let _ = app.emit("auth:status", json!({ "authenticated": false }));
    add_breadcrumb("auth", "user_signed_out", Level::Info);
    refresh_tray(app, state);
}

/// Handle a click on the tray "Sign out" item. The keyring delete blocks
/// (D-Bus, Keychain), so it runs off the tray thread.
fn handle_sign_out_click(app: &tauri::AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<Arc<AppState>>().inner().clone();
        sign_out(&app, &state);
    });
}

/// Tick the tray countdown once a second so it's current whenever the menu opens.
fn spawn_tray_clock(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(1));
        loop {
            iv.tick().await;
            refresh_tray(&app, &state);
        }
    });
}

async fn check_for_updates_internal(api_base: &str) -> Result<Option<SelectedUpdate>, String> {
    let current_version = env!("CARGO_PKG_VERSION");
    log::info!(
        "🔍 Starting update check - current version: {}",
        current_version
    );
    log::info!(
        "🌐 Checking for updates from API: {}/klaayguard/updates/latest",
        api_base
    );

    let client = http_client(Some(Duration::from_secs(30)));

    // Get latest release info
    let response = client
        .get(format!("{}/klaayguard/updates/latest", api_base))
        .send()
        .await
        .map_err(|e| {
            log::error!("❌ Failed to check for updates: {}", e);
            format!("Failed to check for updates: {}", e)
        })?;

    log::info!("📡 API response status: {}", response.status());

    if !response.status().is_success() {
        let error_msg = format!("Update check failed with status: {}", response.status());
        log::error!("❌ {}", error_msg);
        return Err(error_msg);
    }

    let release: ReleaseInfo = response.json().await.map_err(|e| {
        log::error!("❌ Failed to parse release info: {}", e);
        format!("Failed to parse release info: {}", e)
    })?;

    log::info!(
        "📦 Found release: {} with {} assets",
        release.version,
        release.assets.len()
    );
    for (i, asset) in release.assets.iter().enumerate() {
        log::info!("  Asset {}: {} (ID: {})", i + 1, asset.name, asset.id);
        if let Some(orig_name) = &asset.original_name {
            log::info!("    Original name: {}", orig_name);
        }
    }

    // Normalize versions by removing 'v' prefix for comparison
    let normalized_current = current_version.trim_start_matches('v');
    let normalized_release = release.version.trim_start_matches('v');

    // Parse versions as semantic versions for proper comparison
    let current_semver = match semver::Version::parse(normalized_current) {
        Ok(v) => v,
        Err(e) => {
            log::error!(
                "❌ Failed to parse current version '{}': {}",
                normalized_current,
                e
            );
            return Err(format!(
                "Invalid current version format: {}",
                normalized_current
            ));
        }
    };

    let release_semver = match semver::Version::parse(normalized_release) {
        Ok(v) => v,
        Err(e) => {
            log::error!(
                "❌ Failed to parse release version '{}': {}",
                normalized_release,
                e
            );
            return Err(format!(
                "Invalid release version format: {}",
                normalized_release
            ));
        }
    };

    // Only suggest update if release version is newer
    if release_semver > current_semver {
        log::info!(
            "🆚 Version comparison: {} < {} (update available)",
            current_version,
            release.version
        );

        // Linux self-update replaces the AppImage file in place. deb and rpm
        // installs go through the package manager, so they skip.
        #[cfg(target_os = "linux")]
        {
            // The file to replace on self-update is our own AppImage; deb and
            // rpm installs update through the package manager.
            if own_appimage().is_none() {
                log::info!(
                    "ℹ️  Auto-update on Linux serves AppImage installs only; this is not one"
                );
                return Ok(None);
            }
            return match select_appimage_asset(&release.assets, std::env::consts::ARCH) {
                Some(asset) => {
                    log::info!(
                        "✅ Selected Linux AppImage update: {} (ID: {})",
                        asset.original_name.as_deref().unwrap_or(&asset.name),
                        asset.id
                    );
                    Ok(Some(SelectedUpdate {
                        asset_id: asset.id.to_string(),
                        sha256: asset.sha256.clone(),
                    }))
                }
                None => {
                    log::warn!(
                        "⚠️  No Linux {} AppImage asset in the release",
                        std::env::consts::ARCH
                    );
                    Ok(None)
                }
            };
        }

        // Windows self-update reruns the NSIS installer we ship, so the update
        // path and the manual install path use one artifact and one hook set.
        #[cfg(target_os = "windows")]
        {
            let Some(arch_tag) = windows_arch_tag(std::env::consts::ARCH) else {
                log::info!(
                    "ℹ️  Auto-update on Windows has no artifact tag for this architecture ({})",
                    std::env::consts::ARCH
                );
                return Ok(None);
            };
            return match select_windows_installer_asset(&release.assets, arch_tag) {
                Some(asset) => {
                    log::info!(
                        "✅ Selected Windows {} installer update: {} (ID: {})",
                        arch_tag,
                        asset.original_name.as_deref().unwrap_or(&asset.name),
                        asset.id
                    );
                    Ok(Some(SelectedUpdate {
                        asset_id: asset.id.to_string(),
                        sha256: asset.sha256.clone(),
                    }))
                }
                None => {
                    log::warn!("⚠️  No Windows {} installer asset in the release", arch_tag);
                    Ok(None)
                }
            };
        }

        // The manifest returns every macOS build (arm64 + x64); the human-facing
        // `name` does not distinguish them, so match on `original_name` (the real
        // artifact filename) against THIS host's architecture. Picking the wrong
        // arch would install an app the arch-mismatch gate then refuses to launch.
        #[cfg(target_os = "macos")]
        let Some((arch_tag, arch_label)) = host_arch_tags() else {
            log::info!(
                "ℹ️  Auto-update has no macOS artifact for this architecture ({})",
                std::env::consts::ARCH
            );
            return Ok(None);
        };

        #[cfg(target_os = "macos")]
        if let Some(dmg_asset) = select_dmg_asset(&release.assets, arch_tag, arch_label) {
            log::info!(
                "✅ Selected {} update: {} (ID: {})",
                arch_tag,
                dmg_asset
                    .original_name
                    .as_deref()
                    .unwrap_or(&dmg_asset.name),
                dmg_asset.id
            );
            log::info!(
                "🚀 Update available: {} -> {}",
                current_version,
                release.version
            );
            return Ok(Some(SelectedUpdate {
                asset_id: dmg_asset.id.to_string(),
                sha256: dmg_asset.sha256.clone(),
            }));
        } else {
            log::warn!("⚠️  No {} DMG asset found in release assets", arch_tag);
        }
    } else if release_semver < current_semver {
        log::info!(
            "✅ No update needed - current version {} is newer than release {}",
            current_version,
            release.version
        );
    } else {
        log::info!(
            "✅ No update needed - already at latest version: {}",
            current_version
        );
    }

    Ok(None)
}

#[allow(clippy::needless_return)] // the cfg-gated platform blocks need explicit returns
async fn download_and_install_update_internal(
    api_base: &str,
    asset_id: &str,
    expected_sha256: Option<&str>,
    app: &tauri::AppHandle,
) -> Result<(), String> {
    log::info!(
        "📥 Starting download and install process for asset ID: {}",
        asset_id
    );

    // No overall deadline: an installer download that is slow but alive must
    // finish; the read timeout bounds silence instead.
    let client = http_client(None);

    // Download the DMG
    let download_url = format!("{}/klaayguard/download/{}", api_base, asset_id);
    log::info!("🌐 Download URL: {}", download_url);

    let response = client.get(&download_url).send().await.map_err(|e| {
        log::error!("❌ Failed to download update: {}", e);
        format!("Failed to download update: {}", e)
    })?;

    log::info!("📡 Download response status: {}", response.status());

    if !response.status().is_success() {
        let error_msg = format!("Download failed with status: {}", response.status());
        log::error!("❌ {}", error_msg);
        return Err(error_msg);
    }

    let bytes = response.bytes().await.map_err(|e| {
        log::error!("❌ Download error: {}", e);
        format!("Download error: {}", e)
    })?;

    log::info!("📊 Downloaded {} bytes", bytes.len());

    // Verify integrity before we swap a running security agent.
    match expected_sha256 {
        Some(expected) if !sha256_matches(&bytes, expected) => {
            let msg = format!("Update checksum mismatch for expected {}", expected);
            log::error!("❌ {}", msg);
            sentry::capture_message(&msg, Level::Error);
            return Err(msg);
        }
        Some(expected) => log::info!("🔐 Update checksum verified against {}", expected),
        None => log::warn!("⚠️  No checksum provided for update asset; skipping verification"),
    }

    // macOS gets a codesign gate after the checksum; Linux and Windows have
    // nothing after it. Refuse to install unverifiable bytes there.
    if expected_sha256.is_none() && update_requires_checksum(std::env::consts::OS) {
        let msg = format!(
            "No checksum for the {} update; refusing to install",
            std::env::consts::OS
        );
        log::error!("❌ {}", msg);
        sentry::capture_message(&msg, Level::Error);
        return Err(msg);
    }

    #[cfg(target_os = "linux")]
    {
        return install_appimage_update(&bytes, app);
    }

    #[cfg(target_os = "windows")]
    {
        return install_windows_update(&bytes, expected_sha256, app);
    }

    #[cfg(target_os = "macos")]
    {
        // The swap creates entries in /Applications (root:admin 775), which a
        // standard user cannot do. Say so before pulling the DMG every 6 h.
        if nix::unistd::access("/Applications", nix::unistd::AccessFlags::W_OK).is_err() {
            let msg = "No write access to /Applications (not an admin user); the update \
                       must be installed by an administrator or MDM"
                .to_string();
            log::error!("❌ {}", msg);
            report_update_failure_once(&msg);
            return Err(msg);
        }

        // Stage the download in a private, process-scoped temp path rather than the
        // world-known ~/Downloads/KlaayGuard-update.dmg. The signature gate in
        // replace_application verifies the *mounted* bundle, so this is defense-in-depth
        // against a local process swapping the file between write and mount (TOCTOU).
        let dmg_path =
            std::env::temp_dir().join(format!("KlaayGuard-update-{}.dmg", std::process::id()));

        log::info!("💾 Staging to: {:?}", dmg_path);

        let mut file = std::fs::File::create(&dmg_path).map_err(|e| {
            log::error!("❌ Failed to create update file: {}", e);
            format!("Failed to create update file: {}", e)
        })?;
        std::io::Write::write_all(&mut file, &bytes).map_err(|e| {
            log::error!("❌ Write error: {}", e);
            format!("Write error: {}", e)
        })?;

        log::info!("✅ Update downloaded successfully to: {:?}", dmg_path);

        // Mount the DMG and replace the app
        log::info!("🔄 Starting application replacement process...");
        replace_application(&dmg_path, app).await?;

        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        // app is consumed only by the platform install arms.
        let _ = app;
        Err("auto-update is not supported on this platform".to_string())
    }
}

/// Replace the running AppImage with the downloaded one and relaunch.
/// The staged file shares the target directory, so the rename is atomic;
/// a failure at any step leaves the current, known-good file in place.
#[cfg(target_os = "linux")]
fn install_appimage_update(bytes: &[u8], app: &tauri::AppHandle) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let target = own_appimage().ok_or_else(|| {
        "APPIMAGE not set or not this process's image; not an AppImage install".to_string()
    })?;
    let staged = staged_sibling_path(&target, std::process::id());

    // Create the staged file exclusively (create_new) with private perms, so a
    // pre-planted symlink or a hostile file in a shared directory cannot be
    // followed or read mid-write. A leftover from a crashed run is removed
    // first, then retried once.
    let open = || {
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&staged)
    };
    let mut file = match open() {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&staged);
            open().map_err(|e| format!("stage create failed: {}", e))?
        }
        Err(e) => return Err(format!("stage create failed: {}", e)),
    };

    // Write, then fsync before the rename. Without the sync a power loss can
    // commit the rename ahead of the data blocks and brick the agent.
    let write_and_sync = file
        .write_all(bytes)
        .and_then(|_| file.sync_all())
        .and_then(|_| std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)));
    if let Err(e) = write_and_sync {
        let _ = std::fs::remove_file(&staged);
        return Err(format!("stage write failed: {}", e));
    }
    drop(file);

    if let Err(e) = std::fs::rename(&staged, &target) {
        let _ = std::fs::remove_file(&staged);
        let msg = format!("AppImage replace failed: {}", e);
        log::error!("❌ {}", msg);
        sentry::capture_message(&msg, Level::Error);
        return Err(msg);
    }
    // Persist the directory entry so the swap survives a crash right after.
    if let Some(dir) = target.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }

    log::info!("✅ AppImage replaced at {:?}; relaunching", target);
    // The single-instance plugin allows one process at a time, so the new one
    // must start only after this one exits. Poll this PID rather than sleep a
    // fixed time: a fixed sleep that is too short forwards to the dying
    // primary and leaves the agent down. Pass the pid, path, and log path as
    // positional arguments, never interpolated into the script text. If this
    // process outlives the 30s cap, record it in the log before exec'ing.
    let log_file = dirs::data_local_dir()
        .map(|d| d.join("com.klaay.app/logs/KlaayGuard.log"))
        .unwrap_or_else(|| std::path::PathBuf::from("/dev/null"));
    let spawn = std::process::Command::new("sh")
        .arg("-c")
        .arg(
            "pid=\"$1\"; target=\"$2\"; logf=\"$3\"; i=0; \
             while kill -0 \"$pid\" 2>/dev/null && [ \"$i\" -lt 150 ]; do \
             sleep 0.2; i=$((i+1)); done; \
             if kill -0 \"$pid\" 2>/dev/null; then \
             echo \"[relaunch] old pid $pid still alive after 30s cap; exec anyway\" >>\"$logf\"; \
             fi; exec \"$target\"",
        )
        .arg("sh")
        .arg(std::process::id().to_string())
        .arg(&target)
        .arg(&log_file)
        .spawn();
    if let Err(e) = spawn {
        // The update is already installed; only the relaunch failed. Report
        // it, but do not return an error that reads as "update failed" — the
        // new binary runs on the next start.
        log::error!("relaunch spawn failed (update is installed): {}", e);
        sentry::capture_message(
            &format!("appimage_relaunch_spawn_failed: {}", e),
            Level::Error,
        );
        return Ok(());
    }
    app.exit(0);
    Ok(())
}

/// Where to stage the downloaded installer: a private per-user directory
/// under the local app data root, next to the logs. Another user cannot write
/// there, so nothing swaps the installer between our write and our run.
/// `data_local` is a parameter so the path rule is testable on any host.
#[cfg(any(target_os = "windows", test))]
fn windows_update_dir(data_local: &std::path::Path) -> std::path::PathBuf {
    data_local.join("com.klaay.app").join("updates")
}

/// The installer command line for an unattended update, the same flags
/// tauri-plugin-updater passes. `/S` runs the NSIS installer with no window
/// and no prompt; in silent mode the Tauri template stops the running agent
/// itself instead of asking. `/UPDATE` tells the template this is an update:
/// it skips the WebView2 bootstrapper section (whose abort would leave the
/// agent down after we have exited) and creates no new shortcuts, so one the
/// user removed stays removed. `/R` makes the installer start the new agent
/// when it finishes, as the logged-in user. Without `/S` an unattended
/// machine stalls on the "close the app" prompt forever.
#[cfg(any(target_os = "windows", test))]
fn windows_installer_args() -> [&'static str; 3] {
    ["/S", "/UPDATE", "/R"]
}

/// Run the downloaded NSIS installer over this install and let it restart the
/// agent. Windows cannot overwrite a running .exe, so the installer stops this
/// process; we exit right after the spawn so it never has to kill us
/// mid-write. The installer also rewrites the Run key, so every update
/// repairs autostart.
#[cfg(target_os = "windows")]
fn install_windows_update(
    bytes: &[u8],
    expected_sha256: Option<&str>,
    app: &tauri::AppHandle,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::windows::process::CommandExt;

    // The caller refuses a missing checksum on Windows already; keep the gate
    // here too so this function is safe on its own.
    let expected = expected_sha256.ok_or("no checksum for the Windows update")?;

    let dir = windows_update_dir(&dirs::data_local_dir().ok_or("no local app data directory")?);
    std::fs::create_dir_all(&dir).map_err(|e| format!("update dir: {}", e))?;
    // A fixed name means at most one stale file, not one per update. Linux
    // needs a pid suffix because it renames over a live target; we do not.
    let staged = dir.join("KlaayGuard-update.exe");
    let _ = std::fs::remove_file(&staged);

    let written = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&staged)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    if let Err(e) = written {
        // Never leave a partial installer behind.
        let _ = std::fs::remove_file(&staged);
        return Err(format!("stage installer: {}", e));
    }

    // Re-read and re-verify the bytes on disk. Until Authenticode signing is
    // live this is the only check that happens after the bytes hit disk; it
    // catches a short write and narrows the swap window.
    let on_disk = std::fs::read(&staged).map_err(|e| format!("re-read installer: {}", e))?;
    if !sha256_matches(&on_disk, expected) {
        let _ = std::fs::remove_file(&staged);
        let msg = "Staged Windows installer does not match its checksum".to_string();
        log::error!("❌ {}", msg);
        sentry::capture_message(&msg, Level::Error);
        return Err(msg);
    }

    // Leave any job object the agent was started in. A launcher that puts
    // its children in a kill-on-close job (an SSH session does; some
    // management tools do) would otherwise take the installer down with the
    // agent when it exits. Breakaway is refused when the job forbids it, so
    // fall back to a plain spawn rather than fail the update.
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    log::info!("🔄 Running installer {:?} silently", staged);
    let launch = |flags: u32| {
        std::process::Command::new(&staged)
            .args(windows_installer_args())
            .current_dir(&dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(flags)
            .spawn()
    };
    let spawn = launch(CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB).or_else(|e| {
        log::warn!(
            "installer spawn with job breakaway failed ({}); retrying without",
            e
        );
        launch(CREATE_NO_WINDOW)
    });
    if let Err(e) = spawn {
        // Nothing is installed yet, so the running agent stays as it is and
        // the error is honest. This differs from the Linux relaunch rule,
        // where the bytes were already in place.
        let msg = format!("installer spawn failed: {}", e);
        log::error!("❌ {}", msg);
        sentry::capture_message(&format!("windows_update_spawn_failed: {}", e), Level::Error);
        return Err(msg);
    }
    log::info!("✅ Installer started; exiting so it can replace this process");
    app.exit(0);
    Ok(())
}

/// Klaay's Apple Developer Team ID (the OU of our Developer ID Application cert).
/// The update's signature MUST chain to Apple and carry this team, or we refuse to
/// install it.
#[cfg(target_os = "macos")]
const KLAAY_TEAM_ID: &str = "8QK45RW8QK";

/// The independent trust anchor the update channel otherwise lacks.
///
/// The server supplies both the DMG and its "expected" SHA-256, so that hash only
/// proves the bytes arrived intact — not that Klaay produced them. Before we delete
/// the running agent and swap in a downloaded app, verify that the mounted bundle is
/// (1) structurally sound, (2) signed by *our* Developer ID team under an Apple
/// anchor, and (3) accepted by Gatekeeper (i.e. notarized). Any failure is fatal:
/// the update is abandoned and the current, known-good agent keeps running.
#[cfg(target_os = "macos")]
fn verify_klaay_signature(app_path: &std::path::Path) -> Result<(), String> {
    // 1) Structural integrity of the signature over the whole bundle.
    let verify = std::process::Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict", "--verbose=2"])
        .arg(app_path)
        .output()
        .map_err(|e| format!("codesign spawn failed: {}", e))?;
    if !verify.status.success() {
        return Err(format!(
            "codesign --verify failed: {}",
            String::from_utf8_lossy(&verify.stderr).trim()
        ));
    }

    // 2) Bind to our team: the leaf cert's OU must be KLAAY_TEAM_ID. codesign prints
    //    signing details to stderr with `-d`. Matching the whole `TeamIdentifier=...`
    //    line (not a bare substring) avoids a forged team id that merely contains ours.
    let details = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(app_path)
        .output()
        .map_err(|e| format!("codesign -d spawn failed: {}", e))?;
    let details_text = String::from_utf8_lossy(&details.stderr);
    let team_ok = details_text
        .lines()
        .any(|l| l.trim() == format!("TeamIdentifier={}", KLAAY_TEAM_ID));
    if !team_ok {
        return Err(format!(
            "update not signed by Klaay team {} (rejecting)",
            KLAAY_TEAM_ID
        ));
    }

    // 3) Gatekeeper / notarization assessment as an executable.
    let assess = std::process::Command::new("/usr/sbin/spctl")
        .args(["--assess", "--type", "execute", "--verbose=4"])
        .arg(app_path)
        .output()
        .map_err(|e| format!("spctl spawn failed: {}", e))?;
    if !assess.status.success() {
        return Err(format!(
            "Gatekeeper assessment failed (not notarized/accepted): {}",
            String::from_utf8_lossy(&assess.stderr).trim()
        ));
    }

    log::info!(
        "🔏 Update signature verified: Apple-anchored, team {}, notarized",
        KLAAY_TEAM_ID
    );
    Ok(())
}

/// The mount point (`/Volumes/...`) from `hdiutil attach` output. hdiutil prints
/// a table; the mount point is the last tab-separated field of the line that
/// names a `/Volumes/` path. A volume name may contain spaces, so split on tabs,
/// not spaces.
#[cfg(any(target_os = "macos", test))]
fn parse_hdiutil_mount_point(stdout: &str) -> Option<&str> {
    stdout
        .lines()
        .find(|line| line.contains("/Volumes/"))
        .and_then(|line| line.split('\t').next_back())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Detach a mounted update volume. Tries a graceful detach, then a forced one,
/// so a busy volume still comes down. Runs on every path — success or failure —
/// so a failed update never leaks a `/Volumes/KlaayGuard` mount that forces the
/// next one to mount as `/Volumes/KlaayGuard 1`.
#[cfg(target_os = "macos")]
fn detach_dmg(mount_point: &str) {
    log::info!("💿 Unmounting DMG from: {}", mount_point);
    let detached = std::process::Command::new("hdiutil")
        .args(["detach", mount_point])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if detached {
        log::info!("✅ DMG unmounted successfully");
        return;
    }
    log::warn!("⚠️  Graceful detach failed; forcing");
    let _ = std::process::Command::new("hdiutil")
        .args(["detach", "-force", mount_point])
        .status();
}

/// Install the new bundle next to the target, verify it, then swap it in with
/// atomic renames.
///
/// The old, racy path deleted `/Applications/KlaayGuard.app` and then copied the
/// new one on top. If anything failed in that window — or the machine was busy —
/// the app was simply gone, and the launchd `KeepAlive` job spun trying to open a
/// missing bundle (191,227 log lines on one test Mac). This path never deletes
/// the live app: it copies the new bundle beside it, verifies the copy, and
/// swaps by rename. The app is only ever absent for one metadata rename, and the
/// old agent keeps running until the swap completes.
#[cfg(target_os = "macos")]
fn stage_verify_and_swap(
    source_app: &std::path::Path,
    target_app: &std::path::Path,
) -> Result<(), String> {
    let pid = std::process::id();
    let staged = staged_sibling_path(target_app, pid);
    let base = target_app
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "KlaayGuard.app".to_string());
    let backup = target_app.with_file_name(format!(".{}.old-{}", base, pid));

    // Clear leftovers from any earlier crashed update.
    let _ = std::fs::remove_dir_all(&staged);
    let _ = std::fs::remove_dir_all(&backup);

    // 1) Copy the new bundle next to the target. `ditto` is Apple's tool for
    //    copying an `.app`: it preserves symlinks, extended attributes, and the
    //    code signature that `spctl` then checks.
    log::info!("📋 Staging new app at {:?}", staged);
    let copy = std::process::Command::new("/usr/bin/ditto")
        .arg(source_app)
        .arg(&staged)
        .status()
        .map_err(|e| format!("ditto spawn failed: {}", e))?;
    if !copy.success() {
        let _ = std::fs::remove_dir_all(&staged);
        return Err("Failed to stage new app (ditto)".to_string());
    }

    // 2) Verify the STAGED copy — the exact bytes we will run, not the mounted
    //    source. A copy that stripped or corrupted the signature fails here,
    //    before we touch the working install.
    if let Err(e) = verify_klaay_signature(&staged) {
        log::error!("❌ Update signature verification failed: {}", e);
        sentry::capture_message(&format!("update_signature_rejected:{}", e), Level::Error);
        let _ = std::fs::remove_dir_all(&staged);
        return Err(format!("Refusing unverified update: {}", e));
    }

    // 3) Swap with renames on one filesystem. Move the old app aside, move the
    //    new one in, then delete the old. If the second rename fails, roll the
    //    old app back so the agent keeps a working install.
    if target_app.exists() {
        std::fs::rename(target_app, &backup)
            .map_err(|e| format!("Failed to move old app aside: {}", e))?;
    }
    match std::fs::rename(&staged, target_app) {
        Ok(()) => {
            let _ = std::fs::remove_dir_all(&backup);
            log::info!("✅ New app swapped into place");
            Ok(())
        }
        Err(e) => {
            if backup.exists() {
                let _ = std::fs::rename(&backup, target_app);
            }
            let _ = std::fs::remove_dir_all(&staged);
            Err(format!("Failed to swap new app into place: {}", e))
        }
    }
}

/// Verify and install the mounted bundle into `/Applications`.
#[cfg(target_os = "macos")]
fn install_from_mount(mount_point: &str) -> Result<(), String> {
    let source_app = std::path::Path::new(mount_point).join("KlaayGuard.app");
    let target_app = std::path::Path::new("/Applications/KlaayGuard.app");

    log::info!("📂 Source app: {:?}", source_app);
    log::info!("📂 Target app: {:?}", target_app);

    if !source_app.exists() {
        return Err(format!("Source app not found at: {:?}", source_app));
    }

    stage_verify_and_swap(&source_app, target_app)
}

#[cfg(target_os = "macos")]
async fn replace_application(
    dmg_path: &std::path::Path,
    app: &tauri::AppHandle,
) -> Result<(), String> {
    log::info!("💿 Mounting DMG: {:?}", dmg_path);

    // Mount the DMG. `-nobrowse` keeps the update volume out of Finder.
    let mount_output = std::process::Command::new("hdiutil")
        .args(["attach", "-nobrowse", dmg_path.to_str().unwrap()])
        .output()
        .map_err(|e| {
            log::error!("❌ Failed to mount DMG: {}", e);
            format!("Failed to mount DMG: {}", e)
        })?;

    if !mount_output.status.success() {
        let error_msg = "Failed to mount DMG".to_string();
        log::error!(
            "❌ {} - hdiutil output: {}",
            error_msg,
            String::from_utf8_lossy(&mount_output.stderr)
        );
        return Err(error_msg);
    }

    let mount_output_str = String::from_utf8_lossy(&mount_output.stdout);
    log::info!("📋 hdiutil output: {}", mount_output_str);

    let mount_point = parse_hdiutil_mount_point(&mount_output_str)
        .ok_or_else(|| {
            log::error!("❌ Could not find mount point in hdiutil output");
            "Could not find mount point".to_string()
        })?
        .to_string();

    log::info!("📍 Mount point: {}", mount_point);

    // Install, then ALWAYS detach the volume — success or failure — so a failed
    // update leaves no mounted `/Volumes/KlaayGuard` behind.
    let result = install_from_mount(&mount_point);
    detach_dmg(&mount_point);

    // Best-effort: drop the downloaded DMG.
    log::info!("🗑️  Removing temporary DMG file: {:?}", dmg_path);
    if let Err(e) = std::fs::remove_file(dmg_path) {
        log::warn!("⚠️  Failed to remove DMG file: {}", e);
    }

    result?;

    match update_relaunch(std::env::var("KLAAYGUARD_LAUNCHD").as_deref() == Ok("1")) {
        Relaunch::LeaveItToLaunchd => {
            log::info!("🎉 Updated; exiting so launchd relaunches the new build");
            // `app.exit` always ends the process with status 0: the requested
            // code reaches RunEvent::ExitRequested and is then dropped for
            // ControlFlow::Exit, which tao defines as ExitWithCode(0). That is
            // correct here only while KeepAlive is unconditional. A plist that
            // moves to KeepAlive={SuccessfulExit:false} must stop using
            // app.exit, or launchd will never bring the agent back.
            app.exit(0);
            Ok(())
        }
        Relaunch::RestartSelf => {
            log::info!("🎉 Application updated successfully! Restarting...");
            app.restart();
        }
    }
}

/// Who brings the agent back after an update installs.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, PartialEq, Eq)]
enum Relaunch {
    /// Exit and let the launchd `KeepAlive` job start the new build.
    LeaveItToLaunchd,
    /// Nothing else supervises this process, so it restarts itself.
    RestartSelf,
}

/// One relauncher only. Under launchd the LaunchAgent wrapper runs `open -W`
/// with `KeepAlive`, so this process exiting IS the relaunch; restarting
/// ourselves as well spawns a second agent in the same instant, and two
/// simultaneous starts race past the single-instance guard (PROD-4603, seen in
/// production on 2026-09-05: adjacent PIDs, two tray icons). Outside launchd
/// nothing else relaunches us, so there `restart()` stays.
///
/// `under_launchd` is a parameter rather than an env read, so both arms are
/// pinned by tests without touching the process environment.
#[cfg(any(target_os = "macos", test))]
fn update_relaunch(under_launchd: bool) -> Relaunch {
    if under_launchd {
        Relaunch::LeaveItToLaunchd
    } else {
        Relaunch::RestartSelf
    }
}
fn update_check_interval_seconds() -> u64 {
    env_seconds("KLAAYGUARD_UPDATE_INTERVAL_SECONDS", 6 * 60 * 60)
}

/// Report a failed update to Sentry once per process: the check repeats every
/// 6 h, and a device that can never update must be visible, not a log line.
fn report_update_failure_once(msg: &str) {
    static REPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !REPORTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        sentry::capture_message(&format!("auto_update_failed: {}", msg), Level::Error);
    }
}

/// One update check: if a newer build is offered, download + verify + install it
/// (which restarts the app). No-op if already current.
async fn run_update_check(api_base: &str, app: &tauri::AppHandle) {
    match check_for_updates_internal(api_base).await {
        Ok(Some(update)) => {
            log::info!("🔄 Update available, starting download and install process...");
            if let Err(e) = download_and_install_update_internal(
                api_base,
                &update.asset_id,
                update.sha256.as_deref(),
                app,
            )
            .await
            {
                log::error!("💥 Auto-update failed: {}", e);
                report_update_failure_once(&e);
            }
        }
        Ok(None) => log::info!("✅ No updates available - app is up to date"),
        Err(e) => log::warn!("update check failed: {}", e),
    }
}

/// Check for updates immediately, then on a recurring interval (default 6h), so the
/// always-on agent self-updates in place rather than only at restart.
fn spawn_update_loop(app: tauri::AppHandle, api_base: String) {
    tauri::async_runtime::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(update_check_interval_seconds()));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await; // first tick is immediate (startup check)
            log::info!("🚀 Update check against {}", api_base);
            run_update_check(&api_base, &app).await;
        }
    });
}

/// Startup work that may block: the autostart entries, then the stored token,
/// then the sign-in nudge. Runs off the main thread so the tray is already
/// visible while a locked keyring waits on its prompt.
fn startup_blocking_work(app: tauri::AppHandle, state: Arc<AppState>) {
    // Start at login, like the macOS LaunchAgent. An agent that only runs
    // when a human remembers to launch it leaves gaps the fleet dashboard
    // cannot tell from an offline machine.
    #[cfg(target_os = "linux")]
    {
        match install_autostart_entry() {
            Ok(()) => warn_if_autostart_unserved(),
            Err(e) => {
                log::error!("autostart install failed: {}", e);
                sentry::capture_message(&format!("autostart_install_failed: {}", e), Level::Error);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = ensure_autostart_entry() {
            log::error!("autostart repair failed: {}", e);
            sentry::capture_message(&format!("autostart_install_failed: {}", e), Level::Error);
        }
    }

    // Load any saved token; if absent, nudge the user to sign in via the tray.
    let authed = match keychain::load_token() {
        Ok(Some(tok)) => {
            *lock_write(&state.auth_token) = Some(tok);
            state.token_acquired.notify_one();
            true
        }
        Ok(None) => false,
        Err(e) => {
            // A broken credential store looks like "not signed in" to
            // the user. Report it so support can tell the two apart.
            log::error!("keychain: token load failed: {}", e);
            sentry::capture_message(&format!("keychain_token_load_failed: {}", e), Level::Error);
            false
        }
    };
    if authed {
        log::info!("KlaayGuard started - authenticated, collecting in background");
        refresh_identity(&state);
    } else {
        log::info!("KlaayGuard started - sign-in required");
    }

    if !authed {
        notify_signin_needed(&app, &state);
    }
}

/// The API base this build was compiled against.
///
/// The single-instance lock keys on this, never on `get_api_base_url()`. That
/// one prefers the runtime `VITE_API_BASE_URL`, which the LaunchAgent plist
/// injects, and any build can rewrite that plist. Two production agents reading
/// two different injected values would take two different locks and both run.
///
/// `plist_api_base` calls this under `any(macos, test)`, so it is used on the
/// Linux CI runner too and no dead-code warning fires there.
#[cfg(any(target_os = "macos", test))]
fn compiled_api_base_url() -> &'static str {
    option_env!("APP_DEFAULT_API_BASE_URL").unwrap_or("https://api.klaay.com")
}

/// The lock this agent holds for as long as it runs. `flock` binds to the open
/// file description, so the lock lives exactly as long as this `File`; letting
/// it drop would release this login without a sound.
#[cfg(target_os = "macos")]
static AGENT_LOCK: std::sync::OnceLock<std::fs::File> = std::sync::OnceLock::new();

/// Claim this login, or exit because another agent already holds it.
///
/// Runs before Tauri, so it reports through `append_early_log` rather than the
/// plugin logger.
#[cfg(target_os = "macos")]
fn claim_this_login() {
    let Some(path) = single_instance::agent_lock_path(compiled_api_base_url()) else {
        // No data directory means no lock. An agent that cannot collect is
        // worse than two that can, so run and make the gap visible.
        append_early_log("[single_instance] no data directory for the lock; running unguarded");
        sentry::capture_message(
            "single_instance_lock_unavailable: no data dir",
            Level::Warning,
        );
        return;
    };

    // `launchctl kickstart -k` kills the running agent and starts its
    // replacement at once, and the dead process releases its lock a moment
    // later. Retry across that handover before concluding another agent owns
    // this login. Five attempts 400 ms apart sleep four times, so the loser
    // concedes after 1.6 s.
    match single_instance::claim_agent_lock(&path, 5, std::time::Duration::from_millis(400)) {
        single_instance::Claim::Held(file) => {
            // A full cell hands the file straight back inside `Err`, where
            // `let _ =` would drop it and close the fd. One caller reaches
            // here today, so the cell is always empty. Report the second
            // caller rather than swallow it: whoever adds one needs to see
            // that this file, not the parked one, is the lock being closed.
            if AGENT_LOCK.set(file).is_err() {
                append_early_log(
                    "[single_instance] the lock was claimed twice; the second file is closed",
                );
                sentry::capture_message("single_instance_lock_claimed_twice", Level::Warning);
            }
        }
        single_instance::Claim::Taken => {
            append_early_log("[single_instance] another agent already runs for this user; exiting");
            // Exit 0: the launchd job is `open -W`, which simply returns, so
            // KeepAlive does not spin on this.
            std::process::exit(0);
        }
        single_instance::Claim::Unavailable(why) => {
            append_early_log(&format!(
                "[single_instance] lock could not be evaluated ({why}); running unguarded"
            ));
            sentry::capture_message(
                &format!("single_instance_lock_unavailable: {why}"),
                Level::Warning,
            );
        }
    }
}

/// Main entry point for the KlaayGuard security monitoring application.
///
/// This function initializes the Tauri application with security-focused configuration:
/// - Hides the app from the dock on macOS for background operation
/// - Creates a system tray with limited options (no quit functionality)
/// - Sets up automatic updates for security patches
/// - Configures window behavior to prevent accidental closure
///
/// Security Features:
/// - Background operation prevents easy termination
/// - System tray provides controlled access
/// - Automatic updates ensure latest security patches
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // CLI seam: `--install-agent` registers the launchd LaunchAgent and exits
    // immediately, without entering the Tauri event loop. The macOS .pkg
    // postinstall script invokes this (as the console user) so setup happens at
    // install time instead of relying on the user launching the app manually.
    // Uninstall seam: `--forget-credentials` clears the stored sign-in and the
    // staged installer, then exits. The Windows uninstaller runs it (see
    // windows/hooks.nsi) so an offboarded machine keeps no bearer token; the
    // device identity stays, so a reinstall continues the same device record.
    if std::env::args().any(|a| a == "--forget-credentials") {
        #[cfg(target_os = "windows")]
        {
            if let Some(local) = dirs::data_local_dir() {
                let _ = std::fs::remove_dir_all(windows_update_dir(&local));
            }
        }
        match keychain::delete_token() {
            Ok(()) => {
                println!("forget-credentials: stored sign-in cleared");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("forget-credentials failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    if std::env::args().any(|a| a == "--install-agent") {
        #[cfg(target_os = "macos")]
        {
            match tauri::async_runtime::block_on(install_launch_agent()) {
                Ok(msg) => {
                    println!("install-agent: {}", msg);
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("install-agent failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            eprintln!("install-agent is only supported on macOS");
            std::process::exit(1);
        }
    }

    // Claim this login before anything starts. This runs after the CLI seams,
    // so `--install-agent` and `--forget-credentials` never take the lock, and
    // before the Tauri builder, so a losing agent exits without ever reaching
    // the tray.
    #[cfg(target_os = "macos")]
    claim_this_login();

    // Runtime env, else the compile-time default build.rs baked in.
    let api_base = get_api_base_url();
    let frontend = get_frontend_url();
    add_breadcrumb(
        "startup",
        &format!("endpoints api:{} frontend:{}", api_base, frontend),
        Level::Info,
    );
    // naive mismatch hint: localhost vs non-localhost
    let api_is_local = api_base.contains("localhost") || api_base.contains("127.0.0.1");
    let ew_is_local = frontend.contains("localhost") || frontend.contains("127.0.0.1");
    if api_is_local ^ ew_is_local {
        add_breadcrumb(
            "startup",
            "endpoint_mismatch_local_vs_remote",
            Level::Warning,
        );
    }
    let state = Arc::new(AppState {
        auth_token: RwLock::new(None),
        api_base_url: api_base,
        last_attempt_at: RwLock::new(None),
        last_focus_at: RwLock::new(None),
        device_identity: RwLock::new(None),
        user_label: RwLock::new(None),
        token_acquired: tokio::sync::Notify::new(),
        // Assume a usable tray until setup proves otherwise, so a nudge that
        // somehow runs first does not open a window on a healthy desktop.
        tray_built: std::sync::atomic::AtomicBool::new(true),
        tray_watcher_present: std::sync::atomic::AtomicBool::new(true),
    });

    // Only the non-macOS arm below mutates this, so macOS binds it immutably.
    #[cfg(not(target_os = "macos"))]
    let mut builder = tauri::Builder::default();
    #[cfg(target_os = "macos")]
    let builder = tauri::Builder::default();

    // macOS claimed its lock above, before Tauri existed. The plugin's macOS
    // guard unlinks its socket before it binds, so two agents that start
    // together both win it (PROD-4603).
    //
    // Linux and Windows keep the plugin: a D-Bus name and a named mutex are
    // both atomic, so neither has the defect. They also keep the
    // production-only gate, because the plugin keys on the bundle identifier
    // and offers no per-target override on Windows — a development build would
    // otherwise see the installed agent and exit on startup.
    #[cfg(not(target_os = "macos"))]
    if keychain::is_production_target(&get_api_base_url()) {
        // Must init first, so a second launch exits before the other plugins
        // spin up. Tauri documents this ordering.
        builder = builder.plugin(tauri_plugin_single_instance::init(|_app, _args, _cwd| {
            log::info!("single_instance: secondary launch routed to primary instance");
        }));
    } else {
        log::warn!(
            "single_instance skipped: this build talks to {}, not production",
            get_api_base_url()
        );
    }

    let app = builder
        .manage(state.clone())
        .invoke_handler(tauri::generate_handler![
            fallback_sign_in,
            fallback_employee_hub
        ])
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .build(),
        )
        .setup(|app| {
            // Tray-only background service: hide from dock, no window.
            #[cfg(target_os = "macos")]
            {
                app.set_activation_policy(tauri::ActivationPolicy::Accessory);
                log::info!("KlaayGuard configured as background service - tray only, hidden from dock");
            }

            // Architecture mismatch: warn the user natively and do NOT start the
            // collection loop (the binary can't run correctly on this hardware).
            if std::env::var("KLAAY_ARCH_MISMATCH").ok().as_deref() == Some("1") {
                let built = std::env::var("KLAAY_ARCH_BUILT")
                    .unwrap_or_else(|_| std::env::consts::ARCH.to_string());
                let host =
                    std::env::var("KLAAY_ARCH_HOST").unwrap_or_else(|_| "unknown".to_string());
                log::error!("arch_mismatch built={} host={}", built, host);
                #[cfg(target_os = "macos")]
                {
                    let script = format!(
                        "display dialog \"KlaayGuard was built for {} but this Mac is {}. Please reinstall the correct build.\" buttons {{\"OK\"}} with icon stop with title \"KlaayGuard\"",
                        built, host
                    );
                    let mut cmd = std::process::Command::new("osascript");
                    cmd.args(["-e", &script]);
                    let _ = spawn_and_reap(&mut cmd);
                }
                return Ok(());
            }

            let state = app.state::<Arc<AppState>>().inner().clone();

            // Tray menu first, in a neutral state, so the icon is up before any
            // credential-store, D-Bus, or network work; the tray clock flips it
            // to the real state within a second. A live auth/countdown item, an
            // Employee Hub link, and a version line. The name line is prepended
            // above them once the API names the person, and "Sign out" is
            // appended below the version only while signed in (see
            // refresh_tray), so it sits at the very bottom, away from the other
            // clickable items. No quit.
            let user_i = tauri::menu::MenuItem::with_id(
                app,
                "user",
                "",
                false,
                None::<&str>,
            )?;
            let item = tauri::menu::MenuItem::with_id(
                app,
                "auth_action",
                "Starting…",
                false,
                None::<&str>,
            )?;
            let hub_i = tauri::menu::MenuItem::with_id(
                app,
                "employee_hub",
                "Employee Hub",
                true,
                None::<&str>,
            )?;
            let version_i = tauri::menu::MenuItem::with_id(
                app,
                "version",
                format!("Version {}", env!("CARGO_PKG_VERSION")),
                false,
                None::<&str>,
            )?;
            let sign_out_i = tauri::menu::MenuItem::with_id(
                app,
                "sign_out",
                SIGN_OUT_LABEL,
                true,
                None::<&str>,
            )?;
            let sep = tauri::menu::PredefinedMenuItem::separator(app)?;
            let menu = tauri::menu::Menu::with_items(
                app,
                &[
                    &item as &dyn tauri::menu::IsMenuItem<tauri::Wry>,
                    &hub_i,
                    &sep,
                    &version_i,
                ],
            )?;
            // Status-dot icons: green when signed in, red when not. A tray
            // failure must not kill the agent: collection works without a
            // tray, and Linux gets a fallback window below.
            let tray_built = (|| -> Result<(), Box<dyn std::error::Error>> {
                let base = app
                    .default_window_icon()
                    .ok_or("no default window icon")?;
                let (green, red) = (
                    icon_with_dot(base, [46, 204, 113, 255]),
                    icon_with_dot(base, [231, 76, 60, 255]),
                );
                let tray = tauri::tray::TrayIconBuilder::new()
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "auth_action" => open_sign_in(app),
                        "employee_hub" => open_frontend(app, "/employee-hub"),
                        "sign_out" => handle_sign_out_click(app),
                        _ => {}
                    })
                    .icon(red.clone())
                    .tooltip("KlaayGuard")
                    .menu(&menu)
                    .build(app)?;
                app.manage(TrayMenu {
                    item: item.clone(),
                    user: user_i.clone(),
                    user_shown: std::sync::atomic::AtomicBool::new(false),
                    sign_out: sign_out_i.clone(),
                    menu: menu.clone(),
                    tray,
                    green,
                    red,
                    last_signed_in: std::sync::atomic::AtomicBool::new(false),
                });
                Ok(())
            })();
            if let Err(e) = &tray_built {
                log::error!("tray build failed; continuing without tray: {}", e);
                sentry::capture_message(&format!("tray_build_failed: {}", e), Level::Error);
            }

            // Stock GNOME shows no AppIndicator tray. Record both facts here;
            // the sign-in nudge opens the fallback window when it needs one.
            // Only a tray that failed to build leaves no UI at all, so only
            // that case opens a window before the stored token is read.
            #[cfg(target_os = "linux")]
            {
                let watcher = status_notifier_watcher_present();
                state
                    .tray_built
                    .store(tray_built.is_ok(), std::sync::atomic::Ordering::Relaxed);
                state
                    .tray_watcher_present
                    .store(watcher, std::sync::atomic::Ordering::Relaxed);
                if fallback_window_needed(tray_built.is_ok(), watcher, true) {
                    log::warn!(
                        "tray unusable (built={}, watcher={}); opening fallback window",
                        tray_built.is_ok(),
                        watcher
                    );
                    open_fallback_window(app.handle());
                }
            }
            #[cfg(not(target_os = "linux"))]
            drop(tray_built);

            // Check for updates on startup AND on a recurring interval, so an
            // always-on agent self-updates in place without waiting for a restart.
            spawn_update_loop(app.handle().clone(), state.api_base_url.clone());
            // The single collect-and-send loop + the tray countdown clock.
            spawn_tray_clock(app.handle().clone(), state.clone());
            spawn_background_loop(app.handle().clone(), state.clone());

            // Install and kickstart LaunchAgent with KeepAlive
            #[cfg(target_os = "macos")]
            {
                tauri::async_runtime::spawn(async {
                    if let Err(e) = install_launch_agent().await {
                        log::error!("LaunchAgent install failed: {}", e);
                        sentry::capture_message(
                            &format!("launch_agent_install_failed:{}", e),
                            Level::Error,
                        );
                    }
                });
            }

            // Everything else blocks (desktop-database and registry writes,
            // the credential store, which can wait on an unlock prompt), so it
            // runs on its own thread while the event loop starts.
            let app_handle = app.handle().clone();
            std::thread::spawn(move || startup_blocking_work(app_handle, state));

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error building tauri application");

    app.run(|_app_handle, event| match event {
        // Linux only. Closing the Linux fallback window destroys the last
        // window, which would otherwise exit the whole app and stop
        // collection; veto that window-triggered exit (code None). A
        // deliberate app.exit(code) carries Some and still exits.
        //
        // Not compiled on macOS: the agent has no windows there, so this
        // event only ever comes from an OS quit (Cmd+Q, logout, shutdown).
        // Vetoing those would cancel a user logout — the wrong behavior and
        // not needed, since there is no window to protect.
        #[cfg(target_os = "linux")]
        tauri::RunEvent::ExitRequested { code, api, .. } if code.is_none() => {
            log::info!("exit requested by window close; keeping the agent running");
            api.prevent_exit();
        }
        _ => {}
    });
}

#[cfg(test)]
mod identity_label_tests {
    use super::*;

    fn me(attributes: Value) -> Value {
        json!({ "data": { "type": "me", "id": "1", "attributes": attributes } })
    }

    #[test]
    fn names_the_person_by_first_and_last_name() {
        assert_eq!(
            identity_label(&me(json!({
                "first_name": "Emil",
                "last_name": "Kampp",
                "email": "rdk@klaay.com"
            }))),
            Some("Emil Kampp".to_string())
        );
    }

    // A directory that carries only one of the two names still names the
    // person. The email is the fallback, not the second choice.
    #[test]
    fn one_name_is_a_name() {
        assert_eq!(
            identity_label(&me(json!({
                "first_name": "Emil",
                "last_name": null,
                "email": "rdk@klaay.com"
            }))),
            Some("Emil".to_string())
        );
    }

    // The API serves the account-scoped directory name and falls back to the
    // self-managed column, so blank and padded values both reach this code.
    #[test]
    fn falls_back_to_the_email_when_no_name_is_given() {
        assert_eq!(
            identity_label(&me(json!({
                "first_name": "  ",
                "last_name": "",
                "email": "rdk@klaay.com"
            }))),
            Some("rdk@klaay.com".to_string())
        );
    }

    #[test]
    fn trims_the_names_it_shows() {
        assert_eq!(
            identity_label(&me(
                json!({ "first_name": " Emil ", "last_name": " Kampp " })
            )),
            Some("Emil Kampp".to_string())
        );
    }

    // Nothing to show beats a blank line in the menu.
    #[test]
    fn names_nobody_when_the_reply_carries_neither() {
        assert_eq!(identity_label(&me(json!({}))), None);
        assert_eq!(identity_label(&json!({})), None);
    }

    // Nobody validates the length of a name: the person types it, and the API
    // stores what they type. A menu item cannot show a paragraph.
    #[test]
    fn caps_a_name_that_would_swamp_the_menu() {
        let label = identity_label(&me(json!({ "first_name": "a".repeat(801) })))
            .expect("a name that long still names somebody");
        assert!(
            label.chars().count() <= LABEL_MAX_CHARS,
            "kept {} characters",
            label.chars().count()
        );
        assert!(label.ends_with('…'));
    }

    // Cut on a character boundary, never inside one. A name of 801 emoji must
    // not panic and must not split a code point.
    #[test]
    fn caps_a_long_name_without_splitting_a_character() {
        let label =
            identity_label(&me(json!({ "first_name": "😀".repeat(801) }))).expect("emoji name");
        assert!(label.chars().count() <= LABEL_MAX_CHARS);
        assert!(label.starts_with('😀'));
    }

    // A newline inside a name paints a second line in the tray that reads like
    // another menu item. Flatten it.
    #[test]
    fn flattens_a_name_that_carries_a_newline() {
        assert_eq!(
            identity_label(&me(json!({
                "first_name": "Emil\nSign out",
                "last_name": "Kampp"
            }))),
            Some("Emil Sign out Kampp".to_string())
        );
    }

    // A bell is a control character but not whitespace. It must go the same
    // way a newline goes.
    #[test]
    fn flattens_a_name_that_carries_a_control_character() {
        assert_eq!(
            identity_label(&me(json!({
                "first_name": "Emil\u{0007}Kampp",
            }))),
            Some("Emil Kampp".to_string())
        );
    }

    // A right-to-left override is not a control character, but a menu that
    // honours it paints "Emil Sign out". A zero-width space hides a break.
    // Both leave; the name reads as typed.
    #[test]
    fn drops_format_characters_that_restyle_the_line() {
        assert_eq!(
            identity_label(&me(json!({
                "first_name": "Emil\u{202E}tuo ngiS",
                "last_name": "Zero\u{200B}Width"
            }))),
            Some("Emil tuo ngiS Zero Width".to_string())
        );
    }

    // The Arabic letter mark sets the direction of the run that follows it,
    // and prints nothing. A name that carries one still reads as typed.
    #[test]
    fn drops_the_arabic_letter_mark() {
        assert_eq!(
            identity_label(&me(json!({ "first_name": "Emil\u{061C}Kampp" }))),
            Some("Emil Kampp".to_string())
        );
    }

    // The left-to-right and right-to-left marks do the same for a single run.
    #[test]
    fn drops_the_direction_marks() {
        assert_eq!(
            identity_label(&me(json!({
                "first_name": "Emil\u{200E}Kampp",
                "last_name": "Right\u{200F}Left"
            }))),
            Some("Emil Kampp Right Left".to_string())
        );
    }

    // An isolate wraps a run and re-orders it against its neighbours. The pair
    // prints nothing, so a name keeps only what the person typed.
    #[test]
    fn drops_the_bidi_isolates() {
        assert_eq!(
            identity_label(&me(json!({ "first_name": "Emil\u{2066}X\u{2069}Kampp" }))),
            Some("Emil X Kampp".to_string())
        );
    }

    // A byte order mark inside a name is a zero-width no-break space. It hides
    // a break the same way a zero-width space does.
    #[test]
    fn drops_a_byte_order_mark() {
        assert_eq!(
            identity_label(&me(json!({ "first_name": "Emil\u{FEFF}Kampp" }))),
            Some("Emil Kampp".to_string())
        );
    }

    // Emoji, joined sequences and right-to-left text are not control
    // characters. They reach the tray whole.
    #[test]
    fn passes_emoji_and_right_to_left_text_through() {
        assert_eq!(
            identity_label(&me(json!({ "first_name": "👨‍👩‍👧‍👦", "last_name": "أحمد" }))),
            Some("👨‍👩‍👧‍👦 أحمد".to_string())
        );
    }

    // A name of characters that paint nothing is a blank line with bytes in it.
    // The menu must drop it the same way it drops an empty string.
    #[test]
    fn names_nobody_when_the_name_paints_nothing() {
        for name in [
            "\u{E0041}\u{E0042}",
            "\u{00AD}\u{00AD}",
            "\u{180E}",
            "\u{206A}\u{206B}",
            "\u{FFF9}",
            "\u{200D}",
            // No format-character rule reaches these. The word joiner and the
            // invisible operators are Cf like the ones above; HANGUL FILLER is
            // a letter, and it is what people actually use for a blank display
            // name; BRAILLE PATTERN BLANK is a symbol that paints nothing.
            "\u{2060}\u{2064}",
            "\u{3164}",
            "\u{115F}\u{1160}",
            "\u{FFA0}",
            "\u{2800}",
            // Format characters far from the ones a list is written from. Each
            // is Cf, each types into a name field, and each drew a blank row
            // while the rule was a list of ranges.
            "\u{0890}\u{0891}",
            "\u{08E2}",
            "\u{110BD}\u{110CD}",
            "\u{1BCA0}\u{1BCA3}",
            "\u{1D173}\u{1D17A}",
            "\u{13430}\u{1343F}",
        ] {
            assert_eq!(
                identity_label(&me(json!({ "first_name": name }))),
                None,
                "{name:?} paints nothing, so it names nobody"
            );
        }
    }

    // The tag block is not one category. `U+E0001` and `U+E0020`-`U+E007F` are
    // Format; the other 31 code points in `U+E0000`-`U+E007F` are unassigned.
    // The category rule therefore keeps an unassigned tag where the old list
    // dropped it, and that is the wanted answer: an unassigned code point
    // draws a .notdef box, so it paints something. Keeping it also keeps this
    // rule fixed. Classing unassigned as invisible would change the tray the
    // day Unicode assigns one.
    #[test]
    fn drops_the_tag_characters_and_keeps_the_unassigned() {
        assert_eq!(
            identity_label(&me(json!({ "first_name": "\u{E0001}\u{E0020}" }))),
            None
        );
        assert_eq!(
            identity_label(&me(json!({ "first_name": "\u{E0000}" }))),
            Some("\u{E0000}".to_string())
        );
    }

    // The cut counts what the tray draws. A name padded with characters that
    // draw nothing must not lose its visible half to them.
    #[test]
    fn spends_the_label_budget_on_visible_characters() {
        assert_eq!(
            identity_label(&me(json!({
                "first_name": format!("Emil{}", "\u{E0041}".repeat(80))
            }))),
            Some("Emil".to_string())
        );
    }
}

// The name and the token move together. A name that outlives the session that
// earned it names the wrong person, and the tray has no way to know.
#[cfg(test)]
mod session_label_tests {
    use super::*;

    fn state() -> Arc<AppState> {
        state_at("http://127.0.0.1:0")
    }

    /// A fresh, signed-out state that talks to the API at `api_base_url`.
    pub(super) fn state_at(api_base_url: &str) -> Arc<AppState> {
        Arc::new(AppState {
            auth_token: RwLock::new(None),
            api_base_url: api_base_url.to_string(),
            last_attempt_at: RwLock::new(None),
            last_focus_at: RwLock::new(None),
            device_identity: RwLock::new(None),
            user_label: RwLock::new(None),
            token_acquired: tokio::sync::Notify::new(),
            tray_built: std::sync::atomic::AtomicBool::new(true),
            tray_watcher_present: std::sync::atomic::AtomicBool::new(true),
        })
    }

    #[test]
    fn adopting_a_session_names_its_holder() {
        let state = state();
        state.adopt_session("alice-token".into(), Some("Alice Andersen".into()));
        assert_eq!(
            *lock_read(&state.user_label),
            Some("Alice Andersen".to_string())
        );
        assert_eq!(*lock_read(&state.auth_token), Some("alice-token".into()));
    }

    // A 401 from the collection loop drops the token. The dot turns red, so the
    // name must go too.
    #[test]
    fn clearing_a_session_drops_the_name_with_the_token() {
        let state = state();
        state.adopt_session("alice-token".into(), Some("Alice Andersen".into()));
        state.clear_session();
        assert_eq!(*lock_read(&state.user_label), None);
        assert_eq!(*lock_read(&state.auth_token), None);
    }

    // The hand-down case. Bob signs in on Alice's Mac and `/me` fails, so the
    // API names nobody. The tray must not keep naming Alice.
    #[test]
    fn an_unnamed_session_never_inherits_the_last_name() {
        let state = state();
        state.adopt_session("alice-token".into(), Some("Alice Andersen".into()));
        state.adopt_session("bob-token".into(), None);
        assert_eq!(*lock_read(&state.user_label), None);
        assert_eq!(*lock_read(&state.auth_token), Some("bob-token".into()));
    }

    // A sign out during the `/me` round trip wins. The reply that lands after
    // it describes a session that no longer exists.
    #[test]
    fn a_late_reply_never_names_a_session_that_ended() {
        let state = state();
        state.adopt_session("alice-token".into(), None);
        let carried = lock_read(&state.auth_token).clone();
        state.clear_session();
        state.name_holder_of(carried.as_deref(), Some("Alice Andersen".into()));
        assert_eq!(*lock_read(&state.user_label), None);
    }

    #[test]
    fn a_reply_for_the_live_session_names_it() {
        let state = state();
        state.adopt_session("alice-token".into(), None);
        let carried = lock_read(&state.auth_token).clone();
        state.name_holder_of(carried.as_deref(), Some("Alice Andersen".into()));
        assert_eq!(
            *lock_read(&state.user_label),
            Some("Alice Andersen".to_string())
        );
    }
}

// What `/me` says decides whether a token becomes the session, and what the
// tray calls its holder. Each exit is driven against a loopback API, so the
// call site that carried the hand-down fault is covered, not only the
// invariant behind it.
#[cfg(test)]
mod identity_fetch_tests {
    use super::session_label_tests::state_at;
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    pub(super) const ALICE: &str = r#"{"data":{"type":"me","id":"1","attributes":{
        "first_name":"Alice","last_name":"Andersen","email":"alice@example.com"}}}"#;

    /// A loopback API that answers its first request with `status` and `body`,
    /// then closes. Returns the base URL to point the agent at.
    async fn api_that_replies(status: u16, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let base = format!("http://{}", listener.local_addr().expect("local addr"));
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = [0u8; 4096];
            let received = socket.read(&mut request).await.expect("read request");
            assert!(received > 0, "an empty request");
            let reply = format!(
                "HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(reply.as_bytes())
                .await
                .expect("write reply");
            socket.shutdown().await.expect("close");
        });
        base
    }

    /// A base URL nothing listens on: the port was bound, read, and released.
    async fn api_that_is_down() -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        format!("http://{}", listener.local_addr().expect("local addr"))
    }

    #[tokio::test]
    async fn a_401_rejects_the_token() {
        let base = api_that_replies(401, "{}").await;
        assert_eq!(fetch_identity(&base, "t").await, Identity::Rejected);
    }

    #[tokio::test]
    async fn a_403_rejects_the_token() {
        let base = api_that_replies(403, "{}").await;
        assert_eq!(fetch_identity(&base, "t").await, Identity::Rejected);
    }

    // A server error is not a verdict on the token. A blip must never block a
    // legitimate sign-in.
    #[tokio::test]
    async fn a_server_error_is_no_verdict() {
        let base = api_that_replies(500, "").await;
        assert_eq!(fetch_identity(&base, "t").await, Identity::Unknown);
    }

    #[tokio::test]
    async fn an_unreachable_api_is_no_verdict() {
        let base = api_that_is_down().await;
        assert_eq!(fetch_identity(&base, "t").await, Identity::Unknown);
    }

    // A 2xx whose body the agent cannot read is a blip, not an acceptance that
    // names nobody.
    #[tokio::test]
    async fn an_unreadable_reply_is_no_verdict() {
        let base = api_that_replies(200, "<html>").await;
        assert_eq!(fetch_identity(&base, "t").await, Identity::Unknown);
    }

    #[tokio::test]
    async fn an_accepted_token_names_its_holder() {
        let base = api_that_replies(200, ALICE).await;
        assert_eq!(
            fetch_identity(&base, "t").await,
            Identity::Accepted(Some("Alice Andersen".into()))
        );
    }

    #[tokio::test]
    async fn an_accepted_token_becomes_the_named_session() {
        let state = state_at(&api_that_replies(200, ALICE).await);
        assert!(adopt_unless_rejected(&state, "alice-token").await);
        assert_eq!(*lock_read(&state.auth_token), Some("alice-token".into()));
        assert_eq!(
            *lock_read(&state.user_label),
            Some("Alice Andersen".to_string())
        );
    }

    // The call site that carried the hand-down fault. Bob signs in on Alice's
    // Mac and `/me` blips: the token is adopted, and it names nobody.
    #[tokio::test]
    async fn a_blip_adopts_the_token_unnamed() {
        let state = state_at(&api_that_replies(500, "").await);
        state.adopt_session("alice-token".into(), Some("Alice Andersen".into()));
        assert!(adopt_unless_rejected(&state, "bob-token").await);
        assert_eq!(*lock_read(&state.auth_token), Some("bob-token".into()));
        assert_eq!(*lock_read(&state.user_label), None);
    }

    // A rejection is about the new token. The session that is live stays.
    #[tokio::test]
    async fn a_rejected_token_leaves_the_live_session_alone() {
        let state = state_at(&api_that_replies(401, "{}").await);
        state.adopt_session("alice-token".into(), Some("Alice Andersen".into()));
        assert!(!adopt_unless_rejected(&state, "bob-token").await);
        assert_eq!(*lock_read(&state.auth_token), Some("alice-token".into()));
        assert_eq!(
            *lock_read(&state.user_label),
            Some("Alice Andersen".to_string())
        );
    }

    /// The label once the identity refresh, which runs on its own runtime,
    /// has written it. `None` when five seconds pass and it has not.
    pub(super) async fn label_once_written(state: &Arc<AppState>) -> Option<String> {
        for _ in 0..250 {
            if let Some(label) = lock_read(&state.user_label).clone() {
                return Some(label);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    }

    // The heal for a blip at sign-in. The token proved live at the next
    // collection, so the session `/me` could not name is named there, not at
    // the next restart.
    #[tokio::test]
    async fn a_live_unnamed_session_is_named_at_the_next_cycle() {
        let state = state_at(&api_that_replies(200, ALICE).await);
        state.adopt_session("alice-token".into(), None);
        name_unnamed_holder(&state);
        assert_eq!(
            label_once_written(&state).await,
            Some("Alice Andersen".to_string())
        );
    }
}

// Three one-line calls end or heal a session: an invalidated token, a tray
// sign out, and the name a live token earns back at the next collection. Each
// runs here through the real function, on an app handle that `tauri::test`
// builds without a window server.
#[cfg(test)]
mod session_end_tests {
    use super::identity_fetch_tests::{label_once_written, ALICE};
    use super::session_label_tests::state_at;
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A base URL for a state that makes no request of its own.
    const NO_API: &str = "http://127.0.0.1:0";

    // A 401 from the collection loop stops the agent using the token. The dot
    // turns red, so the tray must stop naming anybody.
    #[test]
    fn an_invalidated_token_takes_the_name_with_it() {
        let app = tauri::test::mock_app();
        let state = state_at(NO_API);
        state.adopt_session("alice-token".into(), Some("Alice Andersen".into()));
        // The sign-in nudge is debounced. A nudge one moment old keeps this
        // test from opening a browser.
        *lock_write(&state.last_focus_at) = Some(Instant::now());

        invalidate_auth(app.handle(), &state);

        assert_eq!(*lock_read(&state.auth_token), None);
        assert_eq!(*lock_read(&state.user_label), None);
    }

    // A tray sign out ends the session the person asked to end. The credential
    // store's delete is the one step a test stands in for: deleting the real
    // entry would sign this machine's installed agent out.
    #[test]
    fn a_sign_out_takes_the_name_with_the_token() {
        let app = tauri::test::mock_app();
        let state = state_at(NO_API);
        state.adopt_session("alice-token".into(), Some("Alice Andersen".into()));

        sign_out_with(app.handle(), &state, || Ok(()));

        assert_eq!(*lock_read(&state.auth_token), None);
        assert_eq!(*lock_read(&state.user_label), None);
    }

    /// A loopback API that answers every request by path until the test ends:
    /// an empty collection config, and a `/me` that names Alice.
    async fn api_that_answers_by_path() -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let base = format!("http://{}", listener.local_addr().expect("local addr"));
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = [0u8; 4096];
                    let received = socket.read(&mut request).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&request[..received]).into_owned();
                    let body = if head.contains("GET /me ") {
                        ALICE
                    } else {
                        "{}"
                    };
                    let reply = format!(
                        "HTTP/1.1 200 Reply\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        base
    }

    // The heal for a `/me` blip at sign-in. The config reply proves the token
    // live, so the cycle names the session the sign-in could not name, instead
    // of leaving the tray unnamed until the next restart.
    #[tokio::test]
    async fn a_cycle_names_the_session_the_sign_in_could_not() {
        let app = tauri::test::mock_app();
        let state = state_at(&api_that_answers_by_path().await);
        state.adopt_session("alice-token".into(), None);

        run_cycle(
            app.handle(),
            &state,
            &http_client(Some(Duration::from_secs(10))),
        )
        .await
        .expect("a cycle against the loopback API");

        assert_eq!(
            label_once_written(&state).await,
            Some("Alice Andersen".to_string())
        );
    }
}

#[cfg(test)]
mod update_selection_tests {
    use super::*;

    // Mirrors the real /klaayguard/updates/latest manifest: both macOS arches
    // plus Linux artifacts in one release.
    fn manifest() -> Vec<ReleaseAsset> {
        serde_json::from_str(
            r#"[
              {"id":1,"name":"Linux (Debian/Ubuntu .deb)","original_name":"KlaayGuard_0.1.12_Linux_x86_64_production.deb","sha256":"aa"},
              {"id":2,"name":"MacOS (Apple silicon)","original_name":"KlaayGuard_0.1.12_macOS_arm64_production.dmg","sha256":"bb"},
              {"id":3,"name":"MacOS (Intel)","original_name":"KlaayGuard_0.1.12_macOS_x64_production.dmg","sha256":"cc"},
              {"id":4,"name":"Windows Installer","original_name":"KlaayGuard_0.1.12_Windows_x64_production.exe","sha256":"dd"}
            ]"#,
        )
        .unwrap()
    }

    #[test]
    fn selects_arm64_dmg_for_apple_silicon() {
        let assets = manifest();
        let sel = select_dmg_asset(&assets, "macOS_arm64", "Apple silicon").unwrap();
        assert_eq!(sel.id, 2);
        assert_eq!(
            sel.original_name.as_deref(),
            Some("KlaayGuard_0.1.12_macOS_arm64_production.dmg")
        );
    }

    #[test]
    fn selects_x64_dmg_for_intel() {
        let assets = manifest();
        let sel = select_dmg_asset(&assets, "macOS_x64", "Intel").unwrap();
        assert_eq!(sel.id, 3);
    }

    #[test]
    fn never_selects_a_non_dmg_or_wrong_arch() {
        // The pre-fix bug returned the first ".dmg"/"MacOS" match; assert each
        // arch resolves to its OWN dmg and never a Linux artifact.
        let assets = manifest();
        for (tag, label, want) in [
            ("macOS_arm64", "Apple silicon", 2u64),
            ("macOS_x64", "Intel", 3u64),
        ] {
            let sel = select_dmg_asset(&assets, tag, label).unwrap();
            assert_eq!(sel.id, want);
            assert!(sel.original_name.as_deref().unwrap().ends_with(".dmg"));
        }
    }

    #[test]
    fn falls_back_to_friendly_label_without_original_name() {
        let assets: Vec<ReleaseAsset> =
            serde_json::from_str(r#"[{"id":9,"name":"MacOS (Intel)","sha256":null}]"#).unwrap();
        assert_eq!(
            select_dmg_asset(&assets, "macOS_x64", "Intel").unwrap().id,
            9
        );
        assert!(select_dmg_asset(&assets, "macOS_arm64", "Apple silicon").is_none());
    }

    #[test]
    fn selects_the_windows_installer_by_arch_tag() {
        // One release carries macOS, Linux, and Windows artifacts; matching
        // on the friendly label alone could return a .deb.
        let assets = manifest();
        let sel = select_windows_installer_asset(&assets, "x64").unwrap();
        assert_eq!(sel.id, 4);
        assert!(sel.original_name.as_deref().unwrap().ends_with(".exe"));
    }

    #[test]
    fn windows_installer_never_matches_a_label_only_asset() {
        // select_dmg_asset falls back to the label. The Windows selector must
        // not: the label carries neither architecture nor file type.
        let label_only: Vec<ReleaseAsset> =
            serde_json::from_value(json!([{"id": 9, "name": "Windows Installer"}])).unwrap();
        assert!(select_windows_installer_asset(&label_only, "x64").is_none());
    }

    #[test]
    fn windows_installer_ignores_the_other_windows_artifacts() {
        // Turning on updater artifacts, or shipping arm64 later, must not
        // make an x64 host download the wrong file.
        let assets: Vec<ReleaseAsset> = serde_json::from_value(json!([
            {"id": 1, "name": "x", "original_name": "KlaayGuard_0.2.0_Windows_x64_production.nsis.zip"},
            {"id": 2, "name": "x", "original_name": "KlaayGuard_0.2.0_Windows_x64_production.exe.sig"},
            {"id": 3, "name": "x", "original_name": "KlaayGuard_0.2.0_Windows_arm64_production.exe"},
            {"id": 4, "name": "x", "original_name": "KlaayGuard_0.2.0_Windows_x64_production.exe"}
        ]))
        .unwrap();
        assert_eq!(
            select_windows_installer_asset(&assets, "x64").unwrap().id,
            4
        );
        assert_eq!(
            select_windows_installer_asset(&assets, "arm64").unwrap().id,
            3
        );
    }

    #[test]
    fn windows_arch_tag_follows_the_artifact_names() {
        // Windows artifacts use the short tag while Linux uses the Rust arch
        // string. Passing ARCH straight through never matches, and the agent
        // stops updating in silence.
        assert_eq!(windows_arch_tag("x86_64"), Some("x64"));
        assert_eq!(windows_arch_tag("aarch64"), Some("arm64"));
        assert_eq!(windows_arch_tag("x86"), None);
    }

    #[test]
    fn windows_installer_runs_silently_and_relaunches() {
        // Without /S the NSIS template asks the user to close the running
        // app; an unattended machine stalls there forever. Without /R nothing
        // starts the new agent after the old one is stopped.
        let args = windows_installer_args();
        assert!(args.contains(&"/S"));
        assert!(args.contains(&"/R"));
        // Without /UPDATE the template runs the WebView2 bootstrapper section
        // and re-creates shortcuts, as for a fresh install.
        assert!(args.contains(&"/UPDATE"));
    }

    // PROD-4603: the update ended with app.restart() while the launchd
    // KeepAlive job also relaunched the agent the moment the old process
    // exited. Two relaunchers, two agents. Under launchd there must be one.
    #[test]
    fn only_launchd_relaunches_a_supervised_agent() {
        assert_eq!(update_relaunch(true), Relaunch::LeaveItToLaunchd);
        assert_eq!(update_relaunch(false), Relaunch::RestartSelf);
    }

    #[test]
    fn update_requires_checksum_everywhere_but_macos() {
        // macOS has codesign and Gatekeeper after the hash. Linux and Windows
        // have nothing, so bytes with no server checksum must never run.
        assert!(update_requires_checksum("linux"));
        assert!(update_requires_checksum("windows"));
        assert!(!update_requires_checksum("macos"));
    }

    #[test]
    fn windows_update_dir_stays_under_the_local_app_data() {
        // Staging in a per-user directory stops another user swapping the
        // installer between our write and our run.
        let dir = windows_update_dir(std::path::Path::new(r"C:\Users\u\AppData\Local"));
        assert!(dir.ends_with(std::path::Path::new("com.klaay.app").join("updates")));
    }

    #[test]
    fn checksum_accepts_match_and_rejects_mismatch() {
        // sha256("") well-known digest, bare and "sha256:"-prefixed.
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(sha256_matches(b"", expected));
        assert!(sha256_matches(b"", &format!("sha256:{}", expected)));
        assert!(!sha256_matches(b"tampered", expected));
    }
}

#[cfg(test)]
mod happy_path_tests {
    use super::*;

    // The LaunchAgent plist is one shared file. It names the app to launch and
    // injects the API base that app then talks to. Whoever writes it decides
    // both, so only the app it points at may write it.
    #[test]
    fn only_the_installed_app_writes_its_own_launch_agent() {
        use std::path::Path;
        let installed = Path::new("/Applications/KlaayGuard.app");

        // The installed app describing itself.
        assert!(may_write_launch_agent(
            Path::new("/Applications/KlaayGuard.app/Contents/MacOS/KlaayGuard"),
            installed,
            true
        ));

        // A developer build must not point launchd at the installed app and
        // inject its own server. This is how a production install ends up
        // talking to a localhost port that nothing listens on.
        assert!(!may_write_launch_agent(
            Path::new("/Users/dev/src/klaayguard/src-tauri/target/debug/KlaayGuard"),
            installed,
            true
        ));

        // A copy on a mounted disk image, or one in the Trash, is not the
        // installed app either.
        assert!(!may_write_launch_agent(
            Path::new("/Volumes/KlaayGuard/KlaayGuard.app/Contents/MacOS/KlaayGuard"),
            installed,
            true
        ));
        assert!(!may_write_launch_agent(
            Path::new("/Users/dev/.Trash/KlaayGuard.app/Contents/MacOS/KlaayGuard"),
            installed,
            true
        ));
    }

    // With no app in /Applications the plist has nothing to start, and whatever
    // path it named would be gone by the next login. PROD-4626 puts a Mac in
    // exactly that state: the installer relocates the bundle into a developer
    // checkout and leaves /Applications empty. Nobody writes the file then.
    #[test]
    fn nobody_writes_the_launch_agent_when_no_app_is_installed() {
        use std::path::Path;
        let installed = Path::new("/Applications/KlaayGuard.app");

        assert!(!may_write_launch_agent(
            Path::new("/Users/dev/src/klaayguard/src-tauri/target/debug/KlaayGuard"),
            installed,
            false
        ));
        assert!(!may_write_launch_agent(
            Path::new("/Applications/KlaayGuard.app/Contents/MacOS/KlaayGuard"),
            installed,
            false
        ));
    }

    // Half of what this fix is for: "a wrong value could never heal". The plist
    // injects VITE_API_BASE_URL into the agent it starts, so resolving the
    // plist's own base through the environment would write back whatever the
    // file already held. Set the variable and prove the choice ignores it.
    //
    // Safe to touch the process environment here: no other test reaches
    // `get_api_base_url`, directly or through `keychain::api_base`.
    #[test]
    fn the_launch_agent_ignores_an_injected_server() {
        let injected = "http://localhost:54524";
        std::env::set_var("VITE_API_BASE_URL", injected);
        let chosen = plist_api_base();
        std::env::remove_var("VITE_API_BASE_URL");

        assert_ne!(
            chosen, injected,
            "the plist copied the injected server, so a wrong value can never heal"
        );
        assert_eq!(chosen, compiled_api_base_url());
    }

    #[test]
    fn the_launch_agent_starts_the_app_and_carries_its_server() {
        let plist = render_launch_agent_plist(
            "com.klaay.klaayguard",
            "/Applications/KlaayGuard.app",
            "/Users/dev/Library/Logs/KlaayGuard",
            "https://api.klaay.com",
        );
        assert!(plist.contains("<string>com.klaay.klaayguard</string>"));
        assert!(plist.contains("<string>/Applications/KlaayGuard.app</string>"));
        assert!(plist.contains("<string>https://api.klaay.com</string>"));
        assert!(plist.contains("<key>KLAAYGUARD_LAUNCHD</key>"));
        // The file is written only for an installed app, so the job always runs
        // at login and stays up.
        assert!(plist.contains("<key>RunAtLoad</key>\n    <true/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
        // Every placeholder is filled, or launchd rejects the file.
        assert!(!plist.contains("__"), "an unfilled placeholder remains");
    }

    #[test]
    fn a_hostile_path_cannot_inject_launchd_keys() {
        let plist = render_launch_agent_plist(
            "com.klaay.klaayguard",
            "/Applications/</string><key>ThrottleInterval</key><integer>0</integer><string>.app",
            "/log",
            "https://api.klaay.com",
        );
        assert!(!plist.contains("<key>ThrottleInterval</key>\n    <integer>0</integer>"));
        assert!(plist.contains("&lt;/string&gt;"));
    }

    #[test]
    fn xml_escape_neutralizes_plist_injection() {
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
        // A value trying to break out of <string> and inject a launchd key is neutralized.
        let evil = "x</string><key>RunAtLoad</key><true/><string>";
        let escaped = xml_escape(evil);
        assert!(!escaped.contains("</string>"));
        assert!(!escaped.contains("<key>"));
        assert!(escaped.contains("&lt;/string&gt;"));
    }

    /// Test helper: the (id, sql) pairs of the osquery items only.
    fn osquery_pairs(items: &[CollectionItem]) -> Vec<(String, String)> {
        items
            .iter()
            .filter_map(|i| match i {
                CollectionItem::Osquery { id, sql } => Some((id.clone(), sql.clone())),
                CollectionItem::Builtin { .. } => None,
            })
            .collect()
    }

    #[test]
    fn config_queries_use_explicit_sql_or_default_select() {
        let cfg = json!({"data": [
            {"type": "osquery-table", "id": "system_info"},
            {"type": "osquery-table", "id": "users", "sql": "SELECT username FROM users"}
        ]});
        let q = osquery_pairs(&parse_config_items(&cfg, "linux"));
        assert_eq!(q.len(), 2);
        assert!(q.contains(&(
            "system_info".to_string(),
            "SELECT * FROM system_info".to_string()
        )));
        assert!(q.contains(&(
            "users".to_string(),
            "SELECT username FROM users".to_string()
        )));
    }

    #[test]
    fn config_queries_empty_when_no_data() {
        assert!(parse_config_items(&json!({}), "linux").is_empty());
        assert!(parse_config_items(&json!({"data": []}), "linux").is_empty());
    }

    #[test]
    fn config_items_dispatch_builtin_drops_missing_check() {
        let cfg = json!({"data": [
            {"id": "disk_encryption", "platform": "linux", "type": "builtin", "check": "disk_encryption"},
            {"id": "broken", "type": "builtin"},
            {"id": "os_version", "sql": "SELECT name FROM os_version"}
        ]});
        let items = parse_config_items(&cfg, "linux");
        // The builtin with a check resolves; the one missing `check` is dropped;
        // the osquery item stays osquery.
        assert!(items.contains(&CollectionItem::Builtin {
            id: "disk_encryption".to_string(),
            check: "disk_encryption".to_string(),
        }));
        assert!(!items
            .iter()
            .any(|i| matches!(i, CollectionItem::Builtin { id, .. } if id == "broken")));
        assert_eq!(osquery_pairs(&items).len(), 1);
    }

    #[test]
    fn config_items_dispatch_builtin_type() {
        // kiln's contract is `type: "builtin"`. Reading only `source` sent
        // the Linux disk_encryption and screenlock builtins to osquery,
        // where one misreports LUKS and the other has no table.
        let cfg = json!({"data": [
            {"type": "builtin", "id": "screenlock", "platform": "linux", "check": "screenlock"},
            {"type": "osquery-table", "id": "system_info"}
        ]});
        let items = parse_config_items(&cfg, "linux");
        assert!(items.contains(&CollectionItem::Builtin {
            id: "screenlock".to_string(),
            check: "screenlock".to_string(),
        }));
        assert_eq!(osquery_pairs(&items).len(), 1);
    }

    #[test]
    fn builtin_check_unknown_is_empty() {
        assert_eq!(run_builtin_check("nope"), json!([]));
    }

    // ----- disk encryption -----

    fn summary(rows: &Value) -> Value {
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == "summary")
            .cloned()
            .unwrap()
    }

    #[test]
    fn disk_encryption_detects_luks_root() {
        // Realistic btrfs-on-LUKS layout (Arch/Omarchy, Fedora, openSUSE): the
        // crypt device's singular `mountpoint` is a subvolume, and `/` appears
        // only in the `mountpoints` array. A single-`/` fixture would hide the
        // real bug where the root reads "unknown".
        let lsblk = r#"{"blockdevices":[
          {"name":"nvme0n1","type":"disk","fstype":null,"mountpoint":null,"children":[
            {"name":"nvme0n1p1","type":"part","fstype":"vfat","mountpoints":["/boot"]},
            {"name":"nvme0n1p2","type":"part","fstype":"crypto_LUKS","mountpoint":null,"children":[
              {"name":"root","type":"crypt","fstype":"btrfs","mountpoint":"/var/log",
               "mountpoints":["/var/log","/home","/var/cache/pacman/pkg","/"]}
            ]}
          ]}
        ]}"#;
        // A real home path: the classification is of the mount it lives on.
        let rows = build_disk_encryption_rows(Some(lsblk), "", Some("/home/u"));
        let s = summary(&rows);
        assert_eq!(s["root_encrypted"], "yes");
        // Home is on the same crypt device, matched via its mountpoints list.
        assert_eq!(s["home_encrypted"], "yes");
        assert_eq!(s["mechanisms"], json!(["luks"]));
    }

    #[test]
    fn disk_encryption_home_resolves_to_its_enclosing_mount() {
        // A home directory is not itself a mountpoint; with only `/` mounted
        // it shares the root determination instead of reading "unknown".
        let lsblk = r#"{"blockdevices":[
          {"name":"sda","type":"disk","children":[
            {"name":"sda1","type":"part","fstype":"ext4","mountpoint":"/"}
          ]}
        ]}"#;
        let rows = build_disk_encryption_rows(Some(lsblk), "", Some("/home/u"));
        assert_eq!(summary(&rows)["home_encrypted"], "no");
        // Nothing mounted at all: still unknown, never a guess.
        let rows = build_disk_encryption_rows(None, "", Some("/home/u"));
        assert_eq!(summary(&rows)["home_encrypted"], "unknown");
    }

    #[test]
    fn proc_mounts_octal_escapes_decode_to_bytes() {
        // /proc/mounts escapes space as \040 and non-ASCII bytes one at a time.
        let mounts = "/dev/sda2 /home/u/My\\040Docs ecryptfs rw 0 0\n\
                      /dev/sda3 /mnt/caf\\303\\251 ext4 rw 0 0\n";
        let parsed = parse_proc_mounts(mounts);
        assert_eq!(parsed[0].mountpoint, "/home/u/My Docs");
        assert_eq!(parsed[1].mountpoint, "/mnt/café");
        // An ecryptfs home at a path with a space is found.
        let rows = build_disk_encryption_rows(None, mounts, Some("/home/u/My Docs"));
        assert_eq!(summary(&rows)["home_encrypted"], "yes");
    }

    #[test]
    fn disk_encryption_reports_no_for_plain_root() {
        let lsblk = r#"{"blockdevices":[
          {"name":"sda","type":"disk","children":[
            {"name":"sda1","type":"part","fstype":"ext4","mountpoint":"/"}
          ]}
        ]}"#;
        let rows = build_disk_encryption_rows(Some(lsblk), "", None);
        assert_eq!(summary(&rows)["root_encrypted"], "no");
    }

    #[test]
    fn disk_encryption_unknown_when_root_unresolved() {
        // No lsblk and /proc/mounts has no "/" entry: must not claim "no".
        let rows = build_disk_encryption_rows(None, "tmpfs /run tmpfs rw 0 0\n", None);
        assert_eq!(summary(&rows)["root_encrypted"], "unknown");
    }

    #[test]
    fn disk_encryption_detects_ecryptfs_and_zfs() {
        let mounts = "\
/home/.ecryptfs/u/.Private /home/u ecryptfs rw 0 0
zroot/ROOT/default / zfs rw 0 0
";
        let rows = build_disk_encryption_rows(None, mounts, Some("/home/u"));
        let s = summary(&rows);
        // Root is ZFS: encryption is a dataset property we cannot read -> unknown.
        assert_eq!(s["root_encrypted"], "unknown");
        // Home is ecryptfs -> yes, and the mechanism is recorded.
        assert_eq!(s["home_encrypted"], "yes");
        assert!(s["mechanisms"]
            .as_array()
            .unwrap()
            .contains(&json!("ecryptfs")));
    }

    // ----- screen lock -----

    #[test]
    fn detect_desktop_classifies_the_common_environments() {
        assert_eq!(detect_desktop(Some("ubuntu:GNOME")), Desktop::Gnome);
        assert_eq!(detect_desktop(Some("GNOME")), Desktop::Gnome);
        assert_eq!(detect_desktop(Some("KDE")), Desktop::Kde);
        assert_eq!(detect_desktop(Some("Hyprland")), Desktop::Hyprland);
        assert_eq!(detect_desktop(Some("X-Cinnamon")), Desktop::Cinnamon);
        assert_eq!(detect_desktop(Some("MATE")), Desktop::Mate);
        assert_eq!(detect_desktop(Some("XFCE")), Desktop::Xfce);
        assert_eq!(detect_desktop(Some("xubuntu:XFCE")), Desktop::Xfce);
        assert_eq!(detect_desktop(None), Desktop::Unknown);
    }

    #[test]
    fn xset_timeout_reads_the_x_screensaver_blank_delay() {
        let out = "Keyboard Control:\n  auto repeat:  on\nScreen Saver:\n  \
                   prefer blanking:  yes    allow exposures:  yes\n  \
                   timeout:  600    cycle:  600\nColors:\n";
        assert_eq!(parse_xset_timeout(out), Some(600));
        // A zero timeout means X never blanks, so light-locker never fires.
        assert_eq!(
            parse_xset_timeout("Screen Saver:\n  timeout:  0    cycle:  0\n"),
            Some(0)
        );
        assert_eq!(parse_xset_timeout("no screen saver section"), None);
    }

    #[test]
    fn xfce4_screensaver_needs_all_four_switches_and_a_delay() {
        // All four switches on, 10 min idle + 1 min grace = 660 s.
        let row = screenlock_row_xfce_screensaver(
            Some(true),
            Some(true),
            Some(10),
            Some(true),
            Some(true),
            Some(1),
        );
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 660);
        assert_eq!(row[0]["desktop_environment"], "xfce");
        assert_eq!(row[0]["source"], "xfce4-screensaver");

        // Each switch alone turns the lock off. gs-listener requires
        // saver-enabled AND idle-activation; add_lock_timer requires
        // lock-enabled AND lock/saver-activation/enabled.
        for (saver, idle_act, lock, lock_saver) in [
            (false, true, true, true),
            (true, false, true, true),
            (true, true, false, true),
            (true, true, true, false),
        ] {
            let off = screenlock_row_xfce_screensaver(
                Some(saver),
                Some(idle_act),
                Some(10),
                Some(lock),
                Some(lock_saver),
                Some(0),
            );
            assert_eq!(off[0]["enabled"], "no", "{:?}", off);
        }

        // A zero idle delay never triggers, as on every other desktop.
        let zero = screenlock_row_xfce_screensaver(
            Some(true),
            Some(true),
            Some(0),
            Some(true),
            Some(true),
            Some(0),
        );
        assert_eq!(zero[0]["enabled"], "no");
        assert_eq!(zero[0]["delay_seconds"], 0);

        // xfconf stores only values that differ from the schema, so an
        // untouched machine has no keys at all. Every default is a locking
        // one (5 min idle, 0 grace); reporting it unknown left the compliant
        // majority blank, the same defect the KDE row had.
        let untouched = screenlock_row_xfce_screensaver(None, None, None, None, None, None);
        assert_eq!(untouched[0]["enabled"], "yes");
        assert_eq!(untouched[0]["delay_seconds"], 300);
    }

    #[test]
    fn light_locker_reads_its_autostart_flags() {
        // light-locker takes seconds on the command line, not xfconf.
        assert_eq!(
            parse_light_locker_autostart(
                "[Desktop Entry]\nType=Application\n\
                 Exec=light-locker --lock-after-screensaver=30 --late-locking\n"
            ),
            Some(30)
        );
        // No flag: light-locker's own default is 5 seconds.
        assert_eq!(
            parse_light_locker_autostart("[Desktop Entry]\nExec=light-locker\n"),
            Some(5)
        );
        // The user disabled the entry, so nothing locks.
        assert_eq!(
            parse_light_locker_autostart("[Desktop Entry]\nExec=light-locker\nHidden=true\n"),
            None
        );
    }

    #[test]
    fn light_locker_locks_only_when_x_blanks() {
        // X blanks after 600 s, light-locker locks 5 s later.
        let row = screenlock_row_light_locker(Some(5), Some(600));
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 605);
        assert_eq!(row[0]["desktop_environment"], "xfce");
        assert_eq!(row[0]["source"], "light-locker");

        // X never blanks, so light-locker never fires.
        let never = screenlock_row_light_locker(Some(5), Some(0));
        assert_eq!(never[0]["enabled"], "no");
        assert_eq!(never[0]["delay_seconds"], 0);

        // The autostart entry is disabled: light-locker never runs.
        assert_eq!(
            screenlock_row_light_locker(None, Some(600))[0]["enabled"],
            "no"
        );

        // No xset answer: unknown, never a false "yes".
        assert_eq!(
            screenlock_row_light_locker(Some(5), None)[0]["enabled"],
            "unknown"
        );
    }

    #[test]
    fn gsettings_parsers_read_bool_and_uint() {
        assert_eq!(parse_gsettings_bool("true\n"), Some(true));
        assert_eq!(parse_gsettings_bool("false\n"), Some(false));
        assert_eq!(parse_gsettings_bool("garbage"), None);
        assert_eq!(parse_gsettings_uint("uint32 300\n"), Some(300));
        assert_eq!(parse_gsettings_uint("900"), Some(900));
    }

    #[test]
    fn gnome_lock_needs_enabled_and_nonzero_delay() {
        assert_eq!(
            screenlock_row_gnome(Some(true), Some(300), None)[0]["enabled"],
            "yes"
        );
        // Enabled but idle-delay 0 never triggers.
        assert_eq!(
            screenlock_row_gnome(Some(true), Some(0), None)[0]["enabled"],
            "no"
        );
        assert_eq!(
            screenlock_row_gnome(Some(false), Some(300), None)[0]["enabled"],
            "no"
        );
        // Missing gsettings -> unknown, never a false "no".
        assert_eq!(
            screenlock_row_gnome(None, None, None)[0]["enabled"],
            "unknown"
        );
    }

    fn saver(active: &str, secure: &str, timeout: &str) -> ScreenSaverValues {
        ScreenSaverValues {
            active: Some(active.to_string()),
            secure: Some(secure.to_string()),
            timeout_seconds: Some(timeout.to_string()),
            exe: Some(r"C:\Windows\System32\scrnsave.scr".to_string()),
        }
    }

    #[test]
    fn windows_screenlock_no_when_no_saver_is_selected() {
        // ScreenSaveActive=1 / IsSecure=1 / TimeOut=600 with the saver at
        // "(None)": Windows runs no saver and never locks. Reporting "yes"
        // from the three text values alone is the common false positive.
        let inputs = WindowsScreenLockInputs {
            user_preference: ScreenSaverValues {
                exe: None,
                ..saver("1", "1", "600")
            },
            ..Default::default()
        };
        // The screensaver path alone answers here: the row folds this in with
        // the sleep path, which has its own tests.
        let verdict = screensaver_lock_verdict(&inputs);
        assert_eq!(verdict.locks, Some(false));
        assert!(verdict.detail.contains("no screen saver selected"));
        // An empty string is "(None)" too.
        let inputs = WindowsScreenLockInputs {
            user_preference: ScreenSaverValues {
                exe: Some("".into()),
                ..saver("1", "1", "600")
            },
            ..Default::default()
        };
        assert_eq!(screensaver_lock_verdict(&inputs).locks, Some(false));
    }

    #[test]
    fn reg_sz_parsers_read_windows_text_values() {
        // Windows stores these as REG_SZ text, not DWORDs. Treating an
        // unreadable value as 0 or false invents a "no".
        assert_eq!(parse_reg_sz_bool(Some("1")), Some(true));
        assert_eq!(parse_reg_sz_bool(Some("0")), Some(false));
        assert_eq!(parse_reg_sz_bool(Some(" 1 ")), Some(true));
        assert_eq!(parse_reg_sz_bool(Some("")), None);
        assert_eq!(parse_reg_sz_bool(Some("yes")), None);
        assert_eq!(parse_reg_sz_bool(None), None);
        assert_eq!(parse_reg_sz_u64(Some("600")), Some(600));
        assert_eq!(parse_reg_sz_u64(Some("0")), Some(0));
        assert_eq!(parse_reg_sz_u64(Some("")), None);
        assert_eq!(parse_reg_sz_u64(Some("abc")), None);
    }

    #[test]
    fn windows_screenlock_yes_from_the_machine_inactivity_limit() {
        // The machine inactivity limit locks the console whatever the
        // screensaver says. Reading only the screensaver reports "unknown" on
        // a correctly hardened machine.
        let inputs = WindowsScreenLockInputs {
            inactivity_timeout_secs: Some("900".into()),
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 900);
        assert_eq!(row[0]["source"], "machine_inactivity_policy");
    }

    #[test]
    fn windows_screenlock_ignores_a_zero_inactivity_limit() {
        // Zero means "not configured", not a zero-second lock.
        let inputs = WindowsScreenLockInputs {
            inactivity_timeout_secs: Some("0".into()),
            user_preference: saver("1", "1", "600"),
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 600);
        assert_eq!(row[0]["source"], "user");
    }

    #[test]
    fn windows_screenlock_no_when_the_saver_is_not_secure() {
        // The most common false positive on Windows: the screensaver runs and
        // never asks for a password.
        let inputs = WindowsScreenLockInputs {
            user_preference: saver("1", "0", "600"),
            ..Default::default()
        };
        assert_eq!(screensaver_lock_verdict(&inputs).locks, Some(false));
    }

    #[test]
    fn windows_screenlock_no_when_the_timeout_is_zero() {
        // Mirrors the GNOME idle-delay=0 rule: a lock that never triggers is
        // not a lock.
        let inputs = WindowsScreenLockInputs {
            user_preference: saver("1", "1", "0"),
            ..Default::default()
        };
        let verdict = screensaver_lock_verdict(&inputs);
        assert_eq!(verdict.locks, Some(false));
        assert_eq!(verdict.delay_seconds, Some(0));
    }

    #[test]
    fn windows_screenlock_policy_overrides_the_user_preference() {
        // Group policy wins. Reporting the user value tells the dashboard a
        // managed fleet is unlocked.
        let inputs = WindowsScreenLockInputs {
            user_policy: saver("1", "1", "300"),
            user_preference: saver("0", "0", "0"),
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 300);
        assert_eq!(row[0]["source"], "user_policy");
    }

    #[test]
    fn windows_screenlock_merges_policy_and_user_values() {
        // Windows applies policy per value, not per key. A first-key-wins
        // rule reports "unknown" on the most common managed setup.
        let inputs = WindowsScreenLockInputs {
            user_policy: ScreenSaverValues {
                secure: Some("1".into()),
                ..Default::default()
            },
            user_preference: ScreenSaverValues {
                active: Some("1".into()),
                timeout_seconds: Some("600".into()),
                exe: Some("scrnsave.scr".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 600);
        assert_eq!(row[0]["source"], "user_policy");
        let detail = row[0]["detail"].as_str().unwrap();
        assert!(detail.contains("ScreenSaverIsSecure=true(user_policy)"));
        assert!(detail.contains("ScreenSaveTimeOut=600(user)"));
    }

    #[test]
    fn windows_screenlock_user_policy_beats_the_user_preference() {
        // Pins the middle rank of the three-level precedence.
        let inputs = WindowsScreenLockInputs {
            user_policy: ScreenSaverValues {
                timeout_seconds: Some("300".into()),
                ..Default::default()
            },
            user_preference: saver("1", "1", "1200"),
            ..Default::default()
        };
        assert_eq!(windows_screenlock_row(&inputs)[0]["delay_seconds"], 300);
    }

    #[test]
    fn windows_screenlock_unknown_when_a_value_is_missing() {
        // Guessing "yes" reports a machine compliant on two of three values.
        let inputs = WindowsScreenLockInputs {
            user_preference: ScreenSaverValues {
                active: Some("1".into()),
                timeout_seconds: Some("600".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["enabled"], "unknown");
        assert!(row[0]["detail"]
            .as_str()
            .unwrap()
            .contains("ScreenSaverIsSecure=unset"));
    }

    #[test]
    fn windows_screenlock_unknown_when_nothing_is_readable() {
        // An empty registry read must never look like "no lock". Unknown and
        // no are different answers on the dashboard.
        let row = windows_screenlock_row(&WindowsScreenLockInputs::default());
        assert_eq!(row[0]["enabled"], "unknown");
        assert!(row[0]["delay_seconds"].is_null());
        assert_eq!(row[0]["source"], "none");
    }

    /// A laptop, so both power sources apply. Display-off values are evidence
    /// only and never change a verdict, so they stay unset here.
    fn sleeps(console_lock: bool, ac: u64, dc: u64) -> SleepLockValues {
        SleepLockValues {
            console_lock: Some(console_lock),
            standby_ac_secs: Some(ac),
            standby_dc_secs: Some(dc),
            has_battery: Some(true),
            display_off_ac_secs: None,
            display_off_dc_secs: None,
        }
    }

    #[test]
    fn guids_parse_in_both_spellings_the_registry_uses() {
        let parsed = parse_guid("381b4222-f694-41f0-9685-ff5bb260df2e").unwrap();
        assert_eq!(parsed.d1, 0x381b4222);
        assert_eq!(parsed.d2, 0xf694);
        assert_eq!(parsed.d3, 0x41f0);
        assert_eq!(parsed.d4, [0x96, 0x85, 0xff, 0x5b, 0xb2, 0x60, 0xdf, 0x2e]);
        // Braces and padding are both shapes the registry hands back.
        assert_eq!(
            parse_guid("  {381b4222-f694-41f0-9685-ff5bb260df2e}  "),
            Some(parsed)
        );
        // A scheme that cannot be parsed must not silently read another one.
        assert_eq!(parse_guid(""), None);
        assert_eq!(parse_guid("381b4222-f694-41f0-9685"), None);
        assert_eq!(parse_guid("381b4222-f694-41f0-9685-ff5bb260df2"), None);
        assert_eq!(parse_guid("zzzzzzzz-f694-41f0-9685-ff5bb260df2e"), None);
    }

    #[test]
    fn sleep_lock_reports_the_worst_of_the_two_timeouts() {
        // The machine is on one power source or the other, so "how long can
        // this sit unlocked" is answered by the longer of the two.
        let v = sleep_lock_verdict(&sleeps(true, 900, 600));
        assert_eq!(v.locks, Some(true));
        assert_eq!(v.delay_seconds, Some(900));
        assert_eq!(v.source, "sleep_policy");
    }

    #[test]
    fn sleep_lock_says_no_when_only_one_power_source_sleeps() {
        // Measured on a Windows 11 laptop: mains and battery really do differ.
        // A machine that never sleeps on mains sits unlocked whenever it is
        // plugged in, so this is a "no", not a lock after 600s.
        let v = sleep_lock_verdict(&sleeps(true, 0, 600));
        assert_eq!(v.locks, Some(false));
        assert_eq!(v.delay_seconds, Some(0));
    }

    #[test]
    fn sleep_lock_ignores_the_battery_side_on_a_desktop() {
        // A desktop returns a battery-side timeout that never applies.
        let inputs = SleepLockValues {
            has_battery: Some(false),
            ..sleeps(true, 600, 0)
        };
        let v = sleep_lock_verdict(&inputs);
        assert_eq!(v.locks, Some(true));
        assert_eq!(v.delay_seconds, Some(600));
    }

    #[test]
    fn sleep_lock_says_no_when_waking_needs_no_password() {
        assert_eq!(sleep_lock_verdict(&sleeps(false, 600, 600)).locks, Some(false));
    }

    #[test]
    fn sleep_lock_says_no_when_the_machine_never_sleeps() {
        // Require-a-password is on, but nothing ever triggers it.
        let v = sleep_lock_verdict(&sleeps(true, 0, 0));
        assert_eq!(v.locks, Some(false));
        assert_eq!(v.delay_seconds, Some(0));
    }

    #[test]
    fn sleep_lock_stays_unknown_when_a_timeout_is_unreadable() {
        // One readable zero says nothing about the other side.
        let inputs = SleepLockValues {
            standby_dc_secs: None,
            ..sleeps(true, 0, 0)
        };
        assert_eq!(sleep_lock_verdict(&inputs).locks, None);
        // Nothing read at all names no source, so the row can report "none".
        let v = sleep_lock_verdict(&SleepLockValues::default());
        assert_eq!(v.locks, None);
        assert_eq!(v.source, "none");
    }

    #[test]
    fn windows_screenlock_yes_from_sleep_when_the_saver_is_silent() {
        // The Windows 11 default and the shape Element Standard reported
        // (PROD-5063): a screensaver runs with a timeout but ScreenSaverIsSecure
        // was never written, so the saver alone is "unknown". The machine still
        // locks, through sign-in-on-wake.
        let inputs = WindowsScreenLockInputs {
            user_preference: ScreenSaverValues {
                secure: None,
                ..saver("1", "1", "300")
            },
            sleep: sleeps(true, 1800, 900),
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 1800);
        assert_eq!(row[0]["source"], "sleep_policy");
        // Both mechanisms stay visible in the evidence.
        let detail = row[0]["detail"].as_str().unwrap();
        assert!(detail.contains("ScreenSaverIsSecure=unset"));
        assert!(detail.contains("ConsoleLock=true"));
    }

    #[test]
    fn windows_screenlock_reports_the_soonest_locking_mechanism() {
        // Both lock; the screen is locked at the earlier of the two.
        let inputs = WindowsScreenLockInputs {
            user_preference: saver("1", "1", "300"),
            sleep: sleeps(true, 1800, 900),
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 300);
        assert_eq!(row[0]["source"], "user");
    }

    #[test]
    fn windows_screenlock_no_when_neither_mechanism_locks() {
        // A definite "no" from both is a real answer, not "unknown".
        let inputs = WindowsScreenLockInputs {
            user_preference: saver("1", "0", "600"),
            sleep: sleeps(false, 600, 600),
            ..Default::default()
        };
        assert_eq!(windows_screenlock_row(&inputs)[0]["enabled"], "no");
    }

    #[test]
    fn windows_screenlock_unknown_when_one_mechanism_cannot_be_read() {
        // The screensaver plainly does not lock, but the power configuration
        // could not be read and might. Reporting "no" here would mark a
        // locking machine non-compliant on evidence nobody has.
        let inputs = WindowsScreenLockInputs {
            user_preference: saver("1", "0", "600"),
            sleep: SleepLockValues::default(),
            ..Default::default()
        };
        assert_eq!(windows_screenlock_row(&inputs)[0]["enabled"], "unknown");
    }

    #[test]
    fn windows_screenlock_matches_a_measured_windows_11_laptop() {
        // Measured on a Windows 11 laptop (PROD-5063): the power API reports
        // CONSOLELOCK=1 on both power sources even though `powercfg /q` hides
        // the setting and the registry holds no value for it, while sleep is
        // switched off entirely and the display turns off only on battery.
        // The secure screensaver is what actually locks this machine.
        let inputs = WindowsScreenLockInputs {
            user_preference: ScreenSaverValues {
                active: Some("1".into()),
                secure: Some("1".into()),
                timeout_seconds: Some("300".into()),
                exe: Some(r"C:\Windows\System32\scrnsave.scr".into()),
            },
            sleep: SleepLockValues {
                display_off_ac_secs: Some(0),
                display_off_dc_secs: Some(180),
                ..sleeps(true, 0, 0)
            },
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 300);
        assert_eq!(row[0]["source"], "user");
    }

    #[test]
    fn windows_screenlock_machine_policy_still_beats_the_sleep_path() {
        let inputs = WindowsScreenLockInputs {
            inactivity_timeout_secs: Some("900".into()),
            sleep: sleeps(true, 60, 60),
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["delay_seconds"], 900);
        assert_eq!(row[0]["source"], "machine_inactivity_policy");
    }

    #[test]
    fn bitlocker_protection_parses_the_shell_property_values() {
        // The shell property is an integer as text. Only 1 and 6 mean the
        // data is protected right now; an unparseable value is None.
        assert_eq!(
            parse_bitlocker_protection(Some("1")),
            Some(BitLockerProtection::On)
        );
        assert_eq!(
            parse_bitlocker_protection(Some("2")),
            Some(BitLockerProtection::Off)
        );
        assert_eq!(
            parse_bitlocker_protection(Some(" 5 ")),
            Some(BitLockerProtection::Suspended)
        );
        assert_eq!(
            parse_bitlocker_protection(Some("9")),
            Some(BitLockerProtection::Other(9))
        );
        assert_eq!(
            parse_bitlocker_protection(Some("7")),
            Some(BitLockerProtection::PendingRestart)
        );
        assert_eq!(parse_bitlocker_protection(Some("")), None);
        assert_eq!(parse_bitlocker_protection(None), None);
    }

    #[test]
    fn windows_disk_encryption_only_a_protected_volume_is_yes() {
        // A suspended volume has its key in the clear and an encrypting one
        // is not yet protected. Reporting either as "yes" tells the
        // dashboard a laptop is safe to lose when it is not.
        let yes = |s| windows_disk_encryption_rows("C:", Some(s), "")[1]["root_encrypted"] == "yes";
        assert!(yes(BitLockerProtection::On));
        assert!(yes(BitLockerProtection::Locked));
        assert!(!yes(BitLockerProtection::Off));
        assert!(!yes(BitLockerProtection::Suspended));
        assert!(!yes(BitLockerProtection::Encrypting));
        assert!(!yes(BitLockerProtection::Decrypting));
        assert!(!yes(BitLockerProtection::PendingRestart));
    }

    #[test]
    fn windows_disk_encryption_unknown_when_the_property_is_unreadable() {
        // Unknown and no are different answers on the dashboard.
        let rows = windows_disk_encryption_rows("C:", None, "");
        assert_eq!(rows[1]["root_encrypted"], "unknown");
        assert_eq!(rows[0]["source"], "shell_property");
        assert_eq!(
            windows_disk_encryption_rows("C:", Some(BitLockerProtection::Other(42)), "")[1]
                ["root_encrypted"],
            "unknown"
        );
        // A read blocked by policy says so, instead of looking like a missing
        // property.
        let blocked = windows_disk_encryption_rows("C:", None, "blocked by application control");
        assert_eq!(blocked[1]["root_encrypted"], "unknown");
        assert!(blocked[0]["detail"]
            .as_str()
            .unwrap()
            .contains("blocked by application control"));
    }

    #[test]
    fn windows_disk_encryption_uses_the_linux_summary_shape() {
        // kiln's encryption_status_from_rows reads root_encrypted off the
        // summary row; the Windows builtin must emit the same shape.
        let rows = windows_disk_encryption_rows("C:", Some(BitLockerProtection::On), "");
        let summary = rows
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == "summary")
            .unwrap();
        assert_eq!(summary["root_encrypted"], "yes");
        assert_eq!(summary["mechanisms"], json!(["bitlocker"]));
        assert_eq!(summary["source"], "aggregate");
    }

    #[test]
    fn password_policy_row_converts_the_api_units() {
        // NetUserModalsGet returns seconds and uses u32::MAX for "never".
        // The row must say days and minutes, and null for never, or a
        // 42-day maximum age reads as 3.6 million.
        let p = PasswordPolicy {
            min_password_len: 0,
            max_password_age_secs: 42 * 86_400,
            min_password_age_secs: 0,
            password_history_len: 0,
            lockout_threshold: 10,
            lockout_duration_secs: 600,
            lockout_window_secs: 600,
        };
        let row = &password_policy_rows(Some(p), "local")[0];
        assert_eq!(row["maximum_password_age_days"], 42);
        assert_eq!(row["scope"], "local");
        assert_eq!(row["policy_of"], "local_accounts");
        assert_eq!(row["minimum_password_age_days"], 0);
        assert_eq!(row["lockout_threshold"], 10);
        assert_eq!(row["lockout_duration_minutes"], 10);
        assert_eq!(row["lockout_window_minutes"], 10);
        assert_eq!(row["status"], "ok");
    }

    #[test]
    fn password_policy_row_reports_never_as_null() {
        // A password that never expires must not look like a 49710-day one.
        let p = PasswordPolicy {
            min_password_len: 12,
            max_password_age_secs: TIMEQ_FOREVER,
            min_password_age_secs: 86_400,
            password_history_len: 24,
            lockout_threshold: 0,
            lockout_duration_secs: TIMEQ_FOREVER,
            lockout_window_secs: 1800,
        };
        let row = &password_policy_rows(Some(p), "domain")[0];
        assert!(row["maximum_password_age_days"].is_null());
        assert_eq!(row["scope"], "domain");
        assert!(row["lockout_duration_minutes"].is_null());
        assert_eq!(row["minimum_password_length"], 12);
        assert_eq!(row["password_history_size"], 24);
        assert_eq!(row["lockout_threshold"], 0);
    }

    #[test]
    fn password_policy_unknown_when_the_api_fails() {
        // Never emit zeros for an unreadable policy; zeros mean "no policy".
        let row = &password_policy_rows(None, "unknown")[0];
        assert_eq!(row["status"], "unknown");
        assert!(row.get("minimum_password_length").is_none());
    }

    #[test]
    fn windows_screenlock_row_uses_the_shared_row_shape() {
        // The backend reads one screenlock shape for every operating system.
        let row = windows_screenlock_row(&WindowsScreenLockInputs::default());
        let obj = row[0].as_object().unwrap();
        let mut keys: Vec<_> = obj.keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "delay_seconds",
                "desktop_environment",
                "detail",
                "enabled",
                "source"
            ]
        );
        assert_eq!(row[0]["desktop_environment"], "windows");
    }

    #[test]
    fn kscreenlockerrc_parses_daemon_section() {
        let text = "[Daemon]\nAutolock=false\nTimeout=5\n[Greeter]\nAutolock=true\n";
        let (autolock, timeout) = parse_kscreenlockerrc(text);
        assert_eq!(autolock, Some(false));
        assert_eq!(timeout, Some(300));
        // Plasma 6.3 stores the timeout as a double: 0.5 is thirty seconds,
        // and it must not round up to a minute.
        assert_eq!(parse_kscreenlockerrc("[Daemon]\nTimeout=0.5\n").1, Some(30));
        assert_eq!(
            parse_kscreenlockerrc("[Daemon]\nTimeout=10.0\n").1,
            Some(600)
        );
        // Missing file/keys -> the Plasma default, which locks.
        assert_eq!(screenlock_row_kde(None, None)[0]["enabled"], "yes");
        assert_eq!(
            screenlock_row_kde(Some(true), Some(300))[0]["delay_seconds"],
            300
        );
    }

    #[test]
    fn hypridle_lock_listener_yields_timeout() {
        let cfg = "\
listener {
    timeout = 150
    on-timeout = brightnessctl -s set 10
}
listener {
    timeout = 300
    on-timeout = loginctl lock-session
}
";
        assert_eq!(parse_hypridle_config(cfg), Some(300));
        // A custom lock wrapper (no "hyprlock"/"lock-session") still counts.
        let custom = "listener {\n timeout = 152\n on-timeout = omarchy-system-lock\n}\n";
        assert_eq!(parse_hypridle_config(custom), Some(152));
        // A config with only a non-lock listener -> None -> unknown.
        let dpms = "listener {\n timeout = 600\n on-timeout = hyprctl dispatch dpms off\n}\n";
        assert_eq!(parse_hypridle_config(dpms), None);
        assert_eq!(screenlock_row_hyprland(None)[0]["enabled"], "unknown");
        // A zero timeout never fires. Seen on 2026-08-29: it reported "yes".
        let zero = screenlock_row_hyprland(Some(0));
        assert_eq!(zero[0]["enabled"], "no");
        assert_eq!(zero[0]["delay_seconds"], 0);
        assert_eq!(screenlock_row_hyprland(Some(300))[0]["enabled"], "yes");
    }

    #[test]
    fn kde_absent_keys_mean_plasma_defaults() {
        // An untouched Plasma install writes no kscreenlockerrc. That is the
        // secure default (Autolock=true, 5 min), not unknown.
        let row = screenlock_row_kde(None, None);
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 300);
        assert!(row[0]["detail"]
            .as_str()
            .unwrap()
            .contains("Plasma default"));
        // File values win over the defaults.
        assert_eq!(
            screenlock_row_kde(Some(false), Some(120))[0]["enabled"],
            "no"
        );
        assert_eq!(
            screenlock_row_kde(Some(true), Some(30))[0]["delay_seconds"],
            30
        );
        // A zero timeout never fires, as on every other platform.
        assert_eq!(screenlock_row_kde(None, Some(0))[0]["enabled"], "no");
    }

    #[test]
    fn gsettings_desktops_add_lock_delay_and_mate_counts_minutes() {
        // GNOME/Cinnamon: idle-delay 300 + lock-delay 3600 is a 65-minute
        // lock, not a 5-minute one.
        let g = screenlock_row_gnome(Some(true), Some(300), Some(3600));
        assert_eq!(g[0]["enabled"], "yes");
        assert_eq!(g[0]["delay_seconds"], 3900);
        let c = screenlock_row_gsettings("cinnamon", Some(true), Some(900), None);
        assert_eq!(c[0]["desktop_environment"], "cinnamon");
        assert_eq!(c[0]["delay_seconds"], 900);
        // idle-delay 0 never triggers, whatever lock-delay says.
        assert_eq!(
            screenlock_row_gsettings("cinnamon", Some(true), Some(0), Some(60))[0]["enabled"],
            "no"
        );
        // MATE stores minutes: 5 + 1 minutes is 360 seconds.
        let m = screenlock_row_mate(Some(true), Some(true), Some(5), Some(1));
        assert_eq!(m[0]["enabled"], "yes");
        assert_eq!(m[0]["delay_seconds"], 360);
        assert_eq!(
            screenlock_row_mate(Some(false), Some(true), Some(5), None)[0]["enabled"],
            "no"
        );
        assert_eq!(
            screenlock_row_mate(Some(true), Some(false), Some(5), None)[0]["enabled"],
            "no"
        );
        assert_eq!(
            screenlock_row_mate(None, None, None, None)[0]["enabled"],
            "unknown"
        );
    }

    #[test]
    fn platform_matches_mirrors_osquery_pack_semantics() {
        // Absent / empty / "all" run everywhere.
        assert!(platform_matches(None, "linux"));
        assert!(platform_matches(Some(""), "macos"));
        assert!(platform_matches(Some("all"), "windows"));
        // posix = linux + macos, not windows.
        assert!(platform_matches(Some("posix"), "linux"));
        assert!(platform_matches(Some("posix"), "macos"));
        assert!(!platform_matches(Some("posix"), "windows"));
        // A specific OS matches only itself; case/whitespace insensitive.
        assert!(platform_matches(Some("linux"), "linux"));
        assert!(!platform_matches(Some("darwin"), "linux"));
        // osquery's list and wildcard forms.
        assert!(platform_matches(Some("linux,darwin"), "linux"));
        assert!(platform_matches(Some("linux, darwin"), "macos"));
        assert!(!platform_matches(Some("linux,darwin"), "windows"));
        assert!(platform_matches(Some("any"), "windows"));
        assert!(platform_matches(Some("ubuntu"), "linux"));
        // osquery's "darwin" tag matches a "macos" host (Rust's OS string).
        assert!(platform_matches(Some("darwin"), "macos"));
        assert!(platform_matches(Some(" Darwin "), "macos"));
        assert!(platform_matches(Some("macos"), "macos"));
    }

    #[test]
    fn config_queries_filter_by_platform() {
        let cfg = json!({"data": [
            {"id": "system_info"},
            {"id": "screenlock", "platform": "darwin", "sql": "SELECT enabled FROM screenlock"},
            {"id": "users", "platform": "linux", "sql": "SELECT username FROM users"}
        ]});
        // On Linux: the untagged item and the linux item run; the darwin item is skipped.
        let linux = osquery_pairs(&parse_config_items(&cfg, "linux"));
        let linux_ids: Vec<&String> = linux.iter().map(|(id, _)| id).collect();
        assert!(linux_ids.contains(&&"system_info".to_string()));
        assert!(linux_ids.contains(&&"users".to_string()));
        assert!(!linux_ids.contains(&&"screenlock".to_string()));
        // On macOS: the untagged item and the darwin item run; the linux item is skipped.
        let mac = osquery_pairs(&parse_config_items(&cfg, "macos"));
        let mac_ids: Vec<&String> = mac.iter().map(|(id, _)| id).collect();
        assert!(mac_ids.contains(&&"system_info".to_string()));
        assert!(mac_ids.contains(&&"screenlock".to_string()));
        assert!(!mac_ids.contains(&&"users".to_string()));
    }

    #[test]
    fn read_only_guard_allows_select_and_cte_rejects_the_rest() {
        assert!(is_read_only_query("SELECT * FROM system_info"));
        assert!(is_read_only_query("  select username from users ;  "));
        assert!(is_read_only_query("WITH t AS (SELECT 1) SELECT * FROM t"));
        // Stacked statement smuggled after a legit SELECT.
        assert!(!is_read_only_query("SELECT 1; ATTACH DATABASE 'x' AS y"));
        // Non-query verbs.
        assert!(!is_read_only_query("PRAGMA table_info(users)"));
        assert!(!is_read_only_query("DROP TABLE users"));
        // DML hidden behind a CTE is not a query; a column named like a verb is fine.
        assert!(!is_read_only_query(
            "WITH t AS (SELECT 1) DELETE FROM users"
        ));
        assert!(is_read_only_query("SELECT last_update, deleted FROM x"));
    }

    #[test]
    fn config_queries_drops_non_read_only_sql() {
        let cfg = json!({"data": [
            {"id": "system_info"},
            {"id": "evil", "sql": "SELECT 1; ATTACH DATABASE 'x' AS y"}
        ]});
        let q = osquery_pairs(&parse_config_items(&cfg, "linux"));
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, "system_info");
    }

    #[test]
    fn payload_items_flatten_rows_and_stamp_collected_at() {
        let mut results = HashMap::new();
        results.insert(
            "users".to_string(),
            json!([{"username": "a"}, {"username": "b"}]),
        );
        let items = build_payload_items(&results, "2026-06-22T00:00:00Z");
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|i| i.r#type == "users"));
        assert_eq!(
            items[0].attributes["collected_at"],
            json!("2026-06-22T00:00:00Z")
        );
        assert!(items[0].attributes.get("username").is_some());
    }

    #[test]
    fn payload_items_empty_for_no_rows() {
        let results: HashMap<String, Value> = HashMap::new();
        assert!(build_payload_items(&results, "T").is_empty());
    }

    #[test]
    fn serial_extracted_from_system_info_hardware_serial() {
        // Shaped like real osquery system_info: serial is `hardware_serial`, not `serial_number`.
        let rows = json!([{"hardware_serial": "G97L3X4KYV", "uuid": "9082C1CD", "computer_name": "Athene"}]);
        assert_eq!(extract_serial(&rows), Some("G97L3X4KYV".to_string()));
    }

    #[test]
    fn serial_rejects_bios_placeholders() {
        // OEM boards and VMs report placeholders, and osquery reports "-1"
        // when WMI fails; adopting one merges every such machine into one.
        for s in [
            "To Be Filled By O.E.M.",
            "-1",
            "0",
            "Default string",
            "System Serial Number",
            "0000000000",
            "N/A",
        ] {
            assert_eq!(
                extract_serial(&json!([{"hardware_serial": s}])),
                None,
                "{}",
                s
            );
        }
        assert_eq!(
            extract_serial(&json!([{"hardware_serial": " G97L3X4KYV "}])),
            Some("G97L3X4KYV".to_string())
        );
    }

    #[test]
    fn serial_ignores_osquery_uuid() {
        // Unprivileged osquery on Linux cannot read the DMI uuid and invents a
        // random one per process. A uuid must never become the device identity.
        let only_uuid = json!([{"uuid": "9082C1CD", "hardware_serial": ""}]);
        assert_eq!(extract_serial(&only_uuid), None);
        assert_eq!(extract_serial(&json!([])), None);
        assert_eq!(extract_serial(&Value::Null), None);
    }

    #[test]
    fn machine_id_hash_matches_reference_vector() {
        // echo -n "0123456789abcdef0123456789abcdef" | openssl dgst -sha256 -hmac "com.klaay.klaayguard"
        assert_eq!(
            hash_machine_id("0123456789abcdef0123456789abcdef"),
            "a94933b40c1cb82efd93d7bb3317a191137577124258761a148dc702565207a6"
        );
    }

    #[test]
    fn machine_id_normalized_before_use() {
        assert_eq!(
            normalize_machine_id(" 7cb925cc5c9146aa9c01c733c83dd047\n"),
            Some("7cb925cc5c9146aa9c01c733c83dd047".to_string())
        );
        assert_eq!(normalize_machine_id(""), None);
        assert_eq!(normalize_machine_id("uninitialized\n"), None);
        assert_eq!(
            normalize_machine_id("zz3262c33af9461e9ed5ce8bed32dcbz"),
            None
        );
    }

    #[test]
    fn identity_prefers_stored_value() {
        let d = decide_device_identity(
            Some("stored-id"),
            Some("G97L3X4KYV"),
            Some("0123456789abcdef0123456789abcdef"),
        );
        assert!(matches!(d, IdentityDecision::Use(v) if v == "stored-id"));
    }

    #[test]
    fn identity_adopts_hardware_serial_when_nothing_stored() {
        let d = decide_device_identity(
            None,
            Some("G97L3X4KYV"),
            Some("0123456789abcdef0123456789abcdef"),
        );
        assert!(matches!(d, IdentityDecision::Adopt(v) if v == "G97L3X4KYV"));
    }

    #[test]
    fn identity_adopts_hashed_machine_id_without_serial() {
        // The raw machine id carries a trailing newline straight from the file.
        let d = decide_device_identity(None, None, Some("0123456789abcdef0123456789abcdef\n"));
        assert!(matches!(
            d,
            IdentityDecision::Adopt(v)
                if v == "a94933b40c1cb82efd93d7bb3317a191137577124258761a148dc702565207a6"
        ));
    }

    #[test]
    fn identity_generates_as_last_resort() {
        assert!(matches!(
            decide_device_identity(None, None, None),
            IdentityDecision::Generate
        ));
    }

    #[test]
    fn identity_treats_empty_stored_as_missing() {
        let d = decide_device_identity(Some(""), None, None);
        assert!(matches!(d, IdentityDecision::Generate));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn early_log_dir_follows_the_data_local_dir_on_linux() {
        // The panic hook must write where tauri-plugin-log writes, which
        // resolves through XDG_DATA_HOME, not a fixed ~/.local/share. A user
        // who sets XDG_DATA_HOME must not get split logs.
        let dir = early_log_dir(
            std::path::Path::new("/home/u"),
            std::path::Path::new("/data/xdg"),
        );
        assert_eq!(
            dir,
            std::path::PathBuf::from("/data/xdg/com.klaay.app/logs")
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn early_log_dir_stays_in_library_logs_on_macos() {
        // macOS logs live under ~/Library/Logs, not the data-local dir
        // (which would be Application Support).
        let dir = early_log_dir(
            std::path::Path::new("/Users/u"),
            std::path::Path::new("/Users/u/Library/Application Support"),
        );
        assert_eq!(
            dir,
            std::path::PathBuf::from("/Users/u/Library/Logs/com.klaay.app")
        );
    }

    #[test]
    fn appimage_asset_selected_by_arch_and_suffix() {
        let assets = json!([
            {"id": 1, "original_name": "KlaayGuard_0.2.0_Linux_x86_64_production.deb", "name": "Linux (Debian/Ubuntu .deb)"},
            {"id": 2, "original_name": "KlaayGuard_0.2.0_macOS_x64_production.dmg", "name": "MacOS (Intel)"},
            {"id": 3, "original_name": "KlaayGuard_0.2.0_Linux_aarch64_production.AppImage", "name": "Linux (AppImage)"},
            {"id": 4, "original_name": "KlaayGuard_0.2.0_Linux_x86_64_production.AppImage", "name": "Linux (AppImage)"}
        ]);
        let assets: Vec<ReleaseAsset> = serde_json::from_value(assets).unwrap();
        assert_eq!(select_appimage_asset(&assets, "x86_64").unwrap().id, 4);
        assert_eq!(select_appimage_asset(&assets, "aarch64").unwrap().id, 3);
        // The label alone must never match; original_name is the contract.
        let label_only: Vec<ReleaseAsset> =
            serde_json::from_value(json!([{"id": 9, "name": "Linux (AppImage)"}])).unwrap();
        assert!(select_appimage_asset(&label_only, "x86_64").is_none());
    }

    #[test]
    fn appimage_is_own_requires_the_exe_under_appdir() {
        use std::path::Path;
        // Our own image: the executable runs from the runtime's mount of it.
        assert!(appimage_is_own(
            Path::new("/home/u/Apps/KlaayGuard.AppImage"),
            Path::new("/tmp/.mount_Klaayx"),
            Path::new("/tmp/.mount_Klaayx/usr/bin/klaayguard")
        ));
        // A deb/rpm agent started from an AppImage browser inherits its pair.
        assert!(!appimage_is_own(
            Path::new("/home/u/Apps/zen.AppImage"),
            Path::new("/tmp/.mount_zenXY"),
            Path::new("/usr/bin/klaayguard")
        ));
        assert!(!appimage_is_own(
            Path::new("KlaayGuard.AppImage"),
            Path::new("/tmp/.mount_Klaayx"),
            Path::new("/tmp/.mount_Klaayx/usr/bin/klaayguard")
        ));
    }

    #[test]
    fn staged_path_lands_next_to_the_target() {
        // The staged file or bundle must share the target directory so the
        // final rename stays on one filesystem and is atomic.
        for target in [
            "/home/u/Apps/KlaayGuard.AppImage",
            "/Applications/KlaayGuard.app",
        ] {
            let target = std::path::Path::new(target);
            let staged = staged_sibling_path(target, 4242);
            assert_eq!(staged.parent(), target.parent());
            assert!(staged
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains("4242"));
            assert_ne!(staged, target);
        }
    }

    #[test]
    fn parses_mount_point_from_hdiutil_output() {
        // Real `hdiutil attach` output: a table of dev node, type, mount point,
        // separated by tabs. Take the mount point off the /Volumes line.
        let out = "/dev/disk4          \tGUID_partition_scheme          \t\n\
                   /dev/disk4s1        \tApple_APFS                     \t\n\
                   /dev/disk4s2        \tApple_HFS                      \t/Volumes/KlaayGuard\n";
        assert_eq!(parse_hdiutil_mount_point(out), Some("/Volumes/KlaayGuard"));
    }

    #[test]
    fn parses_mount_point_with_a_space_in_the_volume_name() {
        // A leaked prior mount forces this one to " 1"; the name has a space, so
        // splitting on tabs (not spaces) must still return the whole path.
        let out = "/dev/disk5s2        \tApple_HFS                      \t/Volumes/KlaayGuard 1\n";
        assert_eq!(
            parse_hdiutil_mount_point(out),
            Some("/Volumes/KlaayGuard 1")
        );
    }

    #[test]
    fn no_mount_point_when_hdiutil_output_has_no_volume() {
        assert_eq!(parse_hdiutil_mount_point("/dev/disk9\tApple_HFS\t\n"), None);
        assert_eq!(parse_hdiutil_mount_point(""), None);
    }

    #[test]
    fn fallback_window_shown_only_when_tray_unusable() {
        // Tray built and a StatusNotifier host answers: no window.
        assert!(!fallback_window_needed(true, true, false));
        assert!(!fallback_window_needed(true, true, true));
        // Tray failed to build: no UI exists at all, so a window either way.
        assert!(fallback_window_needed(false, true, true));
        assert!(fallback_window_needed(false, false, true));
        assert!(fallback_window_needed(false, true, false));
        // Tray built but nothing shows it (stock GNOME). A signed-out user
        // needs the window to sign in.
        assert!(fallback_window_needed(true, false, false));
        // A signed-in agent needs no UI: a window at every login is noise.
        assert!(!fallback_window_needed(true, false, true));
    }

    #[test]
    fn autostart_entry_launches_the_running_executable() {
        let entry = autostart_entry("/opt/KlaayGuard.AppImage");
        assert!(entry.contains("Exec=\"/opt/KlaayGuard.AppImage\""));
        assert!(entry.contains("Type=Application"));
        assert!(entry.contains("Name=KlaayGuard"));
    }

    #[test]
    fn autostart_exec_field_quotes_and_escapes() {
        // A plain path is still quoted (valid, and simplest).
        assert_eq!(desktop_exec_field("/opt/K.AppImage"), "\"/opt/K.AppImage\"");
        // Spaces stay inside the quotes.
        assert_eq!(
            desktop_exec_field("/home/u/My Apps/K.AppImage"),
            "\"/home/u/My Apps/K.AppImage\""
        );
        // Reserved characters are backslash-escaped inside the quotes.
        assert_eq!(
            desktop_exec_field("/a/$x`y\"z\\w"),
            "\"/a/\\$x\\`y\\\"z\\\\w\""
        );
        // A literal percent must be doubled so it is not read as a field code.
        assert_eq!(desktop_exec_field("/a/50%off"), "\"/a/50%%off\"");
    }

    #[test]
    fn autostart_respects_a_user_disable() {
        assert!(autostart_is_user_disabled(
            "[Desktop Entry]\nX-GNOME-Autostart-enabled=false\n"
        ));
        assert!(autostart_is_user_disabled("[Desktop Entry]\nHidden=true\n"));
        assert!(!autostart_is_user_disabled(
            "[Desktop Entry]\nX-GNOME-Autostart-enabled=true\n"
        ));
        assert!(!autostart_is_user_disabled("[Desktop Entry]\n"));
    }

    #[test]
    fn autostart_exec_prefers_the_appimage_path() {
        // Inside an AppImage, current_exe points at the temporary mount; the
        // APPIMAGE variable holds the real file the user keeps.
        assert_eq!(
            autostart_exec(
                Some("/home/u/Apps/KlaayGuard.AppImage"),
                "/tmp/.mount_x/usr/bin/KlaayGuard"
            ),
            "/home/u/Apps/KlaayGuard.AppImage"
        );
        assert_eq!(
            autostart_exec(None, "/usr/bin/KlaayGuard"),
            "/usr/bin/KlaayGuard"
        );
    }

    #[test]
    fn autostart_path_is_the_xdg_autostart_entry() {
        assert_eq!(
            autostart_path(std::path::Path::new("/home/u/.config")),
            std::path::PathBuf::from("/home/u/.config/autostart/klaayguard.desktop")
        );
        // A relocated XDG_CONFIG_HOME is where the session looks.
        assert_eq!(
            autostart_path(std::path::Path::new("/data/cfg")),
            std::path::PathBuf::from("/data/cfg/autostart/klaayguard.desktop")
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sign_in_notification_uses_notify_send_on_linux() {
        let (program, args) = notification_command("KlaayGuard", "Sign in now.").unwrap();
        assert_eq!(program, "notify-send");
        assert!(args.contains(&"KlaayGuard".to_string()));
        assert!(args.contains(&"Sign in now.".to_string()));
    }

    // The AppImage sets LD_LIBRARY_PATH and the GTK module vars to its own mount.
    // A browser we spawn must not inherit those, or it loads the wrong libraries
    // and never opens. strip_appimage_paths removes only the AppImage entries.
    #[test]
    #[cfg(target_os = "linux")]
    fn strip_appimage_paths_drops_every_mount_entry() {
        let value = "/tmp/.mount_KlaayX/usr/lib:/tmp/.mount_KlaayX/usr/lib/x86_64-linux-gnu";
        assert_eq!(strip_appimage_paths(value, "/tmp/.mount_KlaayX"), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn strip_appimage_paths_keeps_system_entries() {
        let value = "/tmp/.mount_KlaayX/usr/lib:/opt/foo/lib:/usr/lib";
        assert_eq!(
            strip_appimage_paths(value, "/tmp/.mount_KlaayX"),
            Some("/opt/foo/lib:/usr/lib".to_string())
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn strip_appimage_paths_single_mount_file_is_removed() {
        // GDK_PIXBUF_MODULE_FILE is a single path, not a list.
        let value = "/tmp/.mount_KlaayX/usr/lib/gdk-pixbuf/loaders.cache";
        assert_eq!(strip_appimage_paths(value, "/tmp/.mount_KlaayX"), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn strip_appimage_paths_leaves_non_appimage_value_untouched() {
        assert_eq!(
            strip_appimage_paths("/usr/lib", "/tmp/.mount_KlaayX"),
            Some("/usr/lib".to_string())
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn strip_appimage_paths_matches_on_a_path_boundary() {
        // A directory that merely starts with the mount name is not under it.
        assert_eq!(
            strip_appimage_paths("/tmp/.mount_KlaayXtra/lib", "/tmp/.mount_KlaayX"),
            Some("/tmp/.mount_KlaayXtra/lib".to_string())
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn strip_appimage_paths_tolerates_trailing_slash_and_empties() {
        assert_eq!(
            strip_appimage_paths("/tmp/.mount_KlaayX/usr/lib::", "/tmp/.mount_KlaayX/"),
            None
        );
    }

    // `xdg-settings get default-web-browser` returns a desktop-file name.
    #[test]
    #[cfg(target_os = "linux")]
    fn browser_binary_strips_the_desktop_suffix() {
        assert_eq!(
            browser_binary_from_setting("chromium.desktop\n").as_deref(),
            Some("chromium")
        );
        assert_eq!(
            browser_binary_from_setting("  firefox.desktop  ").as_deref(),
            Some("firefox")
        );
        assert_eq!(browser_binary_from_setting(""), None);
        assert_eq!(browser_binary_from_setting("not-a-desktop"), None);
    }

    // Every check-in must carry the device id and the running agent version, so
    // the backend can record which build sent it.
    #[test]
    fn checkin_meta_carries_device_and_agent_version() {
        let m = checkin_meta("device-abc");
        assert_eq!(m["device_uuid"], "device-abc");
        assert_eq!(m["app_version"], env!("CARGO_PKG_VERSION"));
        assert!(!m["app_version"].as_str().unwrap().is_empty());
    }
}
