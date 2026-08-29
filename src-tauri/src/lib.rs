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
use sentry::{self, Level};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tauri::{Emitter, Manager};
// removed autostart plugin; using manual LaunchAgent management
use tauri_plugin_opener::OpenerExt;
use tauri_plugin_shell::ShellExt;
// use tauri_plugin_log::LogTarget; // use defaults
use tokio::sync::RwLock;

// Re-introduced minimal osquery commands used by the UI.

/// Shared application state for background operations
pub struct AppState {
    pub auth_token: RwLock<Option<String>>,
    pub api_base_url: RwLock<String>,
    pub last_run_at: RwLock<Option<std::time::Instant>>,
    pub last_attempt_at: RwLock<Option<std::time::Instant>>,
    pub last_focus_at: RwLock<Option<std::time::Instant>>, // debounce for focus-on-failure
    pub pending_auth_state: RwLock<Option<String>>, // single-use nonce for the sign-in round-trip
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

/// Read a query-string value from a klaayguard:// deep link, with the same minimal
/// space-decoding the token parser has always used. Returns None for a non-klaayguard
/// URL or a missing key.
fn deep_link_query_value(url: &str, key: &str) -> Option<String> {
    if !url.starts_with("klaayguard://") {
        return None;
    }
    let qs = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    qs.split('&').find_map(|pair| {
        let mut it = pair.splitn(2, '=');
        match (it.next(), it.next()) {
            (Some(k), Some(v)) if k == key => Some(v.replace("%20", " ").replace('+', " ")),
            _ => None,
        }
    })
}

/// Extract and shape-validate the JWT from a `klaayguard://...?token=...` deep link.
/// Returns None for a non-klaayguard URL, a missing token, or one that isn't three
/// dot-separated segments.
fn parse_deep_link_token(url: &str) -> Option<String> {
    let token = deep_link_query_value(url, "token")?;
    (token.matches('.').count() == 2).then_some(token)
}

/// When true, a sign-in callback MUST carry a `state` that matches the nonce we issued.
/// Left false until Klaay Frontend echoes `state` in the klaayguard:// redirect; flip to
/// true once that ships to fully close the deep-link confused-deputy. A *mismatch* is
/// rejected regardless of this flag — only a *missing* state is tolerated during rollout.
const AUTH_STATE_STRICT: bool = false;

/// Decide whether the callback's `state` clears the nonce check. A present-but-wrong
/// state is always rejected (a positive attack signal); a missing nonce or missing
/// state is accepted only while `strict` is false (the Klaay Frontend rollout window).
fn auth_state_ok(strict: bool, expected: Option<&str>, provided: Option<&str>) -> bool {
    match (expected, provided) {
        (Some(want), Some(got)) => want == got,
        _ => !strict,
    }
}

/// 32 bytes of OS CSPRNG as hex, for the sign-in state nonce. Returns None only if the
/// OS RNG is unavailable (effectively never); callers then skip the nonce rather than
/// panic, degrading to the rollout accept-missing path.
fn generate_auth_nonce() -> Option<String> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).ok()?;
    Some(buf.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Defense-in-depth against a compromised/MITM'd config endpoint: only accept a
/// single read-only osquery statement. osquery can still read arbitrary user-readable
/// files via tables like `file`/`hash`, so this does not make the SQL harmless — but it
/// refuses anything that isn't one plain `SELECT` (or a `WITH …` CTE), blocking stacked
/// statements (`SELECT 1; ATTACH …`) and non-query verbs. A table-level allowlist, owned
/// by the product, is the fuller control and should layer on top of this.
fn is_read_only_query(sql: &str) -> bool {
    let trimmed = sql.trim().trim_end_matches(';').trim();
    // Any remaining ';' means a second statement was stacked on.
    if trimmed.contains(';') {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("select") || lower.starts_with("with")
}

/// Whether a config item's `platform` tag matches this host's OS. Mirrors
/// osquery query-pack semantics: absent / empty / "all" runs everywhere;
/// "posix" runs on linux and macos; any other value must equal the OS string
/// (`std::env::consts::OS`: "linux" / "macos" / "windows"). `os` is a parameter
/// so tests pin every branch without cross-compiling. Backward compatible: an
/// item with no tag always runs, so older configs behave as before.
fn platform_matches(tag: Option<&str>, os: &str) -> bool {
    match tag.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("all") => true,
        Some("posix") => os == "linux" || os == "macos",
        // osquery names macOS "darwin"; Rust's OS string is "macos". Treat both
        // as the same platform so the Klaay API's "darwin" tag matches a macOS host.
        Some("darwin") | Some("macos") => os == "macos",
        Some(other) => other == os,
    }
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
/// `source: "builtin"` (and a `check` name) resolves natively; otherwise it is
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
                    let source = item
                        .get("source")
                        .and_then(|v| v.as_str())
                        .unwrap_or("osquery");
                    if source == "builtin" {
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
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let oct: String = (0..3).filter_map(|_| chars.peek().copied()).collect();
                if oct.len() == 3 && oct.chars().all(|d| ('0'..='7').contains(&d)) {
                    if let Ok(code) = u8::from_str_radix(&oct, 8) {
                        for _ in 0..3 {
                            chars.next();
                        }
                        out.push(code as char);
                        continue;
                    }
                }
            }
            out.push(c);
        }
        out
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

    let root_encrypted = determine("/");
    let home_encrypted = match home {
        Some(h) if !h.is_empty() && h != "/" => determine(h),
        // Home on the root filesystem shares its determination.
        Some(_) => root_encrypted,
        None => "unknown",
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
    let lsblk = std::process::Command::new("lsblk")
        .args([
            "-J",
            "-o",
            "NAME,KNAME,TYPE,FSTYPE,MOUNTPOINT,MOUNTPOINTS,PKNAME",
        ])
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

/// Parse the `[Daemon]` section of kscreenlockerrc: (autolock, timeout minutes).
#[cfg(any(target_os = "linux", test))]
fn parse_kscreenlockerrc(text: &str) -> (Option<bool>, Option<u64>) {
    let mut in_daemon = false;
    let mut autolock = None;
    let mut timeout_min = None;
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
                "timeout" => timeout_min = v.trim().parse::<u64>().ok(),
                _ => {}
            }
        }
    }
    (autolock, timeout_min)
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

/// GNOME screenlock row from the two gsettings values. Lock engages only when
/// it is enabled AND the idle delay is non-zero (delay 0 = never triggers).
#[cfg(any(target_os = "linux", test))]
fn screenlock_row_gnome(lock_enabled: Option<bool>, idle_delay: Option<u64>) -> Value {
    match (lock_enabled, idle_delay) {
        (Some(true), Some(d)) if d > 0 => screenlock_row(
            "gnome",
            "yes",
            Some(d),
            "gsettings",
            &format!("lock-enabled=true, idle-delay={}", d),
        ),
        (Some(true), Some(0)) => screenlock_row(
            "gnome",
            "no",
            Some(0),
            "gsettings",
            "lock enabled but idle-delay=0, so it never triggers",
        ),
        (Some(false), _) => {
            screenlock_row("gnome", "no", idle_delay, "gsettings", "lock-enabled=false")
        }
        _ => screenlock_row(
            "gnome",
            "unknown",
            idle_delay,
            "gsettings",
            "gsettings unavailable",
        ),
    }
}

/// KDE screenlock row from kscreenlockerrc. An absent file/key is unknown.
#[cfg(any(target_os = "linux", test))]
fn screenlock_row_kde(autolock: Option<bool>, timeout_min: Option<u64>) -> Value {
    match autolock {
        Some(true) => screenlock_row(
            "kde",
            "yes",
            timeout_min.map(|m| m * 60),
            "kscreenlockerrc",
            "Autolock=true",
        ),
        Some(false) => screenlock_row(
            "kde",
            "no",
            timeout_min.map(|m| m * 60),
            "kscreenlockerrc",
            "Autolock=false",
        ),
        None => screenlock_row(
            "kde",
            "unknown",
            None,
            "kscreenlockerrc",
            "no kscreenlockerrc Autolock key",
        ),
    }
}

/// Hyprland screenlock row from a hypridle timeout (seconds), or unknown.
#[cfg(any(target_os = "linux", test))]
fn screenlock_row_hyprland(lock_timeout: Option<u64>) -> Value {
    match lock_timeout {
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

/// Collect Linux screen-lock posture (unprivileged) for the current desktop.
#[cfg(target_os = "linux")]
fn collect_screenlock() -> Value {
    match detect_desktop(std::env::var("XDG_CURRENT_DESKTOP").ok().as_deref()) {
        Desktop::Gnome => {
            let lock = std::process::Command::new("gsettings")
                .args(["get", "org.gnome.desktop.screensaver", "lock-enabled"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| parse_gsettings_bool(&s));
            let delay = std::process::Command::new("gsettings")
                .args(["get", "org.gnome.desktop.session", "idle-delay"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| parse_gsettings_uint(&s));
            screenlock_row_gnome(lock, delay)
        }
        Desktop::Kde => {
            let text = dirs::config_dir()
                .map(|c| c.join("kscreenlockerrc"))
                .and_then(|p| std::fs::read_to_string(p).ok())
                .unwrap_or_default();
            let (autolock, timeout_min) = parse_kscreenlockerrc(&text);
            screenlock_row_kde(autolock, timeout_min)
        }
        Desktop::Hyprland => {
            let text = dirs::config_dir()
                .map(|c| c.join("hypr/hypridle.conf"))
                .and_then(|p| std::fs::read_to_string(p).ok())
                .unwrap_or_default();
            screenlock_row_hyprland(parse_hypridle_config(&text))
        }
        Desktop::Unknown => screenlock_row(
            "unknown",
            "unknown",
            None,
            "none",
            "no recognized XDG_CURRENT_DESKTOP",
        ),
    }
}

/// The BitLocker state of one volume as Explorer reads it: the shell property
/// `System.Volume.BitLockerProtection` (PKEY {2d15a9a1-a556-4189-91ad-027458f11a07} 1717).
/// Unlike `Win32_EncryptableVolume`, `manage-bde`, and `Get-BitLockerVolume`,
/// this needs no elevation; it is what draws the padlock in File Explorer.
/// Verified at Medium integrity on Windows 11 22621: an unencrypted drive
/// reads 2.
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
        other => BitLockerProtection::Other(other),
    })
}

/// Windows disk-encryption summary row, in the shape the Linux builtin emits
/// so the backend reads one shape. Only a fully protected volume is "yes":
/// a suspended volume has its key in the clear, and a volume still
/// encrypting is not yet protected. An unreadable property is "unknown",
/// never a false "no".
#[cfg(any(target_os = "windows", test))]
fn windows_disk_encryption_rows(drive: &str, status: Option<BitLockerProtection>) -> Value {
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
        Some(BitLockerProtection::Other(n)) => (
            "unknown",
            "bitlocker",
            format!("unrecognised BitLockerProtection value {}", n),
        ),
        None => (
            "unknown",
            "none",
            "System.Volume.BitLockerProtection not readable".to_string(),
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
#[cfg(target_os = "windows")]
fn read_bitlocker_protection(drive: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let script = format!(
        "(New-Object -ComObject Shell.Application).NameSpace('{}').Self.ExtendedProperty('System.Volume.BitLockerProtection')",
        drive
    );
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Collect Windows disk-encryption posture for the system drive, unprivileged.
#[cfg(target_os = "windows")]
fn collect_disk_encryption_windows() -> Value {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let raw = read_bitlocker_protection(&drive);
    windows_disk_encryption_rows(&drive, parse_bitlocker_protection(raw.as_deref()))
}

/// The three screensaver values one registry key can carry, as raw REG_SZ
/// text. Windows stores them as text, not DWORDs. An absent value stays None
/// so the parser can tell "not set" from "set to zero".
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default, Clone, PartialEq)]
struct ScreenSaverValues {
    active: Option<String>,          // ScreenSaveActive     "1" / "0"
    secure: Option<String>,          // ScreenSaverIsSecure  "1" / "0"
    timeout_seconds: Option<String>, // ScreenSaveTimeOut    seconds as text
}

/// Every screen-lock source on a Windows host, as raw text. The IO wrapper
/// fills it; every decision below is pure and unit-tested on any host.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default, Clone, PartialEq)]
struct WindowsScreenLockInputs {
    /// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    /// InactivityTimeoutSecs: the machine inactivity limit, in seconds.
    inactivity_timeout_secs: Option<String>,
    /// HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop
    machine_policy: ScreenSaverValues,
    /// HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop
    user_policy: ScreenSaverValues,
    /// HKCU\Control Panel\Desktop
    user_preference: ScreenSaverValues,
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
/// applies policy PER VALUE, not per key: a machine policy that sets only
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

/// Windows screenlock row. Decision order:
/// 1. A machine inactivity limit above zero locks the console whatever the
///    screensaver says, so it answers "yes" outright.
/// 2. Otherwise the screensaver must be active, must ask for a password, and
///    must have a non-zero timeout. Any definite failure is "no"; a missing
///    value is "unknown". A definite "no" beats "unknown", so a saver that
///    never asks for a password is reported even when its timeout is unset.
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
    let ranked = [
        ("machine_policy", &inputs.machine_policy),
        ("user_policy", &inputs.user_policy),
        ("user", &inputs.user_preference),
    ];
    let active = first_set(&ranked, |v| v.active.as_deref(), parse_reg_sz_bool);
    let secure = first_set(&ranked, |v| v.secure.as_deref(), parse_reg_sz_bool);
    let timeout = first_set(&ranked, |v| v.timeout_seconds.as_deref(), parse_reg_sz_u64);
    let detail = format!(
        "ScreenSaveActive={}({}) ScreenSaverIsSecure={}({}) ScreenSaveTimeOut={}({})",
        fmt_opt(active.value),
        active.source,
        fmt_opt(secure.value),
        secure.source,
        fmt_opt(timeout.value),
        timeout.source
    );
    // The highest-ranking key that contributed anything names the source.
    let source = [active.source, secure.source, timeout.source]
        .into_iter()
        .min_by_key(|s| match *s {
            "machine_policy" => 0,
            "user_policy" => 1,
            "user" => 2,
            _ => 3,
        })
        .unwrap_or("none");
    if source == "none" {
        return screenlock_row(
            "windows",
            "unknown",
            None,
            "none",
            "no screen-lock policy and no screen saver values found",
        );
    }
    if active.value == Some(false) {
        return screenlock_row("windows", "no", timeout.value, source, &detail);
    }
    if secure.value == Some(false) {
        return screenlock_row("windows", "no", timeout.value, source, &detail);
    }
    if timeout.value == Some(0) {
        // Mirrors the GNOME idle-delay=0 rule: a lock that never triggers is
        // not a lock.
        return screenlock_row("windows", "no", Some(0), source, &detail);
    }
    match (active.value, secure.value, timeout.value) {
        (Some(true), Some(true), Some(t)) => {
            screenlock_row("windows", "yes", Some(t), source, &detail)
        }
        _ => screenlock_row("windows", "unknown", timeout.value, source, &detail),
    }
}

#[cfg(any(target_os = "windows", test))]
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
    }
}

/// Read every screen-lock source from the registry. All four keys are
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
        machine_policy: read_screensaver_values(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop",
        ),
        user_policy: read_screensaver_values(
            HKEY_CURRENT_USER,
            r"Software\Policies\Microsoft\Windows\Control Panel\Desktop",
        ),
        user_preference: read_screensaver_values(HKEY_CURRENT_USER, r"Control Panel\Desktop"),
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

/// Returns true only when the API positively rejects the token (401/403). Network
/// errors, timeouts, or any other status return false ("not definitely invalid") so a
/// transient blip never blocks a legitimate sign-in — the collection loop's own 401
/// handling stays the backstop for a token that later turns out bad.
async fn token_definitely_invalid(base: &str, token: &str) -> bool {
    let client = match reqwest::Client::builder()
        .user_agent(concat!("KlaayGuard/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client
        .get(format!("{}/me", base))
        .bearer_auth(token)
        .send()
        .await
    {
        Ok(resp) => matches!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ),
        Err(_) => false,
    }
}

/// Persist a JWT delivered via a klaayguard:// deep link, but only after the API
/// accepts it. The custom URL scheme is registered system-wide, so any local app or
/// web page can fire `klaayguard://…?token=…`; adopting an unvalidated token would let
/// them silently redirect this device's telemetry onto an account they control. We
/// reject only on a definitive 401/403 (see `token_definitely_invalid`).
///
/// NOTE: this still can't stop an attacker who injects a token for *their own valid*
/// account (a confused-deputy). Closing that fully needs an app-generated `state` nonce
/// echoed back by the Klaay Frontend login redirect — tracked as a separate cross-repo task.
fn handle_deep_link_url(app: &tauri::AppHandle, state: &Arc<AppState>, url: &str) {
    let Some(tok) = parse_deep_link_token(url) else {
        log::info!("deep_link_ignored url={}", url);
        return;
    };
    let provided_state = deep_link_query_value(url, "state");
    log::info!(
        "deep_link_token_parsed length={} has_state={} validating",
        tok.len(),
        provided_state.is_some()
    );

    // Outcome: None = state-nonce check failed, Some(false) = token rejected by API,
    // Some(true) = accepted. The nonce is consumed (single-use) before anything else.
    let outcome = tauri::async_runtime::block_on(async {
        let expected = state.pending_auth_state.write().await.take();
        if !auth_state_ok(
            AUTH_STATE_STRICT,
            expected.as_deref(),
            provided_state.as_deref(),
        ) {
            return None;
        }
        let base = state.api_base_url.read().await.clone();
        if token_definitely_invalid(&base, &tok).await {
            return Some(false);
        }
        *state.auth_token.write().await = Some(tok.clone());
        Some(true)
    });

    match outcome {
        Some(true) => {
            // The keyring is the primary store. Without a Secret Service daemon
            // (common on Linux) the agent falls back to a user-only file so the
            // sign-in still survives a reboot. Tell the user the store is
            // degraded instead of failing silently.
            match keychain::save_token(&tok) {
                Ok(keychain::CredentialStore::Keyring) => {}
                Ok(keychain::CredentialStore::File) => {
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
                Err(e) => {
                    log::error!("keychain: token save failed: {}", e);
                    sentry::capture_message(
                        &format!("keychain_token_save_failed: {}", e),
                        Level::Error,
                    );
                }
            }
            let _ = app.emit("auth:status", json!({ "authenticated": true }));
            add_breadcrumb("auth", "deep_link_token_saved", Level::Info);
            sentry::capture_message("deep_link_token_saved", Level::Info);
        }
        Some(false) => {
            log::warn!("deep_link_token_rejected_by_api length={}", tok.len());
            add_breadcrumb("auth", "deep_link_token_rejected", Level::Warning);
            sentry::capture_message("deep_link_token_rejected", Level::Warning);
            let _ = app.emit("auth:status", json!({ "authenticated": false }));
        }
        None => {
            log::warn!("deep_link_state_check_failed rejecting token");
            add_breadcrumb("auth", "deep_link_state_rejected", Level::Warning);
            sentry::capture_message("deep_link_state_rejected", Level::Warning);
            let _ = app.emit("auth:status", json!({ "authenticated": false }));
        }
    }
}

/// Scan process args for a klaayguard deep link and handle it
fn try_handle_deep_link_from_args(app: &tauri::AppHandle, state: &Arc<AppState>) {
    let args: Vec<String> = std::env::args().collect();
    log::info!(
        "process_args count={} sample_arg1={}",
        args.len(),
        args.get(1).cloned().unwrap_or_default()
    );
    for a in args {
        if a.starts_with("klaayguard://") {
            log::info!("deep_link_found_in_process_args");
            handle_deep_link_url(app, state, &a);
            break;
        }
    }
}

/// Executes a batch of SQL statements against osquery and returns results keyed by logical id
/// The vector contains pairs of (logical_id, sql_to_execute).
async fn execute_sql_batch(
    app: tauri::AppHandle,
    queries: Vec<(String, String)>,
) -> Result<HashMap<String, Value>, String> {
    let mut all_results: HashMap<String, Value> = HashMap::new();

    for (logical_id, sql) in queries {
        let cmd = app
            .shell()
            .sidecar("klaayguard-osqueryi")
            .map_err(|e| format!("klaayguard-osqueryi sidecar unavailable: {}", e))?
            .args(["--json", sql.as_str()]);

        // osquery failing to spawn at all is a systemic problem — surface it.
        let output = cmd.output().await.map_err(|e| e.to_string())?;

        // A single failed or unparseable query must not sink the cycle: record an
        // empty result for it and keep collecting (and sending) the others.
        if !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            // Log it too: Sentry is off in released builds, and a breadcrumb
            // alone leaves a missing table undiagnosable from the log file.
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

        let parsed = String::from_utf8(output.stdout)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
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

async fn invalidate_auth(app: &tauri::AppHandle, state: &Arc<AppState>) -> Result<(), String> {
    // Stop using the token, but DON'T delete it from the keychain: a keychain write
    // pops a second OS prompt on unsigned builds, and the stale token is harmless
    // (overwritten on next sign-in). Just clear it in memory and prompt re-login.
    *state.auth_token.write().await = None;
    log::warn!("Authentication invalidated; notifying user to re-sign-in");
    notify_signin_needed(app, state).await;
    let _ = app.emit("auth:invalidated", ());
    let _ = app.emit("auth:status", json!({ "authenticated": false }));
    add_breadcrumb("auth", "auth_invalidated", Level::Warning);
    sentry::capture_message("auth_invalidated", Level::Warning);
    Ok(())
}

fn focus_debounce_seconds() -> u64 {
    std::env::var("KLAAYGUARD_FAILURE_FOCUS_DEBOUNCE_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60)
}

fn collection_interval_seconds() -> u64 {
    std::env::var("KLAAYGUARD_COLLECTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(900)
}

/// Debounced sign-in nudge: opens the login page in the browser and posts a native
/// notification. Replaces the old "focus the window" nudge now that the app is
/// tray-only. The debounce keeps repeated 401s from spamming browser tabs.
async fn notify_signin_needed(app: &tauri::AppHandle, state: &Arc<AppState>) {
    let now = std::time::Instant::now();
    let debounce = std::time::Duration::from_secs(focus_debounce_seconds());
    let should = match *state.last_focus_at.read().await {
        Some(prev) => now.duration_since(prev) >= debounce,
        None => true,
    };
    if !should {
        return;
    }
    *state.last_focus_at.write().await = Some(now);
    log::warn!("sign-in required; opening login page (debounced)");
    add_breadcrumb("ui", "signin_required_notification", Level::Info);
    open_sign_in(app);
    notify_user("KlaayGuard", "Open KlaayGuard in the menu bar to sign in.");
}

async fn emit_error_and_focus(
    app: &tauri::AppHandle,
    _state: &Arc<AppState>,
    event: &str,
    payload: serde_json::Value,
) {
    // Emit to UI listeners
    let _ = app.emit(event, payload.clone());
    // Report to Sentry as an error-level event with context
    let serialized = payload.to_string();
    // Also log locally to KlaayGuard.log
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
                .filter(|s| !s.is_empty())
        })
        .map(|s| s.to_string())
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
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
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
        let _ = cmd.spawn();
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
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
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

/// A fallback window is needed when the tray cannot serve as the UI: the
/// tray failed to build, or no StatusNotifier host is on the bus to show it
/// (stock GNOME without the AppIndicator extension).
#[cfg(any(target_os = "linux", test))]
fn fallback_window_needed(tray_built: bool, watcher_present: bool) -> bool {
    !tray_built || !watcher_present
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

/// Location of the XDG autostart entry for this user.
#[cfg(any(target_os = "linux", test))]
fn autostart_path(home: &std::path::Path) -> std::path::PathBuf {
    home.join(".config/autostart/klaayguard.desktop")
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
    let home = dirs::home_dir().ok_or("no home directory")?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;

    // Trust the APPIMAGE path only if it is absolute and present; otherwise a
    // stray value would persist an attacker-chosen Exec under our name.
    let appimage = std::env::var("APPIMAGE").ok().filter(|p| {
        let p = std::path::Path::new(p);
        p.is_absolute() && p.exists()
    });
    let entry = autostart_entry(&autostart_exec(appimage.as_deref(), &exe.to_string_lossy()));
    let path = autostart_path(&home);

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

/// Resolve the stable device identity. The first run decides it and stores it
/// in the keychain; every later run returns the stored value.
async fn get_device_identity_internal(app: &tauri::AppHandle) -> Result<String, String> {
    // Fast path, and the rule the tests pin as IdentityDecision::Use.
    match keychain::load_device_identity() {
        Ok(Some(stored)) if !stored.is_empty() => return Ok(stored),
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

    let hardware_serial = match execute_sql_batch(
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

    if let Err(e) = keychain::save_device_identity(&identity) {
        // Report but still return the identity: one collection with an
        // unstored identity beats none.
        log::error!("identity: keychain save failed: {}", e);
        sentry::capture_message(&format!("device_identity_save_failed: {}", e), Level::Error);
    }
    log::info!("identity: device identity {}", source);
    Ok(identity)
}

async fn run_cycle(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    client: &reqwest::Client,
) -> Result<(), String> {
    let token = match state.auth_token.read().await.clone() {
        Some(t) => t,
        None => return Ok(()),
    };

    let base = state.api_base_url.read().await.clone();

    // Mark an attempt start and notify UI listeners
    *state.last_attempt_at.write().await = Some(std::time::Instant::now());
    let _ = app.emit("collection:attempt", ());

    // 1) GET /klaayguard/config
    add_breadcrumb("collection", "config_fetch_start", Level::Info);
    sentry::capture_message("collection_config_fetch_start", Level::Info);
    let is_transient_status = |code: u16| -> bool { code == 429 || (500..=599).contains(&code) };
    let retry_delays = [60u64, 120u64];
    let mut attempt = 0usize;
    let cfg_resp = loop {
        match client
            .get(format!("{}/klaayguard/config", base))
            .bearer_auth(&token)
            .send()
            .await
        {
            Ok(resp) => {
                add_breadcrumb(
                    "collection",
                    &format!("config_status:{}", resp.status().as_u16()),
                    Level::Info,
                );
                if !resp.status().is_success()
                    && is_transient_status(resp.status().as_u16())
                    && attempt < retry_delays.len()
                {
                    let delay = retry_delays[attempt];
                    add_breadcrumb(
                        "collection",
                        &format!("transient_retry_in_s:{}", delay),
                        Level::Warning,
                    );
                    sentry::capture_message("collection_transient_retry", Level::Warning);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    attempt += 1;
                    continue;
                }
                break resp;
            }
            Err(e) => {
                add_breadcrumb(
                    "collection",
                    &format!("config_network_error:{}", e),
                    Level::Warning,
                );
                sentry::capture_message("collection_config_network_error", Level::Warning);
                if attempt < retry_delays.len() {
                    let delay = retry_delays[attempt];
                    add_breadcrumb(
                        "collection",
                        &format!("retry_in_s:{}", delay),
                        Level::Warning,
                    );
                    sentry::capture_message("collection_retry", Level::Warning);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    attempt += 1;
                    continue;
                } else {
                    return Err(e.to_string());
                }
            }
        }
    };

    if cfg_resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || cfg_resp.status() == reqwest::StatusCode::FORBIDDEN
    {
        invalidate_auth(app, state).await?;
        let _ = app.emit(
            "collection:error",
            json!({ "stage": "config", "status": cfg_resp.status().as_u16() }),
        );
        sentry::capture_message("collection_auth_invalidated_on_config", Level::Warning);
        return Ok(());
    }
    if !cfg_resp.status().is_success() {
        emit_error_and_focus(
            app,
            state,
            "collection:error",
            json!({ "stage": "config", "status": cfg_resp.status().as_u16() }),
        )
        .await;
        sentry::capture_message("collection_error_config_non_transient", Level::Warning);
        return Ok(());
    }

    let cfg_json: Value = cfg_resp.json().await.map_err(|e| e.to_string())?;
    let items = parse_config_items(&cfg_json, std::env::consts::OS);

    if items.is_empty() {
        emit_error_and_focus(
            app,
            state,
            "collection:error",
            json!({ "stage": "config", "reason": "no_tables" }),
        )
        .await;
        return Ok(());
    }

    // Split osquery items from native (builtin) ones. osquery runs through the
    // sidecar as before; builtin checks resolve in-process. Both fill the same
    // results map keyed by logical id, so the payload builder is unchanged.
    let mut osquery_queries: Vec<(String, String)> = Vec::new();
    let mut builtin_checks: Vec<(String, String)> = Vec::new();
    for item in items {
        match item {
            CollectionItem::Osquery { id, sql } => osquery_queries.push((id, sql)),
            CollectionItem::Builtin { id, check } => builtin_checks.push((id, check)),
        }
    }

    // 2) osquery
    add_breadcrumb("collection", "osquery_start", Level::Info);
    sentry::capture_message("collection_osquery_start", Level::Info);
    let mut results = if osquery_queries.is_empty() {
        HashMap::new()
    } else {
        execute_sql_batch(app.clone(), osquery_queries).await?
    };
    // 2b) native checks (Linux disk encryption, screen lock).
    for (id, check) in builtin_checks {
        results.insert(id, run_builtin_check(&check));
    }
    *state.last_run_at.write().await = Some(std::time::Instant::now());

    // 3) Build the JSON:API payload from the freshly collected rows
    let collected_at = chrono::Utc::now().to_rfc3339();
    let device_serial = get_device_identity_internal(app)
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

    // 4) POST straight to /klaayguard/data, reusing the transient-retry ladder
    let mut post_attempt = 0usize;
    loop {
        let body_json = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        match client
            .post(format!("{}/klaayguard/data", base))
            .bearer_auth(&token)
            .header(reqwest::header::CONTENT_TYPE, "application/vnd.api+json")
            .header(reqwest::header::ACCEPT, "application/vnd.api+json")
            .body(body_json)
            .send()
            .await
        {
            Ok(resp) => {
                add_breadcrumb(
                    "collection",
                    &format!("post_status:{}", resp.status().as_u16()),
                    Level::Info,
                );
                if resp.status() == reqwest::StatusCode::UNAUTHORIZED
                    || resp.status() == reqwest::StatusCode::FORBIDDEN
                {
                    invalidate_auth(app, state).await?;
                    let _ = app.emit(
                        "collection:error",
                        json!({ "stage": "post", "status": resp.status().as_u16() }),
                    );
                    return Ok(());
                }
                if resp.status().is_success() || resp.status() == reqwest::StatusCode::ACCEPTED {
                    let _ = app.emit("collection:success", json!({ "sent_rows": row_count }));
                    log::info!("collection_success sent_rows={}", row_count);
                    add_breadcrumb(
                        "collection",
                        &format!("success_count:{}", row_count),
                        Level::Info,
                    );
                    return Ok(());
                } else if is_transient_status(resp.status().as_u16())
                    && post_attempt < retry_delays.len()
                {
                    let delay = retry_delays[post_attempt];
                    sentry::capture_message("collection_post_transient_retry", Level::Warning);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    post_attempt += 1;
                    continue;
                } else {
                    emit_error_and_focus(
                        app,
                        state,
                        "collection:error",
                        json!({ "stage": "post", "status": resp.status().as_u16() }),
                    )
                    .await;
                    return Ok(());
                }
            }
            Err(e) => {
                if post_attempt < retry_delays.len() {
                    let delay = retry_delays[post_attempt];
                    sentry::capture_message("collection_post_retry", Level::Warning);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    post_attempt += 1;
                    continue;
                } else {
                    emit_error_and_focus(
                        app,
                        state,
                        "collection:error",
                        json!({ "stage": "post", "error": e.to_string() }),
                    )
                    .await;
                    return Ok(());
                }
            }
        }
    }
}

fn spawn_background_loop(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let client = reqwest::Client::builder()
            .user_agent(concat!("KlaayGuard/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client");

        // wait for token once
        loop {
            if state.auth_token.read().await.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }

        // interval's first tick fires immediately, giving the initial collection.
        // Skip (don't burst) ticks missed while the machine was asleep.
        let mut interval =
            tokio::time::interval(Duration::from_secs(collection_interval_seconds()));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(e) = run_cycle(&app, &state, &client).await {
                log::error!("cycle error: {}", e);
                emit_error_and_focus(
                    &app,
                    &state,
                    "collection:error",
                    json!({ "stage": "internal", "error": e }),
                )
                .await;
            }
        }
    });
}

/// Installs a launch agent for automatic startup on macOS.
///
/// This function creates a launchd plist file in the user's LaunchAgents directory
/// and loads it to ensure the app starts automatically on login. This is a mandatory
/// security feature that cannot be disabled by users.
/// Minimal XML text/attribute escaping for values interpolated into the plist
/// template. Keeps a stray `&`/`<`/`>` (or an injected `</string>…`) in a path or URL
/// from corrupting — or injecting keys into — the generated launchd plist.
#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

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

    // Render plist
    let app_path: String = if installed_exists {
        "/Applications/KlaayGuard.app".to_string()
    } else {
        current_exe
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/Applications/KlaayGuard.app".to_string())
    };
    // Determine API base for env injection in LaunchAgent
    let api_base_for_plist: String = std::env::var("VITE_API_BASE_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_API_BASE_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://api.klaay.com".to_string());

    let log_dir = home_dir.join("Library/Logs/KlaayGuard");
    fs::create_dir_all(&log_dir).map_err(|e| format!("Failed to create log directory: {}", e))?;

    let plist_content = include_str!("../resources/com.klaay.klaayguard.plist")
        .replace("__LABEL__", label)
        .replace("__OPEN_PATH__", "/usr/bin/open")
        .replace("__APP_PATH__", &xml_escape(&app_path))
        .replace("__VITE_API_BASE_URL__", &xml_escape(&api_base_for_plist))
        .replace("__LOG_DIR__", &xml_escape(&log_dir.to_string_lossy()));

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

    if installed_exists {
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
    } else {
        // Not installed under /Applications; skip bootstrap to avoid immediate launch errors in dev.
        // launchd will load the agent at next login.
    }

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
/// macOS artifacts use the short tag ("x64"); Linux ones use the Rust arch
/// string ("x86_64"). Passing std::env::consts::ARCH straight through would
/// never match "Windows_x64" and the agent would stop updating in silence.
/// Only x64 ships today, so any other arch returns None rather than guess.
#[cfg(any(target_os = "windows", test))]
fn windows_arch_tag(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("x64"),
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

/// The file to replace on self-update. Set only when this process runs from
/// an AppImage; deb and rpm installs update through the package manager.
#[cfg(any(target_os = "linux", test))]
fn appimage_update_target(appimage_env: Option<&str>) -> Option<std::path::PathBuf> {
    appimage_env
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
}

/// Where to stage the downloaded AppImage: same directory as the target, so
/// the final rename stays on one filesystem and is atomic.
#[cfg(any(target_os = "linux", test))]
fn staged_appimage_path(target: &std::path::Path, pid: u32) -> std::path::PathBuf {
    let base = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "KlaayGuard.AppImage".to_string());
    target.with_file_name(format!(".{}.update-{}", base, pid))
}

/// macOS artifact tags for the current host: (filename infix, friendly-name infix).
/// Returns None on other systems: the installer below mounts a DMG, so a
/// non-macOS host must not download one. Without this gate a Linux or Windows
/// x86_64 host selects the Intel DMG, downloads it, and fails at mount time.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn host_arch_tags() -> Option<(&'static str, &'static str)> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    match std::env::consts::ARCH {
        "aarch64" => Some(("macOS_arm64", "Apple silicon")),
        "x86_64" => Some(("macOS_x64", "Intel")),
        _ => None,
    }
}

/// Pick the DMG asset matching this host's architecture. Prefers the real
/// artifact filename (`original_name`); falls back to the friendly label only
/// when it is absent. Returns None rather than guess the wrong architecture.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
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
    #[serde(rename = "name")]
    _name: Option<String>,
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
const APPIMAGE_CHILD_ENV_VARS: [&str; 6] = [
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "GTK_PATH",
    "GDK_PIXBUF_MODULE_FILE",
    "GIO_MODULE_DIR",
    "GSETTINGS_SCHEMA_DIR",
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
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("{}: {}", browser, e))
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
            // Do not wait: wl-copy stays resident to serve the clipboard.
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
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("xdg-open: {}", e))
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

/// Open a URL in the user's browser, and make sure the user can find it.
///
/// On Wayland an app cannot raise a window, and a URL opened in an
/// already-running browser lands as a background tab the user may never see. So
/// on Linux: open a new browser window (a focusing compositor raises it), copy
/// the URL to the clipboard, and post a notification (clickable where the daemon
/// supports it) that names the link. Off Linux, use the opener plugin unchanged.
fn open_external_url(app: &tauri::AppHandle, url: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let on_clipboard = copy_to_clipboard(url);
        notify_sign_in_link(url, on_clipboard);
        if open_url_in_browser(url).is_ok() {
            return Ok(());
        }
        log::warn!("browser open failed; falling back to opener plugin");
    }
    app.opener()
        .open_url(url.to_string(), None::<&str>)
        .map_err(|e| e.to_string())
}

/// Open the browser to the Klaay Frontend sign-in page; it deep-links back via
/// `klaayguard://auth-callback?token=…`. Invoked from the tray "Sign in" item.
/// Open a Klaay Frontend path in the default browser.
fn open_frontend(app: &tauri::AppHandle, path: &str) {
    let url = format!("{}{}", get_frontend_url(), path);
    log::info!("opening url={}", url);
    if let Err(e) = open_external_url(app, &url) {
        log::error!("failed to open url {}: {}", url, e);
    }
}

/// Open the Klaay Frontend sign-in page; it deep-links back via klaayguard://. Issues a
/// fresh single-use `state` nonce (stored in AppState) and passes it along so the
/// callback can be bound to a sign-in *this* app initiated. If the OS RNG is somehow
/// unavailable we open without a nonce (rollout accept-missing path) rather than block
/// sign-in entirely.
fn open_sign_in(app: &tauri::AppHandle) {
    let mut path = "/login?app=klaayguard".to_string();
    if let Some(nonce) = generate_auth_nonce() {
        let state = app.state::<Arc<AppState>>().inner().clone();
        tauri::async_runtime::block_on(async {
            *state.pending_auth_state.write().await = Some(nonce.clone());
        });
        path.push_str(&format!("&state={}", nonce));
    }
    open_frontend(app, &path);
}

/// Handles + assets for keeping the tray in sync with auth state.
struct TrayMenu {
    item: tauri::menu::MenuItem<tauri::Wry>,
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
async fn refresh_tray(app: &tauri::AppHandle, state: &Arc<AppState>) {
    let (text, enabled) = if state.auth_token.read().await.is_some() {
        let interval = collection_interval_seconds() as i64;
        let remaining = match *state.last_attempt_at.read().await {
            Some(t) => (interval - t.elapsed().as_secs() as i64).max(0),
            None => 0,
        };
        (fmt_countdown(remaining), false)
    } else {
        ("Sign in".to_string(), true)
    };
    let signed_in = !enabled;
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(tray) = handle.try_state::<TrayMenu>() {
            let _ = tray.item.set_text(&text);
            let _ = tray.item.set_enabled(enabled);
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
/// from the OS credential store, forget any pending sign-in nonce, and refresh
/// the tray. refresh_tray then turns the dot red and removes the "Sign out"
/// item. An explicit sign out deletes the stored token, unlike an invalidated
/// one, so the next start does not reuse it.
async fn sign_out(app: &tauri::AppHandle, state: &Arc<AppState>) {
    *state.auth_token.write().await = None;
    *state.pending_auth_state.write().await = None;
    if let Err(e) = keychain::delete_token() {
        log::warn!("sign out: could not delete stored token: {}", e);
    }
    log::info!("user signed out from the tray");
    let _ = app.emit("auth:status", json!({ "authenticated": false }));
    add_breadcrumb("auth", "user_signed_out", Level::Info);
    refresh_tray(app, state).await;
}

/// Handle a click on the tray "Sign out" item.
fn handle_sign_out_click(app: &tauri::AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<Arc<AppState>>().inner().clone();
        sign_out(&app, &state).await;
    });
}

/// Tick the tray countdown once a second so it's current whenever the menu opens.
fn spawn_tray_clock(app: tauri::AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(1));
        loop {
            iv.tick().await;
            refresh_tray(&app, &state).await;
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

    let client = reqwest::Client::new();

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
            let appimage = std::env::var("APPIMAGE").ok();
            let Some(_target) = appimage_update_target(appimage.as_deref()) else {
                log::info!(
                    "ℹ️  Auto-update on Linux serves AppImage installs only; this is not one"
                );
                return Ok(None);
            };
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
                    "ℹ️  Auto-update on Windows serves x64 builds only; this host is {}",
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
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        let Some((arch_tag, arch_label)) = host_arch_tags() else {
            log::info!(
                "ℹ️  Auto-update supports macOS and Linux AppImage installs; skipping on {} {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            return Ok(None);
        };

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
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

    let client = reqwest::Client::new();

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

    let target = appimage_update_target(std::env::var("APPIMAGE").ok().as_deref())
        .ok_or_else(|| "APPIMAGE not set; not an AppImage install".to_string())?;
    let staged = staged_appimage_path(&target, std::process::id());

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

/// The installer command line for an unattended update. `/S` runs the NSIS
/// installer with no window and no prompt; in silent mode the Tauri template
/// stops the running agent itself instead of asking. `/R` makes the installer
/// start the new agent when it finishes, as the logged-in user. Without `/S`
/// an unattended machine stalls on the "close the app" prompt forever.
#[cfg(any(target_os = "windows", test))]
fn windows_installer_args() -> [&'static str; 2] {
    ["/S", "/R"]
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

    // Do not attach a console. `/S`, not this flag, is what makes the install
    // silent; this only stops a console flashing when the agent itself was
    // started from one.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_hdiutil_mount_point(stdout: &str) -> Option<&str> {
    stdout
        .lines()
        .find(|line| line.contains("/Volumes/"))
        .and_then(|line| line.split('\t').next_back())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Where to stage the downloaded `.app`: the same directory as the target, so
/// the final rename stays on one filesystem and is atomic. Mirrors
/// `staged_appimage_path` for the macOS bundle.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn staged_app_path(target: &std::path::Path, pid: u32) -> std::path::PathBuf {
    let base = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "KlaayGuard.app".to_string());
    target.with_file_name(format!(".{}.update-{}", base, pid))
}

/// Detach a mounted update volume. Tries a graceful detach, then a forced one,
/// so a busy volume still comes down. Runs on every path — success or failure —
/// so a failed update never leaks a `/Volumes/KlaayGuard` mount that forces the
/// next one to mount as `/Volumes/KlaayGuard 1`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
    let staged = staged_app_path(target_app, pid);
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

/// Verify and install the mounted bundle into `/Applications`. Returns without
/// touching the disk on a non-macOS host — this arm only runs on macOS.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn install_from_mount(mount_point: &str) -> Result<(), String> {
    let source_app = std::path::Path::new(mount_point).join("KlaayGuard.app");
    let target_app = std::path::Path::new("/Applications/KlaayGuard.app");

    log::info!("📂 Source app: {:?}", source_app);
    log::info!("📂 Target app: {:?}", target_app);

    if !source_app.exists() {
        return Err(format!("Source app not found at: {:?}", source_app));
    }

    #[cfg(target_os = "macos")]
    {
        stage_verify_and_swap(&source_app, target_app)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = target_app;
        Err("macOS update path invoked on a non-macOS host".to_string())
    }
}

// Called only from the macOS update arm; dead on Linux and Windows.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

    log::info!("🎉 Application updated successfully! Restarting...");
    app.restart();
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
fn update_check_interval_seconds() -> u64 {
    std::env::var("KLAAYGUARD_UPDATE_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(6 * 60 * 60)
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
            }
        }
        Ok(None) => log::info!("✅ No updates available - app is up to date"),
        Err(e) => log::warn!("update check failed: {}", e),
    }
}

/// Check for updates immediately, then on a recurring interval (default 6h), so the
/// always-on agent self-updates in place rather than only at restart.
fn spawn_update_loop(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(update_check_interval_seconds()));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await; // first tick is immediate (startup check)
            let api_base = get_api_base_url();
            log::info!("🚀 Update check against {}", api_base);
            run_update_check(&api_base, &app).await;
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // CLI seam: `--install-agent` registers the launchd LaunchAgent and exits
    // immediately, without entering the Tauri event loop. The macOS .pkg
    // postinstall script invokes this (as the console user) so setup happens at
    // install time instead of relying on the user launching the app manually.
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

    // Prefer runtime env; fall back to compile-time embedded default; then hard-coded prod
    let api_base = std::env::var("VITE_API_BASE_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_API_BASE_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://api.klaay.com".to_string());
    if let Ok(frontend) = std::env::var("VITE_FRONTEND_URL") {
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
    } else {
        add_breadcrumb(
            "startup",
            &format!("endpoints api:{} frontend:<unset>", api_base),
            Level::Info,
        );
    }
    let state = Arc::new(AppState {
        auth_token: RwLock::new(None),
        api_base_url: RwLock::new(api_base),
        last_run_at: RwLock::new(None),
        last_attempt_at: RwLock::new(None),
        last_focus_at: RwLock::new(None),
        pending_auth_state: RwLock::new(None),
    });

    let app = tauri::Builder::default()
        .manage(state.clone())
        .invoke_handler(tauri::generate_handler![
            fallback_sign_in,
            fallback_employee_hub
        ])
        // Single-instance must init first, so a second launch exits before the
        // other plugins spin up. Tauri documents this ordering.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // Handle deep link if present in args (secondary launches)
            let st = app.state::<Arc<AppState>>().inner().clone();
            log::info!(
                "single_instance_args count={} sample_arg0={}",
                args.len(),
                args.first().cloned().unwrap_or_default()
            );
            for a in args {
                if a.starts_with("klaayguard://") {
                    log::info!("single_instance_deep_link_received");
                    handle_deep_link_url(app, &st, &a);
                    break;
                }
            }
            log::info!("single_instance: secondary launch routed to primary instance");
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init())
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

            // Register the klaayguard:// handler for this user at run time.
            // Linux package installs also register it through the desktop
            // entry, and the AppImage has only this path. The Windows
            // installer writes the same keys, but only this path repairs them
            // when another program takes the scheme or the install moves.
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                if let Err(e) = app.deep_link().register_all() {
                    log::error!("deep_link register_all failed: {}", e);
                    sentry::capture_message(
                        &format!("deep_link_register_failed: {}", e),
                        Level::Error,
                    );
                }
            }

            #[cfg(target_os = "linux")]
            {
                // Start at login, like the macOS LaunchAgent. An agent that
                // only runs when a human remembers to launch it leaves gaps
                // the fleet dashboard cannot tell from an offline machine.
                if let Err(e) = install_autostart_entry() {
                    log::error!("autostart install failed: {}", e);
                    sentry::capture_message(
                        &format!("autostart_install_failed: {}", e),
                        Level::Error,
                    );
                }
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
                    let _ = std::process::Command::new("osascript")
                        .args(["-e", &script])
                        .spawn();
                }
                return Ok(());
            }

            // Check if we're already running as a regular process to prevent duplicates
            // Duplicate instance prevention handled by single-instance plugin; remove manual pgrep/exit logic

            // Check for updates on startup AND on a recurring interval, so an
            // always-on agent self-updates in place without waiting for a restart.
            spawn_update_loop(app.handle().clone());

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
            // Load any saved token; if absent, nudge the user to sign in via the tray.
            let state_for_loop = app.state::<Arc<AppState>>().inner().clone();
            let authed = match keychain::load_token() {
                Ok(Some(tok)) => {
                    tauri::async_runtime::block_on(async {
                        *state_for_loop.auth_token.write().await = Some(tok);
                    });
                    true
                }
                Ok(None) => false,
                Err(e) => {
                    // A broken credential store looks like "not signed in" to
                    // the user. Report it so support can tell the two apart.
                    log::error!("keychain: token load failed: {}", e);
                    sentry::capture_message(
                        &format!("keychain_token_load_failed: {}", e),
                        Level::Error,
                    );
                    false
                }
            };
            if authed {
                log::info!("KlaayGuard started - authenticated, collecting in background");
            } else {
                log::info!("KlaayGuard started - sign-in required");
                let st = state_for_loop.clone();
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(
                    async move { notify_signin_needed(&app_handle, &st).await },
                );
            }

            // Handle deep link if app was launched by klaayguard:// URL (first instance)
            try_handle_deep_link_from_args(app.handle(), &state_for_loop);

            // Tray menu: live auth/countdown item, an Employee Hub link, and a
            // version line. "Sign out" is appended below the version only while
            // signed in (see refresh_tray), so it sits at the very bottom, away
            // from the other clickable items. No quit.
            let item = tauri::menu::MenuItem::with_id(
                app,
                "auth_action",
                if authed { "Signed in" } else { "Sign in" },
                !authed,
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
            // Start with "Sign out" present only if already signed in; the
            // last_signed_in state below matches, so refresh_tray keeps it in
            // sync on later flips.
            if authed {
                let _ = menu.append(&sign_out_i);
            }
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
                    .icon(if authed { green.clone() } else { red.clone() })
                    .tooltip("KlaayGuard")
                    .menu(&menu)
                    .build(app)?;
                app.manage(TrayMenu {
                    item: item.clone(),
                    sign_out: sign_out_i.clone(),
                    menu: menu.clone(),
                    tray,
                    green,
                    red,
                    last_signed_in: std::sync::atomic::AtomicBool::new(authed),
                });
                Ok(())
            })();
            if let Err(e) = &tray_built {
                log::error!("tray build failed; continuing without tray: {}", e);
                sentry::capture_message(&format!("tray_build_failed: {}", e), Level::Error);
            }

            // Stock GNOME shows no AppIndicator tray. When the tray cannot
            // be the UI, open a small window so the user can still sign in.
            #[cfg(target_os = "linux")]
            {
                let watcher = status_notifier_watcher_present();
                if fallback_window_needed(tray_built.is_ok(), watcher) {
                    log::warn!(
                        "tray unusable (built={}, watcher={}); opening fallback window",
                        tray_built.is_ok(),
                        watcher
                    );
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
                        sentry::capture_message(
                            &format!("fallback_window_failed: {}", e),
                            Level::Error,
                        );
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            drop(tray_built);
            // Spawn the single collect-and-send loop + the tray countdown clock.
            let state_for_loop = app.state::<Arc<AppState>>().inner().clone();
            let app_handle = app.handle().clone();
            spawn_tray_clock(app_handle.clone(), state_for_loop.clone());
            spawn_background_loop(app_handle, state_for_loop);

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error building tauri application");

    app.run(|_app_handle, event| match event {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        tauri::RunEvent::Opened { urls } => {
            // macOS open-url events deliver here; handle klaayguard:// URLs at runtime
            if !urls.is_empty() {
                let st = _app_handle.state::<Arc<AppState>>().inner().clone();
                for u in urls {
                    let s = u.to_string();
                    log::info!("run_event_opened url={}", s);
                    handle_deep_link_url(_app_handle, &st, &s);
                }
            }
        }
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
    fn windows_arch_tag_maps_only_x64() {
        // Windows artifacts use the short tag while Linux uses the Rust arch
        // string. Passing ARCH straight through never matches, and the agent
        // stops updating in silence.
        assert_eq!(windows_arch_tag("x86_64"), Some("x64"));
        assert_eq!(windows_arch_tag("aarch64"), None);
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

    #[test]
    fn deep_link_token_extracted_and_shape_validated() {
        assert_eq!(
            parse_deep_link_token("klaayguard://auth-callback?token=aaa.bbb.ccc"),
            Some("aaa.bbb.ccc".to_string())
        );
        // token among other params
        assert_eq!(
            parse_deep_link_token("klaayguard://x?foo=1&token=aaa.bbb.ccc&bar=2"),
            Some("aaa.bbb.ccc".to_string())
        );
    }

    #[test]
    fn deep_link_token_rejected_when_invalid() {
        assert_eq!(
            parse_deep_link_token("https://evil?token=aaa.bbb.ccc"),
            None
        ); // wrong scheme
        assert_eq!(parse_deep_link_token("klaayguard://x?foo=1"), None); // no token
        assert_eq!(
            parse_deep_link_token("klaayguard://x?token=not-a-jwt"),
            None
        ); // wrong shape
    }

    #[test]
    fn deep_link_state_param_extracted() {
        assert_eq!(
            deep_link_query_value(
                "klaayguard://auth-callback?token=a.b.c&state=deadbeef",
                "state"
            ),
            Some("deadbeef".to_string())
        );
        assert_eq!(
            deep_link_query_value("klaayguard://auth-callback?token=a.b.c", "state"),
            None
        );
        assert_eq!(deep_link_query_value("https://evil?state=x", "state"), None);
    }

    #[test]
    fn auth_state_rollout_semantics() {
        // Rollout (strict=false): missing state OR missing nonce is tolerated...
        assert!(auth_state_ok(false, Some("n"), None)); // old Klaay Frontend: no echo
        assert!(auth_state_ok(false, None, None)); // no pending nonce
        assert!(auth_state_ok(false, None, Some("x"))); // unsolicited-ish, tolerated in rollout
                                                        // ...but a present-and-matching state always passes...
        assert!(auth_state_ok(false, Some("n"), Some("n")));
        // ...and a present-but-WRONG state is always rejected, even in rollout.
        assert!(!auth_state_ok(false, Some("n"), Some("bad")));
    }

    #[test]
    fn auth_state_strict_requires_matching_nonce() {
        assert!(auth_state_ok(true, Some("n"), Some("n")));
        assert!(!auth_state_ok(true, Some("n"), None)); // missing echo now rejected
        assert!(!auth_state_ok(true, None, Some("x"))); // unsolicited rejected
        assert!(!auth_state_ok(true, Some("n"), Some("bad")));
    }

    #[test]
    fn auth_nonce_is_64_hex_chars_and_fresh() {
        let a = generate_auth_nonce().expect("rng");
        let b = generate_auth_nonce().expect("rng");
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[cfg(target_os = "macos")]
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
    fn config_items_dispatch_builtin_source() {
        let cfg = json!({"data": [
            {"id": "disk_encryption", "platform": "linux", "source": "builtin", "check": "disk_encryption"},
            {"id": "broken", "source": "builtin"},
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
        let rows = build_disk_encryption_rows(Some(lsblk), "", Some("/home"));
        let s = summary(&rows);
        assert_eq!(s["root_encrypted"], "yes");
        // Home is on the same crypt device, matched via its mountpoints list.
        assert_eq!(s["home_encrypted"], "yes");
        assert_eq!(s["mechanisms"], json!(["luks"]));
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
        assert_eq!(detect_desktop(Some("XFCE")), Desktop::Unknown);
        assert_eq!(detect_desktop(None), Desktop::Unknown);
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
            screenlock_row_gnome(Some(true), Some(300))[0]["enabled"],
            "yes"
        );
        // Enabled but idle-delay 0 never triggers.
        assert_eq!(
            screenlock_row_gnome(Some(true), Some(0))[0]["enabled"],
            "no"
        );
        assert_eq!(
            screenlock_row_gnome(Some(false), Some(300))[0]["enabled"],
            "no"
        );
        // Missing gsettings -> unknown, never a false "no".
        assert_eq!(screenlock_row_gnome(None, None)[0]["enabled"], "unknown");
    }

    fn saver(active: &str, secure: &str, timeout: &str) -> ScreenSaverValues {
        ScreenSaverValues {
            active: Some(active.to_string()),
            secure: Some(secure.to_string()),
            timeout_seconds: Some(timeout.to_string()),
        }
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
        assert_eq!(windows_screenlock_row(&inputs)[0]["enabled"], "no");
    }

    #[test]
    fn windows_screenlock_no_when_the_timeout_is_zero() {
        // Mirrors the GNOME idle-delay=0 rule: a lock that never triggers is
        // not a lock.
        let inputs = WindowsScreenLockInputs {
            user_preference: saver("1", "1", "0"),
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["enabled"], "no");
        assert_eq!(row[0]["delay_seconds"], 0);
    }

    #[test]
    fn windows_screenlock_machine_policy_overrides_the_user() {
        // Group policy wins. Reporting the user value tells the dashboard a
        // managed fleet is unlocked.
        let inputs = WindowsScreenLockInputs {
            machine_policy: saver("1", "1", "300"),
            user_preference: saver("0", "0", "0"),
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 300);
        assert_eq!(row[0]["source"], "machine_policy");
    }

    #[test]
    fn windows_screenlock_merges_policy_and_user_values() {
        // Windows applies policy per value, not per key. A first-key-wins
        // rule reports "unknown" on the most common managed setup.
        let inputs = WindowsScreenLockInputs {
            machine_policy: ScreenSaverValues {
                secure: Some("1".into()),
                ..Default::default()
            },
            user_preference: ScreenSaverValues {
                active: Some("1".into()),
                timeout_seconds: Some("600".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let row = windows_screenlock_row(&inputs);
        assert_eq!(row[0]["enabled"], "yes");
        assert_eq!(row[0]["delay_seconds"], 600);
        assert_eq!(row[0]["source"], "machine_policy");
        let detail = row[0]["detail"].as_str().unwrap();
        assert!(detail.contains("ScreenSaverIsSecure=true(machine_policy)"));
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
        assert_eq!(parse_bitlocker_protection(Some("")), None);
        assert_eq!(parse_bitlocker_protection(None), None);
    }

    #[test]
    fn windows_disk_encryption_only_a_protected_volume_is_yes() {
        // A suspended volume has its key in the clear and an encrypting one
        // is not yet protected. Reporting either as "yes" tells the
        // dashboard a laptop is safe to lose when it is not.
        let yes = |s| windows_disk_encryption_rows("C:", Some(s))[1]["root_encrypted"] == "yes";
        assert!(yes(BitLockerProtection::On));
        assert!(yes(BitLockerProtection::Locked));
        assert!(!yes(BitLockerProtection::Off));
        assert!(!yes(BitLockerProtection::Suspended));
        assert!(!yes(BitLockerProtection::Encrypting));
        assert!(!yes(BitLockerProtection::Decrypting));
    }

    #[test]
    fn windows_disk_encryption_unknown_when_the_property_is_unreadable() {
        // Unknown and no are different answers on the dashboard.
        let rows = windows_disk_encryption_rows("C:", None);
        assert_eq!(rows[1]["root_encrypted"], "unknown");
        assert_eq!(rows[0]["source"], "shell_property");
        assert_eq!(
            windows_disk_encryption_rows("C:", Some(BitLockerProtection::Other(42)))[1]
                ["root_encrypted"],
            "unknown"
        );
    }

    #[test]
    fn windows_disk_encryption_uses_the_linux_summary_shape() {
        // kiln's encryption_status_from_rows reads root_encrypted off the
        // summary row; the Windows builtin must emit the same shape.
        let rows = windows_disk_encryption_rows("C:", Some(BitLockerProtection::On));
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
        assert_eq!(timeout, Some(5));
        // Missing file/keys -> unknown enabled.
        assert_eq!(screenlock_row_kde(None, None)[0]["enabled"], "unknown");
        assert_eq!(
            screenlock_row_kde(Some(true), Some(5))[0]["delay_seconds"],
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
    fn appimage_update_needs_the_appimage_env() {
        // deb and rpm installs must not self-replace; only an AppImage run
        // (APPIMAGE env set) may.
        assert_eq!(
            appimage_update_target(Some("/home/u/Apps/KlaayGuard.AppImage")),
            Some(std::path::PathBuf::from("/home/u/Apps/KlaayGuard.AppImage"))
        );
        assert_eq!(appimage_update_target(Some("")), None);
        assert_eq!(appimage_update_target(None), None);
    }

    #[test]
    fn staged_appimage_lands_next_to_the_target() {
        // The staged file must share the target directory so the final
        // rename stays on one filesystem and is atomic.
        let staged = staged_appimage_path(
            std::path::Path::new("/home/u/Apps/KlaayGuard.AppImage"),
            4242,
        );
        assert_eq!(staged.parent(), Some(std::path::Path::new("/home/u/Apps")));
        assert!(staged
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("4242"));
        assert_ne!(
            staged,
            std::path::PathBuf::from("/home/u/Apps/KlaayGuard.AppImage")
        );
    }

    #[test]
    fn staged_app_lands_next_to_the_target() {
        // The staged bundle must share the target directory so the final rename
        // stays on one filesystem and is atomic.
        let staged = staged_app_path(std::path::Path::new("/Applications/KlaayGuard.app"), 4242);
        assert_eq!(staged.parent(), Some(std::path::Path::new("/Applications")));
        assert!(staged
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("4242"));
        assert_ne!(
            staged,
            std::path::PathBuf::from("/Applications/KlaayGuard.app")
        );
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
        assert!(!fallback_window_needed(true, true));
        // Tray failed to build: window.
        assert!(fallback_window_needed(false, true));
        // Tray built but nothing shows it (stock GNOME): window.
        assert!(fallback_window_needed(true, false));
        assert!(fallback_window_needed(false, false));
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
            autostart_path(std::path::Path::new("/home/u")),
            std::path::PathBuf::from("/home/u/.config/autostart/klaayguard.desktop")
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
