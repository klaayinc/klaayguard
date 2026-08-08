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
/// Left false until Earthenware echoes `state` in the klaayguard:// redirect; flip to
/// true once that ships to fully close the deep-link confused-deputy. A *mismatch* is
/// rejected regardless of this flag — only a *missing* state is tolerated during rollout.
const AUTH_STATE_STRICT: bool = false;

/// Decide whether the callback's `state` clears the nonce check. A present-but-wrong
/// state is always rejected (a positive attack signal); a missing nonce or missing
/// state is accepted only while `strict` is false (the Earthenware rollout window).
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

/// Turn the /klaayguard/config payload into (logical_id, sql) pairs. An item with an
/// explicit `sql` uses it; otherwise it defaults to `SELECT * FROM <id>`. Statements
/// that aren't a single read-only query are dropped (see `is_read_only_query`).
fn parse_config_queries(cfg: &Value) -> Vec<(String, String)> {
    cfg.get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let id = item.get("id").and_then(|v| v.as_str())?;
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
                    Some((id.to_string(), sql))
                })
                .collect()
        })
        .unwrap_or_default()
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
        .user_agent("klaayguard/0.1")
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
/// echoed back by the Earthenware login redirect — tracked as a separate cross-repo task.
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
            // A failed save means the token lives in memory only and the user
            // signs in again on every launch. Common on Linux without a
            // Secret Service daemon — make it visible instead of silent.
            if let Err(e) = keychain::save_token(&tok) {
                log::error!("keychain: token save failed: {}", e);
                sentry::capture_message(
                    &format!("keychain_token_save_failed: {}", e),
                    Level::Error,
                );
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
        let _ = std::process::Command::new(program).args(args).spawn();
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
    open_earthenware(&app, "/employee-hub");
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
    let queries = parse_config_queries(&cfg_json);

    if queries.is_empty() {
        emit_error_and_focus(
            app,
            state,
            "collection:error",
            json!({ "stage": "config", "reason": "no_tables" }),
        )
        .await;
        return Ok(());
    }

    // 2) osquery
    add_breadcrumb("collection", "osquery_start", Level::Info);
    sentry::capture_message("collection_osquery_start", Level::Info);
    let results = execute_sql_batch(app.clone(), queries).await?;
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
        meta: Some(json!({ "device_uuid": device_serial })),
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
            .user_agent("klaayguard/0.1")
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

/// macOS artifact tags for the current host: (filename infix, friendly-name infix).
/// Returns None on other systems: the installer below mounts a DMG, so a
/// non-macOS host must not download one. Without this gate a Linux or Windows
/// x86_64 host selects the Intel DMG, downloads it, and fails at mount time.
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

fn get_earthenware_url() -> String {
    std::env::var("VITE_EARTHENWARE_URL")
        .ok()
        .or_else(|| option_env!("APP_DEFAULT_EARTHENWARE_URL").map(|s| s.to_string()))
        .unwrap_or_else(|| "https://app.klaay.com".to_string())
}

/// Open the browser to the Earthenware sign-in page; it deep-links back via
/// `klaayguard://auth-callback?token=…`. Invoked from the tray "Sign in" item.
/// Open an Earthenware path in the default browser.
fn open_earthenware(app: &tauri::AppHandle, path: &str) {
    let url = format!("{}{}", get_earthenware_url(), path);
    log::info!("opening url={}", url);
    if let Err(e) = app.opener().open_url(url.clone(), None::<&str>) {
        log::error!("failed to open url {}: {}", url, e);
    }
}

/// Open the Earthenware sign-in page; it deep-links back via klaayguard://. Issues a
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
    open_earthenware(app, &path);
}

/// Handles + assets for keeping the tray in sync with auth state.
struct TrayMenu {
    item: tauri::menu::MenuItem<tauri::Wry>,
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
            // Swap the menubar icon's status dot only when auth state flips.
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
            }
        }
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

        // The manifest returns every macOS build (arm64 + x64); the human-facing
        // `name` does not distinguish them, so match on `original_name` (the real
        // artifact filename) against THIS host's architecture. Picking the wrong
        // arch would install an app the arch-mismatch gate then refuses to launch.
        let Some((arch_tag, arch_label)) = host_arch_tags() else {
            log::info!(
                "ℹ️  Auto-update supports macOS only; skipping on {} {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            return Ok(None);
        };

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

    // Stage the download in a private, process-scoped temp path rather than the
    // world-known ~/Downloads/KlaayGuard-update.dmg. The signature gate in
    // replace_application verifies the *mounted* bundle, so this is defense-in-depth
    // against a local process swapping the file between write and mount (TOCTOU).
    let dmg_path =
        std::env::temp_dir().join(format!("KlaayGuard-update-{}.dmg", std::process::id()));

    log::info!("💾 Downloading to: {:?}", dmg_path);

    // Save the DMG file
    let mut file = std::fs::File::create(&dmg_path).map_err(|e| {
        log::error!("❌ Failed to create update file: {}", e);
        format!("Failed to create update file: {}", e)
    })?;

    let bytes = response.bytes().await.map_err(|e| {
        log::error!("❌ Download error: {}", e);
        format!("Download error: {}", e)
    })?;

    log::info!("📊 Downloaded {} bytes", bytes.len());

    // Verify integrity before we mount and swap a running security agent.
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

async fn replace_application(
    dmg_path: &std::path::Path,
    app: &tauri::AppHandle,
) -> Result<(), String> {
    log::info!("💿 Mounting DMG: {:?}", dmg_path);

    // Mount the DMG
    let mount_output = std::process::Command::new("hdiutil")
        .args(["attach", dmg_path.to_str().unwrap()])
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

    // Extract mount point from hdiutil output
    let mount_output_str = String::from_utf8_lossy(&mount_output.stdout);
    log::info!("📋 hdiutil output: {}", mount_output_str);

    let mount_point = mount_output_str
        .lines()
        .find(|line| line.contains("/Volumes/"))
        .ok_or_else(|| {
            log::error!("❌ Could not find mount point in hdiutil output");
            "Could not find mount point"
        })?
        .split('\t')
        .next_back()
        .ok_or_else(|| {
            log::error!("❌ Could not parse mount point from line");
            "Could not parse mount point"
        })?;

    log::info!("📍 Mount point: {}", mount_point);

    let source_app = std::path::Path::new(mount_point).join("KlaayGuard.app");
    let target_app = std::path::Path::new("/Applications/KlaayGuard.app");

    log::info!("📂 Source app: {:?}", source_app);
    log::info!("📂 Target app: {:?}", target_app);

    // Check if source app exists
    if !source_app.exists() {
        let error_msg = format!("Source app not found at: {:?}", source_app);
        log::error!("❌ {}", error_msg);
        return Err(error_msg);
    }

    // Independent trust anchor: refuse to install anything not signed by Klaay and
    // notarized. This is the gate that turns "the server said so" into a verifiable
    // guarantee. On failure, detach the DMG and abort — the running agent is untouched.
    #[cfg(target_os = "macos")]
    if let Err(e) = verify_klaay_signature(&source_app) {
        log::error!("❌ Update signature verification failed: {}", e);
        sentry::capture_message(&format!("update_signature_rejected:{}", e), Level::Error);
        let _ = std::process::Command::new("hdiutil")
            .args(["detach", mount_point])
            .output();
        return Err(format!("Refusing unverified update: {}", e));
    }

    // Remove old app and copy new one
    if target_app.exists() {
        log::info!("🗑️  Removing old app from: {:?}", target_app);
        std::fs::remove_dir_all(target_app).map_err(|e| {
            log::error!("❌ Failed to remove old app: {}", e);
            format!("Failed to remove old app: {}", e)
        })?;
        log::info!("✅ Old app removed successfully");
    } else {
        log::info!("ℹ️  No existing app found at target location");
    }

    log::info!(
        "📋 Copying new app from {:?} to {:?}",
        source_app,
        target_app
    );
    let copy_result = std::process::Command::new("cp")
        .args([
            "-R",
            source_app.to_str().unwrap(),
            target_app.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| {
            log::error!("❌ Failed to copy new app: {}", e);
            format!("Failed to copy new app: {}", e)
        })?;

    if !copy_result.success() {
        let error_msg = "Failed to copy new app - cp command failed".to_string();
        log::error!("❌ {}", error_msg);
        return Err(error_msg);
    }

    log::info!("✅ New app copied successfully");

    // Unmount the DMG
    log::info!("💿 Unmounting DMG from: {}", mount_point);
    let unmount_result = std::process::Command::new("hdiutil")
        .args(["detach", mount_point])
        .status()
        .map_err(|e| {
            log::error!("❌ Failed to unmount DMG: {}", e);
            format!("Failed to unmount DMG: {}", e)
        })?;

    if !unmount_result.success() {
        log::warn!("⚠️  DMG unmount failed, but continuing...");
    } else {
        log::info!("✅ DMG unmounted successfully");
    }

    // Remove the DMG file
    log::info!("🗑️  Removing temporary DMG file: {:?}", dmg_path);
    if let Err(e) = std::fs::remove_file(dmg_path) {
        log::warn!("⚠️  Failed to remove DMG file: {}", e);
        // Don't fail the whole process for this
    } else {
        log::info!("✅ Temporary DMG file removed");
    }

    log::info!("🎉 Application updated successfully! Restarting...");

    // Restart the application
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
    if let Ok(earthenware) = std::env::var("VITE_EARTHENWARE_URL") {
        add_breadcrumb(
            "startup",
            &format!("endpoints api:{} earthenware:{}", api_base, earthenware),
            Level::Info,
        );
        // naive mismatch hint: localhost vs non-localhost
        let api_is_local = api_base.contains("localhost") || api_base.contains("127.0.0.1");
        let ew_is_local = earthenware.contains("localhost") || earthenware.contains("127.0.0.1");
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
            &format!("endpoints api:{} earthenware:<unset>", api_base),
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
            // Package installs also register it system-wide through the
            // bundler's desktop entry; the AppImage has only this path, since
            // nothing installs its desktop entry for it.
            #[cfg(target_os = "linux")]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                if let Err(e) = app.deep_link().register_all() {
                    log::error!("deep_link register_all failed: {}", e);
                    sentry::capture_message(
                        &format!("deep_link_register_failed: {}", e),
                        Level::Error,
                    );
                }

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

            // Tray menu: live auth/countdown item, an Employee Hub link, and a version
            // line. No quit, no sign-out. Only the auth item updates at runtime.
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
                        "employee_hub" => open_earthenware(app, "/employee-hub"),
                        _ => {}
                    })
                    .icon(if authed { green.clone() } else { red.clone() })
                    .tooltip("KlaayGuard")
                    .menu(&menu)
                    .build(app)?;
                app.manage(TrayMenu {
                    item: item.clone(),
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
        // This is a tray-only background agent. Closing the Linux fallback
        // window destroys the last window, which would otherwise exit the
        // whole app and stop collection. A window-triggered exit carries
        // code None; veto only that. A deliberate app.exit(code) carries
        // Some and still exits normally.
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
              {"id":3,"name":"MacOS (Intel)","original_name":"KlaayGuard_0.1.12_macOS_x64_production.dmg","sha256":"cc"}
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
        assert!(auth_state_ok(false, Some("n"), None)); // old Earthenware: no echo
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

    #[test]
    fn config_queries_use_explicit_sql_or_default_select() {
        let cfg = json!({"data": [
            {"type": "osquery-table", "id": "system_info"},
            {"type": "osquery-table", "id": "users", "sql": "SELECT username FROM users"}
        ]});
        let q = parse_config_queries(&cfg);
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
        assert!(parse_config_queries(&json!({})).is_empty());
        assert!(parse_config_queries(&json!({"data": []})).is_empty());
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
        let q = parse_config_queries(&cfg);
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
}
