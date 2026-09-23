# KlaayGuard Privacy Datasheet

**Product:** KlaayGuard desktop agent
**Version of this document:** 2026-09-11
**Audience:** Customer security and privacy reviewers (incl. BYOD deployments)

## 1. Overview

KlaayGuard is a lightweight desktop agent that collects a narrow set of security-posture telemetry from a workstation and reports it to the Klaay platform every 15 minutes. KlaayGuard is built on [osquery](https://osquery.io), an open-source endpoint instrumentation tool originally developed at Facebook and now widely used in enterprise security programs.

KlaayGuard's purpose is limited to verifying that workstations that must meet controls (disk encryption enabled, screen lock configured, OS patch level current) actually meet them. It is not an EDR or DLP product, and it is not designed for general endpoint surveillance.

The Klaay server, not the agent, defines the query set; the set below is the current production set. The agent enforces one hard limit on every query it runs, described in §9.

## 2. Data Collected and Transmitted to Klaay

The agent runs only the queries the Klaay server instructs it to. The current production query set is the complete list below. Any change to this set requires a server-side configuration change and Klaay tells customers in advance.

| Query | Fields returned | Purpose | Control mapping |
|---|---|---|---|
| `system_info` | Hostname, CPU model, physical/virtual memory, hardware UUID/serial | Device inventory | System inventory (CTRL-033) |
| `os_version` | OS name, version, major/minor/patch, build, platform, architecture | Patch-level verification | Security patches (CTRL-084) |
| `users` | Local account username, UID, GID, home directory, shell, description | Local-account inventory | Access controls (CTRL-033) |
| `startup_items` | Login items / launch agents: name, path, args, type, status | Detect persistence and unauthorized auto-start software | Endpoint integrity (CTRL-152) |
| `disk_encryption` | Per-volume name, encrypted flag, encryption type (FileVault / BitLocker / LUKS), encryption status | Verify data-at-rest encryption | Data at rest (CTRL-165), BYOD (CTRL-098) |
| `screenlock` | Screen-lock enabled flag and delay. macOS: grace period. Linux: the desktop's own lock setting. Windows: `InactivityTimeoutSecs` under the machine policy key; `ScreenSaveActive`, `ScreenSaverIsSecure`, `ScreenSaveTimeOut` under the machine policy, user policy, and `HKEY_CURRENT_USER\Control Panel\Desktop` keys; and, on the active power scheme, whether waking asks for a password, after how long the machine sleeps, after how long the display turns off, and whether the machine has a battery (the "require a password on wakeup", "put the computer to sleep", and "turn off the display" settings, each on mains and on battery) | Verify auto screen lock | Auto screen lock (CTRL-097) |
| `disk_encryption` (Windows) | System drive only: the BitLocker protection state File Explorer shows (`System.Volume.BitLockerProtection`), reduced to encrypted yes / no / unknown | Verify data-at-rest encryption without elevation | Data at rest (CTRL-165) |
| `bitlocker_info` (Windows only) | Per-volume drive letter, protection status, conversion status, encryption method. Readable only when the agent runs elevated; a standard install sends no rows | Raw evidence behind the `disk_encryption` verdict | Data at rest (CTRL-165) |
| `windows_security_center` (Windows only) | Windows Security Center verdicts: firewall, antivirus, antispyware, automatic updates, user account control, internet settings, security center service | Verify firewall, antivirus, and update posture | Antivirus (CTRL-152), Endpoint (CTRL-151), Security patches (CTRL-084) |
| `windows_security_products` (Windows only) | Each registered security product: name, type, state, state timestamp, signatures-up-to-date flag | Verify antivirus and firewall products are on and current | Antivirus (CTRL-152) |
| `patches` (Windows only) | Installed hotfix ID, description, install date | Patch-level verification | Security patches (CTRL-084) |
| `password_policy` (Windows only) | The local account policy from `NetUserModalsGet`: minimum password length, maximum and minimum password age, password history size, lockout threshold, lockout duration and window | Verify password and lockout configuration | Password configuration (CTRL-103) |
| `screenlock_registry` (Windows only) | The raw `ScreenSaveActive`, `ScreenSaverIsSecure`, and `ScreenSaveTimeOut` values under `HKEY_CURRENT_USER\Control Panel\Desktop` | Raw evidence behind the `screenlock` verdict | Auto screen lock (CTRL-097) |
| `preferences` (scoped) | Two specific macOS keys only: `askForPassword` and `askForPasswordDelay` under `com.apple.screensaver` | Verify screensaver password requirement | Auto screen lock (CTRL-097) |

No password values, hashes, or password contents of any kind are collected. On Windows the `password_policy` row carries the local policy (lengths, ages, lockout counts), never a password.

## 3. Data Explicitly NOT Collected

KlaayGuard does **not** collect any of the following:

- Browser history, bookmarks, cookies, or saved credentials
- File contents, file listings, or directory contents
- Keystrokes, clipboard contents, or input events
- Screen captures or screen recordings
- Microphone, camera, or any media input
- Geolocation
- Running-process names, command-line arguments, or process metadata
- Network connections, listening ports, DNS queries, or ARP tables
- Installed application inventory (deb/rpm/msi packages)
- USB or PCI device inventory
- Logged-in user history or login session records
- Email, chat, or any application content

Several of these are available as osquery tables, but the query set does not include them. They cannot be enabled silently. The server must request a query, and the agent's read-only gate (§9) still applies to every request. Klaay tells customers in advance of any change to its hosted query set.

## 4. OS Permissions Required

KlaayGuard does **not** request:

- Full Disk Access
- Accessibility
- Screen Recording
- Microphone, Camera, or Input Monitoring
- Kernel or system extensions
- MDM enrollment or device management profiles

What it does install:

- **macOS:** a user-level LaunchAgent at `~/Library/LaunchAgents/com.klaay.klaayguard.plist` so the agent runs in the user's session at login. This is per-user, not system-wide. The application bundle includes its own copy of osquery; no separate osquery installation is performed and operation does not require admin.
- **Linux:** the app writes a per-user autostart entry at `~/.config/autostart/klaayguard.desktop` on its first start. It honours a user who disables that entry.
- **Windows:** the installer writes one `Run` value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, so the agent starts at logon. The value is per-user. The installer needs no administrator rights and installs no service and no driver.

The agent runs as the logged-in user, not as root/Administrator, and therefore can only see what that user can see.

## 5. Local Storage

- The agent keeps **no local database**. Collected rows go directly from osquery to the Klaay API and are not buffered on disk.
- The only data stored locally are:
  - the authentication token, in the operating system's secure credential store. On a Linux desktop that runs no secret service, the agent stores the token in a file readable only by the user, and tells the user so;
  - the agent's own log files, in the user's log directory.

## 6. Network Transmission

- All transmission is over **HTTPS** to `https://api.klaay.com`.
- Authentication uses expiring JWT bearer tokens; the agent's token is valid for three months and is stored in the operating system's secure credential store (macOS Keychain, Windows Credential Manager, or the Linux secret service).
- Sign-in happens once, at first start, in the user's default browser at `https://app.klaay.com`. The browser hands the agent a one-time code on a local loopback address (`127.0.0.1`); the agent exchanges that code, plus a secret that never leaves the agent process, for its token. The token never travels through a URL, and no other program on the machine can spend the code (RFC 8252, RFC 7636).
- The agent uploads collected rows in batches every **15 minutes**. There is no real-time streaming and no peer-to-peer or third-party data flow.
- Optional crash and error telemetry is sent to Sentry only if a Sentry DSN is configured by Klaay; this stream contains application stack traces and version metadata, not collected osquery data.

## 7. Updates

Klaay signs and notarizes the macOS installers. Klaay does not sign the Linux packages or the Windows installer yet; on those platforms the agent accepts an update only when its SHA-256 hash matches the release record. Updates do not change the data-collection scope on their own. The server-side configuration in §2 governs the data scope.

## 8. BYOD Considerations

KlaayGuard is suitable for personal-device deployment because the data scope is restricted to security posture, not user activity. Three items worth highlighting to end users on personal devices:

- The `users` query enumerates **all local user accounts** on the device (usernames, UIDs, home directory paths). It does not access those accounts' files or activity. On a single-user personal device this is typically a non-issue; on a shared family device, other account names will appear in the inventory.
- The agent runs only while the user it is installed under is logged in. It has no visibility into other user profiles on the same machine.
- A person can work in more than one Klaay workspace. The device reports to the workspace the person picks when they sign the agent in. Klaay can also turn on reporting to every workspace, which is off by default. Klaay then also records the device in each workspace where the person is a current employee. It leaves out a workspace where the person only audits or has the read-only role. A sign-in that asks for no workspace keeps reporting this way until it expires. Each workspace that receives the device sees the inventory and posture in §2.

Customers preferring stricter isolation may install KlaayGuard inside a dedicated work-purpose macOS user profile rather than the user's primary profile. This is supported but is generally not necessary given the limited data scope.

## 9. Source and Verification

The Klaay server defines the query set. The agent enforces one hard limit that the server cannot cross: it runs a query only if it is a single read-only statement. You can read this gate in the agent source at [`src-tauri/src/lib.rs`](../src-tauri/src/lib.rs) (`is_read_only_query`). The gate accepts one plain `SELECT` or one `WITH … ` common table expression, and refuses stacked statements and every non-query verb.

The query set in §2 is the current production set. Klaay customers under NDA may request a code-level walkthrough or attestation.

## 10. Contact

For questions about this datasheet or to request changes for a specific deployment, contact your Klaay account representative or `security@klaay.com`.
