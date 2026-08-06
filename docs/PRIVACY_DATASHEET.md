# KlaayGuard Privacy Datasheet

**Product:** KlaayGuard desktop agent
**Version of this document:** 2026-08-06
**Audience:** Customer security and privacy reviewers (incl. BYOD deployments)

## 1. Overview

KlaayGuard is a lightweight desktop agent that collects a narrow set of security-posture telemetry from a workstation and reports it to the Klaay platform every 15 minutes. It is built on [osquery](https://osquery.io), an open-source endpoint instrumentation tool originally developed at Facebook and now widely used in enterprise security programs.

KlaayGuard's purpose is limited to verifying that workstations meeting Klaay-managed controls (e.g., disk encryption enabled, screen lock configured, OS patch level current) actually meet them. It is not an EDR/DLP product, and it is not designed for general endpoint surveillance.

## 2. Data Collected and Transmitted to Klaay

The agent runs only the queries the Klaay server instructs it to. The current production query set is the complete list below. Any change to this set requires a server-side configuration change and would be communicated to customers in advance.

| Query | Fields returned | Purpose | Control mapping |
|---|---|---|---|
| `system_info` | Hostname, CPU model, physical/virtual memory, hardware UUID/serial | Device inventory | System inventory (CTRL-033) |
| `os_version` | OS name, version, major/minor/patch, build, platform, architecture | Patch-level verification | Security patches (CTRL-084) |
| `users` | Local account username, UID, GID, home directory, shell, description, password-status flags, password last-changed and expiry dates | Local-account inventory | Access controls (CTRL-033) |
| `startup_items` | Login items / launch agents: name, path, args, type, status | Detect persistence and unauthorized auto-start software | Endpoint integrity (CTRL-152) |
| `disk_encryption` | Per-volume name, encrypted flag, encryption type (FileVault / BitLocker / LUKS), encryption status | Verify data-at-rest encryption | Data at rest (CTRL-165), BYOD (CTRL-098) |
| `screenlock` | Screen-lock enabled flag, grace period (macOS) | Verify auto screen lock | Auto screen lock (CTRL-097) |
| `preferences` (scoped) | Two specific macOS keys only: `askForPassword` and `askForPasswordDelay` under `com.apple.screensaver` | Verify screensaver password requirement | Auto screen lock (CTRL-097) |

No password values, hashes, or password contents of any kind are collected — only metadata flags such as "password set", "last changed date", and "expires date" exposed by the operating system.

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

Several of these are available as osquery tables, and KlaayGuard's source repository contains them as commented-out entries in the server config to document explicitly that they are not in use. They cannot be enabled silently — enabling any of them is a server-side configuration change that the Klaay team would communicate to the customer in advance.

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
- **Linux:** no startup entry is installed. The user or administrator starts the agent.
- **Windows:** no Windows build is currently distributed.

The agent runs as the logged-in user, not as root/Administrator, and therefore can only see what that user can see.

## 5. Local Storage

- The agent keeps **no local database**. Collected rows go directly from osquery to the Klaay API and are not buffered on disk.
- The only data stored locally are:
  - the authentication token, in the operating system's secure credential store;
  - the agent's own log files, in the user's log directory.

## 6. Network Transmission

- All transmission is over **HTTPS** to `https://api.klaay.com`.
- Authentication is via short-lived JWT bearer tokens; the agent's auth token is stored in the operating system's secure credential store (macOS Keychain, Windows Credential Manager, or libsecret on Linux).
- Sign-in is performed once at first launch in the user's default browser at `https://app.klaay.com`; the browser returns a token to the agent through the `klaayguard://` URL scheme.
- The agent uploads collected rows in batches every **15 minutes**. There is no real-time streaming and no peer-to-peer or third-party data flow.
- Optional crash and error telemetry is sent to Sentry only if a Sentry DSN is configured by Klaay; this stream contains application stack traces and version metadata, not collected osquery data.

## 7. Updates

KlaayGuard updates are distributed as signed installers. Updates do not change the data-collection scope on their own — the data scope is governed by the server-side configuration documented in §2.

## 8. BYOD Considerations

KlaayGuard is suitable for personal-device deployment because the data scope is restricted to security posture, not user activity. Two items worth highlighting to end users on personal devices:

- The `users` query enumerates **all local user accounts** on the device (usernames, UIDs, home directory paths). It does not access those accounts' files or activity. On a single-user personal device this is typically a non-issue; on a shared family device, other account names will appear in the inventory.
- The agent runs only while the user it is installed under is logged in. It has no visibility into other macOS user profiles on the same machine.

Customers preferring stricter isolation may install KlaayGuard inside a dedicated work-purpose macOS user profile rather than the user's primary profile. This is supported but is generally not necessary given the limited data scope.

## 9. Source and Verification

The data-collection scope described above is defined in the server-side controller `app/controllers/klaayguard/config_controller.rb` in the Klaay platform. Customers under NDA may request a code-level walkthrough or attestation.

## 10. Contact

For questions about this datasheet or to request changes for a specific deployment, contact your Klaay account representative or `security@klaay.com`.
