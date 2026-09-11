# What is KlaayGuard?

**Product:** KlaayGuard desktop agent
**Version of this document:** 2026-08-28
**Audience:** Anyone who wants the full picture of what the agent does. For a
short, non-technical version, see the [Employee Guide](./EMPLOYEE_GUIDE.md).

KlaayGuard is free software under GPL-3.0-or-later. It is the client for the
Klaay platform.

## 1. Summary

KlaayGuard is a small background application for work computers. It checks the
security posture of the computer and reports the result to the Klaay platform.
Klaay uses these reports to show that company controls are met. Examples of
these controls are disk encryption and screen lock.

KlaayGuard is not antivirus software. It is not monitoring software. It does not
watch what you do. It does not block, change, or remove anything on the
computer. It only reads a short, fixed list of settings and sends them to Klaay.

For the exact list of collected data, see the
[Privacy Datasheet](./PRIVACY_DATASHEET.md).

## 2. What the application does

KlaayGuard has one main function and a small set of support functions.

### 2.1 Main function: collect and report

Every 15 minutes, the agent completes this cycle:

1. It asks the Klaay server which checks to run.
2. It runs the checks with [osquery](https://osquery.io), an open-source tool
   that reads system settings. KlaayGuard includes its own copy of osquery.
3. It sends the results to `https://api.klaay.com` over HTTPS.

The server defines the checks. The agent refuses any instruction that is not a
read-only query. It keeps no local database. Results go directly from the
computer to Klaay.

### 2.2 Support functions

These functions exist only to keep the agent itself signed in, current, and
running:

- **Sign-in.** The agent opens the Klaay login page in your browser. After
  login, the browser sends a one-time code to a port the agent listens on, at
  `127.0.0.1`. The agent exchanges that code for a token, with a secret that
  the browser never sees. The agent stores the token in the operating system
  credential store: macOS Keychain, Windows Credential Manager, or the Linux
  secret service.
- **Menu bar icon.** The agent shows a small icon in the menu bar. A green dot
  means signed in. A red dot means signed out. The menu names the signed-in
  person, and shows the time until the next report and a link to the Klaay
  Employee Hub. There is no other user interface and no window.
- **Sign-in reminders.** If the agent is signed out, it opens the login page
  and shows one system notification. It repeats this at most once per minute.
- **Automatic updates.** Every 6 hours, the agent asks Klaay for a new
  version. Before it installs an update, it checks that the file hash
  matches the release record. On macOS it also checks that Apple notarized
  the file and that Klaay signed it. If any check fails, the agent keeps the
  current version. The Linux `.deb` and `.rpm` installs update through the
  package manager instead.
- **Start at login.** The installer registers the agent so that it starts
  when you log in. On macOS the system restarts the agent if it stops. On
  Windows a registry entry starts it at each logon. On Linux the app writes
  an autostart entry at its first start. This keeps posture reports
  continuous.
- **Logs.** The agent writes its own status messages to log files in your
  user folder. It can send crash reports to Sentry when Klaay turns that on.
  Crash reports contain no collected posture data.

## 3. What the application does not do

KlaayGuard does **not**:

- read files, browser history, messages, or email;
- record the screen, keyboard, camera, or microphone;
- track location;
- list your running programs or network connections;
- change any setting on the computer;
- run with administrator rights — it runs as the logged-in user.

The [Privacy Datasheet](./PRIVACY_DATASHEET.md) gives the full list, and lists
the OS permissions that the agent does not request.

## 4. Where data goes

- Posture reports go to the Klaay API (`https://api.klaay.com`) over HTTPS.
- Sign-in uses the Klaay Frontend (`https://app.klaay.com`).
- Crash reports go to Sentry, when Klaay turns that on.
- No other party receives data.

## 5. Installation

Klaay distributes installers from the
[GitHub releases page](https://github.com/klaayinc/klaayguard/releases).
You can also build the agent from source. See the [README](../README.md).
The macOS installers are signed and notarized. The Linux packages and the
Windows installer are not signed yet.
macOS installs use a `.pkg` or `.dmg` file. Linux installs use a `.deb`
(Ubuntu, Debian), an `.rpm` (Fedora, RHEL), or an `.AppImage` (any
distribution). Windows installs use an `.exe` installer, x64 only.

Platform differences on Linux:

- The AppImage updates itself. The .deb and .rpm installs do not; install
  each new version through the package manager.
- On a plain GNOME desktop the tray icon needs the "AppIndicator and
  KStatusNotifierItem Support" extension. Ubuntu includes it.

Platform differences on Windows:

- The installer needs no administrator rights.
- Windows shows a SmartScreen warning at the first run, because Klaay does
  not sign the installer yet. Choose **More info**, then **Run anyway**.

## 6. Questions

Contact your Klaay account representative or `security@klaay.com`.
