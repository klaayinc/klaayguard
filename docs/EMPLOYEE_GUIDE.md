# KlaayGuard — guide for employees

You were asked to install KlaayGuard on your computer. This page tells you what
it is, what it can see, and what it cannot see.

## What is KlaayGuard?

KlaayGuard is a small app that runs in your menu bar (on Linux: your system tray). It checks that your
computer meets the company's security rules, and reports the result to Klaay.
That is all it does.

Examples of the rules it checks:

- Is the disk encrypted?
- Is the screen lock turned on?
- Is the operating system up to date?

Companies must prove these things to auditors and customers. KlaayGuard does
that proof for you, so nobody has to inspect your computer by hand.

## What does it see?

Only settings, never content. It reports:

- basic device info: model, memory, serial number;
- operating system version;
- whether the disk is encrypted;
- whether the screen lock is on;
- the list of user accounts on the computer (names only, not their files);
- the list of apps that start at login.

## What does it NOT see?

KlaayGuard cannot see:

- your files, photos, or documents;
- your browser history or bookmarks;
- your email or messages;
- your screen, keyboard, camera, or microphone;
- your location;
- which apps or websites you use.

It is not monitoring software. It cannot watch what you do, and Klaay cannot
turn that on remotely without telling your company first.

## What will I notice?

Almost nothing:

- A small icon in your menu bar or system tray. A green dot means all is
  well. A red dot means you need to sign in. If the icon does not appear on a
  GNOME desktop, install the "AppIndicator and KStatusNotifierItem
  Support" extension. Ubuntu includes it.
- One sign-in in your browser after you install it.
- Nothing else. It has no window and uses almost no battery. On macOS it
  updates itself. On Linux, install new versions when your IT team asks.

## How do I install it on Linux?

Pick the file for your system from the link your IT team sends:

- Ubuntu or Debian: the `.deb` file.
- Fedora or RHEL: the `.rpm` file.
- Arch or another distribution: the `.AppImage` file. Make it executable,
  then run it.

Open the app once after you install it. On that first run the app
registers itself to start at login and to receive the sign-in link.

## What do I need to do?

1. Install the app.
2. Click the menu bar icon and choose **Sign in**.
3. Log in with your work account in the browser.

That is all. The app starts by itself when you log in to your computer.

## Questions?

- For the full technical detail, see the [Overview](./OVERVIEW.md) and the
  [Privacy Datasheet](./PRIVACY_DATASHEET.md).
- Or write to `security@klaay.com`.
