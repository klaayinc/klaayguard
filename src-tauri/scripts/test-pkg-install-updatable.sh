#!/bin/bash
# Installs a real .pkg with `sudo installer`, then does what the self-update
# does as the logged-in user: move the bundle aside and delete the old copy.
#
# macOS 15 refuses that move for a root:wheel bundle with "Permission denied".
# macOS 26 allows it, so run this on macOS 15. The control step at the end fails
# the test on a macOS that cannot show the refusal.
#
# It installs into /Applications, so it runs only on a CI runner.
set -euo pipefail

APP="/Applications/KlaayGuard.app"
OLD="/Applications/.KlaayGuard.app.old-test"

[ "${CI:-}" = "true" ] || { echo "FAIL: this test installs into /Applications; it runs only in CI"; exit 1; }
sudo -n true || { echo "FAIL: this test needs passwordless sudo"; exit 1; }
[ ! -e "$APP" ] || { echo "FAIL: $APP already exists; refusing to replace a real install"; exit 1; }

cd "$(dirname "$0")/.."

workdir="$(mktemp -d)"
trap 'sudo rm -rf "$APP" "$OLD"; rm -rf "$workdir"' EXIT

fake="$workdir/KlaayGuard.app"
mkdir -p "$fake/Contents/MacOS"
printf '#!/bin/bash\nexit 0\n' > "$fake/Contents/MacOS/KlaayGuard"
chmod +x "$fake/Contents/MacOS/KlaayGuard"
cat > "$fake/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.klaay.app</string>
    <key>CFBundleName</key>
    <string>KlaayGuard</string>
    <key>CFBundleExecutable</key>
    <string>KlaayGuard</string>
    <key>CFBundleShortVersionString</key>
    <string>0.0.0</string>
    <key>CFBundleVersion</key>
    <string>0.0.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
PLIST

bash scripts/build-macos-pkg.sh "$fake" "0.0.0-test" "$workdir/KlaayGuard-test.pkg"
sudo installer -pkg "$workdir/KlaayGuard-test.pkg" -target /
ls -ld "$APP"

# rename(2), the call the agent makes. `mv` can fall back to a copy.
move() {
  /usr/bin/python3 -c 'import os, sys; os.rename(sys.argv[1], sys.argv[2])' "$1" "$2"
}

echo "==> the logged-in admin moves the installed bundle aside"
move "$APP" "$OLD" || { echo "FAIL: the agent cannot move the installed bundle aside, so it never updates"; exit 1; }

echo "==> the same user deletes the old copy, so none stays behind"
rm -rf "$OLD"
[ ! -e "$OLD" ] || { echo "FAIL: the old copy stays in /Applications"; exit 1; }

echo "==> control: this macOS refuses the move for a root:wheel bundle"
sudo installer -pkg "$workdir/KlaayGuard-test.pkg" -target /
sudo chown -R root:wheel "$APP"
sudo chmod -R go-w "$APP"
if move "$APP" "$OLD" 2>/dev/null; then
  echo "FAIL: this macOS moves a root:wheel bundle, so the test above proves nothing here"
  exit 1
fi

echo "==> the repair commands in docs/FLEET_READINESS.md open that bundle again"
sudo chgrp -R admin "$APP"
sudo chmod -R g+w "$APP"
move "$APP" "$OLD" || { echo "FAIL: the repair commands do not let the agent move the bundle"; exit 1; }
rm -rf "$OLD"
[ ! -e "$OLD" ] || { echo "FAIL: the old copy stays after the repair commands"; exit 1; }

echo "PASS: a .pkg install leaves a bundle the logged-in admin can replace"
