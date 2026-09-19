#!/usr/bin/env bash
# Verifies build-macos-pkg.sh produces a well-formed installer:
#   - the payload installs KlaayGuard.app into /Applications,
#   - the payload cannot be relocated out of /Applications,
#   - the postinstall script is embedded and executable, and
#   - that postinstall fails the install when no app was placed.
# Uses a tiny fake .app so it runs fast and touches nothing on the real system
# (no `sudo installer`). Full install-time behaviour is covered by the
# --install-agent seam test.
set -euo pipefail

cd "$(dirname "$0")/.."

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# Minimal stand-in app bundle. It carries an Info.plist with the shipped bundle
# id, because that is what makes it a bundle to pkgbuild: `--analyze` lists the
# payload's bundles, and the relocation this test guards is keyed on the
# identifier. A bare .app directory would analyse to nothing.
fake_app="$workdir/KlaayGuard.app"
mkdir -p "$fake_app/Contents/MacOS"
printf '#!/bin/bash\nexit 0\n' > "$fake_app/Contents/MacOS/KlaayGuard"
chmod +x "$fake_app/Contents/MacOS/KlaayGuard"
cat > "$fake_app/Contents/Info.plist" <<'PLIST'
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

out_pkg="$workdir/KlaayGuard-test.pkg"
echo "==> Building test pkg"
# stderr goes to a file so the unsigned-pkg warning stays quiet on a pass, and so
# a build that fails still says why. Under `set -e` a bare call would abort here
# with no message at all.
build_log="$workdir/build.log"
if ! bash scripts/build-macos-pkg.sh "$fake_app" "0.0.0-test" "$out_pkg" 2>"$build_log"; then
  echo "FAIL: build-macos-pkg.sh exited non-zero"
  cat "$build_log"
  exit 1
fi

test -f "$out_pkg" || { echo "FAIL: pkg was not produced"; exit 1; }

echo "==> Expanding pkg"
expanded="$workdir/expanded"
pkgutil --expand "$out_pkg" "$expanded"

component="$expanded/component.pkg"
test -d "$component" || { echo "FAIL: component.pkg not found in product archive"; exit 1; }

# The payload must be pinned to /Applications. pkgbuild writes a <relocate> block
# for a relocatable bundle, and Installer then redirects the app to any other copy
# LaunchServices knows under the same bundle id, so /Applications stays empty.
pkginfo="$component/PackageInfo"
test -f "$pkginfo" || { echo "FAIL: no PackageInfo in component.pkg"; exit 1; }
if grep -q "<relocate>" "$pkginfo"; then
  echo "FAIL: PackageInfo marks the bundle relocatable, so the app can land outside /Applications"
  exit 1
fi

# postinstall must be embedded and executable.
post="$component/Scripts/postinstall"
if [ ! -f "$post" ]; then
  # Scripts payload is a cpio archive named "Scripts"; extract and check.
  scripts_arch="$component/Scripts"
  test -f "$scripts_arch" || { echo "FAIL: no Scripts payload in component.pkg"; exit 1; }
  ( cd "$workdir" && mkdir -p scripts_out && cat "$scripts_arch" | ( cd scripts_out && cpio -id 2>/dev/null ) )
  post="$workdir/scripts_out/postinstall"
fi
test -f "$post" || { echo "FAIL: postinstall not embedded in pkg"; exit 1; }
test -x "$post" || { echo "FAIL: postinstall is not executable"; exit 1; }
grep -q -- "--install-agent" "$post" || { echo "FAIL: postinstall does not invoke the --install-agent seam"; exit 1; }

# Payload must land KlaayGuard.app in /Applications.
payload="$component/Payload"
test -f "$payload" || { echo "FAIL: no Payload in component.pkg"; exit 1; }
if ! ( cd "$workdir" && mkdir -p payload_out && cat "$payload" | ( cd payload_out && cpio -id 2>/dev/null ) ; test -d payload_out/Applications/KlaayGuard.app ); then
  echo "FAIL: payload does not install Applications/KlaayGuard.app"
  exit 1
fi

# An install that placed no app must fail, not report success. main() reads the
# binary under the destination volume in $3 and returns before it touches launchd,
# so this drives the check alone against an empty volume root.
empty_volume="$workdir/empty-volume"
mkdir -p "$empty_volume"
if bash "$post" "" "" "$empty_volume" >/dev/null 2>&1; then
  echo "FAIL: postinstall reported success with no app installed"
  exit 1
fi

echo "PASS: pkg pins /Applications/KlaayGuard.app, embeds an executable postinstall that calls --install-agent, and fails an install that placed no app"
