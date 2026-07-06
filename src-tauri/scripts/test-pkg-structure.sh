#!/usr/bin/env bash
# Verifies build-macos-pkg.sh produces a well-formed installer:
#   - the payload installs KlaayGuard.app into /Applications, and
#   - the postinstall script is embedded and executable.
# Uses a tiny fake .app so it runs fast and touches nothing on the real system
# (no `sudo installer`). Full install-time behaviour is covered by the
# --install-agent seam test.
set -euo pipefail

cd "$(dirname "$0")/.."

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# Minimal stand-in app bundle.
fake_app="$workdir/KlaayGuard.app"
mkdir -p "$fake_app/Contents/MacOS"
printf '#!/bin/bash\nexit 0\n' > "$fake_app/Contents/MacOS/KlaayGuard"
chmod +x "$fake_app/Contents/MacOS/KlaayGuard"

out_pkg="$workdir/KlaayGuard-test.pkg"
echo "==> Building test pkg"
bash scripts/build-macos-pkg.sh "$fake_app" "0.0.0-test" "$out_pkg" 2>/dev/null

test -f "$out_pkg" || { echo "FAIL: pkg was not produced"; exit 1; }

echo "==> Expanding pkg"
expanded="$workdir/expanded"
pkgutil --expand "$out_pkg" "$expanded"

component="$expanded/component.pkg"
test -d "$component" || { echo "FAIL: component.pkg not found in product archive"; exit 1; }

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

echo "PASS: pkg installs /Applications/KlaayGuard.app and embeds an executable postinstall that calls --install-agent"
