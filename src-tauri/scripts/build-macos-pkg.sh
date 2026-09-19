#!/usr/bin/env bash
# Builds a macOS .pkg installer around a pre-built KlaayGuard.app.
#
# Tauri's bundler does not emit .pkg, so we wrap the .app with Apple's native
# pkgbuild/productbuild. The pkg carries a postinstall script that registers the
# launchd LaunchAgent at install time (see macos/scripts/postinstall).
#
# Signs the installer when INSTALLER_SIGNING_IDENTITY is set (a "Developer ID
# Installer" identity — distinct from the "Developer ID Application" identity
# used to codesign the .app). Without it, an UNSIGNED pkg is produced, which is
# fine for local structural testing but not for distribution.
#
# Usage: build-macos-pkg.sh <path-to-KlaayGuard.app> <version> <output.pkg>
set -euo pipefail

APP_PATH="${1:?path to KlaayGuard.app required}"
VERSION="${2:?version required}"
OUT_PKG="${3:?output pkg path required}"

IDENTIFIER="com.klaay.klaayguard"
SCRIPTS_DIR="$(cd "$(dirname "$0")/../macos/scripts" && pwd)"

test -d "$APP_PATH" || { echo "app not found: $APP_PATH" >&2; exit 1; }
test -x "$SCRIPTS_DIR/postinstall" || { echo "postinstall missing or not executable in $SCRIPTS_DIR" >&2; exit 1; }

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

root="$workdir/root"
mkdir -p "$root/Applications"
cp -R "$APP_PATH" "$root/Applications/"

# pkgbuild marks a bundle payload relocatable by default. Installer then asks
# LaunchServices for any bundle carrying com.klaay.app and writes the app over
# that one instead — a mounted DMG, a copy in the Trash, or a developer build —
# leaving /Applications empty while the installer still reports success. Take
# the analysed plist so the other keys keep pkgbuild's own defaults, and turn
# that one off.
component_plist="$workdir/component.plist"
pkgbuild --analyze --root "$root" "$component_plist"
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$component_plist"

component_pkg="$workdir/component.pkg"
pkgbuild \
  --root "$root" \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  --install-location "/" \
  --component-plist "$component_plist" \
  --scripts "$SCRIPTS_DIR" \
  "$component_pkg"

dist="$workdir/distribution.xml"
cat > "$dist" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>KlaayGuard</title>
    <options customize="never" require-scripts="true" hostArchitectures="arm64,x86_64"/>
    <choices-outline>
        <line choice="default"><line choice="$IDENTIFIER"/></line>
    </choices-outline>
    <choice id="default"/>
    <choice id="$IDENTIFIER" visible="false">
        <pkg-ref id="$IDENTIFIER"/>
    </choice>
    <pkg-ref id="$IDENTIFIER" version="$VERSION" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
XML

if [ -n "${INSTALLER_SIGNING_IDENTITY:-}" ]; then
  productbuild --distribution "$dist" --package-path "$workdir" \
    --sign "$INSTALLER_SIGNING_IDENTITY" "$OUT_PKG"
else
  echo "WARNING: INSTALLER_SIGNING_IDENTITY unset — producing UNSIGNED pkg" >&2
  productbuild --distribution "$dist" --package-path "$workdir" "$OUT_PKG"
fi

echo "Built $OUT_PKG"
