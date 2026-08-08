#!/usr/bin/env bash
# Assert that a KlaayGuard .deb gives a customer a working install.
# Usage: validate-linux-deb.sh <path-to-deb>
set -euo pipefail

DEB="$(realpath "$1")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

failures=0
fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}
pass() {
  echo "  ok: $1"
}

ar x "$DEB"
mkdir -p data control
tar xf data.tar.* -C data
tar xf control.tar.* -C control

DESKTOP="data/usr/share/applications/KlaayGuard.desktop"

# The app binary and the osquery sidecar must be present.
test -f data/usr/bin/KlaayGuard && pass "binary /usr/bin/KlaayGuard" \
  || fail "binary /usr/bin/KlaayGuard is missing"
test -f data/usr/bin/osqueryi && pass "sidecar /usr/bin/osqueryi" \
  || fail "sidecar /usr/bin/osqueryi is missing"

# The desktop entry must exist, be valid, and register the auth scheme.
if test -f "$DESKTOP"; then
  pass "desktop entry present"
  grep -q '^MimeType=.*x-scheme-handler/klaayguard' "$DESKTOP" \
    && pass "MimeType registers klaayguard://" \
    || fail "desktop entry does not register x-scheme-handler/klaayguard; sign-in cannot complete"
  grep -qE '^Exec=.*%U' "$DESKTOP" \
    && pass "Exec passes the URL (%U)" \
    || fail "Exec has no %U field code; the auth callback URL is never delivered"
  if command -v desktop-file-validate >/dev/null; then
    desktop-file-validate "$DESKTOP" && pass "desktop-file-validate" \
      || fail "desktop-file-validate rejected the entry"
  fi
else
  fail "desktop entry $DESKTOP is missing"
fi

# A stray copy outside /usr means a files-mapping path bug.
if find data -name "*.desktop" -not -path "data/usr/*" | grep -q .; then
  fail "a desktop file is installed outside /usr — files mapping path bug"
else
  pass "no desktop file outside /usr"
fi

# The postinstall script must refresh the handler database.
if test -f control/postinst; then
  grep -q update-desktop-database control/postinst \
    && pass "postinst refreshes the desktop database" \
    || fail "postinst does not run update-desktop-database"
else
  fail "control archive has no postinst"
fi

# The package must declare its runtime dependencies.
grep -q '^Depends: ..*' control/control && pass "Depends declared" \
  || fail "control file declares no Depends"

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks passed"
