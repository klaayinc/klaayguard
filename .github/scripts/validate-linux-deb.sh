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
# The sidecar must NOT sit at /usr/bin/osqueryi: the official osquery
# package owns that path, and dpkg aborts the install on the collision.
test -f data/usr/bin/klaayguard-osqueryi && pass "sidecar /usr/bin/klaayguard-osqueryi" \
  || fail "sidecar /usr/bin/klaayguard-osqueryi is missing"
if test -f data/usr/bin/osqueryi; then
  fail "sidecar occupies /usr/bin/osqueryi, which the osquery package owns"
else
  pass "no collision with the osquery package"
fi

# The Linux sidecar must be stripped; debug info is 263 MB of dead weight
# in every package.
if file data/usr/bin/klaayguard-osqueryi 2>/dev/null | grep -q "not stripped"; then
  fail "sidecar ships unstripped with debug info"
else
  pass "sidecar is stripped"
fi

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
  else
    echo "  WARN: desktop-file-validate not installed; skipping that check" >&2
  fi
else
  fail "desktop entry $DESKTOP is missing"
fi

# A stray copy outside /usr means a files-mapping path bug.
# Capture into a variable rather than `find | grep -q`: grep -q exits on the
# first match, find then dies with SIGPIPE, and pipefail would flip this check
# to a false pass — the exact bug class this script exists to catch.
STRAY_DESKTOP="$(find data -name "*.desktop" -not -path "data/usr/*")"
if [ -n "$STRAY_DESKTOP" ]; then
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

# The tray library is dlopen'd, not linked, so ldd cannot police it. The
# package must pull it in, and must accept the ayatana successor that
# Ubuntu 24.04 ships instead of libappindicator3-1.
grep -q 'libayatana-appindicator3-1' control/control \
  && pass "Depends covers libayatana-appindicator" \
  || fail "Depends does not cover libayatana-appindicator3-1; the tray (the only UI) dies on Ubuntu 24.04"

# Customer-visible metadata must not be template placeholders.
grep -q '^Maintainer: you$' control/control \
  && fail "Maintainer is the template placeholder 'you'" \
  || pass "Maintainer is set"
grep -q '^Description: A Tauri App$' control/control \
  && fail "Description is the template placeholder 'A Tauri App'" \
  || pass "Description is set"
grep -qE '^Categories=.+' "$DESKTOP" \
  && pass "desktop Categories set" \
  || fail "desktop entry has empty Categories"

# The agent must use rustls only. A bundled or assumed OpenSSL is a frozen
# TLS stack in the AppImage and an undeclared dependency in the deb.
if objdump -p data/usr/bin/KlaayGuard | grep -qE 'NEEDED.*(libssl|libcrypto)'; then
  fail "binary links OpenSSL; TLS must come from rustls"
else
  pass "no OpenSSL link"
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks passed"
