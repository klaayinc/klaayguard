#!/usr/bin/env bash
# Check the package-repository files a production .deb or .rpm ships (PROD-7007).
# Usage: check-package-repo-files.sh <dir>   (<dir> = the package's
#        /usr/share/klaay-guard/package-repo, extracted)
#
# validate-linux-deb.sh and validate-linux-rpm.sh both call this, so the two
# formats are held to the same rules: the production source lines, both
# signature checks, skip_if_unavailable, and the key that the repository is
# really signed with. Prints "  ok:" / "FAIL:" lines; exits 1 on any failure.
set -uo pipefail

DIR="$1"
SHIPPED_KEY="$(cd "$(dirname "$0")/../.." && pwd)/src-tauri/linux/package-repo/klaay.asc"
failures=0
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }
pass() { echo "  ok: $1"; }

for f in klaay.asc klaay.gpg klaay.list klaay.repo; do
  test -s "$DIR/$f" && pass "ships package-repo/$f" || fail "production build is missing package-repo/$f"
done

grep -qx 'deb \[arch=amd64 signed-by=/usr/share/keyrings/klaay.gpg\] https://pkg.klaay.com/apt stable main' \
  "$DIR/klaay.list" 2>/dev/null \
  && pass "apt source points at pkg.klaay.com with signed-by" \
  || fail "klaay.list is not the production apt source line"

repo_ok=1
for line in 'baseurl=https://pkg.klaay.com/rpm/' 'gpgcheck=1' 'repo_gpgcheck=1' 'skip_if_unavailable=1' \
  'gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-klaay'; do
  grep -qx "$line" "$DIR/klaay.repo" 2>/dev/null || { repo_ok=0; fail "klaay.repo lacks '$line'"; }
done
[ "$repo_ok" = 1 ] && pass "rpm repository points at pkg.klaay.com, checks both signatures, never blocks dnf"

# The binary key apt reads, the armoured one rpm reads, and the key the
# repository is signed with must all be one key, or a family of machines
# rejects every update.
if command -v gpg >/dev/null; then
  fpr() { gpg --batch --with-colons --show-keys "$1" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}'; }
  asc=$(fpr "$DIR/klaay.asc"); bin=$(fpr "$DIR/klaay.gpg"); want=$(fpr "$SHIPPED_KEY")
  if [ -n "$asc" ] && [ "$asc" = "$bin" ] && [ "$asc" = "$want" ]; then
    pass "klaay.asc and klaay.gpg are the repository key ($asc)"
  else
    fail "keys differ: klaay.asc ${asc:-none}, klaay.gpg ${bin:-none}, repository key ${want:-none}"
  fi
else
  fail "gpg is missing; cannot check the shipped keys"
fi

[ "$failures" -eq 0 ]
