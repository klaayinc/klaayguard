#!/usr/bin/env bash
# Assert that the KlaayGuard .rpm carries the same maintainer scripts as the .deb.
#
# The rpm ships `linux/postinst.sh` and `linux/postrm.sh` too, and those scripts
# branch on rpm's own argument forms: 0 for an erase, 1 for an upgrade. Nothing
# else in the repository builds an rpm, so without this check that branch could
# rot unnoticed while the deb stayed green.
#
# Usage: validate-linux-rpm.sh <path-to-rpm>
set -euo pipefail

RPM="$(realpath "$1")"
failures=0
fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}
pass() { echo "  ok: $1"; }

command -v rpm >/dev/null || { echo "FAIL: the 'rpm' tool is missing; cannot read the scriptlets" >&2; exit 1; }

SCRIPTS="$(rpm -qp --scripts "$RPM" 2>/dev/null)"
test -n "$SCRIPTS" || fail "the package carries no scriptlets at all"

# The install side must restart the agent it replaced.
grep -q restart_running_agents <<<"$SCRIPTS" \
  && pass "postinstall restarts the agent it replaces" \
  || fail "postinstall does not restart the running agent; an upgrade keeps the old build alive until logout"

# The removal side must stop the agent whose binary it deleted.
grep -q stop_running_agents <<<"$SCRIPTS" \
  && pass "postuninstall stops the agent it deletes" \
  || fail "postuninstall does not stop the running agent; an erase leaves it running on a deleted binary"

# rpm passes 0 for the last erase and 1 for an upgrade. The removal path must
# read that, or an upgrade would stop the agent the postinstall just restarted.
grep -qE 'remove \| purge \| 0' <<<"$SCRIPTS" \
  && pass "the removal path reads rpm's erase argument" \
  || fail "the removal path does not distinguish rpm's erase (0) from its upgrade (1)"

# Before the rename the package was called klaay. Obsoletes is what makes
# `rpm -U` and dnf remove it while they install this one.
grep -qx 'klaay' <<<"$(rpm -qp --obsoletes "$RPM" 2>/dev/null)" \
  && pass "obsoletes the pre-rename klaay package" \
  || fail "the rpm does not obsolete klaay; the pre-rename package stays installed"

# The binary and the sidecar must be in the payload, as they are in the deb.
FILES="$(rpm -qpl "$RPM" 2>/dev/null)"
grep -qx '/usr/bin/KlaayGuard' <<<"$FILES" \
  && pass "binary /usr/bin/KlaayGuard" \
  || fail "binary /usr/bin/KlaayGuard is missing"
grep -qx '/usr/bin/klaayguard-osqueryi' <<<"$FILES" \
  && pass "sidecar /usr/bin/klaayguard-osqueryi" \
  || fail "sidecar /usr/bin/klaayguard-osqueryi is missing"

# Package repository (PROD-7007). The postinstall treats missing repository
# files as "this build is not production" and removes the machine from the
# repository, so a production rpm built without them would take every rpm
# install off it at the next upgrade. EXPECT_PACKAGE_REPO=1 for the production
# build, 0 for every other; unset skips the file checks.
grep -q register_package_repo <<<"$SCRIPTS" \
  && pass "postinstall registers the package repository" \
  || fail "postinstall has no register_package_repo step; .rpm installs never update"
grep -q remove_package_repo <<<"$SCRIPTS" \
  && pass "postuninstall removes the package repository" \
  || fail "postuninstall has no remove_package_repo step; an erase leaves Klaay's repository behind"
case "${EXPECT_PACKAGE_REPO:-}" in
  1)
    for f in klaay.asc klaay.gpg klaay.list klaay.repo; do
      grep -qx "/usr/share/klaay-guard/package-repo/$f" <<<"$FILES" \
        && pass "ships package-repo/$f" \
        || fail "production build is missing package-repo/$f"
    done
    ;;
  0)
    grep -q '^/usr/share/klaay-guard/package-repo' <<<"$FILES" \
      && fail "a non-production build ships the package repository; it would join the production repository" \
      || pass "non-production build ships no package repository"
    ;;
esac

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks passed"
