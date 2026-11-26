#!/usr/bin/env bash
# Verifies the .pkg postinstall leaves the bundle replaceable by the admin who
# runs the agent.
#
# The installer runs as root, so the bundle lands owned by root:wheel. The agent
# runs as the logged-in user and swaps the bundle by rename (stage_verify_and_swap
# in lib.rs). macOS 15 refuses that rename with "Permission denied" for a bundle
# the user cannot write. test-pkg-install-updatable.sh proves it on a real
# install.
#
# The script drives `make_bundle_updatable` against a fake bundle in a temp
# directory. It never touches /Applications and never runs the install.
set -uo pipefail

cd "$(dirname "$0")/.."

POSTINSTALL="macos/scripts/postinstall"
test -f "$POSTINSTALL" || { echo "FAIL: $POSTINSTALL not found"; exit 1; }

for fn in make_bundle_updatable main; do
  if ! grep -q "^${fn}()" "$POSTINSTALL"; then
    echo "FAIL: $POSTINSTALL defines no ${fn}(); the installed bundle stays root-only and the agent cannot replace it"
    exit 1
  fi
done

workdir="$(mktemp -d)" || { echo "FAIL: mktemp -d failed; refusing to run with an empty workdir"; exit 1; }
trap 'rm -rf "$workdir"' EXIT

# shellcheck source=../macos/scripts/postinstall
. "$POSTINSTALL"

me="$(id -un)"

# A bundle shaped like ours: nested directories, a binary, a symlink.
new_bundle() {
  local app="$1"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  printf 'x' > "$app/Contents/MacOS/KlaayGuard"
  chmod 755 "$app/Contents/MacOS/KlaayGuard"
  printf 'x' > "$app/Contents/Info.plist"
  ln -s Info.plist "$app/Contents/link"
  chmod -R go-w "$app"
}

group_of() { /usr/bin/stat -f %Sg "$1"; }
mode_of() { /usr/bin/stat -f %Sp "$1"; }
owner_of() { /usr/bin/stat -f %Su "$1"; }

echo "==> the bundle gets the admin group, and every entry becomes group-writable"
app="$workdir/one/KlaayGuard.app"
new_bundle "$app"
make_bundle_updatable "$app" "" || { echo "FAIL: make_bundle_updatable failed on a good bundle"; exit 1; }
for path in "$app" "$app/Contents" "$app/Contents/MacOS" "$app/Contents/MacOS/KlaayGuard" "$app/Contents/Info.plist"; do
  [ "$(group_of "$path")" = "admin" ] || { echo "FAIL: $path has group $(group_of "$path"), not admin"; exit 1; }
  case "$(mode_of "$path")" in
    ?????w????*) ;;
    *) echo "FAIL: $path is $(mode_of "$path"), not group-writable"; exit 1 ;;
  esac
done

echo "==> the owner becomes the named user"
app="$workdir/two/KlaayGuard.app"
new_bundle "$app"
make_bundle_updatable "$app" "$me" || { echo "FAIL: make_bundle_updatable failed with a user"; exit 1; }
[ "$(owner_of "$app")" = "$me" ] || { echo "FAIL: the bundle owner is $(owner_of "$app"), not $me"; exit 1; }
[ "$(owner_of "$app/Contents/MacOS/KlaayGuard")" = "$me" ] || { echo "FAIL: a nested file kept another owner"; exit 1; }

echo "==> a standard (non-admin) user gets no owner change: /Applications stops their rename anyway, and ownership would only open the agent files to them"
app="$workdir/four/KlaayGuard.app"
new_bundle "$app"
before=$(owner_of "$app")
standard_user="nobody"
if /usr/sbin/dseditgroup -o checkmember -m "$standard_user" admin >/dev/null 2>&1; then
  echo "FAIL: $standard_user is an admin on this Mac; the test needs a standard user"
  exit 1
fi
make_bundle_updatable "$app" "$standard_user" || { echo "FAIL: make_bundle_updatable failed for a standard user"; exit 1; }
[ "$(owner_of "$app")" = "$before" ] || { echo "FAIL: the owner changed to $(owner_of "$app") for a standard user"; exit 1; }
[ "$(group_of "$app")" = "admin" ] || { echo "FAIL: the group did not change for a standard user"; exit 1; }

echo "==> root as the named user changes no owner, and the group still opens"
app="$workdir/three/KlaayGuard.app"
new_bundle "$app"
before=$(owner_of "$app")
make_bundle_updatable "$app" "root" || { echo "FAIL: make_bundle_updatable failed for root"; exit 1; }
[ "$(owner_of "$app")" = "$before" ] || { echo "FAIL: the owner changed for root"; exit 1; }
[ "$(group_of "$app")" = "admin" ] || { echo "FAIL: the group did not change for root"; exit 1; }

echo "==> a missing bundle returns non-zero"
if make_bundle_updatable "$workdir/none/KlaayGuard.app" "$me" 2>/dev/null; then
  echo "FAIL: make_bundle_updatable reported success for a missing bundle"
  exit 1
fi

echo "==> main must call it before the console-user early exit, so an MDM install with no user still gets the group"
call_line=$(grep -n '^[[:space:]]*make_bundle_updatable ' "$POSTINSTALL" | head -1 | cut -d: -f1)
exit_line=$(grep -n 'log "postinstall: no console user' "$POSTINSTALL" | head -1 | cut -d: -f1)
[ -n "$call_line" ] || { echo "FAIL: main never calls make_bundle_updatable"; exit 1; }
[ "$call_line" -lt "$exit_line" ] || { echo "FAIL: the call (line $call_line) comes after the no-console-user exit (line $exit_line)"; exit 1; }

echo "PASS: the installed bundle is replaceable by the admin who runs the agent"
