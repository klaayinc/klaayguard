#!/usr/bin/env bash
# Verifies the .pkg postinstall stops the agent it replaces.
#
# `launchctl kickstart -k` cannot do it. The launchd job is `/usr/bin/open`, and
# LaunchServices starts the app as a separate process with no parent link, so
# the kill lands on the wrapper and the old binary keeps running. The wrapper's
# replacement then finds that live instance and reactivates it instead of
# launching the new bundle, so the machine reports from the old build until the
# user logs out.
#
# The script drives `stop_running_agent` directly against fake agents in a temp
# directory. It never touches /Applications, and it never runs the install.
#
# RED (before the seam exists): the grep guard below reports the missing
# function and exits 1. The guard also keeps this test from sourcing a file
# whose top level would run the real install against the real Mac.
set -uo pipefail

cd "$(dirname "$0")/.."

POSTINSTALL="macos/scripts/postinstall"
test -f "$POSTINSTALL" || { echo "FAIL: $POSTINSTALL not found"; exit 1; }

# Both seams must exist before sourcing: `stop_running_agent` is what this test
# exercises, and `main` is what keeps the install body from running when the
# file is sourced.
for fn in stop_running_agent main; do
  if ! grep -q "^${fn}()" "$POSTINSTALL"; then
    echo "FAIL: $POSTINSTALL defines no ${fn}(); the installer cannot stop the old agent"
    exit 1
  fi
done

workdir="$(mktemp -d)"
cleanup() {
  pkill -f "^$workdir/" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

# A real Mach-O binary, not a shell script: the rule under test anchors on the
# executable's own path, and a script's command line starts with its interpreter.
printf '#include <unistd.h>\nint main(void){for(;;)pause();return 0;}\n' > "$workdir/idle.c"
installed="$workdir/Applications/KlaayGuard.app/Contents/MacOS/KlaayGuard"
elsewhere="$workdir/dev/KlaayGuard"
mkdir -p "$(dirname "$installed")" "$(dirname "$elsewhere")"
cc -o "$installed" "$workdir/idle.c" || { echo "FAIL: could not build the fake agent"; exit 1; }
cp "$installed" "$elsewhere"

# shellcheck source=../macos/scripts/postinstall
. "$POSTINSTALL"

alive() { kill -0 "$1" 2>/dev/null; }

"$installed" & installed_pid=$!
"$elsewhere" & elsewhere_pid=$!
sleep 0.5
alive "$installed_pid" || { echo "FAIL: the fake installed agent did not start"; exit 1; }
alive "$elsewhere_pid" || { echo "FAIL: the fake second build did not start"; exit 1; }

echo "==> stop_running_agent must stop the agent at the installed path"
stop_running_agent "$(id -u)" "$installed"

if alive "$installed_pid"; then
  echo "FAIL: the old agent still runs, so the new binary never starts until logout"
  exit 1
fi

# The single-instance lock is per login, and `single_instance.rs` keeps a
# developer build running beside the installed one. An installer that killed by
# process name would take both.
echo "==> a build at another path must survive"
if ! alive "$elsewhere_pid"; then
  echo "FAIL: stop_running_agent killed a build outside the installed bundle"
  exit 1
fi
kill "$elsewhere_pid" 2>/dev/null || true

# Order matters as much as the call. Stopping the agent after the kickstart
# leaves the wrapper attached to the old process again.
echo "==> main must stop the agent before it kickstarts the job"
# Executed lines only. Both words appear in the comments that explain them.
stop_line=$(grep -n "^[[:space:]]*stop_running_agent " "$POSTINSTALL" | head -1 | cut -d: -f1)
kick_line=$(grep -n "^[[:space:]]*[^#].*launchctl kickstart" "$POSTINSTALL" | head -1 | cut -d: -f1)
if [ -z "$stop_line" ]; then
  echo "FAIL: main never calls stop_running_agent"
  exit 1
fi
if [ -n "$kick_line" ] && [ "$stop_line" -gt "$kick_line" ]; then
  echo "FAIL: stop_running_agent (line $stop_line) runs after kickstart (line $kick_line)"
  exit 1
fi

echo "PASS: the installer stops the agent it replaces, spares other builds, and stops it before the kickstart"
