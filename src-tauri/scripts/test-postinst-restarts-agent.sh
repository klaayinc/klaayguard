#!/usr/bin/env bash
# Verifies the .deb/.rpm postinstall restarts the agent it replaces.
#
# A package install writes the new /usr/bin/KlaayGuard and leaves the old
# process running the old inode. Linux has no supervisor for this agent: the
# XDG autostart entry fires at login and nothing else. Without this step the
# machine reports posture from the previous build until the user logs out.
#
# Stopping alone is not enough either. A security agent that stops at 10:00 and
# returns at the next login leaves the machine unmonitored for the rest of the
# day, so the postinstall must start the new build in the same session.
#
# The script drives `restart_running_agents` directly against fake agents in a
# temp directory. It never touches /usr/bin and it never runs the install.
#
# Root only: the function starts the replacement with `runuser`, which needs
# root, exactly as dpkg runs the postinstall.
#
# RED (before the seam exists): the grep guard below reports the missing
# function and exits 1.
set -uo pipefail

cd "$(dirname "$0")/.."

POSTINST="linux/postinst.sh"
test -f "$POSTINST" || { echo "FAIL: $POSTINST not found"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  echo "FAIL: run this as root; the postinstall runs as root and so must its test"
  exit 1
fi

if ! grep -q "^restart_running_agents()" "$POSTINST"; then
  echo "FAIL: $POSTINST defines no restart_running_agents(); a package install leaves the old agent running"
  exit 1
fi

workdir="$(mktemp -d)"
cleanup() {
  # Unanchored: this must also take the `runuser` wrapper that holds the
  # replacement agent, whose command line starts with runuser, not the path.
  pkill -f "$workdir" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

# A real ELF binary, not a shell script: the rule under test anchors on the
# executable's own path, and a script's command line starts with its interpreter.
printf '#include <unistd.h>\nint main(void){for(;;)pause();return 0;}\n' > "$workdir/idle.c"
installed="$workdir/bin/KlaayGuard"
elsewhere="$workdir/dev/KlaayGuard"
mkdir -p "$(dirname "$installed")" "$(dirname "$elsewhere")"
cc -o "$installed" "$workdir/idle.c" || { echo "FAIL: could not build the fake agent"; exit 1; }
cp "$installed" "$elsewhere"

# Source the functions without running the install. The postinstall sets `-e`
# for dpkg, and sourcing brings that into this shell, where a `pgrep` that
# matches nothing would end the run with no message. Clear it again.
KLAAYGUARD_POSTINST_LIB=1 . "$POSTINST"
set +e

alive() { kill -0 "$1" 2>/dev/null; }

# `runuser` forks the agent, so the replacement appears a moment after the
# function returns. Wait for it rather than read the gap as a failure.
wait_for_agent() {
  n=0
  while [ "$n" -lt 50 ]; do
    pids=$(pgrep -f "^$1$" 2>/dev/null | tr '\n' ' ')
    [ -n "$pids" ] && { echo "$pids"; return 0; }
    sleep 0.1
    n=$((n + 1))
  done
  return 1
}

# A value only the old process carries. The replacement must inherit it, or the
# new agent starts with no session and never reaches the tray.
KLAAYGUARD_TEST_MARK="postinst-restart-probe" DISPLAY=":99" "$installed" &
installed_pid=$!
"$elsewhere" & elsewhere_pid=$!
sleep 0.5
alive "$installed_pid" || { echo "FAIL: the fake installed agent did not start"; exit 1; }
alive "$elsewhere_pid" || { echo "FAIL: the fake second build did not start"; exit 1; }

echo "==> restart_running_agents must stop the old agent"
restart_running_agents "$installed"

if alive "$installed_pid"; then
  echo "FAIL: the old agent still runs, so the new binary never starts until logout"
  exit 1
fi

echo "==> and must start the new one in the same session"
new_pids="$(wait_for_agent "$installed")"
if [ -z "$new_pids" ]; then
  echo "FAIL: no agent runs at $installed; the machine is unmonitored until the next login"
  exit 1
fi
case " $new_pids " in
  *" $installed_pid "*)
    echo "FAIL: the reported agent is the old process $installed_pid"
    exit 1
    ;;
esac

echo "==> the replacement must carry the old session's environment"
new_pid="${new_pids%% *}"
if ! tr '\0' '\n' < "/proc/$new_pid/environ" | grep -qx "DISPLAY=:99"; then
  echo "FAIL: the new agent lost DISPLAY, so it cannot reach the user's session"
  exit 1
fi

# The autostart entry and the single-instance lock are per user, and a
# developer build runs from another path beside the installed one.
echo "==> a build at another path must survive"
if ! alive "$elsewhere_pid"; then
  echo "FAIL: restart_running_agents killed a build outside the installed path"
  exit 1
fi

echo "==> the desktop database refresh must survive"
grep -q update-desktop-database "$POSTINST" \
  || { echo "FAIL: postinst no longer refreshes the desktop database"; exit 1; }

echo "PASS: the package install stops the old agent, starts the new one with the session it had, and spares other builds"
