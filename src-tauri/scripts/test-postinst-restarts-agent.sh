#!/usr/bin/env bash
# Verifies the .deb/.rpm maintainer scripts hand the machine over correctly.
#
# An install writes the new /usr/bin/KlaayGuard and leaves the old process on
# the old inode. Linux has no supervisor for this agent: the XDG autostart entry
# fires at login and nothing else. Without the postinstall step the machine
# reports posture from the previous build until the user logs out, and without
# the postremove step an uninstall leaves the agent running on a deleted file.
#
# Stopping alone is not enough either. A security agent that stops at 10:00 and
# returns at the next login leaves the machine unmonitored for the rest of the
# day, so the postinstall must start the new build in the same session.
#
# The script drives the functions against fake agents in a temp directory. It
# never touches /usr/bin and it never runs an install.
#
# Root only, and for two reasons: the scripts run as root under dpkg, and the
# restart goes through `runuser`, which needs root to switch user.
#
# Reading another user's `/proc/<pid>/exe` also needs CAP_SYS_PTRACE. dpkg's
# root has it; a default Docker container drops it, so run the container with
# `--cap-add=SYS_PTRACE` or every process looks like a non-agent.
set -uo pipefail

cd "$(dirname "$0")/.."

POSTINST="linux/postinst.sh"
POSTRM="linux/postrm.sh"
TEST_USER="klaayguard-test-agent"

for f in "$POSTINST" "$POSTRM"; do
  test -f "$f" || { echo "FAIL: $f not found"; exit 1; }
done

if [ "$(id -u)" -ne 0 ]; then
  echo "FAIL: run this as root; the maintainer scripts run as root and so must their test"
  exit 1
fi

for fn in agent_pids restart_running_agents main; do
  if ! grep -q "^${fn}()" "$POSTINST"; then
    echo "FAIL: $POSTINST defines no ${fn}(); a package install leaves the old agent running"
    exit 1
  fi
done
for fn in agent_pids stop_running_agents main; do
  if ! grep -q "^${fn}()" "$POSTRM"; then
    echo "FAIL: $POSTRM defines no ${fn}(); a package removal leaves the agent running"
    exit 1
  fi
done

# A maintainer script must carry no way to switch a security control off. An
# environment variable read here would let the installing environment skip the
# restart and exit 0 without a word.
for f in "$POSTINST" "$POSTRM"; do
  if grep -qE '\$\{?KLAAYGUARD_[A-Z_]*(LIB|SKIP|DISABLE)' "$f"; then
    echo "FAIL: $f reads an environment switch; the shipped script must have no off switch"
    exit 1
  fi
done

workdir="$(mktemp -d)"
cleanup() {
  pkill -f "$workdir" 2>/dev/null || true
  userdel -r "$TEST_USER" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

# The agent runs as a person, not as root. `runuser` only switches user when it
# has one to switch to, so a root-only test never exercises the PAM path that
# production depends on.
id "$TEST_USER" >/dev/null 2>&1 || useradd -m -s /bin/sh "$TEST_USER" \
  || { echo "FAIL: could not create the unprivileged test user"; exit 1; }
chmod 755 "$workdir"

# A real ELF binary, not a shell script: the rule under test reads
# /proc/<pid>/exe, and a script's exe link points at its interpreter.
printf '#include <unistd.h>\nint main(void){for(;;)pause();return 0;}\n' > "$workdir/idle.c"
installed="$workdir/bin/KlaayGuard"
elsewhere="$workdir/dev/KlaayGuard"
mkdir -p "$(dirname "$installed")" "$(dirname "$elsewhere")"
cc -o "$installed" "$workdir/idle.c" || { echo "FAIL: could not build the fake agent"; exit 1; }
cp "$installed" "$elsewhere"
chmod -R 755 "$workdir/bin" "$workdir/dev"

# Source the functions with the install itself removed. The shipped scripts end
# with the call to main and carry no flag to suppress it, so the strip is what
# keeps this test from running a real install.
source_without_main() {
  local script="$1" out="$2"
  if [ "$(tail -1 "$script")" != 'main "$@"' ]; then
    echo "FAIL: the last line of $script is not the call to main; this strip is stale"
    exit 1
  fi
  sed '$d' "$script" > "$out"
}
source_without_main "$POSTINST" "$workdir/postinst.lib"
source_without_main "$POSTRM" "$workdir/postrm.lib"

# The postinstall sets `-e` for dpkg, and sourcing brings that into this shell,
# where one command returning non-zero would end the run with no message.
. "$workdir/postinst.lib"
set +e

alive() { kill -0 "$1" 2>/dev/null; }
owner_of() { stat -c %U "/proc/$1" 2>/dev/null; }

# `runuser` forks the agent, so the replacement appears a moment after the
# function returns. Wait for it rather than read the gap as a failure.
wait_for_agent() {
  local n=0
  while [ "$n" -lt 50 ]; do
    local pids
    pids=$(agent_pids "$1" | tr '\n' ' ')
    [ -n "$pids" ] && { echo "$pids"; return 0; }
    sleep 0.1
    n=$((n + 1))
  done
  return 1
}

# The argument is the point. The desktop entry is `Exec={{exec}} %U`, so a
# launch carrying a URL has one, and a command-line match would miss it.
runuser -u "$TEST_USER" -- env DISPLAY=":99" "$installed" "klaayguard://sign-in" &
sleep 0.6
installed_pid="$(agent_pids "$installed" | head -1)"
runuser -u "$TEST_USER" -- "$elsewhere" &
sleep 0.4
elsewhere_pid="$(agent_pids "$elsewhere" | head -1)"

[ -n "$installed_pid" ] || { echo "FAIL: the fake installed agent did not start, or agent_pids cannot see a process with an argument"; exit 1; }
[ -n "$elsewhere_pid" ] || { echo "FAIL: the fake second build did not start"; exit 1; }
[ "$(owner_of "$installed_pid")" = "$TEST_USER" ] || { echo "FAIL: the fake agent does not run as $TEST_USER"; exit 1; }

echo "==> agent_pids must find an agent started with an argument"

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

new_pid="${new_pids%% *}"

echo "==> as the same person, not as root"
if [ "$(owner_of "$new_pid")" != "$TEST_USER" ]; then
  echo "FAIL: the replacement runs as $(owner_of "$new_pid"), not $TEST_USER"
  exit 1
fi

echo "==> carrying the old session's environment"
if ! tr '\0' '\n' < "/proc/$new_pid/environ" | grep -qx "DISPLAY=:99"; then
  echo "FAIL: the new agent lost DISPLAY, so it cannot reach the user's session"
  exit 1
fi

echo "==> a build at another path must survive"
if ! alive "$elsewhere_pid"; then
  echo "FAIL: restart_running_agents killed a build outside the installed path"
  exit 1
fi

# The start runs behind `setsid ... &` with its output discarded, so neither the
# exit code nor the error reaches this script. A PAM denial would therefore kill
# the agent, start nothing, log a restart that did not happen, and exit 0 — the
# one path where this change leaves the machine worse than it found it.
echo "==> a restart that fails must be reported, not logged as done"
mkdir -p "$workdir/fakebin"
printf '#!/bin/sh\nexit 1\n' > "$workdir/fakebin/runuser"
chmod +x "$workdir/fakebin/runuser"
runuser -u "$TEST_USER" -- env DISPLAY=":99" "$installed" "klaayguard://sign-in" &
sleep 0.6
doomed_pid="$(agent_pids "$installed" | head -1)"
[ -n "$doomed_pid" ] || { echo "FAIL: could not start the agent for the failure case"; exit 1; }

failure_output=$(PATH="$workdir/fakebin:$PATH" restart_running_agents "$installed" 2>&1)
failure_code=$?

if [ "$failure_code" -eq 0 ]; then
  echo "FAIL: the restart failed and restart_running_agents reported success"
  echo "      output was: $failure_output"
  exit 1
fi
case "$failure_output" in
  *ERROR*) ;;
  *)
    echo "FAIL: nothing in the log says the agent never came back"
    echo "      output was: $failure_output"
    exit 1
    ;;
esac
if [ -n "$(agent_pids "$installed")" ]; then
  echo "FAIL: the failure case left an agent running; the test proved nothing"
  exit 1
fi

echo "==> a removal must stop the agent it deletes"
(
  # A fresh shell: the postremove defines its own agent_pids, and sourcing both
  # in one shell would hide which copy the assertions exercise.
  . "$workdir/postrm.lib"
  set +e
  stop_running_agents "$installed"
) || true
if [ -n "$(agent_pids "$installed")" ]; then
  echo "FAIL: an agent survived the removal, running on a deleted binary"
  exit 1
fi
if ! alive "$elsewhere_pid"; then
  echo "FAIL: the removal killed a build outside the removed path"
  exit 1
fi

echo "==> an upgrade must not take the removal path"
grep -q 'remove | purge | 0' "$POSTRM" \
  || { echo "FAIL: postrm does not limit the stop to a real removal"; exit 1; }

echo "==> the desktop database refresh must survive in both scripts"
for f in "$POSTINST" "$POSTRM"; do
  grep -q update-desktop-database "$f" \
    || { echo "FAIL: $f no longer refreshes the desktop database"; exit 1; }
done

echo "PASS: the install stops the old agent and starts the new one as the same person, the removal stops it, and other builds survive"
