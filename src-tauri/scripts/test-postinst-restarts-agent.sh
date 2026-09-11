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
TEST_USER_B="klaayguard-test-agent-b"

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
created_user=no
created_user_b=no
cleanup() {
  pkill -f "$workdir" 2>/dev/null || true
  # The stubborn stand-in built below sets SIG_IGN on SIGTERM, so the polite
  # kill above never reaches it. The two blocks that use it force-kill it on
  # the happy path, which leaves this trap as the only cleaner for any early
  # exit in between. Without this line that stand-in outlives the run and
  # keeps executing a binary in a directory the next line deletes.
  sleep 0.2
  pkill -9 -f "$workdir" 2>/dev/null || true
  # Only accounts this run created. A developer whose machine already has one
  # by either name must not lose it, and its home directory, to a test.
  [ "$created_user" = yes ] && userdel -r "$TEST_USER" 2>/dev/null
  [ "$created_user_b" = yes ] && userdel -r "$TEST_USER_B" 2>/dev/null
  rm -rf "$workdir"
}
trap cleanup EXIT

# The agent runs as a person, not as root. `runuser` only switches user when it
# has one to switch to, so a root-only test never exercises the PAM path that
# production depends on.
if ! id "$TEST_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/sh "$TEST_USER" \
    || { echo "FAIL: could not create the unprivileged test user"; exit 1; }
  created_user=yes
fi
# A second login, for the case where one session's restart works and another's
# does not. One agent per user is what the loop restarts.
if ! id "$TEST_USER_B" >/dev/null 2>&1; then
  useradd -m -s /bin/sh "$TEST_USER_B" \
    || { echo "FAIL: could not create the second unprivileged test user"; exit 1; }
  created_user_b=yes
fi
REAL_RUNUSER="$(command -v runuser)"
# The postinstall starts the replacement with systemd-run where systemd runs and with
# runuser everywhere else. A fake for one path only leaves the other untested, and the
# blocks below all mean "the start failed", not "runuser failed".
REAL_SYSTEMD_RUN="$(command -v systemd-run || true)"
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

# An agent that ignores SIGTERM, for the two force-kill paths. Both scripts
# wait 5s for a polite stop before they force one, and nothing else in this
# file reaches that wait.
printf '#include <signal.h>\n#include <unistd.h>\nint main(void){signal(SIGTERM,SIG_IGN);for(;;)pause();return 0;}\n' > "$workdir/stubborn.c"
stubborn="$workdir/stubborn/KlaayGuard"
mkdir -p "$(dirname "$stubborn")"
cc -o "$stubborn" "$workdir/stubborn.c" || { echo "FAIL: could not build the stubborn fake agent"; exit 1; }
chmod -R 755 "$workdir/stubborn"

# The XDG bases the agent resolves its own directories from. `dirs` reads
# XDG_CONFIG_HOME for the autostart entry and for the desktop's screen-lock
# files, and XDG_DATA_HOME for the logs and the credential fallback file, so a
# replacement that loses them works on different files.
xdg_config="$workdir/xdg/config"
xdg_data="$workdir/xdg/data"
mkdir -p "$xdg_config" "$xdg_data"

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

# The argument is the point: no argument list can hide the file a process runs,
# and none has to be guessed. The agent reads only --forget-credentials, so any
# other word serves, and a decoy proves agent_pids matches on the binary.
runuser -u "$TEST_USER" -- env DISPLAY=":99" \
  XDG_CONFIG_HOME="$xdg_config" XDG_DATA_HOME="$xdg_data" \
  "$installed" "decoy-argument" &
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
restart_output=$(restart_running_agents "$installed" 2>&1)
echo "$restart_output"

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

# The start runs `env -i`, so a variable missing from AGENT_SESSION_VARS is
# gone from the replacement. These two decide which files the agent works on,
# not whether it starts, so losing them is silent: the agent runs, and writes
# its autostart entry and its logs where the session never looks.
echo "==> and the XDG bases it resolves its own directories from"
for xdg in "XDG_CONFIG_HOME=$xdg_config" "XDG_DATA_HOME=$xdg_data"; do
  if ! tr '\0' '\n' < "/proc/$new_pid/environ" | grep -qx "$xdg"; then
    echo "FAIL: the new agent lost ${xdg%%=*}, so it reads and writes a different directory than the agent it replaced"
    exit 1
  fi
done

echo "==> a build at another path must survive"
if ! alive "$elsewhere_pid"; then
  echo "FAIL: restart_running_agents killed a build outside the installed path"
  exit 1
fi

# The polite signal must do the stopping. A kill that never reaches the agent
# leaves the wait below it to run its full 5s and force-kill a process that
# would have exited on request. Every upgrade then stalls, a healthy agent dies
# hard, and the log blames it for a stall the script caused. The log line is
# the assertion rather than the elapsed time, because a loaded machine can be
# slow and still be correct.
echo "==> and the healthy agent must have stopped on the polite signal, not been forced"
case "$restart_output" in
  *"ignored SIGTERM"*)
    echo "FAIL: an agent that honours SIGTERM was force-killed, so the polite kill never reached it"
    echo "      output was: $restart_output"
    exit 1
    ;;
esac

# The case this whole change exists for. dpkg unpacks the new binary beside the
# old one and renames it over the target, which leaves the running process on an
# inode that has no name: /proc/<pid>/exe then reads "<path> (deleted)". A match
# on the plain path alone misses it, and the upgrade leaves the previous build
# reporting posture until the next login.
echo "==> an agent whose binary the install replaced must still be found"
cc -o "$installed.dpkg-new" "$workdir/idle.c" \
  || { echo "FAIL: could not build the replacement binary"; exit 1; }
mv "$installed.dpkg-new" "$installed"
chmod 755 "$installed"
if [ "$(readlink "/proc/$new_pid/exe")" != "$installed (deleted)" ]; then
  echo "FAIL: replacing the binary left /proc/$new_pid/exe reading $(readlink "/proc/$new_pid/exe"); this case proves nothing"
  exit 1
fi
case " $(agent_pids "$installed" | tr '\n' ' ') " in
  *" $new_pid "*) ;;
  *)
    echo "FAIL: agent_pids missed the agent on the replaced binary, so an upgrade leaves the previous build reporting"
    exit 1
    ;;
esac

echo "==> and must be restarted onto the new binary"
restart_running_agents "$installed"
if alive "$new_pid"; then
  echo "FAIL: the agent on the replaced binary still runs the previous build"
  exit 1
fi
# `agent_pids` matches the deleted inode as well, by design — that is how it
# finds the process to replace. So a bare "an agent runs" check passes for an
# agent still on the old file, which is the state this whole change exists to
# end. Read the replacement's own exe.
restarted_pids="$(wait_for_agent "$installed")"
if [ -z "$restarted_pids" ]; then
  echo "FAIL: no agent runs the replaced binary; the machine reports nothing until the next login"
  exit 1
fi
for restarted_pid in $restarted_pids; do
  restarted_exe="$(readlink "/proc/$restarted_pid/exe" 2>/dev/null)"
  if [ "$restarted_exe" != "$installed" ]; then
    echo "FAIL: agent $restarted_pid runs '$restarted_exe', not the new binary"
    exit 1
  fi
done
pkill -f "^$installed" 2>/dev/null || true
sleep 0.3

# The start runs behind `setsid ... &` with its output discarded, so neither the
# exit code nor the error reaches this script. A PAM denial would therefore kill
# the agent, start nothing, log a restart that did not happen, and exit 0 — the
# one path where this change leaves the machine worse than it found it.
echo "==> a restart that fails must be reported, not logged as done"
mkdir -p "$workdir/fakebin"
printf '#!/bin/sh\nexit 1\n' > "$workdir/fakebin/runuser"
chmod +x "$workdir/fakebin/runuser"
printf '#!/bin/sh\nexit 1\n' > "$workdir/fakebin/systemd-run"
chmod +x "$workdir/fakebin/systemd-run"
runuser -u "$TEST_USER" -- env DISPLAY=":99" "$installed" "decoy-argument" &
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

# One agent per user is what the loop restarts, so "an agent is running" is not
# the same question as "every agent came back". On a machine with two sessions,
# a restart that works for one user and fails for the other must still report
# failure — otherwise the second user's machine is dark and the install says so
# to no one.
echo "==> every session's agent must come back, not just one"
cat > "$workdir/fakebin/runuser" <<FAKE
#!/bin/sh
# Fail only for the second user, the way one session's PAM denial would.
[ "\$2" = "$TEST_USER_B" ] && exit 1
exec "$REAL_RUNUSER" "\$@"
FAKE
chmod +x "$workdir/fakebin/runuser"
cat > "$workdir/fakebin/systemd-run" <<FAKE
#!/bin/sh
# Same denial on the systemd path, where the user arrives as --uid=.
for a in "\$@"; do [ "\$a" = "--uid=$TEST_USER_B" ] && exit 1; done
exec "$REAL_SYSTEMD_RUN" "\$@"
FAKE
chmod +x "$workdir/fakebin/systemd-run"

runuser -u "$TEST_USER" -- env DISPLAY=":99" "$installed" &
runuser -u "$TEST_USER_B" -- env DISPLAY=":98" "$installed" &
sleep 0.8
before_two="$(agent_pids "$installed" | tr '\n' ' ')"
[ "$(agent_pids "$installed" | wc -l)" -eq 2 ] \
  || { echo "FAIL: expected two agents for the two-session case, got [$before_two]"; exit 1; }

two_output=$(PATH="$workdir/fakebin:$PATH" restart_running_agents "$installed" 2>&1)
two_code=$?
if [ "$two_code" -eq 0 ]; then
  echo "FAIL: one session's agent never came back and the install reported success"
  echo "      output was: $two_output"
  exit 1
fi
case "$two_output" in
  *"$TEST_USER_B"*) ;;
  *)
    echo "FAIL: the error does not name the session that lost its agent"
    echo "      output was: $two_output"
    exit 1
    ;;
esac
pkill -f "^$installed" 2>/dev/null || true
sleep 0.3

# One user can hold two agents — two seats on one login. The check is per killed
# pid, so a single replacement must not answer for both of them.
echo "==> two agents for one user must not collapse into one answer"
rm -f "$workdir/runuser.count"
cat > "$workdir/fakebin/runuser" <<FAKE
#!/bin/sh
# Succeed once, then fail: one replacement arrives, the other never does.
n=\$(cat "$workdir/runuser.count" 2>/dev/null || echo 0)
n=\$((n + 1))
echo "\$n" > "$workdir/runuser.count"
[ "\$n" -ge 2 ] && exit 1
exec "$REAL_RUNUSER" "\$@"
FAKE
chmod +x "$workdir/fakebin/runuser"
cat > "$workdir/fakebin/systemd-run" <<FAKE
#!/bin/sh
# Same one-then-fail on the systemd path, sharing the counter.
n=\$(cat "$workdir/runuser.count" 2>/dev/null || echo 0)
n=\$((n + 1))
echo "\$n" > "$workdir/runuser.count"
[ "\$n" -ge 2 ] && exit 1
exec "$REAL_SYSTEMD_RUN" "\$@"
FAKE
chmod +x "$workdir/fakebin/systemd-run"

runuser -u "$TEST_USER" -- env DISPLAY=":99" "$installed" &
runuser -u "$TEST_USER" -- env DISPLAY=":99" "$installed" seat-two &
sleep 0.8
[ "$(agent_pids "$installed" | wc -l)" -eq 2 ] \
  || { echo "FAIL: expected two agents for one user, got $(agent_pids "$installed" | wc -l)"; exit 1; }

seats_output=$(PATH="$workdir/fakebin:$PATH" restart_running_agents "$installed" 2>&1)
seats_code=$?
if [ "$seats_code" -eq 0 ]; then
  echo "FAIL: one of the user's two agents never came back and the install reported success"
  echo "      output was: $seats_output"
  exit 1
fi
pkill -f "^$installed" 2>/dev/null || true
sleep 0.3

# The block above stubs the starter to fail on its second call, so the second
# start never reaches the real one. This one lets both through: two seats, both
# replacements real. On the systemd path each start needs its own unit name, and
# a name built from the postinstall's own pid is the same on both iterations —
# the second start then fails with "unit already exists" and that user loses a
# seat until the next login. Nothing else in this file reaches that.
echo "==> two seats must both come back, with the real starter on each"
rm -f "$workdir/fakebin/runuser" "$workdir/fakebin/systemd-run"
runuser -u "$TEST_USER" -- env DISPLAY=":99" "$installed" &
runuser -u "$TEST_USER" -- env DISPLAY=":99" "$installed" seat-two &
sleep 0.8
before_seats="$(agent_pids "$installed" | tr '\n' ' ')"
[ "$(agent_pids "$installed" | wc -l)" -eq 2 ] \
  || { echo "FAIL: expected two agents for one user, got [$before_seats]"; exit 1; }

both_output=$(restart_running_agents "$installed" 2>&1)
both_code=$?
after_seats="$(wait_for_agent "$installed")"
after_count=$(echo "$after_seats" | wc -w)
if [ "$both_code" -ne 0 ]; then
  echo "FAIL: both seats had a real starter and the restart still reported failure"
  echo "      output was: $both_output"
  exit 1
fi
if [ "$after_count" -ne 2 ]; then
  echo "FAIL: expected two replacements for the two seats, got $after_count [$after_seats]"
  echo "      output was: $both_output"
  exit 1
fi
for seat_pid in $after_seats; do
  case " $before_seats " in
    *" $seat_pid "*)
      echo "FAIL: agent $seat_pid is one of the originals; that seat was never replaced"
      exit 1
      ;;
  esac
done
systemctl stop 'klaayguard-agent-*' 2>/dev/null || true
pkill -f "^$installed" 2>/dev/null || true
sleep 0.3

# A first install has nothing to restart, and that is not a failure. The
# branch also carries the line that tells an operator which of the two silent
# cases happened — no agent, or no permission to see one.
echo "==> a first install must report that there was nothing to restart"
none_output=$(restart_running_agents "$workdir/bin/KlaayGuard-none" 2>&1)
none_code=$?
if [ "$none_code" -ne 0 ]; then
  echo "FAIL: a first install with no agent running reported failure, which fails the package"
  echo "      output was: $none_output"
  exit 1
fi
case "$none_output" in
  *"nothing to restart"*) ;;
  *)
    echo "FAIL: nothing in the log says there was no agent to restart"
    echo "      output was: $none_output"
    exit 1
    ;;
esac

# `runuser` comes from util-linux and a minimal image can lack it. Without it
# the script must leave the running agent alone: killing an agent it cannot
# restart is the one outcome worse than an old build still reporting.
echo "==> without runuser the running agent must be left alone"
runuser -u "$TEST_USER" -- env DISPLAY=":99" "$installed" &
sleep 0.6
norunuser_pid="$(agent_pids "$installed" | head -1)"
[ -n "$norunuser_pid" ] || { echo "FAIL: could not start the agent for the missing-runuser case"; exit 1; }

# A subshell, so the emptied PATH cannot outlive this case.
norunuser_output=$(PATH=""; restart_running_agents "$installed" 2>&1)
norunuser_code=$?
if [ "$norunuser_code" -ne 0 ]; then
  echo "FAIL: a machine without runuser reported failure, which fails the package"
  echo "      output was: $norunuser_output"
  exit 1
fi
case "$norunuser_output" in
  *"no runuser"*) ;;
  *)
    echo "FAIL: nothing in the log says runuser is missing, so the operator cannot tell why no restart happened"
    echo "      output was: $norunuser_output"
    exit 1
    ;;
esac
if ! alive "$norunuser_pid"; then
  echo "FAIL: the agent was killed on a machine that cannot restart it"
  exit 1
fi
pkill -f "^$installed" 2>/dev/null || true
sleep 0.3

# Past the polite stop and the force-kill both. The stand-in ignores SIGTERM,
# so the 5s wait and the `forcing` line are real. Only SIGKILL is faked: a
# task wedged in uninterruptible sleep outlives one the same way, and the
# replacement then starts against a process that still holds the plugin's bus
# name — the case the ERROR exists to name.
echo "==> an agent that outlives SIGKILL must be named, not passed over"
runuser -u "$TEST_USER" -- env DISPLAY=":99" "$stubborn" &
sleep 0.6
[ -n "$(agent_pids "$stubborn")" ] || { echo "FAIL: the stubborn fake agent did not start"; exit 1; }

survivor_output=$(
  . "$workdir/postinst.lib"
  set +e
  # Swallow the force-kill so the stubborn agent really outlives it. Written
  # over several lines: bash 5.1, which CI runs, rejects a one-line function
  # body that carries a case inside this command substitution.
  kill() {
    if [ "$1" = "-9" ]; then
      return 0
    fi
    builtin kill "$@"
  }
  restart_running_agents "$stubborn" 2>&1
)
case "$survivor_output" in
  *"ignored SIGTERM"*) ;;
  *)
    echo "FAIL: an agent that ignores SIGTERM was never forced"
    echo "      output was: $survivor_output"
    exit 1
    ;;
esac
case "$survivor_output" in
  *"survived SIGKILL"*) ;;
  *)
    echo "FAIL: an agent that outlived SIGKILL was not reported, so the replacement's lost bus name has no explanation"
    echo "      output was: $survivor_output"
    exit 1
    ;;
esac
pkill -9 -f "^$stubborn" 2>/dev/null || true
sleep 0.3

# The removal side of the same case. A force-kill that does not land must not
# print the success line: the agent is still collecting on a deleted binary,
# and the machine's owner believes the package is gone.
echo "==> a removal that cannot kill the agent must say so"
runuser -u "$TEST_USER" -- env DISPLAY=":99" "$stubborn" &
sleep 0.6
[ -n "$(agent_pids "$stubborn")" ] || { echo "FAIL: the stubborn fake agent did not start for the removal case"; exit 1; }

unkillable_output=$(
  . "$workdir/postrm.lib"
  set +e
  # Swallow the force-kill so the stubborn agent really outlives it. Written
  # over several lines: bash 5.1, which CI runs, rejects a one-line function
  # body that carries a case inside this command substitution.
  kill() {
    if [ "$1" = "-9" ]; then
      return 0
    fi
    builtin kill "$@"
  }
  stop_running_agents "$stubborn" 2>&1
)
unkillable_code=$?
if [ "$unkillable_code" -eq 0 ]; then
  echo "FAIL: the agent survived the removal and stop_running_agents reported success"
  echo "      output was: $unkillable_output"
  exit 1
fi
case "$unkillable_output" in
  *"ERROR an agent still runs"*) ;;
  *)
    echo "FAIL: nothing in the log says an agent still runs the deleted binary"
    echo "      output was: $unkillable_output"
    exit 1
    ;;
esac
case "$unkillable_output" in
  *"stopped the agent this removal deleted"*)
    echo "FAIL: the removal claimed success while the agent was still running"
    exit 1
    ;;
esac
pkill -9 -f "^$stubborn" 2>/dev/null || true
sleep 0.3

# The failure case above leaves nothing at the installed path, so without a
# fresh agent here `stop_running_agents` would run on an empty list and the
# block would pass without doing anything.
echo "==> a removal must stop the agent it deletes"
runuser -u "$TEST_USER" -- env DISPLAY=":99" "$installed" "decoy-argument" &
sleep 0.6
removed_pid="$(agent_pids "$installed" | head -1)"
[ -n "$removed_pid" ] || { echo "FAIL: could not start the agent for the removal case"; exit 1; }

# A real removal deletes the file and runs this script after, so the process it
# must stop sits on an inode with no name. The postremove carries its own copy
# of the deleted-inode match, and this is the only place that drives it.
rm "$installed"
if [ "$(readlink "/proc/$removed_pid/exe")" != "$installed (deleted)" ]; then
  echo "FAIL: deleting the binary left /proc/$removed_pid/exe reading $(readlink "/proc/$removed_pid/exe"); this case proves nothing"
  exit 1
fi
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

# Put the stand-in back. The tables below start an agent from this path.
cp "$elsewhere" "$installed"
chmod 755 "$installed"

# Source text would pass even if the case were rewritten to include `upgrade`.
# Drive `main` with each argument the package managers really pass, against a
# live agent, and read what became of it.
outcome_of_main() { # script-lib, arg..., -> "RESTARTED", "SURVIVES", "STOPPED" or "COULD-NOT-START"
  local lib="$1"; shift
  runuser -u "$TEST_USER" -- "$installed" "decoy-argument" &
  sleep 0.5
  local before after
  before="$(agent_pids "$installed" | head -1)"
  [ -n "$before" ] || { echo "COULD-NOT-START"; return; }
  # Point the sourced copy at the stand-in. The assignment lands in this
  # subshell only, and `main` reads AGENT_BIN when it is called.
  ( . "$lib"; AGENT_BIN="$installed"; set +e; main "$@" ) >/dev/null 2>&1
  after="$(agent_pids "$installed" | head -1)"
  if [ -z "$after" ]; then
    echo "STOPPED"
  elif [ "$after" = "$before" ]; then
    echo "SURVIVES"
  else
    echo "RESTARTED"
  fi
  pkill -f "^$installed" 2>/dev/null || true
  sleep 0.2
}

drive_main() { # script-lib, name, "args:WANT"... -> exits 1 on the first mismatch
  local lib="$1" name="$2"; shift 2
  local case_row args want got
  for case_row in "$@"; do
    args="${case_row%:*}"
    want="${case_row##*:}"
    # shellcheck disable=SC2086
    got=$(outcome_of_main "$lib" $args)
    if [ "$got" != "$want" ]; then
      echo "FAIL: $name main '$args' gave $got, expected $want"
      exit 1
    fi
  done
}

echo "==> only a real removal may take the removal path"
drive_main "$workdir/postrm.lib" postrm \
  "remove:STOPPED" "purge:STOPPED" "0:STOPPED" \
  "upgrade 1.2.3:SURVIVES" "failed-upgrade 1.2.3:SURVIVES" \
  "abort-upgrade 1.2.3:SURVIVES" "1:SURVIVES" ":SURVIVES"

# The install side has the mirror rule, and it is driven at every point dpkg
# and rpm reach, not at one. `configure` and rpm's 1 and 2 follow a new binary
# and must restart. `triggered`, `abort-remove` and `abort-upgrade` undo a
# failed operation or answer a trigger, and there the binary on disk never
# changed: a restart would interrupt a healthy agent for nothing.
echo "==> and only a real configure may restart the agent"
drive_main "$workdir/postinst.lib" postinst \
  "configure:RESTARTED" "configure 1.2.3:RESTARTED" "1:RESTARTED" "2:RESTARTED" ":RESTARTED" \
  "triggered /usr/share/applications:SURVIVES" \
  "abort-remove:SURVIVES" "abort-remove in-favour other 1.2.3:SURVIVES" \
  "abort-upgrade 1.2.3:SURVIVES"

echo "==> the desktop database refresh must survive in both scripts"
for f in "$POSTINST" "$POSTRM"; do
  grep -q update-desktop-database "$f" \
    || { echo "FAIL: $f no longer refreshes the desktop database"; exit 1; }
done

echo "PASS: the install stops the old agent and starts the new one as the same person, the removal stops it, and other builds survive"
