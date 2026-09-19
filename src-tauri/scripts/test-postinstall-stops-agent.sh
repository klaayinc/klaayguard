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
for fn in stop_running_agent ensure_agent_running launch_agent main; do
  if ! grep -q "^${fn}()" "$POSTINSTALL"; then
    echo "FAIL: $POSTINSTALL defines no ${fn}(); the installer cannot stop and replace the old agent"
    exit 1
  fi
done

# Guarded, because line 17 carries no `-e`. With `mktemp` failed and `workdir`
# empty, `installed` resolves to the real /Applications binary and `cc`
# overwrites it. The cleanup below then runs `pkill -f "^/"`: every process.
workdir="$(mktemp -d)" || { echo "FAIL: mktemp -d failed; refusing to run with an empty workdir"; exit 1; }
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

# The cap is on the clock. Each tick forks `sleep` and `pgrep`, so a count of
# ticks overruns its stated seconds by two to three times. The Installer bar
# sits for the whole of it.
echo "==> stop_running_agent must force an agent that ignores SIGTERM, within its cap"
printf '#include <signal.h>\n#include <unistd.h>\nint main(void){signal(SIGTERM,SIG_IGN);for(;;)pause();return 0;}\n' > "$workdir/stubborn.c"
stubborn="$workdir/stubborn/KlaayGuard"
mkdir -p "$(dirname "$stubborn")"
cc -o "$stubborn" "$workdir/stubborn.c" || { echo "FAIL: could not build the stubborn agent"; exit 1; }
"$stubborn" & stubborn_pid=$!
disown "$stubborn_pid"   # no "Killed: 9" job notice; bash still reaps it
sleep 0.5
alive "$stubborn_pid" || { echo "FAIL: the stubborn agent did not start"; exit 1; }
STOP_WAIT_SECONDS=2   # the real default is 5
before=$SECONDS
stop_running_agent "$(id -u)" "$stubborn"
elapsed=$((SECONDS - before))
sleep 0.2
if alive "$stubborn_pid"; then
  echo "FAIL: an agent that ignores SIGTERM still runs after the stop"
  exit 1
fi
if [ "$elapsed" -gt 4 ]; then
  echo "FAIL: a ${STOP_WAIT_SECONDS}s cap took ${elapsed}s; the cap counts ticks, not seconds"
  exit 1
fi

# Stopping is half the job. Every launchd step in `main` is best-effort, so an
# install whose bootstrap and kickstart both fail must not end quietly with no
# agent: that is worse than the stale build this script replaces. Both arms are
# asserted, because a launcher that reports success while starting nothing is
# the failure that hides.
AGENT_WAIT_SECONDS=2   # per wait; the real default is 10

# The wait gives up on the clock too. `ensure_agent_running` waits twice, so a
# tick count that overran would hold the Installer bar for about a minute on a
# Mac where no agent returns.
echo "==> wait_for_agent must give up on the clock, not on a tick count"
before=$SECONDS
if wait_for_agent "$(id -u)" "$installed"; then
  echo "FAIL: wait_for_agent saw an agent, and none runs"
  exit 1
fi
elapsed=$((SECONDS - before))
if [ "$elapsed" -gt 3 ]; then
  echo "FAIL: a ${AGENT_WAIT_SECONDS}s wait took ${elapsed}s; the cap counts ticks, not seconds"
  exit 1
fi

echo "==> ensure_agent_running must report failure when nothing starts one"
launch_agent() { :; }
if ensure_agent_running "$(id -u)" "$installed" "$(id -un)" "$workdir/KlaayGuard.app"; then
  echo "FAIL: the installer reported success with no agent running"
  exit 1
fi

echo "==> and must report success once a launcher starts one"
launch_agent() { "$installed" & }
if ! ensure_agent_running "$(id -u)" "$installed" "$(id -un)" "$workdir/KlaayGuard.app"; then
  echo "FAIL: an agent runs, and the installer still reported failure"
  exit 1
fi

# `man launchctl` on asuser: "It does not modify the process' credentials (UID,
# GID, etc.)". A bare `asuser` therefore starts the agent as root, which
# resolves HOME to root's — a different single-instance lock and a different
# credential store than `single_instance.rs` intends — and `pgrep -u "$uid"`
# never sees it, so the check above would report a failure that did not happen.
#
# Proving the credential change needs root and a live GUI session, which no
# runner has. Assert the wrapping instead: the same one the step-1 call carries.
echo "==> launch_agent must start the app as the console user, not as root"
launcher=$(awk '/^launch_agent\(\)/,/^}/' "$POSTINSTALL")
case "$launcher" in
  *"launchctl asuser"*) ;;
  *) echo "FAIL: launch_agent no longer goes through launchctl asuser"; exit 1 ;;
esac
case "$launcher" in
  *sudo*-u*) ;;
  *) echo "FAIL: launch_agent does not wrap in sudo -u; asuser alone starts the agent as root"; exit 1 ;;
esac

# The open question this launcher exists under is whether the bootstrap-port
# failure that step 1 describes also reaches `open`. The EIO text answers that;
# the exit status does not, and the status cannot even say which of launchctl,
# sudo or open produced it. Keep the diagnostic.
#
# The stderr must go to a file rather than through a pipe: `open -g -j` returns
# at once, but a launcher that leaves a child holding the inherited descriptors
# makes a command substitution block, which is the hang `-g -j` exists to avoid.
echo "==> launch_agent must keep the diagnostic, not only the number"
# The launch line itself, not the whole body: a `2>/dev/null` on a later
# housekeeping command is fine, one on the launch throws the evidence away.
launch_line=$(printf '%s\n' "$launcher" | grep '/usr/bin/open')
case "$launch_line" in
  *"2>/dev/null"*)
    echo "FAIL: the launch sends stderr to /dev/null; the EIO text is the evidence and the number is not"
    exit 1
    ;;
esac
case "$launch_line" in
  *'2>"$launch_err"'*) ;;
  *) echo "FAIL: the launch does not capture stderr to a file: [$launch_line]"; exit 1 ;;
esac
case "$launcher" in
  *'launch_status=$?'*) ;;
  *) echo "FAIL: launch_agent does not capture the exit status"; exit 1 ;;
esac
# A command substitution around the launch would block on the inherited
# descriptors, which is the hang `-g -j` exists to avoid.
case "$launch_line" in
  *'$('*)
    echo "FAIL: the launch runs inside a command substitution, which can block on a child holding the descriptors"
    exit 1
    ;;
esac
# `-W` would wait for the app to exit, and hold the installer with it. The
# no-hang argument rests on its absence; the plist carries it, this must not.
case "$launch_line" in
  *" -W"*)
    echo "FAIL: the launch passes -W to open, which waits for the app to exit and hangs the installer"
    exit 1
    ;;
esac
grep -q 'head -c 400 "\$launch_err"' "$POSTINSTALL" \
  || { echo "FAIL: the captured stderr never reaches the log"; exit 1; }
# A failed `mktemp` must not stop the launch. With `launch_err` empty the
# redirect fails, bash never runs the command, and the log names a status the
# launch never produced.
mktemp_line=$(printf '%s\n' "$launcher" | grep '^[[:space:]]*launch_err=.*mktemp')
case "$mktemp_line" in
  *'||'*) ;;
  *) echo "FAIL: launch_agent does not guard a failed mktemp; the redirect fails and the launch never runs"; exit 1 ;;
esac

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

echo "==> and must check the agent came back, after the kickstart"
ensure_line=$(grep -n "^[[:space:]]*ensure_agent_running " "$POSTINSTALL" | head -1 | cut -d: -f1)
if [ -z "$ensure_line" ]; then
  echo "FAIL: main never calls ensure_agent_running; a failed restart leaves the Mac unmonitored in silence"
  exit 1
fi
if [ -n "$kick_line" ] && [ "$ensure_line" -lt "$kick_line" ]; then
  echo "FAIL: ensure_agent_running (line $ensure_line) runs before kickstart (line $kick_line)"
  exit 1
fi

echo "==> and must arm that check before it stops anything"
# A cancelled or killed installer would otherwise keep the stop and lose the
# start, leaving the Mac with no agent and no message.
trap_line=$(grep -n "^[[:space:]]*trap .*ensure_agent_running" "$POSTINSTALL" | head -1 | cut -d: -f1)
if [ -z "$trap_line" ]; then
  echo "FAIL: main arms no trap; an interrupted install keeps the stop and loses the start"
  exit 1
fi
if [ "$trap_line" -gt "$stop_line" ]; then
  echo "FAIL: the trap (line $trap_line) is armed after the stop (line $stop_line)"
  exit 1
fi

# The name guard turns this file into a library when it is not called
# `postinstall`. If the positive arm ever stopped matching, the installer would
# do nothing at all and still report a success.
echo "==> the name guard must run main when the file is named postinstall"
if [ -x /Applications/KlaayGuard.app/Contents/MacOS/KlaayGuard ]; then
  echo "note: KlaayGuard is installed on this Mac; skipping rather than running a real install"
else
  cp "$POSTINSTALL" "$workdir/postinstall"
  guard_out=$(bash "$workdir/postinstall" 2>&1)
  guard_status=$?
  case "$guard_out" in
    *"no KlaayGuard binary at"*) ;;
    *)
      echo "FAIL: the name guard did not run main; the installer would do nothing and report a success"
      echo "      output was: $guard_out"
      exit 1
      ;;
  esac
  # An install that placed no app must fail the installation rather than end
  # green with no app and no agent.
  if [ "$guard_status" -eq 0 ]; then
    echo "FAIL: postinstall exited 0 with no app installed; the installer would report a success"
    exit 1
  fi
fi

echo "PASS: the installer stops the agent it replaces, spares other builds, and reports when none comes back"
