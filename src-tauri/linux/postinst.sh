#!/bin/sh
# Package postinstall for the .deb and the .rpm. It refreshes the desktop
# databases, then restarts the agent this install replaces.
#
# dpkg and rpm both fail the package when this script exits non-zero, so every
# step is best-effort.
set -e

AGENT_BIN=/usr/bin/KlaayGuard

# The session variables the agent needs to reach the tray. The replacement
# inherits them from the process it replaces, so it lands in the same session
# whatever the desktop.
AGENT_SESSION_VARS="DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR XDG_SESSION_TYPE XDG_CURRENT_DESKTOP LANG"

log() { logger -t klaayguard.postinst "$1" 2>/dev/null || true; echo "$1"; }

# One variable out of a running process's environment.
proc_env() {
  tr '\0' '\n' < "/proc/$1/environ" 2>/dev/null | sed -n "s/^$2=//p" | head -1
}

# Every process running this binary, whatever its arguments.
#
# `/proc/<pid>/exe` names the file the process runs, so an argument cannot hide
# it. A command-line match can: the desktop entry is `Exec={{exec}} %U`, so a
# launch carrying a URL has an argument, and an anchored pattern misses it.
#
# The link reads "<path> (deleted)" once the package replaces the file, which is
# exactly the process this script exists to replace.
agent_pids() {
  bin="$1"
  for proc in /proc/[0-9]*; do
    exe=$(readlink "$proc/exe" 2>/dev/null) || continue
    if [ "$exe" = "$bin" ] || [ "$exe" = "$bin (deleted)" ]; then
      echo "${proc#/proc/}"
    fi
  done
}

# Whether an agent runs this binary, waiting for one to appear. `runuser` forks,
# so the replacement arrives a moment after the start returns.
wait_for_agent() {
  waited=0
  while [ "$waited" -lt 50 ]; do
    [ -n "$(agent_pids "$1")" ] && return 0
    sleep 0.1
    waited=$((waited + 1))
  done
  return 1
}

# Restart every agent that runs the binary this package just replaced.
#
# The install writes the new file and leaves the old process on the old inode.
# Linux runs no supervisor for this agent: the XDG autostart entry fires at
# login and nothing else, so without this step the machine reports posture from
# the previous build until the user logs out.
#
# Stopping is only half of it. A security agent that stops at 10:00 and returns
# at the next login leaves the machine unmonitored for the rest of the day, so
# the new build starts here, in the session the old one had.
#
# The match is this package's own path, so an AppImage agent is left alone. That
# matters: on Linux the single-instance guard is the plugin's bundle identifier,
# not a per-path lock, so an AppImage and this package would contend for one
# name. A developer build is spared for a different reason — `lib.rs` registers
# the plugin only when the build talks to production.
restart_running_agents() {
  bin="$1"
  command -v runuser >/dev/null 2>&1 || { log "postinst: no runuser; leaving the running agent alone"; return 0; }

  pids=$(agent_pids "$bin")
  [ -n "$pids" ] || return 0

  for pid in $pids; do
    user=$(stat -c %U "/proc/$pid" 2>/dev/null || true)
    [ -n "$user" ] || continue
    home=$(proc_env "$pid" HOME)
    [ -n "$home" ] || home=$(getent passwd "$user" | cut -d: -f6)
    [ -n "$home" ] || continue

    # Read the environment before the kill: /proc/<pid>/environ goes with it.
    set --
    for v in $AGENT_SESSION_VARS; do
      val=$(proc_env "$pid" "$v")
      [ -n "$val" ] && set -- "$@" "$v=$val"
    done

    kill "$pid" 2>/dev/null || true
    waited=0
    while kill -0 "$pid" 2>/dev/null; do
      if [ "$waited" -ge 50 ]; then
        log "postinst: agent $pid ignored SIGTERM for 5s; forcing"
        kill -9 "$pid" 2>/dev/null || true
        break
      fi
      sleep 0.1
      waited=$((waited + 1))
    done

    # setsid detaches the new agent from this script. Without it the child keeps
    # dpkg's stdout open and apt waits for a process that never exits.
    log "postinst: restarting the agent for $user"
    setsid runuser -u "$user" -- env -i \
      HOME="$home" USER="$user" LOGNAME="$user" \
      PATH=/usr/local/bin:/usr/bin:/bin \
      "$@" "$bin" >/dev/null 2>&1 &
  done

  # The start runs detached with its output discarded, so neither its exit code
  # nor its error reaches this script. Without this check a PAM denial would
  # kill the agent, start nothing, log a restart that never happened, and exit
  # 0 — the one path that leaves the machine worse than it was found, because
  # the old agent at least still reported.
  wait_for_agent "$bin" && return 0
  log "postinst: ERROR the agent did not come back; this machine reports nothing until the next login"
  return 1
}

main() {
  # Refresh the desktop databases so the app icon and menu entry are known at
  # once, without a logout. Distros without file triggers need this.
  update-desktop-database -q /usr/share/applications || true
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true

  restart_running_agents "$AGENT_BIN" || true
}

# The shipped script carries no way to switch this off. The test sources a copy
# with this last line removed.
main "$@"
