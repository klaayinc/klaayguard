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
AGENT_SESSION_VARS="DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR XDG_SESSION_TYPE XDG_CURRENT_DESKTOP LANG KLAAYGUARD_TEST_MARK"

log() { logger -t klaayguard.postinst "$1" 2>/dev/null || true; echo "$1"; }

# One variable out of a running process's environment.
proc_env() {
  tr '\0' '\n' < "/proc/$1/environ" 2>/dev/null | sed -n "s/^$2=//p" | head -1
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
# The match anchors on the installed path. An AppImage agent and a developer
# build run from other paths, keep their own single-instance locks, and this
# package does not own them.
restart_running_agents() {
  bin="$1"
  command -v pgrep >/dev/null 2>&1 || { log "postinst: no pgrep; leaving the running agent alone"; return 0; }
  command -v runuser >/dev/null 2>&1 || { log "postinst: no runuser; leaving the running agent alone"; return 0; }

  pids=$(pgrep -f "^$bin$" 2>/dev/null || true)
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
}

main() {
  # Refresh the desktop databases so the app icon and menu entry are known at
  # once, without a logout. Distros without file triggers need this.
  update-desktop-database -q /usr/share/applications || true
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true

  restart_running_agents "$AGENT_BIN" || true
}

# Run the install unless the test asks for the functions alone. dpkg names this
# script `<package>.postinst` and rpm runs it with no stable $0, so the check
# cannot key on the name: it defaults to running, and only the test opts out.
[ "${KLAAYGUARD_POSTINST_LIB:-}" = "1" ] || main "$@"
