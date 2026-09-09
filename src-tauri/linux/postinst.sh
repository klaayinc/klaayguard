#!/bin/sh
# Package postinstall for the .deb and the .rpm. It refreshes the desktop
# databases, then restarts the agent this install replaces.
#
# dpkg and rpm both fail the package when this script exits non-zero, so every
# step is best-effort.
set -e

AGENT_BIN=/usr/bin/KlaayGuard

# The session variables the agent needs to reach the tray, and the XDG bases
# that decide which directories it reads and writes. The replacement inherits
# them from the process it replaces, so it lands in the same session, on the
# same files, whatever the desktop.
#
# XDG_CONFIG_HOME and XDG_DATA_HOME are here because `dirs` reads them:
# `config_dir()` resolves the autostart entry and the settings file, and
# `data_local_dir()` resolves the logs, the single-instance lock and the
# keychain fallback. `env -i` below drops every variable not on this line, so
# a user who relocates either base would get a replacement that reads and
# writes where neither the session nor the agent it replaced looks.
AGENT_SESSION_VARS="DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR XDG_SESSION_TYPE XDG_CURRENT_DESKTOP XDG_CONFIG_HOME XDG_DATA_HOME LANG"

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

# Whether a *new* agent runs for one user, waiting for it to appear.
#
# "Is an agent running" is the wrong question. The loop below restarts one agent
# per logged-in user, so on a machine with two sessions a check for any process
# passes while one user's agent is gone. Excluding the pid that was killed also
# covers the process that survived SIGKILL: its old pid does not count as the
# replacement.
#
# One replacement may answer for one killed agent, never for two. A user can
# hold two seats, and without the claimed list a single new process would
# satisfy both checks while one of the two never came back.
#
# `runuser` forks, so the new agent arrives a moment after the start returns.
# Echoes the pid it claims, so the caller can add it to that list.
wait_for_new_agent() {
  nbin="$1"
  nuser="$2"
  noldpid="$3"
  nclaimed="$4"
  nwaited=0
  while [ "$nwaited" -lt 50 ]; do
    for npid in $(agent_pids "$nbin"); do
      [ "$npid" = "$noldpid" ] && continue
      case " $nclaimed " in
        *" $npid "*) continue ;;
      esac
      if [ "$(stat -c %U "/proc/$npid" 2>/dev/null)" = "$nuser" ]; then
        echo "$npid"
        return 0
      fi
    done
    sleep 0.1
    nwaited=$((nwaited + 1))
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

  # Say so. "No agent was running" and "I cannot see the agent" reach this line
  # the same way: root without CAP_SYS_PTRACE reads an empty exe link for
  # another user's process. dpkg's root has that capability, so the silence was
  # the defect rather than the blindness.
  restarted=""
  pids=$(agent_pids "$bin")
  if [ -z "$pids" ]; then
    log "postinst: no agent runs $bin; nothing to restart"
    return 0
  fi

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
        # Wait for the kill to land. Starting the replacement while the old
        # process still holds the plugin's bus name makes the *new* agent the
        # one that exits, leaving the deleted-inode build in charge.
        forced=0
        while kill -0 "$pid" 2>/dev/null && [ "$forced" -lt 20 ]; do
          sleep 0.1
          forced=$((forced + 1))
        done
        kill -0 "$pid" 2>/dev/null &&
          log "postinst: ERROR agent $pid survived SIGKILL; the replacement may lose the single-instance name"
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
    restarted="$restarted $user:$pid"
  done

  # The start runs detached with its output discarded, so neither its exit code
  # nor its error reaches this script. Without this check a PAM denial would
  # kill the agent, start nothing, log a restart that never happened, and exit
  # 0 — the one path that leaves the machine worse than it was found, because
  # the old agent at least still reported.
  #
  # Check every session, not the machine. One user's restart can fail while
  # another's works, and a machine-wide question answers yes to that.
  # Seed the claimed list with every pid killed here. A process that survives
  # SIGKILL must not pass as somebody's replacement either.
  missing=0
  claimed=""
  for entry in $restarted; do
    claimed="$claimed ${entry##*:}"
  done
  for entry in $restarted; do
    ruser="${entry%%:*}"
    rpid="${entry##*:}"
    if newpid=$(wait_for_new_agent "$bin" "$ruser" "$rpid" "$claimed"); then
      claimed="$claimed $newpid"
      continue
    fi
    log "postinst: ERROR the agent for $ruser did not come back; that session reports nothing until the next login"
    missing=1
  done
  [ "$missing" -eq 0 ] && return 0
  return 1
}

main() {
  # Refresh the desktop databases so the app icon and menu entry are known at
  # once, without a logout. Distros without file triggers need this.
  update-desktop-database -q /usr/share/applications || true
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true

  # Only where the binary changed. dpkg also calls this script to undo a failed
  # operation (`abort-remove`, `abort-upgrade`) and to answer a trigger, and on
  # those the file on disk is the one the running agent already started from.
  # Restarting there interrupts a healthy agent for nothing.
  case "${1:-configure}" in
    configure | 1 | 2)
      restart_running_agents "$AGENT_BIN" || true
      ;;
    *)
      log "postinst: called as '${1:-}'; the binary did not change, so the agent keeps running"
      ;;
  esac
}

# The shipped script carries no way to switch this off. The test sources a copy
# with this last line removed.
main "$@"
