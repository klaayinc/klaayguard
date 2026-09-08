#!/bin/sh
# Package postremove for the .deb and the .rpm. It refreshes the desktop
# databases, then stops the agent the removal deleted.
#
# dpkg and rpm both fail the package when this script exits non-zero, so every
# step is best-effort.
set -e

AGENT_BIN=/usr/bin/KlaayGuard

log() { logger -t klaayguard.postrm "$1" 2>/dev/null || true; echo "$1"; }

# Every process running this binary, whatever its arguments. `/proc/<pid>/exe`
# reads "<path> (deleted)" once the package removes the file, which is the only
# way left to find the process: the path it started from is gone.
#
# The postinstall carries its own copy. Maintainer scripts ship alone inside the
# package, so neither can source the other.
agent_pids() {
  bin="$1"
  for proc in /proc/[0-9]*; do
    exe=$(readlink "$proc/exe" 2>/dev/null) || continue
    if [ "$exe" = "$bin" ] || [ "$exe" = "$bin (deleted)" ]; then
      echo "${proc#/proc/}"
    fi
  done
}

# Stop every agent left running on the binary this removal deleted.
#
# Nothing else does. The agent has no supervisor on Linux, so an uninstall that
# only deletes files leaves it running on a deleted inode until the next logout:
# a security agent the machine's owner believes is gone, still collecting.
stop_running_agents() {
  bin="$1"
  pids=$(agent_pids "$bin")
  if [ -z "$pids" ]; then
    # "Nothing was running" and "I cannot see it" arrive here the same way:
    # root without CAP_SYS_PTRACE reads an empty exe link for another user's
    # process. Say which line ran, so the silence is not the answer.
    log "postrm: no agent runs $bin; nothing to stop"
    return 0
  fi

  for pid in $pids; do
    kill "$pid" 2>/dev/null || true
  done

  waited=0
  while [ -n "$(agent_pids "$bin")" ]; do
    if [ "$waited" -ge 50 ]; then
      log "postrm: an agent ignored SIGTERM for 5s; forcing"
      for pid in $(agent_pids "$bin"); do
        kill -9 "$pid" 2>/dev/null || true
      done
      break
    fi
    sleep 0.1
    waited=$((waited + 1))
  done

  # Report what happened, not what was attempted. The loop above breaks after
  # the force-kill without re-reading, so the old success line printed even when
  # the agent was still there.
  if [ -n "$(agent_pids "$bin")" ]; then
    log "postrm: ERROR an agent still runs the deleted $bin"
    return 1
  fi
  log "postrm: stopped the agent this removal deleted"
}

main() {
  # Refresh the desktop databases after removal so the menu entry stops being
  # advertised once the package is gone.
  update-desktop-database -q /usr/share/applications || true
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true

  # Only a real removal. dpkg passes `upgrade` and rpm passes 1 when the package
  # is being replaced, and there the postinstall restarts the agent instead.
  case "${1:-}" in
    remove | purge | 0)
      stop_running_agents "$AGENT_BIN" || true
      ;;
  esac
}

# The shipped script carries no way to switch this off. The test sources a copy
# with this last line removed.
main "$@"
