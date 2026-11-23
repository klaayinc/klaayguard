#!/bin/sh
# Package postinstall for the .deb and the .rpm. It refreshes the desktop
# databases, removes what earlier versions left behind, then restarts every
# agent this install replaces onto the new binary.
#
# The package manager removes the earlier package itself: the same package on
# an upgrade, and the pre-rename klaay package through Conflicts, Replaces and
# Obsoletes in tauri.conf.json. What it cannot see is handled here: an agent
# that an AppImage runs, and the login entry tauri-plugin-autostart wrote.
#
# dpkg and rpm both fail the package when this script exits non-zero, so every
# step is best-effort.
set -e

AGENT_BIN=/usr/bin/KlaayGuard
# The binary of the package before the rename to KlaayGuard.
LEGACY_BIN=/usr/bin/klaay

# The session variables the agent needs to reach the tray, and the XDG bases
# that decide which directories it reads and writes. The replacement inherits
# them from the process it replaces, so it lands in the same session, on the
# same files, whatever the desktop.
#
# XDG_CONFIG_HOME and XDG_DATA_HOME are here because `dirs` reads them.
# `config_dir()` resolves the autostart entry the agent writes, and the
# desktop's own screen-lock files it reads: KDE's kscreenlockerrc and
# Hyprland's hypridle.conf. `data_local_dir()` resolves the logs and the
# credential file the agent falls back to where no Secret Service daemon runs.
#
# There is no single-instance lock file on Linux. `src/lib.rs` builds that
# module only for macOS and the test target; Linux keeps the plugin's D-Bus
# name, which this script does not touch.
#
# `env -i` below drops every variable not on this line. A replacement that
# lost XDG_CONFIG_HOME reads a screen-lock config that is not the one this
# desktop uses, and reports the wrong posture.
AGENT_SESSION_VARS="DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR XDG_SESSION_TYPE XDG_CURRENT_DESKTOP XDG_CONFIG_HOME XDG_DATA_HOME LANG"

log() { logger -t klaayguard.postinst "$1" 2>/dev/null || true; echo "$1"; }

# One variable out of a running process's environment.
proc_env() {
  tr '\0' '\n' < "/proc/$1/environ" 2>/dev/null | sed -n "s/^$2=//p" | head -1
}

# Every process running this binary, whatever its arguments.
#
# `/proc/<pid>/exe` names the file the process runs, so no argument list can hide
# it and none has to be guessed. The link reads "<path> (deleted)" once the
# package replaces the file, which is exactly the process this script exists to
# replace.
agent_pids() {
  bin="$1"
  for proc in /proc/[0-9]*; do
    # `readlink exe` resolves in the target's own mount namespace, so an agent
    # at this same path inside a container or a chroot reads as ours and
    # matches. Killing it as root, then starting the host binary for whatever
    # account its uid maps to, is the worst thing this script could do. Take
    # only processes whose root is ours.
    [ "$(readlink "$proc/root" 2>/dev/null)" = "/" ] || continue
    exe=$(readlink "$proc/exe" 2>/dev/null) || continue
    if [ "$exe" = "$bin" ] || [ "$exe" = "$bin (deleted)" ]; then
      echo "${proc#/proc/}"
    fi
  done
}

# Every process running an earlier KlaayGuard that this package did not write:
# an AppImage, which runs from its own `.mount_*` directory, and the pre-rename
# package's binary.
#
# Each one claims the same single-instance name as the package agent. While one
# runs, the new build exits at start, and the machine reports from the earlier
# version. The same root check as `agent_pids` applies.
earlier_agent_pids() {
  for proc in /proc/[0-9]*; do
    [ "$(readlink "$proc/root" 2>/dev/null)" = "/" ] || continue
    exe=$(readlink "$proc/exe" 2>/dev/null) || continue
    case "${exe% (deleted)}" in
      "$LEGACY_BIN" | */.mount_*/usr/bin/KlaayGuard | */.mount_*/usr/bin/klaay)
        echo "${proc#/proc/}"
        ;;
    esac
  done
}

# Delete the login entry tauri-plugin-autostart wrote for v0.1.0 to v0.1.5.
#
# The agent now writes klaayguard.desktop. On a machine that ran those builds
# the old KlaayGuard.desktop stays beside it, and both start an agent at every
# login. The file name alone is not proof: take it only when it starts ours.
remove_legacy_autostart() {
  getent passwd | cut -d: -f6 | sort -u | while IFS= read -r home; do
    entry="$home/.config/autostart/KlaayGuard.desktop"
    [ -f "$entry" ] || continue
    grep -qE '^Exec=.*(KlaayGuard|klaay)' "$entry" || continue
    if rm -f "$entry"; then
      log "postinst: removed the tauri-plugin-autostart entry $entry"
    else
      log "postinst: ERROR could not remove $entry"
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
  # The agents of earlier installs go the same way: stopped, then replaced by
  # this package's binary for the same user, in the same session.
  pids=$(agent_pids "$bin"; earlier_agent_pids)
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

    # `setsid` leaves the terminal and the process group, not the control group.
    # Started that way the replacement stays in whatever cgroup dpkg ran in, so
    # an upgrade driven from a unit — MDM, unattended-upgrades — kills the agent
    # again the moment that unit stops, after this script has already reported
    # success. Measured: inside `systemd-run --wait`, a setsid child dies with
    # the unit; the same child under `systemd-run --collect` outlives it.
    #
    # So put the agent in its own transient unit where systemd runs, and keep
    # setsid for machines without it. setsid is still needed there: without it
    # the child holds dpkg's stdout and apt waits for a process that never exits.
    log "postinst: restarting the agent for $user"
    if command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
      # `$@` holds VAR=value pairs; systemd-run wants one --setenv= per pair.
      # Rotate the list in place — the two branches are exclusive, so the
      # fallback below never sees the rewritten form.
      remaining=$#
      while [ "$remaining" -gt 0 ]; do
        pair="$1"; shift
        set -- "$@" "--setenv=$pair"
        remaining=$((remaining - 1))
      done
      # Name the unit after the pid being replaced, not this script's own. `$$`
      # is the same on every pass of the loop, so a user holding two seats built
      # one name twice and the second start died on "unit already exists" — the
      # fallback has no namespace to collide in, so that would be a regression
      # this branch introduced. `systemd-escape` because an AD or SSSD fleet
      # carries names like `alice@corp.com`, where `@` reads as a template
      # instance and `\` is not a legal unit name at all.
      systemd-run --collect --quiet \
        --unit="klaayguard-agent-$(systemd-escape "$user")-$pid" \
        --uid="$user" \
        --setenv="HOME=$home" --setenv="USER=$user" --setenv="LOGNAME=$user" \
        --setenv="PATH=/usr/local/bin:/usr/bin:/bin" \
        "$@" -- "$bin" >/dev/null 2>&1
    else
      setsid runuser -u "$user" -- env -i \
        HOME="$home" USER="$user" LOGNAME="$user" \
        PATH=/usr/local/bin:/usr/bin:/bin \
        "$@" "$bin" >/dev/null 2>&1 &
    fi
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

# Point the package manager at Klaay's package repository, so the next
# `apt upgrade` or `dnf upgrade` installs the next release (PROD-7007).
#
# The agent's own updater serves AppImage installs only. Before this step a
# .deb or .rpm install stayed on the version it was installed with, and its log
# said "up to date" every six hours.
#
# Three cases leave the machine without the repository, and in each one this
# step also removes what an earlier install wrote, so the state always follows
# the package that is installed now:
#
# * The build carries no repository. Only the production build ships
#   /usr/share/klaay-guard/package-repo: the release passes
#   linux/package-repo.conf.json to that build alone. A development or staging
#   build pointed at the production repository would be "upgraded" to the
#   production build of the same package on the next `apt upgrade`. On rpm this
#   holds for a fresh install only: rpm runs this script before it deletes the
#   old package's files, so a staging rpm installed over a production one still
#   finds them and keeps the registration. postrm.sh says why it leaves that.
# * /etc/klaay/no-repo exists. Some companies forbid extra repositories; this
#   is their switch, documented in docs/PRIVACY_DATASHEET.md.
# * The system has no apt or yum/dnf directory to write to (zypper, for one).
#
# On apt the key is scoped with `signed-by`: it never enters a system-wide
# keyring and vouches for Klaay's repository only. rpm has no such scoping. The
# .repo file names the key, and dnf imports it into rpm's own keyring the first
# time it reads the repository (`rpm -q gpg-pubkey`, as for any third-party rpm
# repository). From then on rpm trusts packages that key signed wherever they
# come from, and an uninstall does not remove the import: a nested rpm call
# inside this script would deadlock on the rpm database lock. The privacy
# datasheet says so and gives the command.
#
# `$1` says which package manager runs this script: dpkg passes `configure`, rpm
# passes the count of installed copies (1 or 2).
PACKAGE_REPO_SRC=/usr/share/klaay-guard/package-repo
PACKAGE_REPO_OPT_OUT=/etc/klaay/no-repo
APT_REPO_KEY=/usr/share/keyrings/klaay.gpg
APT_REPO_LIST=/etc/apt/sources.list.d/klaay.list
RPM_REPO_KEY=/etc/pki/rpm-gpg/RPM-GPG-KEY-klaay
RPM_REPO_FILE=/etc/yum.repos.d/klaay.repo

remove_package_repo() {
  for f in "$APT_REPO_LIST" "$APT_REPO_KEY" "$RPM_REPO_FILE" "$RPM_REPO_KEY"; do
    [ -e "$f" ] || continue
    rm -f "$f" && log "postinst: removed $f"
  done
}

register_package_repo() {
  if [ ! -f "$PACKAGE_REPO_SRC/klaay.gpg" ]; then
    log "postinst: this build carries no package repository; leaving the machine off it"
    remove_package_repo
    return 0
  fi
  if [ -e "$PACKAGE_REPO_OPT_OUT" ]; then
    log "postinst: $PACKAGE_REPO_OPT_OUT exists; leaving the machine off the package repository"
    remove_package_repo
    return 0
  fi

  case "$1" in
    configure)
      if [ ! -d /etc/apt/sources.list.d ]; then
        log "postinst: no /etc/apt/sources.list.d; cannot add the package repository"
        return 0
      fi
      install -D -m 0644 "$PACKAGE_REPO_SRC/klaay.gpg" "$APT_REPO_KEY" &&
        install -m 0644 "$PACKAGE_REPO_SRC/klaay.list" "$APT_REPO_LIST" &&
        log "postinst: added the package repository ($APT_REPO_LIST)"
      ;;
    1 | 2)
      if [ ! -d /etc/yum.repos.d ]; then
        log "postinst: no /etc/yum.repos.d; cannot add the package repository"
        return 0
      fi
      install -D -m 0644 "$PACKAGE_REPO_SRC/klaay.asc" "$RPM_REPO_KEY" &&
        install -m 0644 "$PACKAGE_REPO_SRC/klaay.repo" "$RPM_REPO_FILE" &&
        log "postinst: added the package repository ($RPM_REPO_FILE)"
      ;;
  esac
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
      remove_legacy_autostart || true
      register_package_repo "${1:-configure}" || true
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
