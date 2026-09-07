#!/usr/bin/env bash
# Verifies the `--install-agent` CLI seam on the debug binary. Two rules.
#
# It must EXIT PROMPTLY, without entering the Tauri event loop.
# RED (before the seam exists): `--install-agent` is ignored, the app launches
# the tray UI and never exits, so the timeout kills it -> exit 124 -> FAIL. That
# is an observable failure, not an infinite hang.
#
# It must WRITE NOTHING. Only the app inside /Applications/KlaayGuard.app may
# write the shared LaunchAgent, and `target/debug/KlaayGuard` never is — on a
# runner because no app is installed, on a developer Mac because the installed
# app is a different binary. Either way the seam refuses.
#
# So this script does not cover the successful write. That path belongs to the
# installed app, and the rules it follows are unit tested:
# `may_write_launch_agent` and `render_launch_agent_plist`.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN="target/debug/KlaayGuard"
PLIST="$HOME/Library/LaunchAgents/com.klaay.klaayguard.plist"
# A plain `cargo build` bakes in the production API base, so the lock this
# binary would claim is the unsuffixed one. The seam must exit before it.
LOCK="$HOME/Library/Application Support/com.klaay.app/agent.lock"

echo "==> Building debug binary"
cargo build --bin KlaayGuard >/dev/null

# Move any existing plist aside and put it back on exit, so a file found after
# the run is attributable to it, and a developer Mac keeps the LaunchAgent it
# depends on.
if [ -f "$PLIST" ]; then
  SAVED_DIR="$(mktemp -d)"
  mv "$PLIST" "$SAVED_DIR/plist"
  restore_plist() { rm -f "$PLIST"; mv "$SAVED_DIR/plist" "$PLIST"; rmdir "$SAVED_DIR"; }
else
  restore_plist() { rm -f "$PLIST"; }
fi
trap restore_plist EXIT

# Portable 10s timeout (macOS has no GNU `timeout`): run in background, poll,
# then kill if it's still alive. A killed process yields code 124.
run_with_timeout() {
  local secs=$1; shift
  "$@" & local pid=$!
  local waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$secs" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 1; waited=$((waited + 1))
  done
  wait "$pid"
}

# A production agent already running on this Mac holds the same lock, so its
# presence says nothing about the seam. Only judge a lock this run created.
lock_before=no
[ -e "$LOCK" ] && lock_before=yes

echo "==> Running '$BIN --install-agent' (must exit within 10s)"
set +e
run_with_timeout 10 "$BIN" --install-agent
code=$?
set -e

# The bootstrap/kickstart step is best-effort and only succeeds inside a GUI
# session (the .pkg postinstall guarantees that via `launchctl asuser`); from a
# headless shell it returns EIO, so we don't assert exit 0 here.
if [ "$code" -eq 124 ]; then
  echo "FAIL: binary did not exit within 10s (fell into the event loop)"
  exit 1
fi
if [ -f "$PLIST" ]; then
  echo "FAIL: the debug binary is not the installed app, so it had to leave $PLIST alone"
  exit 1
fi

#  3. it must NOT claim the single-instance lock. The .pkg postinstall runs this
#     seam while the previous agent is still up; a seam that took the lock would
#     either kill the install or leave the lock held by a process that has
#     already exited.
if [ "$lock_before" = no ] && [ -e "$LOCK" ]; then
  echo "FAIL: the seam claimed the single-instance lock at $LOCK"
  exit 1
fi
if [ "$lock_before" = yes ]; then
  echo "note: a lock already existed before this run; skipping the lock check"
fi

echo "PASS: seam exited promptly (code $code), wrote no LaunchAgent, and took no lock"
