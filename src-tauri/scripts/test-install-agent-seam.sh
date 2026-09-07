#!/usr/bin/env bash
# Verifies the `--install-agent` CLI seam: the binary must register the launchd
# LaunchAgent and EXIT PROMPTLY, without entering the Tauri event loop.
#
# RED (before the seam exists): `--install-agent` is ignored, the app launches
# the tray UI and never exits, so `timeout` kills it -> exit 124 -> FAIL. This is
# an observable failure, not an infinite hang.
# GREEN (after the seam): the binary exits 0 within a couple seconds and the
# LaunchAgent plist is present.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN="target/debug/KlaayGuard"
PLIST="$HOME/Library/LaunchAgents/com.klaay.klaayguard.plist"
# A plain `cargo build` bakes in the production API base, so the lock this
# binary would claim is the unsuffixed one. The seam must exit before it.
LOCK="$HOME/Library/Application Support/com.klaay.app/agent.lock"

echo "==> Building debug binary"
cargo build --bin KlaayGuard >/dev/null

# Remove any pre-existing plist so its presence is attributable to this run,
# and the one this run writes on exit: launchd would otherwise load it at the
# next login.
rm -f "$PLIST"
trap 'rm -f "$PLIST"' EXIT

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

# Contract of the seam:
#  1. it must NOT fall into the Tauri event loop (would be killed at 124), and
#  2. it must render + write the LaunchAgent plist to disk (RunAtLoad loads it at
#     next login even if the live `launchctl bootstrap` can't reach a GUI session).
# The bootstrap/kickstart step is best-effort and only succeeds inside a GUI
# session (the .pkg postinstall guarantees that via `launchctl asuser`); from a
# headless shell it returns EIO, so we don't assert exit 0 here.
if [ "$code" -eq 124 ]; then
  echo "FAIL: binary did not exit within 10s (fell into the event loop)"
  exit 1
fi
if [ ! -f "$PLIST" ]; then
  echo "FAIL: LaunchAgent plist was not written to $PLIST (exit code $code)"
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

echo "PASS: seam exited promptly (code $code), wrote the LaunchAgent plist, and took no lock"
