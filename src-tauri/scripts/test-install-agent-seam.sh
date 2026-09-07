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

# The debug binary is not the installed app, so the seam writes the plist only
# on a machine with no app in /Applications. That is the CI runner. A developer
# Mac with the app installed gets the opposite result, and this script must not
# destroy the LaunchAgent that machine depends on.
APP="/Applications/KlaayGuard.app"
if [ -d "$APP" ]; then
  expect_plist=no
else
  expect_plist=yes
fi

# Move any existing plist aside and put it back on exit, so its presence is
# attributable to this run and the machine keeps what it had.
SAVED="$(mktemp -d)/plist"
if [ -f "$PLIST" ]; then
  mv "$PLIST" "$SAVED"
  restore_plist() { rm -f "$PLIST"; mv "$SAVED" "$PLIST"; }
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

# Contract of the seam:
#  1. it must NOT fall into the Tauri event loop (would be killed at 124), and
#  2. it must write the LaunchAgent plist only when this binary IS the installed
#     app. With no app in /Applications the seam writes the file; with one
#     installed, this debug build is a foreign writer and must refuse, or a
#     developer build could redirect the installed agent to its own server.
# The bootstrap/kickstart step is best-effort and only succeeds inside a GUI
# session (the .pkg postinstall guarantees that via `launchctl asuser`); from a
# headless shell it returns EIO, so we don't assert exit 0 here.
if [ "$code" -eq 124 ]; then
  echo "FAIL: binary did not exit within 10s (fell into the event loop)"
  exit 1
fi
if [ "$expect_plist" = yes ] && [ ! -f "$PLIST" ]; then
  echo "FAIL: no app in $APP, so the seam had to write $PLIST (exit code $code)"
  exit 1
fi
if [ "$expect_plist" = no ] && [ -f "$PLIST" ]; then
  echo "FAIL: $APP is installed, so this debug build had to refuse to write $PLIST"
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

if [ "$expect_plist" = yes ]; then
  echo "PASS: seam exited promptly (code $code), wrote the LaunchAgent plist, and took no lock"
else
  echo "PASS: seam exited promptly (code $code), refused to write a foreign LaunchAgent, and took no lock"
fi
