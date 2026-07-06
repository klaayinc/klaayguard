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

echo "==> Building debug binary"
cargo build --bin KlaayGuard >/dev/null

# Remove any pre-existing plist so its presence is attributable to this run.
rm -f "$PLIST"

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

echo "PASS: seam exited promptly (code $code) and wrote the LaunchAgent plist"
