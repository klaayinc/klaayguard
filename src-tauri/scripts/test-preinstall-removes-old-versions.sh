#!/usr/bin/env bash
# Verifies the .pkg preinstall removes every earlier KlaayGuard install before
# Installer writes the new one.
#
# The payload only writes /Applications/KlaayGuard.app. A copy that a .dmg put
# in ~/Applications, a bundle under another name, and the files an older build
# left inside the bundle all outlive that write. So does the login entry that
# tauri-plugin-autostart wrote for v0.1.0 to v0.1.5. Each one is an earlier
# version the Mac still runs or starts.
#
# The test builds a fake volume in a temp directory and runs the preinstall
# against it, the way Installer does: `$3` names the volume. It never touches
# the real /Applications, and it replaces launchctl with a recorder.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

PREINSTALL="macos/scripts/preinstall"
test -f "$PREINSTALL" || { echo "FAIL: $PREINSTALL not found; the installer removes no earlier version"; exit 1; }
test -x "$PREINSTALL" || { echo "FAIL: $PREINSTALL is not executable; Installer will not run it"; exit 1; }

# Refuse to run with an empty workdir: every path below would then resolve to
# the real volume root.
workdir="$(mktemp -d)" || { echo "FAIL: mktemp -d failed; refusing to run with an empty workdir"; exit 1; }
cleanup() {
  pkill -f "^$workdir/" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

vol="$workdir/volume"

# A bundle with an Info.plist carrying `id`. The executable is a real Mach-O
# binary, because the stop anchors on the executable's own path, and a
# script's command line starts with its interpreter.
printf '#include <unistd.h>\nint main(void){for(;;)pause();return 0;}\n' > "$workdir/idle.c"
cc -o "$workdir/idle" "$workdir/idle.c" || { echo "FAIL: could not build the fake agent"; exit 1; }
make_bundle() {
  local app="$1" id="$2" exe="$3"
  mkdir -p "$app/Contents/MacOS"
  cp "$workdir/idle" "$app/Contents/MacOS/$exe"
  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>$id</string>
    <key>CFBundleExecutable</key>
    <string>$exe</string>
</dict>
</plist>
PLIST
}

current="$vol/Applications/KlaayGuard.app"
legacy_name="$vol/Applications/klaay.app"
spaced="$vol/Applications/KlaayGuard (1).app"
per_user="$vol/Users/alice/Applications/KlaayGuard.app"
other="$vol/Applications/Other.app"
make_bundle "$current" com.klaay.app KlaayGuard
make_bundle "$legacy_name" com.klaay.app klaay
make_bundle "$spaced" com.klaay.app KlaayGuard
make_bundle "$per_user" com.klaay.app KlaayGuard
make_bundle "$other" com.other.app Other
# A file only the older build shipped. Writing the payload over the bundle
# keeps it, and the new bundle's code signature then fails.
touch "$current/Contents/MacOS/left-by-an-older-build"

agents="$vol/Users/alice/Library/LaunchAgents"
mkdir -p "$agents"
# tauri-plugin-autostart (v0.1.0 to v0.1.5) named the job after the app.
cat > "$agents/KlaayGuard.plist" <<'PLIST'
<plist version="1.0"><dict><key>Label</key><string>KlaayGuard</string>
<key>ProgramArguments</key><array><string>/Applications/KlaayGuard.app/Contents/MacOS/KlaayGuard</string></array></dict></plist>
PLIST
# The current job. The postinstall rewrites and reloads it; the preinstall
# must leave it alone, or a failed install would leave no login start.
cat > "$agents/com.klaay.klaayguard.plist" <<'PLIST'
<plist version="1.0"><dict><key>Label</key><string>com.klaay.klaayguard</string></dict></plist>
PLIST
# A job of the same file name that some other app wrote.
mkdir -p "$vol/Users/bob/Library/LaunchAgents"
cat > "$vol/Users/bob/Library/LaunchAgents/KlaayGuard.plist" <<'PLIST'
<plist version="1.0"><dict><key>Label</key><string>KlaayGuard</string>
<key>ProgramArguments</key><array><string>/opt/elsewhere/tool</string></array></dict></plist>
PLIST

alive() { kill -0 "$1" 2>/dev/null; }

# Whether `pgrep -f` sees the process at its path, within two seconds. The
# preinstall finds agents that way, so a test that only checks the pid could
# pass while the preinstall has nothing to find.
seen() {
  local end=$((SECONDS + 2))
  until pgrep -f "^$1" >/dev/null 2>&1 || [ $SECONDS -ge $end ]; do sleep 0.1; done
  pgrep -f "^$1" >/dev/null 2>&1
}

"$current/Contents/MacOS/KlaayGuard" & current_pid=$!
"$per_user/Contents/MacOS/KlaayGuard" & per_user_pid=$!
"$other/Contents/MacOS/Other" & other_pid=$!
for exe in "$current/Contents/MacOS/KlaayGuard" "$per_user/Contents/MacOS/KlaayGuard" "$other/Contents/MacOS/Other"; do
  seen "$exe" || { echo "FAIL: the fake process $exe did not start"; exit 1; }
done

# Installer runs the script by its own name with the volume in $3. A copy
# under that name runs `main` the same way.
cp "$PREINSTALL" "$workdir/preinstall"
launchctl_log="$workdir/launchctl.log"
printf '#!/bin/bash\necho "$*" >> %q\n' "$launchctl_log" > "$workdir/launchctl"
chmod +x "$workdir/launchctl"

echo "==> the preinstall removes every earlier install on the volume"
out=$(LAUNCHCTL="$workdir/launchctl" STOP_WAIT_SECONDS=2 bash "$workdir/preinstall" "/tmp/x.pkg" "/" "$vol" 2>&1)
status=$?
echo "$out"
[ "$status" -eq 0 ] || { echo "FAIL: the preinstall exited $status; Installer stops the install"; exit 1; }

failures=0
fail() { echo "FAIL: $1"; failures=$((failures + 1)); }

for app in "$current" "$legacy_name" "$spaced" "$per_user"; do
  [ -e "$app" ] && fail "$app survived; the Mac keeps an earlier version"
done
[ -d "$other" ] || fail "the preinstall removed Other.app, which another app owns"

gone() {
  local end=$((SECONDS + 2))
  until ! alive "$1" || [ $SECONDS -ge $end ]; do sleep 0.1; done
  ! alive "$1"
}
gone "$current_pid" || fail "the agent in /Applications still runs from the deleted bundle"
gone "$per_user_pid" || fail "the agent in ~/Applications still runs from the deleted bundle"
alive "$other_pid" || fail "the preinstall stopped a process another app owns"

[ -e "$agents/KlaayGuard.plist" ] && fail "the tauri-plugin-autostart job survived; it starts an earlier build at login"
[ -f "$agents/com.klaay.klaayguard.plist" ] || fail "the preinstall removed the current LaunchAgent"
[ -f "$vol/Users/bob/Library/LaunchAgents/KlaayGuard.plist" ] \
  || fail "the preinstall removed a KlaayGuard.plist that does not start KlaayGuard"
grep -q "bootout gui/[0-9]*/KlaayGuard" "$launchctl_log" 2>/dev/null \
  || fail "the preinstall did not unload the tauri-plugin-autostart job"

kill "$other_pid" 2>/dev/null || true

echo "==> a second run on a clean volume is a no-op that succeeds"
LAUNCHCTL="$workdir/launchctl" bash "$workdir/preinstall" "/tmp/x.pkg" "/" "$vol" >/dev/null 2>&1 \
  || fail "the preinstall fails on a volume with no earlier install"

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "PASS: the preinstall removes every earlier bundle and the old login job, and spares what is not ours"
