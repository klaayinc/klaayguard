#!/usr/bin/env bash
# A macOS release uploads one installer, the .pkg, and fails when it cannot
# build that file. This runs the upload steps of release-macos.yml as they are
# written, with stand-ins for gh and the Apple tools, over a build directory
# that also holds a .dmg, as `cargo tauri build` leaves it.
#
# Run from the repository root: bash .github/scripts/test-macos-ships-only-pkg.sh
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }

repo="$PWD"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/bin"
cat > "$work/bin/gh" <<'STUB'
#!/bin/bash
# gh release upload <tag> <file>... --repo <repo> --clobber
shift 3
for arg in "$@"; do
  [ "$arg" = "--repo" ] && break
  echo "$arg" >> "$UPLOADS"
done
STUB
cat > "$work/bin/security" <<'STUB'
#!/bin/bash
[ "$1" = "find-identity" ] && echo '  1) ABC "Developer ID Installer: Test (TEAM)"'
exit 0
STUB
printf '#!/bin/bash\nexit 0\n' > "$work/bin/xcrun"
chmod +x "$work/bin/"*

# Write each step that uploads a release asset to its own script, with the
# universal staging values of the matrix filled in.
ruby -ryaml -e '
  job = YAML.load_file(ARGV[0]).dig("jobs", "build-upload")
  matrix = job.dig("strategy", "matrix", "include").find { |row| row["arch"] == "universal" }
  matrix = matrix.merge("build" => "staging")
  steps = job["steps"].select { |step| step["run"].to_s.include?("gh release upload") }
  steps.each_with_index do |step, index|
    script = step["run"].gsub(/\$\{\{ *matrix\.(\w+) *\}\}/) { matrix.fetch(Regexp.last_match(1)) }
    File.write(File.join(ARGV[1], "step-#{index}.sh"), script)
  end
  File.write(File.join(ARGV[1], "bundle-dir"), matrix.values.grep(%r{\Asrc-tauri/target}).first)
' "$repo/.github/workflows/release-macos.yml" "$work"

ls "$work"/step-*.sh >/dev/null 2>&1 || fail "no step uploads a release asset"

# run_release <installer certificate> -> runs every upload step in a fresh tree
run_release() {
  local tree="$work/tree"
  rm -rf "$tree"
  mkdir -p "$tree/src-tauri/scripts"
  local bundle
  bundle="$tree/$(cat "$work/bundle-dir")/release/bundle"
  mkdir -p "$bundle/macos/KlaayGuard.app" "$bundle/dmg"
  touch "$bundle/dmg/KlaayGuard_9.9.9_universal.dmg"
  printf '#!/bin/bash\ntouch "$3"\n' > "$tree/src-tauri/scripts/build-macos-pkg.sh"
  : > "$work/uploads"
  local step
  for step in "$work"/step-*.sh; do
    (
      cd "$tree"
      env PATH="$work/bin:$PATH" UPLOADS="$work/uploads" \
        VERSION=9.9.9 RELEASE_TAG=v9.9.9 GITHUB_REPOSITORY=klaayinc/klaayguard \
        APPLE_INSTALLER_CERTIFICATE="$1" APPLE_INSTALLER_CERTIFICATE_PASSWORD=test \
        KEYCHAIN_PASSWORD=test APPLE_ID=test APPLE_PASSWORD=test APPLE_TEAM_ID=test \
        bash "$step"
    ) > "$work/log" 2>&1 || return 1
  done
}

run_release "$(echo test | base64)" || { cat "$work/log"; fail "an upload step failed"; }
uploaded="$(cat "$work/uploads")"
[ "$uploaded" = "KlaayGuard_9.9.9_macOS_universal_staging.pkg" ] \
  || fail "the release uploads: $(echo $uploaded)"

if run_release ""; then
  fail "the macOS job passes with no installer certificate, so a release can hold no macOS installer"
fi

echo "PASS: a macOS release uploads only the .pkg, and fails without it"
