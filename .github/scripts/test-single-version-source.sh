#!/usr/bin/env bash
# The release tag is the only source of the version. The release workflows
# stamp it into src-tauri/Cargo.toml at build time. No file in the tree may
# hold a second copy that can drift from the tag.
#
# Run from the repository root: bash .github/scripts/test-single-version-source.sh
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }

[ ! -e VERSION ] || fail "VERSION exists; it drifts from the release tag"

if grep -qE '"version"[[:space:]]*:' src-tauri/tauri.conf.json; then
  fail "tauri.conf.json holds a version; Tauri reads it from Cargo.toml"
fi

CARGO_VERSION=$(awk -F'"' '/^version = /{print $2; exit}' src-tauri/Cargo.toml)
[ "$CARGO_VERSION" = "0.0.0" ] \
  || fail "Cargo.toml version is '$CARGO_VERSION'; it must be the 0.0.0 placeholder"

LOCK_VERSION=$(awk -F'"' '/^name = "KlaayGuard"$/{getline; print $2; exit}' src-tauri/Cargo.lock)
[ "$LOCK_VERSION" = "0.0.0" ] \
  || fail "Cargo.lock lists KlaayGuard $LOCK_VERSION; it must match the placeholder"

SELF=test-single-version-source.sh

if grep -rnE --exclude="$SELF" '(cat|Get-Content) VERSION' .github README.md CONTRIBUTING.md docs; then
  fail "something reads the VERSION file"
fi

if grep -rnE --exclude="$SELF" 'sed .*tauri\.conf\.json' .github; then
  fail "a workflow stamps tauri.conf.json; only Cargo.toml carries the version"
fi

echo "PASS: the release tag is the only source of the version"
