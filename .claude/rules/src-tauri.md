---
paths:
  - 'src-tauri/**'
---

# The Rust app in `src-tauri`

Read this before you change Rust code or run a build in `src-tauri`.

## Checks before a push

CI (`.github/workflows/ci.yml`) runs three separate gates in `src-tauri`. Each one passes or fails
on its own.

- `cargo test`
- `cargo fmt --all --check`
- `cargo clippy --all-targets -- -D warnings`

`cargo build`, `cargo clippy` and `cargo test` pass on unformatted code. Only `cargo fmt` catches
formatting. Run all three gates before you push or commit. A warning fails CI. Fix the cause. If a
warning must stay, add `#[allow(...)]` with a comment that says why.

## A fresh worktree has no sidecars

`src-tauri/vendor/` is git-ignored, except `.keep` and `licenses`. `src-tauri/tauri.conf.json`
lists `vendor/klaayguard-osqueryi` under `externalBin`. Tauri resolves it at build time. A new
worktree has no such file, so `cargo build`, `cargo test` and `cargo clippy` all fail.

Link the `klaayguard-osqueryi-*` files from the main checkout's `src-tauri/vendor/` into the
worktree's `src-tauri/vendor/`. This avoids a second download by `rake fetch`. The links stay
untracked.

## A test of the binary must not start the tray

`run()` in `src-tauri/src/lib.rs` handles the CLI seams `--forget-credentials` and
`--install-agent` first and exits. Any other start goes on to the tray and the Tauri event loop,
which never exits.

- Add a new non-UI mode as a seam in `run()`, before the lock and the Tauri builder.
- Add the seam before the first test that calls it. A test of a mode that does not exist hangs
  and does not fail.
- Bound every test that starts the binary with a timeout. `src-tauri/scripts/test-install-agent-seam.sh`
  shows the pattern: it treats exit code 124 as a failure.

## Review rules

- Flag a Rust change in `src-tauri` that `cargo fmt --all --check` would reformat.
- Flag a new `#[allow(...)]` that has no comment giving the reason.
- Flag a test that starts the `KlaayGuard` binary in a mode that reaches the Tauri event loop.
- Flag a test that starts the binary with no timeout.
- Flag a new CLI flag handled after the single-instance lock or the Tauri builder in `run()`.
