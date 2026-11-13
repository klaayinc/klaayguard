# Universal macOS build: trial report

Date: 2026-11-13. Machine: Apple silicon Mac, macOS 26. Branch: this PR.
This report covers step 1 of `fewer-release-variants.md` (sections 3, 8, 10
tests 1 and 2, and the appendix). It changes no workflow.

## Answer

One universal build works. `cargo tauri build --target universal-apple-darwin`
makes one app that holds both slices, one `.dmg`, and the `.pkg` script wraps
it with no change. Two things need a decision or a fix before release:

- The arch gate in `main.rs` reports a mismatch when the app runs under
  Rosetta on Apple silicon (section 5).
- Signing, notarization and a real Intel Mac were not tested (section 6).

## 1. Sidecar: Tauri does not merge

I removed `src-tauri/vendor/klaayguard-osqueryi-universal-apple-darwin` and
built again. The bundle step failed:

```
Error failed to bundle project Failed to copy external binaries: resource path `vendor/klaayguard-osqueryi-universal-apple-darwin` doesn't exist
```

Tauri compiles each arch, joins the main binary itself, and then needs a
sidecar file with the exact name `-universal-apple-darwin`. It does not join
the two per-arch sidecars. The file must already be fat. The shipped
`osqueryd-macos-bare` is fat (`lipo -archs`: `x86_64 arm64`), so one more `cp`
in the `Rakefile` is enough. That `cp` is the change in this PR.

## 2. Build

```
PATH=/opt/homebrew/opt/rustup/bin:$PATH KLAAY_ENV=production \
  cargo tauri build --target universal-apple-darwin
```

Exit 0. Both Rust targets were installed in the rustup toolchain. The shell
found the Homebrew `cargo` first, which has no `x86_64-apple-darwin` target.
The first run failed with `can't find crate for core`. Put the rustup `cargo`
first in `PATH`. CI does this with its own toolchain step.

Outputs under `src-tauri/target/universal-apple-darwin/release/bundle/`:

- `macos/KlaayGuard.app`
- `dmg/KlaayGuard_0.1.12_universal.dmg` (Tauri names the file `_universal`)

Compile time on this Mac, cold cache: the two slices took 2m27s and 1m46s
(cargo's `Finished` lines), plus the join and the bundle.

## 3. Measurements (test 1)

Bundle path: `…/bundle/macos/KlaayGuard.app`.

| Check | Command | Output |
|---|---|---|
| Main binary slices | `lipo -archs Contents/MacOS/KlaayGuard` | `x86_64 arm64` |
| Sidecar slices | `lipo -archs Contents/MacOS/klaayguard-osqueryi` | `x86_64 arm64` |
| Main binary, x86_64 | `vtool -arch x86_64 -show-build` | `LC_VERSION_MIN_MACOSX`, version 10.13 |
| Main binary, arm64 | `vtool -arch arm64 -show-build` | `LC_BUILD_VERSION`, minos 11.0 |
| Sidecar, x86_64 | same | minos 10.15 |
| Sidecar, arm64 | same | minos 11.0 |
| Bundle minimum | `PlistBuddy -c "Print :LSMinimumSystemVersion" Info.plist` | `10.13` |

The minimums match the v0.1.69 thin builds (arm64 11.0, x64 10.13) and the
sidecar (10.15 and 11.0). The universal build changes no minimum.
`tauri.conf.json` still sets none, so the bundle says 10.13 while the sidecar
needs 10.15 on Intel. That gap exists today.

Size against v0.1.69 arm64:

| Item | v0.1.69 arm64 | Universal | Change |
|---|---|---|---|
| `.app` (`du -sk`) | 128268 KB (installed copy on this Mac, version 0.1.69) | 148384 KB | +20116 KB, +15.7% |
| `.dmg` (bytes) | 32108642 (`gh release view v0.1.69`) | 41132809 | +9024167, +28.1% |
| `.pkg` (bytes) | 32228495 (`gh release view v0.1.69`) | 41284838 (unsigned) | +9056343, +28.1% |

The sidecar was already fat, so the `.app` grows only by the second slice of
the main binary (43104064 bytes for both).

## 4. The `.pkg`

```
bash src-tauri/scripts/build-macos-pkg.sh <KlaayGuard.app> 0.1.12 <out.pkg>
```

What the script assumes: any `.app` path, a version, an output path. It has no
arch or path assumption. `Distribution` already sets
`hostArchitectures="arm64,x86_64"`. It signs only if
`INSTALLER_SIGNING_IDENTITY` is set.

Result: built an unsigned `.pkg`. `pkgutil --expand-full` shows the payload
`component.pkg/Payload/Applications/KlaayGuard.app` with `lipo -archs` =
`x86_64 arm64` for the main binary and the sidecar.

Not done: signing, notarization, `stapler validate`, `spctl --assess`.
`security find-identity -v -p codesigning` prints `0 valid identities found`
here. The CI certificates are not on this Mac, and I did not work around that.
The app out of the build is ad-hoc signed (`codesign -dv`: `Signature=adhoc`,
`Format=app bundle with Mach-O universal (x86_64 arm64)`).

## 5. Run (test 2, local part)

I copied the app to a scratch folder and ran the binary with `HOME` set to an
empty folder. This keeps the lock file `agent.lock` apart from the installed
v0.1.69 agent that runs on this Mac (its lock is the same production name).

Native, Apple silicon, three runs of 12 to 15 seconds:

- One process of the copy (`pgrep -f` printed one pid).
- stderr empty. No `arch_mismatch` in the log. The log says
  `KlaayGuard configured as background service - tray only, hidden from dock`.
- The app then asked for sign-in and opened `https://app.klaay.com/login?...`
  in the browser each run. Expected with no token.
- `keychain: token load failed: A default keychain could not be found`. This
  comes from the empty `HOME`, not from the build.

Under Rosetta (`arch -x86_64 …/KlaayGuard`):

- The gate reports a mismatch. stderr:
  `Architecture mismatch: app built for x86_64 but running on arm64 (Apple Silicon) hardware. Please install the arm64 build of KlaayGuard.`
- The log has `arch_mismatch built=x86_64 host=arm64 (Apple Silicon)`.
- The app shows the native dialog ("KlaayGuard was built for x86_64 …") and
  does not start the collection loop (`lib.rs` lines 5639-5656).
- Cause: Rosetta runs the x86_64 slice, so `std::env::consts::ARCH` is
  `x86_64`, and `sysctl hw.optional.arm64` still returns 1.

Not verified:

- The tray icon. The screenshot of this session was black, so I could not
  see the menu bar. The log shows the tray-only setup ran. It does not show
  the icon.
- A posture report reaching kiln. The run had no sign-in.
- A real Intel Mac. On Intel the x86_64 slice runs with `hw.optional.arm64`
  = 0, which the gate accepts, by the code. Not run.
- macOS 10.13 or 10.14.

## 6. What a real change touches

Checked against the appendix of the proposal and the files in this tree.
Line numbers are from this branch.

Done in this PR:

- `Rakefile` line 223: `cp #{OSQUERYD_PATH} #{OSQUERYI_PATH}-universal-apple-darwin`.
- `Rakefile` line 276: add `"#{OSQUERYI_PATH}-universal-apple-darwin"` to
  `vendor_binaries`, so `verify` checks it. `fetch` (line 332) needs no edit:
  it invokes the `OSQUERYI_PATH` task that now makes the file.

Not in this PR (the task forbids workflow changes):

- `.github/workflows/release-macos.yml`
  - Matrix lines 23-41: replace `arch: [arm64, x64]` and its two includes with
    one entry: `target: universal-apple-darwin`,
    `dmg_dir: src-tauri/target/universal-apple-darwin`,
    `artifact_suffix: macOS_universal`.
  - Line 48 (`targets: aarch64-apple-darwin,x86_64-apple-darwin`): keep. The
    universal build needs both.
  - Lines 81-82: add `test -f src-tauri/vendor/klaayguard-osqueryi-universal-apple-darwin`.
  - Line 67 cache key `${{ matrix.target }}-release`: becomes
    `universal-apple-darwin-release`. It then holds both arch target
    folders. Not tested.
  - Lines 126, 151, 193: no edit. `--target`, `dmg_dir` and the `find` calls
    follow the matrix.
  - Line 170: the `.pkg` name uses `artifact_suffix`, so it becomes
    `KlaayGuard_<v>_macOS_universal_<env>.pkg`.
  - Line 199: the `.dmg` copy must make two files from the one universal
    `.dmg`: `KlaayGuard_<v>_macOS_arm64_<env>.dmg` and
    `KlaayGuard_<v>_macOS_x64_<env>.dmg`.
- `.github/workflows/windows-installer-artifact.yml`: matrix lines 186-192
  and the `.dmg` and `.pkg` names (lines 290 and 295) change the same way.
- `.github/workflows/ci.yml` lines 154-157: no rename. Branch protection
  needs `Build (aarch64-apple-darwin)` and `Build (x86_64-apple-darwin)`. CI
  then never builds the universal target. The appendix does not list a new
  job. A job that runs this trial is a decision for Emil.
- `src-tauri/src/main.rs` lines 77-81: the gate. The arm `(true, "x86_64")`
  fires under Rosetta. It must not fire for a universal build. Choose one:
  drop that arm, or skip the check when `proc_translated` is 1. Under
  Rosetta the app then runs translated, as a thin x64 build does today.
- `src-tauri/src/lib.rs`: no edit for step 1. `select_dmg_asset` (line 3905)
  keeps `.dmg` plus `macOS_arm64` or `macOS_x64`, so each old updater finds
  its name. The updater work (`SelectedUpdate` line 3827, path line 4728,
  `hdiutil` line 5168) belongs to step 2.
- `src-tauri/tauri.conf.json`: optional, `bundle.macOS.minimumSystemVersion`
  = `10.15` states the real Intel limit. Not tested here.
- kiln `app/lib/github_releases.rb`, kiln `downloads_controller.rb`,
  earthenware2 `src/utils/klaayguard.ts` and `KlaayGuardCard.vue`: the
  appendix lists them. `macOS_universal` has neither `_x64_` nor
  `_arm64_`, so kiln gives it no label today. Deploy kiln and the Hub first
  (section 8 of the proposal). I did not open these repos.
- Docs: README, `docs/OVERVIEW.md`, `docs/EMPLOYEE_GUIDE.md`, the comment in
  `src-tauri/macos/scripts/postinstall`. The appendix lists them. Not
  checked here.

## 7. Asset names to use

Per environment `<env>` in `development`, `staging`, `production`:

| Asset | Name |
|---|---|
| Universal `.pkg` | `KlaayGuard_<v>_macOS_universal_<env>.pkg` |
| Universal `.dmg`, old arm64 name | `KlaayGuard_<v>_macOS_arm64_<env>.dmg` |
| Universal `.dmg`, old x64 name | `KlaayGuard_<v>_macOS_x64_<env>.dmg` |

The two `.dmg` files are the same bytes. Tauri names its output
`KlaayGuard_<bundle version>_universal.dmg`, so the workflow must rename it.

## 8. Open after this trial

- Real Intel Mac test (install, one process, tray, posture report).
- Signed, notarized `.pkg`: `codesign --verify --deep --strict`, `spctl`,
  `stapler validate`. Needs the CI certificates.
- Tray icon on screen, and a posture report to kiln, on Apple silicon.
- The gate fix in `main.rs`.
- macOS 10.13 and 10.14 behavior.
