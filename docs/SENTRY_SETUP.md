# Sentry Setup for KlaayGuard

This document describes how Sentry error tracking is configured for the
KlaayGuard agent.

## Overview

KlaayGuard is a Rust-only Tauri app. There is no frontend, so there is no
JavaScript Sentry SDK. All reporting comes from the Rust process, configured
in `src-tauri/src/main.rs`.

The agent sends:

- panics and errors, with stack traces;
- lifecycle messages (collection start, `sign_in_token_saved`, update steps)
  that make remote debugging possible without log access.

It never sends collected osquery data.

## Configuration

Configuration lives in `src-tauri/src/main.rs`:

- **DSN:** read from the `VITE_SENTRY_DSN` environment variable at process
  start. When the variable is empty, Sentry is off.

  > **Note:** CI sets `VITE_SENTRY_DSN` only in the *build* environment
  > (`.github/workflows/release-macos.yml`). Nothing bakes it into the binary
  > (`build.rs` does not handle it) and the LaunchAgent plist does not pass it
  > at runtime. Released builds therefore start without a DSN, and Sentry is
  > off in production. It is not recorded whether this is intentional. To turn
  > it on, bake the DSN in `build.rs` (as done for the API URLs) or add it to
  > the plist's `EnvironmentVariables`.
- **Environment:** the `KLAAY_ENV` value (`production`, `staging`,
  `development`).
- **Release:** set from the crate version with `sentry::release_name!()`.
- **PII:** `send_default_pii: false`. Crash telemetry must not carry client
  IPs or user identifiers. Do not enable this without a documented decision.
- **Stack traces:** `attach_stacktrace: true`.
- **Tags:** `component`, `os`, `arch`, and `app_version`.

The Rust dependency is declared in `src-tauri/Cargo.toml`:

```toml
sentry = "0.42.0"
```

## Usage

Sentry initializes before the Tauri app starts. Panics are captured
automatically through the panic hook. Report manually with:

```rust
// Report an error
sentry::capture_error(&error);

// Report a message
sentry::capture_message("Something happened", sentry::Level::Info);
```

## Local testing

```bash
VITE_SENTRY_DSN=<your-dsn> KLAAY_ENV=development cargo tauri build
open src-tauri/target/release/bundle/macos/KlaayGuard.app
```

Then check the Sentry project for the startup lifecycle messages.

## Troubleshooting

No events appear in Sentry:

1. Confirm `VITE_SENTRY_DSN` was set **when the process started**. The DSN is
   read at startup, not at build time, unless CI baked it in.
2. Confirm the DSN is valid and the project exists in Sentry.
3. Check the local log at `~/Library/Logs/com.klaay.app/KlaayGuard.log` —
   panics are written there even when Sentry is off.

## Resources

- [Sentry Rust Documentation](https://docs.sentry.io/platforms/rust/)
- [Sentry Dashboard](https://sentry.io/)
