# Building KlaayGuard

This document describes how to build KlaayGuard for different environments using the `bin/build` script.

## Quick Start

```bash
# Build for development (debug mode, localhost API)
./bin/build development

# Build for staging (release mode, staging API)
./bin/build staging

# Build for production (release mode, production API)
./bin/build production
```

## Environments

### Development

- **API URL**: `http://localhost:3000`
- **Earthenware URL**: `http://localhost:5173`
- **Build Mode**: Debug (unoptimized, with debug symbols)
- **Config**: `src-tauri/tauri.development.json`
- **Product Name**: `KlaayGuard-Dev`
- **Bundle ID**: `com.klaay.app.dev`

Used for local development and testing. The debug build is faster to compile but larger and slower to run.

### Staging

- **API URL**: `https://api.klaay.dev`
- **Earthenware URL**: `https://app.klaay.dev`
- **Build Mode**: Release (optimized)
- **Config**: `src-tauri/tauri.staging.json`
- **Product Name**: `KlaayGuard-Staging`
- **Bundle ID**: `com.klaay.app.staging`

Used for pre-production testing. Fully optimized build connecting to staging infrastructure.

### Production

- **API URL**: `https://api.klaay.com`
- **Earthenware URL**: `https://app.klaay.com`
- **Build Mode**: Release (optimized)
- **Config**: `src-tauri/tauri.conf.json`
- **Product Name**: `KlaayGuard`
- **Bundle ID**: `com.klaay.app`

Used for production releases. Fully optimized build connecting to production infrastructure.

## Build Process

The `bin/build` script:

1. Validates the environment argument
2. Sets environment variables:
   - `KLAAY_ENV`: Controls API URL selection in `build.rs`
   - `VITE_API_BASE_URL`: Explicit API URL (optional)
   - `VITE_EARTHENWARE_URL`: Earthenware frontend URL
3. Selects the appropriate Tauri config file
4. Runs `cargo tauri build` with the correct flags
5. Reports the location of build artifacts

## Build Output

### macOS

```
src-tauri/target/{debug|release}/bundle/
├── macos/
│   └── KlaayGuard*.app
└── dmg/
    └── KlaayGuard*.dmg
```

### Linux

```
src-tauri/target/{debug|release}/bundle/
├── appimage/
│   └── KlaayGuard*.AppImage
└── deb/
    └── KlaayGuard*.deb
```

### Windows

```
src-tauri/target/{debug|release}/bundle/
├── msi/
│   └── KlaayGuard*.msi
└── nsis/
    └── KlaayGuard*.exe
```

## CI/CD Usage

The `bin/build` script is designed to work in CI/CD pipelines without any interactive prompts.

### GitHub Actions Examples

See `.github/workflows/` for complete examples:

- `build-staging.yml`: Builds for staging on push to main/staging branches
- `build-production.yml`: Builds for production on version tags

### Basic CI/CD Integration

```yaml
- name: Build for staging
  run: ./bin/build staging

- name: Upload artifacts
  uses: actions/upload-artifact@v4
  with:
    name: klaayguard-staging
    path: src-tauri/target/release/bundle/
```

## Environment Variable Reference

### Build-time Variables

These are set by `bin/build` and consumed by `build.rs`:

| Variable | Development | Staging | Production |
|----------|-------------|---------|------------|
| `KLAAY_ENV` | `development` | `staging` | `production` |
| `VITE_API_BASE_URL` | `http://localhost:3000` | `https://api.klaay.dev` | `https://api.klaay.com` |
| `VITE_EARTHENWARE_URL` | `http://localhost:5173` | `https://app.klaay.dev` | `https://app.klaay.com` |

### Runtime Variables

These can be set when running the built app (development only):

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_DEFAULT_API_BASE_URL` | From `KLAAY_ENV` | Override API base URL |
| `KLAAYGUARD_COLLECTION_INTERVAL_SECONDS` | `3600` | Data collection interval in seconds |
| `RUST_LOG` | `info` | Logging level |

**Note**: Runtime environment variables only work for development builds launched via Launch Agent. Production and staging builds have the API URL compiled in.

## Local Development vs Production Builds

### `bin/dev` (Local Development)

- **Purpose**: Rapid iteration during development
- **Build Mode**: Debug
- **Features**:
  - Fast compilation (no optimizations)
  - Installs Launch Agent for auto-restart
  - Registers URL scheme for deep links
  - Sets development environment variables
- **Output**: `/Applications/KlaayGuard-Dev.app`

### `bin/build development` (Development CI/CD)

- **Purpose**: Testing development builds in CI/CD
- **Build Mode**: Debug
- **Features**:
  - Same API URLs as `bin/dev`
  - No Launch Agent installation
  - No URL scheme registration
  - Suitable for automated testing
- **Output**: `src-tauri/target/debug/bundle/`

### `bin/build staging` (Staging Release)

- **Purpose**: Pre-production testing
- **Build Mode**: Release (optimized)
- **Features**:
  - Staging API URLs
  - Fully optimized build
  - Ready for distribution
- **Output**: `src-tauri/target/release/bundle/`

### `bin/build production` (Production Release)

- **Purpose**: Public release
- **Build Mode**: Release (optimized)
- **Features**:
  - Production API URLs
  - Fully optimized build
  - Code signing ready
  - Ready for distribution
- **Output**: `src-tauri/target/release/bundle/`

## Code Signing

For production and staging builds, you'll need to configure code signing:

### macOS

Set environment variables in CI/CD:

```bash
export APPLE_CERTIFICATE_BASE64="..."
export APPLE_CERTIFICATE_PASSWORD="..."
export APPLE_ID="..."
export APPLE_PASSWORD="..."
export APPLE_TEAM_ID="..."
```

### Windows

Configure in CI/CD:

```bash
export WINDOWS_CERTIFICATE_BASE64="..."
export WINDOWS_CERTIFICATE_PASSWORD="..."
```

## Troubleshooting

### Build Fails with "Rust not found"

Install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build Fails with "Tauri CLI not found"

The script will attempt to install it automatically, but you can install manually:

```bash
cargo install tauri-cli --version "^2.0.0"
```

### Wrong API URL at Runtime

Check the build logs for warnings showing which `KLAAY_ENV` and API URL were used:

```
warning: KlaayGuard@0.1.12: KLAAY_ENV: production
warning: KlaayGuard@0.1.12: final api_base: https://api.klaay.com
```

If incorrect, ensure you're passing the right environment argument to `bin/build`.

### macOS: "App is damaged and can't be opened"

For development builds, you may need to remove the quarantine attribute:

```bash
xattr -cr /Applications/KlaayGuard-Dev.app
```

For production, ensure proper code signing.

## Performance Comparison

| Build Mode | Compilation Time | Binary Size | Runtime Performance |
|------------|------------------|-------------|---------------------|
| Debug | ~1-2 minutes | ~50-100 MB | Slower (no optimizations) |
| Release | ~5-10 minutes | ~10-20 MB | Fast (full optimizations) |

## Next Steps

- For local development workflow, see [ARCHITECTURE.md](ARCHITECTURE.md)
- For autostart and keep-alive setup, see [AUTOSTART_AND_KEEPALIVE.md](AUTOSTART_AND_KEEPALIVE.md)
- For deep link authentication, see [../earthenware2/docs/KLAAYGUARD_AUTH_FLOW.md](../../earthenware2/docs/KLAAYGUARD_AUTH_FLOW.md)

