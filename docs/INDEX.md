# KlaayGuard Documentation Index

Welcome to the KlaayGuard documentation! This index will help you find the information you need.

## Quick Start

- **[README.md](../README.md)** - Project overview, features, and quick start guide
- **[VERSION](../VERSION)** - Current version number

## Architecture & Design

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Comprehensive system architecture documentation
  - System design and components
  - Data flow diagrams
  - Authentication flow
  - Collection mechanism
  - Retry logic
  - Platform-specific details
  - Performance characteristics
  - Troubleshooting guide

## Implementation Details

- **[IMPLEMENTATION_SUMMARY.md](../IMPLEMENTATION_SUMMARY.md)** - Summary of the system tray refactoring
  - Changes made from React app to system tray-only
  - Before/after architecture comparison
  - Code reduction metrics
  - Migration path

## Configuration & Setup

- **[SENTRY_SETUP.md](SENTRY_SETUP.md)** - Sentry error tracking configuration
  - Environment variables
  - Backend configuration
  - Manual error reporting
  - Key events tracked
  - Troubleshooting
  - Best practices

## Development

### Build & Deploy

- **[scripts/tauri-build.cjs](../scripts/tauri-build.cjs)** - Build script with environment selection
- **[scripts/sync-version.js](../scripts/sync-version.js)** - Version synchronization script
- **[Rakefile](../Rakefile)** - osquery binary bundling

### Source Code

- **[src-tauri/src/lib.rs](../src-tauri/src/lib.rs)** - Main application logic
- **[src-tauri/src/keychain.rs](../src-tauri/src/keychain.rs)** - Secure token storage
- **[src-tauri/src/main.rs](../src-tauri/src/main.rs)** - Entry point

### Configuration Files

- **[src-tauri/tauri.conf.json](../src-tauri/tauri.conf.json)** - Main Tauri configuration
- **[src-tauri/tauri.development.json](../src-tauri/tauri.development.json)** - Development overrides
- **[src-tauri/tauri.staging.json](../src-tauri/tauri.staging.json)** - Staging overrides
- **[src-tauri/tauri.no-updater.json](../src-tauri/tauri.no-updater.json)** - Updater disabled
- **[src-tauri/Cargo.toml](../src-tauri/Cargo.toml)** - Rust dependencies

## Platform-Specific

### macOS

- **[src-tauri/Info.plist](../src-tauri/Info.plist)** - macOS app bundle configuration
- **[src-tauri/resources/com.klaay.klaayguard.plist](../src-tauri/resources/com.klaay.klaayguard.plist)** - LaunchAgent configuration

### Linux

- **[src-tauri/linux/klaayguard.desktop](../src-tauri/linux/klaayguard.desktop)** - Desktop entry and autostart

### Windows

- **[src-tauri/windows/hooks.nsi](../src-tauri/windows/hooks.nsi)** - NSIS installer hooks

## API Integration

### Endpoints

- `GET /me` - Token validation
- `GET /klaayguard/config` - Fetch collection queries
- `POST /klaayguard/data` - Submit collected data
- `GET /klaayguard/updates/latest` - Check for updates
- `GET /klaayguard/download/{asset_id}` - Download update

### Data Format

JSON:API compliant format:

```json
{
  "data": [
    {
      "type": "table_name",
      "attributes": {
        "field1": "value1",
        "field2": "value2"
      }
    }
  ],
  "meta": {
    "device_uuid": "serial-number"
  },
  "jsonapi": {
    "version": "1.0"
  }
}
```

## Key Concepts

### System Tray Application

KlaayGuard runs as a **system tray-only** application:
- No visible windows
- All interactions via tray menu
- Status displayed in tooltip
- Cannot be easily quit (security feature)

### Authentication Flow

1. Click "Login" in tray menu
2. Browser opens to Earthenware
3. User authenticates
4. Deep link callback: `klaayguard://auth-callback?token=JWT`
5. Token saved to system keychain

### Data Collection

1. Every hour (configurable)
2. Fetch queries from API
3. Execute via osquery
4. Send immediately to API
5. Update tray status

### Retry Mechanism

- 3 attempts with exponential backoff
- Delays: 60s, 120s, 240s
- Max delay: 600s (10 minutes)
- Retries on: network errors, 5xx, 429
- No retry on: 401/403 (invalidates token)

## Environment Variables

### Runtime

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `https://api.klaay.com` | Kiln API endpoint |
| `VITE_EARTHENWARE_URL` | `https://app.klaay.com` | Login page URL |
| `KLAAYGUARD_COLLECTION_INTERVAL_SECONDS` | `3600` | Collection frequency |
| `VITE_SENTRY_DSN` | (none) | Error tracking DSN |

### Build-time

| Variable | Description |
|----------|-------------|
| `KLAAY_ENV` | Environment (development/staging/production) |
| `TAURI_SIGNING_PRIVATE_KEY` | Code signing key |

## Commands Reference

### Development

```bash
# Run in development mode
VITE_API_BASE_URL=http://localhost:3000 cargo tauri dev

# Build for development
KLAAY_ENV=development node scripts/tauri-build.cjs

# Check code
cargo check --manifest-path=src-tauri/Cargo.toml

# Sync version across files
node scripts/sync-version.js
```

### Production

```bash
# Build for production
cargo tauri build

# Build for specific platform
cargo tauri build --target aarch64-apple-darwin
cargo tauri build --target x86_64-pc-windows-msvc
cargo tauri build --target x86_64-unknown-linux-gnu
```

### osquery Binaries

```bash
# Verify bundled binaries
rake verify

# Download fresh binaries
rake refresh_binaries

# Clean temporary files
rake clean

# Check download URLs
rake check_urls
```

## Troubleshooting

### Authentication Issues

1. **Token not saving**: Check keychain permissions
2. **401/403 errors**: Token expired, re-authenticate
3. **Deep link not working**: Check URL scheme registration

### Collection Issues

1. **No data collected**: Check authentication status
2. **osquery errors**: Verify binary is executable
3. **API errors**: Check network connectivity

### System Tray Issues

1. **Icon not showing**: Platform-specific (see ARCHITECTURE.md)
2. **Status not updating**: Check logs for errors
3. **Menu not working**: Verify app is running

## Getting Help

1. Check relevant documentation above
2. Review error logs (see ARCHITECTURE.md for locations)
3. Check Sentry dashboard for errors
4. Review git commit history for recent changes

## Contributing

When updating documentation:

1. Update relevant docs when code changes
2. Keep diagrams in sync with implementation
3. Test code examples before committing
4. Run `node scripts/sync-version.js` after version changes
5. Update IMPLEMENTATION_SUMMARY.md for major changes

## Documentation Standards

- Use Mermaid for diagrams
- Include code examples for complex concepts
- Keep platform-specific details separated
- Document environment variables
- Provide troubleshooting steps
- Update INDEX.md when adding new docs

