# Sentry Setup for KlaayGuard

This document describes how to set up and configure Sentry.io error tracking for the KlaayGuard system tray application.

## Overview

KlaayGuard uses Sentry for error tracking and monitoring in the Rust backend. This provides comprehensive error reporting and performance monitoring for the system tray application.

## Configuration

### Environment Variables

Create a `.env.development.local` or `.env.production.local` file in the project root:

```bash
# Sentry Configuration
VITE_SENTRY_DSN=your_sentry_dsn_here

# API Configuration
VITE_API_BASE_URL=http://localhost:3000
VITE_EARTHENWARE_URL=http://localhost:5173
```

### Backend Configuration

The backend Sentry configuration is in `src-tauri/src/main.rs`:

- **DSN**: Retrieved from `VITE_SENTRY_DSN` environment variable
- **Release**: Uses `sentry::release_name!()` macro (includes version and git hash)
- **PII**: Enabled for comprehensive debugging
- **Default Options**: Uses Sentry's default configuration

## Installation

### Backend Dependencies

The Rust dependency is already added to `Cargo.toml`:

```toml
sentry = "0.42.0"
```

No additional installation required.

## Usage

### Automatic Error Capture

Sentry is automatically initialized when the Rust application starts. All panics and errors are automatically captured.

### Manual Error Reporting

You can manually report errors and events:

```rust
use sentry::{self, Level};

// Capture a message
sentry::capture_message("Data collection completed", Level::Info);

// Capture an error
sentry::capture_message("Authentication failed", Level::Error);

// Add breadcrumbs for debugging context
fn add_breadcrumb(category: &str, message: &str, level: Level) {
    let mut data = std::collections::BTreeMap::new();
    data.insert(
        "ts".to_string(),
        serde_json::json!(chrono::Utc::now().to_rfc3339()),
    );
    sentry::add_breadcrumb(sentry::Breadcrumb {
        ty: "default".to_string(),
        category: Some(category.to_string()),
        message: Some(message.to_string()),
        level,
        data,
        ..Default::default()
    });
}
```

### Key Events Tracked

The application automatically tracks:

- **Authentication Events**:
  - `auth_token_saved` - Token successfully saved
  - `auth_token_cleared` - Token cleared
  - `auth_invalidated` - Authentication failed (401/403)
  - `auth_me_request_start` - `/me` API call initiated
  
- **Collection Events**:
  - `collection_config_fetch_start` - Starting config fetch
  - `collection_osquery_start` - Starting osquery execution
  - `collection_auth_invalidated_on_config` - Auth failed during config
  - `collection_auth_invalidated_on_post` - Auth failed during data send

- **Deep Link Events**:
  - `deep_link_token_saved` - Deep link authentication succeeded
  - `deep_link_invalid_token_shape` - Invalid token format
  
- **Architecture Events**:
  - `arch_mismatch` - Running wrong binary architecture (e.g., x86 on ARM)

## Testing

### Test Error Reporting

You can test Sentry integration by triggering an error:

```bash
# Run in development mode
VITE_SENTRY_DSN=your_dsn_here cargo tauri dev

# The app will log events to Sentry
# Check your Sentry dashboard for events
```

### Verify Configuration

Check the logs on startup for Sentry initialization:

```
Sentry initialized with DSN: https://...@sentry.io/...
```

## Development vs Production

- **Development**: Errors are logged to console and sent to Sentry
- **Production**: Errors are sent to Sentry with full context
- **No DSN**: If `VITE_SENTRY_DSN` is not set, Sentry is disabled

## Security Considerations

### PII (Personally Identifiable Information)

PII is enabled for comprehensive debugging. Configure data scrubbing in the Sentry dashboard:

1. Go to your project settings
2. Navigate to "Data Scrubbing"
3. Add rules to scrub sensitive fields

### Data to Consider Scrubbing

- API tokens (automatically filtered in requests)
- User emails (captured in error context)
- Device serial numbers (captured in metadata)
- System information (OS version, hardware)

## Architecture-Specific Events

### ARM vs x86 Detection

KlaayGuard detects when running on incorrect architecture:

```rust
#[cfg(target_os = "macos")]
{
    if std::env::var("KLAAY_ARCH_MISMATCH").ok().as_deref() == Some("1") {
        let built = std::env::var("KLAAY_ARCH_BUILT")
            .unwrap_or_else(|_| std::env::consts::ARCH.to_string());
        let host = std::env::var("KLAAY_ARCH_HOST")
            .unwrap_or_else(|_| "unknown".to_string());
        sentry::capture_message(
            &format!("arch_mismatch: built={} host={}", built, host),
            Level::Error
        );
    }
}
```

## Troubleshooting

### Common Issues

1. **No errors appearing in Sentry**:
   - Check that `VITE_SENTRY_DSN` is set correctly
   - Verify the DSN is valid and the project exists in Sentry
   - Check logs for "Sentry initialized" message

2. **Backend errors not captured**:
   - Verify `VITE_SENTRY_DSN` environment variable is set at build/run time
   - Check that the Rust application is running with the environment variable
   - Use `cargo tauri dev` with the DSN in your terminal

3. **Too many events**:
   - Adjust breadcrumb levels (use `Level::Debug` for verbose events)
   - Configure sample rate in Sentry dashboard
   - Filter events in Sentry dashboard settings

### Debug Mode

To see Sentry events in console:

```rust
// In src-tauri/src/main.rs, add debug flag
let _guard = sentry::init((dsn, sentry::ClientOptions {
    release: sentry::release_name!(),
    debug: true, // Enable debug logging
    ..Default::default()
}));
```

## Monitoring

Once configured, monitor in your Sentry dashboard:

- **Error Rates**: Track application stability
- **Breadcrumbs**: See event sequence leading to errors
- **Release Health**: Track errors by version
- **User Impact**: Identify most common issues
- **Performance**: Track API call latencies (if tracing enabled)

## Event Filtering

Configure event filters in your Sentry dashboard:

1. **Ignore List**: Filter out expected errors (e.g., network timeouts)
2. **Rate Limiting**: Limit duplicate events
3. **Environment Filters**: Separate dev/staging/production
4. **Release Filters**: Track specific versions

## Best Practices

1. **Use Breadcrumbs**: Add context before errors occur
2. **Meaningful Messages**: Use descriptive error messages
3. **Proper Levels**: Use appropriate severity levels
   - `Debug`: Verbose debugging info
   - `Info`: Informational events
   - `Warning`: Potential issues
   - `Error`: Actual errors
4. **Release Tracking**: Always deploy with version tags
5. **Regular Review**: Check Sentry dashboard weekly

## System Tray Integration

Sentry is particularly important for system tray applications since there's no visible UI to display errors. Key events to monitor:

- **Authentication Failures**: Check for 401/403 errors
- **API Connection Issues**: Monitor network failures
- **osquery Execution Errors**: Track data collection failures
- **Deep Link Issues**: Debug authentication flow problems

## Resources

- [Sentry Rust Documentation](https://docs.sentry.io/platforms/rust/)
- [Sentry Dashboard](https://sentry.io/)
- [Error Grouping](https://docs.sentry.io/product/data-management-settings/event-grouping/)
- [Performance Monitoring](https://docs.sentry.io/product/performance/)
