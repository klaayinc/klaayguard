# Sentry Setup for KlaayGuard

This document describes how to set up and configure Sentry.io error tracking for the KlaayGuard application.

## Overview

KlaayGuard uses Sentry for error tracking and monitoring across both the React frontend and Rust backend. This provides comprehensive error reporting and performance monitoring.

## Configuration

### Environment Variables

Create a `.env.local` file in the project root with the following variables:

```bash
# Sentry Configuration
VITE_SENTRY_DSN=your_sentry_dsn_here

# API Configuration
VITE_API_BASE_URL=http://localhost:3000
```

### Frontend Configuration

The frontend Sentry configuration is located in `src/sentry.ts`:

- **DSN**: Retrieved from `VITE_SENTRY_DSN` environment variable
- **Environment**: Set to the current Vite mode (development/production)
- **Release**: Uses `VITE_APP_VERSION` or defaults to package version
- **Sample Rate**: 100% for comprehensive error tracking
- **Integrations**: Browser tracing for performance monitoring

### Backend Configuration

The backend Sentry configuration is in `src-tauri/src/main.rs`:

- **DSN**: Retrieved from `VITE_SENTRY_DSN` environment variable
- **Release**: Uses `sentry::release_name!()` macro
- **PII**: Enabled for comprehensive debugging
- **Default Options**: Uses Sentry's default configuration

## Installation

### Frontend Dependencies

```bash
npm install @sentry/react @sentry/tracing
```

### Backend Dependencies

The Rust dependency is already added to `Cargo.toml`:

```toml
sentry = "0.42.0"
```

## Usage

### Frontend

Sentry is automatically initialized when the app starts. You can manually report errors:

```typescript
import { Sentry } from "../sentry";

// Report an error
Sentry.captureException(new Error("Something went wrong"));

// Report a message
Sentry.captureMessage("User performed action", "info");
```

### Backend

Sentry is automatically initialized when the Rust application starts. Errors are automatically captured, but you can also manually report:

```rust
use sentry;

// Report an error
sentry::capture_error(&error);

// Report a message
sentry::capture_message("Something happened", sentry::Level::Info);
```

## Testing

A test component is available at `src/components/common/SentryTestButton.tsx` that provides buttons to test both error reporting and message capture.

## Development vs Production

- **Development**: Errors are logged to console and sent to Sentry
- **Production**: Errors are sent to Sentry with full context

## Security Considerations

- **PII**: Personally Identifiable Information is captured (configurable)
- **Data Scrubbing**: Configure in Sentry dashboard to scrub sensitive data
- **Release Tracking**: Each release is tracked for better error context

## Troubleshooting

### Common Issues

1. **No errors appearing in Sentry**:

   - Check that `VITE_SENTRY_DSN` is set correctly
   - Verify the DSN is valid and the project exists in Sentry

2. **Frontend errors not captured**:

   - Ensure Sentry is initialized before React renders
   - Check browser console for Sentry initialization errors

3. **Backend errors not captured**:
   - Verify `VITE_SENTRY_DSN` environment variable is set
   - Check that the Rust application is running with the environment variable

### Debug Mode

To enable debug logging for Sentry:

```typescript
// In src/sentry.ts
Sentry.init({
  // ... other options
  debug: true, // Enable debug logging
});
```

## Monitoring

Once configured, you can monitor:

- **Error Rates**: Track application stability
- **Performance**: Monitor app performance with tracing
- **Release Health**: Track errors by release version
- **User Impact**: See which errors affect users most

## Resources

- [Sentry React Documentation](https://docs.sentry.io/platforms/javascript/guides/react/)
- [Sentry Rust Documentation](https://docs.sentry.io/platforms/rust/)
- [Sentry Dashboard](https://sentry.io/)
