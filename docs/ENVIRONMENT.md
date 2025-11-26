# Environment Management

This document describes KlaayGuard's environment variable management system.

## Overview

KlaayGuard uses a centralized environment configuration system to prevent configuration drift across different deployment environments. All environment variables are defined in `.env.*` files and loaded consistently across build scripts, Rust code, and Vite.

## Environment Files

Environment files are located in the project root and follow this structure:

```
.env.defaults           # Safe defaults (committed)
.env.development        # Development environment (committed)
.env.staging           # Staging environment (committed)
.env.production        # Production environment (committed)
.env.*.local           # Local overrides (NOT committed, optional)
```

### Template Files

Template files are provided in `config/`:

- `config/env.defaults` - Copy to `.env.defaults`
- `config/env.development` - Copy to `.env.development`
- `config/env.staging` - Copy to `.env.staging`
- `config/env.production` - Copy to `.env.production`

### Setup

```bash
# Copy template files to create your local env files
cp config/env.development .env.development
cp config/env.staging .env.staging
cp config/env.production .env.production
cp config/env.defaults .env.defaults
```

## Environment Variables

### Required Variables

These variables must be defined in each environment file:

| Variable               | Description       | Example                                |
| ---------------------- | ----------------- | -------------------------------------- |
| `KLAAY_ENV`            | Environment name  | `development`, `staging`, `production` |
| `VITE_API_BASE_URL`    | Kiln API endpoint | `https://api.klaay.com`                |
| `VITE_EARTHENWARE_URL` | Login page URL    | `https://app.klaay.com`                |

### Optional Variables

These variables have safe defaults in `.env.defaults`:

| Variable                                 | Default | Description                       |
| ---------------------------------------- | ------- | --------------------------------- |
| `KLAAYGUARD_COLLECTION_INTERVAL_SECONDS` | `3600`  | Data collection interval (1 hour) |
| `VITE_SENTRY_DSN`                        | (empty) | Sentry error tracking DSN         |

### Build-time Variables

These are used during the build process:

| Variable                    | Description      | Set By          |
| --------------------------- | ---------------- | --------------- |
| `TAURI_SIGNING_PRIVATE_KEY` | Code signing key | CI/CD or manual |

## Environment-Specific Values

### Development

```bash
KLAAY_ENV=development
VITE_API_BASE_URL=http://localhost:3000
VITE_EARTHENWARE_URL=http://localhost:5173
```

### Staging

```bash
KLAAY_ENV=staging
VITE_API_BASE_URL=https://api.klaay.dev
VITE_EARTHENWARE_URL=https://app.klaay.dev
```

### Production

```bash
KLAAY_ENV=production
VITE_API_BASE_URL=https://api.klaay.com
VITE_EARTHENWARE_URL=https://app.klaay.com
```

## Usage

### Build Scripts

The `bin/build` script automatically loads the appropriate environment file based on the environment argument:

```bash
# Development build
bin/build development  # Loads .env.development

# Staging build
bin/build staging      # Loads .env.staging

# Production build
bin/build production   # Loads .env.production
```

### Development Server

The `bin/dev` script loads `.env.development`:

```bash
bin/dev  # Automatically loads .env.development
```

### Manual Override

You can override any variable at runtime:

```bash
# Override API URL for a single build
VITE_API_BASE_URL=http://custom:3000 bin/build development
```

### Local Overrides

Create `.env.development.local` (or `.env.staging.local`, `.env.production.local`) for developer-specific overrides. These files are automatically ignored by git:

```bash
# .env.development.local
VITE_API_BASE_URL=http://192.168.1.100:3000
VITE_SENTRY_DSN=https://your-dev-sentry-dsn
```

## How It Works

### 1. Loading Order

Environment variables are loaded in this order (later overrides earlier):

1. `.env.defaults` - Safe defaults
2. `.env.<KLAAY_ENV>` - Environment-specific values
3. `.env.<KLAAY_ENV>.local` - Local overrides (if exists)
4. System environment variables - Runtime overrides

### 2. Build Process

When you run `bin/build <env>`:

1. The script loads the corresponding `.env.<env>` file
2. Variables are exported to the shell environment
3. Rust's `build.rs` reads these variables
4. Vite reads `VITE_*` prefixed variables
5. Values are compiled into the binary

### 3. Runtime Behavior

The compiled binary uses values in this priority:

1. Runtime environment variables (if set)
2. Compiled-in defaults from build time
3. Hard-coded fallbacks (removed in this refactor)

## CI/CD Integration

### GitHub Actions

CI workflows automatically load environment files:

```yaml
- name: Build for staging
  run: ./bin/build staging # Loads .env.staging
```

### Secrets Management

For sensitive values in CI/CD:

1. Store in GitHub Secrets
2. Export before build:

```yaml
- name: Set environment
  env:
    VITE_SENTRY_DSN: ${{ secrets.SENTRY_DSN }}
    TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_PRIVATE_KEY }}
  run: |
    export VITE_SENTRY_DSN
    export TAURI_SIGNING_PRIVATE_KEY
    ./bin/build production
```

## Validation

### Build-time Validation

The build process validates required variables. If any are missing, the build fails with a clear error message.

### Manual Validation

Run the validation script to check all environment files:

```bash
node scripts/validate-env.js
```

This checks:

- All required variables are defined
- Variable names are correct
- Values are in valid formats
- No typos or missing files

## Troubleshooting

### Problem: API URL drift between environments

**Solution**: Check that all environment files define `VITE_API_BASE_URL` consistently. Run `node scripts/validate-env.js` to detect drift.

### Problem: Build uses wrong API URL

**Solution**: Verify you're using the correct build command:

```bash
# Wrong - doesn't specify environment
cargo tauri build

# Right - uses environment-specific config
bin/build production
```

### Problem: Local override not working

**Solution**: Ensure your `.env.*.local` file is named correctly and contains valid variable assignments. The file should not be committed to git.

### Problem: Variable not available at runtime

**Solution**: Only `VITE_*` prefixed variables are available in the frontend. Other variables are build-time only. For runtime access, they must be compiled in via `build.rs`.

## Migration from Old System

The old system used hard-coded values in multiple places:

1. `bin/build` - Hardcoded switch statements
2. `scripts/tauri-build.cjs` - Hardcoded defaults
3. `src-tauri/build.rs` - Hardcoded fallbacks

The new system:

1. Single source of truth in `.env.*` files
2. All scripts load from environment
3. No hard-coded values
4. Consistent behavior everywhere

## Best Practices

1. **Never commit secrets** - Use `.env.*.local` for sensitive data
2. **Keep templates updated** - When adding variables, update all template files
3. **Validate before commit** - Run `node scripts/validate-env.js`
4. **Document new variables** - Add them to this file's reference tables
5. **Use descriptive names** - Follow the `VITE_*` prefix convention for frontend variables
6. **Provide safe defaults** - Add reasonable defaults to `.env.defaults`
7. **Test all environments** - Build and test development, staging, and production

## References

- [Vite Environment Variables Guide](https://vitejs.dev/guide/env-and-mode.html)
- [12-Factor App Config](https://12factor.net/config)
- [Tauri Environment Variables](https://tauri.app/v1/guides/configuration/environments)


