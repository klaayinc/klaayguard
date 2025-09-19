# KlaayGuard

[![Built with Tauri](https://img.shields.io/badge/built%20with-Tauri-FFC131.svg?logo=tauri)](https://tauri.app)

**KlaayGuard** is a cross-platform desktop security monitoring application that collects system information using osquery and reports it to a centralized API for security analysis.

## 🎯 Purpose

KlaayGuard automatically:

- Installs and manages osquery on Windows, macOS, and Linux
- Collects system security data (processes, network connections, installed software, etc.)
- Reports data to your configured API every 15 minutes (defaults to `http://localhost:3000`)
- Runs as a system tray application for background monitoring
- Provides authentication and secure data transmission

## 🚀 Quick Start

## Downloading a precompiled dev build (Mac)

1. navigate to https://github.com/klaayinc/klaayguard/releases

2. look for the most recent "dev" release

3. download the appropriate package, this will probably be klaay_XXX_aarch64.dmg for apple silicon macs

4. install the package

## Compile dev build (Linux)

1. clone the repo:
   ```bash
   git clone https://github.com/klaayinc/klaayguard.git
   cd klaayguard
   ```

### Prerequisites

```bash
# Install Node.js (v22+ recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 22
nvm use 22

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install Tauri CLI
cargo install tauri-cli

# Install Yarn (if not using npm)
npm install -g yarn
```

### Setup & Development

```bash
# Clone and setup
git clone https://github.com/klaayinc/klaayguard.git
cd klaayguard

# Install dependencies
yarn install

# Run in development (uses http://localhost:3000 by default; CI overrides with env)
yarn tauri dev
```

### Build for Production

```bash
# Build for current platform
yarn tauri build

# Build for specific platforms
yarn tauri build --target x86_64-pc-windows-msvc    # Windows
yarn tauri build --target aarch64-apple-darwin      # macOS Apple Silicon
yarn tauri build --target x86_64-apple-darwin       # macOS Intel
yarn tauri build --target x86_64-unknown-linux-gnu  # Linux
```

## 🏗️ Multi-Platform Support

### Windows

- **Target**: `x86_64-pc-windows-msvc`
- **osquery**: Installed via Chocolatey package manager
- **Features**: System tray, background monitoring

### macOS

- **Targets**: `aarch64-apple-darwin` (Apple Silicon), `x86_64-apple-darwin` (Intel)
- **osquery**: Installed via official PKG installer
- **Features**: System tray, background monitoring, auto-start on login

### Linux

- **Target**: `x86_64-unknown-linux-gnu`
- **osquery**: Supports apt (Debian/Ubuntu), dnf (Fedora), zypper (SUSE)
- **Features**: System tray, background monitoring

### Mobile (Tauri 2.0)

- **iOS**: `aarch64-apple-ios`
- **Android**: `aarch64-linux-android`

## 📁 Project Structure

```
klaayguard/
├── src-tauri/           # Rust backend (Tauri)
│   ├── src/
│   │   ├── lib.rs       # Main application logic
│   │   ├── main.rs      # Entry point
│   │   └── osquery/     # osquery installation & management
│   ├── Cargo.toml       # Rust dependencies
│   └── tauri.conf.json  # Tauri configuration
├── src/                 # React frontend
│   ├── components/      # UI components
│   ├── pages/          # Application pages
│   ├── context/        # React context providers
│   └── constants/      # API configuration
├── package.json        # Node.js dependencies
└── vite.config.ts      # Vite configuration
```

## 🔧 Configuration

### Environment Variables (required)

The app does not hardcode endpoint fallbacks. Provide these envs at build/dev time. CI sets them for releases via matrix and workflow env.

```bash
# .env for local development
VITE_API_BASE_URL=http://localhost:3000
VITE_EARTHENWARE_URL=http://localhost:5173

# Sentry Configuration (optional but recommended)
VITE_SENTRY_DSN=your_sentry_dsn_here
```

### API Endpoints

- **Config**: `GET /klaayguard/config` - Fetch monitoring configuration
- **Data**: `POST /klaayguard/data` - Submit collected system data

## 🛠️ Development Commands

```bash
# Development
yarn dev                 # Start Vite dev server
yarn tauri dev          # Start Tauri development

# Building
yarn build              # Build frontend
yarn tauri build        # Build desktop app
yarn tauri build --release  # Build optimized release

# Platform-specific builds
yarn tauri build --target x86_64-pc-windows-msvc
yarn tauri build --target aarch64-apple-darwin
yarn tauri build --target x86_64-unknown-linux-gnu

# Version management
yarn sync-version       # Sync version across all files
yarn version            # Alias for sync-version
```

## 📋 Version Management

KlaayGuard uses a single source of truth for version management:

### Single Source of Truth

- **VERSION file**: Contains the canonical version number (e.g., `0.1.1`)
- **Automatic sync**: All files are automatically synchronized when building
- **No conflicts**: Eliminates version mismatches between package.json, tauri.conf.json, and Cargo.toml

### How to Update Version

1. **Edit VERSION file**:

   ```bash
   echo "0.1.2" > VERSION
   ```

2. **Sync across all files**:

   ```bash
   yarn sync-version
   ```

3. **Verify synchronization**:
   ```bash
   cat VERSION                    # Should show 0.1.2
   node -p "require('./package.json').version"  # Should show 0.1.2
   node -p "require('./src-tauri/tauri.conf.json').version"  # Should show 0.1.2
   grep '^version =' src-tauri/Cargo.toml  # Should show version = "0.1.2"
   ```

### Files Updated by sync-version

- `package.json` - Node.js package version
- `src-tauri/tauri.conf.json` - Tauri application version
- `src-tauri/Cargo.toml` - Rust crate version

### GitHub Actions Integration

The CI/CD pipeline automatically:

- Reads version from VERSION file
- Syncs versions before building
- Uses consistent versioning for all artifacts
- Creates properly named release assets

## 🔒 Security Features

- **JWT Authentication**: Secure API communication
- **System Integration**: Native osquery installation
- **Background Operation**: System tray with show/hide/quit
- **Auto-Start**: Automatic startup on macOS login (mandatory)
- **Data Encryption**: HTTPS transmission to API
- **Cross-platform**: Consistent security monitoring across platforms

## 📊 Error Monitoring

KlaayGuard includes comprehensive error monitoring and performance tracking using Sentry.io:

- **Frontend Monitoring**: React application errors and performance
- **Backend Monitoring**: Rust application errors and system issues
- **Real-time Alerts**: Immediate notification of critical errors
- **Release Tracking**: Monitor error rates by application version
- **Performance Insights**: Track application performance metrics

### Setup Error Monitoring

1. **Create Sentry Project**: Sign up at [sentry.io](https://sentry.io) and create a new project
2. **Configure DSN**: Add your Sentry DSN to environment variables
3. **Deploy**: Errors will be automatically tracked in production

For detailed setup instructions, see [docs/SENTRY_SETUP.md](docs/SENTRY_SETUP.md).

## 🚀 Automatic Startup on macOS

KlaayGuard configures itself to start at login using a macOS LaunchAgent and is kept running with `KeepAlive`.

### Automatic Configuration

- **No Setup Required**: The app installs a LaunchAgent on first run
- **Always Active**: Auto-start cannot be disabled to ensure continuous monitoring
- **User-Level Service**: Runs when the user is logged in (not system-wide)

### How It Works

- **LaunchAgent**: A reverse-DNS label `com.klaay.klaayguard` is installed at `~/Library/LaunchAgents/com.klaay.klaayguard.plist`
- **KeepAlive**: Launchd restarts the app automatically if it exits
- **Background Mode**: The window close action hides the app instead of quitting
- **Automatic Updates**: After updates, the app restarts itself to apply changes

### Security Benefits

- **Continuous Monitoring**: Ensures security monitoring is always active
- **No User Intervention**: Prevents accidental disabling of security features
- **OS-Native Reliability**: Uses launchd for robust background operation

## 📦 Docker Build (Alternative)

For consistent builds across environments:

```bash
# Build using Docker
docker compose run --rm klaayguard -- yarn run tauri build
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test on target platforms
5. Submit a pull request

## 📄 License

[Add your license information here]
