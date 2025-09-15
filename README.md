# KlaayGuard

[![Built with Tauri](https://img.shields.io/badge/built%20with-Tauri-FFC131.svg?logo=tauri)](https://tauri.app)

**KlaayGuard** is a cross-platform desktop security monitoring application that collects system information using osquery and reports it to a centralized API for security analysis.

## 🎯 Purpose

KlaayGuard automatically:

- Installs and manages osquery on Windows, macOS, and Linux
- Collects system security data (processes, network connections, installed software, etc.)
- Reports data to `https://api.klaay.dev` every 15 minutes
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

# Create environment file
echo "VITE_API_BASE_URL=https://api.klaay.dev" > .env

# Run in development
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

### Environment Variables

```bash
# .env file
VITE_API_BASE_URL=https://api.klaay.dev
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
```

## 🔒 Security Features

- **JWT Authentication**: Secure API communication
- **System Integration**: Native osquery installation
- **Background Operation**: System tray with show/hide/quit
- **Auto-Start**: Automatic startup on macOS login (mandatory)
- **Data Encryption**: HTTPS transmission to API
- **Cross-platform**: Consistent security monitoring across platforms

## 🚀 Automatic Startup on macOS

KlaayGuard automatically configures itself to start on macOS login using the Tauri autostart plugin. This ensures continuous security monitoring without any manual configuration required.

### Automatic Configuration

- **No Setup Required**: The app automatically enables autostart when first run
- **Always Active**: Auto-start cannot be disabled - this ensures continuous security monitoring
- **Tauri Plugin**: Uses the official Tauri autostart plugin for reliable operation
- **User-Level Service**: Runs when the user is logged in (not system-wide)

### How It Works

- **Plugin-Based**: Uses `tauri-plugin-autostart` for cross-platform autostart functionality
- **Launch Agent**: Automatically creates and manages macOS launch agent
- **Background Mode**: App starts in background with system tray access
- **Keep Alive**: Launch agent ensures the app restarts if it crashes
- **Automatic Updates**: Launch agent updates automatically when app is updated

### Security Benefits

- **Continuous Monitoring**: Ensures security monitoring is always active
- **No User Intervention**: Prevents accidental disabling of security features
- **Reliable Operation**: Uses Tauri's proven autostart plugin for robust background operation
- **Framework Integration**: Leverages Tauri's built-in capabilities instead of manual shell commands

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
