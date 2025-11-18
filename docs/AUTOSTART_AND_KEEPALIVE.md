# KlaayGuard Auto-Start and Keep-Alive

This document describes how KlaayGuard ensures it's always running - automatically starting on login and restarting if it crashes or is closed.

## Overview

KlaayGuard implements automatic startup and keep-alive functionality differently for production and development environments:

- **Production**: Uses Tauri's built-in autostart plugin to register a macOS Launch Agent
- **Development**: Uses a custom Launch Agent plist for dev builds

## Production (tauri-plugin-autostart)

### How It Works

The production app uses `tauri-plugin-autostart` which:
1. Creates a macOS Launch Agent when enabled
2. Registers the app to start on user login
3. Stores the configuration in `~/Library/LaunchAgents/`

### When Autostart is Enabled

Autostart is automatically enabled in two scenarios:

1. **First-time authentication**: When a user authenticates via deep link (`klaayguard://auth-callback?token=...`), autostart is enabled immediately after saving the token
2. **Existing authentication**: When the app starts and finds a valid token in the keychain, it enables autostart

### Implementation Details

```rust
/// Enable autostart so KlaayGuard launches on login
async fn enable_autostart(app: &tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    let autostart_manager = app.autolaunch();
    
    // Check if already enabled
    let is_enabled = autostart_manager.is_enabled()
        .map_err(|e| format!("Failed to check autostart status: {}", e))?;
    
    if is_enabled {
        return Ok(());
    }
    
    // Enable autostart
    autostart_manager.enable()
        .map_err(|e| format!("Failed to enable autostart: {}", e))?;
    
    Ok(())
}
```

### User Control

Users can disable autostart through:
- System Preferences → Users & Groups → Login Items
- Or by removing the Launch Agent: `launchctl unload ~/Library/LaunchAgents/com.klaay.app.plist`

## Development (Custom Launch Agent)

### How It Works

The development environment uses a custom Launch Agent defined in `com.klaay.klaayguard-dev.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.klaay.klaayguard-dev</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/KlaayGuard-Dev.app/Contents/MacOS/KlaayGuard-Dev</string>
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <true/>
    
    <key>ProcessType</key>
    <string>Interactive</string>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>APP_DEFAULT_API_BASE_URL</key>
        <string>http://localhost:3000</string>
        <key>VITE_EARTHENWARE_URL</key>
        <string>http://localhost:5173</string>
        <key>KLAAYGUARD_COLLECTION_INTERVAL_SECONDS</key>
        <string>3600</string>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
    
    <key>StandardOutPath</key>
    <string>/tmp/klaayguard-dev-launchd.log</string>
    
    <key>StandardErrorPath</key>
    <string>/tmp/klaayguard-dev-launchd-error.log</string>
</dict>
</plist>
```

### Installation

The Launch Agent is automatically installed when running `bin/dev`:

```fish
# Install Launch Agent for auto-restart and keep-alive
set -l launch_agent_path "$HOME/Library/LaunchAgents/com.klaay.klaayguard-dev.plist"
if test -f com.klaay.klaayguard-dev.plist
    # Unload existing agent if present
    launchctl unload "$launch_agent_path" 2>/dev/null; or true
    
    # Copy plist to LaunchAgents
    cp com.klaay.klaayguard-dev.plist "$launch_agent_path"
    
    # Load the agent
    launchctl load "$launch_agent_path"
end
```

### Key Features

- **RunAtLoad**: App starts immediately when the Launch Agent is loaded
- **KeepAlive**: App automatically restarts if it crashes or is closed
- **Environment Variables**: Development-specific configuration is injected
- **Logging**: stdout and stderr are captured to `/tmp/klaayguard-dev-launchd.log`

### Management Commands

```bash
# Stop and disable auto-restart
launchctl unload ~/Library/LaunchAgents/com.klaay.klaayguard-dev.plist

# Start manually
launchctl start com.klaay.klaayguard-dev

# View logs
tail -f /tmp/klaayguard-dev-launchd.log

# Check if running
launchctl list | grep klaayguard
```

## Testing Auto-Restart

### Production

1. Authenticate the app
2. Check System Preferences → Users & Groups → Login Items for "KlaayGuard"
3. Kill the app: `pkill -9 -f KlaayGuard`
4. Log out and log back in - app should start automatically

### Development

1. Run `bin/dev` to install and start the Launch Agent
2. Verify it's running: `launchctl list | grep klaayguard`
3. Test crash recovery:
   ```bash
   # Kill the app
   pkill -9 -f "KlaayGuard-Dev"
   
   # Wait a few seconds
   sleep 5
   
   # Check if it restarted
   ps aux | grep "KlaayGuard-Dev" | grep -v grep
   ```

## Troubleshooting

### Production App Not Starting on Login

1. Check if autostart is enabled:
   ```bash
   ls -la ~/Library/LaunchAgents/ | grep klaay
   ```

2. Check Launch Agent status:
   ```bash
   launchctl list | grep com.klaay.app
   ```

3. Manually load the agent:
   ```bash
   launchctl load ~/Library/LaunchAgents/com.klaay.app.plist
   ```

### Development App Not Restarting

1. Check Launch Agent status:
   ```bash
   launchctl list | grep klaayguard-dev
   ```

2. Check error logs:
   ```bash
   tail -f /tmp/klaayguard-dev-launchd-error.log
   ```

3. Reload the agent:
   ```bash
   launchctl unload ~/Library/LaunchAgents/com.klaay.klaayguard-dev.plist
   launchctl load ~/Library/LaunchAgents/com.klaay.klaayguard-dev.plist
   ```

4. Check system logs:
   ```bash
   log stream --predicate 'process == "launchd"' --level info | grep klaayguard
   ```

### Gatekeeper / Code Signing Issues

If the Launch Agent fails to start the app due to Gatekeeper (common in development):

1. Manually open the app once: `open -a /Applications/KlaayGuard-Dev.app`
2. Allow it in System Preferences → Security & Privacy
3. Restart the Launch Agent

## Architecture Notes

### Why Different Approaches?

- **Production**: The Tauri plugin handles code signing and app bundle structure correctly, making it more reliable for signed, distributed apps
- **Development**: A custom plist gives us more control over environment variables and logging, which is useful during development

### Process Monitoring

The Launch Agent's `KeepAlive` directive ensures the process is monitored:
- If the app exits for any reason (crash, manual close, etc.), `launchd` automatically restarts it
- This happens within seconds of the process terminating
- The restart is logged to `/tmp/klaayguard-dev-launchd.log`

## References

- [macOS Launch Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [tauri-plugin-autostart](https://github.com/tauri-apps/plugins-workspace/tree/v2/plugins/autostart)
- [launchd.plist manual](https://www.launchd.info/)

