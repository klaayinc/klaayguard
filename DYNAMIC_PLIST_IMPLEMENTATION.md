# Dynamic Plist Generation Implementation

## Problem

The Launch Agent plist file (`com.klaay.klaayguard-dev.plist`) was a static file in the repository that could become outdated or inconsistent with the environment variables loaded from `.env.development`.

### Issues with Static Plist:

1. **Binary path mismatch** - Had `KlaayGuard-Dev` instead of `KlaayGuard`
2. **Environment variable mismatch** - Had `APP_DEFAULT_API_BASE_URL` instead of `VITE_API_BASE_URL`
3. **Drift risk** - Manual updates required when environment variables change
4. **Not synchronized** - Values didn't match `.env.development`

## Solution

The `bin/dev` script now dynamically generates the plist file using the environment variables loaded from `.env.development`.

### Implementation

```bash
# Generate Launch Agent plist with current environment variables
echo -e "${BLUE}📝 Generating Launch Agent configuration...${NORMAL}"
printf '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.klaay.klaayguard-dev</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/KlaayGuard-Dev.app/Contents/MacOS/KlaayGuard</string>
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <true/>
    
    <key>ProcessType</key>
    <string>Interactive</string>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>VITE_API_BASE_URL</key>
        <string>%s</string>
        <key>VITE_EARTHENWARE_URL</key>
        <string>%s</string>
        <key>KLAAYGUARD_COLLECTION_INTERVAL_SECONDS</key>
        <string>%s</string>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
    
    <key>StandardOutPath</key>
    <string>/tmp/klaayguard-dev-launchd.log</string>
    
    <key>StandardErrorPath</key>
    <string>/tmp/klaayguard-dev-launchd-error.log</string>
</dict>
</plist>' "$VITE_API_BASE_URL" "$VITE_EARTHENWARE_URL" "$KLAAYGUARD_COLLECTION_INTERVAL_SECONDS" > com.klaay.klaayguard-dev.plist
echo -e "${GREEN}✓${NORMAL} Plist generated with current environment variables"
```

### How It Works

1. **Load environment** from `.env.development` using `scripts/load-env.sh`
2. **Generate plist** using `printf` with environment variable substitution
3. **Write to file** `com.klaay.klaayguard-dev.plist` in project root
4. **Kill running app** to ensure clean state
5. **Unload old agent** if present
6. **Copy generated plist** to `~/Library/LaunchAgents/`
7. **Load new agent** with correct environment variables

## Benefits

1. **Always Correct Binary Path** - Uses the actual MacOS binary path: `/Applications/KlaayGuard-Dev.app/Contents/MacOS/KlaayGuard`

2. **Synchronized Environment** - Plist environment variables match `.env.development`:
   - `VITE_API_BASE_URL` (not `APP_DEFAULT_API_BASE_URL`)
   - `VITE_EARTHENWARE_URL`
   - `KLAAYGUARD_COLLECTION_INTERVAL_SECONDS`

3. **No Drift** - Generated fresh every time `bin/dev` runs

4. **Single Source of Truth** - Environment variables come from `.env.development`

5. **Automatic Updates** - Any changes to `.env.development` are immediately reflected

## Verification

### Check Generated Plist

```bash
cat com.klaay.klaayguard-dev.plist | grep -A 1 "VITE_API_BASE_URL"
```

Should show:
```xml
<key>VITE_API_BASE_URL</key>
<string>http://localhost:3000</string>
```

### Check Running App

```bash
ps aux | grep -i klaayguard | grep -v grep
```

Should show the app running with correct binary path.

### Check Logs

```bash
tail -f /tmp/klaayguard-dev-launchd.log
```

Should show successful startup and connection to the API URL from `.env.development`.

## Testing

Tested on:
- **Date**: 2025-11-23
- **macOS**: Darwin 24.6.0
- **Fish**: /opt/homebrew/bin/fish
- **Result**: ✅ Success

### Test Output

```
✓ API URL: http://localhost:3000
✓ Earthenware URL: http://localhost:5173
✓ Collection Interval: 3600 seconds

📝 Generating Launch Agent configuration...
✓ Plist generated with current environment variables

🔄 Installing Launch Agent for auto-restart...
✓ Launch Agent plist copied to ~/Library/LaunchAgents/
✓ Launch Agent loaded - KlaayGuard-Dev will:
   • Auto-start on login
   • Auto-restart if it crashes
   • Use API: http://localhost:3000
```

## Migration Notes

### Before (Static Plist)

- Plist file was committed to repository
- Required manual updates when environment variables changed
- Could drift from actual environment configuration
- Had incorrect binary path and environment variable names

### After (Dynamic Plist)

- Plist file is generated at runtime
- Automatically reflects current `.env.development`
- Cannot drift - always synchronized
- Correct binary path and environment variable names

### Static Plist File Status

The static `com.klaay.klaayguard-dev.plist` file in the project root is now overwritten every time `bin/dev` runs. It can be:
- Kept in git as a template/reference (but will be regenerated)
- Removed from git (since it's always generated)
- Added to `.gitignore` if desired

## Future Improvements

1. **Template-based generation** - Use a template file with placeholders for better maintainability
2. **Validation** - Validate generated plist XML before copying to LaunchAgents
3. **Error handling** - Better error messages if environment variables are missing
4. **Cross-platform** - Extend this pattern to Linux/Windows startup configurations

## Related Files

- `bin/dev` - Development script with plist generation
- `scripts/load-env.sh` - Environment variable loader
- `.env.development` - Source of environment variables
- `docs/ENVIRONMENT.md` - Environment management documentation



