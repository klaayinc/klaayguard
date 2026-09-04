# Assert that a KlaayGuard NSIS installer gives a customer a working install.
# Runs on a throwaway CI runner: it installs silently, checks the registry,
# checks the version, then uninstalls silently and checks the cleanup.
# Usage: validate-windows-nsis.ps1 -Installer <path> -Version <x.y.z>
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$Version
)
$ErrorActionPreference = "Stop"
$failures = 0
function Fail($msg) { Write-Host "FAIL: $msg"; $script:failures++ }
function Pass($msg) { Write-Host "  ok: $msg" }

$Installer = (Resolve-Path $Installer).Path
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$classesKey = "HKCU:\Software\Classes\klaayguard"
$uninstallKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\KlaayGuard",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\com.klaay.app"
)

# --- 1. Archive contents -----------------------------------------------------
# The app binary and the osquery sidecar must both be inside the installer.
# Tauri strips the target triple from the sidecar name when it bundles it.
$listing = & 7z l $Installer | Out-String
if ($listing -match "KlaayGuard\.exe") { Pass "KlaayGuard.exe is in the installer" }
else { Fail "KlaayGuard.exe is missing from the installer" }
if ($listing -match "klaayguard-osqueryi\.exe") { Pass "klaayguard-osqueryi.exe is in the installer" }
else { Fail "klaayguard-osqueryi.exe is missing from the installer" }

# --- 2. Silent install --------------------------------------------------------
# /S is the same flag the self-updater uses, so this proves the update path.
# No /R: the agent must not start on a headless runner.
$proc = Start-Process -FilePath $Installer -ArgumentList "/S" -Wait -PassThru
if ($proc.ExitCode -eq 0) { Pass "silent install exits 0" }
else { Fail "silent install exited $($proc.ExitCode)" }

# --- 3. Registry -------------------------------------------------------------
# The Run value comes from our NSIS_HOOK_POSTINSTALL. Its absence means the
# hook did not run or wrote a wrong path; either way the agent never starts at
# logon and the dashboard cannot tell that from a switched-off laptop.
$run = Get-ItemProperty -Path $runKey -Name KlaayGuard -ErrorAction SilentlyContinue
if ($run -and $run.KlaayGuard -match "KlaayGuard\.exe") { Pass "Run key: $($run.KlaayGuard)" }
else { Fail "Run key KlaayGuard is missing or does not name KlaayGuard.exe" }

# The installer no longer registers a klaayguard:// handler, and must not:
# a custom URL scheme is first-come, first-served on the machine, so any local
# program could claim it and receive the sign-in token. Sign-in now comes back
# over a loopback port this process owns. A handler here would mean the scheme
# came back.
$cmd = Get-ItemProperty -Path "$classesKey\shell\open\command" -Name "(default)" -ErrorAction SilentlyContinue
if ($cmd) { Fail "klaayguard:// protocol handler is registered; the scheme was removed and must stay removed" }
else { Pass "no klaayguard:// protocol handler" }

# A doubled backslash in a key name means someone escaped a path NSIS-style.
$bad = Get-ChildItem -Path "HKCU:\Software" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match "\\\\" -or $_.PSChildName -eq "" } | Select-Object -First 1
if ($bad) { Fail "registry key with an empty or doubled-backslash component: $($bad.Name)" }
else { Pass "no doubled-backslash registry keys" }

# --- 4. Installed binary ------------------------------------------------------
$installDir = $null
foreach ($k in $uninstallKeys) {
    $u = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    if ($u -and $u.InstallLocation) { $installDir = $u.InstallLocation.Trim('"'); break }
}
if (-not $installDir) {
    # Fall back to the Run value's directory.
    if ($run) { $installDir = Split-Path ($run.KlaayGuard.Trim('"')) }
}
if ($installDir -and (Test-Path "$installDir\KlaayGuard.exe")) {
    Pass "installed at $installDir"
    $fv = (Get-Item "$installDir\KlaayGuard.exe").VersionInfo.FileVersion
    if ($fv -like "$Version*") { Pass "FileVersion $fv" }
    else { Fail "FileVersion is '$fv', expected '$Version'. The version-sync step did not run." }
    if (Test-Path "$installDir\klaayguard-osqueryi.exe") { Pass "sidecar installed beside the app" }
    else { Fail "klaayguard-osqueryi.exe is not beside KlaayGuard.exe" }
} else {
    Fail "cannot find the installed KlaayGuard.exe"
}

# --- 5. Silent uninstall ------------------------------------------------------
# The NSIS uninstaller copies itself to a temp directory and returns at once,
# so poll for the cleanup instead of trusting the exit code.
if ($installDir -and (Test-Path "$installDir\uninstall.exe")) {
    Start-Process -FilePath "$installDir\uninstall.exe" -ArgumentList "/S" -Wait
    $deadline = (Get-Date).AddSeconds(90)
    do {
        Start-Sleep -Seconds 2
        $runGone = -not (Get-ItemProperty -Path $runKey -Name KlaayGuard -ErrorAction SilentlyContinue)
        $exeGone = -not (Test-Path "$installDir\KlaayGuard.exe")
    } until (($runGone -and $exeGone) -or (Get-Date) -gt $deadline)
    if ($runGone) { Pass "uninstall removed the Run value" } else { Fail "Run value survived uninstall" }
    if ($exeGone) { Pass "uninstall removed KlaayGuard.exe" } else { Fail "KlaayGuard.exe survived uninstall" }
} else {
    Fail "uninstall.exe not found; cannot test NSIS_HOOK_POSTUNINSTALL"
}

if ($failures -gt 0) { Write-Host "$failures check(s) failed"; exit 1 }
Write-Host "all checks passed"
