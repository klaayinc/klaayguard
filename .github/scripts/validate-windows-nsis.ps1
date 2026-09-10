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
# No /R: the installer must leave an agent running without being asked. The
# macOS postinstall carries the same guarantee today; the Linux postinst gets
# it in the sibling pull request, which is still open.
# Two shapes reach no section here. The hook's failure branch needs an elevated
# caller with no shell window; this runner is a logged-on session with a shell,
# so RunAsUser succeeds. The passive path (/P) shows the installer window. It
# would add a fifth install to a job whose bounded waits already fill most of
# its 30 minutes when it fails.
# Never wait on an installer without a deadline. A modal dialog nobody can
# answer looks exactly like a slow runner, so an unbounded wait spends the whole
# job timeout in silence. A bounded one names the problem and moves on.
function Invoke-Installer([string]$Path, [string[]]$Arguments, [int]$TimeoutSeconds = 240) {
    $p = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
        Fail "'$Path $($Arguments -join ' ')' did not finish in $TimeoutSeconds s; it is waiting for an answer nobody can give"
        # A kill that fails leaves an installer still changing the machine while
        # every later section reads it. Say so rather than carry on blind.
        try { $p.Kill(); $p.WaitForExit(10000) | Out-Null }
        catch { Fail "could not kill the stuck installer (pid $($p.Id)): $($_.Exception.Message)" }
        return $null
    }
    return $p
}

$proc = Invoke-Installer $Installer @("/S")
if ($proc -and $proc.ExitCode -eq 0) { Pass "silent install exits 0" }
elseif ($proc) { Fail "silent install exited $($proc.ExitCode)" }

# Wait for a process to appear, and return it. The installer starts the agent
# through the shell, so it arrives a moment after the installer exits.
function Wait-ForAgent([int]$Seconds = 60) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $p = Get-Process -Name KlaayGuard -ErrorAction SilentlyContinue
        if ($p) { return $p }
        Start-Sleep -Seconds 1
    } until ((Get-Date) -gt $deadline)
    return $null
}

# --- 2a. The install leaves an agent running ---------------------------------
# A security agent that waits for the next logon leaves the machine unmonitored
# until then. The installer stops the old process before it writes the files,
# so it owes the machine a running replacement.
$agent = Wait-ForAgent
if (-not $agent) {
    Fail "no KlaayGuard process after the install; the machine is unmonitored until the next logon"
} elseif (@($agent).Count -ne 1) {
    # Two agents is PROD-4603: two tray icons, the device double-reporting every
    # 15 minutes.
    #
    # Know what this catches here. The job sets neither VITE_API_BASE_URL nor
    # APP_DEFAULT_API_BASE_URL, so the build under test talks to production,
    # `is_production_target` is true, and the single-instance mutex is
    # registered. A second launch would exit on that mutex and this count would
    # still read 1. So this guards the mutex against regression; it does not
    # prove the installer starts the agent only once. The hook's own condition
    # is what does that.
    Fail "$(@($agent).Count) KlaayGuard processes run after the install; exactly one must"
} else {
    Pass "exactly one agent runs after the install (pid $($agent[0].Id))"
}

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

# --- 4a. A re-install replaces the running agent ------------------------------
# The question this section answers: does installing the latest version over a
# running agent take over from it? Windows cannot overwrite a running .exe, so
# the installer stops the old process first. If it ever stopped doing that, the
# machine would keep reporting from the old build until the user logged out.
if ($agent) {
    $oldPid = $agent[0].Id
    # /S /UPDATE is what the self-updater runs, minus the /R that asks the
    # template to restart the app. /UPDATE also skips the WebView2 bootstrapper,
    # whose error path is a modal dialog with no one to answer it.
    $proc = Invoke-Installer $Installer @("/S", "/UPDATE")
    if ($proc -and $proc.ExitCode -ne 0) { Fail "the re-install exited $($proc.ExitCode)" }

    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 1
        $oldGone = -not (Get-Process -Id $oldPid -ErrorAction SilentlyContinue)
    } until ($oldGone -or (Get-Date) -gt $deadline)

    if ($oldGone) { Pass "the re-install stopped the old agent (pid $oldPid)" }
    else { Fail "the old agent (pid $oldPid) survived the re-install; the new binary never runs" }

    $fresh = Wait-ForAgent
    if (-not $fresh) { Fail "no agent runs after the re-install" }
    elseif ($fresh.Id -contains $oldPid) { Fail "the agent after the re-install is still the old process $oldPid" }
    elseif (@($fresh).Count -ne 1) { Fail "$(@($fresh).Count) agents run after the re-install; exactly one must" }
    else { Pass "exactly one new agent runs after the re-install (pid $($fresh[0].Id))" }
} else {
    Fail "no running agent to re-install over; the check above already failed"
}

# --- 4b. The real self-update command line ------------------------------------
# Section 4a drops /R on purpose, to drive the new hook. This is the line every
# existing customer takes on a self-update, where the template's .onInstSuccess
# does the restart. Without it that path is asserted only by a unit test on the
# flag list.
#
# It is a smoke test of the command line, not of which code started the agent:
# with /R present both starters are in play, so an inverted condition in the
# hook would still leave one agent running and pass here. Section 4a is where
# the hook itself is exercised.
$beforeUpdate = Get-Process -Name KlaayGuard -ErrorAction SilentlyContinue
$proc = Invoke-Installer $Installer @("/S", "/UPDATE", "/R")
if ($proc -and $proc.ExitCode -ne 0) { Fail "the self-update command line exited $($proc.ExitCode)" }
$afterUpdate = Wait-ForAgent
if (-not $afterUpdate) {
    Fail "no agent runs after '/S /UPDATE /R'; the self-update path leaves the machine unmonitored"
} elseif (@($afterUpdate).Count -ne 1) {
    Fail "$(@($afterUpdate).Count) agents run after '/S /UPDATE /R'; exactly one must"
} elseif ($beforeUpdate -and ($afterUpdate.Id -contains $beforeUpdate[0].Id)) {
    Fail "the self-update left the old agent (pid $($beforeUpdate[0].Id)) in place"
} else {
    Pass "the self-update command line restarts the agent (pid $($afterUpdate[0].Id))"
}

# --- 5. Silent uninstall ------------------------------------------------------
# Stop the agent first. The uninstaller does it too, but an explicit stop keeps
# the file checks below about uninstall, not about a timing race. A stop that
# fails would otherwise resurface as a confusing file-still-there failure.
foreach ($p in @(Get-Process -Name KlaayGuard -ErrorAction SilentlyContinue)) {
    try { $p.Kill(); $p.WaitForExit(10000) | Out-Null }
    catch { Fail "could not stop the agent (pid $($p.Id)) before the uninstall: $($_.Exception.Message)" }
}
# The NSIS uninstaller copies itself to a temp directory and returns at once,
# so poll for the cleanup instead of trusting the exit code.
if ($installDir -and (Test-Path "$installDir\uninstall.exe")) {
    Invoke-Installer "$installDir\uninstall.exe" @("/S") | Out-Null
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
