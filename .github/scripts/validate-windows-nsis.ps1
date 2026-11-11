# Assert that a KlaayGuard NSIS installer gives a customer a working install.
# Runs on a throwaway CI runner: it installs silently, checks the registry,
# checks the version, then uninstalls silently and checks the cleanup.
# Usage: validate-windows-nsis.ps1 -Installer <path> -Version <x.y.z> [-Msi <path>]
# -Msi names an .msi build of the app. With it, the script first plants the
# earlier installs a customer machine can hold, and checks the installer
# removes them all before it installs.
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$Msi = ""
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

# Every KlaayGuard entry in Add/Remove Programs: the per-user list, and the
# per-machine list in both registry views. The name is the one every release
# shipped under, or the pre-rename "klaay".
function Get-KlaayGuardEntries {
    $roots = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($root in $roots) {
        Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and ($p.DisplayName -eq "KlaayGuard" -or $p.DisplayName -eq "klaay")) {
                [pscustomobject]@{ Key = $_.Name; Location = "$($p.InstallLocation)".Trim('"'); Msi = ($p.WindowsInstaller -eq 1) }
            }
        }
    }
}

# --- 1a. Earlier installs ------------------------------------------------------
# The installer must remove every earlier install before it writes a file, on
# every path that reaches it. /S is the one that skips the template's own
# "uninstall first" page, and it is the path the self-updater and every
# deployment tool take. Plant what a customer machine can hold:
#   - a per-user NSIS install in another folder, under an older uninstall key,
#     with its agent running;
#   - a per-machine .msi install, the format early releases shipped, with its
#     agent running.
$legacyDir = "C:\KlaayGuardLegacy"
$msiDir = Join-Path $env:ProgramFiles "KlaayGuard"
$planted = $false
if ($Msi) {
    $Msi = (Resolve-Path $Msi).Path
    $uninstallRoot = "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall"

    # NSIS reads /D= raw, so it must come last and carry no quotes.
    $proc = Invoke-Installer $Installer @("/S", "/D=$legacyDir")
    if (-not $proc -or $proc.ExitCode -ne 0) { Fail "could not plant the earlier NSIS install in $legacyDir" }
    # Move its entry to a key name an older build used, and mark it older. Drop
    # the remembered folder, so the install under test picks the default one
    # and the two do not overlap.
    & reg.exe copy "$uninstallRoot\KlaayGuard" "$uninstallRoot\com.klaay.app" /s /f | Out-Null
    & reg.exe delete "$uninstallRoot\KlaayGuard" /f | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\com.klaay.app" -Name DisplayVersion -Value "0.0.1"
    Remove-Item -Path "HKCU:\Software\Klaay\KlaayGuard" -Recurse -ErrorAction SilentlyContinue

    $proc = Invoke-Installer "msiexec.exe" @("/i", "`"$Msi`"", "/qn", "/norestart")
    if (-not $proc -or $proc.ExitCode -ne 0) { Fail "could not plant the earlier MSI install (msiexec exited $($proc.ExitCode))" }
    Start-Process -FilePath "$msiDir\KlaayGuard.exe" | Out-Null

    $before = @(Get-KlaayGuardEntries)
    $legacyAgent = $null
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 1
        $running = @(Get-Process -Name KlaayGuard -ErrorAction SilentlyContinue | Where-Object { $_.Path })
        $legacyAgent = $running | Where-Object { $_.Path -like "$legacyDir\*" }
        $msiAgent = $running | Where-Object { $_.Path -like "$msiDir\*" }
    } until (($legacyAgent -and $msiAgent) -or (Get-Date) -gt $deadline)

    # A plant that did not take makes every check below pass for nothing.
    if ($before.Count -eq 2 -and ($before | Where-Object Msi) -and (Test-Path "$legacyDir\KlaayGuard.exe") -and (Test-Path "$msiDir\KlaayGuard.exe") -and $legacyAgent -and $msiAgent) {
        Pass "planted an earlier NSIS install and an earlier MSI install, both running"
        $planted = $true
    } else {
        Fail "the earlier installs did not plant: $($before.Count) entries, legacy agent: $([bool]$legacyAgent), MSI agent: $([bool]$msiAgent)"
    }
}

$proc = Invoke-Installer $Installer @("/S")
if ($proc -and $proc.ExitCode -eq 0) { Pass "silent install exits 0" }
elseif ($proc) { Fail "silent install exited $($proc.ExitCode)" }

# --- 1b. Only the new install remains ------------------------------------------
if ($planted) {
    $after = @(Get-KlaayGuardEntries)
    $defaultDir = Join-Path $env:LOCALAPPDATA "KlaayGuard"
    if ($after.Count -eq 1 -and -not $after[0].Msi -and $after[0].Location -eq $defaultDir) {
        Pass "exactly one KlaayGuard entry remains, the new install in $defaultDir"
    } else {
        Fail "$($after.Count) KlaayGuard entries remain after the install, expected only the new one: $(($after | ForEach-Object { "$($_.Key) -> $($_.Location)" }) -join '; ')"
    }
    if (Test-Path "$legacyDir\KlaayGuard.exe") { Fail "the earlier NSIS install in $legacyDir survived" }
    else { Pass "the earlier NSIS install in $legacyDir is gone" }
    if (Test-Path $legacyDir) { Fail "the folder $legacyDir survived the uninstall" }
    if (Test-Path "$msiDir\KlaayGuard.exe") { Fail "the earlier MSI install in $msiDir survived" }
    else { Pass "the earlier MSI install in $msiDir is gone" }
    $stale = @(Get-Process -Name KlaayGuard -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -like "$legacyDir\*" -or $_.Path -like "$msiDir\*" })
    if ($stale.Count -gt 0) { Fail "$($stale.Count) agent(s) still run from an earlier install: $(($stale | ForEach-Object Path) -join ', ')" }
    else { Pass "no agent runs from an earlier install" }
    $runAfter = Get-ItemProperty -Path $runKey -Name KlaayGuard -ErrorAction SilentlyContinue
    if ($runAfter -and $runAfter.KlaayGuard -like "*$defaultDir\KlaayGuard.exe*") { Pass "the Run value names the new install" }
    else { Fail "the Run value names '$($runAfter.KlaayGuard)', not the new install in $defaultDir" }
}

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

# Wait until one agent runs and keeps running, then return it. `/R` puts both
# starters in play — the NSIS hook and the template's .onInstSuccess — so two
# processes exist for a moment and the single-instance lock makes the loser
# concede once its retries run out. Reading the first moment any process exists
# samples that overlap and calls it a defect, which is why the count below is
# taken from the set that holds rather than the set that appears. When nothing
# settles the last set comes back, so a run where two agents really do survive
# still fails on the count.
function Wait-ForSettledAgent([int]$Seconds = 60) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    $previous = @()
    do {
        Start-Sleep -Seconds 1
        $current = @(Get-Process -Name KlaayGuard -ErrorAction SilentlyContinue)
        if ($current.Count -eq 1 -and $previous.Count -eq 1 -and $previous[0].Id -eq $current[0].Id) {
            return $current
        }
        $previous = $current
    } until ((Get-Date) -gt $deadline)
    return $previous
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
$afterUpdate = Wait-ForSettledAgent
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
#
# One pass is not enough. `/R` above leaves both starters in play, so a process
# can appear after the list is taken, and Windows refuses to delete a running
# .exe — the survivor resurfaces 90 seconds later as "KlaayGuard.exe survived
# uninstall", which names the wrong thing. Sweep until nothing is left.
$stopDeadline = (Get-Date).AddSeconds(60)
do {
    $alive = @(Get-Process -Name KlaayGuard -ErrorAction SilentlyContinue)
    foreach ($p in $alive) {
        try { $p.Kill(); $p.WaitForExit(10000) | Out-Null }
        catch { Fail "could not stop the agent (pid $($p.Id)) before the uninstall: $($_.Exception.Message)" }
    }
    Start-Sleep -Seconds 1
} until (@(Get-Process -Name KlaayGuard -ErrorAction SilentlyContinue).Count -eq 0 -or (Get-Date) -gt $stopDeadline)
if (@(Get-Process -Name KlaayGuard -ErrorAction SilentlyContinue).Count -gt 0) {
    Fail "an agent still runs after 60s of stopping it; the uninstall checks below cannot mean anything"
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
