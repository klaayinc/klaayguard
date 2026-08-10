# Fetch the osquery Windows x86_64 sidecar and place it where tauri_build looks
# for the externalBin. rake fetches the macOS and Linux sidecars, but its file
# tasks use a Unix shell, so Windows fetches here instead. Keep the version and
# the checksum in step with OSQUERY_VERSION in the Rakefile.
$ErrorActionPreference = "Stop"

$version = "5.18.1"
$expectedSha = "5429d27daa3323e2fdaf3d2dbd3af3e0a895f288a5bc275d475c4a2293a5efc4"
$zipName = "osquery-$version.windows_x86_64.zip"
$url = "https://github.com/osquery/osquery/releases/download/$version/$zipName"
$dest = "src-tauri/vendor/klaayguard-osqueryi-x86_64-pc-windows-msvc.exe"

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zipName

# The sidecar runs with the user's full privileges, so verify the download
# against the published SHA-256 before the build uses it.
$actualSha = (Get-FileHash -Algorithm SHA256 $zipName).Hash.ToLower()
if ($actualSha -ne $expectedSha) {
    throw "Checksum mismatch for ${zipName}: expected $expectedSha, got $actualSha"
}
Write-Host "Verified checksum for $zipName"

$extractDir = "osquery-win"
if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
Expand-Archive -Path $zipName -DestinationPath $extractDir -Force

$src = Join-Path $extractDir "osquery-$version.windows_x86_64/Program Files/osquery/osqueryd/osqueryd.exe"
if (-not (Test-Path $src)) {
    throw "osqueryd.exe not found in $zipName at $src"
}

New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
Copy-Item -Force $src $dest
Write-Host "Placed sidecar at $dest"
