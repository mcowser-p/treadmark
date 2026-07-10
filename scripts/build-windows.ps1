# scripts/build-windows.ps1
# Run on a Windows host with .NET SDK 6+ installed.
# Produces:
#   dist\cairn-windows-x86_64.exe   (PyInstaller single-file binary)
#   dist\cairn-<version>.msi         (WiX MSI installer)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$version = (python -c "import tomllib; print(tomllib.loads(open('pyproject.toml','rb').read().decode())['project']['version'])").Trim()
Write-Host "Building cairn $version"

New-Item -ItemType Directory -Force -Path dist | Out-Null

# ---------------------------------------------------------------------------
# 1. Single-file .exe via PyInstaller
# ---------------------------------------------------------------------------
Write-Host ">>> windows binary"
python -m pip install --quiet pyinstaller pyyaml pywin32
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

# PyInstaller resolves --icon relative to --specpath (build\), not the CWD,
# so pass an absolute path or it looks for build\windows\cairn.ico.
$icon = (Resolve-Path "windows\cairn.ico").Path

# No `| Out-Null`: piping a native command disables PowerShell's auto-throw on
# non-zero exit, which previously let a failed build slip through. Check
# $LASTEXITCODE explicitly instead.
python -m PyInstaller `
    --onefile `
    --name cairn `
    --distpath dist\_pyi `
    --workpath build\_pyi `
    --specpath build `
    --paths src `
    --icon $icon `
    --hidden-import yaml `
    --hidden-import win32security `
    --hidden-import ntsecuritycon `
    scripts\cairn_launcher.py
if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed" }

Move-Item -Force dist\_pyi\cairn.exe dist\cairn-windows-x86_64.exe
Remove-Item -Recurse -Force dist\_pyi

# A real onefile exe embeds Python (~8-12 MB); a bare bootloader (~300 KB)
# means the build silently produced a broken binary.
$exeSize = (Get-Item dist\cairn-windows-x86_64.exe).Length
if ($exeSize -lt 2MB) {
    throw "built exe is only $exeSize bytes — a bare bootloader, not a full onefile build"
}

# ---------------------------------------------------------------------------
# 2. MSI via WiX v4+ as a .NET tool
# ---------------------------------------------------------------------------
Write-Host ">>> msi"

# WiX v7 gates use behind the OSMF EULA (error WIX7015). Pin to v5, which is
# schema-compatible with this .wxs and has no EULA gate. Pin the extensions to
# the same major so they resolve against the pinned toolset.
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host "  installing wix v5..."
    dotnet tool install --global wix --version 5.0.2
    if ($LASTEXITCODE -ne 0) { throw "wix tool install failed" }
    $env:PATH = "$env:USERPROFILE\.dotnet\tools;$env:PATH"
}

wix extension add -g WixToolset.UI.wixext/5.0.2
if ($LASTEXITCODE -ne 0) { throw "wix UI extension add failed" }
wix extension add -g WixToolset.Util.wixext/5.0.2
if ($LASTEXITCODE -ne 0) { throw "wix Util extension add failed" }

# Stage the artifacts the .wxs references next to cairn.wxs.
# The MSI ships the Windows-native default config (watches Program Files,
# drivers\etc, Start Menu startup, Tasks) — NOT the Linux cairn.yaml.
Copy-Item dist\cairn-windows-x86_64.exe windows\
Copy-Item packaging\cairn-windows.yaml  windows\cairn.yaml

Push-Location windows
try {
    wix build cairn.wxs `
        -arch x64 `
        -d "Version=$version" `
        -ext WixToolset.UI.wixext `
        -ext WixToolset.Util.wixext `
        -o "..\dist\cairn-$version.msi"
    if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
} finally {
    Remove-Item -ErrorAction SilentlyContinue cairn-windows-x86_64.exe, cairn.yaml
    Pop-Location
}

Get-ChildItem dist
Write-Host "Done. Install with:  msiexec /i dist\cairn-$version.msi /qb"
