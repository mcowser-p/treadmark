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
pyinstaller `
    --onefile `
    --name cairn `
    --distpath dist\_pyi `
    --workpath build\_pyi `
    --specpath build `
    --paths src `
    --hidden-import yaml `
    --hidden-import win32security `
    scripts\cairn_launcher.py | Out-Null
Move-Item -Force dist\_pyi\cairn.exe dist\cairn-windows-x86_64.exe
Remove-Item -Recurse -Force dist\_pyi

# ---------------------------------------------------------------------------
# 2. MSI via WiX v4+ as a .NET tool
# ---------------------------------------------------------------------------
Write-Host ">>> msi"

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host "  installing wix tool..."
    dotnet tool install --global wix
    $env:PATH = "$env:USERPROFILE\.dotnet\tools;$env:PATH"
}

# Idempotent extension installs
wix extension add -g WixToolset.UI.wixext
wix extension add -g WixToolset.Util.wixext

# Stage the artifacts the .wxs references next to cairn.wxs
Copy-Item dist\cairn-windows-x86_64.exe windows\
Copy-Item packaging\cairn.yaml          windows\

Push-Location windows
try {
    wix build cairn.wxs `
        -arch x64 `
        -d "Version=$version" `
        -ext WixToolset.UI.wixext `
        -ext WixToolset.Util.wixext `
        -o "..\dist\cairn-$version.msi"
} finally {
    Remove-Item -ErrorAction SilentlyContinue cairn-windows-x86_64.exe, cairn.yaml
    Pop-Location
}

Get-ChildItem dist
Write-Host "Done. Install with:  msiexec /i dist\cairn-$version.msi /qb"
