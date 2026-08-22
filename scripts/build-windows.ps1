# scripts/build-windows.ps1
# Run on a Windows host with .NET SDK 6+ and MSVC (VS Build Tools) installed.
# Produces:
#   dist\treadmark-windows-x86_64.exe   (Nuitka-compiled single-file binary)
#   dist\treadmark-<version>.msi         (WiX MSI installer)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$version = (python -c "import tomllib; print(tomllib.loads(open('pyproject.toml','rb').read().decode())['project']['version'])").Trim()
Write-Host "Building treadmark $version"

New-Item -ItemType Directory -Force -Path dist | Out-Null

# ---------------------------------------------------------------------------
# 1. Single-file COMPILED .exe via Nuitka.
#
# Nuitka, not PyInstaller: PyInstaller ships extractable bytecode (near-source
# recovery with public tooling); Nuitka transpiles the package to C and
# compiles it with MSVC — machine code, no .pyc payload. pywin32's .pyd
# extension modules are bundled as-is (they're public code; ours is what
# gets compiled).
# ---------------------------------------------------------------------------
Write-Host ">>> windows binary (nuitka)"
python -m pip install --quiet nuitka pyyaml pywin32
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
# Install treadmark itself so Nuitka resolves the package like any import.
python -m pip install --quiet -e .
if ($LASTEXITCODE -ne 0) { throw "pip install -e . failed" }

# No `| Out-Null`: piping a native command disables PowerShell's auto-throw on
# non-zero exit, which previously let a failed build slip through. Check
# $LASTEXITCODE explicitly instead.
python -m nuitka `
    --onefile `
    --assume-yes-for-downloads `
    --msvc=latest `
    --include-package=treadmark `
    --include-package=yaml `
    --include-module=win32security `
    --include-module=ntsecuritycon `
    --include-module=pywintypes `
    --windows-icon-from-ico=windows\treadmark.ico `
    --company-name="mcowser-p" `
    --product-name="treadmark" `
    --file-version=$version `
    --product-version=$version `
    --onefile-tempdir-spec='{CACHE_DIR}\treadmark\{VERSION}' `
    --output-filename=treadmark-windows-x86_64.exe `
    --output-dir=build\_nuitka `
    scripts\treadmark_launcher.py
if ($LASTEXITCODE -ne 0) { throw "nuitka build failed" }

Move-Item -Force build\_nuitka\treadmark-windows-x86_64.exe dist\treadmark-windows-x86_64.exe
Remove-Item -Recurse -Force build\_nuitka

# A real onefile exe embeds the runtime (~10+ MB); a tiny stub means the
# build silently produced a broken binary.
$exeSize = (Get-Item dist\treadmark-windows-x86_64.exe).Length
if ($exeSize -lt 2MB) {
    throw "built exe is only $exeSize bytes — a stub, not a full onefile build"
}

# ---------------------------------------------------------------------------
# 2. MSI via WiX v4+ as a .NET tool
# ---------------------------------------------------------------------------
Write-Host ">>> msi"

# WiX v7 gates use behind the OSMF EULA (error WIX7015). Pin to v5, which is
# schema-compatible with this .wxs and has no EULA gate. Pin the extensions to
# the same major so they resolve against the pinned toolset.
# Put the global-tools dir on PATH first, so a CI cache-restored wix is found
# and we skip the ~2-minute reinstall.
$env:PATH = "$env:USERPROFILE\.dotnet\tools;$env:PATH"
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    Write-Host "  installing wix v5..."
    dotnet tool install --global wix --version 5.0.2
    if ($LASTEXITCODE -ne 0) { throw "wix tool install failed" }
}

wix extension add -g WixToolset.UI.wixext/5.0.2
if ($LASTEXITCODE -ne 0) { throw "wix UI extension add failed" }
wix extension add -g WixToolset.Util.wixext/5.0.2
if ($LASTEXITCODE -ne 0) { throw "wix Util extension add failed" }

# Stage the artifacts the .wxs references next to treadmark.wxs.
# The MSI ships the Windows-native default config (watches Program Files,
# drivers\etc, Start Menu startup, Tasks) — NOT the Linux treadmark.yaml.
Copy-Item dist\treadmark-windows-x86_64.exe windows\
Copy-Item packaging\treadmark-windows.yaml  windows\treadmark.yaml

Push-Location windows
try {
    wix build treadmark.wxs `
        -arch x64 `
        -d "Version=$version" `
        -ext WixToolset.UI.wixext `
        -ext WixToolset.Util.wixext `
        -o "..\dist\treadmark-$version.msi"
    if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
} finally {
    Remove-Item -ErrorAction SilentlyContinue treadmark-windows-x86_64.exe, treadmark.yaml
    Pop-Location
}

Get-ChildItem dist
Write-Host "Done. Install with:  msiexec /i dist\treadmark-$version.msi /qb"
