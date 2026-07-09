# scripts/bootstrap.ps1
# One-shot setup for a fresh clone of cairn on Windows.

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

Write-Host ">>> Detecting environment..."

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[!] python is required (3.9 or later). Install from https://python.org or:"
    Write-Host "      winget install Python.Python.3.12"
    exit 1
}

$pyVer = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "    python $pyVer"

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Host "[!] .NET SDK is required to build the MSI. Install with:"
    Write-Host "      winget install Microsoft.DotNet.SDK.8"
    Write-Host "    (continuing — wheel + binary builds will still work)"
}

Write-Host ">>> Installing Python build dependencies..."
python -m pip install --quiet --upgrade pip
python -m pip install --quiet build pyinstaller pyyaml pywin32

Write-Host ">>> Installing cairn in editable mode..."
python -m pip install -e ".[all]"

# Conventional-commit enforcement: PR titles/commits drive releases via
# python-semantic-release, so catch malformed messages at commit time.
# The hook is POSIX sh; Git for Windows runs it under its bundled sh.
if ((Test-Path ".git") -and (Test-Path ".githooks")) {
    Write-Host ">>> Enabling repo git hooks (.githooks/commit-msg)..."
    git config core.hooksPath .githooks
}

if (Get-Command dotnet -ErrorAction SilentlyContinue) {
    if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
        Write-Host ">>> Installing WiX (.NET tool) for MSI builds..."
        dotnet tool install --global wix
        $env:PATH = "$env:USERPROFILE\.dotnet\tools;$env:PATH"
    }
    wix extension add -g WixToolset.UI.wixext   | Out-Null
    wix extension add -g WixToolset.Util.wixext | Out-Null
}

Write-Host ""
Write-Host "Bootstrap complete. Try:"
Write-Host "  cairn --version"
Write-Host "  .\scripts\build-windows.ps1     # produce dist/cairn-windows-x86_64.exe and .msi"
Write-Host ""
