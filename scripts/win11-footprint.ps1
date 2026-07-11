# scripts/win11-footprint.ps1
#
# Windows 11 (arm64 runner) footprint captures: install the common-desktop
# app set via winget and capture what each did. cairn runs from the
# pip-installed package (`python -m cairn`) — a capture needs no MSI; the
# exe/MSI pipeline stays x64 (windows-latest) for now.
#
# The set deliberately spans the three Windows privilege shapes:
#   plain apps        7zip, notepad++, vlc-style — files + registry, no principals
#   per-user installs vscode, python, slack, zoom — land under %LOCALAPPDATA%,
#                     BYPASSING Program Files ACLs (users can modify their own
#                     binaries; the AppLocker story) — not covered by the
#                     Server 2025 captures at all
#   service-bearing   chrome/firefox/adobe updater services + scheduled tasks
#
# winget resolves native arm64 builds where they exist (chrome, firefox,
# vscode, git, python, 7zip, notepad++) and x64-under-emulation otherwise
# (zoom, slack, adobe) — either way the footprint mechanics are identical.
#
# Each app is a SOFT capture (winget flakiness or a package without an
# arm-compatible build logs [i] and moves on); the script fails only if
# NOTHING captured. The CI job is additionally continue-on-error (soak).

$ErrorActionPreference = 'Stop'
function Step($m) { Write-Host "`n== $m" }

Step "environment"
Write-Host "    $(cmd /c ver)"
python --version
python -c "import platform; print('    arch:', platform.machine())"

# ---------------------------------------------------------------------------
# winget bootstrap. Unlike windows-latest (Server 2025), the windows-11-arm
# runner image does not expose winget to the runner session (the App
# Installer package isn't registered for the service account). Bootstrap via
# the official Microsoft.WinGet.Client module — Repair-WinGetPackageManager
# provisions/repairs winget — then resolve the exe (the WindowsApps alias
# usually appears after repair; fall back to the package folder).
# ---------------------------------------------------------------------------
function Resolve-Winget {
    $c = Get-Command winget -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $exe = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe\winget.exe" `
        -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
    if ($exe) { return $exe.FullName }
    return $null
}

Step "ensure winget"
$Winget = Resolve-Winget
if (-not $Winget) {
    Write-Host "    winget not on PATH - bootstrapping via Microsoft.WinGet.Client"
    try {
        Install-PSResource Microsoft.WinGet.Client -TrustRepository -Quiet -ErrorAction Stop
    } catch {
        Install-Module Microsoft.WinGet.Client -Force -Scope CurrentUser -ErrorAction Stop
    }
    Repair-WinGetPackageManager -Force -Latest
    $Winget = Resolve-Winget
}
if (-not $Winget) { throw "winget unavailable after bootstrap" }
Write-Host "    winget: $Winget ($(& $Winget --version))"

$settle = if ($env:CAIRN_SETTLE_SECONDS) { [int]$env:CAIRN_SETTLE_SECONDS } else { 20 }

# Per-app watch paths: scoped tight so baselines stay fast. Every app also
# watches System32\Tasks (updater tasks) + the Services registry subtree
# (updater/maintenance services). Nonexistent paths at baseline are fine —
# they exist after the install and show up as added.
$apps = @(
    @{ Name = "chrome";     WingetId = "Google.Chrome"
       Paths = @("C:\Program Files\Google", "C:\Program Files (x86)\Google") }
    @{ Name = "7zip";       WingetId = "7zip.7zip"
       Paths = @("C:\Program Files\7-Zip") }
    @{ Name = "firefox";    WingetId = "Mozilla.Firefox"
       Paths = @("C:\Program Files\Mozilla Firefox",
                 "C:\Program Files (x86)\Mozilla Maintenance Service") }
    @{ Name = "notepadpp";  WingetId = "Notepad++.Notepad++"
       Paths = @("C:\Program Files\Notepad++") }
    # Per-user shape: default scope installs under %LOCALAPPDATA%\Programs.
    @{ Name = "vscode";     WingetId = "Microsoft.VisualStudioCode"
       Paths = @("$env:LOCALAPPDATA\Programs") }
    @{ Name = "git";        WingetId = "Git.Git"
       Paths = @("C:\Program Files\Git") }
    @{ Name = "python";     WingetId = "Python.Python.3.12"
       Paths = @("$env:LOCALAPPDATA\Programs") }
    @{ Name = "adobereader"; WingetId = "Adobe.Acrobat.Reader.64-bit"
       Paths = @("C:\Program Files\Adobe", "C:\Program Files (x86)\Adobe") }
    @{ Name = "zoom";       WingetId = "Zoom.Zoom"
       Paths = @("C:\Program Files\Zoom", "$env:APPDATA\Zoom") }
    @{ Name = "slack";      WingetId = "SlackTechnologies.Slack"
       Paths = @("C:\Program Files\Slack", "$env:LOCALAPPDATA\slack") }
)

$captured = 0
foreach ($app in $apps) {
    Step "footprint($($app.Name)): baseline, install, capture"
    $cfg = "$env:TEMP\cairn-fp-$($app.Name).json"
    $db  = "$env:TEMP\cairn-fp-$($app.Name).db"
    $fp  = "footprint-windows11-$($app.Name).json"
    @{
        db_path = $db
        paths = @($app.Paths + "$env:SystemRoot\System32\Tasks")
        store_content = $false
        registry_keys = @("HKLM\System\CurrentControlSet\Services")
        registry_recursive = $true
        registry_max_depth = 2
    } | ConvertTo-Json | Out-File -FilePath $cfg -Encoding ascii

    python -m cairn all init --config $cfg --force | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    [i] $($app.Name): baseline failed — skipping"
        continue
    }
    $ok = $true
    try {
        & $Winget install --id $app.WingetId --silent --accept-package-agreements `
            --accept-source-agreements --disable-interactivity 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    } catch { $ok = $false }
    if (-not $ok) {
        Write-Host "    [i] $($app.Name): winget install unavailable/failed — skipping"
        continue
    }
    Start-Sleep -Seconds $settle

    python -m cairn footprint --config $cfg --app $app.Name --report $fp
    if ($LASTEXITCODE -ne 1) {
        Write-Host "    [i] $($app.Name): no footprint delta (exit $LASTEXITCODE) — skipping"
        Remove-Item $fp -ErrorAction SilentlyContinue
        continue
    }
    $captured++

    $m = Get-Content $fp -Raw | ConvertFrom-Json
    $s = $m.summary
    $svc  = @($m.services.windows_services)  | ForEach-Object { $_.name }
    $task = @($m.scheduled.scheduled_tasks)  | ForEach-Object { $_.name }
    Write-Host "    files+ $($s.files_added)  reg+ $($s.registry_values_added)  services $($s.services)  tasks $($s.scheduled_tasks)  risks $($s.risks)"
    if ($svc)  { Write-Host "    services: $($svc -join ', ')" }
    if ($task) { Write-Host "    tasks:    $($task -join ', ')" }
    # Self-documented degradation (e.g. pywin32 missing on arm64): surface it.
    if ($m.permissions_note) { Write-Host "    [i] $($m.permissions_note)" }

    if ($env:GITHUB_STEP_SUMMARY) {
        @(
            "### Windows 11 footprint: $($app.Name) (arm64)",
            "",
            "| files+ | reg values+ | services | tasks | risks |",
            "|---|---|---|---|---|",
            "| $($s.files_added) | $($s.registry_values_added) | $($s.services) | $($s.scheduled_tasks) | $($s.risks) |",
            "",
            $(if ($svc)  { "Services: $($svc -join ', ')" } else { "" }),
            $(if ($task) { "Tasks: $($task -join ', ')" } else { "" }),
            ""
        ) | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
    }
}

if ($captured -eq 0) { throw "no app produced a footprint — see per-app [i] lines above" }
Write-Host "`nWIN11 FOOTPRINT PASS ($captured/$($apps.Count) apps captured)"
