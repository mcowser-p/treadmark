# scripts/win11-footprint.ps1
#
# Windows 11 (arm64 runner) footprint probe: install Chrome via winget and
# capture what it did. cairn runs from the pip-installed package
# (`python -m cairn`) — a capture needs no MSI; the exe/MSI pipeline stays
# x64 (windows-latest) for now.
#
# Chrome is the chosen first app: winget resolves the native arm64 build,
# and the install registers updater services AND scheduled tasks
# (GoogleUpdater*), exercising the task parser on a client OS for the first
# time. Client-OS signal this run adds over Server 2025: consumer Defender
# churn (tests the NOISE_SERVICES filter) and a desktop servicing profile.
#
# Fails loud (the CI job is continue-on-error while the arm runner soaks).

$ErrorActionPreference = 'Stop'
function Step($m) { Write-Host "`n== $m" }

Step "environment"
Write-Host "    $(cmd /c ver)"
python --version
python -c "import platform; print('    arch:', platform.machine())"

Step "baseline: Google paths + Tasks + registry Services"
$cfg = "$env:TEMP\cairn-fp-chrome.json"
$db  = "$env:TEMP\cairn-fp-chrome.db"
@{
    db_path = $db
    paths = @(
        "C:\Program Files\Google",
        "C:\Program Files (x86)\Google",
        "$env:SystemRoot\System32\Tasks"
    )
    store_content = $false
    registry_keys = @("HKLM\System\CurrentControlSet\Services")
    registry_recursive = $true
    registry_max_depth = 2
} | ConvertTo-Json | Out-File -FilePath $cfg -Encoding ascii
python -m cairn all init --config $cfg
if ($LASTEXITCODE -ne 0) { throw "baseline (all init) failed: $LASTEXITCODE" }

Step "install chrome via winget"
winget install --id Google.Chrome --silent --accept-package-agreements `
    --accept-source-agreements --disable-interactivity
if ($LASTEXITCODE -ne 0) { throw "winget install exited $LASTEXITCODE" }

# Same settle rationale as the Server smoke: let updater services/tasks
# finish registering and install-time churn quiet down before scanning.
$settle = if ($env:CAIRN_SETTLE_SECONDS) { [int]$env:CAIRN_SETTLE_SECONDS } else { 20 }
Start-Sleep -Seconds $settle

Step "capture footprint"
$fp = "footprint-windows11-chrome.json"
python -m cairn footprint --config $cfg --app chrome --report $fp
if ($LASTEXITCODE -ne 1) { throw "footprint exited $LASTEXITCODE, expected 1 (install delta)" }

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
        "### Windows 11 footprint: Chrome (arm64)",
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

Write-Host "`nWIN11 FOOTPRINT PASS"
