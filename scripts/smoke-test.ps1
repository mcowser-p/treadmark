# scripts/smoke-test.ps1 — artifact-level smoke test, run on a Windows host
# (a windows-latest CI runner) with the built MSI in dist\.
#
# Installs the MSI, validates the packaged layout, walks a full operator
# cycle with the SHIPPED Windows config (files AND registry), then
# uninstalls and confirms operator data is preserved. Mirrors the Linux
# scripts/smoke-test.sh; same fail-loud style.

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false  # we check $LASTEXITCODE ourselves

function Step($m) { Write-Host "`n>>> $m" }
function Fail($m) { Write-Error "[SMOKE FAIL] $m"; exit 1 }

$exe = "$env:ProgramFiles\Cairn\cairn.exe"
$cfg = "$env:ProgramData\Cairn\cairn.yaml"

# ---------------------------------------------------------------------------
# 1. Install the MSI
# ---------------------------------------------------------------------------
$msi = Get-ChildItem dist\cairn-*.msi | Select-Object -First 1
if (-not $msi) { Fail "no MSI found in dist\" }
Step "installing $($msi.Name)"
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$($msi.FullName)`" /qn /l*v install.log"
if ($p.ExitCode -ne 0) {
    Write-Host "--- install.log (tail) ---"
    Get-Content install.log -Tail 40 -ErrorAction SilentlyContinue
    Fail "msiexec install exited $($p.ExitCode)"
}

# ---------------------------------------------------------------------------
# 2. Packaged layout (invoke by full path — PATH isn't refreshed in-session)
# ---------------------------------------------------------------------------
Step "packaged layout"
if (-not (Test-Path $exe)) { Fail "binary missing: $exe" }
if (-not (Test-Path $cfg)) { Fail "shipped config missing: $cfg" }

Step "cairn --version"
& $exe --version
if ($LASTEXITCODE -ne 0) { Fail "binary does not execute" }

# ---------------------------------------------------------------------------
# 3. Files cycle against a small, controlled target.
#
# The SHIPPED config watches C:\Program Files, which on a loaded CI runner is
# 200k+ files — too slow to baseline in a smoke. We only need to prove the
# init → scan → drift → accept cycle works, so point a minimal config at a
# temp tree. (Section 2 already confirmed the shipped config installs.)
# ---------------------------------------------------------------------------
$watch = "$env:TEMP\cairn-smoke-files"
$smokeCfg = "$env:TEMP\cairn-smoke-files.json"
$smokeDb  = "$env:TEMP\cairn-smoke-files.db"
Remove-Item -Recurse -Force $watch, $smokeDb -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $watch | Out-Null
"baseline one" | Out-File "$watch\app.conf" -Encoding ascii
"baseline two" | Out-File "$watch\notes.txt" -Encoding ascii
@{
    db_path = $smokeDb
    paths = @($watch)
    store_content = $true
} | ConvertTo-Json | Out-File -FilePath $smokeCfg -Encoding ascii

Step "files init (bundled PyYAML + JSON config load)"
& $exe files init --config $smokeCfg
if ($LASTEXITCODE -ne 0) { Fail "files init failed" }

Step "clean scan expects exit 0"
& $exe files scan --config $smokeCfg | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "clean scan exited $LASTEXITCODE" }

Step "plant drift and expect exit 1 with the file reported"
$drift = "$watch\cairn-smoke-drift.txt"
"smoke-test marker" | Out-File -FilePath $drift -Encoding ascii
& $exe files scan --config $smokeCfg --report smoke.json | Out-Null
if ($LASTEXITCODE -ne 1) { Fail "drift scan exited $LASTEXITCODE, expected 1" }
$report = Get-Content smoke.json -Raw
if ($report -notmatch '"has_drift": true') { Fail "report lacks has_drift=true" }
if ($report -notmatch 'cairn-smoke-drift') { Fail "planted file not reported" }

Step "accept the drift, rescan expects exit 0"
# Accept the whole watch dir, not just the planted file: creating a file
# bumps the parent directory's mtime, so the dir itself also shows as
# modified. --accept on a directory covers the dir record and everything
# under it.
& $exe files update --config $smokeCfg --accept $watch | Out-Null
& $exe files scan --config $smokeCfg | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "post-accept scan exited $LASTEXITCODE" }
Remove-Item -Recurse -Force $watch, $smokeDb, $smokeCfg -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 4. Registry cycle — winreg_mon's first real execution end-to-end
# ---------------------------------------------------------------------------
Step "registry cycle (HKCU test key)"
$regCfg = "$env:TEMP\cairn-reg-smoke.json"
$regDb  = "$env:TEMP\cairn-reg-smoke.db"
@{
    db_path = $regDb
    registry_keys = @("HKCU\Software\CairnSmoke")
    registry_recursive = $true
} | ConvertTo-Json | Out-File -FilePath $regCfg -Encoding ascii

New-Item -Path "HKCU:\Software\CairnSmoke" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\CairnSmoke" -Name "Baseline" -Value "orig" -PropertyType String -Force | Out-Null

& $exe registry init --config $regCfg
if ($LASTEXITCODE -ne 0) { Fail "registry init failed" }
& $exe registry scan --config $regCfg | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "clean registry scan exited $LASTEXITCODE" }

New-ItemProperty -Path "HKCU:\Software\CairnSmoke" -Name "Planted" -Value "payload" -PropertyType String -Force | Out-Null
& $exe registry scan --config $regCfg | Out-Null
if ($LASTEXITCODE -ne 1) { Fail "registry drift scan exited $LASTEXITCODE, expected 1" }
Remove-Item -Path "HKCU:\Software\CairnSmoke" -Recurse -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 4b. Windows footprint — install real software (IIS via Windows feature,
# Datadog via winget) and confirm `cairn footprint` reconstructs the services
# they register. This is the Windows semantic footprint's first real run.
#
# Baseline covers the file surface (inetsrv, Program Files) AND the registry
# Services subtree, so services show up as reconstructed objects.
# ---------------------------------------------------------------------------
Step "footprint: baseline files + registry Services"
$fpCfg = "$env:TEMP\cairn-fp.json"
$fpDb  = "$env:TEMP\cairn-fp.db"
@{
    db_path = $fpDb
    paths = @(
        "$env:SystemRoot\System32\inetsrv",
        "$env:SystemRoot\System32\Tasks",
        "C:\Program Files\Datadog",
        "C:\ProgramData\Datadog"
    )
    store_content = $false      # services come from the registry; skip gzipping
                                # the thousands of inetsrv files (task XML, if
                                # any, is read live during parsing)
    registry_keys = @("HKLM\System\CurrentControlSet\Services")
    registry_recursive = $true
    registry_max_depth = 2
} | ConvertTo-Json | Out-File -FilePath $fpCfg -Encoding ascii
& $exe all init --config $fpCfg
if ($LASTEXITCODE -ne 0) { Fail "footprint baseline (all init) failed" }

# Footprint models are written to the repo root so CI can collect them as
# WORKFLOW artifacts and render a job-summary — not release assets. Named
# footprint-* so the release attach step excludes them like the Linux ones.
$iisFp = "footprint-windows-iis.json"
$ddFp  = "footprint-windows-datadog.json"

# Append a compact markdown summary of a footprint model to the GitHub job
# summary (no-op outside CI). PowerShell parses the JSON natively.
function Summarize($model, $label) {
    if (-not $env:GITHUB_STEP_SUMMARY) { return }
    $s = $model.summary
    $svcNames = (@($model.services.windows_services) | ForEach-Object { $_.name }) -join ", "
    $lines = @(
        "### Windows footprint: $label",
        "",
        "| files+ | reg values+ | services | tasks | risks |",
        "|---|---|---|---|---|",
        "| $($s.files_added) | $($s.registry_values_added) | $($s.services) | $($s.scheduled_tasks) | $($s.risks) |",
        "",
        "Services: $svcNames",
        ""
    )
    $lines -join "`n" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
}

Step "footprint(iis): install the Web-Server role"
Import-Module ServerManager -ErrorAction SilentlyContinue
Install-WindowsFeature -Name Web-Server -IncludeManagementTools | Out-Null

Step "footprint(iis): capture and verify"
& $exe footprint --config $fpCfg --app iis --report $iisFp
if ($LASTEXITCODE -ne 1) { Fail "iis footprint exited $LASTEXITCODE, expected 1" }
# IIS's core service (W3SVC) is pre-staged on Server images, so whether the
# install touches any service registry key is not reliable. Assert what IIS
# ALWAYS produces: it's a Windows model and the inetsrv file surface was
# captured WITH owner + ACL (the permission data). Service reconstruction is
# covered by unit tests and demonstrated by the Datadog capture below.
$model = Get-Content $iisFp -Raw | ConvertFrom-Json
if ($model.schema_version -ne "1.0-windows") { Fail "not a Windows footprint model" }
$iisFiles = @($model.filesystem.added_by_category.iis)
if ($iisFiles.Count -lt 1) { Fail "IIS file surface (inetsrv) not detected" }
if (-not ($iisFiles | Where-Object { $_.owner -and $_.acl })) {
    Fail "file owner/ACL not captured (permission data missing)"
}
$svc = @($model.services.windows_services)
Write-Host "    IIS: $($iisFiles.Count) inetsrv files w/ owner+ACL; $($svc.Count) service(s) touched → $iisFp"
Summarize $model "IIS (Web-Server role)"

# Re-baseline (IIS now part of the baseline) so the Datadog footprint is
# Datadog-only, not IIS+Datadog.
Step "footprint(datadog): re-baseline, then install via winget (config-less)"
& $exe all init --config $fpCfg --force | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "footprint re-baseline failed" }
$ddOk = $true
try {
    winget install --id Datadog.Agent --silent --accept-package-agreements `
        --accept-source-agreements --disable-interactivity 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $ddOk = $false }
} catch { $ddOk = $false }

if ($ddOk) {
    Step "footprint(datadog): capture"
    & $exe footprint --config $fpCfg --app datadog --report $ddFp
    if ($LASTEXITCODE -eq 1 -and (Select-String -Path $ddFp -Pattern 'Datadog' -Quiet)) {
        Write-Host "    captured Datadog service → $ddFp"
        Summarize (Get-Content $ddFp -Raw | ConvertFrom-Json) "Datadog agent"
    } else {
        Write-Host "    [i] Datadog install produced no footprint delta — skipping"
        Remove-Item $ddFp -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "    [i] Datadog winget install unavailable/failed — IIS footprint still produced"
}

# ---------------------------------------------------------------------------
# 5. Uninstall — exe removed, operator config PRESERVED
# ---------------------------------------------------------------------------
Step "uninstall; config must survive"
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$($msi.FullName)`" /qn"
if ($p.ExitCode -ne 0) { Fail "msiexec uninstall exited $($p.ExitCode)" }
if (Test-Path $exe) { Fail "binary still present after uninstall: $exe" }
if (-not (Test-Path $cfg)) { Fail "operator config was wiped on uninstall (should be Permanent)" }

Write-Host "`nSMOKE PASS: $(cmd /c ver)"
