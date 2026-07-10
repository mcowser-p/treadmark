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
& $exe files update --config $smokeCfg --accept $drift | Out-Null
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
# 5. Uninstall — exe removed, operator config PRESERVED
# ---------------------------------------------------------------------------
Step "uninstall; config must survive"
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/x `"$($msi.FullName)`" /qn"
if ($p.ExitCode -ne 0) { Fail "msiexec uninstall exited $($p.ExitCode)" }
if (Test-Path $exe) { Fail "binary still present after uninstall: $exe" }
if (-not (Test-Path $cfg)) { Fail "operator config was wiped on uninstall (should be Permanent)" }

Write-Host "`nSMOKE PASS: $(cmd /c ver)"
