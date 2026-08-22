# Windows MSI packaging

Files in this directory:

| File | Purpose |
|---|---|
| `treadmark.wxs` | WiX source — defines the MSI's structure, files, PATH entry, ARP entry, upgrade behavior |
| `License.rtf` | Shown in the installer's license-agreement dialog. Replace with your real license. |
| `treadmark.ico` | Icon shown in "Programs and Features". Replace with your branded icon. |
| `examples/register-treadmark-task.ps1` | Operator-run script to register the hourly scheduled task. |

## Building the MSI

The build is driven by `..\scripts\build-windows.ps1` — it installs WiX, registers the required extensions, runs PyInstaller for the .exe, then `wix build` for the MSI. Run it on a Windows host with .NET SDK 6+.

If you want to invoke `wix build` by hand for a debugging cycle:

```powershell
# one-time setup
dotnet tool install -g wix
wix extension add -g WixToolset.UI.wixext
wix extension add -g WixToolset.Util.wixext

# build (run from this directory; expects treadmark-windows-x86_64.exe and treadmark.yaml staged here)
wix build treadmark.wxs `
    -arch x64 `
    -d Version=0.2.0 `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -o treadmark-0.2.0.msi
```

## Testing the install

```powershell
# Quiet install (basic UI, no prompts):
msiexec /i treadmark-0.2.0.msi /qb /l*v install.log

# Verify the install:
treadmark --version                                  # should print version
Test-Path "$env:ProgramData\Treadmark\treadmark.yaml"    # should be True
Test-Path "$env:ProgramFiles\Treadmark\treadmark.exe"    # should be True

# Build the baseline + a manual scan (files AND registry — `all` runs both):
treadmark all init --config "$env:ProgramData\Treadmark\treadmark.yaml"
treadmark all scan --config "$env:ProgramData\Treadmark\treadmark.yaml"

# Scheduling is a manual ops decision — register an hourly scan yourself, e.g.:
#   schtasks /create /tn "Treadmark scan" /tr "treadmark all scan --config C:\ProgramData\Treadmark\treadmark.yaml" /sc hourly /ru SYSTEM

# Uninstall:
msiexec /x treadmark-0.2.0.msi /qb
# Verify operator data was preserved:
Test-Path "$env:ProgramData\Treadmark\treadmark.yaml"    # should still be True
Test-Path "$env:ProgramData\Treadmark\baseline.db"   # should still be True
```

## Things you'll want to customize before shipping

1. **`UpgradeCode` GUID in `treadmark.wxs`**. Currently `930ffdcd-a101-4776-8189-816e224d76fb` for treadmark. Once you ship a release using a given GUID, that value is permanent for your product line — never change it. Generate a fresh one for any fork with `[guid]::NewGuid()` in PowerShell.
2. **`Manufacturer` and `RegistryKey` paths**. Change `Your Org` and `Software\YourOrg\Treadmark` to your actual organization name.
3. **`License.rtf`** — replace with your real license text.
4. **`treadmark.ico`** — replace with a real icon.
5. **Code signing.** Production MSIs should be Authenticode-signed or AV will flag them and SmartScreen will warn users. After `wix build`:
   ```powershell
   signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
                 /a treadmark-0.2.0.msi
   ```

## Common gotchas

- **Upgrade doesn't replace the old version**: you changed the `UpgradeCode`. Don't.
- **Install fails with "WixUI not found"**: missing `-ext WixToolset.UI.wixext` on the build command.
- **PATH update doesn't take effect immediately**: existing terminals don't see PATH changes. Open a fresh terminal. Or broadcast `WM_SETTINGCHANGE` (advanced; usually not worth it for a server tool).
- **Scheduled task not running**: it isn't registered automatically. Run `examples\register-treadmark-task.ps1` as Administrator after edit­ing `treadmark.yaml`.
