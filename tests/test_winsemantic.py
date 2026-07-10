"""Windows semantic parsers (cairn.winsemantic).

Pure parsing — runs on any OS with fixture data (no winreg needed).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cairn import winsemantic as ws


# A minimal stand-in for cairn.winreg_mon.RegRecord (only the fields the
# parser reads), so these tests need no Windows imports.
@dataclass
class Rec:
    key_path: str
    value_name: str
    value_repr: str


SERVICES = r"HKLM\System\CurrentControlSet\Services"


# ---------------------------------------------------------------------------
# unwrap_repr
# ---------------------------------------------------------------------------

def test_unwrap_repr_types():
    assert ws.unwrap_repr("STR:LocalSystem") == "LocalSystem"
    assert ws.unwrap_repr("INT:2") == 2
    assert ws.unwrap_repr("MULTI_SZ:HTTP\x00WAS") == ["HTTP", "WAS"]
    assert ws.unwrap_repr("BIN:deadbeef") == bytes.fromhex("deadbeef")
    assert ws.unwrap_repr(None) is None


# ---------------------------------------------------------------------------
# Windows services — the IIS W3SVC shape
# ---------------------------------------------------------------------------

def _w3svc_records():
    k = SERVICES + r"\W3SVC"
    return [
        Rec(k, "DisplayName", "STR:World Wide Web Publishing Service"),
        Rec(k, "ImagePath", r"STR:%windir%\system32\svchost.exe -k iissvcs"),
        Rec(k, "Start", "INT:2"),
        Rec(k, "Type", "INT:32"),
        Rec(k, "ObjectName", "STR:LocalSystem"),
        Rec(k, "DependOnService", "MULTI_SZ:HTTP\x00WAS"),
        # a sub-subkey value that must be ignored for identity
        Rec(k + r"\Parameters", "ServiceDll", r"STR:%windir%\system32\iisw3adm.dll"),
    ]


def test_parse_service_identity():
    svcs = ws.parse_windows_services(_w3svc_records())
    assert len(svcs) == 1
    s = svcs[0]
    assert s.name == "W3SVC"
    assert s.display_name == "World Wide Web Publishing Service"
    assert s.start_type == "auto"
    assert s.run_as == "LocalSystem"
    assert s.runs_as_system is True
    assert s.depends_on == ["HTTP", "WAS"]
    assert s.image_binary.lower().endswith("svchost.exe")


def test_parse_service_custom_account_not_system():
    k = SERVICES + r"\DatadogAgent"
    recs = [
        Rec(k, "DisplayName", "STR:Datadog Agent"),
        Rec(k, "ImagePath", r'STR:"C:\Program Files\Datadog\Datadog Agent\bin\agent.exe"'),
        Rec(k, "Start", "INT:2"),
        Rec(k, "ObjectName", "STR:.\\ddagentuser"),
    ]
    s = ws.parse_windows_services(recs)[0]
    assert s.name == "DatadogAgent"
    assert s.run_as == ".\\ddagentuser"
    assert s.runs_as_system is False           # custom account, not SYSTEM
    assert s.image_binary == r"C:\Program Files\Datadog\Datadog Agent\bin\agent.exe"


def test_service_defaults_to_localsystem_when_no_objectname():
    k = SERVICES + r"\NoObjName"
    recs = [Rec(k, "Start", "INT:3"), Rec(k, "ImagePath", r"STR:C:\x.exe")]
    s = ws.parse_windows_services(recs)[0]
    assert s.run_as == "LocalSystem"           # Windows default
    assert s.runs_as_system is True
    assert s.start_type == "manual"


def test_non_service_records_ignored():
    recs = [Rec(r"HKLM\Software\Foo\Run", "x", "STR:y")]
    assert ws.parse_windows_services(recs) == []


def test_service_name_from_key():
    assert ws.service_name_from_key(SERVICES + r"\W3SVC") == "W3SVC"
    # a change under a subkey still identifies the service that was touched
    assert ws.service_name_from_key(SERVICES + r"\BITS\Parameters") == "BITS"
    assert ws.service_name_from_key(SERVICES + r"\W32Time\Config") == "W32Time"
    assert ws.service_name_from_key(r"HKLM\Software\Foo") is None


# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------

TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary></TimeTrigger>
    <BootTrigger/>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
      <LogonType>ServiceAccount</LogonType>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Program Files\\App\\update.exe</Command>
      <Arguments>--silent</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def test_parse_scheduled_task():
    t = ws.parse_scheduled_task(r"C:\Windows\System32\Tasks\App\Update", TASK_XML)
    assert t is not None
    assert t.name == "Update"
    assert t.run_as == "S-1-5-18"
    assert t.run_level == "HighestAvailable"
    assert t.runs_elevated is True
    assert t.runs_as_system is True            # S-1-5-18 = LocalSystem
    assert t.command.endswith("update.exe")
    assert t.arguments == "--silent"
    assert set(t.triggers) == {"TimeTrigger", "BootTrigger"}


def test_parse_scheduled_task_rejects_non_task_xml():
    assert ws.parse_scheduled_task("x", "<html><body/></html>") is None
    assert ws.parse_scheduled_task("x", "not xml at all {") is None
    assert ws.parse_scheduled_task("x", "") is None


# ---------------------------------------------------------------------------
# Path classification
# ---------------------------------------------------------------------------

def test_classify_windows_path():
    c = ws.classify_windows_path
    assert c(r"C:\Windows\System32\Tasks\App\Job") == "scheduled_task"
    assert c(r"C:\inetpub\wwwroot\index.html") == "iis"
    assert c(r"C:\Windows\System32\inetsrv\w3wp.exe") == "iis"
    assert c(r"C:\Program Files\Datadog\agent.exe") == "service_binary"
    assert c(r"C:\Windows\System32\drivers\ddnpm.sys") == "driver"
    assert c(r"C:\Windows\System32\drivers\etc\hosts") == "hosts"
    assert c(r"C:\ProgramData\Datadog\datadog.yaml") == "programdata"
    assert c(r"C:\Users\x\somefile") == "other"


# ---------------------------------------------------------------------------
# Windows risk flagging (footprint._flag_risks_windows) — pure, mac-runnable
# ---------------------------------------------------------------------------

def test_flag_risks_windows():
    from cairn.footprint import _flag_risks_windows

    services = [
        # IIS: auto-start as LocalSystem, image in System32 → low (the norm)
        ws.WindowsService(name="W3SVC", key_path="k1",
                          image_path=r"C:\Windows\System32\svchost.exe -k iissvcs",
                          start_type="auto", run_as="LocalSystem"),
        # Datadog: custom account → medium
        ws.WindowsService(name="DatadogAgent", key_path="k2",
                          image_path=r'"C:\Program Files\Datadog\bin\agent.exe"',
                          start_type="auto", run_as=".\\ddagentuser"),
        # suspicious: image outside standard paths → high
        ws.WindowsService(name="Weird", key_path="k3",
                          image_path=r"C:\Users\Public\evil.exe",
                          start_type="auto", run_as="LocalSystem"),
    ]
    tasks = [
        ws.ScheduledTask(name="Upd", source_path="t", run_as="S-1-5-18",
                         run_level="HighestAvailable"),
    ]
    risks = _flag_risks_windows(services, tasks)
    kinds = {r["kind"]: r["severity"] for r in risks}
    assert kinds["service_image_nonstandard_path"] == "high"
    assert kinds["service_custom_account"] == "medium"
    assert kinds["autostart_service_as_system"] == "low"
    assert kinds["scheduled_task_elevated"] == "medium"


def test_kernel_driver_risk():
    from cairn.footprint import _flag_risks_windows
    # A .sys image (like Datadog's ddnpm) and a Type=1 service both flag high.
    drv_by_ext = ws.WindowsService(
        name="ddnpm", key_path="k",
        image_path=r"\??\C:\Program Files\Datadog\Datadog Agent\bin\agent\driver\ddnpm.sys",
        start_type="disabled", run_as="LocalSystem")
    drv_by_type = ws.WindowsService(name="foo", key_path="k2",
                                    image_path=r"C:\Windows\System32\drivers\foo",
                                    service_type=1, run_as="LocalSystem")
    assert drv_by_ext.is_driver and drv_by_type.is_driver
    risks = _flag_risks_windows([drv_by_ext, drv_by_type], [])
    drv = [r for r in risks if r["kind"] == "kernel_driver_installed"]
    assert len(drv) == 2 and all(r["severity"] == "high" for r in drv)


# ---------------------------------------------------------------------------
# ACL interpretation — world-writable analog
# ---------------------------------------------------------------------------

def test_acl_permissive_principal():
    f = ws.acl_permissive_principal
    # Everyone with GENERIC_WRITE (0x40000000), ACCESS_ALLOWED (type 0)
    assert f("0:0:40000000:Everyone") == "Everyone"
    # BUILTIN\Users with FILE_ALL_ACCESS
    assert f("0:0:001f01ff:BUILTIN\\Users") == "BUILTIN\\Users"
    # Read-only (0x120089) for Everyone → not permissive
    assert f("0:0:00120089:Everyone") is None
    # Write, but for Administrators (not a broad principal) → not flagged
    assert f("0:0:40000000:BUILTIN\\Administrators") is None
    # ACCESS_DENIED (type 1) write for Everyone → not a grant
    assert f("1:0:40000000:Everyone") is None
    assert f(None) is None
    # realistic multi-ACE string: SYSTEM full + Everyone write
    acl = "0:0:001f01ff:NT AUTHORITY\\SYSTEM;0:0:40000000:Everyone"
    assert f(acl) == "Everyone"


def test_flag_windows_world_writable_file():
    from cairn.footprint import _flag_risks_windows
    from dataclasses import dataclass

    @dataclass
    class FR:
        path: str
        acl: str

    added = [
        FR(r"C:\Program Files\App\app.exe", "0:0:40000000:Everyone"),   # high
        FR(r"C:\ProgramData\App\data.txt", "0:0:40000000:BUILTIN\\Users"),  # medium
        FR(r"C:\Program Files\App\readme.txt", "0:0:00120089:Everyone"),   # read-only → none
    ]
    risks = _flag_risks_windows([], [], added)
    ww = [r for r in risks if r["kind"] == "world_writable_file"]
    assert len(ww) == 2
    sev = {r["path"]: r["severity"] for r in ww}
    assert sev[r"C:\Program Files\App\app.exe"] == "high"
    assert sev[r"C:\ProgramData\App\data.txt"] == "medium"
