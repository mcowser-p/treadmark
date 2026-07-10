"""cairn.winsemantic — parse security-relevant objects out of a Windows
install footprint.

The Windows analog of cairn.semantic. Where the Linux side reads systemd
units and /etc/passwd, here we reconstruct:

  - Windows services   — from the registry Services subtree (the run-as
                         identity `ObjectName` is the Windows `User=`)
  - scheduled tasks    — from Task Scheduler XML under %SystemRoot%\\...\\Tasks
  - the file surface   — bucketed by Windows category (System32, Program
                         Files, drivers, IIS, startup, …)

Everything is pure/parsing — the collection (walking the live registry and
filesystem) and the risk assembly live in footprint.py. This module has no
Windows-only imports, so its parsers are unit-testable on any OS with
fixture data.

Install-time only, same caveat as the Linux footprint: this describes what
an installer wrote to disk and the registry, not runtime behaviour.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from xml.etree import ElementTree as ET

SCHEMA_VERSION = "1.0-windows"


# ---------------------------------------------------------------------------
# Registry value-repr decoding (mirror of winreg_mon._value_to_repr encoding)
# ---------------------------------------------------------------------------

def unwrap_repr(value_repr: str):
    """Decode a winreg_mon value_repr back to a Python value.

    STR:x → "x"   INT:5 → 5   MULTI_SZ:a\\x00b → ["a","b"]   BIN:hex → bytes
    Unknown/typed forms return the raw string after the first ':'.
    """
    if value_repr is None:
        return None
    if value_repr.startswith("STR:"):
        return value_repr[4:]
    if value_repr.startswith("INT:"):
        try:
            return int(value_repr[4:])
        except ValueError:
            return value_repr[4:]
    if value_repr.startswith("MULTI_SZ:"):
        body = value_repr[len("MULTI_SZ:"):]
        return [s for s in body.split("\x00") if s]
    if value_repr.startswith("BIN:"):
        try:
            return bytes.fromhex(value_repr[4:])
        except ValueError:
            return value_repr[4:]
    _, _, rest = value_repr.partition(":")
    return rest or value_repr


# ---------------------------------------------------------------------------
# Windows services (from the registry Services subtree)
# ---------------------------------------------------------------------------

# Start (REG_DWORD) → human label
_START_TYPES = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}

# Service run-as accounts that are effectively SYSTEM / high-privilege.
_SYSTEM_ACCOUNTS = {
    "localsystem",
    "nt authority\\system",
    ".\\localsystem",
}

# Built-in service accounts that are NOT full SYSTEM (lower privilege).
_BUILTIN_LOW = {
    "nt authority\\networkservice",
    "nt authority\\localservice",
}

# Anchored: matches ONLY the exact service key (…\Services\<name>) — used to
# group a service's own values, ignoring its subkeys (Parameters, Security).
_SERVICES_KEY = re.compile(
    r"\\services\\(?P<name>[^\\]+)$", re.IGNORECASE)

# Unanchored: the service segment from ANY path under Services, including a
# subkey (…\Services\<name>\Parameters\… → <name>) — used to detect which
# services an install touched, even if only a subkey value changed.
_SERVICE_IN_PATH = re.compile(
    r"\\services\\(?P<name>[^\\]+)", re.IGNORECASE)


@dataclass
class WindowsService:
    name: str
    key_path: str
    display_name: Optional[str] = None
    image_path: Optional[str] = None      # ImagePath (the binary + args)
    start_type: Optional[str] = None       # auto | manual | disabled | boot | system
    service_type: Optional[int] = None     # raw Type dword
    run_as: str = "LocalSystem"            # ObjectName; default is LocalSystem
    depends_on: list[str] = field(default_factory=list)
    description: Optional[str] = None

    @property
    def runs_as_system(self) -> bool:
        return self.run_as.strip().lower() in _SYSTEM_ACCOUNTS

    @property
    def runs_as_builtin(self) -> bool:
        return self.run_as.strip().lower() in (_SYSTEM_ACCOUNTS | _BUILTIN_LOW)

    @property
    def image_binary(self) -> Optional[str]:
        """The executable path from ImagePath, stripping args and quotes."""
        return service_image_binary(self.image_path)

    @property
    def is_driver(self) -> bool:
        """Kernel-mode / filesystem driver: Type 1 (SERVICE_KERNEL_DRIVER) or
        2 (SERVICE_FILE_SYSTEM_DRIVER), or an image ending in .sys."""
        if self.service_type in (1, 2):
            return True
        return (self.image_binary or "").lower().endswith(".sys")


def service_image_binary(image_path: Optional[str]) -> Optional[str]:
    """Extract the executable path from a service ImagePath (drops args)."""
    if not image_path:
        return None
    s = image_path.strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        return s[1:end] if end > 0 else s[1:]
    # unquoted: the binary is up to the first space that ends a .exe/.sys/.dll
    m = re.match(r'^(.*?\.(?:exe|sys|dll))(?:\s|$)', s, re.IGNORECASE)
    if m:
        return m.group(1)
    return s.split(" ")[0]


def service_name_from_key(key_path: str) -> Optional[str]:
    """Return the service <name> for any path under …\\Services\\<name> —
    the service key itself OR any subkey (so a change under Parameters still
    identifies the service that was touched). None if not under Services."""
    m = _SERVICE_IN_PATH.search(key_path or "")
    return m.group("name") if m else None


# Windows services that mutate on their own between any two scans, independent
# of whatever you're installing: the time service rewrites LastKnownGoodTime on
# every NTP sync, the Defender family churns on definition updates, and BITS /
# the update + servicing stack toggle during any background transfer or feature
# install. In an INSTALL FOOTPRINT — "what did this installer write?" — these
# are noise, so `cairn footprint` drops them by default (override with
# footprint_include_noise / `--include-noise`). They are deliberately NOT
# filtered by the FIM registry monitor (`cairn registry` / `all`), where a
# Defender or time-service change may be exactly the tampering you want to see.
NOISE_SERVICES = frozenset({
    "w32time",          # NTP: LastKnownGoodTime updates itself
    "bits",             # Background Intelligent Transfer — toggles on transfers
    "wuauserv",         # Windows Update
    "dosvc",            # Delivery Optimization
    "sppsvc",           # Software Protection Platform (SvcRestartTask)
    "trustedinstaller", # component servicing — churns on feature installs
    "windefend", "wdfilter", "wdnissvc", "wdnisdrv",   # Defender family:
    "wdboot", "wdainisdrv", "sense", "mdcoresvc",      #   constant def updates
    "sharedaccess",     # Internet Connection Sharing
})


def is_noise_service(name: Optional[str]) -> bool:
    """True if `name` is a known background-churn OS service (see
    NOISE_SERVICES). Case-insensitive; False for None/empty."""
    return bool(name) and name.lower() in NOISE_SERVICES


def parse_windows_services(reg_records) -> list[WindowsService]:
    """Reconstruct WindowsService objects from registry records under
    ...\\Services\\<name>. `reg_records` is any iterable of objects with
    `.key_path`, `.value_name`, `.value_repr` (cairn.winreg_mon.RegRecord).

    Only the immediate service key is read — sub-subkeys like Parameters or
    Security are ignored for identity purposes.
    """
    by_service: dict[str, dict] = {}
    for rec in reg_records:
        m = _SERVICES_KEY.search(rec.key_path or "")
        if not m:
            continue
        name = m.group("name")
        svc = by_service.setdefault(name, {"key_path": rec.key_path, "values": {}})
        vname = (rec.value_name or "").lower()
        if vname and vname not in ("<key>", "(default)"):
            svc["values"][vname] = unwrap_repr(rec.value_repr)

    out: list[WindowsService] = []
    for name, data in sorted(by_service.items()):
        v = data["values"]
        start = v.get("start")
        depends = v.get("dependonservice")
        if isinstance(depends, str):
            depends = [depends] if depends else []
        out.append(WindowsService(
            name=name,
            key_path=data["key_path"],
            display_name=v.get("displayname"),
            image_path=v.get("imagepath"),
            start_type=_START_TYPES.get(start) if isinstance(start, int) else None,
            service_type=v.get("type") if isinstance(v.get("type"), int) else None,
            run_as=(v.get("objectname") or "LocalSystem"),
            depends_on=depends or [],
            description=v.get("description"),
        ))
    return out


# ---------------------------------------------------------------------------
# Scheduled tasks (Task Scheduler XML)
# ---------------------------------------------------------------------------

_TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


@dataclass
class ScheduledTask:
    name: str
    source_path: str
    run_as: Optional[str] = None           # Principal UserId or GroupId
    run_level: Optional[str] = None        # LeastPrivilege | HighestAvailable
    logon_type: Optional[str] = None
    command: Optional[str] = None
    arguments: Optional[str] = None
    triggers: list[str] = field(default_factory=list)

    @property
    def runs_elevated(self) -> bool:
        return (self.run_level or "").lower() == "highestavailable"

    @property
    def runs_as_system(self) -> bool:
        ra = (self.run_as or "").strip().lower()
        return ra in ("system", "nt authority\\system", "s-1-5-18", "localsystem")


def _t(tag: str) -> str:
    return _TASK_NS + tag


def parse_scheduled_task(path: str, xml: str) -> Optional[ScheduledTask]:
    """Parse a Task Scheduler XML definition. Returns None if it isn't a task
    document (so callers can pass arbitrary changed files safely)."""
    if not xml:
        return None
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    if not root.tag.endswith("Task"):
        return None

    name = path.replace("/", "\\").rsplit("\\", 1)[-1]

    run_as = run_level = logon_type = None
    principals = root.find(_t("Principals"))
    if principals is not None:
        p = principals.find(_t("Principal"))
        if p is not None:
            uid = p.find(_t("UserId"))
            gid = p.find(_t("GroupId"))
            run_as = (uid.text if uid is not None else
                      gid.text if gid is not None else None)
            rl = p.find(_t("RunLevel"))
            run_level = rl.text if rl is not None else None
            lt = p.find(_t("LogonType"))
            logon_type = lt.text if lt is not None else None

    command = arguments = None
    actions = root.find(_t("Actions"))
    if actions is not None:
        exec_el = actions.find(_t("Exec"))
        if exec_el is not None:
            cmd = exec_el.find(_t("Command"))
            args = exec_el.find(_t("Arguments"))
            command = cmd.text if cmd is not None else None
            arguments = args.text if args is not None else None

    triggers: list[str] = []
    trig = root.find(_t("Triggers"))
    if trig is not None:
        for child in trig:
            triggers.append(child.tag.replace(_TASK_NS, ""))

    return ScheduledTask(
        name=name, source_path=path, run_as=run_as, run_level=run_level,
        logon_type=logon_type, command=command, arguments=arguments,
        triggers=triggers,
    )


# ---------------------------------------------------------------------------
# Windows path classification
# ---------------------------------------------------------------------------

_WIN_CLASSIFIERS: list[tuple[str, re.Pattern]] = [
    ("scheduled_task", re.compile(r"[\\/](system32|syswow64)[\\/]tasks[\\/]|[\\/]windows[\\/]tasks[\\/]", re.I)),
    ("startup",        re.compile(r"[\\/]start menu[\\/]programs[\\/]startup[\\/]", re.I)),
    ("hosts",          re.compile(r"[\\/]drivers[\\/]etc[\\/]hosts$", re.I)),
    ("driver",         re.compile(r"[\\/]system32[\\/]drivers[\\/].+\.sys$", re.I)),
    ("iis",            re.compile(r"[\\/](inetsrv|inetpub)[\\/]", re.I)),
    ("service_binary", re.compile(r"[\\/](program files|program files \(x86\))[\\/].+\.exe$", re.I)),
    ("system32",       re.compile(r"[\\/]system32[\\/]", re.I)),
    ("program_files",  re.compile(r"[\\/]program files( \(x86\))?[\\/]", re.I)),
    ("programdata",    re.compile(r"[\\/]programdata[\\/]", re.I)),
    ("windows",        re.compile(r"[\\/]windows[\\/]", re.I)),
]


def classify_windows_path(path: str) -> str:
    p = (path or "").replace("/", "\\")
    for name, pat in _WIN_CLASSIFIERS:
        if pat.search(p):
            return name
    return "other"


# ---------------------------------------------------------------------------
# ACL interpretation — the Windows analog of "world-writable" on Linux
# ---------------------------------------------------------------------------
# cairn.files.get_acl encodes each ACE as "<type>:<flags>:<mask_hex8>:<principal>"
# joined by ';'. ACE type 0 == ACCESS_ALLOWED.

# Broad principals whose write access is a red flag on a program/system file.
_BROAD_PRINCIPALS = (
    "everyone",
    "builtin\\users",
    "\\users",
    "nt authority\\authenticated users",
    "authenticated users",
)

# Write-specific access-mask bits only (NOT FILE_ALL_ACCESS, which also sets
# READ_CONTROL/SYNCHRONIZE that read-only ACLs carry — a full-access mask is
# still caught via its FILE_WRITE_DATA bits below):
#   FILE_WRITE_DATA 0x2, FILE_APPEND_DATA 0x4, FILE_WRITE_EA 0x10,
#   FILE_WRITE_ATTRIBUTES 0x100, DELETE 0x10000, WRITE_DAC 0x40000,
#   WRITE_OWNER 0x80000, GENERIC_WRITE 0x40000000, GENERIC_ALL 0x10000000.
_WRITE_MASK = (0x00000002 | 0x00000004 | 0x00000010 | 0x00000100 |
               0x00010000 | 0x00040000 | 0x00080000 | 0x40000000 | 0x10000000)


def acl_permissive_principal(acl: Optional[str]) -> Optional[str]:
    """If the DACL grants write/modify/full to a broad principal (Everyone,
    Users, Authenticated Users), return that principal; else None. This is the
    Windows equivalent of a world-writable file."""
    if not acl:
        return None
    for ace in acl.split(";"):
        parts = ace.split(":")
        if len(parts) < 4:
            continue
        ace_type, _flags, mask_hex, principal = parts[0], parts[1], parts[2], ":".join(parts[3:])
        if ace_type != "0":                 # only ACCESS_ALLOWED grants access
            continue
        try:
            mask = int(mask_hex, 16)
        except ValueError:
            continue
        p = principal.strip().lower()
        if (mask & _WRITE_MASK) and any(p == b or p.endswith(b) for b in _BROAD_PRINCIPALS):
            return principal
    return None


# Groups whose membership confers meaningful privilege on Windows.
PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins",
    "backup operators", "server operators", "account operators",
    "print operators", "remote desktop users", "hyper-v administrators",
    "iis_iusrs",  # not privileged per se, but worth surfacing on IIS installs
}
