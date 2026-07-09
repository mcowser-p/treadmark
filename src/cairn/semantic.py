"""cairn.semantic — parse security-relevant objects out of an install footprint.

The scan machinery tells you *which* files changed. This module tells you what
those changes *mean*: which systemd services were registered and what identity
they run as, which cron jobs were installed, which users and groups were
created, which binaries are setuid, which sudoers rules were dropped in.

The output is designed to be consumed by an agent that builds a least-privilege
access model. Everything is structured; nothing requires the agent to re-parse
config file syntax.

IMPORTANT LIMITATION
--------------------
This is an *install-time* footprint. It describes what an installer wrote to
disk. It does NOT describe what the application accesses at runtime. A policy
derived only from this data will:

  - over-grant on the install tree (the app probably reads 5 of the 500 files
    the installer dropped)
  - under-grant on runtime paths (/tmp, /dev/urandom, /etc/resolv.conf,
    sockets, and anything the app creates on first run)

Treat this as one input to the access model, not the whole truth. The schema
carries a `footprint_type: "install_time"` marker so a downstream agent can
merge it with runtime-observed data (eBPF / auditd / strace) later.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field, asdict
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .files import FileRecord


SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Path classification
# ---------------------------------------------------------------------------
# Ordered most-specific first. First match wins.

_CLASSIFIERS: list[tuple[str, re.Pattern]] = [
    ("systemd_unit",      re.compile(r"^/(etc|usr/lib|lib|run)/systemd/(system|user)/.+\.(service|timer|socket|target|mount|path|slice)$")),
    ("systemd_dropin",    re.compile(r"^/(etc|usr/lib|lib)/systemd/(system|user)/.+\.d/.+\.conf$")),
    ("cron_d",            re.compile(r"^/etc/cron\.d/[^/]+$")),
    ("cron_periodic",     re.compile(r"^/etc/cron\.(hourly|daily|weekly|monthly)/[^/]+$")),
    ("crontab_system",    re.compile(r"^/etc/crontab$")),
    ("crontab_user",      re.compile(r"^/var/spool/cron/(crontabs/)?[^/]+$")),
    ("passwd",            re.compile(r"^/etc/passwd$")),
    ("group",             re.compile(r"^/etc/group$")),
    ("shadow",            re.compile(r"^/etc/(shadow|gshadow)$")),
    ("sudoers",           re.compile(r"^/etc/sudoers(\.d/[^/]+)?$")),
    ("pam",               re.compile(r"^/etc/pam\.d/[^/]+$")),
    ("pam_security",      re.compile(r"^/etc/security/.+$")),
    ("polkit",            re.compile(r"^/(etc|usr/share)/polkit-1/.+$")),
    ("dbus_policy",       re.compile(r"^/(etc|usr/share)/dbus-1/system\.d/.+$")),
    ("sysctl",            re.compile(r"^/etc/sysctl\.(conf|d/.+)$")),
    ("udev_rule",         re.compile(r"^/(etc|usr/lib|lib)/udev/rules\.d/.+$")),
    ("ld_so_conf",        re.compile(r"^/etc/ld\.so\.conf(\.d/.+)?$")),
    ("profile_d",         re.compile(r"^/etc/profile\.d/.+$")),
    ("limits_d",          re.compile(r"^/etc/security/limits\.d/.+$")),
    ("apparmor",          re.compile(r"^/etc/apparmor\.d/.+$")),
    ("selinux",           re.compile(r"^/etc/selinux/.+$")),
    ("logrotate",         re.compile(r"^/etc/logrotate\.d/.+$")),
    ("tmpfiles",          re.compile(r"^/(etc|usr/lib)/tmpfiles\.d/.+$")),
    ("sysusers",          re.compile(r"^/(etc|usr/lib)/sysusers\.d/.+$")),
    ("modprobe",          re.compile(r"^/etc/modprobe\.d/.+$")),
    ("init_script",       re.compile(r"^/etc/init\.d/[^/]+$")),
    ("nsswitch",          re.compile(r"^/etc/nsswitch\.conf$")),
    ("config",            re.compile(r"^/etc/.+$")),
    ("binary",            re.compile(r"^/(usr/)?(local/)?(s?bin)/.+$")),
    ("library",           re.compile(r"^/(usr/)?(local/)?lib(64|32|exec)?/.+$")),
    ("opt_tree",          re.compile(r"^/opt/.+$")),
    ("srv_tree",          re.compile(r"^/srv/.+$")),
    ("state_dir",         re.compile(r"^/var/lib/.+$")),
    ("log_dir",           re.compile(r"^/var/log/.+$")),
    ("cache_dir",         re.compile(r"^/var/cache/.+$")),
    ("runtime_dir",       re.compile(r"^/(run|var/run)/.+$")),
    ("share_data",        re.compile(r"^/usr/share/.+$")),
    ("home",              re.compile(r"^/home/.+$")),
]


def strip_root(path: str, root_prefix: str = "") -> str:
    """Translate a scanned path into its on-target absolute form.

    When footprinting a mounted image, a container rootfs, or a chroot, the
    scanner sees /mnt/image/etc/passwd but the *meaningful* path — the one the
    classifier rules and the generated policy care about — is /etc/passwd.
    root_prefix is that mount point.
    """
    if not root_prefix:
        return path
    rp = root_prefix.rstrip("/")
    if path == rp:
        return "/"
    if path.startswith(rp + "/"):
        return path[len(rp):]
    return path


def classify_path(path: str, root_prefix: str = "") -> str:
    """Bucket a path into a security-relevant category."""
    p = strip_root(path, root_prefix).replace("\\", "/")
    for name, pat in _CLASSIFIERS:
        if pat.match(p):
            return name
    return "other"


# ---------------------------------------------------------------------------
# Data classes for parsed objects
# ---------------------------------------------------------------------------

@dataclass
class SystemdUnit:
    name: str                       # e.g. "myapp.service"
    path: str
    unit_type: str                  # service | timer | socket | ...
    description: Optional[str] = None
    exec_start: list[str] = field(default_factory=list)
    exec_start_pre: list[str] = field(default_factory=list)
    exec_stop: list[str] = field(default_factory=list)
    user: Optional[str] = None      # None means root
    group: Optional[str] = None
    working_directory: Optional[str] = None
    # Hardening / access-relevant directives — exactly what a least-privilege
    # model wants to know about.
    capabilities: list[str] = field(default_factory=list)       # CapabilityBoundingSet
    ambient_capabilities: list[str] = field(default_factory=list)
    read_write_paths: list[str] = field(default_factory=list)
    read_only_paths: list[str] = field(default_factory=list)
    inaccessible_paths: list[str] = field(default_factory=list)
    state_directory: list[str] = field(default_factory=list)
    cache_directory: list[str] = field(default_factory=list)
    logs_directory: list[str] = field(default_factory=list)
    runtime_directory: list[str] = field(default_factory=list)
    configuration_directory: list[str] = field(default_factory=list)
    environment_files: list[str] = field(default_factory=list)
    private_tmp: Optional[bool] = None
    protect_system: Optional[str] = None
    protect_home: Optional[str] = None
    no_new_privileges: Optional[bool] = None
    supplementary_groups: list[str] = field(default_factory=list)
    wanted_by: list[str] = field(default_factory=list)
    # Anything we saw but didn't model, so nothing is silently dropped
    other_directives: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class CronJob:
    source_path: str
    kind: str                       # cron_d | crontab_system | crontab_user | cron_periodic
    schedule: Optional[str]         # None for cron.daily-style scripts
    run_as: Optional[str]           # user field; None = owner of the crontab
    command: str
    raw_line: Optional[str] = None


@dataclass
class UserEntry:
    name: str
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str
    is_system_account: bool         # heuristic: uid < 1000
    login_disabled: bool            # shell is nologin/false


@dataclass
class GroupEntry:
    name: str
    gid: int
    members: list[str] = field(default_factory=list)


@dataclass
class GroupMembershipChange:
    group: str
    gid: Optional[int]
    users_added: list[str] = field(default_factory=list)
    users_removed: list[str] = field(default_factory=list)
    group_is_new: bool = False


@dataclass
class SudoRule:
    source_path: str
    raw_line: str
    principal: Optional[str] = None   # user or %group
    hosts: Optional[str] = None
    runas: Optional[str] = None
    nopasswd: bool = False
    commands: Optional[str] = None


@dataclass
class ExecutableEntry:
    path: str
    mode_octal: str
    mode_symbolic: str
    owner: str
    group: str
    setuid: bool
    setgid: bool
    world_writable: bool
    file_capabilities: Optional[str] = None   # from security.capability xattr


@dataclass
class PathEntry:
    path: str
    category: str
    is_dir: bool
    mode_octal: str
    mode_symbolic: str
    owner: str
    group: str
    size: int
    sha256: Optional[str] = None


# ---------------------------------------------------------------------------
# systemd unit parsing
# ---------------------------------------------------------------------------

# Directives that can legitimately appear multiple times and accumulate.
_MULTI_DIRECTIVES = {
    "ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost",
    "ExecReload", "EnvironmentFile", "Environment", "ReadWritePaths",
    "ReadOnlyPaths", "InaccessiblePaths", "StateDirectory", "CacheDirectory",
    "LogsDirectory", "RuntimeDirectory", "ConfigurationDirectory",
    "SupplementaryGroups", "WantedBy", "RequiredBy", "After", "Before",
    "Wants", "Requires",
}


def _split_list(value: str) -> list[str]:
    """systemd list directives are whitespace-separated."""
    return [v for v in value.split() if v]


def _parse_bool(value: str) -> Optional[bool]:
    v = value.strip().lower()
    if v in ("yes", "true", "1", "on"):
        return True
    if v in ("no", "false", "0", "off"):
        return False
    return None


def parse_systemd_unit(path: str, content: str) -> SystemdUnit:
    """Parse a systemd unit file into structured form.

    We do not use configparser: systemd allows duplicate keys (multiple
    ExecStart= lines), keys with no value (which reset a list), and its
    escaping rules differ from INI. Hand-rolled is safer here.
    """
    name = os.path.basename(path)
    unit_type = name.rsplit(".", 1)[-1] if "." in name else "unknown"
    unit = SystemdUnit(name=name, path=path, unit_type=unit_type)

    section = ""
    # Handle line continuations (trailing backslash)
    logical_lines: list[str] = []
    buf = ""
    for raw in content.splitlines():
        line = raw.rstrip()
        if buf:
            buf += " " + line.lstrip()
        else:
            buf = line
        if buf.endswith("\\"):
            buf = buf[:-1].rstrip()
            continue
        logical_lines.append(buf)
        buf = ""
    if buf:
        logical_lines.append(buf)

    for line in logical_lines:
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1]
            continue
        if "=" not in s:
            continue
        key, _, value = s.partition("=")
        key = key.strip()
        value = value.strip()

        # An empty value resets a list directive; model that as clearing.
        if key == "Description":
            unit.description = value
        elif key == "ExecStart":
            if value:
                unit.exec_start.append(value)
            else:
                unit.exec_start.clear()
        elif key == "ExecStartPre":
            unit.exec_start_pre.append(value) if value else unit.exec_start_pre.clear()
        elif key == "ExecStop":
            unit.exec_stop.append(value) if value else unit.exec_stop.clear()
        elif key == "User":
            unit.user = value or None
        elif key == "Group":
            unit.group = value or None
        elif key == "WorkingDirectory":
            unit.working_directory = value or None
        elif key == "CapabilityBoundingSet":
            unit.capabilities = _split_list(value)
        elif key == "AmbientCapabilities":
            unit.ambient_capabilities = _split_list(value)
        elif key == "ReadWritePaths":
            unit.read_write_paths.extend(_split_list(value)) if value else unit.read_write_paths.clear()
        elif key == "ReadOnlyPaths":
            unit.read_only_paths.extend(_split_list(value)) if value else unit.read_only_paths.clear()
        elif key == "InaccessiblePaths":
            unit.inaccessible_paths.extend(_split_list(value)) if value else unit.inaccessible_paths.clear()
        elif key == "StateDirectory":
            unit.state_directory.extend(_split_list(value))
        elif key == "CacheDirectory":
            unit.cache_directory.extend(_split_list(value))
        elif key == "LogsDirectory":
            unit.logs_directory.extend(_split_list(value))
        elif key == "RuntimeDirectory":
            unit.runtime_directory.extend(_split_list(value))
        elif key == "ConfigurationDirectory":
            unit.configuration_directory.extend(_split_list(value))
        elif key == "EnvironmentFile":
            unit.environment_files.append(value)
        elif key == "PrivateTmp":
            unit.private_tmp = _parse_bool(value)
        elif key == "ProtectSystem":
            unit.protect_system = value or None
        elif key == "ProtectHome":
            unit.protect_home = value or None
        elif key == "NoNewPrivileges":
            unit.no_new_privileges = _parse_bool(value)
        elif key == "SupplementaryGroups":
            unit.supplementary_groups.extend(_split_list(value))
        elif key == "WantedBy":
            unit.wanted_by.extend(_split_list(value))
        else:
            unit.other_directives.setdefault(f"{section}.{key}", []).append(value)

    return unit


def systemd_exec_binary(exec_line: str) -> Optional[str]:
    """Extract the binary path from an ExecStart= value, stripping systemd's
    leading modifier characters (-, @, +, !, !!, :) and any arguments."""
    s = exec_line.strip()
    while s and s[0] in "-@+!:":
        s = s[1:]
    s = s.strip()
    if not s:
        return None
    # First whitespace-delimited token is the binary (quoted paths handled crudely)
    if s.startswith('"'):
        end = s.find('"', 1)
        return s[1:end] if end > 0 else s[1:]
    return s.split()[0]


# ---------------------------------------------------------------------------
# cron parsing
# ---------------------------------------------------------------------------

_CRON_SPECIAL = re.compile(r"^@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)\b")


def parse_cron(path: str, content: str, kind: str) -> list[CronJob]:
    """Parse a crontab-format file.

    /etc/crontab and /etc/cron.d/* have a USER field between the schedule and
    the command. Per-user crontabs under /var/spool/cron do not.
    """
    jobs: list[CronJob] = []
    has_user_field = kind in ("cron_d", "crontab_system")

    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Environment assignments (PATH=, SHELL=, MAILTO=) aren't jobs
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", line):
            continue

        m = _CRON_SPECIAL.match(line)
        if m:
            schedule = "@" + m.group(1)
            rest = line[m.end():].strip()
        else:
            parts = line.split(None, 5)
            if len(parts) < (6 if has_user_field else 6):
                # need 5 schedule fields + at least a command
                continue
            schedule = " ".join(parts[:5])
            rest = " ".join(parts[5:])

        if has_user_field:
            bits = rest.split(None, 1)
            if len(bits) < 2:
                continue
            run_as, command = bits[0], bits[1]
        else:
            run_as, command = None, rest

        jobs.append(CronJob(source_path=path, kind=kind, schedule=schedule,
                            run_as=run_as, command=command, raw_line=line))
    return jobs


# ---------------------------------------------------------------------------
# passwd / group diffing
# ---------------------------------------------------------------------------

def _parse_passwd(content: str) -> dict[str, UserEntry]:
    out: dict[str, UserEntry] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, _pw, uid_s, gid_s, gecos, home, shell = parts[:7]
        try:
            uid, gid = int(uid_s), int(gid_s)
        except ValueError:
            continue
        out[name] = UserEntry(
            name=name, uid=uid, gid=gid, gecos=gecos, home=home, shell=shell,
            is_system_account=(uid < 1000),
            login_disabled=any(x in shell for x in ("nologin", "/false", "/bin/sync")),
        )
    return out


def _parse_group(content: str) -> dict[str, GroupEntry]:
    out: dict[str, GroupEntry] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        name, _pw, gid_s, members = parts[:4]
        try:
            gid = int(gid_s)
        except ValueError:
            continue
        out[name] = GroupEntry(name=name, gid=gid,
                               members=[m for m in members.split(",") if m])
    return out


def diff_passwd(old_content: Optional[str], new_content: str) -> list[UserEntry]:
    """Return users present in new but not old."""
    old = _parse_passwd(old_content) if old_content else {}
    new = _parse_passwd(new_content)
    return [u for name, u in new.items() if name not in old]


def diff_group(old_content: Optional[str],
               new_content: str) -> tuple[list[GroupEntry], list[GroupMembershipChange]]:
    """Return (newly created groups, membership changes on any group).

    Membership changes matter for PAM: adding a service account to `docker`,
    `wheel`, `shadow`, `disk`, or a PAM-consulted group is a privilege grant
    that a file diff alone would not surface.
    """
    old = _parse_group(old_content) if old_content else {}
    new = _parse_group(new_content)

    new_groups = [g for name, g in new.items() if name not in old]

    changes: list[GroupMembershipChange] = []
    for name, g in new.items():
        old_members = set(old[name].members) if name in old else set()
        new_members = set(g.members)
        added = sorted(new_members - old_members)
        removed = sorted(old_members - new_members)
        if added or removed or name not in old:
            changes.append(GroupMembershipChange(
                group=name, gid=g.gid,
                users_added=added, users_removed=removed,
                group_is_new=(name not in old),
            ))
    return new_groups, changes


# Groups whose membership confers meaningful privilege. An agent building an
# access model should treat additions to these as high-signal.
PRIVILEGED_GROUPS = {
    "root", "wheel", "sudo", "admin", "adm",
    "docker", "lxd", "kvm", "libvirt",
    "shadow", "disk", "video", "audio", "dialout", "plugdev",
    "systemd-journal", "adm", "syslog",
    "staff", "operator",
}


# ---------------------------------------------------------------------------
# sudoers parsing
# ---------------------------------------------------------------------------

_SUDO_RULE = re.compile(
    r"^(?P<principal>[%+]?[\w\\.-]+)\s+"
    r"(?P<hosts>[\w,!*.-]+)\s*=\s*"
    r"(?:\((?P<runas>[^)]*)\)\s*)?"
    r"(?P<tags>(?:[A-Z_]+:\s*)*)"
    r"(?P<commands>.+)$"
)


def parse_sudoers(path: str, content: str) -> list[SudoRule]:
    rules: list[SudoRule] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Skip Defaults, aliases, and includes — they're not grants per se
        if re.match(r"^(Defaults|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|@include|#include)", line):
            continue
        m = _SUDO_RULE.match(line)
        if not m:
            continue
        tags = m.group("tags") or ""
        rules.append(SudoRule(
            source_path=path,
            raw_line=line,
            principal=m.group("principal"),
            hosts=m.group("hosts"),
            runas=m.group("runas"),
            nopasswd=("NOPASSWD" in tags),
            commands=m.group("commands").strip(),
        ))
    return rules


# ---------------------------------------------------------------------------
# Executable / privilege bit analysis
# ---------------------------------------------------------------------------

def read_file_capabilities(path: str) -> Optional[str]:
    """Read the security.capability xattr, if present. Returns a hex string.

    We deliberately return the raw value rather than decoding the capability
    set: decoding requires knowing the VFS_CAP revision layout, and any agent
    that cares can run `getcap` for a human-readable form. Presence is the
    signal that matters for a least-privilege model.
    """
    try:
        blob = os.getxattr(path, "security.capability")  # type: ignore[attr-defined]
        return blob.hex()
    except (OSError, AttributeError):
        return None


def analyze_executable(rec: "FileRecord") -> Optional[ExecutableEntry]:
    """Return an ExecutableEntry if rec is an executable file, else None."""
    if rec.is_dir or rec.is_symlink:
        return None
    mode = rec.mode
    if not (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
        return None
    return ExecutableEntry(
        path=rec.path,
        mode_octal=oct(stat.S_IMODE(mode)),
        mode_symbolic=stat.filemode(mode),
        owner=rec.owner,
        group=rec.group,
        setuid=bool(mode & stat.S_ISUID),
        setgid=bool(mode & stat.S_ISGID),
        world_writable=bool(mode & stat.S_IWOTH),
        file_capabilities=read_file_capabilities(rec.real_path or rec.path),
    )


def to_path_entry(rec: "FileRecord") -> PathEntry:
    return PathEntry(
        path=rec.path,
        category=classify_path(rec.path),
        is_dir=rec.is_dir,
        mode_octal=oct(stat.S_IMODE(rec.mode)),
        mode_symbolic=stat.filemode(rec.mode),
        owner=rec.owner,
        group=rec.group,
        size=rec.size,
        sha256=rec.sha256,
    )
