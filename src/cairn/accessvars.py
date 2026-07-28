"""cairn.accessvars — turn a footprint model into Ansible access vars.

The consumer is the `mcowser_p.declarative_access` role (the linux-access repo):
given the services, timers, quadlets, and folders an install created, the
role grants a team admin rights scoped to exactly that surface. This module
derives the role's variables from a footprint model and emits them as a YAML
vars file, applied with e.g.

    ansible-playbook playbooks/5_apply_access_profile.yml \
        -e @myapp-access.yml -e group_name=rg.<host>.app-restricted

Design constraints:
  - zero dependencies: YAML is hand-emitted (same reason report.py hand-emits
    SARIF/HTML) — simple scalars, block sequences, and flow maps only.
  - deterministic: same model → byte-identical output. No fresh timestamps
    (the footprint's own generated_at is quoted instead), everything sorted.
  - WHO is not in the file: declarative_access_user/_group are never emitted.
    The operator passes the team at apply time; emitting one here would bind
    the profile to a team at export time.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Optional

from . import __version__

# Footprint categories whose ADDED DIRECTORIES become folder grants.
FOLDER_MODIFY_CATEGORIES = ("config", "state_dir", "opt_tree", "srv_tree",
                            "cache_dir")
# Footprint categories whose files are the installed unit/quadlet surface —
# these get write ACLs (declarative_access_files_modify).
UNIT_FILE_CATEGORIES = ("systemd_unit", "systemd_dropin", "quadlet",
                        "quadlet_dropin")

# Fixed emission order for the role's contract keys.
_KEY_ORDER = (
    "declarative_access_profile_name",
    "declarative_access_sudo",
    "declarative_access_services",
    "declarative_access_timers",
    "declarative_access_quadlets",
    "declarative_access_linger",
    "declarative_access_linger_users",
    "declarative_access_files_modify",
    "declarative_access_folders_modify",
    "declarative_access_folders_read",
    "declarative_access_ownership",
)


def _rootful(path: str) -> bool:
    """System-scope paths only: rootless/user surfaces are managed by their
    owner (via lingering), and /run is tmpfs — an ACL there dies at reboot."""
    return not path.startswith(("/home/", "/root/",
                                "/etc/containers/systemd/users/", "/run/"))


def _fold_dirs(paths: list[str]) -> list[str]:
    """Keep only paths with no kept proper ancestor (a granted parent folder
    already covers its children)."""
    kept: list[str] = []
    for p in sorted(paths):
        if not any(p == k or p.startswith(k + "/") for k in kept):
            kept.append(p)
    return kept


def _under_any(path: str, folders: list[str]) -> bool:
    return any(path == f or path.startswith(f + "/") for f in folders)


def _quote(s: str) -> Optional[str]:
    """Single-quoted YAML scalar. Returns None for values single-quoted YAML
    cannot carry (control characters) — callers drop those with a warning."""
    if any(ord(c) < 32 for c in s):
        return None
    return "'" + s.replace("'", "''") + "'"


def _mode_str(mode_octal) -> Optional[str]:
    """'0o2750' → '2750', '0o755' → '0755' (zero-padded octal string, the
    form ansible.builtin.file expects)."""
    try:
        return format(int(str(mode_octal), 0), "04o")
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Derivation (pure)
# ---------------------------------------------------------------------------

def derive_access_vars(model: dict) -> dict:
    """Footprint model dict → role vars dict. Pure; only non-empty keys."""
    services_units = (model.get("services") or {}).get("systemd_units") or []
    quadlet_units = (model.get("services") or {}).get("quadlets") or []
    fs = model.get("filesystem") or {}
    by_cat = fs.get("added_by_category") or {}
    modified = fs.get("modified") or []
    principals = model.get("principals") or {}

    # --- unit names (bare, per the role contract) ---
    services: set[str] = set()
    timers: set[str] = set()
    for u in services_units:
        name = u.get("name") or ""
        path = u.get("path") or ""
        # System scope only (not user units or /run transients); template
        # units are ambiguous sudoers targets and are excluded.
        if "@" in name or "/systemd/system/" not in path:
            continue
        if u.get("unit_type") == "service" and name.endswith(".service"):
            services.add(name[: -len(".service")])
        elif u.get("unit_type") == "timer" and name.endswith(".timer"):
            timers.add(name[: -len(".timer")])

    quadlets: set[str] = set()
    linger_users: set[str] = set()
    for q in quadlet_units:
        if "@" in (q.get("name") or ""):
            continue
        if q.get("rootless"):
            # Rootless quadlets need no sudo — their owner manages them via
            # `systemctl --user`; lingering keeps them alive across logout.
            if q.get("owner"):
                linger_users.add(q["owner"])
            continue
        svc = q.get("service_name") or ""
        if svc.endswith(".service"):
            quadlets.add(svc[: -len(".service")])

    # --- folders ---
    folder_modify: set[str] = set()
    folder_read: set[str] = set()
    for cat in FOLDER_MODIFY_CATEGORIES:
        for e in by_cat.get(cat) or []:
            if e.get("is_dir") and _rootful(e["path"]):
                folder_modify.add(e["path"])
    for e in by_cat.get("log_dir") or []:
        if e.get("is_dir") and _rootful(e["path"]):
            folder_read.add(e["path"])
    # Directive-derived: StateDirectory= etc. are created at first service
    # start and are frequently absent from the install diff.
    for u in services_units:
        for d in u.get("state_directory") or []:
            folder_modify.add("/var/lib/" + d)
        for d in u.get("configuration_directory") or []:
            folder_modify.add("/etc/" + d)
        for d in u.get("cache_directory") or []:
            folder_modify.add("/var/cache/" + d)
        for d in u.get("logs_directory") or []:
            folder_read.add("/var/log/" + d)

    folders_modify = _fold_dirs(sorted(folder_modify))
    folders_read = [p for p in _fold_dirs(sorted(folder_read))
                    if not _under_any(p, folders_modify)]

    # --- installed unit/quadlet files → write ACLs ---
    files_modify: set[str] = set()
    for cat in UNIT_FILE_CATEGORIES:
        for e in by_cat.get(cat) or []:
            if not e.get("is_dir") and _rootful(e["path"]):
                files_modify.add(e["path"])
    for e in modified:
        if (e.get("category") in UNIT_FILE_CATEGORIES
                and not e.get("is_dir") and _rootful(e["path"])):
            files_modify.add(e["path"])
    files_list = [p for p in sorted(files_modify)
                  if not _under_any(p, folders_modify)]

    # --- ownership: enforce captured owner/group/mode on the granted
    # surface, but only where the install created the owning principal.
    # root:root is the default; declaring it is churn without intent. ---
    added_principals = {u.get("name") for u in principals.get("users_added") or []}
    added_principals |= {g.get("name") for g in principals.get("groups_added") or []}
    added_principals.discard(None)

    entry_by_path: dict[str, dict] = {}
    for entries in by_cat.values():
        for e in entries:
            entry_by_path[e["path"]] = e

    ownership: list[dict] = []
    granted = sorted(set(folders_modify) | set(folders_read) | set(files_list))
    for p in granted:
        e = entry_by_path.get(p)
        if not e:
            continue
        if e.get("owner") in added_principals or e.get("group") in added_principals:
            entry = {"path": p, "owner": e.get("owner"), "group": e.get("group")}
            mode = _mode_str(e.get("mode_octal"))
            if mode:
                entry["mode"] = mode
            ownership.append(entry)

    # --- assemble (omit-empty; the role gates every block on `is defined`) ---
    out: dict = {
        "declarative_access_profile_name": model.get("application") or "unknown",
    }
    if services or timers or quadlets:
        out["declarative_access_sudo"] = True
    if services:
        out["declarative_access_services"] = sorted(services)
    if timers:
        out["declarative_access_timers"] = sorted(timers)
    if quadlets:
        out["declarative_access_quadlets"] = sorted(quadlets)
    if linger_users:
        out["declarative_access_linger"] = True
        out["declarative_access_linger_users"] = sorted(linger_users)
    if files_list:
        out["declarative_access_files_modify"] = files_list
    if folders_modify:
        out["declarative_access_folders_modify"] = folders_modify
    if folders_read:
        out["declarative_access_folders_read"] = folders_read
    if ownership:
        out["declarative_access_ownership"] = ownership
    return out


# ---------------------------------------------------------------------------
# Emission (pure)
# ---------------------------------------------------------------------------

def _emit_scalar(lines: list[str], key: str, value) -> None:
    if value is True:
        lines.append(f"{key}: true")
        return
    q = _quote(str(value))
    if q is None:
        lines.append(f"# {key}: dropped — value contains control characters")
        return
    lines.append(f"{key}: {q}")


def _emit_list(lines: list[str], key: str, values: list[str]) -> None:
    lines.append(f"{key}:")
    for v in values:
        q = _quote(v)
        if q is None:
            lines.append("  # (dropped an entry containing control characters)")
            continue
        lines.append(f"  - {q}")


def _emit_ownership(lines: list[str], key: str, entries: list[dict]) -> None:
    lines.append(f"{key}:")
    for e in entries:
        parts = []
        for k in ("path", "owner", "group", "mode"):
            if e.get(k) is None:
                continue
            q = _quote(str(e[k]))
            if q is None:
                parts = []
                break
            parts.append(f"{k}: {q}")
        if not parts:
            lines.append("  # (dropped an entry containing control characters)")
            continue
        lines.append("  - { " + ", ".join(parts) + " }")


def render_access_vars(model: dict) -> str:
    """Derive + render the vars file text (deterministic)."""
    data = derive_access_vars(model)
    app = data["declarative_access_profile_name"]
    lines = [
        "---",
        f"# Ansible vars for the mcowser_p.declarative_access role — generated by cairn {__version__}",
        f"# application: {app}   footprint schema: {model.get('schema_version', '?')}"
        f"   captured: {model.get('generated_at', '?')}",
        "# Review before applying. Pass the team at apply time:",
        "#   -e group_name=rg.<host>.app-restricted   (or -e user_name=...)",
        "# declarative_access_user / declarative_access_group are intentionally NOT set here.",
    ]
    for key in _KEY_ORDER:
        if key not in data:
            continue
        value = data[key]
        if key == "declarative_access_ownership":
            _emit_ownership(lines, key, value)
        elif isinstance(value, list):
            _emit_list(lines, key, value)
        else:
            _emit_scalar(lines, key, value)
    if len(data) == 1:
        lines.append("# no systemd service/timer/quadlet or folder surface "
                     "detected in this footprint")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Writers / CLI
# ---------------------------------------------------------------------------

def _atomic_write(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def write_access_vars(model: dict, out_path: str, quiet: bool = False) -> None:
    """Render and atomically write the vars file. Raises OSError on failure."""
    text = render_access_vars(model)
    _atomic_write(out_path, text)
    if not quiet:
        if len(derive_access_vars(model)) == 1:
            print("[i] no systemd service/timer/quadlet or folder surface "
                  "detected; access vars are minimal", file=sys.stderr)
        print(f"[i] ansible access vars written → {out_path}", file=sys.stderr)


def cmd_access_vars(json_path: str, out_path: Optional[str] = None) -> int:
    """Standalone CLI: read an existing footprint JSON, emit access vars.

    Exit codes: 0 ok, 2 error (no drift semantics — the footprint already
    carried those)."""
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            model = json.load(f)
    except (OSError, ValueError) as e:
        print(f"[!] cannot read footprint JSON {json_path}: {e}", file=sys.stderr)
        return 2
    if not isinstance(model, dict) or model.get("footprint_type") != "install_time":
        print("[!] not an install-time footprint "
              "(expected footprint_type: install_time)", file=sys.stderr)
        return 2
    if "systemd_units" not in (model.get("services") or {}):
        print("[!] this looks like a Windows footprint — access vars export "
              "is Linux-only", file=sys.stderr)
        return 2

    if not out_path or out_path == "-":
        print(render_access_vars(model), end="")
        return 0
    try:
        write_access_vars(model, out_path)
    except OSError as e:
        print(f"[!] cannot write {out_path}: {e}", file=sys.stderr)
        return 2
    return 0
