"""cairn.footprint — build an install-time footprint model for an application.

Workflow this supports:

    1. Baseline a clean OS image        cairn files init --config clean.yaml
    2. Hand the box to a developer; they install their application
    3. Capture the footprint             cairn footprint --config clean.yaml \
                                            --report footprint.json

The output is a structured description of everything the install touched,
with the security-relevant objects parsed into first-class form: systemd
units (and the identity they run as), cron jobs, users and groups created,
group memberships granted, sudoers rules, setuid binaries, and file
capabilities.

The intended consumer is an agent that derives a least-privilege access
model. The schema is designed so that runtime-observed access data (eBPF,
auditd, strace) can be merged in later under a separate `runtime` key —
the `footprint_type` field marks this document as install-time only.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from . import files as files_mod
from . import semantic as sem


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def _content_of(rec) -> Optional[str]:
    """Decompress stored content from a FileRecord, if any."""
    return files_mod.decompress_content(getattr(rec, "content_gz", None))


def _live_content(path: str, max_bytes: int = 1024 * 1024) -> Optional[str]:
    """Read a file from the live filesystem. Used when the baseline has no
    stored content (e.g. store_content was off, or the file is new)."""
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


def _collect_changes(cfg: dict) -> tuple[list, list, list, list[str]]:
    """Walk the filesystem and diff against the baseline.

    Returns (added, modified, deleted, errors) where modified is a list of
    (old_record, new_record, change_list) tuples. This mirrors cmd_scan's
    collection phase but does not emit reports or touch the baseline.
    """
    db_path = cfg["db_path"]
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"no baseline at {db_path}; run `cairn files init` first")

    conn = files_mod.open_db(db_path)
    try:
        baseline = files_mod.load_baseline(conn)
    finally:
        conn.close()

    seen: set[str] = set()
    added, modified, errors = [], [], []

    for fp in files_mod.walk_paths(cfg):
        try:
            rec = files_mod.stat_file(fp, cfg)
        except (OSError, PermissionError) as e:
            errors.append(f"skip {fp}: {e}")
            continue
        seen.add(rec.path)
        old = baseline.get(rec.path)
        if old is None:
            added.append(rec)
            continue
        diffs = files_mod.diff_records(old, rec, cfg)
        if diffs:
            modified.append((old, rec, diffs))

    deleted_paths = sorted(set(baseline.keys()) - seen)
    deleted = [baseline[p] for p in deleted_paths]
    return added, modified, deleted, errors


# ---------------------------------------------------------------------------
# Semantic extraction
# ---------------------------------------------------------------------------

def _extract(added: list, modified: list) -> dict:
    """Pull parsed security objects out of the raw change lists."""
    systemd_units: list[sem.SystemdUnit] = []
    cron_jobs: list[sem.CronJob] = []
    sudo_rules: list[sem.SudoRule] = []
    users_added: list[sem.UserEntry] = []
    groups_added: list[sem.GroupEntry] = []
    membership_changes: list[sem.GroupMembershipChange] = []
    pam_files: list[str] = []
    security_files: list[dict] = []   # polkit, dbus, sysctl, udev, caps, limits...

    # --- New files: parse from live content (or stored content if present) ---
    for rec in added:
        cat = sem.classify_path(rec.path)
        content = _content_of(rec) or _live_content(rec.real_path or rec.path)

        if cat in ("systemd_unit", "systemd_dropin") and content:
            systemd_units.append(sem.parse_systemd_unit(rec.path, content))
        elif cat == "cron_d" and content:
            cron_jobs.extend(sem.parse_cron(rec.path, content, "cron_d"))
        elif cat == "crontab_user" and content:
            cron_jobs.extend(sem.parse_cron(rec.path, content, "crontab_user"))
        elif cat == "cron_periodic":
            # These are scripts, not crontab lines. Schedule is implied by dir.
            logical = rec.path
            period = logical.split("/")[2].replace("cron.", "")
            cron_jobs.append(sem.CronJob(
                source_path=rec.path, kind="cron_periodic",
                schedule=f"@{period}", run_as="root", command=rec.path))
        elif cat == "sudoers" and content:
            sudo_rules.extend(sem.parse_sudoers(rec.path, content))
        elif cat == "pam":
            pam_files.append(rec.path)
        elif cat == "group" and content:
            g, m = sem.diff_group(None, content)
            groups_added.extend(g)
            membership_changes.extend(m)
        elif cat == "passwd" and content:
            users_added.extend(sem.diff_passwd(None, content))
        elif cat in ("polkit", "dbus_policy", "sysctl", "udev_rule", "ld_so_conf",
                     "profile_d", "limits_d", "apparmor", "selinux", "modprobe",
                     "tmpfiles", "sysusers", "init_script", "nsswitch",
                     "pam_security", "logrotate"):
            security_files.append({"path": rec.path, "category": cat, "change": "added"})

    # --- Modified files: diff old vs new content where semantics require it ---
    for old, new, _changes in modified:
        cat = sem.classify_path(new.path)
        old_content = _content_of(old)
        new_content = _content_of(new) or _live_content(new.real_path or new.path)

        if cat == "passwd" and new_content:
            users_added.extend(sem.diff_passwd(old_content, new_content))
        elif cat == "group" and new_content:
            g, m = sem.diff_group(old_content, new_content)
            groups_added.extend(g)
            membership_changes.extend(m)
        elif cat == "sudoers" and new_content:
            sudo_rules.extend(sem.parse_sudoers(new.path, new_content))
        elif cat in ("systemd_unit", "systemd_dropin") and new_content:
            systemd_units.append(sem.parse_systemd_unit(new.path, new_content))
        elif cat in ("cron_d", "crontab_system") and new_content:
            cron_jobs.extend(sem.parse_cron(new.path, new_content, cat))
        elif cat == "crontab_user" and new_content:
            cron_jobs.extend(sem.parse_cron(new.path, new_content, "crontab_user"))
        elif cat == "pam":
            pam_files.append(new.path)
        elif cat in ("polkit", "dbus_policy", "sysctl", "udev_rule", "ld_so_conf",
                     "profile_d", "limits_d", "apparmor", "selinux", "modprobe",
                     "tmpfiles", "sysusers", "init_script", "nsswitch",
                     "pam_security", "logrotate"):
            security_files.append({"path": new.path, "category": cat, "change": "modified"})

    return {
        "systemd_units": systemd_units,
        "cron_jobs": cron_jobs,
        "sudo_rules": sudo_rules,
        "users_added": users_added,
        "groups_added": groups_added,
        "membership_changes": membership_changes,
        "pam_files": sorted(set(pam_files)),
        "security_files": security_files,
    }


# ---------------------------------------------------------------------------
# Derived access hints — the part the agent actually wants
# ---------------------------------------------------------------------------

def _dedupe_needs(needs: list[dict]) -> list[dict]:
    """Collapse duplicate paths, unioning their access levels and sources.

    A path can be implied by several directives (e.g. ConfigurationDirectory
    and ReadOnlyPaths both point at /etc/myapp). The agent wants one entry per
    path with the widest access any source justified, and the provenance of
    why.
    """
    merged: dict[str, dict] = {}
    for n in needs:
        path = n["path"]
        if not path:
            continue
        if path not in merged:
            merged[path] = {"path": path,
                            "access": set(n["access"].split(",")),
                            "sources": [n["source"]]}
        else:
            merged[path]["access"].update(n["access"].split(","))
            if n["source"] not in merged[path]["sources"]:
                merged[path]["sources"].append(n["source"])
    out = []
    for path in sorted(merged):
        m = merged[path]
        # Stable ordering: read, write, execute
        order = [a for a in ("read", "write", "execute") if a in m["access"]]
        out.append({"path": path, "access": ",".join(order), "sources": m["sources"]})
    return out


def _derive_access_hints(extracted: dict, added: list, modified: list) -> list[dict]:
    """For each service identity the install introduced, gather the paths it
    plausibly needs and at what access level.

    These are *hints*, not a policy. They are derived from declared intent
    (systemd directives) and from file ownership, both of which are install-time
    signals. A real policy needs runtime observation to confirm and to catch
    paths nothing declared.
    """
    # Index installed files by owner and by group so we can attribute them.
    by_owner: dict[str, list[str]] = {}
    by_group: dict[str, list[str]] = {}
    all_records = list(added) + [n for (_o, n, _c) in modified]
    for rec in all_records:
        logical = rec.path
        if rec.owner:
            by_owner.setdefault(rec.owner, []).append(logical)
        if rec.group:
            by_group.setdefault(rec.group, []).append(logical)

    hints: list[dict] = []

    for unit in extracted["systemd_units"]:
        # Only units that actually run something are principals. Timers,
        # targets, and sockets carry no identity of their own — the service
        # they activate does.
        if not (unit.exec_start or unit.exec_start_pre or unit.user):
            continue

        principal = unit.user or "root"
        needs: list[dict] = []

        for e in unit.exec_start + unit.exec_start_pre + unit.exec_stop:
            binary = sem.systemd_exec_binary(e)
            if binary and binary.startswith("/"):
                needs.append({"path": binary, "access": "read,execute",
                              "source": "systemd:ExecStart"})

        if unit.working_directory:
            needs.append({"path": unit.working_directory, "access": "read",
                          "source": "systemd:WorkingDirectory"})
        for ef in unit.environment_files:
            needs.append({"path": ef.lstrip("-"), "access": "read",
                          "source": "systemd:EnvironmentFile"})
        for p in unit.read_write_paths:
            needs.append({"path": p, "access": "read,write",
                          "source": "systemd:ReadWritePaths"})
        for p in unit.read_only_paths:
            needs.append({"path": p, "access": "read",
                          "source": "systemd:ReadOnlyPaths"})
        # systemd's *Directory= directives are relative names under a known root
        for d in unit.state_directory:
            needs.append({"path": f"/var/lib/{d}", "access": "read,write",
                          "source": "systemd:StateDirectory"})
        for d in unit.cache_directory:
            needs.append({"path": f"/var/cache/{d}", "access": "read,write",
                          "source": "systemd:CacheDirectory"})
        for d in unit.logs_directory:
            needs.append({"path": f"/var/log/{d}", "access": "read,write",
                          "source": "systemd:LogsDirectory"})
        for d in unit.runtime_directory:
            needs.append({"path": f"/run/{d}", "access": "read,write",
                          "source": "systemd:RuntimeDirectory"})
        for d in unit.configuration_directory:
            needs.append({"path": f"/etc/{d}", "access": "read",
                          "source": "systemd:ConfigurationDirectory"})

        # Files the installer chowned to this principal are strong evidence.
        # Skip root: root owns everything by default, so "root owns this file"
        # carries no information about what the service actually needs.
        if principal != "root":
            for p in sorted(by_owner.get(principal, []))[:500]:
                needs.append({"path": p, "access": "read,write",
                              "source": "file-owner"})
        if unit.group and unit.group != "root":
            for p in sorted(by_group.get(unit.group, []))[:500]:
                needs.append({"path": p, "access": "read",
                              "source": "file-group"})

        needs = _dedupe_needs(needs)

        hints.append({
            "principal": principal,
            "principal_type": "systemd_service",
            "unit": unit.name,
            "supplementary_groups": unit.supplementary_groups,
            "declared_capabilities": unit.ambient_capabilities or unit.capabilities,
            "hardening": {
                "private_tmp": unit.private_tmp,
                "protect_system": unit.protect_system,
                "protect_home": unit.protect_home,
                "no_new_privileges": unit.no_new_privileges,
            },
            "needs": needs,
        })

    # Cron jobs introduce principals too
    for job in extracted["cron_jobs"]:
        principal = job.run_as or "unknown"
        binary = job.command.split()[0] if job.command else ""
        needs = _dedupe_needs(
            [{"path": binary, "access": "read,execute", "source": "cron:command"}]
            if binary.startswith("/") else []
        )
        if principal != "root":
            for p in sorted(by_owner.get(principal, []))[:500]:
                needs.extend(_dedupe_needs(
                    [{"path": p, "access": "read,write", "source": "file-owner"}]))
        hints.append({
            "principal": principal,
            "principal_type": "cron_job",
            "unit": job.source_path,
            "schedule": job.schedule,
            "needs": _dedupe_needs([
                {"path": n["path"], "access": n["access"],
                 "source": n["sources"][0] if "sources" in n else n.get("source", "")}
                for n in needs
            ]),
        })

    return hints


def _flag_risks(extracted: dict, executables: list[sem.ExecutableEntry]) -> list[dict]:
    """Surface the things a human reviewer should look at before the agent
    turns this into policy."""
    risks: list[dict] = []

    for ex in executables:
        if ex.setuid:
            risks.append({"severity": "high", "kind": "setuid_binary",
                          "detail": f"{ex.path} is setuid {ex.owner}",
                          "path": ex.path})
        if ex.setgid:
            risks.append({"severity": "medium", "kind": "setgid_binary",
                          "detail": f"{ex.path} is setgid {ex.group}",
                          "path": ex.path})
        if ex.world_writable:
            risks.append({"severity": "high", "kind": "world_writable_executable",
                          "detail": f"{ex.path} is world-writable and executable",
                          "path": ex.path})
        if ex.file_capabilities:
            risks.append({"severity": "high", "kind": "file_capabilities",
                          "detail": f"{ex.path} carries a security.capability xattr",
                          "path": ex.path})

    for rule in extracted["sudo_rules"]:
        sev = "high" if rule.nopasswd else "medium"
        risks.append({"severity": sev, "kind": "sudoers_rule",
                      "detail": f"{rule.principal} may run {rule.commands}"
                                + (" without a password" if rule.nopasswd else ""),
                      "path": rule.source_path})

    for chg in extracted["membership_changes"]:
        if chg.group in sem.PRIVILEGED_GROUPS and chg.users_added:
            risks.append({"severity": "high", "kind": "privileged_group_membership",
                          "detail": f"{', '.join(chg.users_added)} added to "
                                    f"privileged group '{chg.group}'",
                          "path": "/etc/group"})

    for u in extracted["users_added"]:
        if u.uid == 0:
            risks.append({"severity": "critical", "kind": "uid_zero_account",
                          "detail": f"account '{u.name}' has uid 0",
                          "path": "/etc/passwd"})
        elif not u.login_disabled and not u.is_system_account:
            risks.append({"severity": "medium", "kind": "login_capable_account",
                          "detail": f"account '{u.name}' has a login shell ({u.shell})",
                          "path": "/etc/passwd"})

    for unit in extracted["systemd_units"]:
        if (unit.user or "root") == "root" and unit.exec_start:
            risks.append({"severity": "medium", "kind": "service_runs_as_root",
                          "detail": f"{unit.name} has no User= directive; runs as root",
                          "path": unit.path})
        if unit.ambient_capabilities:
            risks.append({"severity": "high", "kind": "ambient_capabilities",
                          "detail": f"{unit.name} grants {' '.join(unit.ambient_capabilities)}",
                          "path": unit.path})

    for p in extracted["pam_files"]:
        risks.append({"severity": "high", "kind": "pam_modified",
                      "detail": f"PAM stack modified: {p}", "path": p})

    return risks


# ---------------------------------------------------------------------------
# Container image metadata
# ---------------------------------------------------------------------------

def _load_container_meta(root_prefix: str) -> Optional[dict]:
    """Load <root_prefix>.inspect.json if present (written next to the rootfs
    by scripts/container-rootfs.sh) and pull out the parts of the container's
    access model that live outside the filesystem: USER is the runtime
    principal for a container with no systemd unit, and ENTRYPOINT/CMD are
    what actually runs.

    Never fatal: any parse problem prints an informational note and returns
    None — a footprint without container metadata is incomplete, not wrong.
    """
    if not root_prefix:
        return None
    inspect_path = root_prefix.rstrip("/") + ".inspect.json"
    if not os.path.exists(inspect_path):
        return None
    try:
        with open(inspect_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # docker/podman `image inspect` emit an array of one object.
        if isinstance(data, list):
            data = data[0] if data else {}
        if not isinstance(data, dict):
            raise ValueError("unexpected top-level JSON shape")
        config = data.get("Config") or {}
        user = (config.get("User") or "").strip()
        meta = {
            "source": inspect_path,
            "image": {
                "id": data.get("Id"),
                "repo_tags": data.get("RepoTags") or [],
            },
            "user": user or "root",
            "entrypoint": config.get("Entrypoint") or [],
            "cmd": config.get("Cmd") or [],
            # Env in badly-built images frequently carries secrets. The
            # footprint JSON can already contain sensitive content (stored
            # config diffs), so include it as-is and treat the report itself
            # as sensitive.
            "env": config.get("Env") or [],
            "exposed_ports": config.get("ExposedPorts") or {},
        }
        if user and user not in ("root", "0"):
            meta["note"] = (
                f"Image runs as USER {user}; that user is the container's "
                "runtime principal, and service_runs_as_root findings from "
                "unit files may not apply inside this container."
            )
        return meta
    except (OSError, ValueError, KeyError) as e:
        print(f"[i] could not parse {inspect_path}: {e}; "
              "continuing without container metadata", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Model assembly
# ---------------------------------------------------------------------------

def build_model(cfg: dict, app_name: Optional[str] = None) -> dict:
    root_prefix = files_mod.get_root_prefix(cfg)
    added, modified, deleted, errors = _collect_changes(cfg)
    extracted = _extract(added, modified)

    executables = []
    for rec in added + [n for (_o, n, _c) in modified]:
        ex = sem.analyze_executable(rec)
        if ex:
            executables.append(ex)

    # Group filesystem entries by category so the agent doesn't have to.
    fs_by_category: dict[str, list[dict]] = {}
    for rec in added:
        pe = sem.to_path_entry(rec)
        fs_by_category.setdefault(pe.category, []).append(asdict(pe))

    modified_paths = [asdict(sem.to_path_entry(n)) for (_o, n, _c) in modified]
    deleted_paths = [{"path": r.path, "category": sem.classify_path(r.path)}
                     for r in deleted]

    hints = _derive_access_hints(extracted, added, modified)
    risks = _flag_risks(extracted, executables)

    # Baseline provenance for chain-of-custody
    db_path = cfg["db_path"]
    conn = files_mod.open_db(db_path)
    try:
        meta = {r[0]: r[1] for r in conn.execute("SELECT key, value FROM meta")}
    finally:
        conn.close()

    model = {
        "schema_version": sem.SCHEMA_VERSION,
        "footprint_type": "install_time",
        "footprint_caveat": (
            "This describes what the installer wrote to disk. It does not "
            "describe runtime access. A least-privilege policy derived only "
            "from this data will over-grant on the install tree and "
            "under-grant on runtime paths (/tmp, /dev, sockets, resolver "
            "config). Merge with runtime observation before enforcing."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application": app_name or "unknown",
        "host": platform.node(),
        "platform": platform.platform(),
        "root_prefix": root_prefix or "/",
        "baseline": {
            "db_path": db_path,
            "db_sha256": files_mod.hash_file(db_path, "sha256"),
            "created_at": meta.get("created_at", "unknown"),
            "source_host": meta.get("host", "unknown"),
            "source_os": meta.get("os", "unknown"),
        },
        "summary": {
            "files_added": len(added),
            "files_modified": len(modified),
            "files_deleted": len(deleted),
            "systemd_units": len(extracted["systemd_units"]),
            "cron_jobs": len(extracted["cron_jobs"]),
            "users_added": len(extracted["users_added"]),
            "groups_added": len(extracted["groups_added"]),
            "membership_changes": len(extracted["membership_changes"]),
            "sudo_rules": len(extracted["sudo_rules"]),
            "executables": len(executables),
            "risks": len(risks),
            "scan_errors": len(errors),
        },
        "principals": {
            "users_added":        [asdict(u) for u in extracted["users_added"]],
            "groups_added":       [asdict(g) for g in extracted["groups_added"]],
            "membership_changes": [asdict(m) for m in extracted["membership_changes"]],
        },
        "services": {
            "systemd_units": [asdict(u) for u in extracted["systemd_units"]],
        },
        "scheduled": {
            "cron_jobs": [asdict(j) for j in extracted["cron_jobs"]],
        },
        "privilege": {
            "sudo_rules":       [asdict(r) for r in extracted["sudo_rules"]],
            "setuid_binaries":  [asdict(e) for e in executables if e.setuid],
            "setgid_binaries":  [asdict(e) for e in executables if e.setgid],
            "file_capabilities":[asdict(e) for e in executables if e.file_capabilities],
            "pam_files_touched": extracted["pam_files"],
        },
        "security_relevant_files": extracted["security_files"],
        "executables": [asdict(e) for e in executables],
        "filesystem": {
            "added_by_category": fs_by_category,
            "modified": modified_paths,
            "deleted": deleted_paths,
        },
        "access_hints": hints,
        "risks": risks,
        "scan_errors": errors,
    }

    # Rootfs-scan extras: extraction-fidelity assessment and container image
    # metadata. Both only exist for --root scans; keys are absent otherwise.
    fidelity = files_mod.assess_root_fidelity(cfg)
    if fidelity is not None:
        model["fidelity"] = fidelity
    container = _load_container_meta(root_prefix)
    if container is not None:
        model["container"] = container

    return model


# ---------------------------------------------------------------------------
# Windows footprint model
# ---------------------------------------------------------------------------

WINDOWS_CAVEAT = (
    "This describes what an installer wrote to disk and the registry on "
    "Windows. It does not describe runtime behaviour, and — because Windows "
    "accounts live in the SAM, not a readable file — it does not enumerate "
    "local accounts/groups the installer created. Reconstructed from the file "
    "baseline plus the registry Services subtree; run `cairn all init` before "
    "the install so both halves are captured. Merge with runtime observation "
    "before enforcing a policy."
)


def _flag_risks_windows(services, tasks, added_files=()) -> list[dict]:
    """Surface the Windows install objects a reviewer should look at."""
    from . import winsemantic as wsem
    risks: list[dict] = []

    # Permissive ACLs: a new file writable by Everyone/Users is the Windows
    # world-writable analog. High for a program/system binary, medium else.
    for rec in added_files:
        principal = wsem.acl_permissive_principal(getattr(rec, "acl", None))
        if not principal:
            continue
        low = (rec.path or "").lower()
        privileged = (low.endswith((".exe", ".dll", ".sys")) or
                      "\\program files" in low or "\\system32" in low)
        risks.append({
            "severity": "high" if privileged else "medium",
            "kind": "world_writable_file",
            "detail": f"{rec.path} grants write to '{principal}'",
            "path": rec.path,
        })

    for s in services:
        if s.is_driver:
            risks.append({"severity": "high", "kind": "kernel_driver_installed",
                          "detail": f"service '{s.name}' installs a kernel driver "
                                    f"({s.image_binary})", "path": s.key_path})
        img = s.image_binary or ""
        low = img.lower()
        in_standard = any(x in low for x in
                          ("\\system32\\", "\\syswow64\\", "\\program files"))
        if img and not in_standard:
            risks.append({"severity": "high", "kind": "service_image_nonstandard_path",
                          "detail": f"service '{s.name}' runs {img} (outside "
                                    "System32/Program Files)", "path": s.key_path})
        if not s.runs_as_builtin:
            risks.append({"severity": "medium", "kind": "service_custom_account",
                          "detail": f"service '{s.name}' runs as {s.run_as} "
                                    "(non-builtin account)", "path": s.key_path})
        elif s.start_type == "auto" and s.runs_as_system:
            risks.append({"severity": "low", "kind": "autostart_service_as_system",
                          "detail": f"service '{s.name}' auto-starts as "
                                    f"{s.run_as}", "path": s.key_path})
    for t in tasks:
        if t.runs_as_system or t.runs_elevated:
            risks.append({"severity": "medium", "kind": "scheduled_task_elevated",
                          "detail": f"task '{t.name}' runs as {t.run_as or '?'} "
                                    f"(level {t.run_level or 'default'})",
                          "path": t.source_path})
    return risks


def build_model_windows(cfg: dict, app_name: Optional[str] = None) -> dict:
    from . import winsemantic as wsem
    from . import winreg_mon

    added, modified, deleted, errors = _collect_changes(cfg)

    reg_added, reg_modified, reg_deleted = [], [], []
    registry_error = None
    try:
        reg_added, reg_modified, reg_deleted = winreg_mon.collect_changes(cfg)
    except FileNotFoundError:
        registry_error = ("no registry baseline — run `cairn all init` (not just "
                          "`cairn files init`) so services are captured")

    # A service touched by the install shows up in the diff via whatever value
    # changed (often just Start). Reconstruct each touched service from its
    # FULL current config by re-reading its key live — otherwise a service
    # whose only changed value was Start comes back with a null ImagePath/
    # ObjectName. (Note: a service already registered before the baseline —
    # e.g. IIS's W3SVC pre-staged on some images — won't appear at all; the
    # footprint is a diff, so a pre-existing, unchanged service is not a
    # change. Genuinely new services, like an installed agent, do appear.)
    reg_changed = reg_added + [n for (_o, n) in reg_modified]
    touched = {n for n in (wsem.service_name_from_key(r.key_path) for r in reg_changed) if n}
    full_records = []
    for name in sorted(touched):
        try:
            full_records.extend(winreg_mon.walk_key(
                rf"HKLM\System\CurrentControlSet\Services\{name}", cfg))
        except Exception:
            pass
    services = wsem.parse_windows_services(full_records or reg_changed)

    tasks = []
    for rec in added + [n for (_o, n, _c) in modified]:
        if wsem.classify_windows_path(rec.path) == "scheduled_task":
            content = _content_of(rec) or _live_content(rec.real_path or rec.path)
            if content:
                t = wsem.parse_scheduled_task(rec.path, content)
                if t:
                    tasks.append(t)

    fs_by_category: dict[str, list[dict]] = {}
    for rec in added:
        cat = wsem.classify_windows_path(rec.path)
        fs_by_category.setdefault(cat, []).append({
            "path": rec.path, "size": rec.size, "sha256": rec.sha256,
            # Windows permission model: the file owner (SID/name) and the DACL
            # (access-control entries), the analog of Linux mode+owner+group.
            "owner": rec.owner, "acl": rec.acl,
        })

    risks = _flag_risks_windows(services, tasks, added)

    db_path = cfg["db_path"]
    conn = files_mod.open_db(db_path)
    try:
        meta = {r[0]: r[1] for r in conn.execute("SELECT key, value FROM meta")}
    finally:
        conn.close()

    return {
        "schema_version": wsem.SCHEMA_VERSION,
        "footprint_type": "install_time",
        "footprint_caveat": WINDOWS_CAVEAT,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "application": app_name or "unknown",
        "host": platform.node(),
        "platform": platform.platform(),
        "baseline": {
            "db_path": db_path,
            "db_sha256": files_mod.hash_file(db_path, "sha256"),
            "created_at": meta.get("created_at", "unknown"),
            "source_host": meta.get("host", "unknown"),
            "source_os": meta.get("os", "unknown"),
        },
        "summary": {
            "files_added": len(added),
            "files_modified": len(modified),
            "registry_values_added": len(reg_added),
            "registry_values_modified": len(reg_modified),
            "services": len(services),
            "scheduled_tasks": len(tasks),
            "risks": len(risks),
            "scan_errors": len(errors),
        },
        "services": {
            "windows_services": [asdict(s) for s in services],
        },
        "scheduled": {
            "scheduled_tasks": [asdict(t) for t in tasks],
        },
        "filesystem": {
            "added_by_category": fs_by_category,
            "modified": [{"path": n.path, "owner": n.owner, "acl": n.acl}
                         for (_o, n, _c) in modified],
            "deleted": [{"path": r.path} for r in deleted],
        },
        "registry": {
            "added_values": [{"key_path": r.key_path, "value_name": r.value_name}
                             for r in reg_added],
            "modified_values": [{"key_path": n.key_path, "value_name": n.value_name}
                                for (_o, n) in reg_modified],
            "note": registry_error,
        },
        "risks": risks,
        "scan_errors": errors,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def cmd_footprint(cfg: dict, app_name: Optional[str] = None,
                  report_path: Optional[str] = None,
                  quiet: bool = False) -> int:
    try:
        if files_mod.IS_WINDOWS:
            model = build_model_windows(cfg, app_name)
        else:
            model = build_model(cfg, app_name)
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    files_mod.warn_if_degraded(model.get("fidelity"))

    body = json.dumps(model, indent=2, default=str)

    if report_path and report_path != "-":
        tmp = report_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(body + "\n")
        os.replace(tmp, report_path)
        if not quiet:
            if files_mod.IS_WINDOWS:
                _print_summary_windows(model, report_path)
            else:
                _print_summary(model, report_path)
    else:
        print(body)

    return 1 if model["summary"]["files_added"] or model["summary"]["files_modified"] else 0


def _print_risks_and_footer(model: dict, path: str) -> None:
    risks = model["risks"]
    if risks:
        by_sev: dict[str, int] = {}
        for r in risks:
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        order = ["critical", "high", "medium", "low"]
        parts = [f"{by_sev[k]} {k}" for k in order if k in by_sev]
        print(f"  risks:      {', '.join(parts)}")
        for r in risks:
            if r["severity"] in ("critical", "high"):
                print(f"      [{r['severity']}] {r['detail']}")
    else:
        print("  risks:      none flagged")
    print(f"\n  → {path}")
    print("\n  Note: install-time footprint only. Merge with runtime observation")
    print("  before enforcing a policy. See footprint_caveat in the JSON.\n")


def _print_summary_windows(model: dict, path: str) -> None:
    s = model["summary"]
    print(f"\nInstall footprint for '{model['application']}' on {model['host']}")
    print(f"  files:      +{s['files_added']} added, ~{s['files_modified']} modified")
    print(f"  registry:   +{s['registry_values_added']} values, "
          f"~{s['registry_values_modified']} modified")
    print(f"  services:   {s['services']} Windows service(s), "
          f"{s['scheduled_tasks']} scheduled task(s)")
    if model["registry"].get("note"):
        print(f"  [!] {model['registry']['note']}")
    _print_risks_and_footer(model, path)


def _print_summary(model: dict, path: str) -> None:
    s = model["summary"]
    print(f"\nInstall footprint for '{model['application']}' on {model['host']}")
    print(f"  files:      +{s['files_added']} added, ~{s['files_modified']} modified")
    print(f"  services:   {s['systemd_units']} systemd unit(s), {s['cron_jobs']} cron job(s)")
    print(f"  principals: {s['users_added']} user(s), {s['groups_added']} group(s), "
          f"{s['membership_changes']} membership change(s)")
    print(f"  privilege:  {s['sudo_rules']} sudoers rule(s), {s['executables']} executable(s)")
    _print_risks_and_footer(model, path)
