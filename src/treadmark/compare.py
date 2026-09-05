"""treadmark.compare — compare baselines across hosts.

Two modes:

  treadmark compare against /path/to/golden.db --config local.yaml
        Walk the local filesystem (using `local.yaml`'s paths) and report drift
        relative to the golden baseline. Same UX as `treadmark files scan`, but the
        baseline came from a different machine.

  treadmark compare baselines /path/to/a.db /path/to/b.db
        Pure database-to-database diff. No filesystem walk, no hashing.
        Reports paths only-in-A, only-in-B, and present-in-both-but-different.

The golden-baseline workflow is how you do file integrity monitoring at
fleet scale: build the baseline once on a known-clean reference machine
("golden image"), copy the .db file to every other server of the same
role, then `treadmark compare against` on each to find drift.

Important caveat: this works best when the hosts are *meant* to be
identical (same OS version, same package set, same role). Comparing a
RHEL 8 baseline against a RHEL 9 host produces noise from package
upgrades, not real drift. Group hosts by role + OS and keep one golden
baseline per group.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from . import files as files_mod


# ---------------------------------------------------------------------------
# Loading a baseline from a foreign DB without touching its location.
# ---------------------------------------------------------------------------

def load_external_baseline(db_path: str) -> dict[str, files_mod.FileRecord]:
    """Open a baseline DB read-only and return its records keyed by path."""
    # ?mode=ro stops us from accidentally writing to the golden DB
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        conn.row_factory = sqlite3.Row
        out: dict[str, files_mod.FileRecord] = {}
        for row in conn.execute("SELECT * FROM files"):
            out[row["path"]] = files_mod.row_to_record(row)
        return out
    finally:
        conn.close()


def read_meta(db_path: str) -> dict[str, str]:
    """Pull the meta table (host, created_at, etc.) for context."""
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        out = {}
        for row in conn.execute("SELECT key, value FROM meta"):
            out[row[0]] = row[1]
        return out
    except sqlite3.OperationalError:
        return {}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Path normalization — critical for cross-host compares.
#
# A baseline built on host A under /opt/myapp shouldn't fail to compare
# against host B's /opt/myapp just because absolute paths differ in trivial
# ways (case, trailing slashes, drive letters on Windows). We canonicalize
# before keying records.
# ---------------------------------------------------------------------------

def _canon(path: str, *, case_insensitive: bool = False) -> str:
    p = path.replace("\\", "/").rstrip("/")
    if case_insensitive:
        p = p.lower()
    return p


def _rekey(records: dict[str, files_mod.FileRecord], *, case_insensitive: bool) -> dict[str, files_mod.FileRecord]:
    return {_canon(p, case_insensitive=case_insensitive): r for p, r in records.items()}


# ---------------------------------------------------------------------------
# Mode A: compare a live filesystem walk against a foreign baseline.
# ---------------------------------------------------------------------------

def cmd_against(cfg: dict, golden_db: str, *, json_out: bool = False, quiet: bool = False) -> int:
    """Walk the local FS using cfg, compare against the golden baseline."""
    if not cfg.get("paths"):
        print("[!] config has no `paths` configured.", file=sys.stderr)
        return 2
    # Same fail-closed rule as `files scan`: a typo'd compare_fields must not
    # silently drop comparisons from a drift check.
    problems = files_mod.compare_fields_problems(cfg)
    if problems:
        for msg in problems:
            print(f"[!] {msg}", file=sys.stderr)
        return 2

    golden = load_external_baseline(golden_db)
    golden_meta = read_meta(golden_db)

    # On Windows we want path matching to be case-insensitive; on Linux we don't.
    case_insensitive = sys.platform.startswith("win")
    golden_canon = _rekey(golden, case_insensitive=case_insensitive)

    seen: set[str] = set()
    added: list[files_mod.FileRecord] = []
    modified: list[tuple[files_mod.FileRecord, files_mod.FileRecord, list[str]]] = []

    for fp in files_mod.walk_paths(cfg):
        try:
            rec = files_mod.stat_file(fp, cfg)
        except (OSError, PermissionError) as e:
            print(f"    skip {fp}: {e}", file=sys.stderr)
            continue
        key = _canon(rec.path, case_insensitive=case_insensitive)
        seen.add(key)
        old = golden_canon.get(key)
        if old is None:
            added.append(rec)
            continue
        diffs = files_mod.diff_records(old, rec, cfg)
        if diffs:
            modified.append((old, rec, diffs))

    deleted_keys = sorted(set(golden_canon.keys()) - seen)
    deleted = [golden_canon[k] for k in deleted_keys]

    if json_out:
        print(json.dumps({
            "compared_at": datetime.now(timezone.utc).isoformat(),
            "this_host":   _hostname(),
            "golden": {
                "db_path":    golden_db,
                "host":       golden_meta.get("host", "?"),
                "created_at": golden_meta.get("created_at", "?"),
                "os":         golden_meta.get("os", "?"),
                "file_count": golden_meta.get("file_count", "?"),
            },
            "added":    [asdict(r) for r in added],
            "deleted":  [asdict(r) for r in deleted],
            "modified": [{"old": asdict(o), "new": asdict(n), "changes": d}
                         for (o, n, d) in modified],
        }, indent=2, default=str))
    elif not quiet:
        print(f"\n=== Drift vs golden @ {datetime.now().isoformat(timespec='seconds')} ===")
        print(f"this host:   {_hostname()}")
        print(f"golden host: {golden_meta.get('host', '?')}  "
              f"(baseline built {golden_meta.get('created_at', '?')})")
        print(f"added: {len(added)}   modified: {len(modified)}   "
              f"missing-here: {len(deleted)}")
        if added:
            print("\n[+] PRESENT HERE BUT NOT IN GOLDEN")
            for r in added:
                print(f"    + {r.path}  ({r.size} bytes, owner={r.owner})")
        if modified:
            print("\n[~] DIFFERS FROM GOLDEN")
            for (old, new, diffs) in modified:
                print(f"    ~ {new.path}")
                for d in diffs:
                    print(f"        · {d}")
        if deleted:
            print("\n[-] IN GOLDEN BUT MISSING HERE")
            for r in deleted:
                print(f"    - {r.path}")
        if not (added or modified or deleted):
            print("\nHost matches golden baseline. ✓")

    return 1 if (added or modified or deleted) else 0


# ---------------------------------------------------------------------------
# Mode B: pure DB-to-DB diff. No filesystem walk.
# ---------------------------------------------------------------------------

def cmd_baselines(db_a: str, db_b: str, *, json_out: bool = False) -> int:
    """Compare two baseline databases. Does not touch the filesystem."""
    a = load_external_baseline(db_a)
    b = load_external_baseline(db_b)
    meta_a = read_meta(db_a)
    meta_b = read_meta(db_b)

    case_insensitive = sys.platform.startswith("win")
    a_canon = _rekey(a, case_insensitive=case_insensitive)
    b_canon = _rekey(b, case_insensitive=case_insensitive)

    only_a   = sorted(set(a_canon) - set(b_canon))
    only_b   = sorted(set(b_canon) - set(a_canon))
    in_both  = set(a_canon) & set(b_canon)

    differs: list[tuple[files_mod.FileRecord, files_mod.FileRecord, list[str]]] = []
    cfg = {"track_access_time": False}  # use diff_records' default semantics
    for k in sorted(in_both):
        ra, rb = a_canon[k], b_canon[k]
        d = files_mod.diff_records(ra, rb, cfg)
        if d:
            differs.append((ra, rb, d))

    if json_out:
        print(json.dumps({
            "compared_at": datetime.now(timezone.utc).isoformat(),
            "a": {"db": db_a, "host": meta_a.get("host", "?"),
                  "created_at": meta_a.get("created_at", "?")},
            "b": {"db": db_b, "host": meta_b.get("host", "?"),
                  "created_at": meta_b.get("created_at", "?")},
            "only_in_a": [asdict(a_canon[k]) for k in only_a],
            "only_in_b": [asdict(b_canon[k]) for k in only_b],
            "differs":   [{"a": asdict(ra), "b": asdict(rb), "changes": d}
                          for (ra, rb, d) in differs],
        }, indent=2, default=str))
    else:
        host_a = meta_a.get("host", db_a)
        host_b = meta_b.get("host", db_b)
        print(f"\n=== Baseline diff: {host_a}  vs  {host_b} ===")
        print(f"only in A ({host_a}): {len(only_a)}    "
              f"only in B ({host_b}): {len(only_b)}    "
              f"differs: {len(differs)}")
        if only_a:
            print(f"\n[A] ONLY IN {host_a}")
            for k in only_a:
                r = a_canon[k]
                print(f"    A {r.path}  ({r.size} bytes)")
        if only_b:
            print(f"\n[B] ONLY IN {host_b}")
            for k in only_b:
                r = b_canon[k]
                print(f"    B {r.path}  ({r.size} bytes)")
        if differs:
            print("\n[~] DIFFER BETWEEN HOSTS")
            for (ra, rb, d) in differs:
                print(f"    ~ {rb.path}")
                for change in d:
                    print(f"        · {change}")
        if not (only_a or only_b or differs):
            print("\nBaselines match. ✓")

    return 1 if (only_a or only_b or differs) else 0


def _hostname() -> str:
    import platform
    return platform.node()
