#!/usr/bin/env python3
"""
cairn.winreg_mon — Windows registry integrity monitoring.
Companion to cairn.files; stores registry baselines in the same SQLite DB.

Only runs on Windows. On Linux it exits cleanly with a message so you can
ship the same files to both fleets.

Use via the CLI:
    cairn registry init   --config C:\\ProgramData\\Cairn\\cairn.yaml
    cairn registry scan   --config C:\\ProgramData\\Cairn\\cairn.yaml
    cairn registry update --config C:\\ProgramData\\Cairn\\cairn.yaml
    cairn registry verify --config C:\\ProgramData\\Cairn\\cairn.yaml
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sqlite3
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Iterator, Optional

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import winreg  # stdlib

# ---------------------------------------------------------------------------
# Default registry paths to monitor (autoruns + common persistence + policy)
# ---------------------------------------------------------------------------

DEFAULT_KEYS = [
    # Autoruns — by far the most-targeted persistence spots
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",

    # Winlogon — Userinit / Shell / Notify hijacks
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",

    # Image File Execution Options — debugger hijack
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",

    # AppInit_DLLs — DLL injection into every user-mode process
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",

    # Services
    r"HKLM\System\CurrentControlSet\Services",

    # Policies
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies",
    r"HKLM\Software\Policies",

    # Browser Helper Objects (IE) — old-school but still seen
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",

    # LSA (auth) — protected, but readable for hash comparison
    r"HKLM\System\CurrentControlSet\Control\Lsa",

    # Authentication packages
    r"HKLM\System\CurrentControlSet\Control\SecurityProviders",
]


# ---------------------------------------------------------------------------
# Config (reuses the same YAML/JSON loader pattern as cairn.files)
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "db_path": "fim_baseline.db",
    "registry_keys": DEFAULT_KEYS,
    "registry_recursive": True,
    "registry_max_depth": 6,        # keep the Services tree from blowing up
    "registry_exclude": [],         # substring matches against full key path
    "registry_skip_volatile": True, # don't bother flagging perf counters etc.
}


def load_config(path: Optional[str]) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if not path:
        return cfg
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        return cfg
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError:
            print("[!] PyYAML not installed; install it or use a .json config", file=sys.stderr)
            sys.exit(2)
        user = yaml.safe_load(text) or {}
    else:
        user = json.loads(text)
    cfg.update(user)
    return cfg


# ---------------------------------------------------------------------------
# Registry traversal
# ---------------------------------------------------------------------------

@dataclass
class RegRecord:
    key_path: str            # e.g. HKLM\Software\...\Run
    value_name: str          # "" for the (Default) value, or "<KEY>" for key-only entries
    value_type: int          # winreg REG_* constant
    value_repr: str          # canonical string form of the data (for diffing/display)
    value_hash: str          # sha256 of value_repr — fast equality check
    error: Optional[str]


HIVE_MAP = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKU":  "HKEY_USERS",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKCC": "HKEY_CURRENT_CONFIG",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER":  "HKEY_CURRENT_USER",
    "HKEY_USERS":         "HKEY_USERS",
    "HKEY_CLASSES_ROOT":  "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_CONFIG":"HKEY_CURRENT_CONFIG",
}


def _parse_key(full: str):
    """Split 'HKLM\\Software\\Foo' into (hive_handle, 'Software\\Foo', display_prefix)."""
    parts = full.replace("/", "\\").split("\\", 1)
    short = parts[0].upper()
    if short not in HIVE_MAP:
        raise ValueError(f"unknown hive: {short}")
    hive_name = HIVE_MAP[short]
    hive = getattr(winreg, hive_name)
    sub = parts[1] if len(parts) > 1 else ""
    return hive, sub, short


def _value_to_repr(value, vtype: int) -> str:
    """Stable string representation for hashing & display."""
    if vtype == winreg.REG_BINARY:
        if isinstance(value, (bytes, bytearray)):
            return "BIN:" + value.hex()
        return f"BIN:{value!r}"
    if vtype == winreg.REG_MULTI_SZ:
        # list of strings — join with NUL marker so order is preserved
        return "MULTI_SZ:" + "\x00".join(value or [])
    if vtype in (winreg.REG_DWORD, winreg.REG_QWORD):
        return f"INT:{int(value)}"
    if vtype in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        return f"STR:{value}"
    return f"T{vtype}:{value!r}"


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


def walk_key(full_key: str, cfg: dict, depth: int = 0) -> Iterator[RegRecord]:
    """Yield a RegRecord per value, plus a marker record per subkey."""
    if depth > cfg.get("registry_max_depth", 6):
        return
    for ex in cfg.get("registry_exclude", []):
        if ex.lower() in full_key.lower():
            return
    try:
        hive, subkey, _ = _parse_key(full_key)
    except ValueError as e:
        yield RegRecord(full_key, "", -1, "", "", f"parse-error: {e}")
        return

    # 64-bit view by default; readers can flip to KEY_WOW64_32KEY if needed
    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    try:
        handle = winreg.OpenKey(hive, subkey, 0, access)
    except FileNotFoundError:
        return  # silently skip keys that don't exist on this host
    except PermissionError as e:
        yield RegRecord(full_key, "", -1, "", "", f"open-denied: {e}")
        return
    except OSError as e:
        yield RegRecord(full_key, "", -1, "", "", f"open-error: {e}")
        return

    try:
        # --- enumerate values on this key ---
        try:
            _, num_values, _ = winreg.QueryInfoKey(handle)
        except OSError as e:
            yield RegRecord(full_key, "", -1, "", "", f"queryinfo-error: {e}")
            num_values = 0

        if num_values == 0:
            # Emit a key-existence marker so we can detect deletion of empty keys too
            rep = "KEY_EXISTS"
            yield RegRecord(full_key, "<KEY>", -1, rep, _sha(rep), None)

        for i in range(num_values):
            try:
                vname, vdata, vtype = winreg.EnumValue(handle, i)
            except OSError as e:
                yield RegRecord(full_key, f"<value#{i}>", -1, "", "", f"enum-error: {e}")
                continue
            rep = _value_to_repr(vdata, vtype)
            yield RegRecord(full_key, vname or "(Default)", vtype, rep, _sha(rep), None)

        # --- recurse into subkeys ---
        if cfg.get("registry_recursive", True):
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(handle, i)
                except OSError:
                    break
                yield from walk_key(full_key + "\\" + sub, cfg, depth + 1)
                i += 1
    finally:
        winreg.CloseKey(handle)


# ---------------------------------------------------------------------------
# SQLite storage (separate table, same DB file)
# ---------------------------------------------------------------------------

REG_SCHEMA = """
CREATE TABLE IF NOT EXISTS registry (
    key_path    TEXT NOT NULL,
    value_name  TEXT NOT NULL,
    value_type  INTEGER,
    value_repr  TEXT,
    value_hash  TEXT,
    error       TEXT,
    PRIMARY KEY (key_path, value_name)
);
CREATE INDEX IF NOT EXISTS idx_reg_key ON registry(key_path);
"""


def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(REG_SCHEMA)
    return conn


def save_record(conn: sqlite3.Connection, r: RegRecord) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO registry
           (key_path, value_name, value_type, value_repr, value_hash, error)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (r.key_path, r.value_name, r.value_type, r.value_repr, r.value_hash, r.error),
    )


def load_baseline(conn: sqlite3.Connection) -> dict[tuple[str, str], RegRecord]:
    conn.row_factory = sqlite3.Row
    out: dict[tuple[str, str], RegRecord] = {}
    for row in conn.execute("SELECT * FROM registry"):
        rec = RegRecord(
            key_path=row["key_path"], value_name=row["value_name"],
            value_type=row["value_type"], value_repr=row["value_repr"],
            value_hash=row["value_hash"], error=row["error"],
        )
        out[(rec.key_path, rec.value_name)] = rec
    return out


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _enum_all(cfg: dict) -> Iterator[RegRecord]:
    for k in cfg.get("registry_keys", []):
        yield from walk_key(k, cfg)


def collect_changes(cfg: dict):
    """Diff the live registry against the baseline. Returns
    (added, modified, deleted) where modified is a list of (old, new) tuples.

    Windows-only (walks the live registry via winreg). The footprint command
    consumes this to reconstruct services created by an install. Raises
    FileNotFoundError if no baseline exists.
    """
    import os
    db_path = cfg["db_path"]
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"no baseline at {db_path}; run `cairn all init` first")
    conn = open_db(db_path)
    try:
        baseline = load_baseline(conn)
    finally:
        conn.close()

    seen: set[tuple[str, str]] = set()
    added: list[RegRecord] = []
    modified: list[tuple[RegRecord, RegRecord]] = []
    for rec in _enum_all(cfg):
        key = (rec.key_path, rec.value_name)
        seen.add(key)
        old = baseline.get(key)
        if old is None:
            added.append(rec)
        elif old.value_hash != rec.value_hash:
            modified.append((old, rec))
    deleted = [baseline[k] for k in sorted(set(baseline.keys()) - seen)]
    return added, modified, deleted


def cmd_init(cfg: dict) -> int:
    if not IS_WINDOWS:
        print("[i] registry monitoring only runs on Windows; nothing to do here.")
        return 0
    conn = open_db(cfg["db_path"])
    n = 0
    print(f"[*] building registry baseline → {cfg['db_path']}")
    with conn:
        # wipe any prior registry state so init is a clean slate
        conn.execute("DELETE FROM registry")
        for rec in _enum_all(cfg):
            save_record(conn, rec)
            n += 1
            if n % 1000 == 0:
                print(f"    {n} entries...")
    conn.close()
    print(f"[+] registry baseline done: {n} entries")
    return 0


def cmd_scan(cfg: dict, json_out: bool = False, update: bool = False, quiet: bool = False) -> int:
    if not IS_WINDOWS:
        if not quiet:
            print("[i] registry monitoring only runs on Windows; skipping.")
        return 0
    conn = open_db(cfg["db_path"])
    baseline = load_baseline(conn)
    seen: set[tuple[str, str]] = set()

    added: list[RegRecord] = []
    modified: list[tuple[RegRecord, RegRecord]] = []

    for rec in _enum_all(cfg):
        key = (rec.key_path, rec.value_name)
        seen.add(key)
        old = baseline.get(key)
        if old is None:
            added.append(rec)
            if update:
                with conn: save_record(conn, rec)
            continue
        if old.value_hash != rec.value_hash:
            modified.append((old, rec))
            if update:
                with conn: save_record(conn, rec)

    deleted_keys = sorted(set(baseline.keys()) - seen)
    deleted = [baseline[k] for k in deleted_keys]
    if update and deleted_keys:
        with conn:
            conn.executemany(
                "DELETE FROM registry WHERE key_path = ? AND value_name = ?",
                deleted_keys,
            )
    conn.close()

    if json_out:
        print(json.dumps({
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "host": platform.node(),
            "added":    [asdict(r) for r in added],
            "deleted":  [asdict(r) for r in deleted],
            "modified": [{"old": asdict(o), "new": asdict(n)} for o, n in modified],
        }, indent=2, default=str))
    elif not quiet:
        print(f"\n=== Registry scan @ {datetime.now().isoformat(timespec='seconds')} ===")
        print(f"added: {len(added)}   modified: {len(modified)}   deleted: {len(deleted)}")
        if added:
            print("\n[+] ADDED")
            for r in added:
                print(f"    + {r.key_path}  [{r.value_name}] = {_short(r.value_repr)}")
        if modified:
            print("\n[~] MODIFIED")
            for old, new in modified:
                print(f"    ~ {new.key_path}  [{new.value_name}]")
                print(f"        old: {_short(old.value_repr)}")
                print(f"        new: {_short(new.value_repr)}")
        if deleted:
            print("\n[-] DELETED")
            for r in deleted:
                print(f"    - {r.key_path}  [{r.value_name}]")
        if not (added or modified or deleted):
            print("\nNo registry changes detected. ✓")

    return 1 if (added or modified or deleted) else 0


def _short(s: str, n: int = 120) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + "…"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Windows registry integrity monitor")
    p.add_argument("command", choices=["init", "scan", "update", "verify"])
    p.add_argument("--config", "-c")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    cfg = load_config(args.config)

    if args.command == "init":   return cmd_init(cfg)
    if args.command == "scan":   return cmd_scan(cfg, json_out=args.json)
    if args.command == "update": return cmd_scan(cfg, update=True)
    if args.command == "verify": return cmd_scan(cfg, quiet=True)
    return 2
