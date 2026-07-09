#!/usr/bin/env python3
"""
cairn.files — Cross-platform filesystem integrity monitor.

Works on Linux and Windows. Creates a baseline snapshot of files (hash +
metadata) and reports added / modified / deleted / permission-changed files
on subsequent scans.

Use via the CLI:
    cairn files init   --config /etc/cairn/cairn.yaml
    cairn files scan   --config /etc/cairn/cairn.yaml
    cairn files update --config /etc/cairn/cairn.yaml
    cairn files verify --config /etc/cairn/cairn.yaml

The baseline is stored in a SQLite DB (default: /var/lib/cairn/baseline.db).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sqlite3
import stat
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

# Optional platform modules — imported lazily so the tool runs on either OS.
if IS_LINUX:
    import pwd
    import grp

if IS_WINDOWS:
    try:
        import win32security  # type: ignore
        import ntsecuritycon  # noqa: F401  # type: ignore
        HAVE_PYWIN32 = True
    except ImportError:
        HAVE_PYWIN32 = False


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "db_path": "fim_baseline.db",
    "paths": [],            # list of directories or files to monitor
    "exclude": [],          # substrings; if any appears in the path, skip
    "exclude_extensions": [".log", ".tmp", ".swp"],
    "follow_symlinks": False,
    "hash_algorithm": "sha256",
    "max_file_size_mb": 500,   # files bigger than this are tracked but not hashed
    "track_access_time": False,  # atime is noisy; off by default
}


def load_config(path: Optional[str]) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if not path:
        return cfg
    p = Path(path)
    if not p.exists():
        print(f"[!] config not found: {path} — using defaults", file=sys.stderr)
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
# File metadata model
# ---------------------------------------------------------------------------

@dataclass
class FileRecord:
    path: str
    size: int
    mtime: float
    ctime: float
    atime: float
    mode: int               # POSIX mode bits (0 on Windows-only attrs)
    uid: int
    gid: int
    owner: str              # username (or SID on Windows)
    group: str              # group name (or empty on Windows)
    is_dir: bool
    is_symlink: bool
    sha256: Optional[str]   # None for dirs, oversized files, or unreadable files
    acl: Optional[str]      # Windows DACL text representation, else None
    error: Optional[str]    # populated if the file couldn't be hashed/read
    # Optional gzipped content of the file at baseline time. Captured only
    # for text files under `store_content_max_kb` size, controlled by config.
    # Lets `cairn files scan` show line-level diffs for changed config files.
    content_gz: Optional[bytes] = None
    # The path as it exists on the scanning machine. Differs from `path` only
    # when root_prefix is set (mounted image, container rootfs, chroot).
    # NEVER persisted: the DB stores logical paths, so a baseline captured from
    # one rootfs can be diffed against a different rootfs.
    real_path: Optional[str] = None


# ---------------------------------------------------------------------------
# Walking & hashing
# ---------------------------------------------------------------------------

def hash_file(path: str, algorithm: str = "sha256", chunk: int = 1024 * 1024) -> str:
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Text detection and content capture for diff display
# ---------------------------------------------------------------------------
# We optionally store the gzipped content of small text files in the baseline
# so that `cairn files scan` can render unified diffs for changed configs
# (rather than just "sha256 changed"). This is invaluable for forensic
# investigation but adds two real concerns:
#
#   1. Privacy: the baseline DB now contains snapshots of monitored files.
#      The DB is mode 0700 root-only on Linux and ACL-locked on Windows, but
#      operators should know this and can disable content capture entirely
#      via `store_content: false` in the config.
#
#   2. Size: a baseline of /etc with content capture is roughly 10x larger
#      than one without. Still small in absolute terms (single-digit MB for
#      typical /etc), but worth knowing.

# Read this much from the head of a file to decide if it's text.
_TEXT_PROBE_BYTES = 8192


def _looks_like_text(head: bytes) -> bool:
    """Same heuristic Git uses: NUL byte means binary, otherwise try UTF-8."""
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
        return True
    except UnicodeDecodeError:
        # Try a permissive fallback for legacy Latin-1 configs
        try:
            head.decode("latin-1")
            # If decodable but mostly non-printable, treat as binary
            printable = sum(1 for b in head if 0x20 <= b < 0x7f or b in (9, 10, 13))
            return printable >= 0.85 * len(head)
        except UnicodeDecodeError:
            return False


def capture_content_if_text(path: str, max_bytes: int) -> Optional[bytes]:
    """Read up to max_bytes from path. If it looks like text, return gzipped
    contents. Otherwise return None. Returns None on read failure."""
    if max_bytes <= 0:
        return None
    try:
        with open(path, "rb") as f:
            head = f.read(_TEXT_PROBE_BYTES)
            if not _looks_like_text(head):
                return None
            # Looks like text — read the rest up to max_bytes
            rest = f.read(max(0, max_bytes - len(head)))
        full = head + rest
    except (OSError, PermissionError):
        return None
    import gzip
    return gzip.compress(full, compresslevel=6)


def decompress_content(blob: Optional[bytes]) -> Optional[str]:
    """Inverse of capture_content_if_text. Returns text or None on failure."""
    if not blob:
        return None
    import gzip
    try:
        return gzip.decompress(blob).decode("utf-8", errors="replace")
    except (OSError, gzip.BadGzipFile):
        return None


def get_owner_group(st: os.stat_result, path: str) -> tuple[str, str]:
    """Return (owner, group) as strings. Cross-platform."""
    if IS_LINUX:
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except (KeyError, AttributeError):
            owner = str(st.st_uid)
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except (KeyError, AttributeError):
            group = str(st.st_gid)
        return owner, group

    if IS_WINDOWS and HAVE_PYWIN32:
        try:
            sd = win32security.GetFileSecurity(
                path, win32security.OWNER_SECURITY_INFORMATION
            )
            sid = sd.GetSecurityDescriptorOwner()
            name, domain, _ = win32security.LookupAccountSid(None, sid)
            return f"{domain}\\{name}", ""
        except Exception:
            return "", ""

    return str(getattr(st, "st_uid", "")), str(getattr(st, "st_gid", ""))


def get_acl(path: str) -> Optional[str]:
    """Windows: return a stable string representation of the DACL.
    Linux: returns None (mode bits already cover this)."""
    if not (IS_WINDOWS and HAVE_PYWIN32):
        return None
    try:
        sd = win32security.GetFileSecurity(
            path, win32security.DACL_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return "no-dacl"
        entries = []
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            # ace = ((AceType, AceFlags), AccessMask, Sid)
            (ace_type, ace_flags), mask, sid = ace
            try:
                name, domain, _ = win32security.LookupAccountSid(None, sid)
                principal = f"{domain}\\{name}"
            except Exception:
                principal = str(sid)
            entries.append(f"{ace_type}:{ace_flags}:{mask:08x}:{principal}")
        return ";".join(sorted(entries))  # sort for stable comparison
    except Exception:
        return None


def stat_file(path: str, cfg: dict) -> FileRecord:
    """Build a FileRecord for a single path.

    `path` is the real path on the scanning machine. The resulting record's
    `.path` is the logical path inside the target root (identical unless
    root_prefix is set); `.real_path` retains the scannable location.
    """
    root_prefix = get_root_prefix(cfg)
    follow = cfg.get("follow_symlinks", False)
    st = os.stat(path, follow_symlinks=follow)
    is_dir = stat.S_ISDIR(st.st_mode)
    is_symlink = os.path.islink(path)
    owner, group = get_owner_group(st, path)
    acl = get_acl(path) if not is_dir else None

    sha = None
    err = None
    max_bytes = cfg.get("max_file_size_mb", 500) * 1024 * 1024
    if not is_dir and not is_symlink and st.st_size <= max_bytes:
        try:
            sha = hash_file(path, cfg.get("hash_algorithm", "sha256"))
        except (OSError, PermissionError) as e:
            err = f"hash-failed: {e.__class__.__name__}: {e}"

    # Optional text-content capture for diff display. Off by default; opt in
    # via `store_content: true` in cfg. `store_content_max_kb` caps per-file
    # size; default 256 KB is plenty for config files but won't accidentally
    # eat a 50 MB log.
    content_gz: Optional[bytes] = None
    if (cfg.get("store_content", False)
            and not is_dir and not is_symlink and not err):
        max_content_kb = int(cfg.get("store_content_max_kb", 256))
        if st.st_size <= max_content_kb * 1024:
            content_gz = capture_content_if_text(path, max_content_kb * 1024)

    real = os.path.abspath(path)
    return FileRecord(
        path=to_logical(real, root_prefix),
        real_path=real,
        size=st.st_size,
        mtime=st.st_mtime,
        ctime=st.st_ctime,
        atime=st.st_atime,
        mode=st.st_mode,
        uid=getattr(st, "st_uid", 0),
        gid=getattr(st, "st_gid", 0),
        owner=owner,
        group=group,
        is_dir=is_dir,
        is_symlink=is_symlink,
        sha256=sha,
        acl=acl,
        error=err,
        content_gz=content_gz,
    )


def get_root_prefix(cfg: dict) -> str:
    """Normalized root_prefix from config, or "" for a live host scan."""
    rp = (cfg.get("root_prefix") or "").strip()
    if not rp or rp == "/":
        return ""
    return os.path.abspath(os.path.expanduser(rp)).rstrip("/")


def to_logical(path: str, root_prefix: str) -> str:
    """Real scanned path -> the path as it exists inside the target root.

    /mnt/image/etc/passwd with root_prefix=/mnt/image  ->  /etc/passwd
    Live-host scans (root_prefix="") pass through unchanged.
    """
    if not root_prefix:
        return path
    if path == root_prefix:
        return "/"
    if path.startswith(root_prefix + os.sep) or path.startswith(root_prefix + "/"):
        return path[len(root_prefix):]
    return path


def to_real(logical: str, root_prefix: str) -> str:
    """Inverse of to_logical: the path to actually open on this machine."""
    if not root_prefix:
        return logical
    return root_prefix + logical if logical.startswith("/") else os.path.join(root_prefix, logical)


def should_skip(path: str, cfg: dict) -> bool:
    # Exclude patterns are written against logical paths (/var/cache/, /etc/mtab)
    # so one config works for a live host and for a mounted image alike.
    path = to_logical(path, get_root_prefix(cfg))
    norm = path.replace("\\", "/")
    for pat in cfg.get("exclude", []):
        if pat in norm:
            return True
    ext = os.path.splitext(path)[1].lower()
    if ext in [e.lower() for e in cfg.get("exclude_extensions", [])]:
        return True
    return False


def should_accept(path: str, accept: set[str]) -> bool:
    """Decide whether `path` should be written into the baseline during update.

    Match rules:
      - "*" in accept → accept everything (sentinel for --accept-all)
      - exact path match → accept just that path
      - path is under an accept entry that's a directory → accept

    Paths are normalized to forward slashes and made absolute so Windows
    backslashes, relative arguments, and trailing slashes all behave the
    same.
    """
    if "*" in accept:
        return True
    p = os.path.abspath(path).replace("\\", "/")
    for a in accept:
        a_norm = os.path.abspath(a).replace("\\", "/").rstrip("/")
        if p == a_norm:
            return True
        if p.startswith(a_norm + "/"):
            return True
    return False


def load_accept_file(path: str) -> list[str]:
    """Read accept paths from a text file, one per line. Blanks and lines
    starting with '#' are ignored. Returned paths are not normalized
    (should_accept handles that)."""
    out: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
    return out


def walk_paths(cfg: dict) -> Iterator[str]:
    """Yield real paths to scan.

    `paths:` entries are logical (as they appear inside the target root). When
    root_prefix is set they are joined onto it, so the same config scans a live
    host, a mounted disk image, or an extracted container rootfs unchanged.
    """
    follow = cfg.get("follow_symlinks", False)
    root_prefix = get_root_prefix(cfg)
    for root in cfg.get("paths", []):
        root = os.path.expanduser(os.path.expandvars(root))
        root = to_real(root, root_prefix)
        if not os.path.exists(root):
            print(f"[!] path missing, skipping: {root}", file=sys.stderr)
            continue
        if os.path.isfile(root):
            if not should_skip(root, cfg):
                yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow):
            # let exclude rules prune directories too (faster)
            dirnames[:] = [d for d in dirnames if not should_skip(os.path.join(dirpath, d), cfg)]
            if not should_skip(dirpath, cfg):
                yield dirpath
            for name in filenames:
                fp = os.path.join(dirpath, name)
                if should_skip(fp, cfg):
                    continue
                yield fp


def assess_root_fidelity(cfg: dict, sample_limit: int = 5000) -> Optional[dict]:
    """Sanity-check a --root tree for signs of an unfaithful extraction.

    `docker export | tar -x` run without root silently drops uid/gid
    ownership and setuid bits. Everything downstream that reasons about
    ownership or setuid then produces confident wrong answers. This heuristic
    catches the degenerate signature: (a) virtually every file owned by one
    non-root uid, AND (b) zero setuid bits under the bin directories. Both
    must hold — distroless images legitimately have no setuid binaries, and
    single-uid images exist, but a rootfs satisfying both at once almost
    certainly lost its metadata during extraction.

    Returns None for live-host scans (no root_prefix); otherwise
    {"status": "ok"|"degraded", "sampled_files": N, "reasons": [...]}.
    This is a warning signal only — callers must never fail on it.
    """
    root_prefix = get_root_prefix(cfg)
    if not root_prefix:
        return None

    bin_prefixes = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")
    uid_counts: dict[int, int] = {}
    setuid_seen = False
    sampled = 0
    for fp in walk_paths(cfg):
        if sampled >= sample_limit:
            break
        try:
            st = os.lstat(fp)
        except (OSError, PermissionError):
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        sampled += 1
        uid_counts[st.st_uid] = uid_counts.get(st.st_uid, 0) + 1
        if st.st_mode & stat.S_ISUID:
            logical = to_logical(os.path.abspath(fp), root_prefix)
            if logical.startswith(bin_prefixes):
                setuid_seen = True

    result: dict = {"status": "ok", "sampled_files": sampled, "reasons": []}
    if not sampled:
        return result

    top_uid, top_count = max(uid_counts.items(), key=lambda kv: kv[1])
    uniform_nonroot = top_uid != 0 and top_count > 0.99 * sampled
    if uniform_nonroot and not setuid_seen:
        result["status"] = "degraded"
        result["reasons"] = [
            f"{100.0 * top_count / sampled:.1f}% of {sampled} sampled files are "
            f"owned by uid {top_uid} (non-root); extraction likely ran without "
            "root / --same-owner",
            "no setuid binaries under /bin, /sbin, /usr/bin, /usr/sbin; "
            "setuid bits were likely stripped during extraction",
        ]
    return result


def warn_if_degraded(fidelity: Optional[dict]) -> None:
    """Print a loud stderr warning when a --root tree looks unfaithful."""
    if not fidelity or fidelity.get("status") != "degraded":
        return
    print("[!] rootfs fidelity degraded — ownership and setuid data are "
          "unreliable:", file=sys.stderr)
    for reason in fidelity.get("reasons", []):
        print(f"    - {reason}", file=sys.stderr)
    print("    Re-extract as root (e.g. sudo scripts/container-rootfs.sh) "
          "for a faithful tree.", file=sys.stderr)


# ---------------------------------------------------------------------------
# SQLite storage
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS files (
    path        TEXT PRIMARY KEY,
    size        INTEGER,
    mtime       REAL,
    ctime       REAL,
    atime       REAL,
    mode        INTEGER,
    uid         INTEGER,
    gid         INTEGER,
    owner       TEXT,
    grp         TEXT,
    is_dir      INTEGER,
    is_symlink  INTEGER,
    sha256      TEXT,
    acl         TEXT,
    error       TEXT,
    content_gz  BLOB                 -- gzipped text content, NULL for binary/oversized/unread
);
CREATE INDEX IF NOT EXISTS idx_files_sha ON files(sha256);
"""


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the initial schema. Safe to run on any
    existing baseline — ALTER TABLE ADD COLUMN is a no-op if the column is
    already there (we check first because SQLite doesn't have IF NOT EXISTS
    for column adds before 3.35)."""
    cur = conn.execute("PRAGMA table_info(files)")
    cols = {row[1] for row in cur}
    if "content_gz" not in cols:
        conn.execute("ALTER TABLE files ADD COLUMN content_gz BLOB")
        conn.commit()


def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    _migrate_schema(conn)
    return conn


def save_record(conn: sqlite3.Connection, rec: FileRecord) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO files
           (path, size, mtime, ctime, atime, mode, uid, gid, owner, grp,
            is_dir, is_symlink, sha256, acl, error, content_gz)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            rec.path, rec.size, rec.mtime, rec.ctime, rec.atime, rec.mode,
            rec.uid, rec.gid, rec.owner, rec.group,
            int(rec.is_dir), int(rec.is_symlink), rec.sha256, rec.acl, rec.error,
            rec.content_gz,
        ),
    )


def row_to_record(row: sqlite3.Row) -> FileRecord:
    # content_gz column may not exist in baselines built before the migration
    # was added; fall back to None gracefully.
    try:
        blob = row["content_gz"]
    except (IndexError, KeyError):
        blob = None
    return FileRecord(
        path=row["path"], size=row["size"], mtime=row["mtime"], ctime=row["ctime"],
        atime=row["atime"], mode=row["mode"], uid=row["uid"], gid=row["gid"],
        owner=row["owner"], group=row["grp"],
        is_dir=bool(row["is_dir"]), is_symlink=bool(row["is_symlink"]),
        sha256=row["sha256"], acl=row["acl"], error=row["error"],
        content_gz=blob,
    )


def load_baseline(conn: sqlite3.Connection) -> dict[str, FileRecord]:
    conn.row_factory = sqlite3.Row
    cur = conn.execute("SELECT * FROM files")
    out: dict[str, FileRecord] = {}
    for row in cur:
        out[row["path"]] = row_to_record(row)
    return out


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(cfg: dict, force: bool = False) -> int:
    db_path = cfg["db_path"]
    if os.path.exists(db_path) and not force:
        print(f"[!] {db_path} already exists. Use --force to overwrite, or run `update`.")
        return 2
    if os.path.exists(db_path) and force:
        os.remove(db_path)

    conn = open_db(db_path)
    set_meta(conn, "created_at", datetime.now(timezone.utc).isoformat())
    set_meta(conn, "host", platform.node())
    set_meta(conn, "os", platform.platform())

    count = 0
    started = time.time()
    print(f"[*] building baseline → {db_path}")
    with conn:
        for fp in walk_paths(cfg):
            try:
                rec = stat_file(fp, cfg)
            except (OSError, PermissionError) as e:
                print(f"    skip {fp}: {e}", file=sys.stderr)
                continue
            save_record(conn, rec)
            count += 1
            if count % 500 == 0:
                print(f"    {count} entries...")
    set_meta(conn, "file_count", str(count))
    conn.commit()
    conn.close()
    print(f"[+] baseline done: {count} entries in {time.time() - started:.1f}s")
    return 0


# fields where a change is "metadata" rather than "content"
META_FIELDS = ("size", "mtime", "ctime", "mode", "uid", "gid", "owner", "group", "acl")


def unified_diff_for(old: FileRecord, new: FileRecord, max_lines: int = 60) -> Optional[str]:
    """Render a unified diff between old and new content, if both are stored
    text. Returns None if either side has no stored content. Output is
    truncated to max_lines to keep terminal/report output sane."""
    if not old.content_gz or not new.content_gz:
        return None
    old_text = decompress_content(old.content_gz)
    new_text = decompress_content(new.content_gz)
    if old_text is None or new_text is None:
        return None
    import difflib
    diff_lines = list(difflib.unified_diff(
        old_text.splitlines(keepends=False),
        new_text.splitlines(keepends=False),
        fromfile=f"baseline:{old.path}",
        tofile=f"current:{new.path}",
        lineterm="",
        n=3,
    ))
    if not diff_lines:
        # Hashes differ but content matches — likely an encoding artifact or
        # baseline-vs-scan storage mismatch. Tell the operator something.
        return "(content differs at byte level but unified diff is empty — possible encoding or whitespace issue)"
    if len(diff_lines) > max_lines:
        omitted = len(diff_lines) - max_lines
        diff_lines = diff_lines[:max_lines]
        diff_lines.append(f"... ({omitted} more diff lines truncated)")
    return "\n".join(diff_lines)


def diff_records(old: FileRecord, new: FileRecord, cfg: dict) -> list[str]:
    changes: list[str] = []

    if old.sha256 and new.sha256 and old.sha256 != new.sha256:
        changes.append(f"content sha256 {old.sha256[:12]}…→{new.sha256[:12]}…")
    elif old.size != new.size:
        # different size and we didn't / couldn't hash one side
        changes.append(f"size {old.size}→{new.size}")

    if old.mode != new.mode:
        changes.append(f"mode {stat.filemode(old.mode)}→{stat.filemode(new.mode)}")

    if old.owner != new.owner:
        changes.append(f"owner {old.owner!r}→{new.owner!r}")
    if old.group != new.group:
        changes.append(f"group {old.group!r}→{new.group!r}")

    if old.acl != new.acl:
        changes.append("acl changed")

    # mtime alone (without size/hash change) usually means a touch — still
    # worth noting, but only when the integer-second value actually changed.
    # Sub-second drift is just filesystem timestamp granularity and pollutes
    # forensic output with phantom changes.
    if int(old.mtime) != int(new.mtime) and not any(
        c.startswith("content") or c.startswith("size") for c in changes
    ):
        # Truncate (not round) so the displayed values can never be equal —
        # the comparison above truncates, and "mtime X→X" reads as a bug.
        changes.append(f"mtime {int(old.mtime)}→{int(new.mtime)}")

    if cfg.get("track_access_time") and old.atime != new.atime:
        changes.append("atime changed")

    return changes


def cmd_scan(cfg: dict, json_out: bool = False,
             update_accept: Optional[set[str]] = None,
             dry_run: bool = False, quiet: bool = False,
             report_path: Optional[str] = None, report_format: Optional[str] = None) -> int:
    """Run a scan, optionally update accepted paths in the baseline.

    update_accept semantics:
      None  → plain scan, baseline untouched (the default)
      set() → update mode but no accept paths matched; nothing gets written
      {"*"} → accept-all sentinel (from --accept-all)
      other → write only entries whose path matches the set (see should_accept)

    dry_run=True with update_accept set prints what would be written instead
    of writing, so operators can preview an `update` before committing.

    Output rules (in priority order):
      1. If report_path is set (or cfg['report']['path']), write a report file.
         Format chosen from report_format → cfg['report']['format'] → file extension.
      2. If json_out is True, print JSON to stdout (legacy --json flag).
      3. Otherwise print colorized terminal output (unless quiet=True).

    Returns exit code: 0 = clean, 1 = drift, 2 = error.
    """
    from . import report as report_mod  # local import to avoid circular at module load

    db_path = cfg["db_path"]
    if not os.path.exists(db_path):
        print(f"[!] no baseline at {db_path}; run `init` first", file=sys.stderr)
        return 2

    # --root scans of a badly-extracted tree produce confidently wrong
    # ownership/setuid answers; warn loudly up front (never fail).
    warn_if_degraded(assess_root_fidelity(cfg))

    conn = open_db(db_path)
    baseline = load_baseline(conn)
    seen: set[str] = set()

    added: list[FileRecord] = []
    modified: list[tuple[FileRecord, FileRecord, list[str]]] = []
    errors: list[str] = []
    dry_run_actions: list[tuple[str, str]] = []   # (kind, path) where kind in {"upsert","delete"}

    for fp in walk_paths(cfg):
        try:
            rec = stat_file(fp, cfg)
        except (OSError, PermissionError) as e:
            err = f"skip {fp}: {e}"
            errors.append(err)
            print(f"    {err}", file=sys.stderr)
            continue
        seen.add(rec.path)
        old = baseline.get(rec.path)
        if old is None:
            added.append(rec)
            if update_accept is not None and should_accept(rec.path, update_accept):
                if dry_run:
                    dry_run_actions.append(("upsert", rec.path))
                else:
                    with conn:
                        save_record(conn, rec)
            continue
        diffs = diff_records(old, rec, cfg)
        if diffs:
            modified.append((old, rec, diffs))
            if update_accept is not None and should_accept(rec.path, update_accept):
                if dry_run:
                    dry_run_actions.append(("upsert", rec.path))
                else:
                    with conn:
                        save_record(conn, rec)

    deleted_paths = sorted(set(baseline.keys()) - seen)
    deleted = [baseline[p] for p in deleted_paths]
    if update_accept is not None:
        accepted_deletes = [p for p in deleted_paths if should_accept(p, update_accept)]
        if dry_run:
            dry_run_actions.extend(("delete", p) for p in accepted_deletes)
        elif accepted_deletes:
            with conn:
                conn.executemany("DELETE FROM files WHERE path = ?",
                                 [(p,) for p in accepted_deletes])

    if update_accept is not None and not dry_run:
        set_meta(conn, "last_update", datetime.now(timezone.utc).isoformat())
        conn.commit()
    conn.close()

    # ----- Build the canonical result -----
    result = report_mod.ScanResult(
        scanned_at=datetime.now(timezone.utc).isoformat(),
        host=platform.node(),
        db_path=db_path,
        added=added,
        modified=modified,
        deleted=deleted,
        errors=errors,
    )

    # ----- Resolve report path/format from CLI flags ⇒ config defaults -----
    report_cfg = cfg.get("report") or {}
    final_path   = report_path   or report_cfg.get("path")
    final_format = report_format or report_cfg.get("format")

    # ----- Dispatch output -----
    if final_path:
        # Special case: "-" means stdout. Format must be explicit (no extension to detect).
        if final_path == "-":
            fmt = final_format or "json"
            print(report_mod.render(result, fmt))
        else:
            actual_fmt = report_mod.write_report(result, final_path, final_format)
            if not quiet:
                # Still print a brief status to the terminal so operators know
                # the scan ran and where the report went.
                drift = "DRIFT" if result.has_drift else "clean"
                print(f"[{drift}] cairn scan complete — "
                      f"+{len(added)} ~{len(modified)} -{len(deleted)} "
                      f"→ {final_path} ({actual_fmt})")
    elif json_out:
        # Legacy --json flag — JSON to stdout
        print(report_mod.render(result, "json"), end="")
    elif not quiet:
        print(report_mod.render_terminal(result))

    # ----- Dry-run summary of what update would have done -----
    if dry_run and update_accept is not None:
        upserts = sum(1 for kind, _ in dry_run_actions if kind == "upsert")
        deletes = sum(1 for kind, _ in dry_run_actions if kind == "delete")
        print(f"\n[dry-run] would update baseline:")
        print(f"  upsert: {upserts}   delete: {deletes}")
        for kind, p in dry_run_actions[:50]:
            sym = "+" if kind == "upsert" else "-"
            print(f"    {sym} {p}")
        if len(dry_run_actions) > 50:
            print(f"    ... and {len(dry_run_actions) - 50} more")
        print("(no changes written — re-run without --dry-run to apply)")

    return 1 if result.has_drift else 0


def cmd_update(cfg: dict, accept: list[str], dry_run: bool = False) -> int:
    """Selectively update baseline entries for the given accept paths.

    `accept` is the combined list of arguments from --accept, --accept-from,
    and (if --accept-all was passed) the sentinel "*". An empty list is an
    error — operators must opt in explicitly. Silently accepting all changes
    would erase the forensic record of what changed.
    """
    if not accept:
        print("[!] `update` requires --accept PATH, --accept-from FILE, "
              "or --accept-all", file=sys.stderr)
        print("    cairn does not silently accept all changes — that would",
              file=sys.stderr)
        print("    erase the forensic record of what changed.", file=sys.stderr)
        return 2
    return cmd_scan(cfg, update_accept=set(accept), dry_run=dry_run)


def cmd_verify(cfg: dict) -> int:
    return cmd_scan(cfg, quiet=True)


def cmd_baseline_info(cfg: dict, json_out: bool = False) -> int:
    """Print provenance metadata for the baseline DB itself. Useful for
    chain-of-custody — answers 'when was this baseline taken, by whom,
    on what host, and is the DB file itself unmodified since?'"""
    db_path = cfg["db_path"]
    if not os.path.exists(db_path):
        print(f"[!] no baseline at {db_path}", file=sys.stderr)
        return 2

    # Hash the DB file before opening it (opening creates a journal file
    # which would change mtime even on a read-only operation).
    db_size = os.path.getsize(db_path)
    db_sha256 = hash_file(db_path, "sha256")
    db_mtime = os.path.getmtime(db_path)

    conn = open_db(db_path)
    try:
        meta = {row[0]: row[1] for row in conn.execute("SELECT key, value FROM meta")}
        # Counts and content-storage stats
        cur = conn.execute("SELECT COUNT(*) FROM files")
        file_count = cur.fetchone()[0]
        cur = conn.execute("SELECT COUNT(*) FROM files WHERE content_gz IS NOT NULL")
        content_count = cur.fetchone()[0]
        cur = conn.execute(
            "SELECT COALESCE(SUM(LENGTH(content_gz)), 0) FROM files WHERE content_gz IS NOT NULL"
        )
        content_bytes = cur.fetchone()[0]
        # Sample of paths covered (first few unique top-level dirs)
        cur = conn.execute("SELECT path FROM files WHERE is_dir = 1 ORDER BY path LIMIT 20")
        sample_dirs = [r[0] for r in cur]
    finally:
        conn.close()

    info = {
        "db_path":             db_path,
        "db_size_bytes":       db_size,
        "db_sha256":           db_sha256,
        "db_mtime":            datetime.fromtimestamp(db_mtime, tz=timezone.utc).isoformat(),
        "baseline_created_at": meta.get("created_at", "unknown"),
        "baseline_host":       meta.get("host",       "unknown"),
        "baseline_os":         meta.get("os",         "unknown"),
        "last_update":         meta.get("last_update", "(never updated)"),
        "tracked_entries":     file_count,
        "with_stored_content": content_count,
        "stored_content_bytes": content_bytes,
        "sample_directories":  sample_dirs,
    }

    if json_out:
        print(json.dumps(info, indent=2, default=str))
        return 0

    print()
    print("=" * 78)
    print("  Cairn Baseline Provenance")
    print("=" * 78)
    print(f"DB path:              {info['db_path']}")
    print(f"DB size:              {info['db_size_bytes']:,} bytes")
    print(f"DB SHA-256:           {info['db_sha256']}")
    print(f"DB last modified:     {info['db_mtime']}")
    print()
    print(f"Baseline created at:  {info['baseline_created_at']}")
    print(f"Baseline source host: {info['baseline_host']}")
    print(f"Baseline source OS:   {info['baseline_os']}")
    print(f"Last update:          {info['last_update']}")
    print()
    print(f"Tracked entries:      {info['tracked_entries']:,}")
    print(f"With stored content:  {info['with_stored_content']:,} "
          f"({info['stored_content_bytes']:,} bytes gzipped)")
    if info["sample_directories"]:
        print()
        print("Top-level directories monitored (sample):")
        for d in info["sample_directories"][:10]:
            print(f"  {d}")
        if len(info["sample_directories"]) > 10:
            print(f"  ... and more")
    print()
    print("To verify integrity later, recompute SHA-256 of the DB and compare:")
    print(f"  sha256sum {info['db_path']}")
    print()
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Cross-platform File Integrity Monitor")
    p.add_argument("command", choices=["init", "scan", "update", "verify"],
                   help="init: build baseline. scan: report drift. update: accept changes. verify: silent scan with exit code.")
    p.add_argument("--config", "-c", help="Path to cairn config (.yaml or .json)")
    p.add_argument("--json", action="store_true", help="Emit scan output as JSON")
    p.add_argument("--force", action="store_true", help="Overwrite existing baseline on init")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    if not cfg.get("paths"):
        print("[!] config has no `paths` configured. Edit your config and try again.", file=sys.stderr)
        return 2

    if args.command == "init":
        return cmd_init(cfg, force=args.force)
    if args.command == "scan":
        return cmd_scan(cfg, json_out=args.json)
    if args.command == "update":
        return cmd_update(cfg)
    if args.command == "verify":
        return cmd_verify(cfg)
    return 2
