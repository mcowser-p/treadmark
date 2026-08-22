"""treadmark.gcpmon — GCP account-configuration integrity monitor. SCAFFOLD.

⚠ UNTESTED SCAFFOLD — structured after awsmon but NOT yet exercised against a
real GCP project/org. Deliberately unwired (no CLI subcommand, no active
pyproject extra, no tests run it) until validated. Import-safe without the
Google SDK.

GCP is the cleanest fit of the three clouds: Cloud Asset Inventory
(`asset.list_assets`) returns ALL resources AND their IAM policies in one API,
scoped to a project / folder / organization — no per-service pagination. Two
content types cover the security baseline: RESOURCE (the config) and
IAM_POLICY (who can do what).

Model (mirrors AwsRecord): the CAI asset name is the identity; the "scope" is
the project (the region analog).

Auth: Application Default Credentials (`gcloud auth application-default login`,
a service-account key, or workload identity). Read-only CAI reads only.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sqlite3
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Iterator, Optional

from .awsmon import DEFAULT_VOLATILE_FIELDS, canonicalize  # generic, SDK-free

try:  # optional dependency — see the (commented) `gcp` extra in pyproject
    from google.cloud import asset_v1  # type: ignore
    HAVE_GOOGLE = True
except ImportError:
    HAVE_GOOGLE = False


GCP_VOLATILE_FIELDS = DEFAULT_VOLATILE_FIELDS | frozenset({
    "updateTime", "createTime", "etag", "fingerprint", "generation",
})

# The security-relevant asset types (the "core /etc of GCP"). CAI can return
# everything; we filter to the resources whose config is a posture signal.
CORE_ASSET_TYPES = [
    "compute.googleapis.com/Firewall",
    "compute.googleapis.com/Network",
    "storage.googleapis.com/Bucket",
    "iam.googleapis.com/ServiceAccount",
    "iam.googleapis.com/ServiceAccountKey",
    "cloudkms.googleapis.com/CryptoKey",
    "cloudresourcemanager.googleapis.com/Project",
]


@dataclass
class GcpRecord:
    asset_name: str      # //compute.googleapis.com/projects/.../firewalls/...
    project: str         # the scope (region analog)
    asset_type: str      # compute.googleapis.com/Firewall
    content: str         # "resource" | "iam_policy"
    config_json: str
    config_hash: str
    error: Optional[str] = None


def _volatile(cfg: dict) -> frozenset:
    return GCP_VOLATILE_FIELDS | frozenset(cfg.get("gcp_volatile_fields", []))


def make_record(asset_name: str, project: str, asset_type: str, content: str,
                config, cfg: dict, error: Optional[str] = None) -> GcpRecord:
    cj = canonicalize(config, _volatile(cfg))
    return GcpRecord(
        asset_name=asset_name, project=project, asset_type=asset_type,
        content=content, config_json=cj,
        config_hash=hashlib.sha256(cj.encode("utf-8")).hexdigest(),
        error=error,
    )


# ---------------------------------------------------------------------------
# Enumeration. `list_assets(scope, content_type, asset_types)` is injected so
# tests feed canned assets without the SDK. Each asset carries .name,
# .asset_type, and either .resource.data (dict) or .iam_policy.
# ---------------------------------------------------------------------------

ListAssetsFn = Callable[[str, str, list], Iterator[object]]


def _project_of(cfg: dict, asset) -> str:
    # CAI asset names embed the project; fall back to the configured scope.
    name = getattr(asset, "name", "") or ""
    parts = name.split("/")
    if "projects" in parts:
        i = parts.index("projects")
        if i + 1 < len(parts):
            return parts[i + 1]
    return cfg.get("gcp_scope", "")


def collect_resources(list_assets: ListAssetsFn, cfg: dict
                      ) -> Iterator[GcpRecord]:
    scope = cfg["gcp_scope"]                 # projects/X | folders/Y | organizations/Z
    types = cfg.get("gcp_asset_types") or CORE_ASSET_TYPES
    for asset in list_assets(scope, "RESOURCE", types):
        data = getattr(getattr(asset, "resource", None), "data", None) or {}
        yield make_record(getattr(asset, "name", ""), _project_of(cfg, asset),
                          getattr(asset, "asset_type", ""), "resource",
                          _as_dict(data), cfg)


def collect_iam(list_assets: ListAssetsFn, cfg: dict) -> Iterator[GcpRecord]:
    scope = cfg["gcp_scope"]
    types = cfg.get("gcp_asset_types") or CORE_ASSET_TYPES
    for asset in list_assets(scope, "IAM_POLICY", types):
        policy = getattr(asset, "iam_policy", None)
        yield make_record(getattr(asset, "name", "") + "#iam",
                          _project_of(cfg, asset),
                          getattr(asset, "asset_type", ""), "iam_policy",
                          _as_dict(policy) if policy else {}, cfg)


def _as_dict(obj):
    """Best-effort dict from a proto/Struct/dict for canonicalization."""
    if isinstance(obj, dict) or obj is None:
        return obj or {}
    for attr in ("to_dict",):
        fn = getattr(obj, attr, None)
        if callable(fn):
            try:
                return fn()
            except Exception:
                pass
    try:
        return json.loads(json.dumps(obj, default=lambda o: getattr(
            o, "__dict__", str(o))))
    except Exception:
        return {"_repr": str(obj)}


DRIVERS = {"resources": collect_resources, "iam": collect_iam}


def default_list_assets_fn(cfg: dict) -> ListAssetsFn:
    client = asset_v1.AssetServiceClient()

    def list_assets(scope: str, content_type: str, asset_types: list):
        ct = asset_v1.ContentType[content_type]
        return client.list_assets(request={
            "parent": scope, "content_type": ct, "asset_types": asset_types})
    return list_assets


def _enum_all(cfg: dict, list_assets: ListAssetsFn) -> Iterator[GcpRecord]:
    services = cfg.get("gcp_services") or sorted(DRIVERS)
    for svc in services:
        drv = DRIVERS.get(svc)
        if drv is None:
            print(f"[!] unknown gcp collector '{svc}' — known: "
                  f"{', '.join(sorted(DRIVERS))}", file=sys.stderr)
            continue
        try:
            yield from drv(list_assets, cfg)
        except Exception as e:
            yield GcpRecord(asset_name=f"error:{svc}", project="",
                            asset_type=f"{svc}:error", content="error",
                            config_json="{}", config_hash="",
                            error=f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Storage + diff + commands (identical shape to awsmon; 0/1/2 contract)
# ---------------------------------------------------------------------------

GCP_SCHEMA = """
CREATE TABLE IF NOT EXISTS gcp_resources (
    asset_name  TEXT PRIMARY KEY,
    project     TEXT,
    asset_type  TEXT,
    content     TEXT,
    config_json TEXT,
    config_hash TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_gcp_type ON gcp_resources(asset_type);
"""


def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(GCP_SCHEMA)
    return conn


def save_record(conn: sqlite3.Connection, r: GcpRecord) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO gcp_resources
           (asset_name, project, asset_type, content,
            config_json, config_hash, error)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (r.asset_name, r.project, r.asset_type, r.content,
         r.config_json, r.config_hash, r.error),
    )


def load_baseline(conn: sqlite3.Connection) -> dict:
    conn.row_factory = sqlite3.Row
    out: dict = {}
    for row in conn.execute("SELECT * FROM gcp_resources"):
        rec = GcpRecord(
            asset_name=row["asset_name"], project=row["project"],
            asset_type=row["asset_type"], content=row["content"],
            config_json=row["config_json"], config_hash=row["config_hash"],
            error=row["error"],
        )
        out[rec.asset_name] = rec
    return out


def changed_keys(old: GcpRecord, new: GcpRecord) -> list:
    try:
        a, b = json.loads(old.config_json), json.loads(new.config_json)
    except (ValueError, TypeError):
        return ["<unparseable>"]
    if not isinstance(a, dict) or not isinstance(b, dict):
        return ["<config>"]
    return [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]


def _require_sdk(quiet: bool = False) -> bool:
    if HAVE_GOOGLE:
        return True
    if not quiet:
        print('[!] google-cloud-asset not installed; run:  '
              'pip install "treadmark[gcp]"', file=sys.stderr)
    return False


def cmd_init(cfg: dict, list_assets: Optional[ListAssetsFn] = None) -> int:
    if list_assets is None:
        if not _require_sdk():
            return 2
        list_assets = default_list_assets_fn(cfg)
    conn = open_db(cfg["db_path"])
    n, errs = 0, 0
    print(f"[*] building gcp baseline → {cfg['db_path']}")
    with conn:
        conn.execute("DELETE FROM gcp_resources")
        for rec in _enum_all(cfg, list_assets):
            save_record(conn, rec)
            n += 1
            if rec.error:
                errs += 1
                print(f"    [!] {rec.asset_name}: {rec.error}", file=sys.stderr)
    conn.close()
    print(f"[+] gcp baseline done: {n} assets"
          f"{f' ({errs} errors)' if errs else ''}")
    return 0


def cmd_scan(cfg: dict, json_out: bool = False, update: bool = False,
             quiet: bool = False,
             list_assets: Optional[ListAssetsFn] = None) -> int:
    if list_assets is None:
        if not _require_sdk(quiet):
            return 2
        list_assets = default_list_assets_fn(cfg)
    conn = open_db(cfg["db_path"])
    baseline = load_baseline(conn)
    seen: set = set()
    added, modified = [], []
    for rec in _enum_all(cfg, list_assets):
        seen.add(rec.asset_name)
        old = baseline.get(rec.asset_name)
        if old is None:
            added.append(rec)
            if update:
                with conn:
                    save_record(conn, rec)
        elif old.config_hash != rec.config_hash:
            modified.append((old, rec))
            if update:
                with conn:
                    save_record(conn, rec)
    deleted_names = sorted(set(baseline) - seen)
    deleted = [baseline[i] for i in deleted_names]
    if update and deleted_names:
        with conn:
            conn.executemany("DELETE FROM gcp_resources WHERE asset_name = ?",
                             [(i,) for i in deleted_names])
    conn.close()

    if json_out:
        print(json.dumps({
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "host": platform.node(),
            "added": [asdict(r) for r in added],
            "deleted": [asdict(r) for r in deleted],
            "modified": [{"old": asdict(o), "new": asdict(n),
                          "changed_keys": changed_keys(o, n)}
                         for o, n in modified],
        }, indent=2, default=str))
    elif not quiet:
        print(f"\n=== GCP scan @ {datetime.now().isoformat(timespec='seconds')} ===")
        print(f"added: {len(added)}   modified: {len(modified)}   "
              f"deleted: {len(deleted)}")
        if not (added or modified or deleted):
            print("No GCP configuration drift detected. ✓")
    return 1 if (added or modified or deleted) else 0
