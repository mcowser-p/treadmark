"""treadmark.azmon — Azure account-configuration integrity monitor. SCAFFOLD.

⚠ UNTESTED SCAFFOLD — structured after awsmon but NOT yet exercised against a
real Azure tenant. Deliberately unwired (no CLI subcommand, no pyproject extra
active, no tests run it) until validated. Import-safe without the Azure SDK.

When validated, the shared diff/canonicalize/SARIF logic in awsmon should be
lifted into a `cloudbase.py` that awsmon/azmon/gcpmon all import — do that
refactor once TWO clouds are proven, not speculatively.

Model (mirrors AwsRecord): the Azure resource ID is the identity (the ARN
analog); the "scope" is the subscription (the region analog). Enumeration is
via Azure Resource Graph — one KQL query returns resources across
subscriptions, far cheaper than per-provider ARM listing.

Auth: azure.identity.DefaultAzureCredential (service principal env vars,
managed identity, or `az login`). Read-only Resource Graph queries only.
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

try:  # optional dependency — see the (commented) `azure` extra in pyproject
    from azure.identity import DefaultAzureCredential  # type: ignore
    from azure.mgmt.resourcegraph import ResourceGraphClient  # type: ignore
    HAVE_AZURE = True
except ImportError:
    HAVE_AZURE = False


# Azure adds its own churning fields on top of the shared timestamp set.
AZURE_VOLATILE_FIELDS = DEFAULT_VOLATILE_FIELDS | frozenset({
    "provisioningState", "lastModifiedTime", "creationTime", "etag",
    "resourceGuid",
})


@dataclass
class AzureRecord:
    resource_id: str     # /subscriptions/.../resourceGroups/.../providers/...
    subscription: str    # the scope (region analog)
    provider: str        # microsoft.network | microsoft.authorization | ...
    resource_type: str   # e.g. microsoft.network/networksecuritygroups
    config_json: str
    config_hash: str
    error: Optional[str] = None


def _volatile(cfg: dict) -> frozenset:
    return AZURE_VOLATILE_FIELDS | frozenset(cfg.get("azure_volatile_fields", []))


def make_record(provider: str, resource_type: str, resource_id: str,
                subscription: str, config, cfg: dict,
                error: Optional[str] = None) -> AzureRecord:
    cj = canonicalize(config, _volatile(cfg))
    return AzureRecord(
        resource_id=resource_id, subscription=subscription, provider=provider,
        resource_type=resource_type, config_json=cj,
        config_hash=hashlib.sha256(cj.encode("utf-8")).hexdigest(),
        error=error,
    )


# ---------------------------------------------------------------------------
# Drivers — each a Resource Graph KQL query + the type label it produces.
# `query(kql)` is injected so tests feed canned rows without the SDK.
# The security-relevant "core /etc of Azure": RBAC, network exposure,
# storage/keyvault posture, and the audit pipeline (activity/diagnostics).
# ---------------------------------------------------------------------------

QueryFn = Callable[[str], Iterator[dict]]   # kql -> rows (each: id/type/... + properties)

DRIVERS: dict[str, str] = {
    # service key            -> KQL (Resource Graph tables: resources, authorizationresources)
    "role-assignments":
        "authorizationresources "
        "| where type == 'microsoft.authorization/roleassignments'",
    "network-security-groups":
        "resources | where type == 'microsoft.network/networksecuritygroups'",
    "storage-accounts":
        "resources | where type == 'microsoft.storage/storageaccounts'",
    "key-vaults":
        "resources | where type == 'microsoft.keyvault/vaults'",
    "public-ips":
        "resources | where type == 'microsoft.network/publicipaddresses'",
    "sql-servers":
        "resources | where type == 'microsoft.sql/servers'",
}


def collect(query: QueryFn, service: str, kql: str, cfg: dict
            ) -> Iterator[AzureRecord]:
    for row in query(kql):
        rid = row.get("id", "")
        rtype = row.get("type", service)
        provider = rtype.split("/", 1)[0] if "/" in rtype else rtype
        sub = row.get("subscriptionId", "")
        yield make_record(provider, rtype, rid, sub, row, cfg)


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

def default_query_fn(cfg: dict) -> QueryFn:
    cred = DefaultAzureCredential()
    client = ResourceGraphClient(cred)
    subs = cfg.get("azure_subscriptions")  # None = all accessible

    def query(kql: str) -> Iterator[dict]:
        from azure.mgmt.resourcegraph.models import QueryRequest  # type: ignore
        skip_token = None
        while True:
            req = QueryRequest(subscriptions=subs, query=kql,
                               options={"$skipToken": skip_token}
                               if skip_token else None)
            resp = client.resources(req)
            for row in resp.data:
                yield row
            skip_token = getattr(resp, "skip_token", None)
            if not skip_token:
                break
    return query


def _enum_all(cfg: dict, query: QueryFn) -> Iterator[AzureRecord]:
    services = cfg.get("azure_services") or sorted(DRIVERS)
    for svc in services:
        kql = DRIVERS.get(svc)
        if kql is None:
            print(f"[!] unknown azure service '{svc}' — known: "
                  f"{', '.join(sorted(DRIVERS))}", file=sys.stderr)
            continue
        try:
            yield from collect(query, svc, kql, cfg)
        except Exception as e:
            yield AzureRecord(resource_id=f"error:{svc}", subscription="",
                              provider=svc, resource_type=f"{svc}:error",
                              config_json="{}", config_hash="",
                              error=f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Storage + diff + commands (identical shape to awsmon; 0/1/2 contract)
# ---------------------------------------------------------------------------

AZURE_SCHEMA = """
CREATE TABLE IF NOT EXISTS azure_resources (
    resource_id   TEXT PRIMARY KEY,
    subscription  TEXT,
    provider      TEXT,
    resource_type TEXT,
    config_json   TEXT,
    config_hash   TEXT,
    error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_az_provider ON azure_resources(provider);
"""


def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(AZURE_SCHEMA)
    return conn


def save_record(conn: sqlite3.Connection, r: AzureRecord) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO azure_resources
           (resource_id, subscription, provider, resource_type,
            config_json, config_hash, error)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (r.resource_id, r.subscription, r.provider, r.resource_type,
         r.config_json, r.config_hash, r.error),
    )


def load_baseline(conn: sqlite3.Connection) -> dict:
    conn.row_factory = sqlite3.Row
    out: dict = {}
    for row in conn.execute("SELECT * FROM azure_resources"):
        rec = AzureRecord(
            resource_id=row["resource_id"], subscription=row["subscription"],
            provider=row["provider"], resource_type=row["resource_type"],
            config_json=row["config_json"], config_hash=row["config_hash"],
            error=row["error"],
        )
        out[rec.resource_id] = rec
    return out


def changed_keys(old: AzureRecord, new: AzureRecord) -> list:
    try:
        a, b = json.loads(old.config_json), json.loads(new.config_json)
    except (ValueError, TypeError):
        return ["<unparseable>"]
    if not isinstance(a, dict) or not isinstance(b, dict):
        return ["<config>"]
    return [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]


def _require_sdk(quiet: bool = False) -> bool:
    if HAVE_AZURE:
        return True
    if not quiet:
        print('[!] azure SDK not installed; run:  pip install "treadmark[azure]"',
              file=sys.stderr)
    return False


def cmd_init(cfg: dict, query: Optional[QueryFn] = None) -> int:
    if query is None:
        if not _require_sdk():
            return 2
        query = default_query_fn(cfg)
    conn = open_db(cfg["db_path"])
    n, errs = 0, 0
    print(f"[*] building azure baseline → {cfg['db_path']}")
    with conn:
        conn.execute("DELETE FROM azure_resources")
        for rec in _enum_all(cfg, query):
            save_record(conn, rec)
            n += 1
            if rec.error:
                errs += 1
                print(f"    [!] {rec.resource_id}: {rec.error}", file=sys.stderr)
    conn.close()
    print(f"[+] azure baseline done: {n} resources"
          f"{f' ({errs} errors)' if errs else ''}")
    return 0


def cmd_scan(cfg: dict, json_out: bool = False, update: bool = False,
             quiet: bool = False, query: Optional[QueryFn] = None) -> int:
    if query is None:
        if not _require_sdk(quiet):
            return 2
        query = default_query_fn(cfg)
    conn = open_db(cfg["db_path"])
    baseline = load_baseline(conn)
    seen: set = set()
    added, modified = [], []
    for rec in _enum_all(cfg, query):
        seen.add(rec.resource_id)
        old = baseline.get(rec.resource_id)
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
    deleted_ids = sorted(set(baseline) - seen)
    deleted = [baseline[i] for i in deleted_ids]
    if update and deleted_ids:
        with conn:
            conn.executemany("DELETE FROM azure_resources WHERE resource_id = ?",
                             [(i,) for i in deleted_ids])
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
        print(f"\n=== Azure scan @ {datetime.now().isoformat(timespec='seconds')} ===")
        print(f"added: {len(added)}   modified: {len(modified)}   "
              f"deleted: {len(deleted)}")
        if not (added or modified or deleted):
            print("No Azure configuration drift detected. ✓")
    return 1 if (added or modified or deleted) else 0
