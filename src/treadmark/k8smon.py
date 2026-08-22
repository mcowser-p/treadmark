"""treadmark.k8smon — Kubernetes cluster-configuration integrity monitor. SCAFFOLD.

⚠ UNTESTED SCAFFOLD — structured after awsmon/gcpmon but NOT yet exercised
against a real cluster. Deliberately unwired (no CLI subcommand, no active
pyproject extra, no tests run it) until validated. Import-safe without the
kubernetes client.

Kubernetes is the most natural FIM target of all: the API server is a
declarative config store, so a baseline-diff catches exactly the security
drift you care about — an edited RBAC binding, a loosened NetworkPolicy, a new
admission webhook, a ServiceAccount granted more than it needs.

Model (mirrors AwsRecord): identity is the NAME-based key `{kind}/{ns}/{name}`
(not metadata.uid — a redeployed object with the same name should read as
modified, not deleted+added); the "scope" is the namespace ("cluster" for
cluster-scoped kinds).

Auth: config.load_kube_config() (a kubeconfig) or load_incluster_config()
(in-cluster ServiceAccount). Read-only list calls only.

SECRETS DISCIPLINE: the Secret driver records METADATA ONLY — name, type, and
the sorted KEY NAMES of `data`. Secret VALUES are never read into a record.
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

try:  # optional dependency — see the (commented) `k8s` extra in pyproject
    from kubernetes import client, config  # type: ignore
    HAVE_K8S = True
except ImportError:
    HAVE_K8S = False


# Server-managed churn that must never read as config drift. This is the
# largest volatile surface of any subsystem — a k8s object is mostly fields
# the API server rewrites on its own.
K8S_VOLATILE_FIELDS = DEFAULT_VOLATILE_FIELDS | frozenset({
    "resourceVersion", "uid", "creationTimestamp", "generation",
    "managedFields", "selfLink", "status", "resource_version",
    "creation_timestamp", "managed_fields", "self_link",
    # the annotation kubectl rewrites on every apply
    "kubectl.kubernetes.io/last-applied-configuration",
})


@dataclass
class K8sRecord:
    uid: str             # identity: {kind}/{namespace}/{name}
    namespace: str       # scope; "cluster" for cluster-scoped kinds
    api_version: str
    kind: str
    config_json: str
    config_hash: str
    error: Optional[str] = None


def _volatile(cfg: dict) -> frozenset:
    return K8S_VOLATILE_FIELDS | frozenset(cfg.get("k8s_volatile_fields", []))


def _to_dict(obj):
    """Best-effort plain dict from a kubernetes client model or a dict."""
    if isinstance(obj, dict) or obj is None:
        return obj or {}
    fn = getattr(obj, "to_dict", None)
    if callable(fn):
        try:
            return fn()
        except Exception:
            pass
    return {"_repr": str(obj)}


def _meta(d: dict) -> dict:
    return d.get("metadata") or {}


def make_record(kind: str, obj, cfg: dict,
                error: Optional[str] = None) -> K8sRecord:
    d = _to_dict(obj)
    m = _meta(d)
    ns = m.get("namespace") or "cluster"
    name = m.get("name") or "?"
    cj = canonicalize(d, _volatile(cfg))
    return K8sRecord(
        uid=f"{kind}/{ns}/{name}", namespace=ns,
        api_version=d.get("apiVersion") or d.get("api_version") or "",
        kind=kind, config_json=cj,
        config_hash=hashlib.sha256(cj.encode("utf-8")).hexdigest(),
        error=error,
    )


# ---------------------------------------------------------------------------
# Drivers — each yields (kind, object) pairs from an injected `apis` bundle so
# tests feed canned objects without the SDK. The security "/etc of k8s".
# ---------------------------------------------------------------------------

class Apis:
    """Thin bundle of the typed API clients a driver needs. The default
    factory builds real ones; tests pass a stand-in with the same attrs."""
    def __init__(self, rbac=None, net=None, core=None, admission=None):
        self.rbac = rbac
        self.net = net
        self.core = core
        self.admission = admission


def _items(resp):
    items = getattr(resp, "items", None)
    if items is None and isinstance(resp, dict):
        items = resp.get("items", [])
    return items or []


def collect_rbac(apis: Apis, cfg: dict) -> Iterator[K8sRecord]:
    api = apis.rbac
    for obj in _items(api.list_role_for_all_namespaces()):
        yield make_record("Role", obj, cfg)
    for obj in _items(api.list_cluster_role()):
        yield make_record("ClusterRole", obj, cfg)
    for obj in _items(api.list_role_binding_for_all_namespaces()):
        yield make_record("RoleBinding", obj, cfg)
    for obj in _items(api.list_cluster_role_binding()):
        yield make_record("ClusterRoleBinding", obj, cfg)


def collect_network_policies(apis: Apis, cfg: dict) -> Iterator[K8sRecord]:
    for obj in _items(apis.net.list_network_policy_for_all_namespaces()):
        yield make_record("NetworkPolicy", obj, cfg)


def collect_service_accounts(apis: Apis, cfg: dict) -> Iterator[K8sRecord]:
    for obj in _items(apis.core.list_service_account_for_all_namespaces()):
        yield make_record("ServiceAccount", obj, cfg)


def collect_admission(apis: Apis, cfg: dict) -> Iterator[K8sRecord]:
    api = apis.admission
    for obj in _items(api.list_validating_webhook_configuration()):
        yield make_record("ValidatingWebhookConfiguration", obj, cfg)
    for obj in _items(api.list_mutating_webhook_configuration()):
        yield make_record("MutatingWebhookConfiguration", obj, cfg)


def collect_secrets_metadata(apis: Apis, cfg: dict) -> Iterator[K8sRecord]:
    # METADATA ONLY. Never read Secret values into a record — strip data /
    # stringData to their KEY NAMES before make_record.
    for obj in _items(apis.core.list_secret_for_all_namespaces()):
        d = dict(_to_dict(obj))   # copy: never mutate the caller's object
        data = d.get("data") or {}
        string_data = d.get("stringData") or d.get("string_data") or {}
        d["data"] = sorted(data.keys()) if isinstance(data, dict) else "<opaque>"
        d.pop("stringData", None)
        d.pop("string_data", None)
        if string_data:
            d["stringDataKeys"] = sorted(string_data.keys())
        yield make_record("Secret", d, cfg)


def collect_pod_security(apis: Apis, cfg: dict) -> Iterator[K8sRecord]:
    # Namespace pod-security-admission posture lives in the namespace labels.
    for obj in _items(apis.core.list_namespace()):
        yield make_record("Namespace", obj, cfg)


DRIVERS: dict[str, Callable[[Apis, dict], Iterator[K8sRecord]]] = {
    "rbac":              collect_rbac,
    "network-policies":  collect_network_policies,
    "service-accounts":  collect_service_accounts,
    "admission":         collect_admission,
    "secrets-metadata":  collect_secrets_metadata,
    "pod-security":      collect_pod_security,
}


def default_apis(cfg: dict) -> Apis:
    try:
        config.load_kube_config(context=cfg.get("k8s_context"))
    except Exception:
        config.load_incluster_config()
    return Apis(
        rbac=client.RbacAuthorizationV1Api(),
        net=client.NetworkingV1Api(),
        core=client.CoreV1Api(),
        admission=client.AdmissionregistrationV1Api(),
    )


def _enum_all(cfg: dict, apis: Apis) -> Iterator[K8sRecord]:
    services = cfg.get("k8s_collectors") or sorted(DRIVERS)
    for svc in services:
        drv = DRIVERS.get(svc)
        if drv is None:
            print(f"[!] unknown k8s collector '{svc}' — known: "
                  f"{', '.join(sorted(DRIVERS))}", file=sys.stderr)
            continue
        try:
            yield from drv(apis, cfg)
        except Exception as e:
            yield K8sRecord(uid=f"error/{svc}", namespace="cluster",
                            api_version="", kind=f"{svc}:error",
                            config_json="{}", config_hash="",
                            error=f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Storage + diff + commands (identical shape to awsmon; 0/1/2 contract)
# ---------------------------------------------------------------------------

K8S_SCHEMA = """
CREATE TABLE IF NOT EXISTS k8s_resources (
    uid         TEXT PRIMARY KEY,
    namespace   TEXT,
    api_version TEXT,
    kind        TEXT,
    config_json TEXT,
    config_hash TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_k8s_kind ON k8s_resources(kind);
"""


def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(K8S_SCHEMA)
    return conn


def save_record(conn: sqlite3.Connection, r: K8sRecord) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO k8s_resources
           (uid, namespace, api_version, kind, config_json, config_hash, error)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (r.uid, r.namespace, r.api_version, r.kind,
         r.config_json, r.config_hash, r.error),
    )


def load_baseline(conn: sqlite3.Connection) -> dict:
    conn.row_factory = sqlite3.Row
    out: dict = {}
    for row in conn.execute("SELECT * FROM k8s_resources"):
        rec = K8sRecord(
            uid=row["uid"], namespace=row["namespace"],
            api_version=row["api_version"], kind=row["kind"],
            config_json=row["config_json"], config_hash=row["config_hash"],
            error=row["error"],
        )
        out[rec.uid] = rec
    return out


def changed_keys(old: K8sRecord, new: K8sRecord) -> list:
    try:
        a, b = json.loads(old.config_json), json.loads(new.config_json)
    except (ValueError, TypeError):
        return ["<unparseable>"]
    if not isinstance(a, dict) or not isinstance(b, dict):
        return ["<config>"]
    return [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]


def _require_sdk(quiet: bool = False) -> bool:
    if HAVE_K8S:
        return True
    if not quiet:
        print('[!] kubernetes client not installed; run:  '
              'pip install "treadmark[k8s]"', file=sys.stderr)
    return False


def cmd_init(cfg: dict, apis: Optional[Apis] = None) -> int:
    if apis is None:
        if not _require_sdk():
            return 2
        apis = default_apis(cfg)
    conn = open_db(cfg["db_path"])
    n, errs = 0, 0
    print(f"[*] building k8s baseline → {cfg['db_path']}")
    with conn:
        conn.execute("DELETE FROM k8s_resources")
        for rec in _enum_all(cfg, apis):
            save_record(conn, rec)
            n += 1
            if rec.error:
                errs += 1
                print(f"    [!] {rec.uid}: {rec.error}", file=sys.stderr)
    conn.close()
    print(f"[+] k8s baseline done: {n} objects"
          f"{f' ({errs} errors)' if errs else ''}")
    return 0


def cmd_scan(cfg: dict, json_out: bool = False, update: bool = False,
             quiet: bool = False, apis: Optional[Apis] = None) -> int:
    if apis is None:
        if not _require_sdk(quiet):
            return 2
        apis = default_apis(cfg)
    conn = open_db(cfg["db_path"])
    baseline = load_baseline(conn)
    seen: set = set()
    added, modified = [], []
    for rec in _enum_all(cfg, apis):
        seen.add(rec.uid)
        old = baseline.get(rec.uid)
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
    deleted_uids = sorted(set(baseline) - seen)
    deleted = [baseline[i] for i in deleted_uids]
    if update and deleted_uids:
        with conn:
            conn.executemany("DELETE FROM k8s_resources WHERE uid = ?",
                             [(i,) for i in deleted_uids])
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
        print(f"\n=== k8s scan @ {datetime.now().isoformat(timespec='seconds')} ===")
        print(f"added: {len(added)}   modified: {len(modified)}   "
              f"deleted: {len(deleted)}")
        if not (added or modified or deleted):
            print("No Kubernetes configuration drift detected. ✓")
    return 1 if (added or modified or deleted) else 0
