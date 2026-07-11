"""cairn.awsmon — AWS account-configuration integrity monitor.

The third cairn subsystem, modeled on winreg_mon: a point-in-time baseline of
security-relevant account configuration, an offline diff on rescan, and the
0/1/2 exit-code contract. Where the registry monitor walks hives, this walks
read-only AWS APIs (Describe*/List*/Get* only) across the account's regions.

Design notes:
- boto3 is an OPTIONAL dependency (`pip install "cairn[aws]"`), mirroring the
  pywin32 pattern — the core package keeps zero hard runtime deps. Without it
  every command explains and exits 2.
- Each resource's configuration is stored as a CANONICAL serialization:
  sorted keys, volatile fields stripped (last-used timestamps, delivery
  times, ResponseMetadata). Volatile churn must never read as drift — the
  same lesson the Windows footprint learned with NOISE_SERVICES.
- Service drivers are pure functions taking a client object, so tests inject
  fakes and never touch the network. The shipped driver set is the curated
  "/etc of AWS" (iam, s3, ec2 network, cloudtrail, kms, lambda); config keys
  `aws_services` / `aws_regions` narrow the scope, and broader coverage means
  adding drivers to DRIVERS — not a new mechanism.
- Records live in an `aws_resources` table in the SAME baseline DB as files
  and registry records (one artifact per host/account pairing works fine;
  most users will point `db_path` at a dedicated aws baseline).
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

try:
    import boto3  # type: ignore
    HAVE_BOTO3 = True
except ImportError:
    HAVE_BOTO3 = False


# ---------------------------------------------------------------------------
# Record + canonical serialization
# ---------------------------------------------------------------------------

@dataclass
class AwsRecord:
    arn: str             # canonical identity (synthetic where AWS has no ARN)
    region: str          # "global" for account-level services (IAM, S3 list)
    service: str         # iam | s3 | ec2 | cloudtrail | kms | lambda
    resource_type: str   # e.g. iam:user, ec2:security-group
    config_json: str     # canonical serialization of the resource config
    config_hash: str     # sha256 of config_json — fast equality check
    error: Optional[str] = None


# Fields that change on their own between two scans of an UNCHANGED account.
# Stripped (at any nesting depth) before serialization so they never read as
# drift. Config key `aws_volatile_fields` extends this list.
DEFAULT_VOLATILE_FIELDS = frozenset({
    "ResponseMetadata",
    # IAM last-activity churn
    "PasswordLastUsed", "LastUsedDate", "LastAccessedDate",
    # CloudTrail delivery/notification heartbeats
    "LatestDeliveryTime", "LatestDeliveryAttemptTime",
    "LatestNotificationTime", "LatestNotificationAttemptTime",
    "LatestDigestDeliveryTime", "LatestDeliveryAttemptSucceeded",
    "LatestNotificationAttemptSucceeded",
    "StartLoggingTime", "StopLoggingTime",
    "TimeLoggingStarted", "TimeLoggingStopped",
})


def _strip_volatile(obj, volatile: frozenset):
    if isinstance(obj, dict):
        return {k: _strip_volatile(v, volatile)
                for k, v in obj.items() if k not in volatile}
    if isinstance(obj, list):
        return [_strip_volatile(v, volatile) for v in obj]
    return obj


def canonicalize(obj, volatile: Optional[frozenset] = None) -> str:
    """Stable serialization of a boto3 response fragment: volatile fields
    stripped at any depth, keys sorted, datetimes stringified. Two scans of an
    unchanged resource must produce byte-identical output."""
    cleaned = _strip_volatile(obj, volatile or DEFAULT_VOLATILE_FIELDS)
    return json.dumps(cleaned, sort_keys=True, default=str)


def volatile_set(cfg: dict) -> frozenset:
    extra = cfg.get("aws_volatile_fields", [])
    return DEFAULT_VOLATILE_FIELDS | frozenset(extra)


def make_record(service: str, resource_type: str, arn: str, region: str,
                config, cfg: dict, error: Optional[str] = None) -> AwsRecord:
    cj = canonicalize(config, volatile_set(cfg))
    return AwsRecord(
        arn=arn, region=region, service=service, resource_type=resource_type,
        config_json=cj,
        config_hash=hashlib.sha256(cj.encode("utf-8")).hexdigest(),
        error=error,
    )


# ---------------------------------------------------------------------------
# API helpers — driver-side plumbing that also works with fake test clients
# ---------------------------------------------------------------------------

def _pages(client, op: str, result_key: str, **kwargs) -> Iterator[dict]:
    """Yield items across pages. Real boto3 clients paginate; a fake test
    client just implements the operation method returning one page."""
    get_paginator = getattr(client, "get_paginator", None)
    if get_paginator is not None:
        try:
            for page in get_paginator(op).paginate(**kwargs):
                for item in page.get(result_key, []):
                    yield item
            return
        except Exception:
            # operation may not be paginatable on this client — fall through
            pass
    resp = getattr(client, op)(**kwargs)
    for item in resp.get(result_key, []):
        yield item


def _try(fn, *args, absent=None, **kwargs):
    """Call an API that legitimately 404s (no bucket policy, no PAB, ...).
    Returns `absent` for any client error — the ABSENCE is itself config."""
    try:
        return fn(*args, **kwargs)
    except Exception:
        return absent


# ---------------------------------------------------------------------------
# Service drivers. Each takes the relevant client(s) and yields AwsRecords.
# Read-only calls only. A failure inside one resource yields an error record;
# a failure of the whole driver is caught by the caller.
# ---------------------------------------------------------------------------

def collect_iam(client, region: str, cfg: dict) -> Iterator[AwsRecord]:
    # Users: identity + MFA + access-key METADATA (never secrets; last-used
    # dates are volatile-stripped).
    for u in _pages(client, "list_users", "Users"):
        cfg_obj = dict(u)
        cfg_obj["MFADevices"] = _try(
            lambda: [d["SerialNumber"] for d in
                     client.list_mfa_devices(UserName=u["UserName"])["MFADevices"]],
            absent=[])
        cfg_obj["AccessKeys"] = _try(
            lambda: [{"AccessKeyId": k["AccessKeyId"], "Status": k["Status"]}
                     for k in client.list_access_keys(
                         UserName=u["UserName"])["AccessKeyMetadata"]],
            absent=[])
        yield make_record("iam", "iam:user", u["Arn"], "global", cfg_obj, cfg)

    # Roles: the trust policy is the security document.
    for r in _pages(client, "list_roles", "Roles"):
        yield make_record("iam", "iam:role", r["Arn"], "global", dict(r), cfg)

    # Customer-managed policies with their default version document.
    for p in _pages(client, "list_policies", "Policies", Scope="Local"):
        obj = dict(p)
        doc = _try(lambda: client.get_policy_version(
            PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"]
        )["PolicyVersion"]["Document"])
        obj["Document"] = doc
        yield make_record("iam", "iam:policy", p["Arn"], "global", obj, cfg)

    # Account password policy — absence is a finding-worthy config too.
    pol = _try(lambda: client.get_account_password_policy()["PasswordPolicy"],
               absent={"PasswordPolicy": "NOT SET"})
    yield make_record("iam", "iam:account-password-policy",
                      "arn:aws:iam:::account-password-policy", "global",
                      pol, cfg)


def collect_s3(client, region: str, cfg: dict) -> Iterator[AwsRecord]:
    for b in _pages(client, "list_buckets", "Buckets"):
        name = b["Name"]
        arn = f"arn:aws:s3:::{name}"
        obj = {
            "Name": name,
            "Policy": _try(lambda: json.loads(
                client.get_bucket_policy(Bucket=name)["Policy"])),
            "PublicAccessBlock": _try(lambda: client.get_public_access_block(
                Bucket=name)["PublicAccessBlockConfiguration"]),
            "Acl": _try(lambda: client.get_bucket_acl(Bucket=name)["Grants"]),
            "Encryption": _try(lambda: client.get_bucket_encryption(
                Bucket=name)["ServerSideEncryptionConfiguration"]),
        }
        yield make_record("s3", "s3:bucket", arn, "global", obj, cfg)


def collect_ec2(client, region: str, cfg: dict) -> Iterator[AwsRecord]:
    for sg in _pages(client, "describe_security_groups", "SecurityGroups"):
        arn = (f"arn:aws:ec2:{region}:{sg.get('OwnerId', '')}:"
               f"security-group/{sg['GroupId']}")
        yield make_record("ec2", "ec2:security-group", arn, region,
                          dict(sg), cfg)
    for acl in _pages(client, "describe_network_acls", "NetworkAcls"):
        arn = (f"arn:aws:ec2:{region}:{acl.get('OwnerId', '')}:"
               f"network-acl/{acl['NetworkAclId']}")
        yield make_record("ec2", "ec2:network-acl", arn, region,
                          dict(acl), cfg)
    for vpc in _pages(client, "describe_vpcs", "Vpcs"):
        arn = (f"arn:aws:ec2:{region}:{vpc.get('OwnerId', '')}:"
               f"vpc/{vpc['VpcId']}")
        yield make_record("ec2", "ec2:vpc", arn, region, dict(vpc), cfg)


def collect_cloudtrail(client, region: str, cfg: dict) -> Iterator[AwsRecord]:
    resp = client.describe_trails(includeShadowTrails=False)
    for t in resp.get("trailList", []):
        arn = t.get("TrailARN", f"arn:aws:cloudtrail:{region}::trail/{t['Name']}")
        obj = dict(t)
        # IsLogging is tamper signal #1 — an attacker's first move is often
        # StopLogging. The volatile list strips the delivery heartbeats.
        status = _try(lambda: client.get_trail_status(Name=arn))
        if status:
            obj["IsLogging"] = status.get("IsLogging")
        yield make_record("cloudtrail", "cloudtrail:trail", arn, region,
                          obj, cfg)


def collect_kms(client, region: str, cfg: dict) -> Iterator[AwsRecord]:
    for k in _pages(client, "list_keys", "Keys"):
        arn = k["KeyArn"]
        meta = _try(lambda: client.describe_key(KeyId=k["KeyId"])["KeyMetadata"])
        if meta is None:
            yield make_record("kms", "kms:key", arn, region, {}, cfg,
                              error="describe_key failed")
            continue
        if meta.get("KeyManager") == "AWS":
            continue  # AWS-managed keys churn on Amazon's schedule, not yours
        obj = dict(meta)
        obj["RotationEnabled"] = _try(lambda: client.get_key_rotation_status(
            KeyId=k["KeyId"])["KeyRotationEnabled"])
        obj["KeyPolicy"] = _try(lambda: json.loads(client.get_key_policy(
            KeyId=k["KeyId"], PolicyName="default")["Policy"]))
        yield make_record("kms", "kms:key", arn, region, obj, cfg)


def collect_lambda(client, region: str, cfg: dict) -> Iterator[AwsRecord]:
    for fn in _pages(client, "list_functions", "Functions"):
        arn = fn["FunctionArn"]
        obj = dict(fn)
        # Env var NAMES are config; env var VALUES are potentially secrets.
        env = obj.get("Environment", {})
        if isinstance(env, dict) and "Variables" in env:
            obj["Environment"] = {"VariableNames":
                                  sorted(env["Variables"].keys())}
        obj["ResourcePolicy"] = _try(lambda: json.loads(
            client.get_policy(FunctionName=fn["FunctionName"])["Policy"]))
        yield make_record("lambda", "lambda:function", arn, region, obj, cfg)


# region=None marks account-global drivers (scanned once, not per region).
DRIVERS: dict[str, dict] = {
    "iam":        {"client": "iam",        "global": True,  "fn": collect_iam},
    "s3":         {"client": "s3",         "global": True,  "fn": collect_s3},
    "ec2":        {"client": "ec2",        "global": False, "fn": collect_ec2},
    "cloudtrail": {"client": "cloudtrail", "global": False, "fn": collect_cloudtrail},
    "kms":        {"client": "kms",        "global": False, "fn": collect_kms},
    "lambda":     {"client": "lambda",     "global": False, "fn": collect_lambda},
}


# ---------------------------------------------------------------------------
# Enumeration across services × regions
# ---------------------------------------------------------------------------

# client_factory(service, region) -> client. Tests inject fakes; the default
# builds boto3 clients from the configured profile.
ClientFactory = Callable[[str, Optional[str]], object]


def default_client_factory(cfg: dict) -> ClientFactory:
    session = boto3.Session(profile_name=cfg.get("aws_profile"))

    def factory(service: str, region: Optional[str]):
        return session.client(service, region_name=region)
    return factory


def enabled_regions(cfg: dict, factory: ClientFactory) -> list[str]:
    if cfg.get("aws_regions"):
        return list(cfg["aws_regions"])
    ec2 = factory("ec2", None)
    resp = ec2.describe_regions(AllRegions=False)
    return sorted(r["RegionName"] for r in resp["Regions"])


def _enum_all(cfg: dict, factory: ClientFactory) -> Iterator[AwsRecord]:
    services = cfg.get("aws_services") or sorted(DRIVERS)
    regions: Optional[list[str]] = None

    for svc in services:
        drv = DRIVERS.get(svc)
        if drv is None:
            print(f"[!] unknown aws service '{svc}' — known: "
                  f"{', '.join(sorted(DRIVERS))}", file=sys.stderr)
            continue
        if drv["global"]:
            svc_regions = ["global"]
        else:
            if regions is None:
                regions = enabled_regions(cfg, factory)
            svc_regions = regions
        for region in svc_regions:
            try:
                client = factory(drv["client"],
                                 None if region == "global" else region)
                yield from drv["fn"](client, region, cfg)
            except Exception as e:
                # A whole-driver failure (auth, endpoint, throttle) becomes
                # one error record — partial scans stay useful, never crash.
                yield AwsRecord(arn=f"error:{svc}:{region}", region=region,
                                service=svc, resource_type=f"{svc}:error",
                                config_json="{}", config_hash="",
                                error=f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Storage — aws_resources table in the shared baseline DB
# ---------------------------------------------------------------------------

AWS_SCHEMA = """
CREATE TABLE IF NOT EXISTS aws_resources (
    arn           TEXT PRIMARY KEY,
    region        TEXT,
    service       TEXT,
    resource_type TEXT,
    config_json   TEXT,
    config_hash   TEXT,
    error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_aws_service ON aws_resources(service);
"""


def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(AWS_SCHEMA)
    return conn


def save_record(conn: sqlite3.Connection, r: AwsRecord) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO aws_resources
           (arn, region, service, resource_type, config_json, config_hash, error)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (r.arn, r.region, r.service, r.resource_type,
         r.config_json, r.config_hash, r.error),
    )


def load_baseline(conn: sqlite3.Connection) -> dict[str, AwsRecord]:
    conn.row_factory = sqlite3.Row
    out: dict[str, AwsRecord] = {}
    for row in conn.execute("SELECT * FROM aws_resources"):
        rec = AwsRecord(
            arn=row["arn"], region=row["region"], service=row["service"],
            resource_type=row["resource_type"],
            config_json=row["config_json"], config_hash=row["config_hash"],
            error=row["error"],
        )
        out[rec.arn] = rec
    return out


def changed_keys(old: AwsRecord, new: AwsRecord) -> list[str]:
    """Top-level config keys that differ — the registry value_repr analog,
    specific enough for a report line to be actionable."""
    try:
        a, b = json.loads(old.config_json), json.loads(new.config_json)
    except (ValueError, TypeError):
        return ["<unparseable>"]
    if not isinstance(a, dict) or not isinstance(b, dict):
        return ["<config>"]
    keys = sorted(set(a) | set(b))
    return [k for k in keys if a.get(k) != b.get(k)]


# ---------------------------------------------------------------------------
# Commands — same contract as the registry monitor (0 clean / 1 drift / 2 err)
# ---------------------------------------------------------------------------

def _require_boto3(quiet: bool = False) -> bool:
    if HAVE_BOTO3:
        return True
    if not quiet:
        print('[!] boto3 not installed; run:  pip install "cairn[aws]"',
              file=sys.stderr)
    return False


def cmd_init(cfg: dict, factory: Optional[ClientFactory] = None) -> int:
    if factory is None:
        if not _require_boto3():
            return 2
        factory = default_client_factory(cfg)
    conn = open_db(cfg["db_path"])
    n, errs = 0, 0
    print(f"[*] building aws baseline → {cfg['db_path']}")
    with conn:
        conn.execute("DELETE FROM aws_resources")
        for rec in _enum_all(cfg, factory):
            save_record(conn, rec)
            n += 1
            if rec.error:
                errs += 1
                print(f"    [!] {rec.arn}: {rec.error}", file=sys.stderr)
            if n % 500 == 0:
                print(f"    {n} resources...")
        # Provenance in the shared meta table (files.py owns the schema; the
        # table only exists if a files baseline shares this db — optional).
        if _has_meta(conn):
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("aws_scanned_at", datetime.now(timezone.utc).isoformat()))
    conn.close()
    suffix = f" ({errs} errors)" if errs else ""
    print(f"[+] aws baseline done: {n} resources{suffix}")
    return 0


def _has_meta(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
    ).fetchone()
    return row is not None


def cmd_scan(cfg: dict, json_out: bool = False, update: bool = False,
             quiet: bool = False, factory: Optional[ClientFactory] = None,
             report_path: Optional[str] = None,
             report_format: Optional[str] = None) -> int:
    if factory is None:
        if not _require_boto3(quiet):
            return 2
        factory = default_client_factory(cfg)
    conn = open_db(cfg["db_path"])
    baseline = load_baseline(conn)
    seen: set[str] = set()

    added: list[AwsRecord] = []
    modified: list[tuple[AwsRecord, AwsRecord]] = []

    for rec in _enum_all(cfg, factory):
        seen.add(rec.arn)
        old = baseline.get(rec.arn)
        if old is None:
            added.append(rec)
            if update:
                with conn:
                    save_record(conn, rec)
            continue
        if old.config_hash != rec.config_hash:
            modified.append((old, rec))
            if update:
                with conn:
                    save_record(conn, rec)

    deleted_arns = sorted(set(baseline.keys()) - seen)
    deleted = [baseline[a] for a in deleted_arns]
    if update and deleted_arns:
        with conn:
            conn.executemany("DELETE FROM aws_resources WHERE arn = ?",
                             [(a,) for a in deleted_arns])
    conn.close()

    if report_path or report_format:
        from . import report as report_mod
        result = report_mod.AwsScanResult(
            scanned_at=datetime.now(timezone.utc).isoformat(),
            host=platform.node(), db_path=cfg["db_path"],
            added=added, modified=modified, deleted=deleted,
        )
        report_mod.write_aws_report(result, report_path, report_format)

    if json_out:
        print(json.dumps({
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "host": platform.node(),
            "added":    [asdict(r) for r in added],
            "deleted":  [asdict(r) for r in deleted],
            "modified": [{"old": asdict(o), "new": asdict(n),
                          "changed_keys": changed_keys(o, n)}
                         for o, n in modified],
        }, indent=2, default=str))
    elif not quiet:
        print(f"\n=== AWS scan @ {datetime.now().isoformat(timespec='seconds')} ===")
        print(f"added: {len(added)}   modified: {len(modified)}   "
              f"deleted: {len(deleted)}")
        if added:
            print("\n[+] ADDED")
            for r in added:
                print(f"    + {r.resource_type}  {r.arn}")
        if modified:
            print("\n[~] MODIFIED")
            for old, new in modified:
                keys = ", ".join(changed_keys(old, new)) or "config"
                print(f"    ~ {new.resource_type}  {new.arn}")
                print(f"        changed: {keys}")
        if deleted:
            print("\n[-] DELETED")
            for r in deleted:
                print(f"    - {r.resource_type}  {r.arn}")
        if not (added or modified or deleted):
            print("\nNo AWS configuration drift detected. ✓")

    return 1 if (added or modified or deleted) else 0
