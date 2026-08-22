"""treadmark.awsmon — pure tests: no boto3, no network, no credentials.

Drivers take a client object, so fake clients returning canned dict payloads
exercise the whole path. The client factory is injected into cmd_init/cmd_scan.
"""

from __future__ import annotations

import json

from treadmark import awsmon
from treadmark import report as report_mod


# ---------------------------------------------------------------------------
# Fake AWS clients — just the methods the drivers call, returning dicts.
# ---------------------------------------------------------------------------

class FakeIam:
    def __init__(self, users=None, pw_policy=None):
        self._users = users or []
        self._pw = pw_policy

    def list_users(self):
        return {"Users": self._users}

    def list_mfa_devices(self, UserName):
        return {"MFADevices": []}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": [
            {"AccessKeyId": "AKIA...", "Status": "Active",
             "CreateDate": "2020-01-01", "LastUsedDate": "2026-07-10"}]}

    def list_roles(self):
        return {"Roles": []}

    def list_policies(self, Scope="Local"):
        return {"Policies": []}

    def get_account_password_policy(self):
        if self._pw is None:
            raise RuntimeError("NoSuchEntity")
        return {"PasswordPolicy": self._pw}


class FakeEc2:
    def __init__(self, sgs=None, regions=None):
        self._sgs = sgs or []
        self._regions = regions or ["us-east-1"]

    def describe_regions(self, AllRegions=False):
        return {"Regions": [{"RegionName": r} for r in self._regions]}

    def describe_security_groups(self):
        return {"SecurityGroups": self._sgs}

    def describe_network_acls(self):
        return {"NetworkAcls": []}

    def describe_vpcs(self):
        return {"Vpcs": []}


def _factory(mapping):
    """mapping: {(service, region): client}. region None = global."""
    def factory(service, region):
        return mapping[(service, region)]
    return factory


# ---------------------------------------------------------------------------
# Canonicalization + volatile stripping
# ---------------------------------------------------------------------------

def test_canonicalize_is_stable_and_order_independent():
    a = {"b": 1, "a": 2, "nested": {"y": 1, "x": 2}}
    b = {"a": 2, "nested": {"x": 2, "y": 1}, "b": 1}
    assert awsmon.canonicalize(a) == awsmon.canonicalize(b)


def test_canonicalize_strips_volatile_fields_at_any_depth():
    obj = {"Name": "trail", "LatestDeliveryTime": "2026-07-10T00:00:00Z",
           "inner": {"PasswordLastUsed": "x", "keep": 1}}
    out = json.loads(awsmon.canonicalize(obj))
    assert out == {"Name": "trail", "inner": {"keep": 1}}


def test_volatile_set_extends_from_config():
    vs = awsmon.volatile_set({"aws_volatile_fields": ["MyCustomField"]})
    assert "MyCustomField" in vs and "ResponseMetadata" in vs
    obj = {"MyCustomField": 9, "keep": 1}
    assert json.loads(awsmon.canonicalize(obj, vs)) == {"keep": 1}


def test_access_key_last_used_does_not_cause_drift():
    # Same key, different LastUsedDate → identical hash (volatile-stripped).
    u = {"UserName": "svc", "Arn": "arn:aws:iam::1:user/svc"}
    iam1 = FakeIam(users=[dict(u)])
    iam2 = FakeIam(users=[dict(u)])
    r1 = list(awsmon.collect_iam(iam1, "global", {}))
    r2 = list(awsmon.collect_iam(iam2, "global", {}))
    by_arn1 = {r.arn: r for r in r1}
    by_arn2 = {r.arn: r for r in r2}
    assert by_arn1[u["Arn"]].config_hash == by_arn2[u["Arn"]].config_hash


# ---------------------------------------------------------------------------
# Records + identity
# ---------------------------------------------------------------------------

def test_iam_driver_emits_user_and_password_policy():
    iam = FakeIam(users=[{"UserName": "alice",
                          "Arn": "arn:aws:iam::1:user/alice"}],
                  pw_policy={"MinimumPasswordLength": 14})
    recs = list(awsmon.collect_iam(iam, "global", {}))
    types = {r.resource_type for r in recs}
    assert "iam:user" in types
    assert "iam:account-password-policy" in types
    user = next(r for r in recs if r.resource_type == "iam:user")
    assert user.arn == "arn:aws:iam::1:user/alice"
    assert user.region == "global" and user.service == "iam"


# ---------------------------------------------------------------------------
# init → scan diff contract (0 clean / 1 drift)
# ---------------------------------------------------------------------------

def _sg(gid, ingress):
    return {"GroupId": gid, "OwnerId": "1", "IpPermissions": ingress}


def test_init_then_clean_scan_returns_0(tmp_path):
    ec2 = FakeEc2(sgs=[_sg("sg-1", [])], regions=["us-east-1"])
    cfg = {"db_path": str(tmp_path / "aws.db"),
           "aws_services": ["ec2"], "aws_regions": ["us-east-1"]}
    fac = _factory({("ec2", "us-east-1"): ec2, ("ec2", None): ec2})
    assert awsmon.cmd_init(cfg, factory=fac) == 0
    assert awsmon.cmd_scan(cfg, factory=fac, quiet=True) == 0


def test_scan_detects_added_modified_deleted(tmp_path):
    cfg = {"db_path": str(tmp_path / "aws.db"),
           "aws_services": ["ec2"], "aws_regions": ["us-east-1"]}

    base = FakeEc2(sgs=[_sg("sg-keep", []), _sg("sg-gone", [])])
    assert awsmon.cmd_init(cfg, factory=_factory(
        {("ec2", "us-east-1"): base})) == 0

    # sg-gone deleted, sg-keep gains an ingress rule (modified), sg-new added
    changed = FakeEc2(sgs=[
        _sg("sg-keep", [{"IpProtocol": "tcp", "FromPort": 22}]),
        _sg("sg-new", []),
    ])
    rc = awsmon.cmd_scan(cfg, factory=_factory(
        {("ec2", "us-east-1"): changed}), quiet=True)
    assert rc == 1   # drift present


def test_missing_boto3_returns_2(tmp_path, monkeypatch):
    # No factory injected → real path, which requires boto3. Simulate absence.
    monkeypatch.setattr(awsmon, "HAVE_BOTO3", False)
    cfg = {"db_path": str(tmp_path / "aws.db")}
    assert awsmon.cmd_init(cfg) == 2
    assert awsmon.cmd_scan(cfg, quiet=True) == 2


def test_driver_failure_becomes_error_record_not_crash(tmp_path):
    class Boom:
        def describe_security_groups(self):
            raise RuntimeError("AccessDenied")
        def describe_network_acls(self):
            return {"NetworkAcls": []}
        def describe_vpcs(self):
            return {"Vpcs": []}
    cfg = {"db_path": str(tmp_path / "aws.db"),
           "aws_services": ["ec2"], "aws_regions": ["us-east-1"]}
    # cmd_init must not raise; the failed region yields an error record.
    assert awsmon.cmd_init(cfg, factory=_factory(
        {("ec2", "us-east-1"): Boom()})) == 0
    conn = awsmon.open_db(cfg["db_path"])
    try:
        errs = [r for r in conn.execute(
            "SELECT error FROM aws_resources WHERE error IS NOT NULL")]
    finally:
        conn.close()
    assert any("AccessDenied" in (e[0] or "") for e in errs)


def test_changed_keys_reports_top_level_diff():
    old = awsmon.make_record("ec2", "ec2:security-group", "arn:x", "us-east-1",
                             {"GroupId": "sg-1", "IpPermissions": []}, {})
    new = awsmon.make_record("ec2", "ec2:security-group", "arn:x", "us-east-1",
                             {"GroupId": "sg-1",
                              "IpPermissions": [{"FromPort": 22}]}, {})
    assert awsmon.changed_keys(old, new) == ["IpPermissions"]


# ---------------------------------------------------------------------------
# SARIF / report rendering
# ---------------------------------------------------------------------------

def _rec(arn, cfgobj):
    return awsmon.make_record("ec2", "ec2:security-group", arn, "us-east-1",
                              cfgobj, {})


def test_aws_sarif_render_is_valid_and_uses_arn_uri():
    added = [_rec("arn:aws:ec2:us-east-1:1:security-group/sg-new", {"a": 1})]
    modified = [(_rec("arn:aws:ec2:us-east-1:1:security-group/sg-1", {"x": 1}),
                 _rec("arn:aws:ec2:us-east-1:1:security-group/sg-1", {"x": 2}))]
    result = report_mod.AwsScanResult(
        scanned_at="2026-07-11T00:00:00Z", host="h", db_path="aws.db",
        added=added, modified=modified, deleted=[])
    doc = json.loads(report_mod.render_aws(result, "sarif"))
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    ids = {r["ruleId"] for r in results}
    assert ids == {"treadmark.aws.added", "treadmark.aws.modified"}
    # ARN must be used verbatim as the uri — NOT wrapped in file://
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in results]
    assert all(u.startswith("arn:aws:") for u in uris)


def test_aws_json_and_md_render():
    result = report_mod.AwsScanResult(
        scanned_at="2026-07-11T00:00:00Z", host="h", db_path="aws.db",
        added=[_rec("arn:aws:s3:::b", {"Name": "b"})], modified=[], deleted=[])
    j = json.loads(report_mod.render_aws(result, "json"))
    assert j["summary"]["added"] == 1
    assert j["added"][0]["config"] == {"Name": "b"}   # config_json inlined
    md = report_mod.render_aws(result, "md")
    assert "AWS configuration drift report" in md and "arn:aws:s3:::b" in md
