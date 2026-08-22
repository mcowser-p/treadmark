# Cloud configuration drift with treadmark

> **⚠ Status: DORMANT.** `treadmark aws` shipped in 0.10.0 but is now a dormant
> scaffold pending validation against a real AWS account — the published
> product is the OS FIM (files/registry/footprint). The `awsmon` module and
> its fake-client unit tests remain in the tree and must stay green; the CLI
> subcommand and the `aws` pyproject extra are commented out (the same
> treatment as azure/gcp/k8s below). This page describes the behavior once
> re-wired. To re-enable: uncomment the `aws` subparser, `_run_aws`, and its
> dispatch branch in `src/treadmark/__main__.py`, plus the `aws` extra in
> `pyproject.toml`.

`treadmark aws` applies treadmark's forensic model — a point-in-time **baseline**, an
offline **diff** on rescan, exit codes **0/1/2**, and SARIF/JSON reports — to
an AWS account's security-relevant configuration. It answers "what changed in
this account since I last approved its state?" without an always-on recorder.

It is **not** a compliance scanner (that's [Prowler](https://github.com/prowler-cloud/prowler)),
an inventory/query engine ([Steampipe](https://steampipe.io/),
[CloudQuery](https://www.cloudquery.io/)), or AWS Config. It is a FIM: baseline,
detect drift, alert. Point it at a hardened account and every deviation — a
loosened security group, a disabled CloudTrail, a new IAM policy, KMS rotation
turned off — surfaces on the next scan.

## Install (once re-enabled)

```
pip install "treadmark[aws]"
```

`boto3` is an optional dependency; the core package has none. Without it the
`aws` subcommand exits 2 with an install hint (nothing else is affected).

## Credentials & least-privilege

Credentials come from the standard boto3 chain: the `aws_profile` in your
config, `--profile`, `AWS_PROFILE` / `AWS_ACCESS_KEY_*`, or an instance/task
role. Every call treadmark makes is **read-only**. The simplest grant is the
AWS-managed **`SecurityAudit`** policy. A minimal custom policy covers exactly
the shipped drivers:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:ListUsers", "iam:ListRoles", "iam:ListPolicies",
      "iam:ListMFADevices", "iam:ListAccessKeys",
      "iam:GetPolicyVersion", "iam:GetAccountPasswordPolicy",
      "s3:ListAllMyBuckets", "s3:GetBucketPolicy", "s3:GetBucketAcl",
      "s3:GetBucketPublicAccessBlock", "s3:GetEncryptionConfiguration",
      "ec2:DescribeRegions", "ec2:DescribeSecurityGroups",
      "ec2:DescribeNetworkAcls", "ec2:DescribeVpcs",
      "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
      "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus",
      "kms:GetKeyPolicy",
      "lambda:ListFunctions", "lambda:GetPolicy"
    ],
    "Resource": "*"
  }]
}
```

## Workflow

```bash
# 1. Baseline the account on a day you consider it good.
treadmark aws init --config packaging/treadmark-aws.yaml

# 2. Later — scheduled, or after a change window — scan for drift.
treadmark aws scan --config packaging/treadmark-aws.yaml --report drift.sarif
#    exit 0 = matches baseline, 1 = drift, 2 = error

# 3. Once you've reviewed and accepted the new state, fold it in.
treadmark aws update --config packaging/treadmark-aws.yaml
```

By default `init` discovers and scans every **enabled** region; `aws_regions`
(or `--region`, repeatable) narrows it. `aws_services` narrows which of the
curated drivers run.

## What gets baselined (v1)

| Service | Resources | Why it matters |
|---|---|---|
| `iam` | users (+MFA, access-key metadata), roles + trust policies, customer-managed policies + documents, account password policy | the identity blast radius |
| `s3` | bucket policy, public-access block, ACL grants, default encryption | public-exposure surface |
| `ec2` | security groups + rules, network ACLs, VPCs | network reachability |
| `cloudtrail` | trails + `IsLogging` status | logging **on/off** is tamper signal #1 |
| `kms` | customer keys, rotation status, key policies | key governance (AWS-managed keys are ignored — they churn on Amazon's schedule) |
| `lambda` | function config, execution role, env var **names**, resource policy | code-exec identity & exposure |

Broadening coverage means adding a driver to the `DRIVERS` registry in
`awsmon.py` — same mechanism, no new plumbing.

## Noise: the volatile-fields concept

An account changes on its own between scans — `PasswordLastUsed`,
`LatestDeliveryTime`, `ResponseMetadata`. treadmark strips a built-in list of these
**volatile** fields (at any nesting depth) before diffing, so background churn
never reads as drift. If a field in *your* account misbehaves, add it to
`aws_volatile_fields` in the config — the same denoise lever the Windows
footprint uses for background services.

## Secrets discipline

Baselines store **no secrets**: Lambda env var *names* only (never values),
policy documents are configuration, key material is never read. But a baseline
still *describes your security posture*, so treat the DB and reports as
sensitive — same care as a filesystem baseline.

## Reports & alerting

`--report drift.sarif` (or `.json` / `.md` / `.txt`, by extension; `--format`
to force) writes the drift as **SARIF 2.1.0** with rule IDs
`treadmark.aws.added|modified|deleted` and the resource ARN as the location. That
is the format GitHub code-scanning ingests. Wiring a scheduled workflow to
upload it (or open issues) is a deliberate next step, not shipped here — note
that SARIF **code-scanning alerts on private repos require GitHub Advanced
Security**; the free path on a private repo is filing an Issue from the scan
summary.

## Other clouds — the bookmark

The record model (`AwsRecord`: identity + scope + canonical config + hash) and
the driver-registry pattern are provider-agnostic. Adding a cloud is a new
`*mon.py` with its own driver set and native inventory API. All four providers
are currently **dormant**: AWS is unit-tested but CLI-unwired pending
real-account validation; Azure, GCP, and Kubernetes are untested scaffolds.
Their CLI subcommands and pyproject extras are commented out until each is
validated against a real account/tenant/cluster:

| Provider | Module | Status | Native inventory / config API | Auth |
|---|---|---|---|---|
| AWS | `awsmon` | dormant (unit-tested; CLI unwired) | per-service `Describe*/List*/Get*` (boto3) | profile / env / instance role |
| Azure | `azmon` | scaffold (untested) | Azure Resource Graph | service principal / managed identity |
| GCP | `gcpmon` | scaffold (untested) | Cloud Asset Inventory (`cloudasset`) | service account / ADC |
| Kubernetes | `k8smon` | scaffold (untested) | API server `list` (RBAC, NetworkPolicy, admission, ServiceAccounts, Secret **metadata only**) | kubeconfig / in-cluster SA |

Each reuses the same table shape, the 0/1/2 contract, and the volatile-stripping
denoise — only the collectors are provider-specific. To enable one: uncomment
its subparser + dispatch in `__main__.py`, its extra in `pyproject.toml`, add
fake-client tests, and (once the first non-AWS cloud is proven) lift the shared
diff/SARIF/canonicalize logic into a `cloudbase.py`.
