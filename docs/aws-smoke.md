# EC2 AMI smoke testing

`scripts/smoke-aws.sh` proves the released artifacts install and run on the
**real AWS images** treadmark's users deploy on — not just in containers. Each run
launches one EC2 instance per platform from the current official AMI, installs
the artifact (.rpm/.deb/MSI), walks the full init → scan → drift → accept
cycle via the existing smoke scripts, reports a per-platform verdict, and
terminates everything.

| platform id | image | instance | artifact |
|---|---|---|---|
| `al2023` | Amazon Linux 2023 x86_64 | t3.small | `.rpm` |
| `al2023-arm64` | Amazon Linux 2023 Graviton | t4g.small | `.rpm` (aarch64) |
| `ubuntu-2404` | Ubuntu 24.04 LTS x86_64 | t3.small | `.deb` |
| `ubuntu-2404-arm64` *(opt-in)* | Ubuntu 24.04 Graviton | t4g.small | `.deb` (arm64) |
| `alma9` | AlmaLinux OS 9 x86_64 | t3.small | `.rpm` |
| `alma10` | AlmaLinux OS 10 x86_64 | t3.small | `.rpm` |
| `win2022` | Windows Server 2022 Full Base | t3.medium | `.msi` |
| `win2025` | Windows Server 2025 Full Base | t3.medium | `.msi` |

AMI IDs are never hardcoded: Amazon Linux / Ubuntu / Windows come from AWS's
public SSM parameters, AlmaLinux from `describe-images` against the AlmaLinux
OS Foundation owner account (`764336703387`), newest non-Beta image wins.

**Cost + time:** a full 7-leg run holds ~14 vCPUs for 20–35 minutes (Windows
is the critical path) — well under $0.25 on-demand. Fresh accounts with the
default 5-vCPU quota should run subsets (`--platforms al2023,win2022`).

## Design: zero ingress, S3 phone-home

No SSH keys, no WinRM, no SSM sessions — AlmaLinux AMIs don't ship the SSM
agent, so user-data is the only bootstrap that works uniformly. The security
group has **zero ingress rules**. Each instance:

1. downloads its artifact + smoke script via **presigned URLs** (no
   credentials on the box for reads),
2. runs `scripts/smoke-test.sh` (Linux; core cycle by default,
   `SMOKE_FOOTPRINT=1` with `--extended`) or `scripts/smoke-test.ps1`
   (Windows; winget-dependent captures self-skip on Server AMIs),
3. uploads `smoke.log` + `status.json` with the **put-only** instance role
   `treadmark-smoke-instance` (can write `runs/*/results/*`, nothing else),
4. echoes `TREADMARK-SMOKE-RESULT: <platform> <rc>` to the serial console — the
   fallback the driver reads when the upload path fails,
5. shuts down; `--instance-initiated-shutdown-behavior terminate` reaps the
   instance even if the driver died.

The driver polls S3 for `status.json` markers, downloads results into
`smoke-out/aws/<run-id>/<platform>/`, and classifies each leg:

- **PASS** — smoke ran, exit 0
- **SMOKE-FAIL** — smoke ran, nonzero exit (the log says why; glibc mismatches
  are auto-annotated, see below)
- **INFRA-FAIL** — the leg never phoned home (see `console.txt`)

Everything created is tagged `Project=treadmark-smoke` + `RunId=<id>`.

## One-time setup

```bash
aws configure   # or set AWS_PROFILE — needs the operator policy below
bash scripts/smoke-aws.sh setup --region us-east-1
```

`setup` is idempotent. It creates:

- S3 bucket `treadmark-smoke-<account>-<region>` — public access blocked, and a
  lifecycle rule expires `runs/` after 7 days (no S3 cleanup needed, ever)
- IAM role + instance profile `treadmark-smoke-instance` — trusts EC2, inline
  policy allows only `s3:PutObject` on `arn:aws:s3:::treadmark-smoke-*/runs/*/results/*`

## Usage

```bash
bash scripts/smoke-aws.sh                                  # latest release, all 7 legs
bash scripts/smoke-aws.sh --platforms al2023,win2022       # subset
bash scripts/smoke-aws.sh --release v0.11.0                # a specific release
bash scripts/smoke-aws.sh --dist dist/ --platforms alma9   # locally built artifacts
bash scripts/smoke-aws.sh --extended                       # + footprint captures
bash scripts/smoke-aws.sh --dry-run                        # resolve AMIs, launch nothing
bash scripts/smoke-aws.sh sweep --hours 3                  # reap stale tagged resources
```

Flags: `--region`, `--profile`, `--subnet-id` (when there's no default VPC —
the subnet must have outbound internet), `--timeout MIN`, `--keep` (leave
instances up; clean with `sweep --hours 0`).

By default artifacts come from the latest GitHub release via `gh release
download` — that's the point: prove the bits users download. `--dist DIR`
tests a local build instead (note there's no way to build the MSI outside
Windows, so Windows legs effectively require a release).

## Running from GitHub Actions

`.github/workflows/aws-smoke.yml` is a `workflow_dispatch`-only wrapper —
trigger it from the Actions tab with a platform list and optional release tag.
One-time OIDC setup in the AWS account:

1. Create (or reuse) the GitHub OIDC provider
   `token.actions.githubusercontent.com`.
2. Create a role `treadmark-smoke-ci` with this trust policy (adjust `OWNER/REPO`):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::<ACCOUNT>:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
      "StringLike":   { "token.actions.githubusercontent.com:sub": "repo:OWNER/REPO:*" }
    }
  }]
}
```

3. Attach the operator policy below to that role.
4. Run `smoke-aws.sh setup` once with admin credentials (the operator policy
   deliberately can't create IAM roles).
5. Set repo **variables** `AWS_SMOKE_ROLE_ARN` and `AWS_SMOKE_REGION`.

## Operator / CI policy (least privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Ec2Smoke",
      "Effect": "Allow",
      "Action": [
        "ec2:RunInstances", "ec2:TerminateInstances", "ec2:CreateTags",
        "ec2:DescribeInstances", "ec2:DescribeInstanceStatus",
        "ec2:DescribeImages", "ec2:DescribeVpcs", "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables", "ec2:DescribeSecurityGroups",
        "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
        "ec2:GetConsoleOutput"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PublicAmiParams",
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": "arn:aws:ssm:*::parameter/aws/service/*"
    },
    {
      "Sid": "StagingBucket",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket", "s3:ListBucket", "s3:GetObject", "s3:PutObject",
        "s3:DeleteObject", "s3:PutBucketPublicAccessBlock",
        "s3:PutLifecycleConfiguration", "s3:PutBucketTagging", "s3:GetBucketLocation"
      ],
      "Resource": ["arn:aws:s3:::treadmark-smoke-*", "arn:aws:s3:::treadmark-smoke-*/*"]
    },
    {
      "Sid": "PassInstanceRole",
      "Effect": "Allow",
      "Action": ["iam:PassRole", "iam:GetRole", "iam:GetInstanceProfile"],
      "Resource": [
        "arn:aws:iam::*:role/treadmark-smoke-instance",
        "arn:aws:iam::*:instance-profile/treadmark-smoke-instance"
      ],
      "Condition": { "StringEquals": { "iam:PassedToService": "ec2.amazonaws.com" } }
    },
    { "Sid": "Identity", "Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*" }
  ]
}
```

The `Condition` on `PassInstanceRole` only applies to `iam:PassRole`; IAM
ignores it for the two `Get*` actions. Role/profile **creation**
(`iam:CreateRole`, `iam:CreateInstanceProfile`, `iam:AddRoleToInstanceProfile`,
`iam:PutRolePolicy`, `iam:TagRole`) is needed only for the one-time `setup`
and belongs with a human admin, not the CI role.

## Troubleshooting

- **INFRA-FAIL** — read `smoke-out/aws/<run-id>/<platform>/console.txt` (the
  serial console). Common causes: subnet without internet egress, instance
  profile created seconds before the run (retry), vCPU quota.
- **`curl: Failed to connect to ...s3...amazonaws.com ... Timeout` on the
  console** — the instance has no egress path. The driver preflights the
  route table and forces a public IP on IGW subnets, so if you still see
  this the block is outside the route table: most likely **VPC Block Public
  Access** (org-level, blocks IGW traffic) or an egress firewall. Use a
  NAT-routed private subnet via `--subnet-id`, or ask for the S3
  gateway-endpoint mode if your VPCs never allow internet egress.
- **`--keep`** leaves instances running for inspection (there's still no
  ingress — attach a security group manually if you need a shell). Clean up
  with `sweep --hours 0`.
- **A killed driver** leaks at most a security group: instances self-terminate
  when the smoke finishes, and S3 expires via lifecycle. `sweep` reaps the
  rest.
- **Windows legs are slow** — 10–20 min from launch to verdict is normal
  (boot + MSI + IIS install + registry baselines).

## Known findings this harness exists to catch {#glibc}

- **glibc floor.** Nuitka binaries take the build host's versioned glibc
  symbols. Through 0.10.0 the release binaries were built on Ubuntu 24.04
  (glibc 2.39) and **died on Amazon Linux 2023 and EL9** (glibc 2.34) with
  `GLIBC_2.38 not found`. The build now runs in an `almalinux:9` container
  (see `scripts/build-binary-linux.sh`), setting a 2.34 floor that covers
  EL9, EL10, AL2023, and Ubuntu 24.04. A SMOKE-FAIL whose log matches that
  error is auto-annotated `[COMPAT: ...]` in the summary — if you ever see
  it again, the build base regressed.
- **winget doesn't exist on Windows Server AMIs** — `smoke-test.ps1` skips
  the Datadog/extended captures there and keeps IIS (a Windows feature) as
  the hard assertion.
- **`--extended` footprints run only on distros whose package set the smoke
  knows** (`ubuntu-2404*`, `alma10`, `al2023*`). AlmaLinux 9 is excluded:
  EL9 has no valkey (it arrived in EL10), so alma9 runs the core cycle only.
