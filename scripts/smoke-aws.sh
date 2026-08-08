#!/usr/bin/env bash
# scripts/smoke-aws.sh — run the artifact smoke tests on REAL EC2 instances
# launched from the AMIs cairn's users deploy on: Amazon Linux 2023 (x86_64 +
# Graviton), Ubuntu 24.04, AlmaLinux 9/10, and Windows Server 2022/2025.
#
#   bash scripts/smoke-aws.sh setup                    # one-time infra (bucket + instance role)
#   bash scripts/smoke-aws.sh                          # latest release, all default platforms
#   bash scripts/smoke-aws.sh --platforms al2023,win2022
#   bash scripts/smoke-aws.sh --release v0.11.0 --extended
#   bash scripts/smoke-aws.sh --dist dist/ --platforms alma9   # locally built artifacts
#   bash scripts/smoke-aws.sh sweep --hours 3          # kill anything tagged + stale
#
# Design: ZERO-INGRESS. No SSH keys, no WinRM, no SSM sessions (AlmaLinux AMIs
# don't ship the SSM agent). Each instance bootstraps from user-data
# (packaging/aws/userdata-*.in): downloads the artifact + smoke script via
# presigned URLs, runs scripts/smoke-test.sh / smoke-test.ps1, uploads
# smoke.log + status.json to S3 with a put-only instance role, then shuts
# down — shutdown-behavior=terminate reaps it even if this driver dies. The
# driver polls S3 for status markers; `ec2 get-console-output` is the
# fallback diagnostic. Results land in smoke-out/aws/<run-id>/<platform>/.
#
# Cost: a full 7-leg run holds ~14 vCPUs for 20-35 min — well under $0.25.
# Requirements: aws CLI v2, gh (unless --dist), an AWS profile with the
# policy in docs/aws-smoke.md, and a default VPC with internet egress (or
# --subnet-id pointing at a subnet that has it).

set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ALMA_OWNER_ID=764336703387       # AlmaLinux OS Foundation's AWS account
INSTANCE_ROLE=cairn-smoke-instance
DEFAULT_PLATFORMS="al2023 al2023-arm64 ubuntu-2404 alma9 alma10 win2022 win2025"
KNOWN_PLATFORMS="$DEFAULT_PLATFORMS ubuntu-2404-arm64"
# Distros whose repo package set smoke-test.sh's footprint captures know.
# alma9 is deliberately absent: EL9 has no valkey (arrived in EL10).
FOOTPRINT_OK="ubuntu-2404 ubuntu-2404-arm64 alma10 al2023 al2023-arm64"
POLL_SECONDS=20

step() { printf '\n>>> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { warn "$*"; exit 2; }

usage() {
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Argument parsing (subcommand first, then flags)
# ---------------------------------------------------------------------------
CMD=run
case "${1:-}" in
    setup|sweep) CMD=$1; shift ;;
    run) shift ;;
esac

PLATFORMS_CSV=""
RELEASE_TAG=""
DIST_DIR=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
PROFILE=""
SUBNET_ID=""
EXTENDED=0
KEEP=0
TIMEOUT_MIN=""
DRY_RUN=0
SWEEP_HOURS=3

while [ $# -gt 0 ]; do
    case "$1" in
        --platforms) PLATFORMS_CSV=$2; shift 2 ;;
        --release)   RELEASE_TAG=$2; shift 2 ;;
        --dist)      DIST_DIR=$2; shift 2 ;;
        --region)    REGION=$2; shift 2 ;;
        --profile)   PROFILE=$2; shift 2 ;;
        --subnet-id) SUBNET_ID=$2; shift 2 ;;
        --extended)  EXTENDED=1; shift ;;
        --keep)      KEEP=1; shift ;;
        --timeout)   TIMEOUT_MIN=$2; shift 2 ;;
        --dry-run)   DRY_RUN=1; shift ;;
        --hours)     SWEEP_HOURS=$2; shift 2 ;;
        -h|--help)   usage 0 ;;
        *) warn "unknown argument: $1"; usage 2 ;;
    esac
done

command -v aws >/dev/null 2>&1 || die "aws CLI not found"
[ -n "$REGION" ] || REGION=$(aws configure get region ${PROFILE:+--profile "$PROFILE"} 2>/dev/null || true)
[ -n "$REGION" ] || die "no region: pass --region, set AWS_REGION, or configure the profile"

awsx() { aws ${PROFILE:+--profile "$PROFILE"} --region "$REGION" "$@"; }

ACCOUNT=$(awsx sts get-caller-identity --query Account --output text) \
    || die "cannot resolve AWS identity (credentials?)"
BUCKET="cairn-smoke-${ACCOUNT}-${REGION}"

# ---------------------------------------------------------------------------
# Platform table. platform_spec <id> sets the P_* globals.
# ---------------------------------------------------------------------------
platform_spec() {
    P_OS=linux P_AMI_MODE=ssm P_ITYPE=t3.small P_TIMEOUT=20
    case "$1" in
        al2023)
            P_AMI_KEY=/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64
            P_ARTGLOB='cairn-*.x86_64.rpm' ;;
        al2023-arm64)
            P_AMI_KEY=/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64
            P_ITYPE=t4g.small
            P_ARTGLOB='cairn-*.aarch64.rpm' ;;
        ubuntu-2404)
            P_AMI_KEY=/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id
            P_ARTGLOB='cairn_*_amd64.deb' ;;
        ubuntu-2404-arm64)
            P_AMI_KEY=/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id
            P_ITYPE=t4g.small
            P_ARTGLOB='cairn_*_arm64.deb' ;;
        alma9)
            P_AMI_MODE=alma P_AMI_KEY='AlmaLinux OS 9*'
            P_ARTGLOB='cairn-*.x86_64.rpm' ;;
        alma10)
            P_AMI_MODE=alma P_AMI_KEY='AlmaLinux OS 10*'
            P_ARTGLOB='cairn-*.x86_64.rpm' ;;
        win2022)
            P_OS=windows P_ITYPE=t3.medium P_TIMEOUT=35
            P_AMI_KEY=/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base
            P_ARTGLOB='cairn-*.msi' ;;
        win2025)
            P_OS=windows P_ITYPE=t3.medium P_TIMEOUT=35
            P_AMI_KEY=/aws/service/ami-windows-latest/Windows_Server-2025-English-Full-Base
            P_ARTGLOB='cairn-*.msi' ;;
        *) die "unknown platform: $1 (known: $KNOWN_PLATFORMS)" ;;
    esac
    if [ "$P_OS" = linux ] && [ "$EXTENDED" = 1 ]; then P_TIMEOUT=45; fi
    [ -n "$TIMEOUT_MIN" ] && P_TIMEOUT=$TIMEOUT_MIN
    return 0
}

resolve_ami() {  # resolve_ami <platform> → AMI id on stdout
    platform_spec "$1"
    if [ "$P_AMI_MODE" = ssm ]; then
        awsx ssm get-parameter --name "$P_AMI_KEY" \
            --query 'Parameter.Value' --output text
    else
        local arch=x86_64
        # JMESPath backticks are literal inside single quotes; Beta images
        # are excluded, newest CreationDate wins (deterministic).
        awsx ec2 describe-images --owners "$ALMA_OWNER_ID" \
            --filters "Name=name,Values=$P_AMI_KEY" \
                      "Name=architecture,Values=$arch" \
                      "Name=state,Values=available" \
            --query 'sort_by(Images[?!contains(Name, `Beta`) && !contains(Name, `beta`)], &CreationDate)[-1].ImageId' \
            --output text
    fi
}

# ---------------------------------------------------------------------------
# setup — idempotent one-time infrastructure (bucket + instance role)
# ---------------------------------------------------------------------------
ensure_bucket() {
    if awsx s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
        note "bucket exists: $BUCKET"
        return 0
    fi
    step "creating bucket $BUCKET"
    if [ "$REGION" = us-east-1 ]; then
        awsx s3api create-bucket --bucket "$BUCKET" >/dev/null
    else
        awsx s3api create-bucket --bucket "$BUCKET" \
            --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
    fi
    awsx s3api put-public-access-block --bucket "$BUCKET" \
        --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    awsx s3api put-bucket-tagging --bucket "$BUCKET" \
        --tagging 'TagSet=[{Key=Project,Value=cairn-smoke}]'
    # Run artifacts are disposable — expire them instead of sweeping.
    awsx s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" \
        --lifecycle-configuration '{"Rules":[{"ID":"expire-runs","Status":"Enabled",
          "Filter":{"Prefix":"runs/"},"Expiration":{"Days":7}}]}'
}

cmd_setup() {
    step "cairn-smoke setup (account $ACCOUNT, region $REGION)"
    ensure_bucket

    if awsx iam get-role --role-name "$INSTANCE_ROLE" >/dev/null 2>&1; then
        note "role exists: $INSTANCE_ROLE"
    else
        step "creating instance role $INSTANCE_ROLE (put-only on runs/*/results/*)"
        awsx iam create-role --role-name "$INSTANCE_ROLE" \
            --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{
              "Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},
              "Action":"sts:AssumeRole"}]}' \
            --tags Key=Project,Value=cairn-smoke >/dev/null
    fi
    awsx iam put-role-policy --role-name "$INSTANCE_ROLE" \
        --policy-name results-put-only \
        --policy-document '{"Version":"2012-10-17","Statement":[{
          "Effect":"Allow","Action":"s3:PutObject",
          "Resource":"arn:aws:s3:::cairn-smoke-*/runs/*/results/*"}]}'

    if awsx iam get-instance-profile --instance-profile-name "$INSTANCE_ROLE" >/dev/null 2>&1; then
        note "instance profile exists: $INSTANCE_ROLE"
    else
        awsx iam create-instance-profile --instance-profile-name "$INSTANCE_ROLE" >/dev/null
        awsx iam add-role-to-instance-profile \
            --instance-profile-name "$INSTANCE_ROLE" --role-name "$INSTANCE_ROLE"
        note "instance profile created (allow ~10s to propagate before the first run)"
    fi
    step "setup complete — bucket $BUCKET, instance profile $INSTANCE_ROLE"
}

# ---------------------------------------------------------------------------
# sweep — terminate anything tagged Project=cairn-smoke older than --hours
# ---------------------------------------------------------------------------
cmd_sweep() {
    local epoch cutoff ids
    epoch=$(( $(date +%s) - SWEEP_HOURS * 3600 ))
    # BSD (macOS) date first, GNU fallback.
    cutoff=$(date -u -r "$epoch" +%Y-%m-%dT%H:%M:%S 2>/dev/null \
          || date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%S)
    step "sweep: cairn-smoke instances launched before ${cutoff}Z"
    ids=$(awsx ec2 describe-instances \
        --filters "Name=tag:Project,Values=cairn-smoke" \
                  "Name=instance-state-name,Values=pending,running,stopping,stopped" \
        --query "Reservations[].Instances[?LaunchTime<'$cutoff'][].InstanceId" \
        --output text | tr '\t' ' ')
    if [ -n "${ids// /}" ]; then
        note "terminating: $ids"
        # shellcheck disable=SC2086
        awsx ec2 terminate-instances --instance-ids $ids >/dev/null
    else
        note "no stale instances"
    fi
    # Unattached leftover security groups (in-use ones fail and are skipped;
    # rerun after the instances above finish terminating).
    local sgs sg
    sgs=$(awsx ec2 describe-security-groups \
        --filters "Name=group-name,Values=cairn-smoke-*" \
        --query 'SecurityGroups[].GroupId' --output text | tr '\t' ' ')
    for sg in $sgs; do
        if awsx ec2 delete-security-group --group-id "$sg" >/dev/null 2>&1; then
            note "deleted security group $sg"
        else
            note "security group $sg still in use — rerun sweep later"
        fi
    done
    step "sweep done (S3 run data expires via bucket lifecycle)"
}

# ---------------------------------------------------------------------------
# run — the main flow
# ---------------------------------------------------------------------------
SELECTED=()
AMI_IDS=()
INSTANCE_IDS=()
RESULTS=()       # PASS | SMOKE-FAIL | INFRA-FAIL | pending
NOTES=()
SG_ID=""
SUBNET=""
ASSOC_IP=false
RUN_ID=""
OUT_DIR=""
STAGE_DIR=""

select_platforms() {
    local csv p known
    csv=${PLATFORMS_CSV:-all}
    [ "$csv" = all ] && csv=$(echo "$DEFAULT_PLATFORMS" | tr ' ' ',')
    for p in $(echo "$csv" | tr ',' ' '); do
        known=0
        case " $KNOWN_PLATFORMS " in *" $p "*) known=1 ;; esac
        [ "$known" = 1 ] || die "unknown platform: $p (known: $KNOWN_PLATFORMS)"
        SELECTED+=("$p")
    done
    [ ${#SELECTED[@]} -gt 0 ] || die "no platforms selected"
}

fetch_artifacts() {
    STAGE_DIR="$OUT_DIR/stage"
    mkdir -p "$STAGE_DIR"
    local p f
    if [ -n "$DIST_DIR" ]; then
        step "using local artifacts from $DIST_DIR"
        for p in "${SELECTED[@]}"; do
            platform_spec "$p"
            f=$(ls "$DIST_DIR"/$P_ARTGLOB 2>/dev/null | head -n1) \
                || die "no artifact matching $P_ARTGLOB in $DIST_DIR (needed by $p)"
            cp "$f" "$STAGE_DIR/"
        done
        return 0
    fi
    command -v gh >/dev/null 2>&1 || die "gh CLI not found (or use --dist DIR)"
    gh auth status >/dev/null 2>&1 \
        || die "gh is not authenticated — run \`gh auth login\` once (or export GH_TOKEN), or pass --dist DIR to test locally built artifacts"
    step "downloading release artifacts (${RELEASE_TAG:-latest})"
    # Union of the patterns the selected platforms need, plus checksums.
    local args=() seen=" "
    for p in "${SELECTED[@]}"; do
        platform_spec "$p"
        case "$seen" in *" $P_ARTGLOB "*) continue ;; esac
        seen="$seen$P_ARTGLOB "
        args+=(-p "$P_ARTGLOB")
    done
    args+=(-p 'SHA256SUMS')
    gh release download ${RELEASE_TAG:+"$RELEASE_TAG"} "${args[@]}" -D "$STAGE_DIR" \
        || die "gh release download failed (tag: ${RELEASE_TAG:-latest})"

    if [ -f "$STAGE_DIR/SHA256SUMS" ]; then
        step "verifying checksums"
        local shatool="sha256sum"
        command -v sha256sum >/dev/null 2>&1 || shatool="shasum -a 256"
        (cd "$STAGE_DIR" && for f in *; do
            [ "$f" = SHA256SUMS ] && continue
            grep -E " \*?$f\$" SHA256SUMS | $shatool -c - >/dev/null \
                || { echo "checksum FAILED: $f"; exit 1; }
            echo "    ok: $f"
        done) || die "artifact checksum verification failed"
    fi
}

stage_to_s3() {
    step "staging artifacts to s3://$BUCKET/runs/$RUN_ID/dist/"
    awsx s3 cp --recursive --only-show-errors \
        "$STAGE_DIR" "s3://$BUCKET/runs/$RUN_ID/dist/" \
        --exclude SHA256SUMS
    awsx s3 cp --only-show-errors scripts/smoke-test.sh \
        "s3://$BUCKET/runs/$RUN_ID/dist/smoke-test.sh"
    awsx s3 cp --only-show-errors scripts/smoke-test.ps1 \
        "s3://$BUCKET/runs/$RUN_ID/dist/smoke-test.ps1"
}

presign() { awsx s3 presign "s3://$BUCKET/runs/$RUN_ID/dist/$1" --expires-in 7200; }

render_userdata() {  # render_userdata <platform> <artifact-file> → path on stdout
    local p=$1 art=$2 tpl out content smoke_name smoke_url art_url fp ext
    platform_spec "$p"
    if [ "$P_OS" = windows ]; then
        tpl=packaging/aws/userdata-windows.ps1.in
        smoke_name=smoke-test.ps1
    else
        tpl=packaging/aws/userdata-linux.sh.in
        smoke_name=smoke-test.sh
    fi
    art_url=$(presign "$art")
    smoke_url=$(presign "$smoke_name")
    fp=0; ext=0
    if [ "$EXTENDED" = 1 ]; then
        ext=1
        case " $FOOTPRINT_OK " in *" $p "*) fp=1 ;; esac
    fi
    out="$OUT_DIR/userdata-$p"
    content=$(cat "$tpl")
    content=${content//__PLATFORM__/$p}
    content=${content//__REGION__/$REGION}
    content=${content//__BUCKET__/$BUCKET}
    content=${content//__RESULTS_PREFIX__/runs/$RUN_ID/results/$p}
    content=${content//__ARTIFACT_FILE__/$art}
    content=${content//__ARTIFACT_URL__/$art_url}
    content=${content//__SMOKE_URL__/$smoke_url}
    content=${content//__SMOKE_FOOTPRINT__/$fp}
    content=${content//__SMOKE_EXTENDED__/$ext}
    content=${content//__KEEP__/$KEEP}
    printf '%s\n' "$content" > "$out"
    echo "$out"
}

create_sg() {
    local vpc rt gw
    if [ -n "$SUBNET_ID" ]; then
        SUBNET=$SUBNET_ID
        vpc=$(awsx ec2 describe-subnets --subnet-ids "$SUBNET" \
            --query 'Subnets[0].VpcId' --output text)
    else
        vpc=$(awsx ec2 describe-vpcs --filters Name=is-default,Values=true \
            --query 'Vpcs[0].VpcId' --output text)
        [ "$vpc" != None ] || die "no default VPC in $REGION — pass --subnet-id"
        SUBNET=$(awsx ec2 describe-subnets \
            --filters "Name=vpc-id,Values=$vpc" "Name=default-for-az,Values=true" \
            --query 'Subnets[0].SubnetId' --output text)
        [ "$SUBNET" != None ] || SUBNET=$(awsx ec2 describe-subnets \
            --filters "Name=vpc-id,Values=$vpc" \
            --query 'Subnets[0].SubnetId' --output text)
        [ "$SUBNET" != None ] || die "no subnet in VPC $vpc — pass --subnet-id"
    fi

    # Preflight the egress path: the legs need outbound HTTPS to S3 (artifact
    # download + results upload). Catch a dead-end subnet HERE with a clear
    # error instead of a 20-minute leg timeout whose console.txt is full of
    # "curl: Failed to connect to ...s3...amazonaws.com: Timeout".
    rt=$(awsx ec2 describe-route-tables \
        --filters "Name=association.subnet-id,Values=$SUBNET" \
        --query 'RouteTables[0].RouteTableId' --output text)
    [ "$rt" != None ] || rt=$(awsx ec2 describe-route-tables \
        --filters "Name=vpc-id,Values=$vpc" "Name=association.main,Values=true" \
        --query 'RouteTables[0].RouteTableId' --output text)
    gw=$(awsx ec2 describe-route-tables --route-table-ids "$rt" \
        --query "RouteTables[0].Routes[?DestinationCidrBlock=='0.0.0.0/0'].[GatewayId, NatGatewayId, State]" \
        --output text 2>/dev/null | tr '\t' ' ')
    case "$gw" in
        # A route whose target was deleted (e.g. a removed NAT gateway) stays
        # in the table as a blackhole — the VPC LOOKS routed but nothing gets
        # out. Seen in the wild; fail loudly.
        *blackhole*) die "subnet $SUBNET's default route is BLACKHOLED (${gw//None/}) — its target no longer exists, so nothing there can reach S3. Point 0.0.0.0/0 back at the VPC's internet gateway (ec2 replace-route) or pass --subnet-id of a healthy subnet." ;;
        *igw-*) ASSOC_IP=true ;;   # internet gateway → instance needs a public IP
        *nat-*) ASSOC_IP=false ;;  # NAT path → private IP is fine
        *) die "subnet $SUBNET has no default route to an internet/NAT gateway — the smoke cannot reach S3 from there. Pass --subnet-id of a subnet with egress (and check VPC Block Public Access if the org enables it)." ;;
    esac
    note "subnet: $SUBNET (egress: ${gw//None/}, associate-public-ip: $ASSOC_IP)"
    # ZERO ingress on purpose; default egress-all stays (repos, S3, presigned
    # URLs all need outbound).
    # NB: EC2 rejects non-ASCII in GroupDescription — keep this plain.
    SG_ID=$(awsx ec2 create-security-group \
        --group-name "cairn-smoke-$RUN_ID" \
        --description "cairn EC2 smoke $RUN_ID (no ingress, egress only)" \
        --vpc-id "$vpc" \
        --tag-specifications "ResourceType=security-group,Tags=[{Key=Project,Value=cairn-smoke},{Key=RunId,Value=$RUN_ID}]" \
        --query GroupId --output text)
    note "security group: $SG_ID (no ingress)"
}

launch_platform() {  # launch_platform <idx> <platform> <ami> <userdata-file>
    local idx=$1 p=$2 ami=$3 ud=$4 id tries
    platform_spec "$p"
    tries=0
    while :; do
        if id=$(awsx ec2 run-instances \
            --image-id "$ami" \
            --instance-type "$P_ITYPE" \
            --network-interfaces "DeviceIndex=0,SubnetId=$SUBNET,Groups=$SG_ID,AssociatePublicIpAddress=$ASSOC_IP" \
            --iam-instance-profile "Name=$INSTANCE_ROLE" \
            --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
            --instance-initiated-shutdown-behavior terminate \
            --user-data "file://$ud" \
            --tag-specifications \
              "ResourceType=instance,Tags=[{Key=Project,Value=cairn-smoke},{Key=RunId,Value=$RUN_ID},{Key=Platform,Value=$p},{Key=Name,Value=cairn-smoke-$RUN_ID-$p}]" \
              "ResourceType=volume,Tags=[{Key=Project,Value=cairn-smoke},{Key=RunId,Value=$RUN_ID}]" \
            --query 'Instances[0].InstanceId' --output text 2>"$OUT_DIR/launch-$p.err"); then
            break
        fi
        # A freshly created instance profile takes ~10s to become launchable.
        if grep -q "Invalid IAM Instance Profile" "$OUT_DIR/launch-$p.err" && [ "$tries" -lt 6 ]; then
            tries=$((tries + 1)); sleep 10; continue
        fi
        warn "launch failed for $p:"; cat "$OUT_DIR/launch-$p.err" >&2
        RESULTS[$idx]="INFRA-FAIL"; NOTES[$idx]="run-instances failed"
        return 0
    done
    INSTANCE_IDS[$idx]=$id
    note "$p → $id ($P_ITYPE, timeout ${P_TIMEOUT}m)"
}

fetch_console() {  # fetch_console <platform> <instance-id>
    local out tries=0
    # Console output lags the instance by a minute or two (and survives
    # termination only briefly) — poll a few times before accepting empty.
    while :; do
        out=$(awsx ec2 get-console-output --instance-id "$2" \
            --query Output --output text 2>/dev/null || true)
        [ -n "$out" ] && [ "$out" != None ] && break
        tries=$((tries + 1))
        [ "$tries" -ge 3 ] && return 0
        sleep 15
    done
    # The API base64-encodes the console; decode if it decodes, else keep raw.
    printf '%s' "$out" | openssl base64 -d -A 2>/dev/null > "$OUT_DIR/$1/console.txt" \
        || printf '%s\n' "$out" > "$OUT_DIR/$1/console.txt"
}

fetch_results() {  # fetch_results <platform>
    mkdir -p "$OUT_DIR/$1"
    awsx s3 cp --recursive --only-show-errors \
        "s3://$BUCKET/runs/$RUN_ID/results/$1/" "$OUT_DIR/$1/" 2>/dev/null || true
}

classify() {  # classify <idx> <platform> — after fetch_results/fetch_console
    local idx=$1 p=$2 rc="" log="$OUT_DIR/$p/smoke.log" st="$OUT_DIR/$p/status.json"
    if [ -f "$st" ]; then
        rc=$(grep -o '"exit_code"[: ]*[0-9]*' "$st" | grep -o '[0-9]*$' || true)
    elif [ -f "$OUT_DIR/$p/console.txt" ]; then
        # Marker echoed to the serial console — upload path failed but the
        # smoke itself ran.
        rc=$(grep -o "CAIRN-SMOKE-RESULT: $p [0-9]*" "$OUT_DIR/$p/console.txt" \
             | tail -n1 | grep -o '[0-9]*$' || true)
        [ -n "$rc" ] && NOTES[$idx]="via console fallback (S3 upload failed)"
    fi
    if [ -z "$rc" ]; then
        RESULTS[$idx]="INFRA-FAIL"
        if [ -z "${NOTES[$idx]}" ]; then
            if [ -f "$OUT_DIR/$p/console.txt" ]; then
                NOTES[$idx]="no status marker (see console.txt)"
            else
                NOTES[$idx]="no status marker and the serial console came back empty — rerun with --keep to inspect"
            fi
        fi
        return 0
    fi
    if [ "$rc" = 0 ]; then
        RESULTS[$idx]="PASS"
    else
        RESULTS[$idx]="SMOKE-FAIL"
        NOTES[$idx]="exit $rc${NOTES[$idx]:+; ${NOTES[$idx]}}"
        if [ -f "$log" ] && grep -qE "GLIBC_[0-9.]+' not found|binary does not execute" "$log"; then
            NOTES[$idx]="${NOTES[$idx]} [COMPAT: binary needs a newer glibc than this distro ships — see docs/aws-smoke.md#glibc]"
        fi
    fi
}

instance_state() {
    awsx ec2 describe-instances --instance-ids "$1" \
        --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null \
        || echo unknown
}

poll_loop() {
    local start now deadline idx p id state pending
    start=$(date +%s)
    step "waiting for legs to phone home (poll every ${POLL_SECONDS}s)"
    while :; do
        pending=0
        now=$(date +%s)
        idx=0
        for p in "${SELECTED[@]}"; do
            if [ "${RESULTS[$idx]}" = pending ]; then
                id=${INSTANCE_IDS[$idx]}
                platform_spec "$p"
                deadline=$((start + P_TIMEOUT * 60))
                if awsx s3api head-object --bucket "$BUCKET" \
                    --key "runs/$RUN_ID/results/$p/status.json" >/dev/null 2>&1; then
                    fetch_results "$p"; classify "$idx" "$p"
                    note "$p: ${RESULTS[$idx]}"
                elif [ -n "$id" ]; then
                    state=$(instance_state "$id")
                    if [ "$state" = terminated ]; then
                        # One last look — the marker can land seconds before
                        # the instance disappears.
                        fetch_results "$p"; fetch_console "$p" "$id" || true
                        classify "$idx" "$p"
                        note "$p: ${RESULTS[$idx]} (instance terminated)"
                    elif [ "$now" -gt "$deadline" ]; then
                        warn "$p: timeout after ${P_TIMEOUT}m — collecting console and terminating"
                        mkdir -p "$OUT_DIR/$p"; fetch_console "$p" "$id" || true
                        fetch_results "$p"; classify "$idx" "$p"
                        [ "${RESULTS[$idx]}" = pending ] && { RESULTS[$idx]="INFRA-FAIL"; NOTES[$idx]="timeout ${P_TIMEOUT}m"; }
                        awsx ec2 terminate-instances --instance-ids "$id" >/dev/null 2>&1 || true
                    fi
                fi
            fi
            [ "${RESULTS[$idx]}" = pending ] && pending=1
            idx=$((idx + 1))
        done
        [ "$pending" = 0 ] && break
        sleep "$POLL_SECONDS"
    done
}

print_summary() {
    local idx=0 p fail=0 line md
    step "results  (logs: ${OUT_DIR#"$REPO"/})"
    printf '    %-20s %-12s %s\n' PLATFORM RESULT NOTES
    printf '    %-20s %-12s %s\n' -------- ------ -----
    md="| platform | result | notes |\n|---|---|---|\n"
    for p in "${SELECTED[@]}"; do
        printf '    %-20s %-12s %s\n' "$p" "${RESULTS[$idx]}" "${NOTES[$idx]}"
        md="$md| $p | ${RESULTS[$idx]} | ${NOTES[$idx]:-} |\n"
        [ "${RESULTS[$idx]}" = PASS ] || fail=1
        idx=$((idx + 1))
    done
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        { echo "### cairn EC2 AMI smoke — $RUN_ID"; echo ""; printf "$md"; echo ""; } \
            >> "$GITHUB_STEP_SUMMARY"
    fi
    return "$fail"
}

teardown() {
    local idx=0 id ids="" p
    trap - EXIT INT TERM
    [ -n "$RUN_ID" ] || return 0
    if [ "$KEEP" = 1 ]; then
        step "--keep: leaving instances + security group $SG_ID up"
        note "clean up later with: bash scripts/smoke-aws.sh sweep --hours 0"
        return 0
    fi
    for p in "${SELECTED[@]:-}"; do
        id=${INSTANCE_IDS[$idx]:-}
        if [ -n "$id" ] && [ "$(instance_state "$id")" != terminated ]; then
            ids="$ids $id"
        fi
        idx=$((idx + 1))
    done
    if [ -n "${ids// /}" ]; then
        step "terminating:$ids"
        # shellcheck disable=SC2086
        awsx ec2 terminate-instances --instance-ids $ids >/dev/null 2>&1 || true
        # shellcheck disable=SC2086
        awsx ec2 wait instance-terminated --instance-ids $ids 2>/dev/null || true
    fi
    if [ -n "$SG_ID" ]; then
        # ENIs release a minute or two after termination — retry the delete.
        local i=0
        while ! awsx ec2 delete-security-group --group-id "$SG_ID" >/dev/null 2>&1; do
            i=$((i + 1))
            [ "$i" -ge 12 ] && { warn "could not delete $SG_ID — run: smoke-aws.sh sweep"; return 0; }
            sleep 15
        done
        note "security group deleted"
    fi
}

cmd_run() {
    select_platforms
    RUN_ID=$(date +%Y%m%d-%H%M%S)-$$
    OUT_DIR="$REPO/smoke-out/aws/$RUN_ID"
    mkdir -p "$OUT_DIR"

    step "cairn EC2 AMI smoke — run $RUN_ID (account $ACCOUNT, region $REGION)"
    note "platforms: ${SELECTED[*]}"

    step "resolving AMIs"
    local p ami idx=0
    for p in "${SELECTED[@]}"; do
        ami=$(resolve_ami "$p")
        [ -n "$ami" ] && [ "$ami" != None ] || die "could not resolve an AMI for $p"
        platform_spec "$p"
        AMI_IDS+=("$ami")
        INSTANCE_IDS+=("")
        RESULTS+=(pending)
        NOTES+=("")
        note "$(printf '%-20s %-22s %-10s %s' "$p" "$ami" "$P_ITYPE" "$P_ARTGLOB")"
    done

    if [ "$DRY_RUN" = 1 ]; then
        step "--dry-run: stopping before any AWS resources are created"
        return 0
    fi

    # Infra must exist first — fail with instructions rather than silently
    # creating IAM from the run path.
    awsx s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1 \
        || die "bucket $BUCKET missing — run: bash scripts/smoke-aws.sh setup"
    awsx iam get-instance-profile --instance-profile-name "$INSTANCE_ROLE" >/dev/null 2>&1 \
        || die "instance profile $INSTANCE_ROLE missing — run: bash scripts/smoke-aws.sh setup"

    fetch_artifacts
    stage_to_s3
    trap teardown EXIT INT TERM
    create_sg

    step "launching ${#SELECTED[@]} instance(s)"
    idx=0
    for p in "${SELECTED[@]}"; do
        platform_spec "$p"
        local art
        art=$(basename "$(ls "$STAGE_DIR"/$P_ARTGLOB | head -n1)")
        launch_platform "$idx" "$p" "${AMI_IDS[$idx]}" "$(render_userdata "$p" "$art")"
        idx=$((idx + 1))
    done

    poll_loop
    teardown

    if print_summary; then
        printf '\nAWS SMOKE PASS: all %d platform(s)\n' "${#SELECTED[@]}"
    else
        printf '\nAWS SMOKE FAIL — see %s\n' "${OUT_DIR#"$REPO"/}"
        exit 1
    fi
}

case "$CMD" in
    setup) cmd_setup ;;
    sweep) cmd_sweep ;;
    run)   cmd_run ;;
esac
