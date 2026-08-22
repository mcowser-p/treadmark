# Golden Baseline Workflow

Compare every server in your fleet against a known-good reference baseline. This is how you do file integrity monitoring at scale — instead of maintaining N independent baselines (and N change records, and N alert streams), you maintain one golden baseline per host role and compare every host against it.

## When to use this

**Good fits:**
- Stateless web/app servers behind a load balancer (all should be identical)
- Build agents
- Container hosts running the same image
- Domain controllers in the same forest
- Any "cattle, not pets" fleet

**Bad fits:**
- Database servers (data files diverge by design)
- Hosts with hostname-specific configs (`/etc/hostname`, TLS certs, machine IDs)
- Mixed OS versions (RHEL 8 vs RHEL 9 will show kernel/lib drift constantly)

For bad-fit hosts use the per-host baseline workflow (`treadmark files init` / `treadmark files scan`) instead.

## The two modes

### `treadmark compare against` — drift check on a live host

Walks the local filesystem and reports differences against a reference DB. Exit 0 = matches golden, exit 1 = drift.

```
treadmark compare against /opt/treadmark/golden-web.db --config /etc/treadmark/treadmark.yaml
```

### `treadmark compare baselines` — pure database diff

Diffs two DB files. No filesystem walk, no hashing, fast.

```
treadmark compare baselines /opt/treadmark/golden-web.db /var/lib/treadmark/baseline.db
```

Useful for:
- "How does prod-web-01 differ from prod-web-02?" (compare their baselines)
- "What changed between Tuesday's snapshot and Friday's?" (compare two snapshots of the same host)
- Audit: a third party can verify drift without filesystem access

## End-to-end golden image workflow

### 1. Build the golden baseline on a reference host

```bash
# On a freshly-provisioned, hardened, known-clean machine:
treadmark files init --config /etc/treadmark/treadmark.yaml
cp /var/lib/treadmark/baseline.db /opt/treadmark/golden-web-v1.0.db
```

Bake the version into the filename. Every config change, package update, or intentional deploy means a new golden baseline.

### 2. Sign and distribute it

```bash
sha256sum /opt/treadmark/golden-web-v1.0.db > golden-web-v1.0.db.sha256
gpg --detach-sign /opt/treadmark/golden-web-v1.0.db
```

Push to your config-management system (Ansible, Puppet, Chef, Salt) along with the .sig and .sha256. **Do not push it from the same channel that pushes your binaries** — if both are compromised, file integrity monitoring is theater.

### 3. Compare on every host

Cron / systemd timer / scheduled task on each server:

```bash
# Verify the golden baseline hasn't been tampered with in transit
sha256sum -c /opt/treadmark/golden-web-v1.0.db.sha256
gpg --verify /opt/treadmark/golden-web-v1.0.db.sig

# Compare and forward to SIEM
treadmark compare against /opt/treadmark/golden-web-v1.0.db \
    --config /etc/treadmark/treadmark.yaml \
    --json | logger -t treadmark-drift
```

Exit code 1 means drift. Wire it into your alerting.

### 4. Triage drift

When a host alerts, the JSON shows you exactly what changed. Three categories:

- **Expected drift** — package updates, log rotation, app deploys. Update the golden baseline (step 1) and roll out v1.1.
- **Acceptable host-specific drift** — hostname, IP-bound certs, machine-id. Add these to the `exclude:` list in `treadmark.yaml`.
- **Unexpected drift** — investigate immediately. This is what treadmark is for.

## Handling host-specific files

Some files legitimately differ per-host. The shipped `/etc/treadmark/treadmark.yaml`
already contains this list as a commented-out **"Golden-baseline / cross-host
compares"** block at the bottom of its `exclude:` section — uncomment it when
the config feeds cross-host compares. (It ships commented out because these
same files are legitimate tamper targets on a single host: a changed
`/etc/hosts` or SSH host key is exactly what a forensic scan should catch.)

Common offenders:

```yaml
exclude:
  - /etc/hostname
  - /etc/hosts                   # often has the host's own IP
  - /etc/machine-id
  - /etc/ssh/ssh_host_           # SSH host keys (per-machine)
  - /etc/cloud/                  # cloud-init runtime data
  - /var/lib/dbus/machine-id
  - /etc/iscsi/initiatorname.iscsi
  - /etc/krb5.keytab             # Kerberos host principal
```

For Windows web servers behind a load balancer:

```yaml
exclude:
  - \Windows\Panther\            # provisioning logs
  - \ProgramData\Microsoft\Crypto\RSA\MachineKeys\
  - \Windows\System32\config\TxR\
  - \Windows\System32\spp\store\  # activation tokens
```

Tune iteratively: run `treadmark compare against` on a known-clean host, anything flagged that *should* differ goes into `exclude:`, repeat until clean.

## Versioning the golden baseline

Treat golden baselines like any other artifact. Recommended:

```
/opt/treadmark/baselines/
├── web-debian12-v2026.05.04.db        # filename = role-os-date
├── web-debian12-v2026.05.04.db.sig
├── web-debian12-v2026.05.04.db.sha256
├── db-debian12-v2026.05.04.db
└── ...
```

A small `current` symlink (or registry value on Windows) lets the cron job always reach for the right one without hard-coding paths:

```bash
treadmark compare against /opt/treadmark/baselines/current.db --config /etc/treadmark/treadmark.yaml
```

## What about hosts that need their OWN baseline too?

Both workflows can coexist. A host can have a per-host baseline (`treadmark files scan` against its local `baseline.db`) AND be checked against the golden. The per-host baseline catches "did anything change since yesterday?", the golden catches "is this host still consistent with its peers?".

Run them in sequence:

```bash
treadmark files verify --config /etc/treadmark/treadmark.yaml \
    || logger -t treadmark-local "host changed since last update"

treadmark compare against /opt/treadmark/baselines/current.db --config /etc/treadmark/treadmark.yaml \
    || logger -t treadmark-drift "host diverges from golden"
```

## Compliance angle

Auditors love this pattern because it's evidence-friendly: "here is the golden baseline (signed, dated), here is the hourly diff against it (signed log lines), here is the ticket where each diff was reviewed and accepted or remediated." Maps cleanly onto PCI-DSS 11.5, NIST 800-53 SI-7, and CIS Controls 3.x and 4.x.
