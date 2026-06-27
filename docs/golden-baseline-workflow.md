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

For bad-fit hosts use the per-host baseline workflow (`cairn files init` / `cairn files scan`) instead.

## The two modes

### `cairn compare against` — drift check on a live host

Walks the local filesystem and reports differences against a reference DB. Exit 0 = matches golden, exit 1 = drift.

```
cairn compare against /opt/cairn/golden-web.db --config /etc/cairn/cairn.yaml
```

### `cairn compare baselines` — pure database diff

Diffs two DB files. No filesystem walk, no hashing, fast.

```
cairn compare baselines /opt/cairn/golden-web.db /var/lib/cairn/baseline.db
```

Useful for:
- "How does prod-web-01 differ from prod-web-02?" (compare their baselines)
- "What changed between Tuesday's snapshot and Friday's?" (compare two snapshots of the same host)
- Audit: a third party can verify drift without filesystem access

## End-to-end golden image workflow

### 1. Build the golden baseline on a reference host

```bash
# On a freshly-provisioned, hardened, known-clean machine:
cairn files init --config /etc/cairn/cairn.yaml
cp /var/lib/cairn/baseline.db /opt/cairn/golden-web-v1.0.db
```

Bake the version into the filename. Every config change, package update, or intentional deploy means a new golden baseline.

### 2. Sign and distribute it

```bash
sha256sum /opt/cairn/golden-web-v1.0.db > golden-web-v1.0.db.sha256
gpg --detach-sign /opt/cairn/golden-web-v1.0.db
```

Push to your config-management system (Ansible, Puppet, Chef, Salt) along with the .sig and .sha256. **Do not push it from the same channel that pushes your binaries** — if both are compromised, file integrity monitoring is theater.

### 3. Compare on every host

Cron / systemd timer / scheduled task on each server:

```bash
# Verify the golden baseline hasn't been tampered with in transit
sha256sum -c /opt/cairn/golden-web-v1.0.db.sha256
gpg --verify /opt/cairn/golden-web-v1.0.db.sig

# Compare and forward to SIEM
cairn compare against /opt/cairn/golden-web-v1.0.db \
    --config /etc/cairn/cairn.yaml \
    --json | logger -t cairn-drift
```

Exit code 1 means drift. Wire it into your alerting.

### 4. Triage drift

When a host alerts, the JSON shows you exactly what changed. Three categories:

- **Expected drift** — package updates, log rotation, app deploys. Update the golden baseline (step 1) and roll out v1.1.
- **Acceptable host-specific drift** — hostname, IP-bound certs, machine-id. Add these to the `exclude:` list in `cairn.yaml`.
- **Unexpected drift** — investigate immediately. This is what cairn is for.

## Handling host-specific files

Some files legitimately differ per-host. Common offenders:

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

Tune iteratively: run `cairn compare against` on a known-clean host, anything flagged that *should* differ goes into `exclude:`, repeat until clean.

## Versioning the golden baseline

Treat golden baselines like any other artifact. Recommended:

```
/opt/cairn/baselines/
├── web-debian12-v2026.05.04.db        # filename = role-os-date
├── web-debian12-v2026.05.04.db.sig
├── web-debian12-v2026.05.04.db.sha256
├── db-debian12-v2026.05.04.db
└── ...
```

A small `current` symlink (or registry value on Windows) lets the cron job always reach for the right one without hard-coding paths:

```bash
cairn compare against /opt/cairn/baselines/current.db --config /etc/cairn/cairn.yaml
```

## What about hosts that need their OWN baseline too?

Both workflows can coexist. A host can have a per-host baseline (`cairn files scan` against its local `baseline.db`) AND be checked against the golden. The per-host baseline catches "did anything change since yesterday?", the golden catches "is this host still consistent with its peers?".

Run them in sequence:

```bash
cairn files verify --config /etc/cairn/cairn.yaml \
    || logger -t cairn-local "host changed since last update"

cairn compare against /opt/cairn/baselines/current.db --config /etc/cairn/cairn.yaml \
    || logger -t cairn-drift "host diverges from golden"
```

## Compliance angle

Auditors love this pattern because it's evidence-friendly: "here is the golden baseline (signed, dated), here is the hourly diff against it (signed log lines), here is the ticket where each diff was reviewed and accepted or remediated." Maps cleanly onto PCI-DSS 11.5, NIST 800-53 SI-7, and CIS Controls 3.x and 4.x.
