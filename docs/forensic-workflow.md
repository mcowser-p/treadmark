# Forensic Workflow

cairn is a forensic tool. You run it after something has happened — to answer the question "what changed on this system since it was last known-good?"

It does **not** run on a schedule. It does **not** continuously monitor. It does **not** alert. Those are the jobs of an HIDS/EDR/SIEM. cairn is what an admin reaches for when the EDR fired, when the user complained, when the box is acting weird, or when a regulator asks "prove this server hasn't been tampered with."

## The mental model

```
┌─────────────────┐                    ┌─────────────────┐
│ System known    │     time passes    │ Something       │
│ to be good      │ ─────────────────► │ happened.       │
│ (post-deploy,   │                    │ Investigate.    │
│  post-harden,   │                    │                 │
│  post-audit)    │                    │                 │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
   capture baseline                       run scan
   cairn files init                       cairn files scan
         │                                      │
         ▼                                      ▼
   /var/lib/cairn/baseline.db            drift report
   (evidence; protect it)                (what changed,
                                          when, by how much)
```

Two phases. The baseline is the "before." The scan is the "after." Everything else is plumbing.

## When to run `init`

You run `cairn files init` **once**, on a system you've decided is the reference state. Common moments:

- **Right after provisioning** a server, before it sees production traffic
- **Right after hardening** (CIS benchmark applied, firewall rules locked down, sshd config tightened)
- **Right after a clean patch cycle** completes
- **Right after a security audit** signs off
- **Right after an incident response** declares the system clean

Whatever moment you pick, document it. The baseline's value as forensic evidence depends on knowing what state it represents.

```sh
# On the reference host:
sudo cairn files init --config /etc/cairn/cairn.yaml
sudo cairn baseline info --config /etc/cairn/cairn.yaml > /etc/cairn/baseline-provenance.txt
```

That second line saves the baseline's metadata (creation time, host, OS, DB hash) to a file you can attach to a change ticket or audit packet.

## Protect the baseline

The baseline is your evidence. If an attacker rewrites it, your future scans become theater. Three precautions, in order of importance:

1. **Lock down the file.** The package installer creates `/var/lib/cairn/` with mode 0700, root-only. Don't loosen that. On Windows the MSI sets a DACL allowing only Administrators and SYSTEM.

2. **Hash it offline.** After `init`, record the DB's SHA-256 somewhere outside the host:
   ```sh
   sudo cairn baseline info --config /etc/cairn/cairn.yaml --json \
       | jq -r '.db_sha256' \
       | tee /tmp/cairn-baseline.sha256
   # Now copy /tmp/cairn-baseline.sha256 to your runbook, ticket, or vault.
   ```
   When you run a scan months later, recompute the hash with `sha256sum /var/lib/cairn/baseline.db` and confirm it matches. If it doesn't, the baseline was tampered with and the scan output cannot be trusted.

3. **Consider an out-of-band copy.** For high-value hosts (domain controllers, build servers, secrets stores), copy the baseline DB to read-only storage (S3 with object lock, an ops vault, even a printed QR code of the SHA-256). Rerun scans against the offline copy if the on-host one is suspect.

## When to run `scan`

You run `cairn files scan` when you have a question. Examples:

- The EDR fired on `web-04`. What's been touched since last week's deploy?
- The user reports "the binary feels different." Has it been replaced?
- An auditor needs proof that `/etc/sudoers` hasn't changed since approval.
- You're inheriting a server and want to see if the previous owner left any surprises.

```sh
# Human-readable terminal output:
sudo cairn files scan --config /etc/cairn/cairn.yaml

# Drop a Markdown report into an incident ticket:
sudo cairn files scan --config /etc/cairn/cairn.yaml --report /tmp/$(hostname)-drift-$(date +%Y%m%d-%H%M).md

# Hand a CSV to compliance:
sudo cairn files scan --config /etc/cairn/cairn.yaml --report /tmp/audit.csv

# Get JSON for a runbook script:
sudo cairn files scan --config /etc/cairn/cairn.yaml --report /tmp/drift.json
```

Exit code is 0 if the host matches the baseline, 1 if anything changed. Useful in scripts but not the point — the report content matters more.

## Reading a scan report

A scan tells you four things:

1. **Added** — files present now that weren't in the baseline. New shells, new cron entries, new world-writable scripts in `/tmp` are interesting. New log rotations are usually noise.

2. **Modified** — files whose contents, permissions, or ownership changed.

3. **Deleted** — baseline files that are gone now. Missing log files are normal; missing binaries are not.

4. **Unified diff** (when content storage is enabled) — for changed text files, the actual line-level changes. This is the headline feature for forensic work.

Without diffs, modifying `sshd_config` shows up as "sha256 changed." With diffs enabled in your config, you see:

```diff
--- baseline:/etc/ssh/sshd_config
+++ current:/etc/ssh/sshd_config
@@ -1,4 +1,5 @@
-PermitRootLogin no
-PasswordAuthentication no
+PermitRootLogin yes
+PasswordAuthentication yes
 PubkeyAuthentication yes
-Port 22
+Port 2222
+PermitEmptyPasswords yes
```

That's the difference between "something changed" and "the server was hardened backwards." Enable in your config:

```yaml
store_content: true
store_content_max_kb: 256
```

There's a tradeoff — see "Content storage tradeoff" below.

## Triaging changes

Scans produce noise. Real forensic work is mostly figuring out which entries matter. Some heuristics:

**Almost always benign:**
- `mtime` changes on directory entries (filesystem updated, file inside changed)
- Log files (`/var/log/*`)
- Package manager databases (`/var/lib/dpkg/`, `/var/lib/rpm/`)
- Cache files (`/var/cache/`)
- Kernel modules added by routine `apt upgrade`

**Worth a closer look:**
- Owner/group changes on system binaries (`chown root:wheel /bin/sh` is a classic backdoor setup)
- Mode changes that grant new write or execute (`chmod 4755` adding suid)
- New files in `/etc/cron.*`, `/etc/init.d`, `/etc/systemd/system`
- Changes to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/`
- New shells in `/etc/shells`
- Changes to PAM config (`/etc/pam.d/`)
- New SUID/SGID binaries anywhere

**Almost always bad:**
- Modified system binaries (`/bin/ls`, `/usr/sbin/sshd`)
- New world-writable directories or files in privileged locations
- Files with mtime in the future or matching suspicious incident windows
- Changes to `/root/.ssh/authorized_keys`

If a scan flags something in the third category, **stop running cairn and start running incident response.** cairn told you what; IR is for who and how.

## Content storage tradeoff

`store_content: true` is the difference between "useful FIM" and "useful forensic tool." But it has real costs:

| | `store_content: false` | `store_content: true` |
|---|---|---|
| Detect change | ✓ | ✓ |
| Show what line changed | ✗ | ✓ |
| Baseline DB size (typical /etc) | ~500 KB | ~3-8 MB |
| Baseline contains sensitive data | No (just hashes) | **Yes** (config, keys, anything text) |
| init speed | Fast | ~10% slower |
| scan speed | Same | Same |

The privacy implication is the one to think about. If your baseline contains the actual contents of `/etc/shadow`, `/etc/ssh/ssh_host_*_key`, `/root/.ssh/authorized_keys`, and any application config with embedded secrets, then your baseline DB is now sensitive in a way it wasn't before. The DB's 0700 root-only permissions still protect it, but:

- A compromised root account that wouldn't have had time to read every config file individually now has them all in one DB
- Backups of `/var/lib/cairn/` are now sensitive
- A baseline copied off-host for safekeeping is now a sensitive artifact

You can selectively enable content storage for non-sensitive paths only by maintaining two configs and two baselines — one with `store_content: true` for `/etc/sshd_config`, `/etc/sudoers`, `/etc/cron.*`, and one with `store_content: false` for everything else. Most environments don't bother and just lock down the baseline.

If you can't accept the privacy tradeoff, set `store_content: false` and live with sha256-level diffs. cairn still tells you what changed, just not what line.

## End-to-end investigation example

A scenario: monitoring fired on `web-04` overnight. You have a baseline from last week's deploy.

```sh
# 1. Verify the baseline hasn't been tampered with
ssh web-04 sudo sha256sum /var/lib/cairn/baseline.db
# Compare to the value you saved in your runbook after init.

# 2. Run the scan with a markdown report
ssh web-04 sudo cairn files scan --config /etc/cairn/cairn.yaml \
    --report /tmp/web-04-$(date +%s).md
ssh web-04 sudo cat /tmp/web-04-*.md > web-04-drift.md

# 3. Open web-04-drift.md in your browser via the Markdown preview, or
#    paste into your incident ticket for color rendering.

# 4. Triage the report. Anything in the "Almost always bad" category
#    above? Stop and escalate to IR.

# 5. If everything's explained (planned change, package update, etc.),
#    accept those specific changes into the baseline so they don't appear
#    on future scans. cairn requires you to be explicit about what you
#    accept — see "Accepting expected changes" below.
ssh web-04 sudo cairn files update --config /etc/cairn/cairn.yaml \
    --accept /etc/cron.d/myapp \
    --accept-from runbook/january-patch-accepted.list \
    --dry-run                                          # preview first
ssh web-04 sudo cairn files update --config /etc/cairn/cairn.yaml \
    --accept /etc/cron.d/myapp \
    --accept-from runbook/january-patch-accepted.list  # then apply

ssh web-04 sudo cairn baseline info --config /etc/cairn/cairn.yaml \
    > runbook/web-04-baseline-2026-05.txt
```

That last step matters: an updated baseline needs new provenance. Save the new SHA-256 to your runbook so the next scan can verify against it.

## Accepting expected changes

If a scan flags drift you understand and accept (planned package upgrade, deliberate config change, scheduled deploy), `cairn files update` rewrites the matching baseline entries so those files don't appear on future scans. cairn requires you to be explicit about what you're accepting — it does **not** silently accept all changes, because that would erase the forensic record of what changed.

```sh
# Accept changes to one specific file
cairn files update --config /etc/cairn/cairn.yaml --accept /etc/sshd_config

# Accept everything beneath a directory (e.g. after a planned package upgrade)
cairn files update --config /etc/cairn/cairn.yaml --accept /usr/lib/firefox

# Read accept paths from a file (good for review-then-apply workflows)
cairn files update --config /etc/cairn/cairn.yaml --accept-from accepted.list

# Preview without writing — recommended before any non-trivial accept
cairn files update --config /etc/cairn/cairn.yaml \
    --accept /etc/sshd_config --dry-run

# Last resort: accept everything (erases evidence of what changed)
cairn files update --config /etc/cairn/cairn.yaml --accept-all
```

The `--accept-from` file is a plain text file with one path per line. Lines starting with `#` are ignored, blank lines are ignored. Useful for review workflows: an admin reviews the scan output, copies the paths they've explained into the file, optionally adds a comment per group, then applies. Example:

```
# Monthly patch — ticket OPS-4421
/usr/lib/firefox
/usr/share/firefox

# Approved change request CR-2026-051
/etc/sshd_config
```

Path matching: an `--accept` argument that's a file matches that exact file; an argument that's a directory matches everything beneath. Paths are normalized so `/etc/cron.d/`, `/etc/cron.d`, and a relative path that resolves to the same place all behave identically.

Running `update` without `--accept`, `--accept-from`, or `--accept-all` is an error.

After accepting, **save the baseline's new SHA-256 to your runbook**. The baseline has changed, so the previous integrity hash no longer applies:

```sh
cairn baseline info --config /etc/cairn/cairn.yaml --json \
    | jq -r '.db_sha256' \
    > runbook/baseline-$(hostname)-$(date +%F).sha256
```

## What cairn won't tell you

Be honest about the tool's limits:

- **Who made the change.** cairn knows the file changed; it doesn't know what process or user. For that you need auditd, eBPF, ETW, or a full HIDS like Wazuh.
- **When the change happened.** cairn knows the file is different than at baseline time; it can't tell you whether it changed yesterday or three months ago. mtime gives you a hint but is trivially forged.
- **Whether the change was authorized.** That's a human judgment call. cairn surfaces facts; the operator interprets them.
- **Whether the system is still compromised.** A scan only covers monitored paths. An attacker who modified `/etc/sshd_config` (monitored) and dropped a binary in `/opt/secret-payload/` (unmonitored) shows only the first change. Be paranoid about coverage.

## Compliance angle

For PCI-DSS 11.5, NIST 800-53 SI-7, CIS Controls 3.x and 4.x, the auditor wants to see:

1. **A baseline exists and is dated.** `cairn baseline info` provides this.
2. **The baseline's integrity is verifiable.** The DB SHA-256 in the provenance dump is the chain-of-custody anchor.
3. **Drift was reviewed.** Periodic `cairn files scan` runs with reports archived to a ticket system gives you the audit trail.
4. **Discrepancies were remediated or accepted.** That's a process question, not a tool question — but the cairn report is the artifact you attach to whatever ticket records the decision.

You don't need scheduled scans to satisfy these controls. You need *evidence of periodic review*, which can be quarterly manual scans documented in tickets. Scheduling is one way to produce that evidence; running `cairn files scan` before each compliance attestation is another.
