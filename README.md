# treadmark — File Integrity Forensics for Linux & Windows

A treadmark is a stack of stones placed by trail-walkers to mark "I was here, and the ground was solid." This tool does the same thing for your filesystem: capture a known-good baseline of file hashes, metadata, and (optionally) text content. Later, when something happens, run a scan to see exactly what changed.

treadmark is a **forensic tool**, not a continuous monitor. You reach for it when:

- The EDR fired and you need to know what touched the system
- A user reports "the binary feels different"
- An auditor needs proof `/etc/sudoers` matches the approved version
- You're inheriting a server and want to see what the previous owner left behind
- Something is wrong and you need a list of facts about what's different from last week

If you want continuous monitoring with real-time alerting, who-data attribution, and a SIEM dashboard, run [Wazuh](https://wazuh.com/) or a commercial HIDS. treadmark fits in the gap where you want a single binary, no agent, no central server, and human-readable answers.

Single binary. No agent. No daemon. Same idea as AIDE / Tripwire with a saner package story and unified diffs of changed config files.

## Install

Pick one — they all give you the same `treadmark` command.

| Target | Artifact | Install |
|---|---|---|
| Debian / Ubuntu | `.deb` | `sudo apt install ./treadmark_X.Y.Z_amd64.deb` |
| RHEL / Rocky / Fedora | `.rpm` | `sudo dnf install ./treadmark-X.Y.Z-1.x86_64.rpm` |
| Locked-down Linux server | single binary | drop `treadmark-linux-x86_64` on the host |
| Windows | `.msi` | `msiexec /i treadmark-X.Y.Z.msi /qb` |
| Dev / pipx | wheel | `pipx install ./treadmark-X.Y.Z-py3-none-any.whl` |

Artifacts come from the GitHub Releases page, signed with `SHA256SUMS`.

## Folder layout

The installers create FHS-compliant locations:

| Purpose | Linux | Windows |
|---|---|---|
| Binary | `/usr/bin/treadmark` | `C:\Program Files\Treadmark\treadmark.exe` |
| Config | `/etc/treadmark/treadmark.yaml` | `C:\ProgramData\Treadmark\treadmark.yaml` |
| Baseline DB | `/var/lib/treadmark/baseline.db` | `C:\ProgramData\Treadmark\baseline.db` |

The config and baseline are preserved on uninstall and upgrade — operators have tuned them, the package manager doesn't get to clobber them.

## The two-step workflow

treadmark has exactly one operating model:

```
1. Capture baseline → 2. Run scan when investigating → (optional) update baseline
```

```sh
# On a known-good system, capture the baseline:
sudo $EDITOR /etc/treadmark/treadmark.yaml          # decide what to monitor
sudo treadmark files init --config /etc/treadmark/treadmark.yaml

# Save the baseline's provenance to your runbook (chain-of-custody):
sudo treadmark baseline info --config /etc/treadmark/treadmark.yaml > runbook/baseline-$(hostname).txt

# Later, when investigating: run a scan to see what changed:
sudo treadmark files scan --config /etc/treadmark/treadmark.yaml --report drift.md
```

That's it. No daemon, no scheduling, no reconciliation loop. See [`docs/forensic-workflow.md`](docs/forensic-workflow.md) for the full investigation guide.

## Unified diffs of changed configs

The default config enables `store_content: true`, which gzip-stores the contents of small text files in the baseline. When a config file changes, the scan shows you the actual diff:

```diff
~ /etc/ssh/sshd_config
    · content sha256 2f09c298cbfd…→f5ae63c1f343…
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

That's the difference between *something changed* and *the server was hardened backwards*.

There's a privacy tradeoff (the baseline now contains snapshots of your config files) — see [`docs/forensic-workflow.md`](docs/forensic-workflow.md) for the full discussion. Set `store_content: false` to disable.

## Subcommands

```
treadmark files       init|scan|update|verify       Filesystem snapshot + drift detection
treadmark registry    init|scan|update|verify       Windows registry baseline (Win only)
treadmark all         init|scan|update|verify       files + registry sequentially
treadmark baseline    info                          Provenance dump for chain-of-custody
treadmark compare     against <golden.db>           Compare host to a reference baseline
treadmark compare     baselines <a.db> <b.db>       Compare two baselines, no FS walk
```

`scan` exits 0 if the host matches the baseline, 1 if anything changed, 2 on error. Useful in scripts but not the point — the report content matters more.

## Output formats

`treadmark files scan` writes seven formats:

| Flag | Format | When |
|---|---|---|
| (default) | colorized terminal | reading on a TTY |
| `--report drift.json` | JSON document | jq, scripts, ad-hoc analysis |
| `--report drift.ndjson` | newline-delimited JSON | Splunk / Datadog / Elastic ingest |
| `--report drift.csv` | CSV (one row per change) | Excel, ServiceNow, audit packs |
| `--report drift.sarif` | SARIF | GitHub Code Scanning |
| `--report drift.md` | Markdown | tickets, postmortems, Slack pastes |
| `--report drift.html` | self-contained HTML | email, audit packets |
| `--report drift.txt` | plain text | grep, archive, copy anywhere |

See [`docs/output-formats.md`](docs/output-formats.md) for the full guide and automation recipes.

## Building from source

CI is the source of truth (`.github/workflows/release.yml`); local builds are best-effort. Releases are automated via [Conventional Commits](https://www.conventionalcommits.org/) — see [CONTRIBUTING.md](CONTRIBUTING.md). Every merge to `main` with a `feat:` or `fix:` commit cuts a release with all artifacts attached.

To reproduce locally:

```sh
# Linux (needs python3, dpkg-deb, rpmbuild)
bash scripts/build-linux.sh
# → dist/{*.whl, treadmark-linux-*, *.deb, *.rpm}

# Windows (needs Python 3.9+ and .NET SDK 6+)
.\scripts\build-windows.ps1
# → dist/{treadmark-windows-x86_64.exe, treadmark-*.msi}
```

See [`windows/README.md`](windows/README.md) for the WiX-specific build details.

## Documentation

- [`docs/forensic-workflow.md`](docs/forensic-workflow.md) — the investigation workflow, triage tips, what treadmark won't tell you
- [`docs/output-formats.md`](docs/output-formats.md) — every report format explained
- [`docs/golden-baseline-workflow.md`](docs/golden-baseline-workflow.md) — fleet-scale "golden image" comparisons
- [`windows/README.md`](windows/README.md) — MSI build, signing, customization
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — Conventional Commits, automated releases

## License

Apache License 2.0 — see [LICENSE](LICENSE).
