# Output and report formats

`cairn files scan` produces output in seven formats. Pick the one that matches your downstream tooling — there's no single best choice.

## Quick reference

```sh
# Terminal (default; auto-colors when on a TTY)
cairn files scan --config /etc/cairn/cairn.yaml

# Write a report file (format auto-detected from extension)
cairn files scan --config /etc/cairn/cairn.yaml --report drift.json
cairn files scan --config /etc/cairn/cairn.yaml --report drift.ndjson
cairn files scan --config /etc/cairn/cairn.yaml --report drift.csv
cairn files scan --config /etc/cairn/cairn.yaml --report drift.sarif
cairn files scan --config /etc/cairn/cairn.yaml --report drift.md
cairn files scan --config /etc/cairn/cairn.yaml --report drift.html
cairn files scan --config /etc/cairn/cairn.yaml --report drift.txt

# Force a format regardless of extension
cairn files scan --config cairn.yaml --report drift.out --format ndjson

# Stream a format to stdout for piping
cairn files scan --config cairn.yaml --report - --format ndjson | logger -t cairn
```

You can also set a default report path in `cairn.yaml`:

```yaml
report:
  path: /var/lib/cairn/reports/latest.json
  format: json     # optional; inferred from path extension
```

CLI flags always override config defaults.

## When to use each format

### Machine-readable

#### `json` — single-document JSON
The default for ad-hoc processing. One large object with `summary`, `added`, `modified`, `deleted`. Easy to feed to `jq`, Python, Slack webhooks, Ansible.

```sh
cairn files scan --report drift.json
jq '.summary' drift.json
jq '.modified[].new.path' drift.json
```

#### `ndjson` — newline-delimited JSON
One event per line. The right format for log-aggregation pipelines (Splunk HEC, Datadog Agent, Vector, Fluent Bit, Loki). Each line is a complete, parseable JSON object — pipelines can ingest partial files and event-by-event.

The first line is always a `scan_summary` event so downstream tools can detect a complete scan. Then one line per added/modified/deleted file.

```sh
cairn files scan --report - --format ndjson | curl -X POST \
    -H "Authorization: Splunk $TOKEN" \
    -d @- https://splunk.example.com/services/collector
```

#### `csv` — row-per-change CSV
Auditor catnip. Opens cleanly in Excel and Google Sheets. Each row has an `event_type` column (`added`/`modified`/`deleted`) so you can pivot.

```sh
cairn files scan --report drift.csv
# Now drift.csv → email to compliance team → they pivot in Excel
```

Columns: `scanned_at, host, event_type, path, size_old, size_new, sha256_old, sha256_new, owner_old, owner_new, group_old, group_new, mode_old, mode_new, mtime_old, mtime_new, changes`

#### `sarif` — Static Analysis Results Interchange Format
Used by GitHub Code Scanning, Azure DevOps, Defect Dojo. Cairn maps its events to three SARIF rules:

| Rule ID | Severity | Triggers on |
|---|---|---|
| `cairn.file.added` | warning | A file appears that wasn't in the baseline |
| `cairn.file.modified` | error | Hash, size, permissions, or owner changed |
| `cairn.file.deleted` | warning | Baseline file is missing |

**Honest caveat:** SARIF is designed for code-quality findings (line numbers, fix suggestions). FIM events fit imperfectly. The output is good enough for SARIF-aware ingestion, but it won't surface as cleanly in GitHub's Code Scanning UI as a SAST tool would. Use it if you specifically want to feed FIM drift into a SARIF dashboard.

```sh
cairn files scan --report drift.sarif
gh api repos/owner/repo/code-scanning/sarifs --input drift.sarif
```

### Human-readable

#### `md` — Markdown
Best human-readable format. Renders in GitHub, GitLab, Slack, Confluence, Notion, and is plain text in a pinch. Includes a status line, summary table, and per-section tables for added/modified/deleted files.

Drop into an incident ticket or Slack channel to communicate "this is what changed."

```sh
cairn files scan --report drift.md
gh issue create --body-file drift.md --title "FIM drift on web-01"
```

#### `html` — Self-contained HTML
Inline CSS, no external dependencies. Suitable for emailing or attaching to audit packets. Color-coded by event type. Opens in any browser.

```sh
cairn files scan --report drift.html
mailx -s "FIM scan: $(hostname)" -a drift.html ops@example.com < /dev/null
```

#### `txt` — Plain text
ASCII tables, full hashes, no colors, no truncation. Different from terminal output: this is meant to be saved and grepped, not viewed live. Useful when you need a "blob of text I can paste anywhere."

## Terminal output

Without `--report`, scan output goes to the terminal. We auto-detect:

- **TTY** → colored output (green for added, yellow for modified, red for deleted)
- **Pipe / redirect** → no colors
- **`NO_COLOR=1`** → no colors (honored per [the convention](https://no-color.org))
- **`FORCE_COLOR=1`** → colors regardless of TTY

```sh
cairn files scan --config cairn.yaml                    # colors if TTY
cairn files scan --config cairn.yaml | tee scan.log     # no colors, log file readable
NO_COLOR=1 cairn files scan --config cairn.yaml         # never color
FORCE_COLOR=1 cairn files scan --config cairn.yaml | less -R   # colored even though piped
```

## Common automation patterns

### Run hourly, ship NDJSON to a SIEM

`/etc/cron.d/cairn-scan`:
```
15 * * * * root /usr/bin/cairn files verify --config /etc/cairn/cairn.yaml \
    --report - --format ndjson | logger -t cairn-drift
```

`logger -t cairn-drift` writes to syslog with a tag your aggregator can route on.

### Run hourly, write a report, alert if drift

```sh
#!/bin/sh
# /usr/local/bin/cairn-watch
set -e
REPORT=/var/lib/cairn/reports/$(date +%Y%m%d-%H%M).json
cairn files scan --config /etc/cairn/cairn.yaml --report "$REPORT"
if [ $? -eq 1 ]; then
    # Drift detected; alert
    cairn files scan --config /etc/cairn/cairn.yaml --report - --format md \
        | curl -X POST -H 'Content-type: application/json' \
            --data-binary @- https://hooks.slack.com/services/...
fi
```

### CI: fail a deploy if the build server has drifted

```yaml
- name: FIM check before deploy
  run: |
    cairn files verify --config /etc/cairn/cairn.yaml \
        --report cairn-drift.sarif --format sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: cairn-drift.sarif
```

The drift becomes a finding in GitHub's Security tab.

### Audit: monthly Excel report

```sh
# In a monthly cron
cairn files scan --config /etc/cairn/cairn.yaml \
    --report /srv/audit/$(date +%Y-%m)-cairn.csv

# Compliance team picks it up via SMB / Confluence / wherever
```

## Exit codes

Every output format respects the same exit codes:

| Code | Meaning |
|---|---|
| 0 | Clean — host matches baseline |
| 1 | Drift — at least one file added/modified/deleted |
| 2 | Error — bad config, missing baseline, etc. |

This matches what cron, systemd `ExecStart`, monitoring agents, and CI runners expect. Wire your alerting to "exit code 1" and you're done.
