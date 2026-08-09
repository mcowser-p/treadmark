"""cairn.report — render scan results in multiple formats.

The scan logic produces a ScanResult; renderers turn that into bytes for
each supported format. This separation keeps scan code free of formatting
concerns and makes adding a new format a matter of writing one renderer.

Supported formats (auto-detected from file extension, or via --format):
    json        single-document JSON, easiest for ad-hoc / jq processing
    ndjson      one event per line, what every log pipeline wants
    csv         row-per-change with event_type column, opens in Excel
    sarif       Static Analysis Results Interchange Format, for GitHub
                Security tab integration. Caveat: cairn's events fit the
                SARIF schema imperfectly; treat the SARIF output as
                "good enough for ingest" rather than canonical.
    md          Markdown — best human format for tickets, postmortems,
                Slack/Confluence pastes
    html        Self-contained HTML with inline styles, suitable for
                emailing or attaching to audit packets
    txt         Plain text with ASCII tables, no colors, no truncation —
                meant to be saved and grepped (NOT the same as terminal output)
"""

from __future__ import annotations

import csv as csv_module
import io
import json
import os
import platform
import re
import socket
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .files import FileRecord


# ---------------------------------------------------------------------------
# Canonical scan result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Everything a renderer needs to produce output. Built once by cmd_scan,
    consumed by zero or more renderers."""
    scanned_at: str                                  # ISO 8601 UTC
    host: str
    db_path: str
    added:    list["FileRecord"]                     = field(default_factory=list)
    modified: list[tuple["FileRecord", "FileRecord", list[str]]] = field(default_factory=list)
    deleted:  list["FileRecord"]                     = field(default_factory=list)
    errors:   list[str]                              = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return bool(self.added or self.modified or self.deleted)

    @property
    def summary_counts(self) -> dict[str, int]:
        return {
            "added":    len(self.added),
            "modified": len(self.modified),
            "deleted":  len(self.deleted),
            "errors":   len(self.errors),
        }


# ---------------------------------------------------------------------------
# Format dispatch
# ---------------------------------------------------------------------------

def _try_diff(old, new) -> Optional[str]:
    """Wrap files.unified_diff_for safely. Returns None if either side
    has no stored content or anything goes wrong."""
    try:
        from . import files as files_mod
        return files_mod.unified_diff_for(old, new)
    except Exception:
        return None


# Maps file extension → format name. Used for --report path.json auto-detect.
EXT_TO_FORMAT = {
    ".json":   "json",
    ".ndjson": "ndjson",
    ".jsonl":  "ndjson",
    ".csv":    "csv",
    ".sarif":  "sarif",
    ".md":     "md",
    ".markdown": "md",
    ".html":   "html",
    ".htm":    "html",
    ".txt":    "txt",
}

VALID_FORMATS = {"json", "ndjson", "csv", "sarif", "md", "html", "txt"}


def detect_format(path: str, explicit: Optional[str]) -> str:
    """Pick a format. Explicit --format wins; else infer from extension; else json."""
    if explicit:
        if explicit not in VALID_FORMATS:
            raise ValueError(f"unknown format: {explicit!r}; "
                             f"valid: {sorted(VALID_FORMATS)}")
        return explicit
    ext = os.path.splitext(path)[1].lower()
    return EXT_TO_FORMAT.get(ext, "json")


def render(result: ScanResult, fmt: str) -> str:
    """Render a ScanResult to a string in the requested format."""
    if fmt == "json":   return _render_json(result)
    if fmt == "ndjson": return _render_ndjson(result)
    if fmt == "csv":    return _render_csv(result)
    if fmt == "sarif":  return _render_sarif(result)
    if fmt == "md":     return _render_markdown(result)
    if fmt == "html":   return _render_html(result)
    if fmt == "txt":    return _render_plaintext(result)
    raise ValueError(f"unknown format: {fmt}")


def write_report(result: ScanResult, path: str, fmt: Optional[str] = None) -> str:
    """Render and write to disk. Returns the format used."""
    actual_fmt = detect_format(path, fmt)
    body = render(result, actual_fmt)
    # Write atomically: temp file + rename. Avoids partial reads if a SIEM
    # is tailing the file at the same time we're writing.
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(body)
    os.replace(tmp, path)
    return actual_fmt


# ---------------------------------------------------------------------------
# JSON / NDJSON
# ---------------------------------------------------------------------------

def _record_dict(rec) -> dict:
    """Convert a FileRecord to a plain dict, with the hash readable.
    Strips the binary content_gz field — that's only useful inside the
    baseline DB, not in JSON output."""
    d = asdict(rec)
    d.pop("content_gz", None)
    return d


def _modification_dict(old, new, changes: list[str]) -> dict:
    out = {"old": _record_dict(old), "new": _record_dict(new), "changes": changes}
    diff = _try_diff(old, new)
    if diff:
        out["unified_diff"] = diff
    return out


def _common_envelope(result: ScanResult) -> dict:
    """The non-event metadata that every report includes up top."""
    return {
        "scanned_at":     result.scanned_at,
        "host":           result.host,
        "db_path":        result.db_path,
        "tool":           "cairn",
        "summary":        result.summary_counts,
        "has_drift":      result.has_drift,
    }


def _render_json(result: ScanResult) -> str:
    payload = _common_envelope(result)
    payload["added"]    = [_record_dict(r)             for r in result.added]
    payload["modified"] = [_modification_dict(o, n, c) for (o, n, c) in result.modified]
    payload["deleted"]  = [_record_dict(r)             for r in result.deleted]
    if result.errors:
        payload["errors"] = result.errors
    return json.dumps(payload, indent=2, default=str) + "\n"


def _render_ndjson(result: ScanResult) -> str:
    """One event per line. Each line is a self-contained JSON object that
    a log pipeline can ingest independently. Includes a leading 'summary'
    event so downstream tools can detect a complete scan."""
    out: list[str] = []
    common = {
        "scanned_at": result.scanned_at,
        "host":       result.host,
        "tool":       "cairn",
    }

    # Summary line first — log pipelines can use this to reconcile counts.
    summary = {**common, "event": "scan_summary", **result.summary_counts,
               "has_drift": result.has_drift}
    out.append(json.dumps(summary, default=str))

    for rec in result.added:
        out.append(json.dumps({**common, "event": "file_added", **_record_dict(rec)},
                              default=str))
    for (old, new, changes) in result.modified:
        evt = {**common, "event": "file_modified",
               "path": new.path, "changes": changes,
               "old": _record_dict(old), "new": _record_dict(new)}
        diff = _try_diff(old, new)
        if diff:
            evt["unified_diff"] = diff
        out.append(json.dumps(evt, default=str))
    for rec in result.deleted:
        out.append(json.dumps({**common, "event": "file_deleted", **_record_dict(rec)},
                              default=str))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "scanned_at", "host", "event_type", "path",
    "size_old", "size_new",
    "sha256_old", "sha256_new",
    "owner_old", "owner_new",
    "group_old", "group_new",
    "mode_old", "mode_new",
    "mtime_old", "mtime_new",
    "changes",
    "unified_diff",
]


def _csv_row(result: ScanResult, event_type: str,
             old=None, new=None, changes: Optional[list[str]] = None,
             diff: Optional[str] = None) -> dict:
    """Build a flat dict suitable for csv.DictWriter."""
    primary = new or old   # for added/deleted, only one side exists
    return {
        "scanned_at": result.scanned_at,
        "host":       result.host,
        "event_type": event_type,
        "path":       primary.path if primary else "",
        "size_old":   old.size       if old else "",
        "size_new":   new.size       if new else "",
        "sha256_old": old.sha256     if old else "",
        "sha256_new": new.sha256     if new else "",
        "owner_old":  old.owner      if old else "",
        "owner_new":  new.owner      if new else "",
        "group_old":  old.group      if old else "",
        "group_new":  new.group      if new else "",
        "mode_old":   oct(old.mode)  if old else "",
        "mode_new":   oct(new.mode)  if new else "",
        "mtime_old":  _fmt_mtime(old.mtime) if old else "",
        "mtime_new":  _fmt_mtime(new.mtime) if new else "",
        "changes":    "; ".join(changes) if changes else "",
        "unified_diff": diff or "",
    }


def _render_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    w = csv_module.DictWriter(buf, fieldnames=CSV_COLUMNS, lineterminator="\n",
                              quoting=csv_module.QUOTE_MINIMAL)
    w.writeheader()
    for rec in result.added:
        w.writerow(_csv_row(result, "added", new=rec))
    for (old, new, changes) in result.modified:
        diff = _try_diff(old, new)
        w.writerow(_csv_row(result, "modified", old=old, new=new,
                            changes=changes, diff=diff))
    for rec in result.deleted:
        w.writerow(_csv_row(result, "deleted", old=rec))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------
# Caveat: SARIF is designed for code-quality findings with line numbers and
# rules. cairn's events ("file's hash changed") fit imperfectly — we map
# each event type to a SARIF rule with severity, and use the file path as
# the result location. The output is good enough for SARIF-aware ingestion
# (GitHub Code Scanning, Azure DevOps, Defect Dojo) but isn't going to look
# as native as a SAST tool's output.

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SARIF_RULES = [
    {
        "id":   "cairn.file.added",
        "name": "FileAdded",
        "shortDescription": {"text": "A file appeared that was not in the baseline."},
        "fullDescription":  {"text": "Indicates a new file was created in a monitored path since the baseline was captured. Investigate whether the addition is expected."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id":   "cairn.file.modified",
        "name": "FileModified",
        "shortDescription": {"text": "A file's content or metadata changed."},
        "fullDescription":  {"text": "The hash, size, permissions, or ownership of a monitored file changed since the baseline."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id":   "cairn.file.deleted",
        "name": "FileDeleted",
        "shortDescription": {"text": "A file present in the baseline is missing."},
        "fullDescription":  {"text": "A file that existed when the baseline was captured is no longer present in the monitored path."},
        "defaultConfiguration": {"level": "warning"},
    },
]


def _sarif_result(rule_id: str, level: str, message: str, path: str) -> dict:
    # locations.physicalLocation expects a URI; use file:// for absolute paths.
    uri = path
    if uri.startswith("/") or (len(uri) > 2 and uri[1] == ":"):
        # Absolute path — wrap as file URI
        uri = "file://" + uri.replace("\\", "/")
    return {
        "ruleId":  rule_id,
        "level":   level,
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
            },
        }],
    }


def _render_sarif(result: ScanResult) -> str:
    findings: list[dict] = []
    for rec in result.added:
        findings.append(_sarif_result(
            "cairn.file.added", "warning",
            f"File appeared since baseline: {rec.path} (size {rec.size}, owner {rec.owner})",
            rec.path,
        ))
    for (old, new, changes) in result.modified:
        msg = f"File changed since baseline: {new.path} ({'; '.join(changes)})"
        diff = _try_diff(old, new)
        if diff:
            msg += "\n\n" + diff
        findings.append(_sarif_result(
            "cairn.file.modified", "error", msg, new.path,
        ))
    for rec in result.deleted:
        findings.append(_sarif_result(
            "cairn.file.deleted", "warning",
            f"File missing since baseline: {rec.path}",
            rec.path,
        ))

    sarif = {
        "version":  SARIF_VERSION,
        "$schema":  SARIF_SCHEMA,
        "runs": [{
            "tool": {
                "driver": {
                    "name":    "cairn",
                    "informationUri": "https://github.com/mcowser-p/cairn",
                    "rules":   SARIF_RULES,
                },
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": result.scanned_at,
                "machine":    result.host,
            }],
            "results": findings,
        }],
    }
    return json.dumps(sarif, indent=2, default=str) + "\n"


# ---------------------------------------------------------------------------
# Plain text
# ---------------------------------------------------------------------------

def _fmt_mtime(epoch: float) -> str:
    """Format an epoch timestamp as a human-readable UTC string."""
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, ValueError):
        return str(epoch)


def _fmt_size(n: int) -> str:
    """Human-readable size: 1.2 MB, 4.5 KB, etc."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024  # type: ignore
    return f"{n:.1f} PB"


def _fmt_mode(mode: int) -> str:
    """Convert a stat.st_mode integer to drwxr-xr-x style — same logic as stat.filemode."""
    import stat
    return stat.filemode(mode) if mode else ""


def _render_plaintext(result: ScanResult) -> str:
    s = result.summary_counts
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append(f"  Cairn File Integrity Scan Report")
    lines.append("=" * 78)
    lines.append(f"Scanned at: {result.scanned_at}")
    lines.append(f"Host:       {result.host}")
    lines.append(f"Baseline:   {result.db_path}")
    lines.append(f"Status:     {'DRIFT DETECTED' if result.has_drift else 'CLEAN'}")
    lines.append("")
    lines.append(f"Summary:    {s['added']} added, {s['modified']} modified, "
                 f"{s['deleted']} deleted")
    lines.append("")

    if result.added:
        lines.append("-" * 78)
        lines.append("ADDED FILES")
        lines.append("-" * 78)
        for rec in result.added:
            lines.append(f"  + {rec.path}")
            lines.append(f"      size:  {_fmt_size(rec.size)}")
            lines.append(f"      owner: {rec.owner}:{rec.group}")
            lines.append(f"      mode:  {_fmt_mode(rec.mode)}")
            if rec.sha256:
                lines.append(f"      sha256: {rec.sha256}")
            lines.append(f"      mtime: {_fmt_mtime(rec.mtime)}")
            lines.append("")

    if result.modified:
        lines.append("-" * 78)
        lines.append("MODIFIED FILES")
        lines.append("-" * 78)
        for (old, new, changes) in result.modified:
            lines.append(f"  ~ {new.path}")
            for c in changes:
                lines.append(f"      · {c}")
            if old.sha256 and new.sha256 and old.sha256 != new.sha256:
                lines.append(f"      sha256 (old): {old.sha256}")
                lines.append(f"      sha256 (new): {new.sha256}")
            diff = _try_diff(old, new)
            if diff:
                lines.append("")
                lines.append("      unified diff:")
                for dl in diff.splitlines():
                    lines.append(f"        {dl}")
            lines.append("")

    if result.deleted:
        lines.append("-" * 78)
        lines.append("DELETED FILES")
        lines.append("-" * 78)
        for rec in result.deleted:
            lines.append(f"  - {rec.path}")
            lines.append(f"      was: {_fmt_size(rec.size)}, owner {rec.owner}:{rec.group}")
            lines.append("")

    if not result.has_drift:
        lines.append("No changes detected. ✓")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _md_escape(s: str) -> str:
    """Escape pipe characters so they don't break table cells."""
    return s.replace("|", "\\|")


def _short_hash(h: Optional[str]) -> str:
    return (h[:12] + "…") if h and len(h) > 12 else (h or "")


def _render_markdown(result: ScanResult) -> str:
    s = result.summary_counts
    status_emoji = "🔴" if result.has_drift else "✅"
    lines: list[str] = []
    lines.append(f"# Cairn Scan Report")
    lines.append("")
    lines.append(f"**Status:** {status_emoji} {'Drift detected' if result.has_drift else 'Clean'}")
    lines.append(f"**Host:** `{result.host}`  ")
    lines.append(f"**Scanned at:** {result.scanned_at}  ")
    lines.append(f"**Baseline:** `{result.db_path}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| | Count |")
    lines.append("|---|---:|")
    lines.append(f"| Added    | {s['added']} |")
    lines.append(f"| Modified | {s['modified']} |")
    lines.append(f"| Deleted  | {s['deleted']} |")
    lines.append("")

    if result.added:
        lines.append(f"## Added ({len(result.added)})")
        lines.append("")
        lines.append("| Path | Size | Owner | Mode | SHA-256 |")
        lines.append("|---|---:|---|---|---|")
        for rec in result.added:
            lines.append(f"| `{_md_escape(rec.path)}` | {_fmt_size(rec.size)} "
                         f"| {rec.owner}:{rec.group} | `{_fmt_mode(rec.mode)}` "
                         f"| `{_short_hash(rec.sha256)}` |")
        lines.append("")

    if result.modified:
        lines.append(f"## Modified ({len(result.modified)})")
        lines.append("")
        for (old, new, changes) in result.modified:
            lines.append(f"### `{_md_escape(new.path)}`")
            lines.append("")
            for c in changes:
                lines.append(f"- {c}")
            if old.sha256 and new.sha256 and old.sha256 != new.sha256:
                lines.append(f"- `sha256` was `{old.sha256}`")
                lines.append(f"- `sha256` now `{new.sha256}`")
            diff = _try_diff(old, new)
            if diff:
                lines.append("")
                lines.append("```diff")
                lines.append(diff)
                lines.append("```")
            lines.append("")

    if result.deleted:
        lines.append(f"## Deleted ({len(result.deleted)})")
        lines.append("")
        lines.append("| Path | Was | Owner |")
        lines.append("|---|---:|---|")
        for rec in result.deleted:
            lines.append(f"| `{_md_escape(rec.path)}` | {_fmt_size(rec.size)} "
                         f"| {rec.owner}:{rec.group} |")
        lines.append("")

    if not result.has_drift:
        lines.append("_No changes detected._")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

HTML_HEAD = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Cairn Scan Report — {host}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         max-width: 1100px; margin: 2em auto; padding: 0 1em; color: #1f2328;
         line-height: 1.5; }}
  h1, h2, h3 {{ border-bottom: 1px solid #d1d9e0; padding-bottom: 0.3em; }}
  h1 {{ margin-bottom: 0.2em; }}
  .meta {{ color: #59636e; font-size: 0.95em; margin-bottom: 1.5em; }}
  .meta code {{ background: #eff1f3; padding: 0.1em 0.4em; border-radius: 3px; }}
  .status-clean    {{ color: #1a7f37; font-weight: 600; }}
  .status-drift    {{ color: #cf222e; font-weight: 600; }}
  table  {{ border-collapse: collapse; width: 100%; margin: 1em 0; font-size: 0.9em; }}
  th, td {{ text-align: left; padding: 0.45em 0.7em; border-bottom: 1px solid #d1d9e0; }}
  th     {{ background: #f6f8fa; }}
  tr:nth-child(even) td {{ background: #fcfcfd; }}
  td.path {{ font-family: ui-monospace, "SF Mono", Menlo, monospace;
             font-size: 0.85em; word-break: break-all; }}
  td.num  {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .added    td.path {{ color: #1a7f37; }}
  .deleted  td.path {{ color: #cf222e; }}
  .modified td.path {{ color: #9a6700; }}
  .change-list {{ margin: 0.5em 0 1.5em 1em; padding-left: 1em; }}
  .change-list li {{ font-family: ui-monospace, monospace; font-size: 0.85em; }}
  .summary-table {{ max-width: 320px; }}
  .hash {{ font-family: ui-monospace, monospace; font-size: 0.8em; color: #59636e; }}
  pre.diff {{ background: #f6f8fa; padding: 0.8em 1em; border-radius: 6px;
              overflow-x: auto; font-size: 0.82em; line-height: 1.4;
              border: 1px solid #d1d9e0; }}
  .diff-meta {{ color: #59636e; display: block; }}
  .diff-hunk {{ color: #6f42c1; display: block; }}
  .diff-add  {{ background: #dafbe1; color: #1a7f37; display: block; }}
  .diff-del  {{ background: #ffebe9; color: #cf222e; display: block; }}
</style></head>
<body>"""


def _h(s: str) -> str:
    """Escape HTML special chars."""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))


def _render_html(result: ScanResult) -> str:
    s = result.summary_counts
    parts: list[str] = []
    parts.append(HTML_HEAD.format(host=_h(result.host)))
    status_class = "status-drift" if result.has_drift else "status-clean"
    status_text  = "Drift detected" if result.has_drift else "Clean"

    parts.append(f"<h1>Cairn Scan Report</h1>")
    parts.append(f'<div class="meta">')
    parts.append(f'<strong>Status:</strong> <span class="{status_class}">{status_text}</span><br>')
    parts.append(f'<strong>Host:</strong> <code>{_h(result.host)}</code><br>')
    parts.append(f'<strong>Scanned at:</strong> {_h(result.scanned_at)}<br>')
    parts.append(f'<strong>Baseline:</strong> <code>{_h(result.db_path)}</code>')
    parts.append(f'</div>')

    parts.append('<h2>Summary</h2>')
    parts.append('<table class="summary-table">')
    parts.append('<tr><th>Event</th><th class="num">Count</th></tr>')
    parts.append(f'<tr><td>Added</td>   <td class="num">{s["added"]}</td></tr>')
    parts.append(f'<tr><td>Modified</td><td class="num">{s["modified"]}</td></tr>')
    parts.append(f'<tr><td>Deleted</td> <td class="num">{s["deleted"]}</td></tr>')
    parts.append('</table>')

    if result.added:
        parts.append(f'<h2>Added ({len(result.added)})</h2>')
        parts.append('<table>')
        parts.append('<tr><th>Path</th><th class="num">Size</th><th>Owner</th>'
                     '<th>Mode</th><th>SHA-256</th></tr>')
        for rec in result.added:
            parts.append(
                f'<tr class="added">'
                f'<td class="path">{_h(rec.path)}</td>'
                f'<td class="num">{_fmt_size(rec.size)}</td>'
                f'<td>{_h(rec.owner)}:{_h(rec.group)}</td>'
                f'<td><code>{_h(_fmt_mode(rec.mode))}</code></td>'
                f'<td class="hash">{_h(_short_hash(rec.sha256))}</td>'
                f'</tr>')
        parts.append('</table>')

    if result.modified:
        parts.append(f'<h2>Modified ({len(result.modified)})</h2>')
        for (old, new, changes) in result.modified:
            parts.append(f'<h3 class="modified" style="font-family: monospace;">'
                         f'{_h(new.path)}</h3>')
            parts.append('<ul class="change-list">')
            for c in changes:
                parts.append(f'<li>{_h(c)}</li>')
            if old.sha256 and new.sha256 and old.sha256 != new.sha256:
                parts.append(f'<li>sha256 was <span class="hash">{_h(old.sha256)}</span></li>')
                parts.append(f'<li>sha256 now <span class="hash">{_h(new.sha256)}</span></li>')
            parts.append('</ul>')
            diff = _try_diff(old, new)
            if diff:
                # Color-coded unified diff: simple + and - line styling
                diff_html_lines = []
                for dl in diff.splitlines():
                    cls = ""
                    if dl.startswith("+++") or dl.startswith("---"):
                        cls = "diff-meta"
                    elif dl.startswith("@@"):
                        cls = "diff-hunk"
                    elif dl.startswith("+"):
                        cls = "diff-add"
                    elif dl.startswith("-"):
                        cls = "diff-del"
                    diff_html_lines.append(
                        f'<span class="{cls}">{_h(dl)}</span>' if cls else _h(dl)
                    )
                parts.append('<pre class="diff">')
                parts.append("\n".join(diff_html_lines))
                parts.append('</pre>')

    if result.deleted:
        parts.append(f'<h2>Deleted ({len(result.deleted)})</h2>')
        parts.append('<table>')
        parts.append('<tr><th>Path</th><th class="num">Was</th><th>Owner</th></tr>')
        for rec in result.deleted:
            parts.append(
                f'<tr class="deleted">'
                f'<td class="path">{_h(rec.path)}</td>'
                f'<td class="num">{_fmt_size(rec.size)}</td>'
                f'<td>{_h(rec.owner)}:{_h(rec.group)}</td>'
                f'</tr>')
        parts.append('</table>')

    if not result.has_drift:
        parts.append('<p><em>No changes detected.</em></p>')

    parts.append('</body></html>')
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Improved terminal output (used by cmd_scan when not writing a report)
# ---------------------------------------------------------------------------

# ANSI color codes. Only emitted when stdout is a TTY and NO_COLOR is unset.
class _Color:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[31m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    BLUE   = "\033[34m"
    CYAN   = "\033[36m"


def _use_color() -> bool:
    """Honor NO_COLOR convention and TTY detection."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    import sys
    return sys.stdout.isatty()


def render_terminal(result: ScanResult, *, use_color: Optional[bool] = None) -> str:
    """Print a colorized, human-friendly summary suitable for a terminal.
    Different from the .txt report — shorter, with colors when on a TTY."""
    if use_color is None:
        use_color = _use_color()

    def c(text: str, code: str) -> str:
        return f"{code}{text}{_Color.RESET}" if use_color else text

    s = result.summary_counts
    lines: list[str] = []
    lines.append("")
    lines.append(c("┌" + "─" * 76 + "┐", _Color.DIM))
    lines.append(c("│", _Color.DIM)
                 + f"  Cairn scan @ {result.scanned_at[:19]}".ljust(76)
                 + c("│", _Color.DIM))
    lines.append(c("│", _Color.DIM)
                 + f"  host: {result.host}   baseline: {result.db_path}".ljust(76)
                 + c("│", _Color.DIM))
    lines.append(c("└" + "─" * 76 + "┘", _Color.DIM))

    # Summary line
    parts = [
        c(f"+{s['added']} added",      _Color.GREEN),
        c(f"~{s['modified']} modified", _Color.YELLOW),
        c(f"-{s['deleted']} deleted",   _Color.RED),
    ]
    lines.append("  " + "   ".join(parts))
    lines.append("")

    if result.added:
        lines.append(c("ADDED", _Color.BOLD + _Color.GREEN))
        for rec in result.added:
            lines.append(c("  + ", _Color.GREEN) + rec.path
                         + c(f"   ({_fmt_size(rec.size)}, owner={rec.owner})", _Color.DIM))
        lines.append("")

    if result.modified:
        lines.append(c("MODIFIED", _Color.BOLD + _Color.YELLOW))
        for (old, new, changes) in result.modified:
            lines.append(c("  ~ ", _Color.YELLOW) + new.path)
            for ch in changes:
                lines.append(c("      · " + ch, _Color.DIM))
            diff = _try_diff(old, new)
            if diff:
                for dl in diff.splitlines():
                    if dl.startswith("+++") or dl.startswith("---"):
                        lines.append(c("      " + dl, _Color.DIM))
                    elif dl.startswith("@@"):
                        lines.append(c("      " + dl, _Color.CYAN))
                    elif dl.startswith("+"):
                        lines.append(c("      " + dl, _Color.GREEN))
                    elif dl.startswith("-"):
                        lines.append(c("      " + dl, _Color.RED))
                    else:
                        lines.append("      " + dl)
        lines.append("")

    if result.deleted:
        lines.append(c("DELETED", _Color.BOLD + _Color.RED))
        for rec in result.deleted:
            lines.append(c("  - ", _Color.RED) + rec.path
                         + c(f"   (was {_fmt_size(rec.size)})", _Color.DIM))
        lines.append("")

    if not result.has_drift:
        lines.append("  " + c("✓ No changes detected.", _Color.GREEN))
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# AWS drift reports (cairn aws scan --report ...)
#
# A parallel, lightweight result type: AwsRecords have no size/mode/owner, so
# they get their own renderers instead of being shoehorned through the
# FileRecord-shaped ones. SARIF reuses the same envelope; artifactLocation.uri
# is the ARN (a plain string is valid; _sarif_result's absolute-path heuristic
# does not touch "arn:..." values).
# ---------------------------------------------------------------------------

@dataclass
class AwsScanResult:
    scanned_at: str
    host: str
    db_path: str
    added:    list = field(default_factory=list)   # [AwsRecord]
    modified: list = field(default_factory=list)   # [(old, new)]
    deleted:  list = field(default_factory=list)   # [AwsRecord]

    @property
    def has_drift(self) -> bool:
        return bool(self.added or self.modified or self.deleted)


AWS_SARIF_RULES = [
    {
        "id":   "cairn.aws.added",
        "name": "AwsResourceAdded",
        "shortDescription": {"text": "An AWS resource appeared that was not in the baseline."},
        "fullDescription":  {"text": "A new resource (IAM principal, security group, bucket policy, trail, key, function...) exists in the account since the baseline was captured. Investigate whether the addition is expected."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id":   "cairn.aws.modified",
        "name": "AwsResourceModified",
        "shortDescription": {"text": "An AWS resource's configuration drifted from the baseline."},
        "fullDescription":  {"text": "The canonical configuration of a monitored AWS resource changed since the baseline (policy edit, rule change, logging toggled, rotation disabled...)."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id":   "cairn.aws.deleted",
        "name": "AwsResourceDeleted",
        "shortDescription": {"text": "An AWS resource present in the baseline is gone."},
        "fullDescription":  {"text": "A resource that existed when the baseline was captured no longer exists (or is no longer visible to the scanning credentials)."},
        "defaultConfiguration": {"level": "warning"},
    },
]


def _aws_changed_keys(old, new) -> list:
    from .awsmon import changed_keys   # lazy: avoids import cycle
    return changed_keys(old, new)


def _render_aws_sarif(result: AwsScanResult) -> str:
    findings: list[dict] = []
    for rec in result.added:
        findings.append(_sarif_result(
            "cairn.aws.added", "warning",
            f"AWS resource appeared since baseline: {rec.resource_type} "
            f"{rec.arn} (region {rec.region})",
            rec.arn,
        ))
    for (old, new) in result.modified:
        keys = ", ".join(_aws_changed_keys(old, new)) or "config"
        findings.append(_sarif_result(
            "cairn.aws.modified", "error",
            f"AWS resource drifted from baseline: {new.resource_type} "
            f"{new.arn} (region {new.region}) — changed: {keys}",
            new.arn,
        ))
    for rec in result.deleted:
        findings.append(_sarif_result(
            "cairn.aws.deleted", "warning",
            f"AWS resource missing since baseline: {rec.resource_type} "
            f"{rec.arn} (region {rec.region})",
            rec.arn,
        ))

    sarif = {
        "version":  SARIF_VERSION,
        "$schema":  SARIF_SCHEMA,
        "runs": [{
            "tool": {
                "driver": {
                    "name":    "cairn-aws",
                    "informationUri": "https://github.com/mcowser-p/cairn",
                    "rules":   AWS_SARIF_RULES,
                },
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": result.scanned_at,
                "machine":    result.host,
            }],
            "results": findings,
        }],
    }
    return json.dumps(sarif, indent=2, default=str) + "\n"


def _aws_record_dict(rec) -> dict:
    d = asdict(rec)
    # config_json is already a JSON string; inline it for readable reports
    try:
        d["config"] = json.loads(d.pop("config_json"))
    except (ValueError, TypeError):
        pass
    return d


def _render_aws_json(result: AwsScanResult) -> str:
    doc = {
        "report_type": "cairn_aws_scan",
        "generated_at": result.scanned_at,
        "host": result.host,
        "baseline_db": result.db_path,
        "summary": {
            "added": len(result.added),
            "modified": len(result.modified),
            "deleted": len(result.deleted),
        },
        "added":   [_aws_record_dict(r) for r in result.added],
        "modified": [{"old": _aws_record_dict(o), "new": _aws_record_dict(n),
                      "changed_keys": _aws_changed_keys(o, n)}
                     for (o, n) in result.modified],
        "deleted": [_aws_record_dict(r) for r in result.deleted],
    }
    return json.dumps(doc, indent=2, default=str) + "\n"


def _render_aws_markdown(result: AwsScanResult) -> str:
    lines = [
        "# AWS configuration drift report",
        "",
        f"- **Scanned:** {result.scanned_at}",
        f"- **Scanned from:** {result.host}",
        f"- **Baseline:** `{result.db_path}`",
        f"- **Drift:** {len(result.added)} added, "
        f"{len(result.modified)} modified, {len(result.deleted)} deleted",
        "",
    ]
    if result.added:
        lines += ["## Added", "", "| Type | ARN | Region |", "|---|---|---|"]
        lines += [f"| {r.resource_type} | `{_md_escape(r.arn)}` | {r.region} |"
                  for r in result.added] + [""]
    if result.modified:
        lines += ["## Modified", "",
                  "| Type | ARN | Region | Changed keys |", "|---|---|---|---|"]
        lines += [f"| {n.resource_type} | `{_md_escape(n.arn)}` | {n.region} "
                  f"| {_md_escape(', '.join(_aws_changed_keys(o, n)) or 'config')} |"
                  for (o, n) in result.modified] + [""]
    if result.deleted:
        lines += ["## Deleted", "", "| Type | ARN | Region |", "|---|---|---|"]
        lines += [f"| {r.resource_type} | `{_md_escape(r.arn)}` | {r.region} |"
                  for r in result.deleted] + [""]
    if not result.has_drift:
        lines += ["No AWS configuration drift detected.", ""]
    return "\n".join(lines)


def _render_aws_plaintext(result: AwsScanResult) -> str:
    lines = [f"AWS drift scan @ {result.scanned_at} (from {result.host})",
             f"baseline: {result.db_path}",
             f"added: {len(result.added)}  modified: {len(result.modified)}  "
             f"deleted: {len(result.deleted)}", ""]
    for r in result.added:
        lines.append(f"  + {r.resource_type}  {r.arn}")
    for (o, n) in result.modified:
        keys = ", ".join(_aws_changed_keys(o, n)) or "config"
        lines.append(f"  ~ {n.resource_type}  {n.arn}  (changed: {keys})")
    for r in result.deleted:
        lines.append(f"  - {r.resource_type}  {r.arn}")
    if not result.has_drift:
        lines.append("  no drift detected")
    return "\n".join(lines) + "\n"


AWS_FORMATS = {"json", "sarif", "md", "txt"}


def render_aws(result: AwsScanResult, fmt: str) -> str:
    if fmt == "json":  return _render_aws_json(result)
    if fmt == "sarif": return _render_aws_sarif(result)
    if fmt == "md":    return _render_aws_markdown(result)
    if fmt == "txt":   return _render_aws_plaintext(result)
    raise ValueError(f"format {fmt!r} not supported for aws scans; "
                     f"valid: {sorted(AWS_FORMATS)}")


def write_aws_report(result: AwsScanResult, path, fmt=None) -> str:
    """Render and atomically write an AWS drift report. Path may be None when
    only --format was given (prints to stdout)."""
    actual = detect_format(path or "-", fmt)
    body = render_aws(result, actual)
    if not path or path == "-":
        print(body, end="")
        return actual
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(body)
    os.replace(tmp, path)
    return actual
