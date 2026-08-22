"""Report output formats parse cleanly and carry the right envelope."""

from __future__ import annotations

import csv
import io
import json
import os

FIXED_TIME = 1_700_000_000


def _pin_dirs(tree):
    """Pin directory mtimes so adding/removing files doesn't produce phantom
    'modified' directory entries when a test crosses a second boundary."""
    os.utime(tree, (FIXED_TIME, FIXED_TIME))
    os.utime(tree / "sub", (FIXED_TIME, FIXED_TIME))


def _drifted_setup(run_cli, make_config, watch_tree):
    tree = watch_tree()
    _pin_dirs(tree)
    cfg_path, cfg = make_config([tree])
    run_cli("files", "init", "-c", cfg_path)
    (tree / "dropped.bin").write_bytes(b"payload")
    (tree / "app.conf").write_text("key = 1\nmode = tampered\n")
    (tree / "sub" / "notes.txt").unlink()
    _pin_dirs(tree)
    return tree, cfg_path, cfg


def test_json_report_parses(run_cli, make_config, watch_tree, tmp_path):
    _tree, cfg_path, _cfg = _drifted_setup(run_cli, make_config, watch_tree)
    out_path = tmp_path / "drift.json"
    rc, _out, _err = run_cli("files", "scan", "-c", cfg_path,
                             "--report", str(out_path))
    assert rc == 1

    payload = json.loads(out_path.read_text())
    assert payload["tool"] == "treadmark"
    assert payload["has_drift"] is True
    assert payload["summary"]["added"] == 1
    assert payload["summary"]["deleted"] == 1
    # Directories can also appear as modified (their size changes when
    # entries are added/removed), so match the file entry by path.
    conf_mods = [m for m in payload["modified"]
                 if m["new"]["path"].endswith("app.conf")]
    assert conf_mods and conf_mods[0]["changes"]
    # store_content is on, so the modified entry carries a unified diff.
    assert "unified_diff" in conf_mods[0]


def test_sarif_report_parses_and_schema_basics(run_cli, make_config, watch_tree, tmp_path):
    _tree, cfg_path, _cfg = _drifted_setup(run_cli, make_config, watch_tree)
    out_path = tmp_path / "drift.sarif"
    run_cli("files", "scan", "-c", cfg_path, "--report", str(out_path))

    sarif = json.loads(out_path.read_text())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "treadmark"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"treadmark.file.added", "treadmark.file.modified", "treadmark.file.deleted"} <= rule_ids
    assert run["results"], "expected findings for a drifted scan"
    assert all(res["ruleId"] in rule_ids for res in run["results"])


def test_csv_report_parses(run_cli, make_config, watch_tree, tmp_path):
    _tree, cfg_path, _cfg = _drifted_setup(run_cli, make_config, watch_tree)
    out_path = tmp_path / "drift.csv"
    run_cli("files", "scan", "-c", cfg_path, "--report", str(out_path))

    rows = list(csv.DictReader(io.StringIO(out_path.read_text())))
    events = {r["event_type"] for r in rows}
    assert events == {"added", "modified", "deleted"}
    assert all(r["path"] for r in rows)
    assert [r for r in rows
            if r["event_type"] == "added" and r["path"].endswith("dropped.bin")]
    assert [r for r in rows
            if r["event_type"] == "deleted" and r["path"].endswith("notes.txt")]


def test_ndjson_each_line_parses(run_cli, make_config, watch_tree, tmp_path):
    _tree, cfg_path, _cfg = _drifted_setup(run_cli, make_config, watch_tree)
    out_path = tmp_path / "drift.ndjson"
    run_cli("files", "scan", "-c", cfg_path, "--report", str(out_path))

    lines = [ln for ln in out_path.read_text().splitlines() if ln.strip()]
    assert len(lines) >= 3
    for ln in lines:
        json.loads(ln)


def test_format_inferred_from_extension(run_cli, make_config, watch_tree, tmp_path):
    _tree, cfg_path, _cfg = _drifted_setup(run_cli, make_config, watch_tree)
    out_path = tmp_path / "drift.sarif"
    _rc, out, _err = run_cli("files", "scan", "-c", cfg_path,
                             "--report", str(out_path))
    assert "(sarif)" in out
    assert "$schema" in out_path.read_text()


def test_report_stdout_dash(run_cli, make_config, watch_tree):
    _tree, cfg_path, _cfg = _drifted_setup(run_cli, make_config, watch_tree)
    rc, out, _err = run_cli("files", "scan", "-c", cfg_path,
                            "--report", "-", "--format", "json")
    assert rc == 1
    payload = json.loads(out)
    assert payload["has_drift"] is True


def test_legacy_json_flag(run_cli, make_config, watch_tree):
    _tree, cfg_path, _cfg = _drifted_setup(run_cli, make_config, watch_tree)
    rc, out, _err = run_cli("files", "scan", "-c", cfg_path, "--json")
    assert rc == 1
    assert json.loads(out)["tool"] == "treadmark"
