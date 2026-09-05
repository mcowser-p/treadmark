"""compare_fields: selecting which record fields scans diff.

`compare_fields: ["sha256", "size"]` makes a scan report only content
changes — metadata-only drift (a re-touched mtime, a chmod) stops showing
up as `modified`. Unset compares everything (the long-standing behavior),
and malformed values are rejected with exit 2: a typo must never silently
drop comparisons from a security scan.
"""

from __future__ import annotations

import json
import os
import sys
import time

import pytest

linux_only = pytest.mark.skipif(sys.platform == "win32",
                                reason="relies on POSIX mode bits")

CONTENT_ONLY = ["sha256", "size"]
NO_TIMESTAMPS = ["sha256", "size", "mode", "owner", "group", "acl"]


def _touch_future(path, offset=100):
    """Bump mtime by a whole number of seconds so the integer-second
    comparison in diff_records definitely sees it."""
    t = time.time() + offset
    os.utime(path, (t, t))


def _scan_json(run_cli, cfg_path):
    rc, out, _err = run_cli("files", "scan", "--config", cfg_path, "--json")
    return rc, json.loads(out)


def _changes_for(payload, name):
    """All change strings for paths ending in `name` (joined for greps)."""
    out = []
    for m in payload["modified"]:
        if m["new"]["path"].endswith(name):
            out.extend(m["changes"])
    return "; ".join(out)


# ---------------------------------------------------------------------------
# Content-only scans
# ---------------------------------------------------------------------------

def test_content_only_ignores_mtime_touch(run_cli, make_config, watch_tree):
    root = watch_tree()
    cfg_path, _ = make_config([root], compare_fields=CONTENT_ONLY)
    assert run_cli("files", "init", "--config", cfg_path)[0] == 0

    _touch_future(root / "app.conf")
    rc, payload = _scan_json(run_cli, cfg_path)
    assert rc == 0
    assert payload["modified"] == []
    assert not payload["has_drift"]


def test_content_only_still_reports_content_change(run_cli, make_config, watch_tree):
    root = watch_tree()
    cfg_path, _ = make_config([root], compare_fields=CONTENT_ONLY)
    assert run_cli("files", "init", "--config", cfg_path)[0] == 0

    # same length as the original so this is a pure sha256 change, no size
    (root / "app.conf").write_text("key = 2\nmode = safe\n", encoding="utf-8")
    rc, payload = _scan_json(run_cli, cfg_path)
    assert rc == 1
    assert "content sha256" in _changes_for(payload, "app.conf")


@linux_only
def test_content_only_ignores_chmod(run_cli, make_config, watch_tree):
    root = watch_tree()
    cfg_path, _ = make_config([root], compare_fields=CONTENT_ONLY)
    assert run_cli("files", "init", "--config", cfg_path)[0] == 0

    os.chmod(root / "app.conf", 0o600)
    rc, payload = _scan_json(run_cli, cfg_path)
    assert rc == 0
    assert payload["modified"] == []


# ---------------------------------------------------------------------------
# Keeping security metadata while dropping timestamp churn
# ---------------------------------------------------------------------------

@linux_only
def test_no_timestamps_keeps_mode_drops_mtime(run_cli, make_config, watch_tree):
    root = watch_tree()
    cfg_path, _ = make_config([root], compare_fields=NO_TIMESTAMPS)
    assert run_cli("files", "init", "--config", cfg_path)[0] == 0

    os.chmod(root / "app.conf", 0o600)            # must still be reported
    _touch_future(root / "sub" / "notes.txt")     # must stay invisible
    rc, payload = _scan_json(run_cli, cfg_path)
    assert rc == 1
    assert "mode" in _changes_for(payload, "app.conf")
    assert _changes_for(payload, "notes.txt") == ""


def test_default_still_reports_mtime_touch(run_cli, make_config, watch_tree):
    root = watch_tree()
    cfg_path, _ = make_config([root])
    assert run_cli("files", "init", "--config", cfg_path)[0] == 0

    _touch_future(root / "app.conf")
    rc, payload = _scan_json(run_cli, cfg_path)
    assert rc == 1
    assert "mtime" in _changes_for(payload, "app.conf")


# ---------------------------------------------------------------------------
# compare against honors the same option
# ---------------------------------------------------------------------------

def test_compare_against_honors_compare_fields(run_cli, make_config, watch_tree):
    root = watch_tree()
    golden_path, golden_cfg = make_config([root], name="golden")
    assert run_cli("files", "init", "--config", golden_path)[0] == 0

    _touch_future(root / "app.conf")

    noisy_path, _ = make_config([root], name="noisy")
    assert run_cli("compare", "against", golden_cfg["db_path"],
                   "--config", noisy_path)[0] == 1

    quiet_path, _ = make_config([root], name="quiet", compare_fields=CONTENT_ONLY)
    assert run_cli("compare", "against", golden_cfg["db_path"],
                   "--config", quiet_path)[0] == 0


# ---------------------------------------------------------------------------
# Validation: malformed compare_fields exits 2, loudly
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    ["sha265", "size"],     # typo'd field name
    "sha256",               # string, not a list
    [],                     # empty list
    [42],                   # non-string entry
])
def test_malformed_compare_fields_rejected_by_scan(run_cli, make_config,
                                                   watch_tree, bad):
    root = watch_tree()
    cfg_path, _ = make_config([root], compare_fields=bad)
    rc, _out, err = run_cli("files", "scan", "--config", cfg_path)
    assert rc == 2
    assert "compare_fields" in err


def test_typo_names_the_offender_and_the_valid_set(run_cli, make_config, watch_tree):
    root = watch_tree()
    cfg_path, _ = make_config([root], compare_fields=["sha265"])
    rc, _out, err = run_cli("files", "scan", "--config", cfg_path)
    assert rc == 2
    assert "sha265" in err
    assert "sha256" in err          # the valid list is spelled out


def test_malformed_compare_fields_rejected_by_init(run_cli, make_config, watch_tree):
    root = watch_tree()
    cfg_path, cfg = make_config([root], compare_fields=["sha265"])
    rc, _out, err = run_cli("files", "init", "--config", cfg_path)
    assert rc == 2
    assert "compare_fields" in err
    assert not os.path.exists(cfg["db_path"])


def test_malformed_compare_fields_rejected_by_compare_against(run_cli, make_config,
                                                              watch_tree):
    root = watch_tree()
    golden_path, golden_cfg = make_config([root], name="golden")
    assert run_cli("files", "init", "--config", golden_path)[0] == 0

    bad_path, _ = make_config([root], name="bad", compare_fields=["sha265"])
    rc, _out, err = run_cli("compare", "against", golden_cfg["db_path"],
                            "--config", bad_path)
    assert rc == 2
    assert "compare_fields" in err
