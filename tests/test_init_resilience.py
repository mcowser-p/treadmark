"""A single pathological file must never abort a baseline or a scan.

cmd_init/cmd_scan historically caught only (OSError, PermissionError) around
the per-file stat/save, so any other exception (a value sqlite can't bind, an
unexpected raise from a helper) crashed the whole run with a bare exit 1 —
which is what silently blocked releases when it hit one file deep in a large
watched tree. These tests pin the resilient behavior.
"""

from __future__ import annotations

import os

import pytest

from treadmark import files


def _cfg(tmp_path, tree):
    return {
        "db_path": str(tmp_path / "baseline.db"),
        "paths": [str(tree)],
        "store_content": True,
        "store_content_max_kb": 256,
    }


def _tree(tmp_path):
    root = tmp_path / "watch"
    root.mkdir()
    for n in ("a.conf", "b.conf", "c.conf"):
        (root / n).write_text(f"key = {n}\n", encoding="utf-8")
    return root


def test_init_survives_one_bad_file(tmp_path, monkeypatch, capsys):
    tree = _tree(tmp_path)
    cfg = _cfg(tmp_path, tree)
    bad = str(tree / "b.conf")

    real_stat_file = files.stat_file

    def flaky(path, c):
        if os.path.abspath(path) == os.path.abspath(bad):
            raise RuntimeError("simulated non-OSError (e.g. a bad sqlite bind)")
        return real_stat_file(path, c)

    monkeypatch.setattr(files, "stat_file", flaky)

    rc = files.cmd_init(cfg, force=True)
    assert rc == 0                              # not a crash
    assert os.path.exists(cfg["db_path"])       # baseline was written
    err = capsys.readouterr().err
    assert "RuntimeError" in err and "b.conf" in err   # named, not swallowed

    # The good files are in the baseline; the bad one is skipped.
    conn = files.open_db(cfg["db_path"])
    try:
        meta = {r[0]: r[1] for r in conn.execute("SELECT key, value FROM meta")}
        paths = [r[0] for r in conn.execute("SELECT path FROM files")]
    finally:
        conn.close()
    assert meta["scan_errors"] == "1"
    assert any(p.endswith("a.conf") for p in paths)
    assert any(p.endswith("c.conf") for p in paths)
    assert not any(p.endswith("b.conf") for p in paths)


def test_scan_survives_one_bad_file(tmp_path, monkeypatch):
    tree = _tree(tmp_path)
    cfg = _cfg(tmp_path, tree)
    assert files.cmd_init(cfg, force=True) == 0

    real_stat_file = files.stat_file
    bad = str(tree / "b.conf")

    def flaky(path, c):
        if os.path.abspath(path) == os.path.abspath(bad):
            raise RuntimeError("boom")
        return real_stat_file(path, c)

    monkeypatch.setattr(files, "stat_file", flaky)
    # A clean scan (nothing changed but the injected error) must not crash;
    # rc is 0 (no drift) or 1 (drift) but never an uncaught-exception exit.
    rc = files.cmd_scan(cfg)
    assert rc in (0, 1)


@pytest.mark.skipif(os.name == "nt", reason="POSIX-only: NT filenames are always valid UTF-16")
def test_init_survives_real_surrogate_filename(tmp_path, capsys):
    """Reproduces the actual release blocker: a file whose name isn't valid
    UTF-8. os.walk surrogate-escapes it; sqlite can't bind that path. It must
    be skipped (at the walk), not crash the baseline."""
    tree = _tree(tmp_path)
    # Create a file with a raw 0xFF byte in its name (invalid UTF-8).
    bad_bytes = os.fsencode(str(tree)) + b"/bad\xff\xfename.conf"
    try:
        fd = os.open(bad_bytes, os.O_CREAT | os.O_WRONLY, 0o644)
        os.close(fd)
    except (OSError, ValueError):
        pytest.skip("filesystem rejects non-UTF-8 filenames")

    cfg = _cfg(tmp_path, tree)
    rc = files.cmd_init(cfg, force=True)
    assert rc == 0                              # no crash
    assert os.path.exists(cfg["db_path"])
    assert "undecodable filename" in capsys.readouterr().err

    conn = files.open_db(cfg["db_path"])
    try:
        paths = [r[0] for r in conn.execute("SELECT path FROM files")]
    finally:
        conn.close()
    # good files recorded; the undecodable one is absent, not fatal
    assert any(p.endswith("a.conf") for p in paths)
    assert not any("bad" in p and "name.conf" in p for p in paths)


def test_init_still_refuses_overwrite_without_force(tmp_path):
    tree = _tree(tmp_path)
    cfg = _cfg(tmp_path, tree)
    assert files.cmd_init(cfg, force=True) == 0
    assert files.cmd_init(cfg, force=False) == 2   # unchanged contract
