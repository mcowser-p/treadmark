"""--root path remapping: get_root_prefix, to_logical/to_real, DB storage."""

from __future__ import annotations

import sqlite3
import sys

import pytest

from cairn import files


def test_get_root_prefix_empty_slash_and_trailing(tmp_path):
    assert files.get_root_prefix({}) == ""
    assert files.get_root_prefix({"root_prefix": ""}) == ""
    assert files.get_root_prefix({"root_prefix": "/"}) == ""
    assert files.get_root_prefix({"root_prefix": "  "}) == ""
    got = files.get_root_prefix({"root_prefix": str(tmp_path) + "/"})
    assert got == str(tmp_path)


def test_to_logical_strips_prefix():
    assert files.to_logical("/mnt/image/etc/passwd", "/mnt/image") == "/etc/passwd"


def test_to_logical_root_itself_is_slash():
    assert files.to_logical("/mnt/image", "/mnt/image") == "/"


def test_to_logical_passthrough_outside_prefix():
    assert files.to_logical("/somewhere/else", "/mnt/image") == "/somewhere/else"
    # Sibling dir sharing the prefix string must NOT be stripped.
    assert files.to_logical("/mnt/image2/etc", "/mnt/image") == "/mnt/image2/etc"


def test_to_logical_no_prefix_identity():
    assert files.to_logical("/etc/passwd", "") == "/etc/passwd"


def test_to_real_and_round_trip():
    prefix = "/mnt/image"
    for logical in ("/etc/passwd", "/usr/bin/x", "/"):
        real = files.to_real(logical, prefix)
        assert real.startswith(prefix)
        assert files.to_logical(real, prefix) == logical
    assert files.to_real("/etc/passwd", "") == "/etc/passwd"


@pytest.mark.skipif(sys.platform == "win32",
                    reason="uses a Linux /etc-style rootfs fixture")
def test_cli_root_flag_stores_logical_paths(run_cli, linux_rootfs, rootfs_config):
    root = linux_rootfs()
    cfg_path, cfg = rootfs_config()

    rc, _out, _err = run_cli("files", "init", "-c", cfg_path,
                             "--root", str(root), "--force")
    assert rc == 0

    conn = sqlite3.connect(cfg["db_path"])
    try:
        paths = [r[0] for r in conn.execute("SELECT path FROM files")]
    finally:
        conn.close()

    assert paths, "baseline is empty"
    assert "/etc/passwd" in paths
    # No real (tmpdir-prefixed) path may leak into the baseline.
    assert all(not p.startswith(str(root)) for p in paths)
