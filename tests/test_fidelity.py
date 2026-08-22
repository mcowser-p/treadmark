"""assess_root_fidelity: detecting unfaithful rootfs extractions.

An unprivileged test run is naturally the "broken extraction" state: every
file in the fixture rootfs is owned by the (non-root) test uid, exactly like
`docker export | tar -x` run without root.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

from treadmark import files
from conftest import install_app

pytestmark = pytest.mark.skipif(sys.platform == "win32",
                                reason="fidelity heuristics are POSIX-only")

# hasattr guard: this line runs at COLLECTION time on every platform — the
# module-level win32 pytestmark above skips the tests but not the import,
# and os.getuid does not exist on Windows.
requires_nonroot = pytest.mark.skipif(
    hasattr(os, "getuid") and os.getuid() == 0,
    reason="degraded detection requires a non-root owner uid")


def _rootfs_cfg(root, cfg_dict):
    cfg = dict(cfg_dict)
    cfg["root_prefix"] = str(root)
    return cfg


def test_none_on_live_scan():
    assert files.assess_root_fidelity(dict(files.DEFAULT_CONFIG)) is None


@requires_nonroot
def test_degraded_when_uniform_nonroot_and_no_setuid(linux_rootfs, rootfs_config):
    root = linux_rootfs()
    install_app(root, setuid=False)
    _cfg_path, cfg = rootfs_config()
    result = files.assess_root_fidelity(_rootfs_cfg(root, cfg))
    assert result["status"] == "degraded"
    assert result["sampled_files"] > 0
    assert len(result["reasons"]) == 2
    assert "setuid" in result["reasons"][1]


def test_ok_when_setuid_present(linux_rootfs, rootfs_config):
    root = linux_rootfs()
    install_app(root, setuid=True)   # setuid helper defeats the AND-condition
    _cfg_path, cfg = rootfs_config()
    result = files.assess_root_fidelity(_rootfs_cfg(root, cfg))
    assert result["status"] == "ok"
    assert result["reasons"] == []


@requires_nonroot
def test_footprint_json_contains_fidelity_block(run_cli, linux_rootfs,
                                                rootfs_config, tmp_path):
    root = linux_rootfs()
    cfg_path, _cfg = rootfs_config()
    run_cli("files", "init", "-c", cfg_path, "--root", str(root), "--force")
    install_app(root, setuid=False)

    report = tmp_path / "fp.json"
    _rc, _out, err = run_cli("footprint", "-c", cfg_path, "--root", str(root),
                             "--app", "myapp", "--report", str(report))
    model = json.loads(report.read_text())
    assert model["fidelity"]["status"] == "degraded"
    assert "fidelity degraded" in err


@requires_nonroot
def test_scan_prints_fidelity_warning(run_cli, linux_rootfs, rootfs_config):
    root = linux_rootfs()   # clean rootfs: no setuid anywhere → degraded
    cfg_path, _cfg = rootfs_config()
    run_cli("files", "init", "-c", cfg_path, "--root", str(root), "--force")
    rc, _out, err = run_cli("files", "scan", "-c", cfg_path, "--root", str(root))
    assert rc == 0   # warning only — never an error
    assert "fidelity degraded" in err


def test_live_scan_never_warns(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    run_cli("files", "init", "-c", cfg_path)
    _rc, _out, err = run_cli("files", "scan", "-c", cfg_path)
    assert "fidelity" not in err
