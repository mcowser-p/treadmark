"""cairn compare: baseline-to-baseline diffs and live-vs-golden compare."""

from __future__ import annotations

import json
import os


FIXED_TIME = 1_700_000_000


def _pin_mtimes(root):
    """Give every entry a fixed mtime so cross-tree compares don't produce
    phantom mtime drift from files being created milliseconds apart."""
    for dirpath, _dirnames, filenames in os.walk(root):
        os.utime(dirpath, (FIXED_TIME, FIXED_TIME))
        for name in filenames:
            os.utime(os.path.join(dirpath, name), (FIXED_TIME, FIXED_TIME))


def _build_tree(base, *, marker="same"):
    data = base / "data"
    data.mkdir(parents=True)
    (data / "app.conf").write_text(f"marker = {marker}\n")
    (data / "common.txt").write_text("common\n")
    _pin_mtimes(base)
    return base


def test_compare_baselines_identical(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_a_path, cfg_a = make_config([tree], name="a")
    cfg_b_path, cfg_b = make_config([tree], name="b")
    run_cli("files", "init", "-c", cfg_a_path)
    run_cli("files", "init", "-c", cfg_b_path)

    rc, out, _err = run_cli("compare", "baselines", cfg_a["db_path"], cfg_b["db_path"])
    assert rc == 0
    assert "Baselines match" in out


def test_compare_baselines_drift(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_a_path, cfg_a = make_config([tree], name="a")
    cfg_b_path, cfg_b = make_config([tree], name="b")
    run_cli("files", "init", "-c", cfg_a_path)

    (tree / "app.conf").write_text("key = changed\n")
    (tree / "planted.bin").write_bytes(b"x")
    run_cli("files", "init", "-c", cfg_b_path)

    rc, out, _err = run_cli("compare", "baselines",
                            cfg_a["db_path"], cfg_b["db_path"], "--json")
    assert rc == 1
    payload = json.loads(out)
    only_b_paths = [r["path"] for r in payload["only_in_b"]]
    differ_paths = [d["b"]["path"] for d in payload["differs"]]
    assert str(tree / "planted.bin") in only_b_paths
    assert str(tree / "app.conf") in differ_paths


def test_compare_against_golden(run_cli, make_config, tmp_path):
    # Two rootfs trees with identical logical layout; one file differs.
    # root_prefix makes the stored paths logical, so the golden baseline
    # from tree A compares cleanly against tree B.
    tree_a = _build_tree(tmp_path / "golden-host", marker="same")
    tree_b = _build_tree(tmp_path / "checked-host", marker="tampered")

    cfg_a_path, cfg_a = make_config(["/data"], name="golden",
                                    root_prefix=str(tree_a))
    cfg_b_path, _cfg_b = make_config(["/data"], name="local",
                                     root_prefix=str(tree_b))
    assert run_cli("files", "init", "-c", cfg_a_path)[0] == 0

    rc, out, _err = run_cli("compare", "against", cfg_a["db_path"],
                            "-c", cfg_b_path)
    assert rc == 1
    assert "/data/app.conf" in out

    # An identical tree compares clean.
    tree_c = _build_tree(tmp_path / "clean-host", marker="same")
    cfg_c_path, _cfg_c = make_config(["/data"], name="clean",
                                     root_prefix=str(tree_c))
    rc, out, _err = run_cli("compare", "against", cfg_a["db_path"],
                            "-c", cfg_c_path)
    assert rc == 0
    assert "matches golden" in out
