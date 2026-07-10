"""Full init → scan → update lifecycle through the real CLI entry point."""

from __future__ import annotations

import os
import subprocess
import sys

from conftest import SRC_DIR


def test_init_creates_baseline(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, cfg = make_config([tree])
    rc, out, _err = run_cli("files", "init", "-c", cfg_path)
    assert rc == 0
    assert os.path.exists(cfg["db_path"])
    assert "baseline done" in out


def test_init_refuses_overwrite_without_force(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    assert run_cli("files", "init", "-c", cfg_path)[0] == 0
    rc, out, _err = run_cli("files", "init", "-c", cfg_path)
    assert rc == 2
    assert "--force" in out
    assert run_cli("files", "init", "-c", cfg_path, "--force")[0] == 0


def test_scan_clean_exits_0(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    run_cli("files", "init", "-c", cfg_path)
    rc, _out, _err = run_cli("files", "scan", "-c", cfg_path)
    assert rc == 0


def test_scan_detects_added_modified_deleted(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    run_cli("files", "init", "-c", cfg_path)

    (tree / "dropped.bin").write_bytes(b"\x00new payload")
    (tree / "app.conf").write_text("key = 2\nmode = unsafe\n")
    (tree / "sub" / "notes.txt").unlink()

    rc, out, _err = run_cli("files", "scan", "-c", cfg_path)
    assert rc == 1
    assert "dropped.bin" in out
    assert "app.conf" in out
    assert "notes.txt" in out


def test_scan_shows_unified_diff_for_text_change(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])   # store_content on by fixture default
    run_cli("files", "init", "-c", cfg_path)
    (tree / "app.conf").write_text("key = 1\nmode = unsafe\n")
    _rc, out, _err = run_cli("files", "scan", "-c", cfg_path)
    assert "-mode = safe" in out
    assert "+mode = unsafe" in out


def test_update_requires_accept(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    run_cli("files", "init", "-c", cfg_path)
    rc, _out, err = run_cli("files", "update", "-c", cfg_path)
    assert rc == 2
    assert "--accept" in err


def test_update_accept_single_path(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    run_cli("files", "init", "-c", cfg_path)
    changed = tree / "app.conf"
    changed.write_text("key = 9\n")

    rc, _out, _err = run_cli("files", "update", "-c", cfg_path,
                             "--accept", str(changed))
    assert rc == 1  # the update run itself still reports the drift it saw
    rc, _out, _err = run_cli("files", "scan", "-c", cfg_path)
    assert rc == 0


def test_update_accept_dir_covers_children(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    run_cli("files", "init", "-c", cfg_path)
    (tree / "sub" / "notes.txt").write_text("rewritten\n")
    (tree / "sub" / "extra.txt").write_text("new\n")

    run_cli("files", "update", "-c", cfg_path, "--accept", str(tree / "sub"))
    assert run_cli("files", "scan", "-c", cfg_path)[0] == 0


def test_update_dry_run_changes_nothing(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    run_cli("files", "init", "-c", cfg_path)
    (tree / "app.conf").write_text("key = 3\n")

    rc, out, _err = run_cli("files", "update", "-c", cfg_path,
                            "--accept-all", "--dry-run")
    assert "dry-run" in out
    assert "no changes written" in out
    # Baseline untouched: the drift is still there.
    assert run_cli("files", "scan", "-c", cfg_path)[0] == 1


def test_update_accept_all(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    run_cli("files", "init", "-c", cfg_path)
    (tree / "app.conf").write_text("key = 4\n")
    (tree / "sub" / "notes.txt").unlink()

    run_cli("files", "update", "-c", cfg_path, "--accept-all")
    assert run_cli("files", "scan", "-c", cfg_path)[0] == 0


def test_verify_exit_codes(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    run_cli("files", "init", "-c", cfg_path)
    assert run_cli("files", "verify", "-c", cfg_path)[0] == 0
    (tree / "planted").write_text("x")
    assert run_cli("files", "verify", "-c", cfg_path)[0] == 1


def test_all_init_accepts_force(run_cli, make_config, watch_tree):
    # `cairn all init --force` must work like `files init --force` (the
    # registry half no-ops on non-Windows). Regression: --force was missing
    # from the `all` subparser.
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    assert run_cli("all", "init", "-c", cfg_path)[0] == 0
    assert run_cli("all", "init", "-c", cfg_path, "--force")[0] == 0


def test_scan_without_baseline_exits_2(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    rc, _out, err = run_cli("files", "scan", "-c", cfg_path)
    assert rc == 2
    assert "no baseline" in err


def test_no_paths_configured_exits_2(run_cli, make_config):
    cfg_path, _cfg = make_config([])
    rc, _out, err = run_cli("files", "init", "-c", cfg_path)
    assert rc == 2
    assert "paths" in err


def test_baseline_info(run_cli, make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    run_cli("files", "init", "-c", cfg_path)
    rc, out, _err = run_cli("baseline", "info", "-c", cfg_path)
    assert rc == 0
    assert "DB SHA-256" in out


# ---------------------------------------------------------------------------
# Packaged entry point smoke tests (subprocess)
# ---------------------------------------------------------------------------

def _subprocess_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_subprocess_version():
    r = subprocess.run([sys.executable, "-m", "cairn", "--version"],
                       capture_output=True, text=True, env=_subprocess_env())
    assert r.returncode == 0
    assert "cairn" in r.stdout


def test_subprocess_init_scan_round_trip(make_config, watch_tree):
    tree = watch_tree()
    cfg_path, _cfg = make_config([tree])
    env = _subprocess_env()

    r = subprocess.run([sys.executable, "-m", "cairn", "files", "init",
                        "-c", cfg_path],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr

    r = subprocess.run([sys.executable, "-m", "cairn", "files", "scan",
                        "-c", cfg_path],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
