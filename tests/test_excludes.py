"""should_skip semantics and walk_paths filtering/pruning."""

from __future__ import annotations

import os

from treadmark import files


def _cfg(**overrides):
    cfg = dict(files.DEFAULT_CONFIG)
    cfg["exclude_extensions"] = []
    cfg.update(overrides)
    return cfg


# ---------------------------------------------------------------------------
# should_skip unit semantics
# ---------------------------------------------------------------------------

def test_substring_match():
    cfg = _cfg(exclude=["/var/cache/"])
    assert files.should_skip("/var/cache/apt/pkgcache.bin", cfg)
    # Documented current behavior: patterns are substrings, not anchors —
    # a pattern matches anywhere in the path.
    assert files.should_skip("/opt/var/cache/x", cfg)
    assert not files.should_skip("/var/lib/app/data", cfg)


def test_exclude_pattern_is_case_sensitive():
    cfg = _cfg(exclude=["/var/cache/"])
    assert not files.should_skip("/VAR/CACHE/apt", cfg)


def test_extension_match_case_insensitive_both_ways():
    assert files.should_skip("/etc/app/debug.LOG", _cfg(exclude_extensions=[".log"]))
    assert files.should_skip("/etc/app/debug.log", _cfg(exclude_extensions=[".LOG"]))
    assert not files.should_skip("/etc/app/app.conf", _cfg(exclude_extensions=[".log"]))


def test_backslash_normalization():
    cfg = _cfg(exclude=["/var/cache/"])
    assert files.should_skip("\\var\\cache\\apt", cfg)


def test_exclude_applies_to_logical_path_under_root(tmp_path):
    (tmp_path / "etc").mkdir()
    mtab = tmp_path / "etc" / "mtab"
    mtab.write_text("x")
    cfg = _cfg(exclude=["/etc/mtab"], root_prefix=str(tmp_path))
    assert files.should_skip(str(mtab), cfg)
    # Proof that matching happens on the LOGICAL path: a pattern equal to the
    # real rootfs prefix matches every real path, but never a logical one —
    # so with root mapping active it must not skip anything.
    cfg_prefix_pat = _cfg(exclude=[str(tmp_path)], root_prefix=str(tmp_path))
    assert not files.should_skip(str(mtab), cfg_prefix_pat)


# ---------------------------------------------------------------------------
# walk_paths filtering
# ---------------------------------------------------------------------------

def test_walk_skips_excluded_files(tmp_path):
    root = tmp_path / "watch"
    root.mkdir()
    (root / "keep.conf").write_text("k")
    (root / "drop.log").write_text("d")
    cfg = _cfg(paths=[str(root)], exclude_extensions=[".log"])
    walked = list(files.walk_paths(cfg))
    assert str(root / "keep.conf") in walked
    assert str(root / "drop.log") not in walked


def test_walk_prunes_excluded_dirs(tmp_path, monkeypatch):
    root = tmp_path / "watch"
    (root / "excluded").mkdir(parents=True)
    (root / "included").mkdir()
    (root / "excluded" / "hidden.txt").write_text("x")
    (root / "included" / "visible.txt").write_text("y")

    # Spy on os.walk to prove the excluded dir is pruned from traversal
    # (dirnames mutation), not merely filtered out of the yielded results.
    real_walk = os.walk
    visited: list[str] = []

    def spying_walk(top, **kwargs):
        for dirpath, dirnames, filenames in real_walk(top, **kwargs):
            visited.append(dirpath)
            yield dirpath, dirnames, filenames

    monkeypatch.setattr(files.os, "walk", spying_walk)

    cfg = _cfg(paths=[str(root)], exclude=["/excluded"])
    walked = list(files.walk_paths(cfg))

    assert str(root / "included" / "visible.txt") in walked
    # Compare relative to the watch root: the pytest tmpdir name itself
    # contains the word "excluded" (from the test name).
    assert all("excluded" not in os.path.relpath(p, root) for p in walked)
    assert str(root / "excluded") not in visited


def test_single_file_path_respects_exclude(tmp_path):
    f = tmp_path / "solo.log"
    f.write_text("x")
    cfg = _cfg(paths=[str(f)], exclude_extensions=[".log"])
    assert list(files.walk_paths(cfg)) == []
    cfg_ok = _cfg(paths=[str(f)])
    assert list(files.walk_paths(cfg_ok)) == [str(f)]


def test_missing_path_warns_and_continues(tmp_path, capsys):
    present = tmp_path / "present"
    present.mkdir()
    (present / "f.txt").write_text("x")
    cfg = _cfg(paths=[str(tmp_path / "absent"), str(present)])
    walked = list(files.walk_paths(cfg))
    assert str(present / "f.txt") in walked
    assert "path missing" in capsys.readouterr().err
