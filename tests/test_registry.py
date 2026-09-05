"""Windows registry monitor (treadmark.winreg_mon).

The functional cycle tests run ONLY on Windows (they need a live registry);
they are the first real exercise of winreg_mon on a Windows CI runner. The
parse and Linux-no-op tests run everywhere.
"""

from __future__ import annotations

import json
import sys

import pytest

from treadmark import winreg_mon

WIN = sys.platform == "win32"
win_only = pytest.mark.skipif(not WIN, reason="registry monitoring is Windows-only")


# ---------------------------------------------------------------------------
# Cross-platform: key parsing and the Linux no-op contract
# ---------------------------------------------------------------------------

def test_parse_key_accepts_both_separators():
    # winreg is imported inside winreg_mon only on Windows; _parse_key resolves
    # the hive via winreg.* so this call is Windows-only for the hive handle,
    # but the separator/hive-name logic is testable via the error path anywhere.
    if WIN:
        _hive, sub, short = winreg_mon._parse_key(r"HKLM\Software\Foo\Bar")
        assert short == "HKLM" and sub == r"Software\Foo\Bar"
        # forward slashes normalize to backslashes
        _h2, sub2, _s2 = winreg_mon._parse_key("HKLM/Software/Foo")
        assert sub2 == r"Software\Foo"
    with pytest.raises(ValueError):
        winreg_mon._parse_key(r"NOTAHIVE\Software")


def test_default_config_has_persistence_keys():
    cfg = winreg_mon.DEFAULT_CONFIG
    joined = "\n".join(cfg["registry_keys"])
    assert r"CurrentVersion\Run" in joined      # autoruns
    assert r"Services" in joined                # service hijack
    assert r"Winlogon" in joined                # userinit/shell


@pytest.mark.skipif(WIN, reason="verifies the NON-Windows no-op path")
def test_registry_commands_noop_on_non_windows(tmp_path, capsys):
    cfg = {"db_path": str(tmp_path / "reg.db"),
           "registry_keys": [r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"]}
    assert winreg_mon.cmd_init(cfg) == 0          # no-op, rc 0
    assert winreg_mon.cmd_scan(cfg) == 0
    assert "only runs on Windows" in capsys.readouterr().out
    # No DB is created on the no-op path.
    assert not (tmp_path / "reg.db").exists()


# ---------------------------------------------------------------------------
# Cross-platform: value-name-level excludes (matching + validation are pure)
# ---------------------------------------------------------------------------

LSA = r"HKLM\System\CurrentControlSet\Control\Lsa"


def test_value_exclude_matches_key_substring_and_exact_value():
    cfg = {"registry_exclude_values": [{"key": r"control\lsa", "value": "lsapid"}]}
    # both halves are case-insensitive
    assert winreg_mon.value_excluded(LSA, "LsaPid", cfg)
    # other values on the same key stay monitored
    assert not winreg_mon.value_excluded(LSA, "Security Packages", cfg)
    # same value name under an unrelated key stays monitored
    assert not winreg_mon.value_excluded(r"HKLM\Software\Foo", "LsaPid", cfg)


def test_value_exclude_normalizes_separators():
    cfg = {"registry_exclude_values": [{"key": "Control/Lsa", "value": "LsaPid"}]}
    assert winreg_mon.value_excluded(LSA, "LsaPid", cfg)


def test_value_exclude_without_key_matches_every_key():
    cfg = {"registry_exclude_values": [{"value": "Guid"}]}
    assert winreg_mon.value_excluded(
        r"HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters", "Guid", cfg)
    assert winreg_mon.value_excluded(r"HKCU\Anything", "GUID", cfg)
    # value names match exactly, not by substring
    assert not winreg_mon.value_excluded(r"HKCU\Anything", "GuidCache", cfg)


def test_value_exclude_default_value_notation():
    cfg = {"registry_exclude_values": [
        {"key": r"CurrentVersion\Run", "value": "(Default)"}]}
    assert winreg_mon.value_excluded(
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "(Default)", cfg)


def test_value_exclude_malformed_entries_never_match():
    cfg = {"registry_exclude_values": ["LsaPid", {"key": "x"}, {"value": ""}]}
    assert not winreg_mon.value_excluded(LSA, "LsaPid", cfg)


def test_value_exclude_validation():
    ok = {"registry_exclude_values": [{"key": "a", "value": "b"}, {"value": "c"}]}
    assert winreg_mon.value_exclude_problems(ok) == []
    assert winreg_mon.value_exclude_problems({}) == []

    bad = {"registry_exclude_values": [
        "LsaPid",                          # not a mapping
        {"key": "x"},                      # missing value
        {"value": ""},                     # empty value
        {"value": "ok", "vale": "typo"},   # unknown field
    ]}
    problems = winreg_mon.value_exclude_problems(bad)
    assert len(problems) == 4
    assert any("vale" in p for p in problems)

    not_a_list = {"registry_exclude_values": "LsaPid"}
    assert len(winreg_mon.value_exclude_problems(not_a_list)) == 1


def test_bad_value_excludes_fail_commands_on_any_os(tmp_path, capsys):
    """Config typos surface with exit 2 even on Linux — the same file ships
    to both fleets, so the Linux side must not silently no-op past them."""
    cfg = {"db_path": str(tmp_path / "reg.db"),
           "registry_keys": [r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"],
           "registry_exclude_values": [{"key": "missing-the-value-field"}]}
    assert winreg_mon.cmd_init(cfg) == 2
    assert winreg_mon.cmd_scan(cfg) == 2
    assert "registry_exclude_values[0]" in capsys.readouterr().err
    assert not (tmp_path / "reg.db").exists()


@pytest.mark.skipif(WIN, reason="verifies the NON-Windows no-op path")
def test_valid_value_excludes_keep_linux_noop(tmp_path, capsys):
    cfg = {"db_path": str(tmp_path / "reg.db"),
           "registry_keys": [r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"],
           "registry_exclude_values": [{"key": r"Control\Lsa", "value": "LsaPid"}]}
    assert winreg_mon.cmd_scan(cfg) == 0
    assert "only runs on Windows" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Windows-only: real init → scan → drift → detect → cleanup
# ---------------------------------------------------------------------------

@pytest.fixture
def reg_config(tmp_path):
    """Config pointing at a per-test HKCU key we can safely create/delete."""
    def _make(subkey):
        return {
            "db_path": str(tmp_path / "reg.db"),
            "registry_keys": [rf"HKCU\Software\TreadmarkTest\{subkey}"],
            "registry_recursive": True,
            "registry_max_depth": 4,
        }
    return _make


@win_only
def test_registry_init_scan_clean(reg_config):
    import winreg
    sub = r"Software\TreadmarkTest\clean"
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub)
    try:
        winreg.SetValueEx(key, "Alpha", 0, winreg.REG_SZ, "one")
        winreg.CloseKey(key)
        cfg = reg_config("clean")
        assert winreg_mon.cmd_init(cfg) == 0
        assert winreg_mon.cmd_scan(cfg, quiet=True) == 0     # no drift
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)


@win_only
def test_registry_detects_added_and_modified(reg_config, capsys):
    import winreg
    sub = r"Software\TreadmarkTest\drift"
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub)
    try:
        winreg.SetValueEx(key, "Existing", 0, winreg.REG_SZ, "orig")
        cfg = reg_config("drift")
        assert winreg_mon.cmd_init(cfg) == 0
        # drop init's progress output; only scan's stdout is the JSON contract
        capsys.readouterr()

        # add a value + modify the existing one → drift
        winreg.SetValueEx(key, "Planted", 0, winreg.REG_SZ, "payload")
        winreg.SetValueEx(key, "Existing", 0, winreg.REG_SZ, "tampered")
        winreg.CloseKey(key)

        rc = winreg_mon.cmd_scan(cfg, json_out=True)
        assert rc == 1
        payload = json.loads(capsys.readouterr().out)
        added_names = {r["value_name"] for r in payload["added"]}
        mod_names = {n["new"]["value_name"] for n in payload["modified"]}
        assert "Planted" in added_names
        assert "Existing" in mod_names
    finally:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
        except OSError:
            pass


@win_only
def test_registry_value_exclude_unmonitors_single_value(reg_config, capsys):
    """One churny value on a key can be excluded while its siblings stay
    watched — the Lsa\\LsaPid problem in miniature."""
    import winreg
    sub = r"Software\TreadmarkTest\valx"
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub)
    try:
        winreg.SetValueEx(key, "Noisy", 0, winreg.REG_SZ, "boot-1")
        winreg.SetValueEx(key, "Signal", 0, winreg.REG_SZ, "clean")
        cfg = reg_config("valx")
        cfg["registry_exclude_values"] = [
            {"key": r"TreadmarkTest\valx", "value": "Noisy"}]
        assert winreg_mon.cmd_init(cfg) == 0
        capsys.readouterr()

        winreg.SetValueEx(key, "Noisy", 0, winreg.REG_SZ, "boot-2")   # churn
        winreg.SetValueEx(key, "Signal", 0, winreg.REG_SZ, "tampered")
        winreg.CloseKey(key)

        rc = winreg_mon.cmd_scan(cfg, json_out=True)
        assert rc == 1
        payload = json.loads(capsys.readouterr().out)
        mod_names = {n["new"]["value_name"] for n in payload["modified"]}
        assert "Signal" in mod_names
        seen_anywhere = {r["value_name"] for r in payload["added"] + payload["deleted"]}
        seen_anywhere |= mod_names
        assert "Noisy" not in seen_anywhere
    finally:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
        except OSError:
            pass


@win_only
def test_registry_update_accepts_drift(reg_config):
    import winreg
    sub = r"Software\TreadmarkTest\accept"
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub)
    try:
        cfg = reg_config("accept")
        assert winreg_mon.cmd_init(cfg) == 0
        winreg.SetValueEx(key, "New", 0, winreg.REG_SZ, "v")
        winreg.CloseKey(key)
        assert winreg_mon.cmd_scan(cfg, update=True) == 1    # reports what it accepts
        assert winreg_mon.cmd_scan(cfg, quiet=True) == 0     # now clean
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
