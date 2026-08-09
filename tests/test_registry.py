"""Windows registry monitor (cairn.winreg_mon).

The functional cycle tests run ONLY on Windows (they need a live registry);
they are the first real exercise of winreg_mon on a Windows CI runner. The
parse and Linux-no-op tests run everywhere.
"""

from __future__ import annotations

import json
import sys

import pytest

from cairn import winreg_mon

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
# Windows-only: real init → scan → drift → detect → cleanup
# ---------------------------------------------------------------------------

@pytest.fixture
def reg_config(tmp_path):
    """Config pointing at a per-test HKCU key we can safely create/delete."""
    def _make(subkey):
        return {
            "db_path": str(tmp_path / "reg.db"),
            "registry_keys": [rf"HKCU\Software\CairnTest\{subkey}"],
            "registry_recursive": True,
            "registry_max_depth": 4,
        }
    return _make


@win_only
def test_registry_init_scan_clean(reg_config):
    import winreg
    sub = r"Software\CairnTest\clean"
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
    sub = r"Software\CairnTest\drift"
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub)
    try:
        winreg.SetValueEx(key, "Existing", 0, winreg.REG_SZ, "orig")
        cfg = reg_config("drift")
        assert winreg_mon.cmd_init(cfg) == 0
        # init prints progress lines; drop them so the JSON parse below
        # sees only cmd_scan's output.
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
def test_registry_update_accepts_drift(reg_config):
    import winreg
    sub = r"Software\CairnTest\accept"
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
