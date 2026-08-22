"""load_config: defaults, merging, YAML/JSON handling."""

from __future__ import annotations

import json
import sys

import pytest

from treadmark import files


def test_defaults_when_no_path():
    cfg = files.load_config(None)
    assert cfg == files.DEFAULT_CONFIG
    # Must be a copy: mutating the result must not poison the module default.
    cfg["db_path"] = "/elsewhere.db"
    assert files.DEFAULT_CONFIG["db_path"] != "/elsewhere.db"


def test_missing_file_warns_and_uses_defaults(tmp_path, capsys):
    cfg = files.load_config(str(tmp_path / "does-not-exist.json"))
    assert cfg == files.DEFAULT_CONFIG
    assert "config not found" in capsys.readouterr().err


def test_json_config_merges_over_defaults(tmp_path):
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({"db_path": "/tmp/x.db", "exclude": ["/var/cache/"]}))
    cfg = files.load_config(str(p))
    assert cfg["db_path"] == "/tmp/x.db"
    assert cfg["exclude"] == ["/var/cache/"]
    # Unspecified keys keep their defaults.
    assert cfg["hash_algorithm"] == files.DEFAULT_CONFIG["hash_algorithm"]
    assert cfg["exclude_extensions"] == files.DEFAULT_CONFIG["exclude_extensions"]


def test_yaml_config(tmp_path):
    pytest.importorskip("yaml")
    p = tmp_path / "cfg.yaml"
    p.write_text("db_path: /tmp/y.db\npaths:\n  - /etc\n")
    cfg = files.load_config(str(p))
    assert cfg["db_path"] == "/tmp/y.db"
    assert cfg["paths"] == ["/etc"]


def test_yaml_without_pyyaml_exits_2(tmp_path, monkeypatch, capsys):
    p = tmp_path / "cfg.yaml"
    p.write_text("db_path: /tmp/y.db\n")
    # None in sys.modules makes `import yaml` raise ImportError.
    monkeypatch.setitem(sys.modules, "yaml", None)
    with pytest.raises(SystemExit) as exc:
        files.load_config(str(p))
    assert exc.value.code == 2
    assert "PyYAML" in capsys.readouterr().err


def test_empty_yaml_yields_defaults(tmp_path):
    pytest.importorskip("yaml")
    p = tmp_path / "empty.yaml"
    p.write_text("")
    assert files.load_config(str(p)) == files.DEFAULT_CONFIG
