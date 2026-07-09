"""Shared fixtures for the cairn test suite.

Tests invoke the real CLI entry point (cairn.__main__.main) in-process: it
takes an argv list and returns an exit code without calling sys.exit, which
gives us direct assertions, captured output, and coverage. Two subprocess
smoke tests in test_cli_cycle.py validate the packaged entry point.

The rootfs fixture is built programmatically rather than checked in: git does
not preserve setuid bits or ownership, so a committed fixture tree would
silently lose exactly the properties under test.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# Allow running the suite from a clean checkout without `pip install -e .`.
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


@pytest.fixture
def run_cli(capsys):
    """Invoke the cairn CLI in-process. Returns (exit_code, stdout, stderr)."""
    from cairn.__main__ import main

    def _run(*argv: str):
        rc = main(list(argv))
        captured = capsys.readouterr()
        return rc, captured.out, captured.err

    return _run


@pytest.fixture
def make_config(tmp_path):
    """Factory writing a JSON config (JSON needs no PyYAML) into tmp_path.

    Returns (config_path, config_dict). db_path defaults to a per-name DB
    inside tmp_path so multiple baselines can coexist in one test.
    """
    def _make(paths, *, name="baseline", **overrides):
        cfg = {
            "db_path": str(tmp_path / f"{name}.db"),
            "paths": [str(p) for p in paths],
            "store_content": True,
            "store_content_max_kb": 256,
        }
        cfg.update(overrides)
        cfg_path = tmp_path / f"{name}.config.json"
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
        return str(cfg_path), cfg

    return _make


@pytest.fixture
def watch_tree(tmp_path):
    """Factory creating a small monitored tree with text files, a subdir,
    and a .log file (excluded by the default extension list)."""
    def _make(name="watch"):
        root = tmp_path / name
        (root / "sub").mkdir(parents=True)
        (root / "app.conf").write_text("key = 1\nmode = safe\n", encoding="utf-8")
        (root / "sub" / "notes.txt").write_text("hello\n", encoding="utf-8")
        (root / "debug.log").write_text("noise\n", encoding="utf-8")
        return root

    return _make


# ---------------------------------------------------------------------------
# Fixture rootfs for --root / footprint / fidelity tests
# ---------------------------------------------------------------------------

BASE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
)

BASE_GROUP = (
    "root:x:0:\n"
    "docker:x:999:\n"
)

UNIT_WITH_USER = """\
[Unit]
Description=MyApp service

[Service]
User=myapp
Group=myapp
ExecStart=/usr/bin/myapp --serve
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
StateDirectory=myapp
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
"""

UNIT_NO_USER = """\
[Unit]
Description=MyApp agent (no User= — runs as root)

[Service]
ExecStart=/usr/bin/myapp-helper --agent
"""

CRON_D_ENTRY = "*/5 * * * * myapp /usr/bin/myapp-helper --tick\n"

ROOTFS_DIRS = [
    "etc/systemd/system",
    "etc/cron.d",
    "usr/bin",
    "usr/lib",
    "bin",
    "var/lib",
]


def build_clean_rootfs(root: Path) -> None:
    """A minimal 'clean OS image': dirs, passwd/group, one stock binary."""
    for d in ROOTFS_DIRS:
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "etc/passwd").write_text(BASE_PASSWD, encoding="utf-8")
    (root / "etc/group").write_text(BASE_GROUP, encoding="utf-8")
    stock = root / "usr/bin/stock-tool"
    stock.write_bytes(b"\x7fELF stock tool")
    os.chmod(stock, 0o755)


def install_app(root: Path, *, setuid: bool = True) -> None:
    """Mutate the rootfs the way an application installer would."""
    app = root / "usr/bin/myapp"
    app.write_bytes(b"\x7fELF myapp main binary")
    os.chmod(app, 0o755)

    helper = root / "usr/bin/myapp-helper"
    helper.write_bytes(b"\x7fELF myapp helper")
    # Setting the setuid bit on a file we own needs no root.
    os.chmod(helper, 0o4755 if setuid else 0o755)

    (root / "etc/systemd/system/myapp.service").write_text(
        UNIT_WITH_USER, encoding="utf-8")
    (root / "etc/systemd/system/myapp-agent.service").write_text(
        UNIT_NO_USER, encoding="utf-8")
    (root / "etc/cron.d/myapp").write_text(CRON_D_ENTRY, encoding="utf-8")

    # New system account (uid<1000, nologin), one login-capable user, a new
    # group, and membership added to the privileged `docker` group.
    (root / "etc/passwd").write_text(
        BASE_PASSWD
        + "myapp:x:997:997::/var/lib/myapp:/usr/sbin/nologin\n"
        + "dev1:x:1001:1001::/home/dev1:/bin/bash\n",
        encoding="utf-8")
    (root / "etc/group").write_text(
        "root:x:0:\n"
        "docker:x:999:myapp\n"
        "myapp:x:997:\n",
        encoding="utf-8")

    (root / "var/lib/myapp").mkdir(exist_ok=True)
    (root / "var/lib/myapp/state.dat").write_bytes(b"state")


@pytest.fixture
def linux_rootfs(tmp_path):
    """Factory returning a clean fixture rootfs. Call install_app() on it to
    simulate the application install."""
    def _make(name="rootfs"):
        root = tmp_path / name
        build_clean_rootfs(root)
        return root

    return _make


@pytest.fixture
def rootfs_config(make_config):
    """Config whose logical paths cover the fixture rootfs layout."""
    def _make(**overrides):
        return make_config(
            ["/etc", "/usr/bin", "/bin", "/var/lib"],
            name=overrides.pop("name", "rootfs-baseline"),
            **overrides,
        )

    return _make
