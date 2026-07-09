"""End-to-end footprint capture on the programmatic fixture rootfs."""

from __future__ import annotations

import json
import sys

import pytest

from conftest import install_app

pytestmark = pytest.mark.skipif(sys.platform == "win32",
                                reason="footprint parses Linux rootfs layouts")


@pytest.fixture
def footprint_model(run_cli, linux_rootfs, rootfs_config, tmp_path):
    """Init a clean-rootfs baseline, install the app, capture the footprint."""
    root = linux_rootfs()
    cfg_path, _cfg = rootfs_config()
    rc, _out, _err = run_cli("files", "init", "-c", cfg_path,
                             "--root", str(root), "--force")
    assert rc == 0

    install_app(root)

    report = tmp_path / "footprint.json"
    rc, _out, _err = run_cli("footprint", "-c", cfg_path, "--root", str(root),
                             "--app", "myapp", "--report", str(report))
    assert rc == 1  # changes present
    return json.loads(report.read_text()), root


def _added_paths(model):
    out = []
    for entries in model["filesystem"]["added_by_category"].values():
        out.extend(e["path"] for e in entries)
    return out


def test_summary_counts(footprint_model):
    model, _root = footprint_model
    s = model["summary"]
    assert s["files_added"] >= 5
    assert s["files_modified"] >= 2      # /etc/passwd and /etc/group
    assert s["systemd_units"] == 2
    assert s["cron_jobs"] == 1
    assert s["users_added"] == 2
    assert s["groups_added"] == 1
    assert model["footprint_type"] == "install_time"


def test_added_files_present_with_categories(footprint_model):
    model, _root = footprint_model
    by_cat = model["filesystem"]["added_by_category"]
    assert "/usr/bin/myapp" in [e["path"] for e in by_cat.get("binary", [])]
    unit_paths = [e["path"] for e in by_cat.get("systemd_unit", [])]
    assert "/etc/systemd/system/myapp.service" in unit_paths


def test_unit_identity_and_capabilities_extracted(footprint_model):
    model, _root = footprint_model
    units = {u["name"]: u for u in model["services"]["systemd_units"]}
    assert units["myapp.service"]["user"] == "myapp"
    assert units["myapp.service"]["capabilities"] == ["CAP_NET_BIND_SERVICE"]
    assert units["myapp.service"]["exec_start"] == ["/usr/bin/myapp --serve"]
    assert units["myapp-agent.service"]["user"] is None


def test_cron_job_parsed_with_user_field(footprint_model):
    model, _root = footprint_model
    job = model["scheduled"]["cron_jobs"][0]
    assert job["run_as"] == "myapp"
    assert job["schedule"] == "*/5 * * * *"
    assert "/usr/bin/myapp-helper" in job["command"]


def test_principals_from_passwd_group_diff(footprint_model):
    model, _root = footprint_model
    users = {u["name"]: u for u in model["principals"]["users_added"]}
    assert users["myapp"]["is_system_account"] is True
    assert users["myapp"]["login_disabled"] is True
    assert users["dev1"]["login_disabled"] is False

    groups = [g["name"] for g in model["principals"]["groups_added"]]
    assert "myapp" in groups

    docker_changes = [m for m in model["principals"]["membership_changes"]
                      if m["group"] == "docker"]
    assert docker_changes and docker_changes[0]["users_added"] == ["myapp"]


def test_risks(footprint_model):
    model, _root = footprint_model
    risks_by_kind: dict = {}
    for r in model["risks"]:
        risks_by_kind.setdefault(r["kind"], []).append(r)

    setuid = risks_by_kind["setuid_binary"]
    assert any("/usr/bin/myapp-helper" in r["detail"] for r in setuid)

    assert "privileged_group_membership" in risks_by_kind
    assert "login_capable_account" in risks_by_kind

    # service_runs_as_root fires only for the unit lacking User=.
    root_svcs = [r["detail"] for r in risks_by_kind["service_runs_as_root"]]
    assert any("myapp-agent.service" in d for d in root_svcs)
    assert not any("myapp.service " in d for d in root_svcs)


def test_setuid_binary_in_privilege_section(footprint_model):
    model, _root = footprint_model
    setuid_paths = [e["path"] for e in model["privilege"]["setuid_binaries"]]
    assert setuid_paths == ["/usr/bin/myapp-helper"]


def test_access_hints_for_service_principal(footprint_model):
    model, _root = footprint_model
    svc_hints = [h for h in model["access_hints"]
                 if h.get("principal_type") == "systemd_service"
                 and h["principal"] == "myapp"]
    assert svc_hints
    needs = {n["path"]: n for n in svc_hints[0]["needs"]}
    assert "execute" in needs["/usr/bin/myapp"]["access"]
    assert "/var/lib/myapp" in needs  # from StateDirectory=


def test_baseline_provenance_block(footprint_model):
    model, _root = footprint_model
    b = model["baseline"]
    assert len(b["db_sha256"]) == 64
    assert b["created_at"] != "unknown"
    assert b["source_host"]


def test_logical_paths_no_tmpdir_leakage(footprint_model):
    model, root = footprint_model
    assert model["root_prefix"] == str(root)
    for p in _added_paths(model):
        assert p.startswith("/")
        assert str(root) not in p


def test_footprint_clean_rootfs_exits_0(run_cli, linux_rootfs, rootfs_config, tmp_path):
    root = linux_rootfs(name="untouched")
    cfg_path, _cfg = rootfs_config(name="untouched-baseline")
    run_cli("files", "init", "-c", cfg_path, "--root", str(root), "--force")
    report = tmp_path / "clean-footprint.json"
    rc, _out, _err = run_cli("footprint", "-c", cfg_path, "--root", str(root),
                             "--app", "nothing", "--report", str(report))
    assert rc == 0
    model = json.loads(report.read_text())
    assert model["summary"]["files_added"] == 0


def test_footprint_without_baseline_exits_2(run_cli, linux_rootfs, rootfs_config):
    root = linux_rootfs(name="nobaseline")
    cfg_path, _cfg = rootfs_config(name="missing-baseline")
    rc, _out, err = run_cli("footprint", "-c", cfg_path, "--root", str(root),
                            "--app", "x")
    assert rc == 2
    assert "no baseline" in err
