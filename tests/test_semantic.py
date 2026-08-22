"""Pure parser tests for treadmark.semantic — quadlets and timer directives.

No rootfs fixture and no platform skips: these exercise string parsing only,
so they run everywhere (including Windows).
"""

from __future__ import annotations

from treadmark import semantic as sem


# ---------------------------------------------------------------------------
# Path classification
# ---------------------------------------------------------------------------

def test_classify_quadlet_rootful_roots():
    assert sem.classify_path("/etc/containers/systemd/web.container") == "quadlet"
    assert sem.classify_path("/usr/share/containers/systemd/db.volume") == "quadlet"


def test_classify_quadlet_all_extensions():
    for ext in ("container", "pod", "network", "volume", "kube", "image", "build"):
        assert sem.classify_path(f"/etc/containers/systemd/x.{ext}") == "quadlet"


def test_classify_quadlet_rootless_locations():
    assert sem.classify_path(
        "/home/dev1/.config/containers/systemd/x.container") == "quadlet"
    assert sem.classify_path(
        "/root/.config/containers/systemd/x.container") == "quadlet"
    assert sem.classify_path(
        "/etc/containers/systemd/users/1000/x.container") == "quadlet"


def test_classify_quadlet_dropin():
    assert sem.classify_path(
        "/etc/containers/systemd/web.container.d/10-override.conf") == "quadlet_dropin"


def test_classify_non_quadlet_containers_files_still_config():
    # Only files under a containers/systemd root are quadlets.
    assert sem.classify_path("/etc/containers/registries.conf") == "config"
    assert sem.classify_path("/etc/containers/policy.json") == "config"


def test_classify_plain_home_file_unaffected():
    assert sem.classify_path("/home/dev1/notes.txt") == "home"


# ---------------------------------------------------------------------------
# Generated service-name mapping (podman-systemd.unit(5))
# ---------------------------------------------------------------------------

def test_quadlet_service_name_all_types():
    f = sem.quadlet_service_name
    assert f("web.container") == "web.service"
    assert f("app.kube") == "app.service"
    assert f("db.pod") == "db-pod.service"
    assert f("data.volume") == "data-volume.service"
    assert f("net.network") == "net-network.service"
    assert f("base.image") == "base-image.service"
    assert f("site.build") == "site-build.service"


# ---------------------------------------------------------------------------
# parse_quadlet
# ---------------------------------------------------------------------------

QUADLET = """\
[Unit]
Description=Web frontend

[Container]
Image=registry.example.com/web:1
Exec=serve --port 80
User=10001
PublishPort=8080:80
Volume=/srv/web:/data:Z
Volume=webcache:/cache
Network=internal.network
EnvironmentFile=/etc/web/env

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
"""


def test_parse_quadlet_container_fields():
    q = sem.parse_quadlet("/etc/containers/systemd/web.container", QUADLET)
    assert q.quadlet_type == "container"
    assert q.service_name == "web.service"
    assert q.rootless is False and q.owner is None
    assert q.description == "Web frontend"
    assert q.image == "registry.example.com/web:1"
    assert q.exec == ["serve --port 80"]
    assert q.container_user == "10001"
    assert q.publish_ports == ["8080:80"]
    assert q.volumes == ["/srv/web:/data:Z", "webcache:/cache"]
    assert q.networks == ["internal.network"]
    assert q.environment_files == ["/etc/web/env"]
    assert q.wanted_by == ["multi-user.target"]
    # Unmodeled keys are preserved, not dropped
    assert q.other_directives["Service.Restart"] == ["always"]


def test_parse_quadlet_service_name_override():
    content = "[Container]\nImage=x\nServiceName=custom-web\n"
    q = sem.parse_quadlet("/etc/containers/systemd/web.container", content)
    assert q.service_name == "custom-web.service"


def test_parse_quadlet_rootless_owner_from_home_path():
    q = sem.parse_quadlet("/home/alice/.config/containers/systemd/x.container",
                          "[Container]\nImage=x\n", file_owner="runner")
    assert q.rootless is True
    assert q.owner == "alice"   # path evidence wins over the file owner


def test_parse_quadlet_root_home_is_rootless_root():
    q = sem.parse_quadlet("/root/.config/containers/systemd/x.container",
                          "[Container]\nImage=x\n")
    assert q.rootless is True
    assert q.owner == "root"


def test_parse_quadlet_etc_users_uid_dir():
    q = sem.parse_quadlet("/etc/containers/systemd/users/1000/x.container",
                          "[Container]\nImage=x\n")
    assert q.rootless is True
    assert q.owner == "1000"    # loginctl accepts numeric uids


def test_parse_quadlet_etc_users_owner_fallback():
    q = sem.parse_quadlet("/etc/containers/systemd/users/x.container",
                          "[Container]\nImage=x\n", file_owner="bob")
    assert q.rootless is True
    assert q.owner == "bob"


# ---------------------------------------------------------------------------
# Timer directives on systemd units
# ---------------------------------------------------------------------------

TIMER = """\
[Unit]
Description=Nightly job

[Timer]
OnCalendar=daily
OnCalendar=Mon..Fri 02:00
Persistent=true
OnBootSec=15min

[Install]
WantedBy=timers.target
"""


def test_parse_timer_fields():
    u = sem.parse_systemd_unit("/etc/systemd/system/job.timer", TIMER)
    assert u.unit_type == "timer"
    assert u.on_calendar == ["daily", "Mon..Fri 02:00"]
    assert u.persistent is True
    assert u.on_boot_sec == "15min"
    assert u.activates == "job.service"
    # Modeled [Timer] keys must not also land in the catch-all
    assert not any(k.startswith("Timer.") for k in u.other_directives)


def test_timer_calendar_reset_semantics():
    content = "[Timer]\nOnCalendar=daily\nOnCalendar=\nOnCalendar=weekly\n"
    u = sem.parse_systemd_unit("/etc/systemd/system/x.timer", content)
    assert u.on_calendar == ["weekly"]


def test_timer_activates_honors_unit_directive():
    content = "[Timer]\nOnCalendar=daily\nUnit=other.service\n"
    u = sem.parse_systemd_unit("/etc/systemd/system/x.timer", content)
    assert u.activates == "other.service"


def test_timer_monotonic_fields():
    content = "[Timer]\nOnUnitActiveSec=1h\nOnActiveSec=30s\n"
    u = sem.parse_systemd_unit("/etc/systemd/system/x.timer", content)
    assert u.on_unit_active_sec == "1h"
    assert u.on_active_sec == "30s"


def test_path_unit_unit_directive_stays_in_catch_all():
    # Section gating: Unit= inside [Path] is not a timer directive.
    content = "[Path]\nPathExists=/run/x\nUnit=handler.service\n"
    u = sem.parse_systemd_unit("/etc/systemd/system/watch.path", content)
    assert u.activates is None
    assert u.other_directives["Path.Unit"] == ["handler.service"]


def test_service_unit_has_no_activates():
    u = sem.parse_systemd_unit("/etc/systemd/system/x.service",
                               "[Service]\nExecStart=/bin/true\n")
    assert u.activates is None
