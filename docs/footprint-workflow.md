# Install Footprint & Access Modeling

`cairn footprint` answers one question: **what did this application's install actually touch?**

It produces a structured JSON model of every file, service, scheduled job, user, group, and privilege grant the install introduced — with the security-relevant objects parsed rather than left as raw file diffs. The intended consumer is an agent that derives a least-privilege access model.

## The caveat, up front

This is an **install-time** footprint. It describes what an installer wrote to disk. It does not describe what the application accesses when it runs.

A policy derived only from this data will be wrong in both directions:

- **Over-grant on the install tree.** The installer drops 500 files under `/opt/myapp`; the app reads maybe five of them at runtime.
- **Under-grant on runtime paths.** The app reads `/etc/resolv.conf`, writes to `/tmp`, opens `/dev/urandom`, binds a socket. The installer wrote none of those, so they are absent here. A policy built from this alone breaks the app on first start.

Treat this as **one input** to the access model. The output carries `footprint_type: "install_time"` and a `footprint_caveat` string so a downstream agent can reason about its own limits. The schema reserves room for a `runtime` key so eBPF/auditd/strace observations can be merged later.

Install footprint tells you the *declared* surface. Runtime observation tells you the *used* surface. You need both.

## Basic workflow: a live host

```sh
# 1. On the clean OS, before the developer touches it
sudo cairn files init --config /etc/cairn/cairn-footprint-linux.yaml

# 2. Hand the box over. Developer installs their application.

# 3. Capture the footprint
sudo cairn footprint \
    --config /etc/cairn/cairn-footprint-linux.yaml \
    --app myapp \
    --report myapp-footprint.json
```

Exit code is `1` when a footprint was found (files changed), `0` when nothing changed, `2` on error.

`packaging/cairn-footprint-linux.yaml` ships a config tuned for this job. Its exclude list is deliberately more aggressive than the forensic-drift config: it drops package-manager bookkeeping, caches, logs, generated symlink farms, and host-specific files (`/etc/machine-id`, `/etc/resolv.conf`, SSH host keys) that change on their own and would drown the signal.

`store_content: true` is **required**. The semantic parsers read `/etc/passwd`, `/etc/group`, sudoers, and systemd units out of the baseline to diff them. Without stored content there is nothing to diff against.

## Scanning a rootfs instead of a live host

`--root DIR` treats `DIR` as `/`. Paths in the config are joined onto it, and the baseline stores **logical** paths (`/etc/passwd`, not `/mnt/image/etc/passwd`). That makes baselines portable: capture one from a base image, diff it against a completely different directory.

This works for anything you can mount or extract:

| Target | How to get a rootfs |
|---|---|
| Container image | `scripts/container-rootfs.sh myapp:1.4.0 /tmp/rootfs/myapp` |
| VM disk image | `guestmount -a disk.qcow2 -i --ro /mnt/image` |
| Cloud image / AMI snapshot | attach the volume, `mount /dev/xvdf1 /mnt/image` |
| Chroot / build root | it's already a directory |
| Backup / archive | `tar -x -C /mnt/image --same-owner` |

### Container images

```sh
# Extract both images (run as root so uid/gid and setuid bits survive)
sudo ./scripts/container-rootfs.sh myapp-base:1.0 /tmp/rootfs/base
sudo ./scripts/container-rootfs.sh myapp:1.4.0    /tmp/rootfs/app

# Baseline the base image
sudo cairn files init --config packaging/cairn-footprint-linux.yaml \
    --root /tmp/rootfs/base --force

# Footprint the derived image
sudo cairn footprint --config packaging/cairn-footprint-linux.yaml \
    --root /tmp/rootfs/app --app myapp --report myapp-footprint.json
```

**Extract as root.** `docker export | tar -x` without root silently drops uid/gid ownership and setuid bits. Ownership-based access hints and setuid risk detection both become wrong — and wrong quietly, which is worse than failing.

### Why not just diff the layers?

You can. `docker save` gives you layer tarballs and a manifest; walking those gets you added and removed paths, and even file modes, without extracting anything. If a file list is all you need, that's cheaper.

What a layer diff doesn't give you is the semantic layer. It reports that `/etc/systemd/system/myapp.service` was added. It doesn't tell you the unit runs as uid 997, that uid 997 was added to `docker` in the same layer, and that the unit grants itself `CAP_NET_BIND_SERVICE`. Extracting those relationships is the point of `footprint`.

Layer diffs also only exist for OCI images. A mounted VM disk, a golden AMI, and a machine a contractor handed back have no manifest. `--root` handles all of them identically.

### What `--root` misses on container images

`docker export` flattens the filesystem but drops image *metadata*: `ENTRYPOINT`, `CMD`, `USER`, `ENV`, `EXPOSE`, and volume declarations. Those are real parts of a container's access model — `USER` in particular determines the runtime principal, and a container with no systemd unit still has one.

`container-rootfs.sh` writes `<dest>.inspect.json` alongside the rootfs for exactly this reason. Feed both to the policy agent.

## What gets parsed

| Object | Sources | What's extracted |
|---|---|---|
| systemd units | `/etc/systemd/system`, `/usr/lib/systemd/system`, drop-ins | `User=`, `Group=`, all `ExecStart*`, `SupplementaryGroups=`, `AmbientCapabilities=`, `CapabilityBoundingSet=`, `ReadWritePaths=`, `ReadOnlyPaths=`, `StateDirectory=`/`LogsDirectory=`/`RuntimeDirectory=`/`ConfigurationDirectory=`/`CacheDirectory=`, `EnvironmentFile=`, `WorkingDirectory=`, the hardening directives (`PrivateTmp`, `ProtectSystem`, `ProtectHome`, `NoNewPrivileges`), and for `.timer` units the `[Timer]` schedule (`OnCalendar=`, `On*Sec=`, `Persistent=`) plus the service the timer activates |
| podman quadlets | `/etc/containers/systemd`, `/usr/share/containers/systemd`, rootless `~/.config/containers/systemd` and `/etc/containers/systemd/users/` | quadlet type, the generated unit name (`foo.container` → `foo.service`, `foo.pod` → `foo-pod.service`, …, honoring `ServiceName=`), `Image=`, `Exec=`, container `User=`, `PublishPort=`, `Volume=`, `Network=`, `EnvironmentFile=`, and rootless-ness + the owning user (derived from the path) |
| cron jobs | `/etc/cron.d/*`, `/etc/crontab`, `/etc/cron.{hourly,daily,weekly,monthly}/*`, `/var/spool/cron/*` | schedule (including `@reboot` and friends), the user field where the format has one, the command |
| users | `/etc/passwd` diff | name, uid, gid, home, shell, whether it's a system account, whether login is disabled |
| groups | `/etc/group` diff | new groups, and **membership changes on existing groups** — this is how you catch a service account being added to `docker`, `sudo`, or `shadow` |
| sudo rules | `/etc/sudoers`, `/etc/sudoers.d/*` | principal (user or `%group`), runas target, `NOPASSWD`, permitted commands |
| privileged binaries | mode bits + `security.capability` xattr | setuid, setgid, world-writable-and-executable, file capabilities |
| PAM | `/etc/pam.d/*`, `/etc/security/*` | which files the install touched (always flagged) |
| other integration points | polkit, D-Bus system policy, sysctl, udev rules, `ld.so.conf.d`, `profile.d`, `limits.d`, AppArmor, SELinux, tmpfiles, sysusers, modprobe, logrotate, init scripts, nsswitch | recorded with category and added/modified |

Everything else is bucketed by category (`binary`, `library`, `config`, `opt_tree`, `state_dir`, …) under `filesystem.added_by_category`, so nothing is silently dropped.

## Output structure

```
schema_version, footprint_type, footprint_caveat, generated_at,
application, host, platform, root_prefix
baseline{ db_path, db_sha256, created_at, source_host, source_os }
summary{ counts }
principals{ users_added, groups_added, membership_changes }
services{ systemd_units, quadlets }
scheduled{ cron_jobs }
privilege{ sudo_rules, setuid_binaries, setgid_binaries,
           file_capabilities, pam_files_touched }
security_relevant_files[]
executables[]
filesystem{ added_by_category, modified, deleted }
access_hints[]        <- the part the policy agent wants
risks[]               <- the part a human should read first
scan_errors[]
```

### `access_hints`

One entry per principal the install introduced. For each, the paths it plausibly needs and at what level, with provenance:

```json
{
  "principal": "myapp",
  "principal_type": "systemd_service",
  "unit": "myapp.service",
  "supplementary_groups": ["docker"],
  "declared_capabilities": ["CAP_NET_BIND_SERVICE"],
  "hardening": { "private_tmp": true, "protect_system": "strict",
                 "no_new_privileges": true },
  "needs": [
    { "path": "/etc/myapp", "access": "read",
      "sources": ["systemd:ReadOnlyPaths", "systemd:ConfigurationDirectory"] },
    { "path": "/opt/myapp/bin/server", "access": "read,execute",
      "sources": ["systemd:ExecStart"] },
    { "path": "/var/lib/myapp", "access": "read,write",
      "sources": ["systemd:StateDirectory"] }
  ]
}
```

Paths are deduplicated and access levels unioned across the directives that justified them, so `/etc/myapp` appears once even though two directives point at it.

Two deliberate omissions:

- **Timers, targets, and sockets are not principals.** A `.timer` has no `ExecStart` and no `User=`. The service it activates carries the identity; the timer doesn't. Emitting a hint for it would invent a principal that never runs anything.
- **`root` file-ownership is not evidence.** Root owns most of the filesystem by default. "root owns `/etc`" tells you nothing about what a root service needs. Ownership-based hints are only emitted for non-root principals, where a deliberate `chown` during install is a real signal.

### `risks`

Severity-ranked things a human should look at before any of this becomes policy:

| Kind | Severity |
|---|---|
| `uid_zero_account` | critical |
| `setuid_binary`, `world_writable_executable`, `file_capabilities` | high |
| `sudoers_rule` with `NOPASSWD` | high |
| `privileged_group_membership` (`sudo`, `docker`, `wheel`, `shadow`, `disk`, …) | high |
| `ambient_capabilities` | high |
| `pam_modified` | high |
| `sudoers_rule` requiring a password | medium |
| `setgid_binary` | medium |
| `service_runs_as_root` (no `User=`) | medium |
| `login_capable_account` | medium |

`service_runs_as_root` fires on any unit without a `User=` directive. That's usually correct behavior for a system daemon, not a finding — it's there so the agent has to decide rather than assume.

## Feeding the agent

The JSON is the interface. A reasonable prompt shape:

> Here is an install-time footprint (`footprint_type: install_time`). Derive a candidate least-privilege policy for each principal in `access_hints`. Treat `needs` as a lower bound, not a complete set — the app will touch runtime paths absent from this document. Flag every entry in `risks` for human review before enforcement. Do not grant anything under `filesystem.added_by_category` that no principal's `needs` justifies.

The last sentence matters. The install tree is the thing most likely to get over-granted, because it's the biggest section of the document and the easiest to hand-wave into "the app probably needs all of this."

**Windows prompt addendum.** When the footprint is `schema 1.0-windows`, additionally instruct:

> Treat each service's `run_as` and each scheduled task's identity as the principal set — the SAM is unreadable, so never claim an account was "created", only that it is *referenced*; flag every non-builtin `run_as` for on-host reconciliation. Derive DACL scoping (`icacls`) from the per-file `owner`/`acl` evidence; prefer `NT SERVICE\<name>` virtual accounts or gMSAs over custom accounts, and propose `sc.exe sidtype restricted` plus privilege stripping per user-mode service (staged first). Emit the `service_binary` sha256 inventory as AppLocker/WDAC allowlist input, but regenerate rule hashes on-host — AppLocker uses Authenticode PE hashes, not flat-file sha256. Kernel drivers are not principals: route them to driver-signing / WDAC review. Firewall rules, COM registrations, and WMI subscriptions are capture gaps — anything network-facing is `[needs-runtime-confirmation]`. State the install channel: winget/MSI installs have full footprint visibility; Windows Feature installs activate pre-staged component-store payload, so absent services are not evidence of absence — complete them from app knowledge and say so.

The output format for a full report is the Windows section map in the runbooks reading guide (`smoke-out/runbooks/README.md`): the same 13 sections as the Linux runbooks, with Windows meanings, plus a PowerShell/INF/XML stub set.

## Exporting Ansible access vars

`--access-vars PATH` (or the standalone `cairn access-vars footprint.json -o PATH`) turns a Linux footprint into a ready-to-review Ansible vars file for the `usc.declarative_access` role: bare service/timer names for scoped sudoers grants, quadlet-generated unit names, the installed unit/quadlet files (write ACLs), the config/state/log folders the install created, ownership entries for paths owned by install-created accounts, and `loginctl` linger users for rootless quadlets.

```sh
sudo cairn footprint --config ... --app myapp \
    --report myapp-footprint.json --access-vars myapp-access.yml
# or later, from the archived JSON:
cairn access-vars myapp-footprint.json -o myapp-access.yml
```

WHO gets the access is deliberately not in the file — the operator passes `-e group_name=...` at apply time. Review the file before applying; it inherits the install-time caveat at the top of this document. The end-to-end workflow, the vars contract, and the security tradeoffs live in the linux-access repo (`docs/declarative-systemd-access.md` there); cairn only emits the vars.

## Windows

Windows services (reconstructed from the registry `Services` subtree) and scheduled tasks (parsed from their Task Scheduler XML) are extracted as semantic objects, the same way systemd units are on Linux — each carries its run-as identity, start type, and image path, and file entries carry the Windows owner + DACL (the analog of Linux mode/owner/group). Run `cairn all init` on the clean OS (not just `cairn files init`) so the registry half is baselined.

Windows models also carry `access_hints`, in the same shape as Linux: one entry per principal the install introduced (each service's run-as account, each scheduled task's identity), listing the paths it plausibly needs with the evidence — the service binary from `ImagePath` (read+execute), config paths passed as `ImagePath` arguments (read), and files the installer chowned to that account (read+write). SYSTEM/builtin identities get no ownership-derived paths for the same reason root doesn't on Linux: they own most of the OS by default, so ownership carries no signal. Kernel drivers are excluded — they aren't user-mode principals. The enforcement side belongs to the operator: scope DACLs (`icacls`) to those principals, prefer virtual service accounts (`NT SERVICE\<name>`) or gMSAs over LocalSystem, grant service accounts only `SeServiceLogonRight`, and use the per-file `sha256` inventory as AppLocker/WDAC allowlist input.

Because Windows rewrites service registry keys as normal background activity — the time service updates `LastKnownGoodTime` on every NTP sync, Defender churns on definition updates, and BITS / the update + servicing stack toggle during any feature install — an install footprint would otherwise be full of services the installer never touched. `cairn footprint` drops these known background-churn services by default (the list is `winsemantic.NOISE_SERVICES`), so the model shows what the installer actually did. Pass `--include-noise` to keep them. This filtering is footprint-only: the FIM monitor (`cairn registry` / `cairn all`) keeps every change, because a Defender or time-service edit may be exactly the tampering you want to catch.

## Known gaps

- **COM registrations, firewall rules, and WMI subscriptions are not parsed** on Windows. `cairn registry` captures the underlying registry keys, but nothing turns those particular key shapes into semantic objects yet. (Windows services and scheduled tasks *are* parsed — see above.)
- **No runtime observation.** By design. See the caveat at the top.
- **Network posture is invisible.** Listening ports are a runtime property. `AmbientCapabilities=CAP_NET_BIND_SERVICE` hints at a privileged port, but the actual bind isn't in this document.
- **Installer-run scripts leave no trace of intent.** If a postinstall script runs `chmod 777 /srv/data`, the footprint records the resulting mode. It cannot tell you the script did it deliberately or by accident.
- **Container `USER`, `ENTRYPOINT`, and `ENV` are outside the rootfs.** Capture them from `image inspect` separately.
