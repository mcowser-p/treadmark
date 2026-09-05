# Changelog

All notable changes to cairn are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). After the initial release, entries below this line are appended automatically by `python-semantic-release` from conventional commit messages — don't edit them by hand.

## v0.12.0 (2026-09-05)

### Features

- `compare_fields` config option (`files scan`, `compare against`,
  `footprint`): a list naming which record diffs are reported — any of
  `sha256`, `size`, `mode`, `owner`, `group`, `acl`, `mtime`, `atime`.
  `[sha256, size, mode, owner, group, acl]` keeps content and
  permission/ownership detection while ignoring timestamp-only drift
  (golden-image clones re-touch mtime across whole trees at first boot).
  Unset compares everything, exactly as before.
- `registry_exclude_values` config option (`treadmark registry`):
  value-name-level excludes — `{key: <key-path substring>, value: <exact
  value name>}` mappings, both halves case-insensitive, `key` optional —
  so a single churny value (a PID, a per-boot GUID) can be unmonitored
  without unwatching its whole key.
- Both options fail closed: a malformed or typo'd entry exits 2 with a
  pointed message instead of silently narrowing a scan.
- Shipped Windows config: `Control\Lsa` → `LsaPid` (the lsass PID, new
  every boot) is excluded out of the box, with commented golden-image
  blocks for the other per-clone identity values and a no-timestamps
  `compare_fields` example.

## v0.11.0 (2026-08-22)

### ⚠ Breaking

- **cairn is now treadmark.** The command is `treadmark`, the package is
  `treadmark`, and the config file is `treadmark-footprint-linux.yaml`.
  `cairn` invocations and `cairn-*.yaml` configs no longer work.

### Features

- **PyPI**: `pip install treadmark` — sdist and wheel are published on every
  release via PyPI Trusted Publishing (binaries remain the primary channel).
- **Docs**: mkdocs site with a ReadTheDocs config (`treadmark.readthedocs.io`).
- `footprint`: capture raw sudoers file contents in the privilege section.
- `footprint --access-vars`: derive pam_group local groups, and model
  per-group writable/readable paths for install-created groups.

### Bug fixes

- `access-vars` output now suggests the `<hostname>-app_restricted` group
  convention (the retired `rg.<host>` dot notation is gone).
- `files`: store logical paths with forward slashes on Windows.

### Changed

- `cairn aws` (shipped in 0.10.0) demoted to a **dormant scaffold** pending validation against a real AWS account: the subcommand, its dispatch, and the `aws` extra (plus boto3 in `all`) are commented out. `awsmon.py` and its fake-client unit tests remain in the tree. Re-enable by uncommenting the marked blocks in `src/cairn/__main__.py` and `pyproject.toml` — see `docs/cloud-workflow.md`.

### Features

- Widened default watch set in `/etc/cairn/cairn.yaml`: now also monitors `/opt`, `/home`, `/root`, `/usr/local/bin`, `/usr/local/sbin`, the vendor systemd tree (`/usr/lib/systemd` — units, generators, sleep/shutdown hooks), and per-user crontabs (`/var/spool/cron`). Home-dir noise (`.cache`, Trash, snap) is excluded, but shell rc files, `~/.ssh`, and shell history stay watched. Note: with `store_content` on, watching `/home`/`/root` can capture dotfiles and SSH keys into the (root-only) baseline DB — treat it as sensitive.
- Curated noise excludes in the default `/etc/cairn/cairn.yaml`: package-manager bookkeeping, caches, package-tool backup droppings, initramfs images, and `/run` are now excluded out of the box, while classic tamper targets (`/etc/hosts`, CA bundles, `/etc/machine-id`, SSH host keys, the kernel image) stay watched. A commented-out "golden baseline / cross-host compare" block covers per-host identity files. **Upgrade note:** on a host with an existing baseline, the next scan reports newly-excluded paths as deleted once — accept them with `cairn files update --accept`.
- `cairn footprint` embeds container image metadata (`USER`, `ENTRYPOINT`, `CMD`, `ENV`, exposed ports) from `<root>.inspect.json` when scanning with `--root`, and detects unfaithful rootfs extractions (non-root `docker export | tar -x` drops uid/gid and setuid bits), stamping `fidelity: degraded` into the report and warning on scans.

- `cairn footprint` — capture an application's install-time footprint as a structured JSON model for least-privilege policy generation. Parses systemd units (identity, exec, capabilities, hardening, directory directives), cron jobs, `/etc/passwd` and `/etc/group` diffs including membership changes on existing groups, sudoers rules, setuid/setgid binaries, and file capabilities. Emits per-principal `access_hints` with provenance, and severity-ranked `risks`.
- `--root DIR` on `cairn files` and `cairn footprint` — treat DIR as `/` when scanning a mounted disk image, extracted container rootfs, or chroot. Baselines store logical paths, so a baseline captured from one rootfs can be diffed against another.
- `scripts/container-rootfs.sh` — extract a container image's flattened filesystem plus its image metadata for footprinting.
- `packaging/cairn-footprint-linux.yaml` — config tuned for install-footprint capture, with aggressive exclusion of package-manager bookkeeping, caches, and host-specific files.

### Documentation

- `docs/footprint-workflow.md` — footprint workflow, container and disk-image scanning, output schema, and the install-time vs. runtime limitation.

## [0.2.0] — 2026-05-17

Initial release.

### Features

- File integrity baseline + scan for Linux and Windows from a single binary
- SHA-256 hashing with metadata capture (size, mtime, mode, owner/group, optional ACL on Windows)
- Optional gzipped content storage of small text files in the baseline, enabling unified diffs of changed configs in scan output
- Windows registry monitoring (`cairn registry init|scan`) for autoruns, services, policies, and other persistence-relevant hives
- Seven output formats: terminal (auto-colored), JSON, NDJSON, CSV, SARIF, Markdown, HTML, plain text
- `cairn baseline info` exposes provenance for chain-of-custody (DB SHA-256, source host, creation timestamp)
- `cairn compare against` / `cairn compare baselines` for cross-host drift comparison against a reference baseline
- Selective `cairn files update --accept PATH` with `--accept-from FILE` and `--dry-run` — update silently accepts no changes; operators must opt in explicitly per path

### Packaging

- `.deb` for Debian/Ubuntu (dpkg-deb)
- `.rpm` for RHEL/Rocky/Fedora (rpmbuild)
- `.msi` for Windows (WiX 4+)
- Single-file binaries (PyInstaller) for Linux and Windows
- Python wheel for pipx / pip / PyPI

### Operational

- GitHub Actions CI matrix building all artifacts on every PR
- Conventional-commits PR title enforcement
- `python-semantic-release` for automated versioning and changelog generation
