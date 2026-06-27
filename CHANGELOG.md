# Changelog

All notable changes to cairn are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). After the initial release, entries below this line are appended automatically by `python-semantic-release` from conventional commit messages — don't edit them by hand.

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
