Name:           cairn
Version:        %{_version}
Release:        1%{?dist}
Summary:        Cross-platform File Integrity Monitor
License:        MIT
URL:            https://example.com/cairn
BuildArch:      %{_target_arch}

# We pre-build the binary with PyInstaller; nothing for rpmbuild to compile.
AutoReqProv:    no

%description
A cairn is a stack of stones marking known-good ground. This is the same
idea for files: build a baseline once, then verify nothing has been
disturbed on subsequent scans. Runs on Linux and Windows. AIDE-style,
single binary, no agent required.

%install
# %{_sourcedir} contains the staged tree built by build-rpm.sh
mkdir -p %{buildroot}
cp -a %{_sourcedir}/payload/. %{buildroot}/

%files
/usr/bin/cairn
%config(noreplace) /etc/cairn/cairn.yaml
%dir /etc/cairn
%doc /usr/share/doc/cairn/README.md
%doc /usr/share/doc/cairn/golden-baseline-workflow.md
%doc /usr/share/doc/cairn/output-formats.md
%doc /usr/share/doc/cairn/forensic-workflow.md

%post
if [ ! -d /var/lib/cairn ]; then
    mkdir -p /var/lib/cairn
    chmod 700 /var/lib/cairn
fi

cat <<'EOF'

cairn installed.

cairn is a forensic tool: capture a known-good baseline now, then run a
scan after-the-fact to see what changed. It does NOT run on a schedule.

Folder layout:
  /usr/bin/cairn          - the binary
  /etc/cairn/cairn.yaml   - default config (edit before first run)
  /var/lib/cairn/         - baseline DB lives here (root-only, mode 0700)

Typical workflow:
  1. Edit /etc/cairn/cairn.yaml to choose what to monitor.
  2. On a known-good system, capture the baseline:
       cairn files init --config /etc/cairn/cairn.yaml
  3. Inspect the baseline's provenance for evidence purposes:
       cairn baseline info --config /etc/cairn/cairn.yaml
  4. Later, when investigating: run a scan to see what changed:
       cairn files scan --config /etc/cairn/cairn.yaml --report drift.md

See /usr/share/doc/cairn/forensic-workflow.md for the full investigation
workflow.

EOF

%changelog
* %{_changelog_date} ops <ops@example.com> - %{_version}-1
- Release %{_version}.
