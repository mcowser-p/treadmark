Name:           treadmark
Version:        %{_version}
Release:        1%{?dist}
Summary:        Cross-platform File Integrity Monitor
License:        Apache-2.0
URL:            https://github.com/mcowser-p/treadmark
BuildArch:      %{_target_arch}

# We pre-build the binary with PyInstaller; nothing for rpmbuild to compile.
AutoReqProv:    no

%description
A treadmark is a stack of stones marking known-good ground. This is the same
idea for files: build a baseline once, then verify nothing has been
disturbed on subsequent scans. Runs on Linux and Windows. AIDE-style,
single binary, no agent required.

%install
# %{_sourcedir} contains the staged tree built by build-rpm.sh
mkdir -p %{buildroot}
cp -a %{_sourcedir}/payload/. %{buildroot}/

%files
/usr/bin/treadmark
%config(noreplace) /etc/treadmark/treadmark.yaml
%dir /etc/treadmark
%doc /usr/share/doc/treadmark/README.md
%doc /usr/share/doc/treadmark/golden-baseline-workflow.md
%doc /usr/share/doc/treadmark/output-formats.md
%doc /usr/share/doc/treadmark/forensic-workflow.md

%post
if [ ! -d /var/lib/treadmark ]; then
    mkdir -p /var/lib/treadmark
    chmod 700 /var/lib/treadmark
fi

cat <<'EOF'

treadmark installed.

treadmark is a forensic tool: capture a known-good baseline now, then run a
scan after-the-fact to see what changed. It does NOT run on a schedule.

Folder layout:
  /usr/bin/treadmark          - the binary
  /etc/treadmark/treadmark.yaml   - default config (edit before first run)
  /var/lib/treadmark/         - baseline DB lives here (root-only, mode 0700)

Typical workflow:
  1. Edit /etc/treadmark/treadmark.yaml to choose what to monitor.
  2. On a known-good system, capture the baseline:
       treadmark files init --config /etc/treadmark/treadmark.yaml
  3. Inspect the baseline's provenance for evidence purposes:
       treadmark baseline info --config /etc/treadmark/treadmark.yaml
  4. Later, when investigating: run a scan to see what changed:
       treadmark files scan --config /etc/treadmark/treadmark.yaml --report drift.md

See /usr/share/doc/treadmark/forensic-workflow.md for the full investigation
workflow.

EOF

%changelog
* %{_changelog_date} mcowser-p <mcowser-p@users.noreply.github.com> - %{_version}-1
- Release %{_version}.
