"""Unified CLI: `treadmark files <cmd>`, `treadmark registry <cmd>`, etc.

Installed as the `treadmark` console script via pyproject.toml. Also runnable as
`python -m treadmark` for development.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__, files, winreg_mon, compare


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="treadmark",
        description="Cross-platform File Integrity Monitor",
    )
    p.add_argument("--version", action="version", version=f"treadmark {__version__}")
    sub = p.add_subparsers(dest="subsystem", required=True)

    # ----- files -----
    pf = sub.add_parser("files", help="Filesystem integrity monitor")
    pf.add_argument("command", choices=["init", "scan", "update", "verify"])
    pf.add_argument("--config", "-c")
    pf.add_argument("--json", action="store_true",
                    help="Print JSON to stdout (legacy; equivalent to --report - --format json)")
    pf.add_argument("--force", action="store_true",
                    help="Overwrite existing baseline on init")
    pf.add_argument("--report", metavar="PATH",
                    help="Write a report to PATH. Use '-' for stdout. "
                         "Format auto-detected from extension; override with --format.")
    pf.add_argument("--format", dest="report_format",
                    choices=["json", "ndjson", "csv", "sarif", "md", "html", "txt"],
                    help="Force report format. Otherwise inferred from --report extension.")
    # Flags for `update`. treadmark requires explicit opt-in so it doesn't
    # silently erase forensic evidence of what changed.
    pf.add_argument("--accept", action="append", default=[], metavar="PATH",
                    help="Accept changes for this path (repeatable). For directories, "
                         "accepts all files beneath. Required for `update`.")
    pf.add_argument("--accept-from", metavar="FILE",
                    help="Read accept paths from FILE (one per line; # comments OK).")
    pf.add_argument("--accept-all", action="store_true",
                    help="Accept ALL observed changes. Use sparingly — this erases "
                         "the forensic record of what changed.")
    pf.add_argument("--dry-run", action="store_true",
                    help="Show what update would do; write nothing.")
    pf.add_argument("--root", metavar="DIR",
                    help="Treat DIR as '/' (mounted image, container rootfs, chroot). "
                         "Paths in the config are joined onto it; the baseline stores "
                         "logical paths, so baselines are portable across rootfs.")

    # ----- registry (Windows-only at runtime; arg is accepted everywhere) -----
    pr = sub.add_parser("registry", help="Windows registry integrity monitor")
    pr.add_argument("command", choices=["init", "scan", "update", "verify"])
    pr.add_argument("--config", "-c")
    pr.add_argument("--json", action="store_true")

    # ----- aws (SCAFFOLD, dormant — unit-tested, CLI unwired; uncomment to wire) -----
    # awsmon.py has fake-client unit tests (tests/test_awsmon.py) but has NOT
    # been validated against a real AWS account, so the subcommand is dormant
    # for now. To enable: uncomment this block, _run_aws, its dispatch branch
    # in main(), and the `aws` extra (+ boto3 in `all`) in pyproject.toml.
    # Deliberately NOT part of `all`: a local host and a cloud account are
    # different trust domains with different credentials and cadences.
    #
    # paws = sub.add_parser("aws",
    #                       help="AWS account-configuration drift monitor "
    #                            "(baseline + scan; requires boto3 via "
    #                            "`pip install treadmark[aws]`)")
    # paws.add_argument("command", choices=["init", "scan", "update", "verify"])
    # paws.add_argument("--config", "-c")
    # paws.add_argument("--json", action="store_true")
    # paws.add_argument("--profile", metavar="NAME",
    #                   help="AWS profile override (else config aws_profile / "
    #                        "environment credentials)")
    # paws.add_argument("--region", action="append", default=[], metavar="R",
    #                   help="Limit to region R (repeatable; overrides config "
    #                        "aws_regions; default = all enabled regions)")
    # paws.add_argument("--report", metavar="PATH",
    #                   help="Write the drift report to PATH "
    #                        "(json/sarif/md/txt by extension; '-' = stdout)")
    # paws.add_argument("--format", dest="report_format",
    #                   choices=["json", "sarif", "md", "txt"],
    #                   help="Force report format (else inferred from --report)")

    # ----- azure / gcp / k8s (SCAFFOLD — untested; uncomment to wire) -----
    # Modules src/treadmark/azmon.py, gcpmon.py, k8smon.py exist and follow the
    # awsmon shape, but are unwired pending real-tenant/cluster validation. To
    # enable: uncomment these subparsers, the dispatch branches in main(), and
    # the azure/gcp/k8s extras in pyproject.toml; then add fake-client tests.
    #
    # for _name, _help in (("azure", "Azure account-config drift (needs treadmark[azure])"),
    #                      ("gcp",   "GCP account-config drift (needs treadmark[gcp])"),
    #                      ("k8s",   "Kubernetes cluster-config drift (needs treadmark[k8s])")):
    #     _p = sub.add_parser(_name, help=_help)
    #     _p.add_argument("command", choices=["init", "scan", "update", "verify"])
    #     _p.add_argument("--config", "-c")
    #     _p.add_argument("--json", action="store_true")

    # ----- all (run files + registry back-to-back) -----
    pa = sub.add_parser("all", help="Run files + registry sequentially")
    pa.add_argument("command", choices=["init", "scan", "update", "verify"])
    pa.add_argument("--config", "-c")
    pa.add_argument("--json", action="store_true")
    pa.add_argument("--force", action="store_true",
                    help="Overwrite existing baseline on init (files half)")

    # ----- compare -----
    pc = sub.add_parser("compare",
                        help="Compare this host (or a baseline) against another baseline")
    pc_sub = pc.add_subparsers(dest="compare_mode", required=True)

    # `treadmark compare against <golden.db> --config local.yaml`
    pca = pc_sub.add_parser("against",
                            help="Walk this host and compare to a golden baseline DB")
    pca.add_argument("golden_db", help="Path to the reference baseline DB")
    pca.add_argument("--config", "-c", required=True,
                     help="Local config (which paths to walk on THIS host)")
    pca.add_argument("--json", action="store_true")

    # `treadmark compare baselines <a.db> <b.db>`
    pcb = pc_sub.add_parser("baselines",
                            help="Diff two baseline databases (no filesystem walk)")
    pcb.add_argument("db_a", help="First baseline DB")
    pcb.add_argument("db_b", help="Second baseline DB")
    pcb.add_argument("--json", action="store_true")

    # ----- footprint (install-time application footprint for access modeling) -----
    pfp = sub.add_parser("footprint",
                         help="Capture an application's install-time footprint as a "
                              "structured model for least-privilege policy generation")
    pfp.add_argument("--config", "-c",
                     help="Config whose baseline was captured on the clean OS")
    pfp.add_argument("--app", metavar="NAME",
                     help="Name of the application being profiled")
    pfp.add_argument("--report", metavar="PATH",
                     help="Write the model to PATH as JSON. Use '-' or omit for stdout.")
    pfp.add_argument("--access-vars", metavar="PATH", dest="access_vars",
                     help="Also write an Ansible vars YAML for the "
                          "declarative_access role: bare service/timer names, "
                          "quadlet-generated units, unit files for write ACLs, and "
                          "the config/state/log folders the install created. "
                          "Review before applying; pass the team via "
                          "-e group_name=... at apply time. Linux footprints only.")
    pfp.add_argument("--root", metavar="DIR",
                     help="Treat DIR as '/' (mounted image, container rootfs, chroot).")
    pfp.add_argument("--include-noise", action="store_true",
                     help="Windows: keep OS background-churn services (Defender, "
                          "time sync, the update/servicing stack). Off by default "
                          "so the footprint shows only what the installer did.")

    # ----- access-vars (footprint JSON → Ansible vars for declarative_access) -----
    pav = sub.add_parser("access-vars",
                         help="Convert an existing footprint JSON into an Ansible "
                              "vars file for the declarative_access role "
                              "(same output as `footprint --access-vars`)")
    pav.add_argument("footprint_json",
                     help="Footprint JSON produced by `treadmark footprint --report`")
    pav.add_argument("-o", "--out", metavar="PATH",
                     help="Write the vars YAML to PATH. Use '-' or omit for stdout.")

    # ----- baseline (provenance / inspection) -----
    pb = sub.add_parser("baseline",
                        help="Inspect baseline provenance for forensic / chain-of-custody use")
    pb_sub = pb.add_subparsers(dest="baseline_mode", required=True)
    pbi = pb_sub.add_parser("info",
                            help="Print metadata about the baseline DB (creation time, host, integrity hash)")
    pbi.add_argument("--config", "-c")
    pbi.add_argument("--json", action="store_true")

    return p


def _run_files(args) -> int:
    cfg = files.load_config(args.config)
    if getattr(args, "root", None):
        cfg["root_prefix"] = args.root
    if not cfg.get("paths"):
        print("[!] config has no `paths` configured.", file=sys.stderr)
        return 2
    if args.command == "init":
        return files.cmd_init(cfg, force=getattr(args, "force", False))
    if args.command == "scan":
        return files.cmd_scan(
            cfg,
            json_out=args.json,
            report_path=getattr(args, "report", None),
            report_format=getattr(args, "report_format", None),
        )
    if args.command == "update":
        accept = list(getattr(args, "accept", []) or [])
        if getattr(args, "accept_from", None):
            try:
                accept.extend(files.load_accept_file(args.accept_from))
            except OSError as e:
                print(f"[!] cannot read --accept-from {args.accept_from}: {e}",
                      file=sys.stderr)
                return 2
        if getattr(args, "accept_all", False):
            accept.append("*")
        return files.cmd_update(cfg, accept=accept,
                                dry_run=getattr(args, "dry_run", False))
    if args.command == "verify":
        return files.cmd_verify(cfg)
    return 2


def _run_registry(args) -> int:
    cfg = winreg_mon.load_config(args.config)
    if args.command == "init":
        return winreg_mon.cmd_init(cfg)
    if args.command == "scan":
        return winreg_mon.cmd_scan(cfg, json_out=args.json)
    if args.command == "update":
        return winreg_mon.cmd_scan(cfg, update=True)
    if args.command == "verify":
        return winreg_mon.cmd_scan(cfg, quiet=True)
    return 2


# SCAFFOLD — dormant with the aws subparser (see build_parser):
# def _run_aws(args) -> int:
#     from . import awsmon
#     cfg = files.load_config(args.config)
#     if getattr(args, "profile", None):
#         cfg["aws_profile"] = args.profile
#     if getattr(args, "region", None):
#         cfg["aws_regions"] = args.region
#     if args.command == "init":
#         return awsmon.cmd_init(cfg)
#     if args.command == "scan":
#         return awsmon.cmd_scan(cfg, json_out=args.json,
#                                report_path=args.report,
#                                report_format=args.report_format)
#     if args.command == "update":
#         return awsmon.cmd_scan(cfg, update=True)
#     if args.command == "verify":
#         return awsmon.cmd_scan(cfg, quiet=True)
#     return 2


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to a legacy codepage (cp1252) that can't encode
    # the arrows/checkmarks in our output (→ ✓ …), which crashes init/scan with
    # a UnicodeEncodeError. Force UTF-8. No-op where stdout is already UTF-8.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass

    args = build_parser().parse_args(argv)

    if args.subsystem == "files":
        return _run_files(args)
    if args.subsystem == "registry":
        return _run_registry(args)
    # SCAFFOLD — uncomment once awsmon (real-account) / azmon / gcpmon are
    # validated (see build_parser):
    # if args.subsystem == "aws":
    #     return _run_aws(args)
    # if args.subsystem == "azure":
    #     from . import azmon
    #     cfg = files.load_config(args.config)
    #     return {"init": azmon.cmd_init}.get(args.command, lambda c: azmon.cmd_scan(
    #         c, json_out=args.json, update=args.command == "update",
    #         quiet=args.command == "verify"))(cfg)
    # if args.subsystem == "gcp":
    #     from . import gcpmon
    #     cfg = files.load_config(args.config)
    #     return {"init": gcpmon.cmd_init}.get(args.command, lambda c: gcpmon.cmd_scan(
    #         c, json_out=args.json, update=args.command == "update",
    #         quiet=args.command == "verify"))(cfg)
    # if args.subsystem == "k8s":
    #     from . import k8smon
    #     cfg = files.load_config(args.config)
    #     return {"init": k8smon.cmd_init}.get(args.command, lambda c: k8smon.cmd_scan(
    #         c, json_out=args.json, update=args.command == "update",
    #         quiet=args.command == "verify"))(cfg)
    if args.subsystem == "all":
        # exit code is the worst of the two (drift > clean), matching what
        # alerting systems expect from a verify-style check
        rc1 = _run_files(args)
        rc2 = _run_registry(args)
        return max(rc1, rc2)
    if args.subsystem == "compare":
        if args.compare_mode == "against":
            cfg = files.load_config(args.config)
            return compare.cmd_against(cfg, args.golden_db, json_out=args.json)
        if args.compare_mode == "baselines":
            return compare.cmd_baselines(args.db_a, args.db_b, json_out=args.json)
    if args.subsystem == "baseline":
        if args.baseline_mode == "info":
            cfg = files.load_config(args.config)
            return files.cmd_baseline_info(cfg, json_out=args.json)
    if args.subsystem == "footprint":
        from . import footprint as footprint_mod
        cfg = files.load_config(args.config)
        if getattr(args, "root", None):
            cfg["root_prefix"] = args.root
        if getattr(args, "include_noise", False):
            cfg["footprint_include_noise"] = True
        if not cfg.get("paths"):
            print("[!] config has no `paths` configured.", file=sys.stderr)
            return 2
        return footprint_mod.cmd_footprint(cfg, app_name=args.app,
                                           report_path=args.report,
                                           access_vars_path=args.access_vars)
    if args.subsystem == "access-vars":
        from . import accessvars
        return accessvars.cmd_access_vars(args.footprint_json, args.out)
    return 2


if __name__ == "__main__":
    sys.exit(main())
