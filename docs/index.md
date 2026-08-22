# treadmark

Cross-platform file integrity monitor and install-footprint capture for
Linux and Windows. treadmark records what an installation actually
created — services, timers, quadlets, files, folders, ownership — and
can export the result as a ready-to-review Ansible vars file for the
[mcowser_p.declarative_access](https://galaxy.ansible.com/ui/repo/published/mcowser_p/declarative_access/)
collection.

## Guides

- [Footprint workflow](footprint-workflow.md) — capture an install footprint and export access vars
- [Golden baseline workflow](golden-baseline-workflow.md) — baseline and drift-check a fleet
- [Forensic workflow](forensic-workflow.md) — investigate changes after the fact
- [Cloud workflow](cloud-workflow.md) — cloud-side monitoring scaffolds
- [AWS smoke testing](aws-smoke.md) — the EC2/AMI test harness
- [Output formats](output-formats.md) — report and JSON schema reference
