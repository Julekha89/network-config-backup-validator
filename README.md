# Network Configuration Backup & Validation Toolkit

![CI](https://github.com/Julekha89/network-config-backup-validator/actions/workflows/ci.yml/badge.svg)

A Python portfolio project for **network infrastructure operations and configuration change review**. It reads two authorized local configuration snapshots, creates redacted backups, detects changes, produces a unified diff, and applies illustrative Cisco IOS-style policy checks. Designed as an offline proof-of-concept for Network Developer and Infrastructure Engineer applications.

> **Portfolio demonstration:** The included device configurations are synthetic. This tool does **not** log in to network devices, schedule remote backups, deploy changes, or guarantee security compliance. Do not use the example checks as a substitute for organization-approved validation.

## Features

- Compare **baseline** and **current** text configuration snapshots
- Generate **timestamped JSON validation reports** and unified configuration diffs
- Save **sanitized local backup copies** for review
- Detect missing examples of hostname, SSH v2, logging, and VTY transport input SSH/none
- SHA-256 fingerprints for *redacted* snapshots
- Pure Python standard library, cross-platform CLI
- Eight automated unit tests and GitHub Actions CI

## Architecture

```text
Local baseline + current configuration files
                     |
                     v
          Read and redact secrets
                     |
               +-----+-----+
               |           |
               v           v
        Change detection   Example policy validation
               |           |
               +-----+-----+
                     |
                     v
        Backups + diff + JSON report
```

## Run locally

Requires **Python 3.10+**. From the repository root:

```bash
python -m src.config_toolkit
```

Example output:

```text
Device: demo-router | Changed: True | Checks: 4/4 | Output: output/demo-router
```

Inspect generated files in `output/demo-router/`:

```text
baseline_redacted.txt
current_redacted.txt
changes.diff
validation_report.json
```

To compare other **local, authorized** sample files:

```bash
python -m src.config_toolkit --baseline examples/configs/router_baseline.txt --current examples/configs/router_current.txt --device branch-router-01 --output output/branch-router-01
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Repository structure

```text
src/config_toolkit.py                  CLI, redaction, comparison, and validation
examples/configs/router_baseline.txt   Synthetic baseline config
examples/configs/router_current.txt    Synthetic changed config
tests/test_config_toolkit.py            Automated tests
.github/workflows/ci.yml              CI unit tests and offline demo
.gitignore                            Ignore local outputs and secrets
LICENSE                               MIT license
```

## Validation checks

| Check | Example condition |
|---|---|
| `hostname` | `hostname NAME` present |
| `ssh_version_2` | `ip ssh version 2` present |
| `logging_enabled` | `logging host` / `logging on` / `logging buffered` / `logging trap` present |
| `no_telnet` | `transport input ssh` or `transport input none` present somewhere |

Checks are **simple text matches**, not full configuration parsing. For example, `no_telnet` does not inspect every VTY range, and the credential redactor does not cover every vendor secret format. Do **not** upload real credentials or sensitive configurations.

## Security and operating boundaries

- Only process lab configs or backups you are authorized to inspect.
- Credentials and environment secrets must never be committed to GitHub.
- Redaction is best-effort; always manually review outputs before sharing.
- No SSH, Telnet, SNMP, API calls or device modifications occur.
- A changed configuration is reported, not automatically rejected or rolled back.

## Future enhancements

- Vendor-aware parsing and more complete redaction rules
- Policy-as-code YAML profiles with severity levels
- Approved-device SSH/SFTP collectors with vault-managed credentials
- Scheduled backup rotation and retention policies
- Pull-request based config review, notifications and change tickets
- Real lab validation against supported network platforms

## Skills demonstrated

Python automation · Network configuration management · Configuration comparison · Change detection · Security-conscious reporting · JSON · GitHub Actions · Unit testing · Network operations

## License

MIT — see [LICENSE](LICENSE).
