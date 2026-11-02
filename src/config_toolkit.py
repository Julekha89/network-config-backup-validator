"""Offline network configuration snapshot, change detection and policy checks.

Designed for authorized, local text configuration files only; no network logins.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

RULES = {
    "hostname": re.compile(r"(?m)^hostname\s+\S+\s*$"),
    "ssh_version_2": re.compile(r"(?mi)^ip ssh version 2\s*$"),
    "logging_enabled": re.compile(r"(?mi)^logging (?:host|on|buffered|trap)\b"),
    "no_telnet": re.compile(r"(?mi)^\s*transport input (?:ssh|none)\s*$"),
}
SENSITIVE = re.compile(r"(?im)^(?:\s*(?:password|secret|enable secret|username\s+\S+\s+(?:password|secret)|snmp-server community|tacacs-server key|radius-server key|ipsec pre-shared-key)\b).*$")


def read_config(path: Path) -> str:
    """Read an existing local configuration file as UTF-8."""
    return path.read_text(encoding="utf-8")


def redact(config: str) -> str:
    """Mask entire lines containing common credential commands (not exhaustive)."""
    return SENSITIVE.sub("! [REDACTED SENSITIVE LINE]", config)


def validate(config: str) -> dict[str, bool]:
    """Simple Cisco IOS-style example checks, not vendor-certified compliance."""
    return {name: bool(pattern.search(config)) for name, pattern in RULES.items()}


def compare(old: str, new: str, old_label="baseline", new_label="current") -> str:
    """Return unified diff of sanitized configuration text."""
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=old_label, tofile=new_label,
    ))


def checksum(config: str) -> str:
    return hashlib.sha256(config.encode("utf-8")).hexdigest()


def generate_report(baseline: str, current: str, device: str) -> dict:
    """Produce structured report using sanitized input only."""
    safe_old, safe_new = redact(baseline), redact(current)
    checks = validate(safe_new)
    return {
        "device": device,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "changed": safe_old != safe_new,
        "baseline_sha256": checksum(safe_old),
        "current_sha256": checksum(safe_new),
        "checks": checks,
        "checks_passed": sum(checks.values()),
        "checks_total": len(checks),
        "diff": compare(safe_old, safe_new),
        "disclaimer": "Illustrative IOS-style checks only; verify against your approved standards.",
    }


def process(baseline_path: Path, current_path: Path, output_dir: Path, device: str) -> dict:
    baseline = read_config(baseline_path)
    current = read_config(current_path)
    report = generate_report(baseline, current, device)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "baseline_redacted.txt").write_text(redact(baseline), encoding="utf-8")
    (output_dir / "current_redacted.txt").write_text(redact(current), encoding="utf-8")
    (output_dir / "changes.diff").write_text(report["diff"], encoding="utf-8")
    (output_dir / "validation_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Offline configuration backup, diff, and validation demo")
    p.add_argument("--baseline", type=Path, default=Path("examples/configs/router_baseline.txt"))
    p.add_argument("--current", type=Path, default=Path("examples/configs/router_current.txt"))
    p.add_argument("--device", default="demo-router")
    p.add_argument("--output", type=Path, default=Path("output/demo-router"))
    args = p.parse_args(argv)
    try:
        result = process(args.baseline, args.current, args.output, args.device)
    except (OSError, UnicodeError) as exc:
        p.exit(2, f"Unable to process configuration: {exc}\n")
    print(f"Device: {result['device']} | Changed: {result['changed']} | "
          f"Checks: {result['checks_passed']}/{result['checks_total']} | Output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
