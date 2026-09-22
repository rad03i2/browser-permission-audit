from __future__ import annotations

import argparse
import json
import sys
from .core import ManifestError, audit_path

VERSION = "1.0.0"

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="browser-permission-audit", description="Audit Chromium extension manifest permissions offline.")
    p.add_argument("path", nargs="?", default=".", help="manifest.json or extension directory")
    p.add_argument("--json", action="store_true", dest="as_json", help="emit machine-readable JSON")
    p.add_argument("--fail-on", choices=["moderate", "high", "critical"], help="return exit code 2 at or above this risk")
    p.add_argument("--version", action="version", version=f"browser-permission-audit {VERSION} — Radwan Abdulhadi Ahmed / @rad03i2")
    return p

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = audit_path(args.path)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"{report.name} — risk: {report.risk.upper()} ({report.score}/100)")
        print(f"Manifest: V{report.manifest_version or '?'} | API permissions: {len(report.permissions)} | Host permissions: {len(report.host_permissions)}")
        if not report.findings:
            print("No requested permissions or flagged policy patterns found.")
        for finding in report.findings:
            suffix = f" [{finding.permission}]" if finding.permission else ""
            print(f"- {finding.severity.upper():6} {finding.message}{suffix}")
    if args.fail_on:
        ranks = {"low": 0, "moderate": 1, "high": 2, "critical": 3}
        if ranks[report.risk] >= ranks[args.fail_on]:
            return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
