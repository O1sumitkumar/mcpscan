"""mcpscan CLI — scan MCP servers for security vulnerabilities."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _color(text: str, level: str) -> str:
    codes = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[33m",
        "MEDIUM": "\033[93m",
        "LOW": "\033[94m",
        "SAFE": "\033[92m",
        "BOLD": "\033[1m",
        "DIM": "\033[2m",
    }
    if not sys.stdout.isatty():
        return text
    return f"{codes.get(level,'')}{text}\033[0m"


def _print_result(result, verbose: bool = False) -> None:
    level = result.risk_level
    print(f"\n{_color(level, level)} {_color(result.server_name, 'BOLD')}")
    print(f"  Risk score:  {result.risk_score:.0f}/100")
    print(f"  Tools:       {result.tool_count}")
    print(f"  Findings:    {result.finding_count}")
    print(f"  Scan time:   {result.scan_time_ms:.1f}ms")

    if result.error:
        print(f"  Error: {result.error}")
        return

    if result.is_safe:
        print(_color("  No security issues detected.", "SAFE"))
        return

    for finding in result.findings:
        print()
        print(f"  {_color(f'[{finding.rule_id}] {finding.name}', finding.severity.value.upper())}")
        print(f"  Severity: {finding.severity.value.upper()}")
        print("  Description:")
        for line in finding.rule.description.splitlines():
            print(f"    {line.strip()}")
        print("  Remediation:")
        for line in finding.rule.remediation.splitlines():
            print(f"    {line.strip()}")
        if verbose and finding.snippets:
            print("  Found:")
            for s in finding.snippets[:3]:
                print(f"    - {s[:120]}")
    print()


# Risk levels that make `mcpscan scan` exit 1, for a file or a directory.
_FAILING_LEVELS = ("CRITICAL", "HIGH")


def _exit_code(results) -> int:
    """2 if any scan could not finish (ERROR), 1 for a failing level, else 0."""
    if any(r.risk_level == "ERROR" for r in results):
        return 2
    return 1 if any(r.risk_level in _FAILING_LEVELS for r in results) else 0


def cmd_scan(args) -> int:
    from mcpscan import MCPScanner

    scanner = MCPScanner(verbose=args.verbose)
    path = Path(args.target)

    if not path.exists():
        print(f"Error: {path} not found")
        return 2

    if path.is_dir():
        # One recursive match covers both top-level and nested manifests; the set
        # keeps a file from being scanned twice and sorting keeps output stable.
        paths = sorted(set(path.rglob("*.json")))
        report = scanner.scan_files(paths)
        if args.format == "json":
            print(
                json.dumps(
                    {
                        "total": report.total,
                        "critical": report.critical_count,
                        "flagged": report.flagged_count,
                        "results": [
                            {
                                "server": r.server_name,
                                "risk_level": r.risk_level,
                                "risk_score": r.risk_score,
                                "tool_count": r.tool_count,
                                "findings": [
                                    {
                                        "id": f.rule_id,
                                        "name": f.name,
                                        "severity": f.severity.value,
                                        "snippets": f.snippets,
                                    }
                                    for f in r.findings
                                ],
                            }
                            for r in report.results
                        ],
                    },
                    indent=2,
                )
            )
        else:
            print(report.summary())
        return _exit_code(report.results)

    result = scanner.scan_file(path)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "server": result.server_name,
                    "risk_level": result.risk_level,
                    "risk_score": result.risk_score,
                    "tool_count": result.tool_count,
                    "findings": [
                        {
                            "id": f.rule_id,
                            "name": f.name,
                            "severity": f.severity.value,
                            "description": f.rule.description,
                            "remediation": f.rule.remediation,
                            "snippets": f.snippets,
                        }
                        for f in result.findings
                    ],
                },
                indent=2,
            )
        )
    else:
        _print_result(result, verbose=args.verbose)

    return _exit_code([result])


def cmd_rules(args) -> None:
    from mcpscan.rules import ALL_RULES

    print(f"\nMCPscan has {len(ALL_RULES)} detection rules:\n")
    for rule in ALL_RULES:
        print(f"  {rule.id}  [{rule.severity.value.upper()}]  {rule.name}")
        print(f"         Tags: {', '.join(rule.tags)}")
    print()


def main() -> None:
    p = argparse.ArgumentParser(
        prog="mcpscan",
        description="Security scanner for MCP (Model Context Protocol) servers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mcpscan scan server.json
  mcpscan scan server.json --format json
  mcpscan scan ./manifests/
  mcpscan rules
        """,
    )
    p.add_argument("--version", action="version", version="mcpscan 1.0.0")
    sub = p.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan an MCP manifest file or directory")
    p_scan.add_argument("target", help="JSON manifest file or directory")
    p_scan.add_argument("--format", choices=["text", "json"], default="text")
    p_scan.add_argument("--verbose", "-v", action="store_true", help="Show matched snippets")
    p_scan.set_defaults(func=cmd_scan)

    p_rules = sub.add_parser("rules", help="List all detection rules")
    p_rules.set_defaults(func=cmd_rules)

    args = p.parse_args()
    result = args.func(args)
    sys.exit(result if isinstance(result, int) else 0)


if __name__ == "__main__":
    main()
