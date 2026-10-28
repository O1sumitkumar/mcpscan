"""Core scanner engine for mcpscan."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcpscan.rules import ALL_RULES, MCPRule, Severity

_SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 1,
}


@dataclass
class MCPFinding:
    rule: MCPRule
    snippets: list[str]

    @property
    def rule_id(self) -> str:
        return self.rule.id

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    @property
    def name(self) -> str:
        return self.rule.name

    def __repr__(self) -> str:
        return f"MCPFinding({self.rule_id}, {self.severity.value})"


@dataclass
class MCPScanResult:
    server_name: str
    findings: list[MCPFinding]
    risk_score: float
    risk_level: str
    tool_count: int = 0
    scan_time_ms: float = 0.0
    error: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        return self.risk_level == "SAFE"

    @property
    def critical_findings(self) -> list[MCPFinding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def summary_line(self) -> str:
        return (
            f"[{self.risk_level}] {self.server_name} "
            f"(score={self.risk_score:.0f}/100, "
            f"{self.finding_count} finding(s), "
            f"{self.tool_count} tool(s))"
        )

    def __repr__(self) -> str:
        return (
            f"MCPScanResult({self.server_name!r}, "
            f"{self.risk_level}, score={self.risk_score:.0f})"
        )


@dataclass
class MCPBatchReport:
    results: list[MCPScanResult]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def safe_count(self) -> int:
        return sum(1 for r in self.results if r.is_safe)

    @property
    def flagged_count(self) -> int:
        return sum(1 for r in self.results if not r.is_safe)

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.results if r.risk_level == "CRITICAL")

    def summary(self) -> str:
        lines = [
            "",
            "=" * 64,
            "  MCPSCAN — BATCH SCAN REPORT",
            "=" * 64,
            f"  Servers scanned:  {self.total}",
            f"  Safe:             {self.safe_count}",
            f"  Flagged:          {self.flagged_count}",
            f"  Critical:         {self.critical_count}",
            "-" * 64,
        ]
        for r in self.results:
            lines.append(f"  {r.summary_line()}")
            for f in r.findings[:2]:
                lines.append(f"    -> {f.rule_id}: {f.name}")
        lines += ["=" * 64, ""]
        return "\n".join(lines)


# Lowest risk level a single finding of each severity can produce.
_SEVERITY_FLOOR = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "LOW",
}
_LEVEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _compute_risk(findings: list[MCPFinding]) -> tuple[float, str]:
    if not findings:
        return 0.0, "SAFE"
    raw = sum(_SEVERITY_WEIGHTS.get(f.severity, 1) for f in findings)
    score = min(100.0, float(raw))
    if score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"
    # The level is never lower than the worst single finding, so one HIGH
    # finding is reported as HIGH even when the summed score is below 40.
    for f in findings:
        floor = _SEVERITY_FLOOR.get(f.severity, "LOW")
        if _LEVEL_ORDER.index(floor) > _LEVEL_ORDER.index(level):
            level = floor
    return score, level


def _parse_jsonl_tools(text: str) -> list[dict[str, Any]]:
    """Parse a JSONL tool listing: one tool object per non-empty line."""
    tools = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            tool = json.loads(line)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSONL parse error on line {lineno}: {e.msg}") from e
        if not isinstance(tool, dict):
            raise ValueError(f"JSONL parse error on line {lineno}: expected a tool object")
        tools.append(tool)
    return tools


class MCPScanner:
    """
    Scan MCP server manifests for security vulnerabilities.

    Supports JSON manifests (from HTTP servers or file),
    JSONL tool listings, and raw Python dicts.

    Example:
        scanner = MCPScanner()

        # Scan a JSON manifest file
        result = scanner.scan_file("server-manifest.json")
        print(result.risk_level)

        # Scan a dict (e.g. from HTTP response)
        manifest = {"tools": [...], "serverInfo": {...}}
        result = scanner.scan_manifest(manifest, name="my-mcp-server")

        # Scan multiple
        report = scanner.scan_files(["server1.json", "server2.json"])
        print(report.summary())
    """

    def __init__(
        self,
        rules: list[MCPRule] | None = None,
        verbose: bool = False,
    ) -> None:
        self.rules = rules or ALL_RULES
        self.verbose = verbose

    def scan_manifest(self, manifest: dict[str, Any], name: str = "server") -> MCPScanResult:
        """Scan a parsed MCP manifest dict."""
        t0 = time.time()
        findings: list[MCPFinding] = []

        for rule in self.rules:
            try:
                snippets = rule.check(manifest)
            except Exception:
                snippets = []
            if snippets:
                findings.append(MCPFinding(rule=rule, snippets=snippets))

        score, level = _compute_risk(findings)
        return MCPScanResult(
            server_name=name,
            findings=findings,
            risk_score=score,
            risk_level=level,
            tool_count=len(manifest.get("tools", [])),
            scan_time_ms=round((time.time() - t0) * 1000, 2),
            raw=manifest,
        )

    def scan_file(self, path: str | Path, encoding: str = "utf-8") -> MCPScanResult:
        """Scan an MCP manifest JSON file or a JSONL tool listing (one tool per line)."""
        p = Path(path)
        self._log(f"  Scanning {p.name}...")
        try:
            text = p.read_text(encoding=encoding, errors="replace")
            if p.suffix.lower() == ".jsonl":
                return self.scan_tool_list(_parse_jsonl_tools(text), name=p.name)
            manifest = json.loads(text)
        except json.JSONDecodeError as e:
            return MCPScanResult(
                server_name=p.name,
                findings=[],
                risk_score=0.0,
                risk_level="ERROR",
                error=f"JSON parse error: {e}",
            )
        except Exception as e:
            return MCPScanResult(
                server_name=p.name,
                findings=[],
                risk_score=0.0,
                risk_level="ERROR",
                error=str(e),
            )
        return self.scan_manifest(manifest, name=p.name)

    def scan_files(self, paths: list[str | Path]) -> MCPBatchReport:
        """Scan multiple MCP manifest files."""
        results = [self.scan_file(p) for p in paths]
        return MCPBatchReport(results=results)

    def scan_tool_list(self, tools: list[dict[str, Any]], name: str = "server") -> MCPScanResult:
        """Scan a list of tool definitions directly."""
        return self.scan_manifest({"tools": tools}, name=name)

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)
