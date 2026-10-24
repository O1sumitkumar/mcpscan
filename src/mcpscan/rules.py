"""
MCP security detection rules for mcpscan.
Covers OWASP Agentic AI Top 10 risks as they apply to MCP servers.
Zero external dependencies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class MCPRule:
    id: str
    name: str
    severity: Severity
    description: str
    remediation: str
    tags: list[str] = field(default_factory=list)

    def check(self, target: dict[str, Any]) -> list[str]:
        """Check a parsed MCP manifest/tool definition. Return list of findings."""
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"MCPRule({self.id!r}, {self.severity.value})"


# ── MR-001: Prompt Injection in Tool Description ───


class PromptInjectionRule(MCPRule):
    _PATTERNS = [
        re.compile(p, re.IGNORECASE | re.MULTILINE)
        for p in [
            r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
            r"disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions?",
            r"(?:new|updated|override)\s+system\s+prompt",
            r"jailbreak|DAN\s+mode",
            r"you\s+are\s+now\s+(?:a\s+)?(?:different|free|unrestricted)",
            r"(?:bypass|override|disable)\s+(?:safety|content|ethical)\s+(?:filter|guardrail)",
            r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions?",
            r"forget\s+(?:everything|all)\s+(?:you|above)",
        ]
    ]

    def check(self, target: dict[str, Any]) -> list[str]:
        findings = []
        for tool in target.get("tools", []):
            text = f"{tool.get('name','')} {tool.get('description','')} {str(tool.get('inputSchema',''))}"
            for pat in self._PATTERNS:
                if pat.search(text):
                    findings.append(f"Tool '{tool.get('name','?')}': {pat.pattern[:60]}")
        return findings


RULE_PROMPT_INJECTION = PromptInjectionRule(
    id="MR-001",
    name="Prompt Injection in Tool Description",
    severity=Severity.CRITICAL,
    description=(
        "One or more tool descriptions contain prompt injection patterns — "
        "text designed to override the agent's system instructions when the "
        "tool schema is loaded into the LLM's context. This is 'tool-poisoning', "
        "a variant of prompt injection specific to MCP."
    ),
    remediation=(
        "Tool names and descriptions must contain only functional documentation. "
        "Remove any instruction-override language. See OWASP Agentic AI ASI-01."
    ),
    tags=["prompt-injection", "tool-poisoning", "owasp-asi01", "clawhavoc"],
)


# ── MR-002: Unsafe Authentication ─────────────────


class UnsafeAuthRule(MCPRule):
    def check(self, target: dict[str, Any]) -> list[str]:
        findings = []
        auth = target.get("auth", target.get("authentication", {}))
        # No auth declared at all for a server with tools
        if target.get("tools") and not auth:
            findings.append("Server exposes tools with no authentication declared")

        # Static API key in manifest
        for key in ["api_key", "apiKey", "secret", "token", "password", "credential"]:
            val = auth.get(key, "") if isinstance(auth, dict) else ""
            if val and len(str(val)) > 8:
                findings.append(f"Hardcoded credential in auth.{key}")

        # Check for plain HTTP transport (not HTTPS)
        transport = target.get("transport", target.get("url", ""))
        if (
            isinstance(transport, str)
            and transport.startswith("http://")
            and "localhost" not in transport
            and "127.0.0.1" not in transport
        ):
            findings.append(f"Insecure HTTP transport (non-localhost): {transport[:80]}")

        return findings


RULE_UNSAFE_AUTH = UnsafeAuthRule(
    id="MR-002",
    name="Unsafe Authentication",
    severity=Severity.HIGH,
    description=(
        "The MCP server uses insecure authentication — no auth declared for a "
        "tool-exposing server, hardcoded credentials, or non-HTTPS transport. "
        "Astrix's 5,200-server audit found 53% use insecure long-lived static secrets."
    ),
    remediation=(
        "Use OAuth 2.0 or short-lived bearer tokens. Never hardcode credentials. "
        "Use HTTPS for all non-localhost transports."
    ),
    tags=["authentication", "credentials", "https", "owasp-asi06"],
)


# ── MR-003: Over-broad Tool Permissions ───────────


class OverBroadPermissionsRule(MCPRule):
    _FS_PATTERNS = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"(?:read|write|delete|list)\s+(?:all|any|every)\s+files?",
            r"full\s+(?:file\s+)?system\s+access",
            r"access\s+(?:all|any)\s+(?:files?|directories?|paths?)",
            r"unrestricted\s+(?:file|disk|storage)\s+access",
        ]
    ]
    _NET_PATTERNS = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"(?:access|connect\s+to|query)\s+(?:all|any)\s+(?:urls?|endpoints?|servers?|hosts?)",
            r"unrestricted\s+(?:network|internet|http)\s+access",
            r"make\s+(?:any|all|arbitrary)\s+(?:http|network)\s+requests?",
        ]
    ]

    def check(self, target: dict[str, Any]) -> list[str]:
        findings = []
        for tool in target.get("tools", []):
            desc = tool.get("description", "")
            for pat in self._FS_PATTERNS:
                if pat.search(desc):
                    findings.append(f"Tool '{tool.get('name','?')}': over-broad filesystem access")
                    break
            for pat in self._NET_PATTERNS:
                if pat.search(desc):
                    findings.append(f"Tool '{tool.get('name','?')}': over-broad network access")
                    break
        return findings


RULE_OVER_BROAD_PERMISSIONS = OverBroadPermissionsRule(
    id="MR-003",
    name="Over-broad Tool Permissions",
    severity=Severity.HIGH,
    description=(
        "One or more tools declare permissions significantly beyond their stated purpose — "
        "unrestricted filesystem access, arbitrary network requests, or access to all resources. "
        "This violates the principle of least privilege."
    ),
    remediation=(
        "Scope every tool to the minimum required access. Use explicit path allowlists "
        "for filesystem tools and domain allowlists for network tools."
    ),
    tags=["permissions", "least-privilege", "owasp-asi05"],
)


# ── MR-004: Path Traversal in Filesystem Tools ────


class PathTraversalRule(MCPRule):
    _PATTERNS = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"\.\./",
            r"\.\.\\",
            r"(?:read|write|open|access)\s+(?:file\s+at\s+)?(?:any\s+)?path",
            r"(?:arbitrary|user.provided|custom)\s+(?:file\s+)?path",
        ]
    ]

    def check(self, target: dict[str, Any]) -> list[str]:
        findings = []
        for tool in target.get("tools", []):
            name = tool.get("name", "").lower()
            desc = tool.get("description", "")
            schema = str(tool.get("inputSchema", ""))
            text = f"{desc} {schema}"

            is_fs_tool = any(k in name for k in ["file", "read", "write", "path", "fs", "dir"])
            if not is_fs_tool:
                continue

            # Check each path-like parameter for its own restriction, so a pattern
            # on an unrelated field (e.g. encoding) cannot hide an open path field
            input_schema = tool.get("inputSchema")
            properties = input_schema.get("properties") if isinstance(input_schema, dict) else None
            if isinstance(properties, dict):
                for prop_name, prop in properties.items():
                    if "path" not in prop_name.lower():
                        continue
                    if isinstance(prop, dict) and ("pattern" in prop or "enum" in prop):
                        continue
                    findings.append(
                        f"Tool '{tool.get('name','?')}': path parameter '{prop_name}' "
                        "has no pattern restriction"
                    )
            for pat in self._PATTERNS:
                if pat.search(text):
                    findings.append(f"Tool '{tool.get('name','?')}': potential path traversal")
                    break
        return findings


RULE_PATH_TRAVERSAL = PathTraversalRule(
    id="MR-004",
    name="Path Traversal Risk",
    severity=Severity.HIGH,
    description=(
        "A filesystem tool accepts arbitrary paths without pattern restrictions, "
        "which could allow agents to traverse outside intended directories using "
        "../ sequences or absolute paths to sensitive system files."
    ),
    remediation=(
        "Add a 'pattern' constraint to path parameters in the JSON schema. "
        "Validate paths server-side against an allowlist of permitted directories."
    ),
    tags=["path-traversal", "filesystem", "owasp-asi07"],
)


# ── MR-005: Suspicious Tool Names ─────────────────


class SuspiciousToolNameRule(MCPRule):
    _SUSPICIOUS = re.compile(
        r"(?:exfil|harvest|steal|grab|extract_all|dump_|leak|bypass|override|"
        r"inject|intercept|sniff|capture_all|send_to|upload_all)",
        re.IGNORECASE,
    )

    def check(self, target: dict[str, Any]) -> list[str]:
        findings = []
        for tool in target.get("tools", []):
            name = tool.get("name", "")
            if self._SUSPICIOUS.search(name):
                findings.append(f"Tool name '{name}' matches suspicious pattern")
        return findings


RULE_SUSPICIOUS_TOOL_NAMES = SuspiciousToolNameRule(
    id="MR-005",
    name="Suspicious Tool Name",
    severity=Severity.HIGH,
    description=(
        "One or more tool names contain patterns associated with malicious activity — "
        "data exfiltration, system bypass, credential harvesting, or traffic interception."
    ),
    remediation=(
        "Tool names must clearly and honestly describe their function. "
        "Reject any tool with a name that implies undisclosed harmful capability."
    ),
    tags=["naming", "supply-chain", "tool-poisoning"],
)


# ── MR-006: Missing Tool Schema ───────────────────


class MissingSchemaRule(MCPRule):
    def check(self, target: dict[str, Any]) -> list[str]:
        findings = []
        for tool in target.get("tools", []):
            if not tool.get("inputSchema"):
                findings.append(
                    f"Tool '{tool.get('name','?')}': no inputSchema — "
                    "unvalidated inputs accepted"
                )
            if not tool.get("description"):
                findings.append(
                    f"Tool '{tool.get('name','?')}': no description — "
                    "agent cannot determine safe usage"
                )
        return findings


RULE_MISSING_SCHEMA = MissingSchemaRule(
    id="MR-006",
    name="Missing Tool Schema or Description",
    severity=Severity.MEDIUM,
    description=(
        "One or more tools lack an inputSchema or description. "
        "Without a schema, inputs are unvalidated. Without a description, "
        "the agent cannot determine whether calling this tool is safe or appropriate."
    ),
    remediation=(
        "Every tool must have a description explaining its purpose, "
        "required permissions, and expected inputs. Add a JSON Schema for all parameters."
    ),
    tags=["schema", "documentation", "owasp-asi08"],
)


# ── MR-007: Excessive Tool Count ──────────────────


class ExcessiveToolCountRule(MCPRule):
    THRESHOLD = 50

    def check(self, target: dict[str, Any]) -> list[str]:
        count = len(target.get("tools", []))
        if count > self.THRESHOLD:
            return [
                f"Server exposes {count} tools (threshold: {self.THRESHOLD}). "
                "Large tool counts increase attack surface and context confusion risk."
            ]
        return []


RULE_EXCESSIVE_TOOLS = ExcessiveToolCountRule(
    id="MR-007",
    name="Excessive Tool Count",
    severity=Severity.LOW,
    description=(
        "The server exposes more than 50 tools. Large tool counts increase the "
        "risk of context window confusion (the LLM may invoke unintended tools), "
        "and expand the attack surface for tool-poisoning attacks."
    ),
    remediation=(
        "Split large tool sets into focused servers. Each server should expose "
        "only the tools needed for a specific capability domain."
    ),
    tags=["attack-surface", "tool-count"],
)


# ── MR-008: Suspicious URL in Tool Definition ─────


class SuspiciousURLRule(MCPRule):
    _URL_RE = re.compile(r"https?://[^\s\"'<>]{10,}", re.IGNORECASE)
    _SUSPICIOUS = [
        re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        re.compile(r"(?:ngrok|tunnel|webhook\.site|requestbin|pipedream)", re.IGNORECASE),
        re.compile(r"(?:pastebin|hastebin|rentry\.co)", re.IGNORECASE),
        re.compile(r"(?:bit\.ly|tinyurl|rb\.gy|is\.gd)/"),
        re.compile(r"\.(?:xyz|tk|ml|ga|cf|gq|top)\b"),
    ]

    def check(self, target: dict[str, Any]) -> list[str]:
        findings = []
        for tool in target.get("tools", []):
            text = f"{tool.get('description','')} {str(tool.get('inputSchema',''))}"
            for url_match in self._URL_RE.finditer(text):
                url = url_match.group(0)
                for pat in self._SUSPICIOUS:
                    if pat.search(url):
                        findings.append(
                            f"Tool '{tool.get('name','?')}': suspicious URL: {url[:80]}"
                        )
                        break
        return findings


RULE_SUSPICIOUS_URLS = SuspiciousURLRule(
    id="MR-008",
    name="Suspicious URL in Tool Definition",
    severity=Severity.MEDIUM,
    description=(
        "A tool definition references URLs associated with exfiltration infrastructure: "
        "raw IP addresses, tunnelling services (ngrok), URL shorteners, "
        "pastebin sites, or high-abuse TLDs."
    ),
    remediation=(
        "All URLs in tool definitions must reference well-known domains "
        "with a clear business purpose. Never reference raw IPs or tunnel endpoints."
    ),
    tags=["urls", "c2", "exfiltration"],
)


# ── All rules ──────────────────────────────────────

ALL_RULES: list[MCPRule] = [
    RULE_PROMPT_INJECTION,
    RULE_UNSAFE_AUTH,
    RULE_OVER_BROAD_PERMISSIONS,
    RULE_PATH_TRAVERSAL,
    RULE_SUSPICIOUS_TOOL_NAMES,
    RULE_MISSING_SCHEMA,
    RULE_EXCESSIVE_TOOLS,
    RULE_SUSPICIOUS_URLS,
]
