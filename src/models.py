"""Data models for probe scanner."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]


class Category(Enum):
    """Finding categories."""
    SECRETS = "secrets"
    INJECTION = "injection"
    FILESYSTEM = "filesystem"
    VALIDATION = "validation"
    TRANSPORT = "transport"


class Grade(Enum):
    """Security grade A-F."""
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"

    @property
    def label(self) -> str:
        return {
            Grade.A: "Excellent",
            Grade.B: "Good",
            Grade.C: "Needs Improvement",
            Grade.D: "Poor",
            Grade.F: "Failing",
        }[self]


class Transport(Enum):
    """MCP server transport type."""
    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable-http"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    """A single security finding."""
    severity: Severity
    category: Category
    title: str
    description: str
    recommendation: str
    location: Optional[str] = None  # file:line or config key
    evidence: Optional[str] = None  # the actual problematic value/pattern

    @property
    def sort_key(self) -> int:
        return self.severity.weight


@dataclass
class ServerConfig:
    """Parsed MCP server configuration."""
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    transport: Transport = Transport.STDIO
    url: Optional[str] = None
    source_file: Optional[Path] = None  # where the config was found
    source_app: Optional[str] = None  # "claude-code", "cursor", "vscode"
    server_path: Optional[Path] = None  # resolved path to server source

    def resolve_server_path(self) -> Optional[Path]:
        """Try to find the actual server source file."""
        if self.server_path and self.server_path.exists():
            return self.server_path

        # Check args for file paths
        for arg in self.args:
            p = Path(arg).expanduser()
            if p.exists() and p.is_file():
                self.server_path = p
                return p

        # For python/node commands, the server is usually the first arg
        if self.command in ("python3", "python", "node", "npx", "uvx"):
            for arg in self.args:
                if arg.startswith("-"):
                    continue
                p = Path(arg).expanduser()
                if p.exists():
                    self.server_path = p
                    return p

        return None


@dataclass
class ScanResult:
    """Complete scan result for one MCP server."""
    server: ServerConfig
    findings: list[Finding] = field(default_factory=list)
    grade: Grade = Grade.A
    score: int = 100  # 0-100, higher is better

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def findings_by_severity(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key, reverse=True)


@dataclass
class FullReport:
    """Complete scan report across all servers."""
    results: list[ScanResult] = field(default_factory=list)
    config_sources: list[Path] = field(default_factory=list)

    @property
    def overall_grade(self) -> Grade:
        if not self.results:
            return Grade.A
        # Overall grade = worst individual grade
        grade_order = [Grade.F, Grade.D, Grade.C, Grade.B, Grade.A]
        for g in grade_order:
            if any(r.grade == g for r in self.results):
                return g
        return Grade.A

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.results)

    @property
    def total_critical(self) -> int:
        return sum(r.critical_count for r in self.results)

    @property
    def total_high(self) -> int:
        return sum(r.high_count for r in self.results)

    @property
    def servers_scanned(self) -> int:
        return len(self.results)
