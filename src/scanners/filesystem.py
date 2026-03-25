"""Detect unrestricted filesystem access in MCP server source code."""

import re
from pathlib import Path

from ..models import Category, Finding, ServerConfig, Severity

# Sensitive paths that should never be accessed by MCP servers
SENSITIVE_PATHS = [
    r"/etc/passwd",
    r"/etc/shadow",
    r"~/.ssh",
    r"\.ssh/",
    r"~/.aws",
    r"\.aws/credentials",
    r"~/.gnupg",
    r"\.gnupg/",
    r"~/.env",
    r"/etc/sudoers",
    r"\.secrets",
    r"\.git/config",
]

# Path traversal patterns
TRAVERSAL_PATTERNS = [
    {
        "pattern": r"open\s*\([^)]*\+[^)]*\)",
        "title": "Dynamic file path in open()",
        "severity": Severity.MEDIUM,
        "description": (
            "File path constructed by string concatenation in open(). "
            "If any part comes from tool parameters, path traversal (../../) "
            "could access files outside the intended directory."
        ),
        "recommendation": (
            "Validate and sanitize file paths before opening. Use "
            "pathlib.Path.resolve() and check the result is within the "
            "expected directory."
        ),
    },
    {
        "pattern": r"open\s*\(\s*f['\"]",
        "title": "f-string file path in open()",
        "severity": Severity.MEDIUM,
        "description": (
            "File path built with f-string in open(). If the interpolated "
            "variable comes from tool parameters, path traversal is possible."
        ),
        "recommendation": (
            "Resolve the path with pathlib and verify it stays within the "
            "allowed directory before opening."
        ),
    },
    {
        "pattern": r"Path\s*\([^)]*\+[^)]*\)\s*\.\s*(read|write|open)",
        "title": "Dynamic Path() with file operation",
        "severity": Severity.MEDIUM,
        "description": (
            "File path constructed dynamically before a file operation. "
            "Path traversal may be possible if input is user-controlled."
        ),
        "recommendation": (
            "Use .resolve() on the constructed path and verify it's within "
            "the expected base directory."
        ),
    },
]

# Dangerous file operations without apparent validation
UNGUARDED_FILE_OPS = [
    {
        "pattern": r"os\.(remove|unlink|rmdir)\s*\(",
        "title": "File deletion without apparent path validation",
        "severity": Severity.HIGH,
        "description": (
            "File deletion operation found. If the path argument can be "
            "influenced by tool parameters, arbitrary files could be deleted."
        ),
        "recommendation": (
            "Validate the target path is within the expected directory. "
            "Use pathlib.Path.resolve() and check against an allowed base path."
        ),
    },
    {
        "pattern": r"shutil\.(rmtree|move|copy)\s*\(",
        "title": "Recursive file operation (shutil)",
        "severity": Severity.MEDIUM,
        "description": (
            "Recursive file operation found. shutil.rmtree() can delete "
            "entire directory trees if given an unexpected path."
        ),
        "recommendation": (
            "Validate paths before passing to shutil. Ensure the target "
            "is within the expected working directory."
        ),
    },
    {
        "pattern": r"os\.chmod\s*\(",
        "title": "Permission modification (os.chmod)",
        "severity": Severity.MEDIUM,
        "description": (
            "File permission modification found. If the path or mode "
            "can be influenced by tool parameters, it could weaken "
            "file security."
        ),
        "recommendation": (
            "Validate the target path and ensure permissions are only "
            "modified for files within the expected directory."
        ),
    },
]


def scan(server: ServerConfig) -> list[Finding]:
    """Scan server source code for filesystem security issues."""
    findings = []
    source = server.resolve_server_path()
    if not source:
        return findings

    files = _collect_files(source)

    for filepath in files:
        try:
            content = filepath.read_text(errors="replace")
        except OSError:
            continue

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Check for access to sensitive paths
            for sensitive in SENSITIVE_PATHS:
                if re.search(re.escape(sensitive), line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=Category.FILESYSTEM,
                        title=f"Access to sensitive path: {sensitive}",
                        description=(
                            f"Source code references sensitive path '{sensitive}'. "
                            f"MCP servers should not access system credential files "
                            f"or security-critical paths."
                        ),
                        recommendation=(
                            "Remove access to sensitive system paths. If the server "
                            "needs credentials, use environment variables or a "
                            "dedicated secret manager."
                        ),
                        location=f"{filepath}:{i}",
                        evidence=stripped[:120],
                    ))

            # Check traversal patterns
            for pat in TRAVERSAL_PATTERNS:
                if re.search(pat["pattern"], line):
                    findings.append(Finding(
                        severity=pat["severity"],
                        category=Category.FILESYSTEM,
                        title=pat["title"],
                        description=pat["description"],
                        recommendation=pat["recommendation"],
                        location=f"{filepath}:{i}",
                        evidence=stripped[:120],
                    ))

            # Check unguarded file operations
            for pat in UNGUARDED_FILE_OPS:
                if re.search(pat["pattern"], line):
                    findings.append(Finding(
                        severity=pat["severity"],
                        category=Category.FILESYSTEM,
                        title=pat["title"],
                        description=pat["description"],
                        recommendation=pat["recommendation"],
                        location=f"{filepath}:{i}",
                        evidence=stripped[:120],
                    ))

    return findings


def _collect_files(source: Path) -> list[Path]:
    """Collect source files to scan."""
    if source.is_file():
        return [source]
    files = []
    for ext in ("*.py", "*.js", "*.ts", "*.mjs"):
        files.extend(source.rglob(ext))
    return [
        f for f in files
        if "node_modules" not in str(f)
        and "__pycache__" not in str(f)
    ]
