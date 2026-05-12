"""Detect command injection vulnerabilities in MCP server source code."""

import ast
import re
from pathlib import Path

from ..models import Category, Finding, ServerConfig, Severity

# Dangerous patterns: subprocess with shell=True, os.system, eval/exec
INJECTION_PATTERNS = [
    # Python patterns
    {
        "pattern": r"subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
        "title": "subprocess with shell=True",
        "severity": Severity.HIGH,
        "description": (
            "Using subprocess with shell=True allows shell injection if any "
            "argument contains user-controlled input. An attacker could inject "
            "commands via tool parameters."
        ),
        "recommendation": (
            "Use shell=False (the default) and pass arguments as a list. "
            "Example: subprocess.run(['cmd', arg1, arg2]) instead of "
            "subprocess.run(f'cmd {arg1} {arg2}', shell=True)"
        ),
    },
    {
        "pattern": r"os\.system\s*\(",
        "title": "os.system() call",
        "severity": Severity.HIGH,
        "description": (
            "os.system() passes commands through the shell, enabling injection. "
            "If any part of the command string includes tool parameters, an "
            "attacker can execute arbitrary commands."
        ),
        "recommendation": (
            "Replace os.system() with subprocess.run() using a list of arguments "
            "and shell=False."
        ),
    },
    {
        "pattern": r"os\.popen\s*\(",
        "title": "os.popen() call",
        "severity": Severity.HIGH,
        "description": (
            "os.popen() executes a command through the shell. If the command "
            "includes user input, it enables command injection."
        ),
        "recommendation": (
            "Replace with subprocess.run() using shell=False and capture output "
            "via stdout=subprocess.PIPE."
        ),
    },
    {
        "pattern": r"(?<!\w)eval\s*\(",
        "title": "eval() call",
        "severity": Severity.CRITICAL,
        "description": (
            "eval() executes arbitrary Python code. If the evaluated string "
            "includes tool parameters or user input, it enables code injection."
        ),
        "recommendation": (
            "Avoid eval() entirely. Use ast.literal_eval() for safe parsing of "
            "literal values, or json.loads() for JSON data."
        ),
    },
    {
        "pattern": r"(?<!\w)exec\s*\(",
        "title": "exec() call",
        "severity": Severity.CRITICAL,
        "description": (
            "exec() executes arbitrary Python code. This is extremely dangerous "
            "if any part of the executed code comes from tool parameters."
        ),
        "recommendation": (
            "Remove exec() and implement the needed functionality directly. "
            "If dynamic behavior is required, use a safe dispatch pattern."
        ),
    },
    # Node.js patterns
    {
        "pattern": r"child_process\.(exec|execSync)\s*\(",
        "title": "child_process.exec() (shell command)",
        "severity": Severity.HIGH,
        "description": (
            "child_process.exec() runs commands through the shell, enabling "
            "injection if arguments include user input from tool parameters."
        ),
        "recommendation": (
            "Use child_process.execFile() or child_process.spawn() instead, "
            "which don't invoke a shell."
        ),
    },
    {
        "pattern": r"new\s+Function\s*\(",
        "title": "new Function() constructor",
        "severity": Severity.CRITICAL,
        "description": (
            "The Function constructor creates functions from strings, similar "
            "to eval(). If input includes tool parameters, it enables code injection."
        ),
        "recommendation": (
            "Avoid creating functions from strings. Implement logic directly."
        ),
    },
]

# F-string or format string in subprocess/os.system (amplifies injection risk)
FORMAT_IN_COMMAND_PATTERNS = [
    {
        "pattern": r"subprocess\.\w+\s*\(\s*f['\"]",
        "title": "f-string in subprocess call",
        "severity": Severity.HIGH,
        "description": (
            "Using an f-string to build a subprocess command is a strong "
            "indicator of command injection vulnerability. Variables interpolated "
            "into the command string can contain shell metacharacters."
        ),
        "recommendation": (
            "Pass arguments as a list instead of building a command string. "
            "Example: subprocess.run(['git', 'clone', url]) not "
            "subprocess.run(f'git clone {url}')"
        ),
    },
    {
        "pattern": r"subprocess\.\w+\s*\([^)]*\.format\s*\(",
        "title": ".format() in subprocess call",
        "severity": Severity.HIGH,
        "description": (
            "Using .format() to build a subprocess command enables injection "
            "if any format argument is user-controlled."
        ),
        "recommendation": (
            "Pass arguments as a list instead of building a command string."
        ),
    },
    {
        "pattern": r"os\.system\s*\(\s*f['\"]",
        "title": "f-string in os.system()",
        "severity": Severity.CRITICAL,
        "description": (
            "Combining os.system() with f-strings is the most dangerous "
            "injection pattern. Both the shell invocation and string "
            "interpolation are unsafe."
        ),
        "recommendation": (
            "Replace entirely with subprocess.run() using a list of arguments "
            "and shell=False."
        ),
    },
]

PATTERNS_BY_TITLE = {pat["title"]: pat for pat in INJECTION_PATTERNS}
FORMAT_PATTERNS_BY_TITLE = {pat["title"]: pat for pat in FORMAT_IN_COMMAND_PATTERNS}


def scan(server: ServerConfig) -> list[Finding]:
    """Scan server source code for command injection vulnerabilities."""
    findings = []
    source = server.resolve_server_path()
    if not source:
        return findings

    # For Python packages invoked via -m, try to find the package directory
    if not source.exists():
        return findings

    files_to_scan = _collect_source_files(source)

    seen = set()

    for filepath in files_to_scan:
        try:
            content = filepath.read_text(errors="replace")
        except OSError:
            continue

        if filepath.suffix == ".py":
            for finding in _scan_python_ast(filepath, content):
                _append_once(findings, seen, finding)

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Check injection patterns
            for pat in INJECTION_PATTERNS:
                if re.search(pat["pattern"], line):
                    _append_once(findings, seen, Finding(
                        severity=pat["severity"],
                        category=Category.INJECTION,
                        title=pat["title"],
                        description=pat["description"],
                        recommendation=pat["recommendation"],
                        location=f"{filepath}:{i}",
                        evidence=stripped[:120],
                    ))

            # Check format-string-in-command patterns
            for pat in FORMAT_IN_COMMAND_PATTERNS:
                if re.search(pat["pattern"], line):
                    _append_once(findings, seen, Finding(
                        severity=pat["severity"],
                        category=Category.INJECTION,
                        title=pat["title"],
                        description=pat["description"],
                        recommendation=pat["recommendation"],
                        location=f"{filepath}:{i}",
                        evidence=stripped[:120],
                    ))

    return findings


def _collect_source_files(source: Path) -> list[Path]:
    """Collect all source files to scan from a server path."""
    if source.is_file():
        return [source]

    # If it's a directory, scan all Python/JS/TS files
    files = []
    for ext in ("*.py", "*.js", "*.ts", "*.mjs"):
        files.extend(sorted(source.rglob(ext)))

    # Skip test files and node_modules
    return [
        f for f in files
        if "node_modules" not in str(f)
        and "test" not in f.name.lower()
        and "__pycache__" not in str(f)
    ]


def _scan_python_ast(filepath: Path, content: str) -> list[Finding]:
    """Use Python AST to catch multiline calls and import aliases."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    lines = content.splitlines()
    module_aliases, function_aliases = _collect_import_aliases(tree)
    findings = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        function_name = _resolve_call_name(node.func, module_aliases, function_aliases)
        if not function_name:
            continue

        title = _title_for_call(function_name, node)
        if title:
            findings.append(_finding_from_title(title, filepath, node, lines))

        format_title = _format_title_for_call(function_name, node)
        if format_title:
            findings.append(_finding_from_title(format_title, filepath, node, lines))

    return findings


def _collect_import_aliases(tree: ast.AST) -> tuple[dict[str, str], dict[str, str]]:
    module_aliases: dict[str, str] = {}
    function_aliases: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_name = alias.name.split(".")[0]
                if root_name in ("subprocess", "os"):
                    local_name = alias.asname or root_name
                    module_aliases[local_name] = root_name

        if isinstance(node, ast.ImportFrom) and node.module in ("subprocess", "os"):
            for alias in node.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                function_aliases[local_name] = f"{node.module}.{alias.name}"

    return module_aliases, function_aliases


def _resolve_call_name(
    func: ast.expr,
    module_aliases: dict[str, str],
    function_aliases: dict[str, str],
) -> str | None:
    if isinstance(func, ast.Name):
        if func.id in ("eval", "exec"):
            return func.id
        return function_aliases.get(func.id)

    if not isinstance(func, ast.Attribute):
        return None

    if isinstance(func.value, ast.Name):
        module_name = module_aliases.get(func.value.id, func.value.id)
        if module_name in ("subprocess", "os"):
            return f"{module_name}.{func.attr}"

    return None


def _title_for_call(function_name: str, node: ast.Call) -> str | None:
    if function_name in {
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_output",
        "subprocess.check_call",
    } and _call_has_shell_true(node):
        return "subprocess with shell=True"

    if function_name == "os.system":
        return "os.system() call"

    if function_name == "os.popen":
        return "os.popen() call"

    if function_name == "eval":
        return "eval() call"

    if function_name == "exec":
        return "exec() call"

    return None


def _format_title_for_call(function_name: str, node: ast.Call) -> str | None:
    if not function_name.startswith("subprocess.") and function_name != "os.system":
        return None

    if not node.args:
        return None

    first_arg = node.args[0]
    if isinstance(first_arg, ast.JoinedStr):
        if function_name == "os.system":
            return "f-string in os.system()"
        return "f-string in subprocess call"

    if (
        function_name.startswith("subprocess.")
        and isinstance(first_arg, ast.Call)
        and isinstance(first_arg.func, ast.Attribute)
        and first_arg.func.attr == "format"
    ):
        return ".format() in subprocess call"

    return None


def _call_has_shell_true(node: ast.Call) -> bool:
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


def _finding_from_title(
    title: str,
    filepath: Path,
    node: ast.AST,
    lines: list[str],
) -> Finding:
    pat = PATTERNS_BY_TITLE.get(title) or FORMAT_PATTERNS_BY_TITLE[title]
    lineno = getattr(node, "lineno", 1)
    evidence = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else title
    return Finding(
        severity=pat["severity"],
        category=Category.INJECTION,
        title=pat["title"],
        description=pat["description"],
        recommendation=pat["recommendation"],
        location=f"{filepath}:{lineno}",
        evidence=evidence[:120],
    )


def _append_once(
    findings: list[Finding],
    seen: set[tuple[str, str | None]],
    finding: Finding,
) -> None:
    key = (finding.title, finding.location)
    if key in seen:
        return
    seen.add(key)
    findings.append(finding)
