"""Detect missing input validation in MCP server tool handlers."""

import ast
import re
from pathlib import Path

from ..models import Category, Finding, ServerConfig, Severity


def scan(server: ServerConfig) -> list[Finding]:
    """Scan server source code for missing input validation."""
    findings = []
    source = server.resolve_server_path()
    if not source:
        return findings

    files = _collect_files(source)

    for filepath in files:
        if not filepath.suffix == ".py":
            continue

        try:
            content = filepath.read_text(errors="replace")
        except OSError:
            continue

        # Try AST analysis for Python files
        findings.extend(_analyze_python_ast(filepath, content))

        # Regex fallback for patterns AST might miss
        findings.extend(_analyze_regex(filepath, content))

    return findings


def _analyze_python_ast(filepath: Path, content: str) -> list[Finding]:
    """Use Python AST to find tool handlers without validation."""
    findings = []

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        # Look for functions that handle tool calls
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Heuristic: functions named handle_*, tool_*, or containing
        # "tool" in the name are likely tool handlers
        name = node.name.lower()
        is_handler = (
            name.startswith("handle_")
            or name.startswith("tool_")
            or "handler" in name
            or "dispatch" in name
        )

        if not is_handler:
            continue

        # Check if the function body contains any validation
        has_validation = _function_has_validation(node)

        if not has_validation:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.VALIDATION,
                title=f"Tool handler '{node.name}' may lack input validation",
                description=(
                    f"Function '{node.name}' appears to be a tool handler but "
                    f"doesn't contain obvious input validation (type checks, "
                    f"bounds checks, or assertions). Tool parameters from AI "
                    f"agents should be validated before use."
                ),
                recommendation=(
                    "Add input validation at the start of tool handlers. "
                    "Check parameter types, validate string lengths, and "
                    "reject unexpected values before processing."
                ),
                location=f"{filepath}:{node.lineno}",
            ))

    return findings


def _function_has_validation(func_node: ast.FunctionDef) -> bool:
    """Check if a function contains validation patterns."""
    for node in ast.walk(func_node):
        # isinstance() checks
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "isinstance":
                return True

        # Type annotations on parameters (basic validation signal)
        if func_node.args.annotations:
            return True

        # if/raise patterns (validation guard)
        if isinstance(node, ast.Raise):
            return True

        # Assert statements
        if isinstance(node, ast.Assert):
            return True

        # try/except ValueError (common validation pattern)
        if isinstance(node, ast.ExceptHandler):
            if node.type and isinstance(node.type, ast.Name):
                if node.type.id in ("ValueError", "TypeError", "KeyError"):
                    return True

    return False


def _analyze_regex(filepath: Path, content: str) -> list[Finding]:
    """Regex-based validation checks for patterns AST might miss."""
    findings = []
    lines = content.splitlines()

    # Check for direct dictionary access without .get() on arguments/params
    # Pattern: arguments["key"] or params["key"] without prior validation
    args_direct_access = re.compile(
        r"(arguments|params|args|parameters|tool_input)\s*\[\s*['\"]"
    )

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        # Direct dict access on tool arguments without .get()
        if args_direct_access.search(line):
            # Check if there's a .get() alternative nearby (within 5 lines)
            context = "\n".join(lines[max(0, i-3):min(len(lines), i+3)])
            if ".get(" not in context and "try:" not in context:
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=Category.VALIDATION,
                    title="Direct dict access on tool arguments",
                    description=(
                        "Accessing tool arguments with bracket notation without "
                        "a surrounding try/except or .get() fallback. Missing "
                        "keys will crash the handler."
                    ),
                    recommendation=(
                        "Use .get() with a default value, or wrap in try/except "
                        "KeyError to handle missing parameters gracefully."
                    ),
                    location=f"{filepath}:{i}",
                    evidence=stripped[:120],
                ))

    return findings


def _collect_files(source: Path) -> list[Path]:
    """Collect source files to scan."""
    if source.is_file():
        return [source]
    files = []
    for ext in ("*.py",):
        files.extend(source.rglob(ext))
    return [
        f for f in files
        if "node_modules" not in str(f)
        and "__pycache__" not in str(f)
        and "test" not in f.name.lower()
    ]
