"""
Probe MCP Server

An MCP server that audits other MCP servers. Exposes probe's security
scanning capabilities as MCP tools, so AI agents can self-audit their
own MCP connections.

Tools:
- probe_scan: Scan all discovered MCP servers for security issues
- probe_scan_server: Scan a specific MCP server by name
- probe_list: List all discovered MCP servers
- probe_check_config: Check a specific config file for issues
"""

import json
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .config import discover_servers
from .grader import grade_server
from .models import FullReport, ScanResult
from .output import render_json
from .scanners import secrets, injection, filesystem, validation, transport

ALL_SCANNERS = [secrets, injection, filesystem, validation, transport]

mcp = FastMCP("probe", instructions="""
Probe is an MCP server security scanner. It finds plaintext secrets,
command injection vulnerabilities, missing input validation, and
transport security issues in MCP server configurations.

Use these tools to audit your MCP setup:
- probe_scan: Full scan of all discovered servers (start here)
- probe_scan_server: Scan a specific server by name
- probe_list: See what servers are configured
- probe_check_config: Scan a specific config file path
""")


def _run_scan(servers: list) -> str:
    """Run all scanners on a list of servers and return JSON report."""
    if not servers:
        return json.dumps({"message": "No MCP servers found to scan.", "results": []})

    report = FullReport()
    report.config_sources = [*{s.source_file for s in servers if s.source_file}]

    for srv in servers:
        result = ScanResult(server=srv)
        for scanner in ALL_SCANNERS:
            result.findings.extend(scanner.scan(srv))
        grade_server(result)
        report.results.append(result)

    return render_json(report)


@mcp.tool()
def probe_scan() -> str:
    """Scan all discovered MCP servers for security issues.

    Auto-discovers servers from ~/.mcp.json, project .mcp.json files,
    and other known config locations. Returns a JSON report with grades
    (A-F), findings by severity, and fix recommendations.

    Start here to get an overview of your MCP security posture.
    """
    servers = discover_servers()
    return _run_scan(servers)


@mcp.tool()
def probe_scan_server(name: str) -> str:
    """Scan a specific MCP server by name.

    Args:
        name: The server name as it appears in your MCP config
              (e.g., "engram", "kv", "slack-bot")

    Returns JSON with the server's grade, findings, and recommendations.
    """
    servers = discover_servers()
    matched = [s for s in servers if s.name == name]

    if not matched:
        available = [s.name for s in servers]
        return json.dumps({
            "error": f"Server '{name}' not found",
            "available_servers": available,
        })

    return _run_scan(matched)


@mcp.tool()
def probe_list() -> str:
    """List all discovered MCP servers without scanning them.

    Shows server names, transport types, commands, source files,
    and config locations. Use this to see what's configured before
    running a full scan.
    """
    servers = discover_servers()

    if not servers:
        return json.dumps({"message": "No MCP servers found.", "servers": []})

    result = []
    for srv in servers:
        source_path = srv.resolve_server_path()
        result.append({
            "name": srv.name,
            "transport": srv.transport.value,
            "command": srv.command,
            "args": srv.args,
            "env_vars": len(srv.env),
            "source_file": str(source_path) if source_path else None,
            "config_file": str(srv.source_file) if srv.source_file else None,
            "config_app": srv.source_app,
        })

    return json.dumps({"servers": result, "count": len(result)}, indent=2)


@mcp.tool()
def probe_check_config(config_path: str) -> str:
    """Scan a specific MCP config file for security issues.

    Args:
        config_path: Absolute path to an MCP config file
                     (e.g., ~/.mcp.json, ~/.cursor/mcp.json)

    Returns JSON with grades and findings for all servers
    defined in that config file.
    """
    path = Path(config_path).expanduser()
    if not path.exists():
        return json.dumps({"error": f"Config file not found: {config_path}"})

    servers = discover_servers([path])
    return _run_scan(servers)


if __name__ == "__main__":
    mcp.run()
