"""Discover and parse MCP server configurations."""

import json
from pathlib import Path
from typing import Optional

from .models import ServerConfig, Transport


# Known config locations for each tool
CONFIG_LOCATIONS = [
    # Claude Code — user-level
    ("claude-code", Path("~/.mcp.json")),
    # Claude Code — project-level (found via cwd walk)
    ("claude-code", None),  # sentinel: walk up from cwd
    # Cursor
    ("cursor", Path("~/.cursor/mcp.json")),
    # VS Code
    ("vscode", Path("~/.vscode/settings.json")),
    # Windsurf
    ("windsurf", Path("~/.windsurf/mcp.json")),
]


def find_config_files(scan_paths: Optional[list[Path]] = None) -> list[tuple[str, Path]]:
    """Find all MCP config files on this system.

    Returns list of (app_name, config_path) tuples.
    """
    found = []

    if scan_paths:
        # Scan user-specified paths
        for p in scan_paths:
            p = p.expanduser().resolve()
            if p.exists() and p.is_file():
                app = _guess_app(p)
                found.append((app, p))
        return found

    # Auto-discover from known locations
    for app, path in CONFIG_LOCATIONS:
        if path is None:
            # Walk up from cwd looking for .mcp.json
            project_configs = _find_project_configs(Path.cwd())
            for pc in project_configs:
                found.append((app, pc))
            continue

        expanded = path.expanduser()
        if expanded.exists():
            found.append((app, expanded))

    return found


def _find_project_configs(start: Path) -> list[Path]:
    """Walk up from start looking for project-level .mcp.json files."""
    found = []
    current = start.resolve()
    home = Path.home().resolve()

    while current != current.parent:
        candidate = current / ".mcp.json"
        if candidate.exists() and candidate.resolve() != (home / ".mcp.json").resolve():
            found.append(candidate)
        current = current.parent

    return found


def _guess_app(path: Path) -> str:
    """Guess which app a config file belongs to."""
    parts = str(path).lower()
    if ".cursor" in parts:
        return "cursor"
    if ".vscode" in parts:
        return "vscode"
    if ".windsurf" in parts:
        return "windsurf"
    return "claude-code"


def parse_config(app: str, config_path: Path) -> list[ServerConfig]:
    """Parse an MCP config file into ServerConfig objects."""
    try:
        data = json.loads(config_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return []

    servers = []

    # Claude Code / Cursor / Windsurf format: {"mcpServers": {"name": {...}}}
    mcp_servers = data.get("mcpServers", {})

    # VS Code format: {"mcp.servers": {"name": {...}}} or nested
    if not mcp_servers and "mcp.servers" in data:
        mcp_servers = data["mcp.servers"]

    for name, conf in mcp_servers.items():
        if not isinstance(conf, dict):
            continue

        command = conf.get("command", "")
        args = conf.get("args", [])
        env = conf.get("env", {})
        url = conf.get("url", "")

        # Determine transport
        transport = Transport.STDIO
        if url:
            if "sse" in url.lower() or url.startswith("http"):
                transport = Transport.SSE
            transport_str = conf.get("transport", "")
            if transport_str == "streamable-http":
                transport = Transport.STREAMABLE_HTTP

        server = ServerConfig(
            name=name,
            command=command,
            args=list(args) if isinstance(args, list) else [str(args)],
            env=env if isinstance(env, dict) else {},
            transport=transport,
            url=url if url else None,
            source_file=config_path,
            source_app=app,
        )

        # Try to find the actual server source code
        server.resolve_server_path()

        servers.append(server)

    return servers


def discover_servers(scan_paths: Optional[list[Path]] = None) -> list[ServerConfig]:
    """Discover all MCP servers from config files.

    Main entry point for the config module.
    """
    configs = find_config_files(scan_paths)
    servers = []
    seen = set()

    for app, config_path in configs:
        for server in parse_config(app, config_path):
            # Dedup by name + source
            key = (server.name, str(server.source_file))
            if key not in seen:
                seen.add(key)
                servers.append(server)

    return servers
