"""CLI for probe — MCP server security scanner."""

import sys
from pathlib import Path
from typing import Optional

import click

from .config import discover_servers
from .grader import grade_server
from .models import FullReport, ScanResult
from .output import render_json, render_terminal
from .scanners import secrets, injection, filesystem, validation, transport


ALL_SCANNERS = [secrets, injection, filesystem, validation, transport]


@click.group()
@click.version_option(version="0.1.0", prog_name="probe")
def main():
    """probe — MCP server security scanner.

    Scans your MCP server configurations for plaintext secrets,
    command injection vulnerabilities, missing input validation,
    and transport security issues.
    """
    pass


@main.command()
@click.option(
    "--path", "-p",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Specific config file(s) to scan. Default: auto-discover.",
)
@click.option(
    "--json", "json_output",
    is_flag=True,
    help="Output results as JSON.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show detailed descriptions and recommendations.",
)
@click.option(
    "--server", "-s",
    multiple=True,
    help="Only scan specific server(s) by name.",
)
def scan(
    path: tuple[Path, ...],
    json_output: bool,
    verbose: bool,
    server: tuple[str, ...],
):
    """Scan MCP server configurations for security issues."""
    # Discover servers
    scan_paths = [*path] if path else None
    servers = discover_servers(scan_paths)

    if not servers:
        if not json_output:
            click.echo("No MCP servers found. Check your config files.")
            click.echo("Searched: ~/.mcp.json, ~/.cursor/mcp.json, .mcp.json")
        sys.exit(0)

    # Filter by name if requested
    if server:
        server_set = set(server)
        servers = [s for s in servers if s.name in server_set]
        if not servers:
            click.echo(f"No servers matching: {', '.join(server)}")
            sys.exit(1)

    # Run scanners on each server
    report = FullReport()
    report.config_sources = [*{s.source_file for s in servers if s.source_file}]

    for srv in servers:
        result = ScanResult(server=srv)

        for scanner in ALL_SCANNERS:
            result.findings.extend(scanner.scan(srv))

        # Grade it
        grade_server(result)
        report.results.append(result)

    # Output
    if json_output:
        click.echo(render_json(report))
    else:
        render_terminal(report, verbose=verbose)

    # Exit code: non-zero if any critical/high findings
    if report.total_critical > 0 or report.total_high > 0:
        sys.exit(2)


@main.command("list")
@click.option(
    "--path", "-p",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Specific config file(s) to check.",
)
def list_servers(path: tuple[Path, ...]):
    """List discovered MCP servers without scanning."""
    scan_paths = [*path] if path else None
    servers = discover_servers(scan_paths)

    if not servers:
        click.echo("No MCP servers found.")
        return

    click.echo(f"\nFound {len(servers)} MCP server(s):\n")
    for srv in servers:
        source = f" ({srv.source_app})" if srv.source_app else ""
        source_path = srv.resolve_server_path()
        click.echo(f"  {srv.name}")
        click.echo(f"    Transport: {srv.transport.value}")
        click.echo(f"    Command:   {srv.command} {' '.join(srv.args)}")
        if source_path:
            click.echo(f"    Source:     {source_path}")
        if srv.env:
            click.echo(f"    Env vars:  {len(srv.env)} configured")
        click.echo(f"    Config:    {srv.source_file}{source}")
        click.echo()


if __name__ == "__main__":
    main()
