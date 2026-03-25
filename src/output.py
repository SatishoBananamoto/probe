"""Output rendering for probe scan results."""

import json
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import FullReport, Grade, ScanResult, Severity


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: "!",
    Severity.MEDIUM: "~",
    Severity.LOW: "-",
    Severity.INFO: "i",
}

GRADE_COLORS = {
    Grade.A: "bold green",
    Grade.B: "green",
    Grade.C: "yellow",
    Grade.D: "red",
    Grade.F: "bold red",
}


def render_terminal(report: FullReport, verbose: bool = False) -> None:
    """Render a full report to the terminal using Rich."""
    console = Console()

    if not report.results:
        console.print("\n[dim]No MCP servers found to scan.[/dim]\n")
        return

    # Header
    console.print()
    console.print(
        Panel(
            f"[bold]probe[/bold] — MCP Server Security Scanner\n"
            f"[dim]{report.servers_scanned} server(s) scanned from "
            f"{len(report.config_sources)} config file(s)[/dim]",
            border_style="blue",
        )
    )

    # Per-server results
    for result in report.results:
        _render_server(console, result, verbose)

    # Summary
    _render_summary(console, report)
    console.print()


def _render_server(
    console: Console, result: ScanResult, verbose: bool
) -> None:
    """Render results for a single server."""
    server = result.server
    grade_color = GRADE_COLORS[result.grade]

    # Server header
    transport_label = server.transport.value
    source_label = f" ({server.source_app})" if server.source_app else ""

    header = Text()
    header.append(f"  {server.name}", style="bold")
    header.append(f"  [{transport_label}]{source_label}  ", style="dim")
    header.append(f"Grade: ", style="")
    header.append(f"{result.grade.value}", style=grade_color)
    header.append(f" ({result.score}/100)", style="dim")

    console.print()
    console.print(header)

    if not result.findings:
        console.print("    [green]No issues found[/green]")
        return

    # Findings
    for finding in result.findings_by_severity():
        icon = SEVERITY_ICONS[finding.severity]
        color = SEVERITY_COLORS[finding.severity]

        console.print(f"    [{color}][{icon}] {finding.title}[/{color}]")

        if verbose:
            # Show description and recommendation in verbose mode
            desc_lines = finding.description.split(". ")
            for line in desc_lines[:2]:
                console.print(f"        [dim]{line}.[/dim]")

            if finding.location:
                console.print(f"        [dim]at {finding.location}[/dim]")

            console.print(
                f"        [cyan]Fix:[/cyan] {finding.recommendation.split('. ')[0]}."
            )


def _render_summary(console: Console, report: FullReport) -> None:
    """Render the summary section."""
    console.print()

    overall_color = GRADE_COLORS[report.overall_grade]

    # Summary table
    table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
        show_edge=False,
    )
    table.add_column("label", style="dim")
    table.add_column("value")

    table.add_row(
        "Overall Grade",
        Text(
            f"{report.overall_grade.value} — {report.overall_grade.label}",
            style=overall_color,
        ),
    )
    table.add_row("Servers Scanned", str(report.servers_scanned))
    table.add_row("Total Findings", str(report.total_findings))

    if report.total_critical > 0:
        table.add_row(
            "Critical",
            Text(str(report.total_critical), style="bold red"),
        )
    if report.total_high > 0:
        table.add_row(
            "High",
            Text(str(report.total_high), style="red"),
        )

    console.print(Panel(table, title="Summary", border_style="blue"))


def render_json(report: FullReport) -> str:
    """Render a full report as JSON."""
    data = {
        "probe_version": "0.1.0",
        "overall_grade": report.overall_grade.value,
        "servers_scanned": report.servers_scanned,
        "total_findings": report.total_findings,
        "config_sources": [str(p) for p in report.config_sources],
        "results": [
            {
                "server": {
                    "name": r.server.name,
                    "command": r.server.command,
                    "transport": r.server.transport.value,
                    "source_app": r.server.source_app,
                    "source_file": str(r.server.source_file) if r.server.source_file else None,
                },
                "grade": r.grade.value,
                "score": r.score,
                "findings": [
                    {
                        "severity": f.severity.value,
                        "category": f.category.value,
                        "title": f.title,
                        "description": f.description,
                        "recommendation": f.recommendation,
                        "location": f.location,
                        "evidence": f.evidence,
                    }
                    for f in r.findings_by_severity()
                ],
            }
            for r in report.results
        ],
    }
    return json.dumps(data, indent=2)
