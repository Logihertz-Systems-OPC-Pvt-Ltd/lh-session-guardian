# ==============================================================================
# Product:       lh-session-guardian (lh-session)
# Module:        src.lh_session_guardian.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command-line interface for lh-session-guardian."""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from lh_session_guardian import __version__
from lh_session_guardian.exporters import (
    export_json,
    export_sarif,
    render_table_report,
    severity_to_style,
)
from lh_session_guardian.models import RULES_REGISTRY, FindingSeverity
from lh_session_guardian.session_analyzer import audit_session_target

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-session",
    help=(
        "Zero-daemon JWT token policy, session fixation, and cookie security hygiene guardian. "
        "Developed by Logihertz Systems (OPC) Private Limited."
    ),
    add_completion=True,
    rich_markup_mode=None,
)

console = Console()


class OutputFormat(StrEnum):
    """Supported output formats."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


def version_callback(value: bool) -> None:
    """Print package version and exit."""
    if value:
        console.print(f"lh-session-guardian v{__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-v",
            help="Show package version and exit",
            callback=version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Zero-daemon JWT, session fixation, and cookie security hygiene guardian."""


@app.command(name="scan")
def scan(
    target: Annotated[
        Path,
        typer.Argument(
            help="Target JWT file, session manifest, Nginx conf, env file, or directory to audit",
            exists=True,
            readable=True,
        ),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Report output format (table, json, sarif)",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Optional destination file path for audit report",
        ),
    ] = None,
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity",
            "-m",
            help="Minimum finding severity threshold to include (low, medium, high, critical)",
        ),
    ] = "low",
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Minimum severity threshold that triggers non-zero exit code",
        ),
    ] = "high",
) -> None:
    """Audit JWT policies, captured tokens, session configurations, and cookie directives."""
    min_sev = FindingSeverity.from_string(min_severity)
    fail_sev = FindingSeverity.from_string(fail_on)

    report = audit_session_target(target)

    # Filter findings by min_severity
    filtered_findings = [f for f in report.findings if f.severity.meets_threshold(min_sev)]
    report.findings = filtered_findings
    report.findings_count = len(filtered_findings)
    crit = sum(1 for f in filtered_findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in filtered_findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in filtered_findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in filtered_findings if f.severity == FindingSeverity.LOW)
    report.summary = {"critical": crit, "high": hi, "medium": med, "low": lo}

    # Render according to requested format
    if format == OutputFormat.TABLE:
        render_table_report(report, console=console)
        if output:
            table_console = Console(record=True, width=120)
            render_table_report(report, console=table_console)
            output.write_text(table_console.export_text(), encoding="utf-8")
            console.print(f"[dim]Audit report written to {output}[/dim]")
    elif format == OutputFormat.JSON:
        json_output = export_json(report)
        if output:
            output.write_text(json_output, encoding="utf-8")
            console.print(f"[dim]JSON audit report written to {output}[/dim]")
        else:
            console.print_json(json_output)
    elif format == OutputFormat.SARIF:
        sarif_output = export_sarif(report)
        if output:
            output.write_text(sarif_output, encoding="utf-8")
            console.print(f"[dim]SARIF audit report written to {output}[/dim]")
        else:
            print(sarif_output)

    # Determine exit code based on fail_on threshold
    trigger_findings = [f for f in report.findings if f.severity.meets_threshold(fail_sev)]
    if trigger_findings:
        sys.exit(1)


@app.command(name="rules")
def rules() -> None:
    """List all supported JWT token and session hygiene detection rules."""
    table = Table(
        title="lh-session-guardian Rule Catalog",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Rule ID", style="bold", width=14)
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Category", width=20)
    table.add_column("Title & Summary", width=56)

    for rule_id, rule_def in RULES_REGISTRY.items():
        sev_style = severity_to_style(rule_def.severity)
        title_summary = f"[bold]{rule_def.title}[/bold]\n[dim]{rule_def.description}[/dim]"
        table.add_row(
            rule_id,
            f"[{sev_style}]{rule_def.severity.value}[/]",
            rule_def.category,
            title_summary,
        )

    console.print(table)
