"""Rich terminal output formatter."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from llm_scanner.findings.models import Severity
from llm_scanner.scanner import ScanResult

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def _severity_badge(s: Severity) -> Text:
    color = SEVERITY_COLORS.get(s, "white")
    return Text(f" {s.value.upper()} ", style=f"bold {color} on default")


def format_text(result: ScanResult, use_color: bool = True) -> str:
    """Render scan results as Rich terminal output, return as string."""
    buf = StringIO()
    console = Console(file=buf, highlight=False, no_color=not use_color)

    active = result.active_findings

    if not active:
        console.print("\n[bold green]✓ No findings above threshold.[/bold green]")
    else:
        console.print()
        for finding in active:
            color = SEVERITY_COLORS.get(finding.severity, "white")
            header = (
                f"[{color}]{finding.rule_id}[/{color}]  "
                f"{finding.rule_name}  "
                f"[dim]{finding.owasp_category} · {finding.cwe}[/dim]"
            )
            location = f"[cyan]{finding.file_path}[/cyan]:[bold]{finding.line}[/bold]:{finding.col}"
            snippet_text = str(finding.snippet)

            body = f"{location}\n\n[dim]{snippet_text}[/dim]\n\n"
            body += f"[italic]{finding.description.strip()}[/italic]\n\n"
            body += f"[bold]Remediation:[/bold] {finding.remediation.strip()[:200]}…"

            console.print(
                Panel(
                    body,
                    title=header,
                    title_align="left",
                    border_style=color,
                    expand=False,
                )
            )

    # Summary table
    console.print()
    table = Table(title="Scan Summary", show_header=True, header_style="bold")
    table.add_column("Metric")
    table.add_column("Value", justify="right")

    table.add_row("Files scanned", str(result.files_scanned))
    table.add_row("Files skipped", str(result.files_skipped))
    table.add_row("Total findings", str(len(active)))
    table.add_row("Scan duration", f"{result.duration_seconds:.2f}s")
    console.print(table)

    # Per-severity breakdown
    counts = result.counts_by_severity()
    sev_table = Table(title="Findings by Severity", show_header=True)
    sev_table.add_column("Severity")
    sev_table.add_column("Count", justify="right")
    for sev in [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]:
        n = counts.get(sev.value, 0)
        if n:
            color = SEVERITY_COLORS.get(sev, "white")
            sev_table.add_row(f"[{color}]{sev.value.upper()}[/{color}]", str(n))
    if any(counts.values()):
        console.print(sev_table)

    # Show errors/warnings if any
    if result.errors:
        console.print()
        console.print(
            f"[yellow]⚠ {len(result.errors)} warning(s) during scan:[/yellow]"
        )
        for err in result.errors[:10]:
            console.print(f"  [dim]• {err}[/dim]")
        if len(result.errors) > 10:
            console.print(f"  [dim]… and {len(result.errors) - 10} more[/dim]")

    return buf.getvalue()
