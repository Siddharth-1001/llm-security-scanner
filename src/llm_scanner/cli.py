"""CLI entry point for llm-security-scanner."""
from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from llm_scanner import __version__
from llm_scanner.config import load_config
from llm_scanner.findings.models import Severity
from llm_scanner.formatters.json_fmt import format_json
from llm_scanner.formatters.sarif import format_sarif
from llm_scanner.formatters.text import format_text
from llm_scanner.scanner import ScanResult, run_scan

console = Console(stderr=True)

SEVERITY_ORDER = {
    "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
}


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="llm-scan")
def cli() -> None:
    """LLM Security Scanner — detect OWASP LLM Top 10 vulnerabilities."""


@cli.command("scan")
@click.argument(
    "target",
    type=click.Path(exists=True, path_type=Path),
    default=Path("."),
    required=False,
)
@click.option("--config", "-c", type=click.Path(path_type=Path), default=None,
              help="Path to .llm-scanner.yml config file.")
@click.option("--severity", "-s",
              type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
              default=None, help="Minimum severity threshold (overrides config).")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
              default=None, help="Output format (overrides config).")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write results to file instead of stdout.")
@click.option("--rule", "enabled_rules", multiple=True,
              help="Enable only specific rule IDs (repeatable).")
@click.option("--disable-rule", "disabled_rules", multiple=True,
              help="Disable specific rule IDs (repeatable).")
@click.option("--rules-dir", "rules_dirs", multiple=True, type=click.Path(path_type=Path),
              help="Additional directory containing custom rules (repeatable).")
@click.option("--exclude", "excludes", multiple=True,
              help="Glob pattern to exclude from scanning (repeatable).")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Suppress banner and summary; output findings only.")
@click.option("--no-progress", is_flag=True, default=False,
              help="Suppress progress output to stderr.")
@click.option("--fail-on", "fail_on",
              type=click.Choice(["critical", "high", "medium", "low", "info", "never"], case_sensitive=False),
              default=None,
              help="Exit with code 1 if any finding at or above this severity is found.")
def scan(
    target: Path,
    config: Path | None,
    severity: str | None,
    output_format: str | None,
    output: Path | None,
    enabled_rules: tuple[str, ...],
    disabled_rules: tuple[str, ...],
    rules_dirs: tuple[str, ...],
    excludes: tuple[str, ...],
    quiet: bool,
    no_progress: bool,
    fail_on: str | None,
) -> None:
    """Scan TARGET directory or file for LLM security vulnerabilities.

    TARGET defaults to the current directory.
    """
    silent = quiet or no_progress
    cli_overrides: dict = {"target_path": target}
    if severity:
        cli_overrides["severity_threshold"] = severity
    if output_format:
        cli_overrides["output_format"] = output_format
    if output:
        cli_overrides["output_file"] = output
    if enabled_rules:
        cli_overrides["enabled_rules"] = list(enabled_rules)
    if disabled_rules:
        cli_overrides["disabled_rules"] = list(disabled_rules)
    if rules_dirs:
        cli_overrides["custom_rules_dirs"] = [Path(d) for d in rules_dirs]
    if excludes:
        cli_overrides["extra_excludes"] = list(excludes)

    try:
        cfg = load_config(config, cli_overrides)
    except Exception as exc:
        console.print(f"[bold red]Configuration error:[/bold red] {exc}")
        sys.exit(2)

    if not silent:
        console.print(f"[bold]llm-scan[/bold] v{__version__}  scanning [cyan]{cfg.target_path}[/cyan] …")

    try:
        result: ScanResult = run_scan(cfg)
    except Exception as exc:
        console.print(f"[bold red]Scan error:[/bold red] {exc}")
        sys.exit(2)

    if not silent:
        n = len(result.active_findings)
        console.print(
            f"Scanned [bold]{result.files_scanned}[/bold] file(s) in "
            f"{result.duration_seconds:.2f}s — "
            f"[{'bold red' if n else 'bold green'}]{n} finding(s)[/]"
        )

    fmt = cfg.output_format
    if fmt == "json":
        rendered = format_json(result)
    elif fmt == "sarif":
        rendered = format_sarif(result, base_path=cfg.target_path)
    else:
        rendered = format_text(result, use_color=(output is None))

    if cfg.output_file:
        cfg.output_file.write_text(rendered, encoding="utf-8")
        if not silent:
            console.print(f"Results written to [cyan]{cfg.output_file}[/cyan]")
    else:
        click.echo(rendered)

    threshold = fail_on or cfg.severity_threshold
    if threshold != "never":
        threshold_order = SEVERITY_ORDER.get(threshold, 0)
        has_violation = any(
            SEVERITY_ORDER.get(f.severity.value, 0) >= threshold_order
            for f in result.active_findings
        )
        sys.exit(1 if has_violation else 0)


@cli.command("version")
def version_cmd() -> None:
    """Print version and exit."""
    click.echo(f"llm-scan {__version__}")


@cli.command("init")
@click.option("--output", "-o", type=click.Path(path_type=Path),
              default=Path(".llm-scanner.yml"),
              help="Where to write the config file.")
def init(output: Path) -> None:
    """Generate a default .llm-scanner.yml in the current directory."""
    if output.exists():
        click.confirm(f"{output} already exists. Overwrite?", abort=True)
    template = """\
# LLM Security Scanner Configuration
severity_threshold: high
output_format: text
exclude:
  - "**/.git/**"
  - "**/node_modules/**"
  - "**/__pycache__/**"
  - "**/.venv/**"
  - "**/venv/**"
  - "**/dist/**"
  - "**/build/**"
# disable_rules: []
# custom_rules_dirs: []
"""
    output.write_text(template, encoding="utf-8")
    console.print(f"[green]Created[/green] {output}")


def main() -> None:
    """Entrypoint called by pyproject.toml scripts."""
    cli()


if __name__ == "__main__":
    main()
