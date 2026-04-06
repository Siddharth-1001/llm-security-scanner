"""Main scanner orchestrator — runs the full analysis pipeline."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic

from llm_scanner.config import ScanConfig
from llm_scanner.discovery import Language, SourceFile, discover_files
from llm_scanner.findings.models import Finding, Severity
from llm_scanner.findings.suppression import apply_suppressions
from llm_scanner.parsers.python_parser import PythonParser
from llm_scanner.rules.engine import load_rules
from llm_scanner.rules.matchers import PythonMatcher

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.active_findings:
            counts[f.severity.value] += 1
        return counts

    def counts_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.active_findings:
            counts[f.owasp_category] = counts.get(f.owasp_category, 0) + 1
        return counts


def _meets_threshold(severity: Severity, threshold: Severity) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)


def run_scan(cfg: ScanConfig) -> ScanResult:
    """Execute full scan pipeline and return aggregated results."""
    start = monotonic()
    result = ScanResult()

    # Load rules
    rules = load_rules(
        custom_dirs=cfg.custom_rules_dirs or [],
        enabled_rules=cfg.enabled_rules or None,
        disabled_rules=cfg.disabled_rules or None,
    )
    if not rules:
        logger.warning("No rules loaded — check rules directory")

    threshold = Severity(cfg.severity_threshold)

    # Discover files
    source_files: list[SourceFile] = discover_files(cfg.target_path, cfg.exclude_globs)
    python_parser = PythonParser()

    # Track source text for suppression
    source_cache: dict[Path, str] = {}
    all_findings: list[Finding] = []

    for sf in source_files:
        if sf.language == Language.PYTHON:
            parsed = python_parser.parse(sf.path)
            if parsed is None:
                result.files_skipped += 1
                result.errors.append(f"Failed to read {sf.path}")
                continue
            source_cache[sf.path] = parsed.source
            matcher = PythonMatcher(parsed.source, sf.path)
            if matcher.tree is None:
                result.errors.append(f"Syntax error in {sf.path}")
                result.files_skipped += 1
                continue
            for rule in rules:
                if "python" not in rule.languages:
                    continue
                try:
                    findings = matcher.match_rule(rule)
                    # Filter by threshold
                    findings = [
                        f for f in findings if _meets_threshold(f.severity, threshold)
                    ]
                    all_findings.extend(findings)
                except Exception as e:
                    msg = f"Rule {rule.id} failed on {sf.path}: {e}"
                    logger.warning(msg)
                    result.errors.append(msg)
            result.files_scanned += 1
        else:
            # JS/TS: count but skip matching (not yet supported)
            result.files_scanned += 1

    # Apply inline suppressions
    all_findings = apply_suppressions(all_findings, source_cache)

    # Sort: severity desc, then file path, then line
    all_findings.sort(
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), str(f.file_path), f.line)
    )

    result.findings = all_findings
    result.duration_seconds = monotonic() - start
    return result
