from __future__ import annotations

import re
from pathlib import Path

from llm_scanner.findings.models import Finding

# Matches: # llm-scan:ignore  OR  # llm-scan:ignore[LLM01-001,LLM02-003]
_IGNORE_PATTERN = re.compile(r"#\s*llm-scan:ignore(?:\[([^\]]+)\])?")


def _parse_suppressions(source: str) -> dict[int, set[str] | None]:
    """Return {line_number: None (suppress all) | set(rule_ids)}."""
    suppressions: dict[int, set[str] | None] = {}
    for i, line in enumerate(source.splitlines(), start=1):
        m = _IGNORE_PATTERN.search(line)
        if m:
            if m.group(1):
                rule_ids = {r.strip() for r in m.group(1).split(",")}
                suppressions[i] = rule_ids
            else:
                suppressions[i] = None  # suppress all rules on this line
    return suppressions


def apply_suppressions(
    findings: list[Finding], source_files: dict[Path, str]
) -> list[Finding]:
    """Mark findings as suppressed if covered by inline ignore comments."""
    cache: dict[Path, dict[int, set[str] | None]] = {}

    for finding in findings:
        source = source_files.get(finding.file_path)
        if source is None:
            continue
        if finding.file_path not in cache:
            cache[finding.file_path] = _parse_suppressions(source)
        suppressions = cache[finding.file_path]
        if finding.line not in suppressions:
            continue
        sup = suppressions[finding.line]
        if sup is None:
            # None means suppress all rules on this line
            finding.suppressed = True
        elif finding.rule_id in sup:
            finding.suppressed = True

    return findings
