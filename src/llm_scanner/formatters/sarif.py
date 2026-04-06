"""SARIF 2.1.0 output formatter for GitHub Code Scanning."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from llm_scanner import __version__
from llm_scanner.findings.models import Finding, Severity
from llm_scanner.scanner import ScanResult

SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def _make_rule(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_name.replace("-", " ").title().replace(" ", ""),
        "shortDescription": {"text": finding.rule_name},
        "fullDescription": {"text": finding.description},
        "helpUri": "https://owasp.org/www-project-top-10-for-llm-applications/",
        "help": {"text": finding.remediation, "markdown": finding.remediation},
        "properties": {
            "tags": [finding.owasp_category, finding.cwe],
            "precision": "medium",
            "problem.severity": SARIF_SEVERITY_MAP.get(finding.severity, "warning"),
        },
        "defaultConfiguration": {
            "level": SARIF_SEVERITY_MAP.get(finding.severity, "warning"),
        },
    }


def _make_result(finding: Finding, base_path: Path | None = None) -> dict[str, object]:
    try:
        uri = (
            finding.file_path.relative_to(base_path).as_posix()
            if base_path
            else finding.file_path.as_posix()
        )
    except ValueError:
        uri = finding.file_path.as_posix()

    snippet_text = "\n".join(finding.snippet.lines) if finding.snippet.lines else ""

    return {
        "ruleId": finding.rule_id,
        "level": SARIF_SEVERITY_MAP.get(finding.severity, "warning"),
        "message": {
            "text": f"{finding.description.strip()} See remediation: {finding.remediation.strip()[:200]}"
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.col,
                        "snippet": {"text": snippet_text},
                    },
                }
            }
        ],
        "properties": {
            "owasp_category": finding.owasp_category,
            "cwe": finding.cwe,
        },
    }


def format_sarif(result: ScanResult, base_path: Path | None = None) -> str:
    """Serialize scan results to SARIF 2.1.0 JSON string."""
    active = result.active_findings

    # Deduplicate rules
    seen_rules: dict[str, dict[str, object]] = {}
    for f in active:
        if f.rule_id not in seen_rules:
            seen_rules[f.rule_id] = _make_rule(f)

    sarif_output = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "llm-security-scanner",
                        "version": __version__,
                        "informationUri": "https://github.com/llm-security-scanner/llm-security-scanner",
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": [_make_result(f, base_path) for f in active],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif_output, indent=2, default=str)
