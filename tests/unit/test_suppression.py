"""Tests for inline suppression engine."""
from pathlib import Path
import pytest
from llm_scanner.findings.models import CodeSnippet, Finding, Severity
from llm_scanner.findings.suppression import apply_suppressions


def _make_finding(path: Path, line: int, rule_id: str = "LLM01-001") -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name="test",
        owasp_category="LLM01",
        cwe="CWE-77",
        severity=Severity.HIGH,
        file_path=path,
        line=line,
        col=1,
        snippet=CodeSnippet(lines=["x"], start_line=line),
        description="desc",
        remediation="fix",
    )


def test_suppress_all_on_line():
    path = Path("test.py")
    source = "code()  # llm-scan:ignore\n"
    findings = [_make_finding(path, 1)]
    result = apply_suppressions(findings, {path: source})
    assert result[0].suppressed is True


def test_suppress_specific_rule():
    path = Path("test.py")
    source = "code()  # llm-scan:ignore[LLM01-001]\n"
    findings = [_make_finding(path, 1, "LLM01-001")]
    result = apply_suppressions(findings, {path: source})
    assert result[0].suppressed is True


def test_suppress_specific_rule_does_not_suppress_other():
    path = Path("test.py")
    source = "code()  # llm-scan:ignore[LLM01-001]\n"
    findings = [_make_finding(path, 1, "LLM02-001")]
    result = apply_suppressions(findings, {path: source})
    assert result[0].suppressed is False


def test_no_suppression_on_different_line():
    path = Path("test.py")
    source = "line1\ncode()  # llm-scan:ignore\nline3\n"
    findings = [_make_finding(path, 1)]  # line 1, suppress is on line 2
    result = apply_suppressions(findings, {path: source})
    assert result[0].suppressed is False


def test_suppress_multiple_rules():
    path = Path("test.py")
    source = "code()  # llm-scan:ignore[LLM01-001,LLM02-001]\n"
    f1 = _make_finding(path, 1, "LLM01-001")
    f2 = _make_finding(path, 1, "LLM02-001")
    f3 = _make_finding(path, 1, "LLM08-001")
    result = apply_suppressions([f1, f2, f3], {path: source})
    assert result[0].suppressed is True
    assert result[1].suppressed is True
    assert result[2].suppressed is False


def test_empty_findings_returns_empty():
    path = Path("test.py")
    source = "# llm-scan:ignore\n"
    result = apply_suppressions([], {path: source})
    assert result == []


def test_finding_with_no_source_not_suppressed():
    path = Path("test.py")
    findings = [_make_finding(path, 1)]
    result = apply_suppressions(findings, {})
    assert result[0].suppressed is False


def test_suppress_preserves_other_fields():
    path = Path("test.py")
    source = "code()  # llm-scan:ignore\n"
    f = _make_finding(path, 1, "LLM01-001")
    result = apply_suppressions([f], {path: source})
    assert result[0].rule_id == "LLM01-001"
    assert result[0].severity == Severity.HIGH


def test_suppress_multiline_source():
    path = Path("test.py")
    source = "safe_line()\nbad_line()  # llm-scan:ignore\nanother_safe()\n"
    f_line1 = _make_finding(path, 1)
    f_line2 = _make_finding(path, 2)
    f_line3 = _make_finding(path, 3)
    result = apply_suppressions([f_line1, f_line2, f_line3], {path: source})
    assert result[0].suppressed is False
    assert result[1].suppressed is True
    assert result[2].suppressed is False
