"""Tests for Finding and Severity models."""

from pathlib import Path

from llm_scanner.findings.models import CodeSnippet, Finding, Severity


def test_severity_ordering():
    # Severity defines __lt__ only; use < for reliable ordering
    assert Severity.HIGH < Severity.CRITICAL
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.INFO < Severity.LOW


def test_severity_values():
    assert Severity("critical") == Severity.CRITICAL
    assert Severity.HIGH.value == "high"


def test_code_snippet_str():
    snippet = CodeSnippet(lines=["line1", "line2", "line3"], start_line=5)
    text = str(snippet)
    assert "line1" in text
    assert "5" in text  # line number appears


def _make_finding(**kwargs) -> Finding:
    defaults = {
        "rule_id": "LLM01-001",
        "rule_name": "test-rule",
        "owasp_category": "LLM01",
        "cwe": "CWE-77",
        "severity": Severity.HIGH,
        "file_path": Path("test.py"),
        "line": 10,
        "col": 1,
        "snippet": CodeSnippet(lines=["code"], start_line=10),
        "description": "Test description",
        "remediation": "Fix it",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_finding_to_dict():
    f = _make_finding()
    d = f.to_dict()
    assert d["rule_id"] == "LLM01-001"
    assert d["severity"] == "high"
    assert d["line"] == 10
    assert "snippet" in d
    assert d["suppressed"] is False


def test_finding_suppressed_default():
    f = _make_finding()
    assert f.suppressed is False


def test_finding_suppressed_can_be_set():
    f = _make_finding()
    f.suppressed = True
    assert f.suppressed is True


def test_code_snippet_single_line():
    snippet = CodeSnippet(lines=["only_line"], start_line=1)
    text = str(snippet)
    assert "only_line" in text
    assert "1" in text


def test_finding_to_dict_file_path_is_string():
    f = _make_finding()
    d = f.to_dict()
    assert isinstance(d["file_path"], str)


def test_finding_to_dict_snippet_contains_code():
    f = _make_finding(snippet=CodeSnippet(lines=["my_code()"], start_line=10))
    d = f.to_dict()
    assert "my_code" in str(d["snippet"])


def test_finding_with_tags():
    f = _make_finding(tags=["injection", "owasp"])
    assert "injection" in f.tags
    assert "owasp" in f.tags


def test_severity_all_values():
    for val in ("critical", "high", "medium", "low", "info"):
        s = Severity(val)
        assert s.value == val
