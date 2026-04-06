"""Integration tests for the full scan pipeline."""
from pathlib import Path
import json
import pytest
from llm_scanner.config import ScanConfig
from llm_scanner.scanner import run_scan

FIXTURES = Path(__file__).parent.parent / "fixtures" / "python"
VULNERABLE = FIXTURES / "vulnerable"
CLEAN = FIXTURES / "clean"


@pytest.fixture
def base_config():
    return ScanConfig(
        target_path=VULNERABLE,
        severity_threshold="info",
    )


def test_vulnerable_fixtures_produce_findings(base_config):
    """Scanning vulnerable code should find at least some issues."""
    result = run_scan(base_config)
    assert result.files_scanned > 0
    assert len(result.active_findings) > 0, "Expected findings in vulnerable fixtures"


def test_clean_fixtures_produce_fewer_findings():
    """Clean code should produce fewer findings than vulnerable code."""
    cfg_vuln = ScanConfig(target_path=VULNERABLE, severity_threshold="info")
    cfg_clean = ScanConfig(target_path=CLEAN, severity_threshold="info")
    result_vuln = run_scan(cfg_vuln)
    result_clean = run_scan(cfg_clean)
    assert len(result_vuln.active_findings) > len(result_clean.active_findings)


def test_severity_threshold_filters():
    """High threshold should produce fewer or equal findings than low threshold."""
    cfg_low = ScanConfig(target_path=VULNERABLE, severity_threshold="low")
    cfg_high = ScanConfig(target_path=VULNERABLE, severity_threshold="high")
    result_low = run_scan(cfg_low)
    result_high = run_scan(cfg_high)
    assert len(result_high.active_findings) <= len(result_low.active_findings)


def test_finding_has_required_fields(base_config):
    result = run_scan(base_config)
    for finding in result.active_findings:
        assert finding.rule_id
        assert finding.owasp_category.startswith("LLM")
        assert finding.file_path.exists()
        assert finding.line >= 1
        assert finding.severity is not None
        assert finding.description
        assert finding.remediation


def test_disabled_rule_suppresses_finding(base_config):
    all_result = run_scan(base_config)
    if not all_result.active_findings:
        pytest.skip("No findings to disable")
    first_rule = all_result.active_findings[0].rule_id
    cfg_disabled = ScanConfig(
        target_path=VULNERABLE,
        severity_threshold="info",
        disabled_rules=[first_rule],
    )
    disabled_result = run_scan(cfg_disabled)
    disabled_ids = {f.rule_id for f in disabled_result.active_findings}
    assert first_rule not in disabled_ids


def test_json_output_is_valid(base_config):
    from llm_scanner.formatters.json_fmt import format_json
    result = run_scan(base_config)
    json_str = format_json(result)
    data = json.loads(json_str)
    assert "findings" in data
    assert "summary" in data
    assert data["summary"]["files_scanned"] > 0


def test_sarif_output_is_valid(base_config):
    from llm_scanner.formatters.sarif import format_sarif
    result = run_scan(base_config)
    sarif_str = format_sarif(result)
    data = json.loads(sarif_str)
    assert data["version"] == "2.1.0"
    assert "runs" in data
    assert len(data["runs"]) == 1


def test_text_output_not_empty(base_config):
    from llm_scanner.formatters.text import format_text
    result = run_scan(base_config)
    text = format_text(result, use_color=False)
    assert len(text) > 0
    assert "Scan Summary" in text


def test_scan_result_counts(base_config):
    result = run_scan(base_config)
    assert result.files_scanned >= 0
    by_sev = result.counts_by_severity()
    assert isinstance(by_sev, dict)
    total_from_sev = sum(by_sev.values())
    assert total_from_sev == len(result.active_findings)


def test_scan_result_has_duration(base_config):
    result = run_scan(base_config)
    assert result.duration_seconds >= 0.0


def test_counts_by_category(base_config):
    result = run_scan(base_config)
    by_cat = result.counts_by_category()
    assert isinstance(by_cat, dict)
    for key in by_cat:
        assert key.startswith("LLM"), f"Unexpected category key: {key}"


def test_no_active_findings_when_all_suppressed(tmp_path):
    """When all findings are suppressed via inline comments, active_findings is empty."""
    vuln_file = tmp_path / "test.py"
    vuln_file.write_text(
        "response = openai.ChatCompletion.create(model='gpt-4', messages=[])  # llm-scan:ignore\n"
        "eval('bad')  # llm-scan:ignore\n"
    )
    cfg = ScanConfig(target_path=tmp_path, severity_threshold="info")
    result = run_scan(cfg)
    # All findings should be suppressed; active_findings excludes suppressed ones
    assert all(f.suppressed for f in result.findings if f.file_path == vuln_file)


def test_enabled_rules_only_fires_those_rules(base_config):
    all_result = run_scan(base_config)
    if not all_result.active_findings:
        pytest.skip("No findings to filter")
    first_rule = all_result.active_findings[0].rule_id
    cfg_enabled = ScanConfig(
        target_path=VULNERABLE,
        severity_threshold="info",
        enabled_rules=[first_rule],
    )
    enabled_result = run_scan(cfg_enabled)
    for finding in enabled_result.active_findings:
        assert finding.rule_id == first_rule
