"""Tests for rule loading engine."""
from pathlib import Path
import pytest
from llm_scanner.rules.engine import load_rules


def test_loads_builtin_rules():
    rules = load_rules()
    assert len(rules) >= 10, f"Expected 10+ rules, got {len(rules)}"


def test_rules_have_required_fields():
    rules = load_rules()
    for rule in rules:
        assert rule.id, f"Rule missing id"
        assert rule.name, f"Rule {rule.id} missing name"
        assert rule.category.startswith("LLM"), f"Rule {rule.id} bad category"
        assert rule.severity in ("critical", "high", "medium", "low", "info"), \
            f"Rule {rule.id} bad severity: {rule.severity}"
        assert rule.languages, f"Rule {rule.id} missing languages"
        assert rule.patterns, f"Rule {rule.id} missing patterns"


def test_disable_rule():
    all_rules = load_rules()
    first_id = all_rules[0].id
    filtered = load_rules(disabled_rules=[first_id])
    assert not any(r.id == first_id for r in filtered)
    assert len(filtered) == len(all_rules) - 1


def test_enable_specific_rules():
    all_rules = load_rules()
    first_id = all_rules[0].id
    filtered = load_rules(enabled_rules=[first_id])
    assert len(filtered) == 1
    assert filtered[0].id == first_id


def test_custom_rules_dir_not_found_is_ok(tmp_path):
    rules = load_rules(custom_dirs=[tmp_path / "nonexistent"])
    # Should still load builtin rules
    assert len(rules) >= 10


def test_custom_rule_loaded(tmp_path):
    custom_rule = tmp_path / "custom_rule.yaml"
    custom_rule.write_text("""
id: CUSTOM-001
name: custom-test-rule
category: LLM01
severity: high
cwe: CWE-77
languages:
  - python
description: Custom test rule
remediation: Fix it
patterns:
  - type: function_call
    function: custom_func
""")
    rules = load_rules(custom_dirs=[tmp_path])
    custom = [r for r in rules if r.id == "CUSTOM-001"]
    assert len(custom) == 1
    assert custom[0].name == "custom-test-rule"


def test_all_rules_have_python_language():
    rules = load_rules()
    for rule in rules:
        assert "python" in rule.languages, f"Rule {rule.id} missing python language"


def test_rules_ids_are_unique():
    rules = load_rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "Duplicate rule IDs found"


def test_disable_multiple_rules():
    all_rules = load_rules()
    ids_to_disable = [r.id for r in all_rules[:2]]
    filtered = load_rules(disabled_rules=ids_to_disable)
    for rule_id in ids_to_disable:
        assert not any(r.id == rule_id for r in filtered)
    assert len(filtered) == len(all_rules) - 2


def test_enable_multiple_rules():
    all_rules = load_rules()
    ids_to_enable = [r.id for r in all_rules[:3]]
    filtered = load_rules(enabled_rules=ids_to_enable)
    assert len(filtered) == 3
    filtered_ids = {r.id for r in filtered}
    assert filtered_ids == set(ids_to_enable)


def test_custom_rule_combined_with_builtins(tmp_path):
    custom_rule = tmp_path / "extra.yaml"
    custom_rule.write_text("""
id: CUSTOM-999
name: extra-rule
category: LLM01
severity: low
cwe: CWE-77
languages:
  - python
description: Extra rule
remediation: N/A
patterns:
  - type: function_call
    function: extra_func
""")
    all_builtins = load_rules()
    combined = load_rules(custom_dirs=[tmp_path])
    assert len(combined) == len(all_builtins) + 1
    assert any(r.id == "CUSTOM-999" for r in combined)
