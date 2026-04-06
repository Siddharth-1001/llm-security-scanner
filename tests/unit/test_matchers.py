"""Tests for Python AST matchers."""
from pathlib import Path
import pytest
from llm_scanner.rules.matchers import PythonMatcher
from llm_scanner.rules.models import Pattern, Rule


def _make_rule(id: str, category: str, patterns: list[Pattern]) -> Rule:
    return Rule(
        id=id,
        name=id,
        category=category,
        severity="high",
        cwe="CWE-77",
        languages=["python"],
        patterns=patterns,
        description="Test",
        remediation="Fix it",
    )


def _match(source: str, rule: Rule) -> list:
    matcher = PythonMatcher(source, Path("test.py"))
    return matcher.match_rule(rule)


class TestFunctionCallMatcher:
    def test_detects_function_call(self):
        source = "import subprocess\nsubprocess.run('ls')\n"
        rule = _make_rule("T01", "LLM08", [Pattern(type="function_call", functions=["subprocess.run"])])
        findings = _match(source, rule)
        assert len(findings) == 1

    def test_no_false_positive(self):
        source = "safe_function()\n"
        rule = _make_rule("T01", "LLM08", [Pattern(type="function_call", functions=["subprocess.run"])])
        findings = _match(source, rule)
        assert len(findings) == 0

    def test_detects_eval(self):
        source = "eval('1+1')\n"
        rule = _make_rule("T02", "LLM02", [Pattern(type="function_call", function="eval")])
        findings = _match(source, rule)
        assert len(findings) == 1

    def test_detects_multiple_calls(self):
        source = "eval('a')\neval('b')\n"
        rule = _make_rule("T02", "LLM02", [Pattern(type="function_call", function="eval")])
        findings = _match(source, rule)
        assert len(findings) == 2

    def test_finding_has_correct_line(self):
        source = "x = 1\neval('bad')\n"
        rule = _make_rule("T02", "LLM02", [Pattern(type="function_call", function="eval")])
        findings = _match(source, rule)
        assert findings[0].line == 2

    def test_finding_has_correct_rule_id(self):
        source = "eval('x')\n"
        rule = _make_rule("LLM02-999", "LLM02", [Pattern(type="function_call", function="eval")])
        findings = _match(source, rule)
        assert findings[0].rule_id == "LLM02-999"


class TestArgumentMissingMatcher:
    def test_detects_missing_max_tokens(self):
        source = """
import openai
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "hello"}]
)
"""
        rule = _make_rule("LLM04-001", "LLM04", [
            Pattern(type="argument_missing",
                    functions=["ChatCompletion.create"],
                    argument="max_tokens")
        ])
        findings = _match(source, rule)
        assert len(findings) == 1

    def test_no_finding_when_arg_present(self):
        source = """
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[],
    max_tokens=1000
)
"""
        rule = _make_rule("LLM04-001", "LLM04", [
            Pattern(type="argument_missing",
                    functions=["ChatCompletion.create"],
                    argument="max_tokens")
        ])
        findings = _match(source, rule)
        assert len(findings) == 0

    def test_finding_has_correct_category(self):
        source = "openai.ChatCompletion.create(model='gpt-4', messages=[])\n"
        rule = _make_rule("LLM04-001", "LLM04", [
            Pattern(type="argument_missing",
                    functions=["ChatCompletion.create"],
                    argument="max_tokens")
        ])
        findings = _match(source, rule)
        assert all(f.owasp_category == "LLM04" for f in findings)


class TestArgumentTaintedMatcher:
    def test_detects_fstring_with_user_input(self):
        # _is_tainted handles JoinedStr directly; pass f-string as top-level arg
        source = """
user_input = input("Enter: ")
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=f"Help: {user_input}"
)
"""
        rule = _make_rule("LLM01-001", "LLM01", [
            Pattern(type="argument_tainted",
                    functions=["ChatCompletion.create"],
                    tainted_sources=["user_input", "input"])
        ])
        findings = _match(source, rule)
        assert len(findings) >= 1

    def test_no_finding_for_static_prompt(self):
        source = """
PROMPT = "You are a helpful assistant."
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "system", "content": PROMPT}]
)
"""
        rule = _make_rule("LLM01-001", "LLM01", [
            Pattern(type="argument_tainted",
                    functions=["ChatCompletion.create"],
                    tainted_sources=["user_input"])
        ])
        findings = _match(source, rule)
        assert len(findings) == 0


class TestOutputToSinkMatcher:
    def test_detects_llm_output_to_eval(self):
        # Matcher tracks variables directly assigned from LLM calls; use response directly
        source = """
import openai
response = openai.ChatCompletion.create(model="gpt-4", messages=[])
eval(response)
"""
        rule = _make_rule("LLM02-001", "LLM02", [
            Pattern(type="output_to_sink",
                    functions=["ChatCompletion.create"],
                    sinks=["eval"])
        ])
        findings = _match(source, rule)
        assert len(findings) >= 1

    def test_syntax_error_returns_empty(self):
        source = "def broken(:\n"
        rule = _make_rule("T01", "LLM01", [Pattern(type="function_call", function="eval")])
        findings = _match(source, rule)
        assert findings == []

    def test_empty_source_returns_empty(self):
        source = ""
        rule = _make_rule("T01", "LLM01", [Pattern(type="function_call", function="eval")])
        findings = _match(source, rule)
        assert findings == []


class TestMatcherFilePath:
    def test_finding_file_path_matches_input(self):
        source = "eval('x')\n"
        path = Path("some/dir/app.py")
        rule = _make_rule("T01", "LLM01", [Pattern(type="function_call", function="eval")])
        matcher = PythonMatcher(source, path)
        findings = matcher.match_rule(rule)
        assert findings[0].file_path == path
