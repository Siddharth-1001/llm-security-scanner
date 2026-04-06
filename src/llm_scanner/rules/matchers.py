"""AST pattern matchers for Python source code."""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from llm_scanner.findings.models import CodeSnippet, Finding, Severity
from llm_scanner.rules.models import Pattern, Rule

logger = logging.getLogger(__name__)

# Common tainted source names (user-controlled input)
TAINTED_SOURCES = frozenset(
    {
        "request",
        "input",
        "argv",
        "sys.argv",
        "environ",
        "os.environ",
        "flask.request",
        "django.request",
        "query_params",
        "form",
        "json",
        "data",
        "body",
        "args",
        "kwargs",
        "params",
    }
)

# LLM API call functions (qualified and unqualified)
LLM_API_CALLS = frozenset(
    {
        "ChatCompletion.create",
        "openai.ChatCompletion.create",
        "client.chat.completions.create",
        "chat.completions.create",
        "client.messages.create",
        "messages.create",
        "anthropic.Anthropic",
        "openai.OpenAI",
        "generate",
        "complete",
        "chat",
    }
)

# Dangerous sinks for LLM output
DANGEROUS_SINKS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "os.system",
        "os.popen",
        "open",
    }
)


def _get_source_snippet(
    source_lines: list[str], line: int, context: int = 1
) -> CodeSnippet:
    """Extract source lines around the given line (1-based)."""
    start = max(0, line - 1 - context)
    end = min(len(source_lines), line + context)
    return CodeSnippet(
        lines=source_lines[start:end],
        start_line=start + 1,
    )


def _get_func_name(node: ast.expr) -> str:
    """Get a dotted function name from a Call node's func attribute."""
    if isinstance(node, ast.Attribute):
        return f"{_get_func_name(node.value)}.{node.attr}"
    elif isinstance(node, ast.Name):
        return node.id
    return ""


def _is_tainted(node: ast.expr, tainted_names: frozenset[str]) -> bool:
    """Heuristic: check if an expression node derives from a tainted source."""
    if isinstance(node, ast.Name):
        return node.id in tainted_names
    elif isinstance(node, ast.Attribute):
        return _is_tainted(node.value, tainted_names)
    elif isinstance(node, ast.JoinedStr):  # f-string
        return any(
            _is_tainted(v, tainted_names)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_tainted(node.left, tainted_names) or _is_tainted(
            node.right, tainted_names
        )
    elif isinstance(node, ast.Call):
        func_name = _get_func_name(node.func)
        if func_name in ("str", "format", "encode", "decode"):
            return any(_is_tainted(a, tainted_names) for a in node.args)
    return False


def _contains_tainted_string(node: ast.expr, tainted_names: frozenset[str]) -> bool:
    """Check if a string-building expression (f-string, concat) uses tainted sources."""
    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.FormattedValue) and _is_tainted(
                value.value, tainted_names
            ):
                return True
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _contains_tainted_string(
            node.left, tainted_names
        ) or _contains_tainted_string(node.right, tainted_names)
    return False


class PythonMatcher:
    def __init__(self, source: str, file_path: Path):
        self.source = source
        self.source_lines = source.splitlines()
        self.file_path = file_path
        try:
            self.tree = ast.parse(source)
        except SyntaxError:
            self.tree = None

    def match_rule(self, rule: Rule) -> list[Finding]:
        if self.tree is None:
            return []
        findings: list[Finding] = []
        for pattern in rule.patterns:
            if rule.languages and "python" not in rule.languages:
                continue
            matched = self._match_pattern(pattern, rule)
            findings.extend(matched)
        return findings

    def _match_pattern(self, pattern: Pattern, rule: Rule) -> list[Finding]:
        if pattern.type == "function_call":
            return self._match_function_call(pattern, rule)
        elif pattern.type == "argument_missing":
            return self._match_argument_missing(pattern, rule)
        elif pattern.type == "argument_tainted":
            return self._match_argument_tainted(pattern, rule)
        elif pattern.type == "output_to_sink":
            return self._match_output_to_sink(pattern, rule)
        elif pattern.type == "string_concat_taint":
            return self._match_string_concat_taint(pattern, rule)
        return []

    def _make_finding(self, rule: Rule, node: ast.AST) -> Finding:
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        return Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            owasp_category=rule.category,
            cwe=rule.cwe,
            severity=Severity(rule.severity),
            file_path=self.file_path,
            line=line,
            col=col,
            snippet=_get_source_snippet(self.source_lines, line),
            description=rule.description,
            remediation=rule.remediation,
        )

    def _match_function_call(self, pattern: Pattern, rule: Rule) -> list[Finding]:
        """Detect calls to specific functions."""
        target_funcs = set()
        if pattern.function:
            target_funcs.add(pattern.function)
        target_funcs.update(pattern.functions)

        findings: list[Finding] = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = _get_func_name(node.func)
            if any(func_name.endswith(t) or func_name == t for t in target_funcs):
                findings.append(self._make_finding(rule, node))
        return findings

    def _match_argument_missing(self, pattern: Pattern, rule: Rule) -> list[Finding]:
        """Detect LLM API calls missing a required argument."""
        target_funcs = set()
        if pattern.function:
            target_funcs.add(pattern.function)
        target_funcs.update(pattern.functions)

        findings: list[Finding] = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = _get_func_name(node.func)
            if not any(func_name.endswith(t) or func_name == t for t in target_funcs):
                continue
            # Check if the required argument is present
            kwarg_names = {kw.arg for kw in node.keywords}
            if pattern.argument and pattern.argument not in kwarg_names:
                findings.append(self._make_finding(rule, node))
        return findings

    def _match_argument_tainted(self, pattern: Pattern, rule: Rule) -> list[Finding]:
        """Detect tainted (user-controlled) values in LLM API arguments."""
        target_funcs = set()
        if pattern.function:
            target_funcs.add(pattern.function)
        target_funcs.update(pattern.functions)
        tainted_sources = frozenset(pattern.tainted_sources) | TAINTED_SOURCES

        findings: list[Finding] = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = _get_func_name(node.func)
            if not any(func_name.endswith(t) or func_name == t for t in target_funcs):
                continue
            # Check all arguments for taint
            all_args: list[ast.expr] = list(node.args)
            all_args.extend(kw.value for kw in node.keywords)
            for arg in all_args:
                if _contains_tainted_string(arg, tainted_sources) or _is_tainted(
                    arg, tainted_sources
                ):
                    findings.append(self._make_finding(rule, node))
                    break
        return findings

    def _match_output_to_sink(self, pattern: Pattern, rule: Rule) -> list[Finding]:
        """Detect LLM output passed to dangerous sinks."""
        sinks = frozenset(pattern.sinks) if pattern.sinks else DANGEROUS_SINKS
        llm_funcs = frozenset(pattern.functions) if pattern.functions else LLM_API_CALLS

        # First pass: collect variables assigned from LLM calls
        llm_vars: set[str] = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    call_name = _get_func_name(node.value.func)
                    if any(call_name.endswith(f) or call_name == f for f in llm_funcs):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                llm_vars.add(target.id)
            elif isinstance(node, ast.AnnAssign) and node.value:
                if isinstance(node.value, ast.Call):
                    call_name = _get_func_name(node.value.func)
                    if any(call_name.endswith(f) or call_name == f for f in llm_funcs):
                        if isinstance(node.target, ast.Name):
                            llm_vars.add(node.target.id)

        # Second pass: find sink calls using LLM-derived variables
        findings: list[Finding] = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            sink_name = _get_func_name(node.func)
            if not any(sink_name.endswith(s) or sink_name == s for s in sinks):
                continue
            all_args: list[ast.expr] = list(node.args)
            all_args.extend(kw.value for kw in node.keywords)
            for arg in all_args:
                if isinstance(arg, ast.Name) and arg.id in llm_vars:
                    findings.append(self._make_finding(rule, node))
                    break
        return findings

    def _match_string_concat_taint(self, pattern: Pattern, rule: Rule) -> list[Finding]:
        """Detect string concatenation of tainted values in LLM API arguments."""
        # This is similar to argument_tainted but more specifically looks for
        # f-strings and concatenations with tainted data in any LLM API call
        return self._match_argument_tainted(pattern, rule)
