from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

PatternType = Literal[
    "function_call",
    "argument_missing",
    "argument_tainted",
    "string_concat_taint",
    "output_to_sink",
    "import_check",
]


@dataclass
class Pattern:
    type: PatternType
    # function_call / output_to_sink
    function: str | None = None
    functions: list[str] = field(default_factory=list)
    # argument_missing: flag if this arg is absent
    argument: str | None = None
    # argument_tainted: check if arg value comes from tainted sources
    tainted_sources: list[str] = field(default_factory=list)
    # output_to_sink: sink function names
    sinks: list[str] = field(default_factory=list)
    # import_check: module to flag if imported with certain usage
    module: str | None = None
    # extra raw pattern data for extensibility
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Rule:
    id: str
    name: str
    category: str  # "LLM01"–"LLM10"
    severity: str  # "critical"/"high"/"medium"/"low"/"info"
    cwe: str  # "CWE-77"
    languages: list[str]  # ["python"], ["javascript"], ["python","javascript"]
    patterns: list[Pattern]
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    enabled: bool = True
