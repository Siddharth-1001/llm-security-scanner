from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def order(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    def __lt__(self, other: Severity) -> bool:
        return self.order < other.order


@dataclass
class CodeSnippet:
    lines: list[str]
    start_line: int  # 1-based

    def __str__(self) -> str:
        return "\n".join(
            f"{self.start_line + i:4d} | {line}" for i, line in enumerate(self.lines)
        )


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    owasp_category: str  # e.g. "LLM01"
    cwe: str  # e.g. "CWE-77"
    severity: Severity
    file_path: Path
    line: int  # 1-based
    col: int  # 1-based
    snippet: CodeSnippet
    description: str
    remediation: str
    suppressed: bool = False
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "owasp_category": self.owasp_category,
            "cwe": self.cwe,
            "severity": self.severity.value,
            "file_path": str(self.file_path),
            "line": self.line,
            "col": self.col,
            "snippet": {
                "lines": self.snippet.lines,
                "start_line": self.snippet.start_line,
            },
            "description": self.description,
            "remediation": self.remediation,
            "suppressed": self.suppressed,
            "tags": self.tags,
        }
