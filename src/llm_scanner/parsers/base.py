"""Abstract parser interface."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from llm_scanner.discovery import Language


@dataclass
class ParsedFile:
    path: Path
    language: Language
    source: str


class BaseParser:
    """Abstract base for language parsers."""

    def can_parse(self, language: Language) -> bool:
        raise NotImplementedError

    def parse(self, path: Path) -> ParsedFile | None:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            return ParsedFile(path=path, language=self._language(), source=source)
        except OSError:
            return None

    def _language(self) -> Language:
        raise NotImplementedError
