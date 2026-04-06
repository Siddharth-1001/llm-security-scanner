"""Python source file parser."""
from __future__ import annotations
from pathlib import Path

from llm_scanner.discovery import Language
from llm_scanner.parsers.base import BaseParser, ParsedFile


class PythonParser(BaseParser):
    def can_parse(self, language: Language) -> bool:
        return language == Language.PYTHON

    def _language(self) -> Language:
        return Language.PYTHON
