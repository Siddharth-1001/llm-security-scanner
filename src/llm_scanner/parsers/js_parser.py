"""JavaScript/TypeScript parser (Phase 1: source text passthrough)."""
from __future__ import annotations
from pathlib import Path

from llm_scanner.discovery import Language
from llm_scanner.parsers.base import BaseParser, ParsedFile


class JSParser(BaseParser):
    """Phase 1 stub — reads source text; AST matching deferred to Phase 2."""

    def can_parse(self, language: Language) -> bool:
        return language in (Language.JAVASCRIPT, Language.TYPESCRIPT)

    def _language(self) -> Language:
        return Language.JAVASCRIPT
