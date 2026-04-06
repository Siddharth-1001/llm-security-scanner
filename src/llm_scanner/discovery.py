"""File discovery: walk a directory tree, detect languages, apply exclusions."""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import pathspec


class Language(str, Enum):
    """Programming languages recognised by the scanner."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    UNKNOWN = "unknown"


# Map file extensions → Language (lower-cased, with leading dot).
_EXT_MAP: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
}


def _detect_language(path: Path) -> Language:
    return _EXT_MAP.get(path.suffix.lower(), Language.UNKNOWN)


@dataclass(frozen=True, slots=True)
class SourceFile:
    """A source file discovered during directory traversal."""

    path: Path
    language: Language
    size_bytes: int


def discover_files(
    root: Path,
    exclude_globs: list[str] | None = None,
) -> list[SourceFile]:
    """Recursively discover source files under *root*, applying exclusions.

    Parameters
    ----------
    root:
        Directory (or single file) to scan.
    exclude_globs:
        List of gitignore-style glob patterns.  Paths matching any of these
        patterns are skipped.  Patterns are evaluated relative to *root*.

    Returns
    -------
    list[SourceFile]
        Discovered files sorted by path, with ``Language.UNKNOWN`` entries
        filtered out (they carry no scannable content).
    """
    root = root.resolve()

    spec = pathspec.PathSpec.from_lines("gitwildmatch", exclude_globs or [])

    results: list[SourceFile] = []

    if root.is_file():
        lang = _detect_language(root)
        if lang is not Language.UNKNOWN:
            results.append(
                SourceFile(path=root, language=lang, size_bytes=root.stat().st_size)
            )
        return results

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dir_rel = Path(dirpath).relative_to(root)

        # Prune excluded directories in-place so os.walk won't descend.
        dirnames[:] = [
            d
            for d in dirnames
            if not spec.match_file(str(dir_rel / d) + "/")
            and not spec.match_file(str(dir_rel / d))
        ]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            rel_path = file_path.relative_to(root)

            if spec.match_file(str(rel_path)):
                continue

            lang = _detect_language(file_path)
            if lang is Language.UNKNOWN:
                continue

            try:
                size = file_path.stat().st_size
            except OSError:
                # Skip files we can't stat (e.g. broken symlinks).
                continue

            results.append(SourceFile(path=file_path, language=lang, size_bytes=size))

    results.sort(key=lambda sf: sf.path)
    return results
