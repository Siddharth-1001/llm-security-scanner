"""Tests for file discovery."""

from pathlib import Path

import pytest

from llm_scanner.discovery import Language, discover_files


def test_discovers_python_files(tmp_path):
    (tmp_path / "a.py").write_text("print('hello')")
    (tmp_path / "b.py").write_text("x = 1")
    files = discover_files(tmp_path, [])
    paths = [f.path.name for f in files]
    assert "a.py" in paths
    assert "b.py" in paths


def test_detects_language_correctly(tmp_path):
    (tmp_path / "a.py").write_text("")
    (tmp_path / "b.js").write_text("")
    (tmp_path / "c.ts").write_text("")
    (tmp_path / "d.tsx").write_text("")
    files = {f.path.name: f for f in discover_files(tmp_path, [])}
    assert files["a.py"].language == Language.PYTHON
    assert files["b.js"].language == Language.JAVASCRIPT
    assert files["c.ts"].language == Language.TYPESCRIPT
    assert files["d.tsx"].language == Language.TYPESCRIPT


def test_excludes_node_modules(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.py").write_text("x=1")
    (tmp_path / "main.py").write_text("x=1")
    files = discover_files(tmp_path, ["**/node_modules/**"])
    names = [f.path.name for f in files]
    assert "main.py" in names
    assert "lib.py" not in names


def test_single_file_target(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("x = 1")
    files = discover_files(f, [])
    assert len(files) == 1
    assert files[0].language == Language.PYTHON


def test_excludes_git_directory(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("x=1")
    (tmp_path / "app.py").write_text("x=1")
    files = discover_files(tmp_path, ["**/.git/**"])
    assert all(f.path.name == "app.py" for f in files)


def test_empty_directory_returns_empty(tmp_path):
    files = discover_files(tmp_path, [])
    assert files == []


def test_unknown_extension_excluded(tmp_path):
    (tmp_path / "notes.txt").write_text("some notes")
    (tmp_path / "app.py").write_text("x = 1")
    files = discover_files(tmp_path, [])
    names = [f.path.name for f in files]
    assert "notes.txt" not in names
    assert "app.py" in names


def test_source_file_has_size(tmp_path):
    content = "x = 1\n"
    f = tmp_path / "app.py"
    f.write_text(content)
    files = discover_files(tmp_path, [])
    assert files[0].size_bytes == len(content.encode())


def test_source_file_is_frozen(tmp_path):
    (tmp_path / "app.py").write_text("")
    files = discover_files(tmp_path, [])
    sf = files[0]
    with pytest.raises((AttributeError, TypeError)):
        sf.path = Path("other.py")  # type: ignore


def test_nested_directories_discovered(tmp_path):
    subdir = tmp_path / "sub"
    subdir.mkdir()
    (subdir / "nested.py").write_text("x = 1")
    (tmp_path / "top.py").write_text("y = 2")
    files = discover_files(tmp_path, [])
    names = [f.path.name for f in files]
    assert "nested.py" in names
    assert "top.py" in names


def test_mjs_detected_as_javascript(tmp_path):
    (tmp_path / "module.mjs").write_text("export default {}")
    files = discover_files(tmp_path, [])
    assert any(f.language == Language.JAVASCRIPT for f in files)


def test_cjs_detected_as_javascript(tmp_path):
    (tmp_path / "module.cjs").write_text("module.exports = {}")
    files = discover_files(tmp_path, [])
    assert any(f.language == Language.JAVASCRIPT for f in files)
