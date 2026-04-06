# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-06

### Added
- **7 new detection rules** (21 total):
  - LLM01-003: RAG context injection (indirect prompt injection via poisoned retrieval)
  - LLM02-005: LLM output passed to unsafe deserialization (pickle, yaml.load)
  - LLM05-001: Unverified model loading (torch.load, pickle-based models)
  - LLM05-002: trust_remote_code=True in model loading
  - LLM06-004: Hardcoded API keys for LLM providers
  - LLM08-004: Unrestricted tool use in agentic frameworks
  - LLM10-001: Missing rate limiting on LLM-facing endpoints
- `import_check` pattern type now fully implemented
- Taint propagation through variable assignments
- Expanded taint sources for 2025/2026 agentic patterns (tool_input, rag_context, etc.)
- Expanded LLM API function recognition (responses.create, llm.invoke, chain.invoke)
- Expanded dangerous sinks (pickle.loads, yaml.load, __import__, shutil.rmtree)
- SECURITY.md for responsible vulnerability disclosure
- CHANGELOG.md
- GitHub Actions CI/CD workflow
- Pre-commit configuration (.pre-commit-config.yaml)
- py.typed marker for PEP 561 compliance
- .editorconfig for consistent formatting across editors
- Comprehensive .gitignore

### Fixed
- **License mismatch**: LICENSE file (MIT) now matches pyproject.toml and README
- **Suppression logic bug**: `None` return from dict.get() was ambiguous with "suppress all" sentinel
- **Deprecated pathspec API**: Migrated from `gitwildmatch` to `gitignore` pattern factory
- **Silent scan failures**: Rule matching errors now logged as warnings and collected in `result.errors`
- **Fragile rules path**: BUILTIN_RULES_DIR now uses importlib.resources with fallback
- **Syntax error handling**: Files with syntax errors are properly skipped with error tracking
- **Duplicate rule detection**: Engine now warns and skips duplicate rule IDs
- **Rule validation**: Missing required fields in YAML rules are caught and reported

### Changed
- Version bumped to 0.2.0 (Beta status)
- Scanner errors now displayed in CLI output (up to 10 warnings shown)
- Rule engine validates required fields before creating Rule objects
- Python classifier updated to include 3.13

## [0.1.0] - 2026-03-01

### Added
- Initial release with 15 built-in detection rules
- OWASP LLM Top 10 categories: LLM01, LLM02, LLM04, LLM06, LLM08
- Python AST-based pattern matching
- CLI with scan, init, version commands
- Text, JSON, and SARIF output formats
- Inline suppression comments (`# llm-scan:ignore`)
- Config file support (.llm-scanner.yml)
- GitHub Actions SARIF integration
