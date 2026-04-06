# Contributing to LLM Security Scanner

Thank you for your interest in contributing! This guide covers everything you need to get started.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Be respectful, inclusive, and constructive.

## Getting Started

### Development Environment Setup

```bash
git clone https://github.com/llm-security-scanner/llm-security-scanner.git
cd llm-security-scanner

python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

pip install -e ".[dev,test]"
pre-commit install
pytest  # verify setup
```

### Project Structure

| Path | Description |
|------|-------------|
| `src/llm_scanner/` | Core scanner code |
| `src/llm_scanner/rules/` | Rule engine, matchers, and models |
| `src/llm_scanner/findings/` | Finding models and suppression |
| `src/llm_scanner/formatters/` | Text, JSON, SARIF output |
| `src/llm_scanner/parsers/` | Language-specific AST parsers |
| `rules/builtin/` | Built-in detection rules (YAML) |
| `tests/` | Unit, integration tests, and fixtures |
| `docs/` | Documentation source |
| `.github/` | CI workflows and issue templates |

## Types of Contributions

### Writing Detection Rules (Most Needed!)

1. Create a YAML rule file in `rules/builtin/<LLMxx_category>/`
2. Follow the schema in `rules/schema.yaml`
3. Add fixture files in `tests/fixtures/python/vulnerable/` and `tests/fixtures/python/clean/`
4. Write a test in `tests/unit/test_rule_engine.py` or `tests/integration/`

**Rule checklist:**
- [ ] Rule YAML validates against `rules/schema.yaml`
- [ ] Vulnerable fixture triggers the rule
- [ ] Clean fixture does NOT trigger the rule
- [ ] Mapped to OWASP LLM Top 10 category and CWE
- [ ] Description explains the risk; remediation gives actionable fix

### Bug Fixes

1. Open an issue describing the bug with reproduction steps
2. Reference the issue in your PR: `fix: resolve false positive in LLM01-003 (#42)`
3. Include a test case that reproduces and verifies the fix

### Feature Development

Discuss large features in a GitHub Issue before starting. Include tests and documentation.

## Development Workflow

### Branching

| Branch | Purpose |
|--------|---------|
| `main` | Stable, release-ready |
| `feature/*` | New features and rules |
| `fix/*` | Bug fixes |
| `docs/*` | Documentation changes |

### Commit Convention (Conventional Commits)

```
feat: add LLM02-005 detection rule for innerHTML sink
fix: resolve false positive in Python f-string detection
docs: add remediation guide for LLM06 rules
test: add fixture for LangChain agent detection
chore: update tree-sitter dependency to v0.22
```

### Pull Request Process

1. Fork and create a feature branch from `main`
2. Write code, tests, and docs
3. Ensure CI passes: `ruff check .` + `mypy src/` + `pytest`
4. Fill out the PR template and request review
5. Address feedback; maintainer merges via squash merge

## Code Standards

| Area | Tool | Standard |
|------|------|---------|
| Formatting | `ruff format` | 88 char line length |
| Linting | `ruff check` | All rules except E501 |
| Type Checking | `mypy --strict` | Full strict mode |
| Testing | `pytest` | 80%+ coverage |
| Docstrings | Google style | All public APIs |

## Security Vulnerability Reporting

**DO NOT** open a public GitHub issue for security vulnerabilities in the scanner itself.

See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

MIT License. By contributing, you agree your contributions will be licensed under the same license.
