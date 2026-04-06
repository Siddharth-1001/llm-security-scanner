# LLM Security Scanner

> **Static analysis tool for detecting [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-llm-applications/) vulnerabilities in LLM-integrated applications.**

[![CI](https://github.com/llm-security-scanner/llm-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/llm-security-scanner/llm-security-scanner/actions)
[![PyPI](https://img.shields.io/pypi/v/llm-security-scanner)](https://pypi.org/project/llm-security-scanner/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)

---

As LLMs power 95% of software in 2026 — from code assistants to autonomous agents — **security gaps in LLM integrations are the #1 attack surface**. Prompt injection, insecure output handling, supply chain poisoning, and unrestricted agent tools are no longer theoretical risks.

**llm-scan** is a zero-dependency SAST tool that catches these vulnerabilities before they reach production. It runs in your CI pipeline, your editor, and your terminal — with 21 built-in rules mapping directly to the OWASP LLM Top 10.

## Why llm-scan?

- **Purpose-built for LLM code**: Not a generic linter — every rule targets real LLM attack vectors
- **Zero config to start**: `pip install llm-security-scanner && llm-scan scan .`
- **CI-native**: SARIF output plugs directly into GitHub Code Scanning
- **Extensible**: Write custom YAML rules in minutes — no code required
- **Fast**: Pure Python AST analysis, no external services, no API keys needed
- **2026-ready**: Covers agentic AI, RAG poisoning, tool-use injection, supply chain attacks

## Installation

```bash
pip install llm-security-scanner
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uvx llm-scan scan .
```

### Requirements

- Python 3.10+
- No runtime dependencies on LLM providers or external services

## Quick Start

```bash
# Scan current directory
llm-scan scan .

# Scan with JSON output
llm-scan scan ./my-project --format json

# Export SARIF for GitHub Code Scanning
llm-scan scan ./my-project --format sarif --output results.sarif

# Fail CI on high+ severity findings
llm-scan scan . --fail-on high

# Only show critical findings
llm-scan scan . --severity critical

# Scan a single file
llm-scan scan src/agents/chat.py
```

## What It Detects

### 21 Built-in Rules across 8 OWASP LLM Categories

| OWASP Category | Rules | What It Catches | Severity |
|---|---|---|---|
| **LLM01: Prompt Injection** | 3 | User input in system prompts, LangChain template injection, RAG context injection | Critical/High |
| **LLM02: Insecure Output** | 5 | LLM output → `eval()`, `exec()`, subprocess, SQL, HTML, deserialization | Critical |
| **LLM04: Model DoS** | 3 | Missing `max_tokens`, missing timeouts on LLM API calls | High/Medium |
| **LLM05: Supply Chain** | 2 | `torch.load`/`pickle.load` model loading, `trust_remote_code=True` | Critical/High |
| **LLM06: Sensitive Info** | 4 | PII/secrets in prompts, system prompt exposure, hardcoded API keys | Critical/High |
| **LLM08: Excessive Agency** | 4 | Unrestricted exec/file/subprocess in tools, unscoped agent tools | Critical/High |
| **LLM10: Unbounded Consumption** | 1 | Missing rate limiting on LLM-facing endpoints | High |

> **New in 0.2.0**: RAG injection, deserialization sinks, supply chain rules, agentic tool-use detection, hardcoded API keys.

### Example Detection

```python
# ❌ LLM01-001: User input in system prompt (CRITICAL)
system_prompt = f"You are a helpful assistant. User said: {user_message}"

# ❌ LLM02-001: LLM output passed to eval (CRITICAL)
code = client.chat.completions.create(...)
eval(code)

# ❌ LLM05-002: trust_remote_code enables RCE (CRITICAL)
model = AutoModel.from_pretrained("user/model", trust_remote_code=True)

# ❌ LLM08-004: Unrestricted agent tools (CRITICAL)
agent = AgentExecutor(agent=react_agent, tools=[exec_tool, file_tool])

# ✅ Safe: User input only in user role
messages = [
    {"role": "system", "content": STATIC_SYSTEM_PROMPT},
    {"role": "user", "content": user_input},
]
response = client.chat.completions.create(
    model="gpt-4o",
    messages=messages,
    max_tokens=1000,
)
```

## GitHub Actions Integration

```yaml
# .github/workflows/security.yml
name: LLM Security Scan
on: [push, pull_request]

permissions:
  security-events: write

jobs:
  llm-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install scanner
        run: pip install llm-security-scanner

      - name: Run LLM security scan
        run: llm-scan scan . --format sarif --output llm-scan.sarif --fail-on high

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: llm-scan.sarif
```

## Configuration

Create `.llm-scanner.yml` in your project root (or run `llm-scan init`):

```yaml
# .llm-scanner.yml
severity_threshold: high          # Minimum severity to report
output_format: text               # text | json | sarif

exclude:
  - "**/node_modules/**"
  - "**/.venv/**"
  - "**/tests/fixtures/**"
  - "**/migrations/**"

# disable_rules:
#   - LLM04-003                   # We handle timeouts at infra level

# custom_rules_dirs:
#   - ./security-rules             # Your team's custom rules
```

Config resolution order (later wins):
1. Built-in defaults
2. `.llm-scanner.yml` (auto-discovered by walking up from target)
3. CLI flags

## Suppressing Findings

```python
# Suppress all rules on this line
response = client.chat.completions.create(...)  # llm-scan:ignore

# Suppress a specific rule
response = client.chat.completions.create(...)  # llm-scan:ignore[LLM04-001]

# Suppress multiple rules
eval(sanitized_code)  # llm-scan:ignore[LLM02-001,LLM08-001]
```

## Writing Custom Rules

Create a YAML file following the [rule schema](rules/schema.yaml):

```yaml
# my-rules/CUSTOM-001.yaml
id: CUSTOM-001
name: unsafe-llm-wrapper
category: LLM01
severity: high
cwe: CWE-77
languages: [python]
description: >
  Our internal llm_wrapper() accepts raw user input without sanitization.
remediation: >
  Use the sanitized_llm_call() wrapper instead.
patterns:
  - type: function_call
    functions:
      - llm_wrapper
      - unsafe_chat
```

```bash
llm-scan scan . --rules-dir ./my-rules
```

### Pattern Types

| Type | Purpose | Key Fields |
|------|---------|------------|
| `function_call` | Flag calls to specific functions | `functions` |
| `argument_missing` | Flag missing required args (e.g., `max_tokens`) | `functions`, `argument` |
| `argument_tainted` | Flag user-controlled input in function args | `functions`, `tainted_sources` |
| `output_to_sink` | Flag LLM output flowing to dangerous functions | `functions`, `sinks` |
| `string_concat_taint` | Flag tainted string building in LLM calls | `functions`, `tainted_sources` |
| `import_check` | Flag imports of dangerous modules | `module` |

## CLI Reference

```
Usage: llm-scan [OPTIONS] COMMAND [ARGS]...

Commands:
  scan     Scan TARGET for LLM security vulnerabilities
  init     Generate a default .llm-scanner.yml
  version  Print version and exit

Scan Options:
  TARGET                            Directory or file to scan (default: .)
  -f, --format [text|json|sarif]    Output format (default: text)
  -s, --severity LEVEL              Minimum severity to report
  -c, --config PATH                 Config file path
  --rules-dir PATH                  Additional rules directory (repeatable)
  --exclude PATTERN                 Glob exclusion pattern (repeatable)
  --fail-on LEVEL                   Exit 1 if findings >= severity (or "never")
  -o, --output PATH                 Write results to file
  -q, --quiet                       Suppress banner and summary
  --no-progress                     Suppress progress output
  --rule RULE_ID                    Enable only these rules (repeatable)
  --disable-rule RULE_ID            Disable specific rules (repeatable)
  -h, --help                        Show help
```

## Architecture

```
┌─────────┐     ┌──────────┐     ┌───────────┐
│   CLI   │────▶│  Config   │────▶│ Discovery │
└─────────┘     └──────────┘     └───────────┘
                                       │
                                       ▼
┌──────────┐    ┌──────────┐     ┌───────────┐
│Formatters│◀───│ Findings │◀────│  Scanner  │
│text/json/│    │& Suppress│     │ + Matcher │
│  sarif   │    └──────────┘     └───────────┘
└──────────┘                          │
                                      ▼
                                ┌───────────┐
                                │Rule Engine│
                                │  (YAML)   │
                                └───────────┘
```

## Roadmap

- [ ] JavaScript/TypeScript support (tree-sitter based)
- [ ] Multi-file taint tracking (inter-procedural analysis)
- [ ] MCP server configuration scanning
- [ ] LangGraph/CrewAI/AutoGen framework-specific rules
- [ ] IDE extensions (VS Code, JetBrains)
- [ ] `--fix` mode for auto-remediation suggestions
- [ ] Pre-commit hook integration
- [ ] API mode for CI/CD platform integrations

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, rule authoring guide, and PR process.

**Most needed contributions:**
1. New detection rules (especially for LLM03, LLM07, LLM09 categories)
2. JavaScript/TypeScript parser implementation
3. False positive/negative reports with reproducible examples
4. Framework-specific rules (LangChain, LlamaIndex, Haystack, etc.)

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines.

## License

[MIT](LICENSE) — © 2026 Siddharth Bhalsod & LLM Security Scanner Contributors
