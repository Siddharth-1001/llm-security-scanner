# LLM Security Scanner

> Static analysis tool for detecting [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-llm-applications/) vulnerabilities in LLM-integrated applications.

[![CI](https://github.com/<org>/llm-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/<org>/llm-security-scanner/actions)
[![PyPI](https://img.shields.io/pypi/v/llm-security-scanner)](https://pypi.org/project/llm-security-scanner/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)

**llm-scan** detects security vulnerabilities in codebases that integrate Large Language Models — prompt injection, insecure output handling, sensitive data exposure, excessive agency, and more.

## Installation

```bash
pip install llm-security-scanner
```

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
```

## What It Detects

| OWASP Category | Description | Severity |
|---|---|---|
| LLM01: Prompt Injection | User input directly in system prompts, LangChain template injection | Critical |
| LLM02: Insecure Output | LLM output passed to eval(), exec(), subprocess, SQL, HTML | Critical |
| LLM04: Model DoS | Missing max_tokens, missing timeouts on LLM API calls | High |
| LLM06: Sensitive Info | PII/secrets in prompts, system prompt exposure | Critical/High |
| LLM08: Excessive Agency | Unrestricted exec/file/subprocess access in agent tools | Critical |

**15 built-in rules** covering 5 OWASP LLM categories. More rules added each release.

## GitHub Actions Integration

```yaml
# .github/workflows/security.yml
- name: LLM Security Scan
  run: |
    pip install llm-security-scanner
    llm-scan scan . --format sarif --output llm-scan.sarif --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: llm-scan.sarif
```

## Configuration

Create `.llm-scanner.yml` in your project root (or run `llm-scan init`):

```yaml
severity_threshold: high
output_format: text
exclude:
  - "**/node_modules/**"
  - "**/.venv/**"
  - "**/tests/fixtures/**"
# disable_rules:
#   - LLM04-003
```

## Suppressing False Positives

```python
# Suppress all rules on this line
response = openai_client.chat.completions.create(...)  # llm-scan:ignore

# Suppress a specific rule
response = openai_client.chat.completions.create(...)  # llm-scan:ignore[LLM04-001]
```

## Writing Custom Rules

Create a YAML file in any directory and pass it with `--rules-dir`:

```yaml
# my-rules/custom-001.yaml
id: CUSTOM-001
name: my-custom-pattern
category: LLM01
severity: high
cwe: CWE-77
languages: [python]
description: Custom detection rule
remediation: How to fix it
patterns:
  - type: function_call
    function: my_llm_wrapper
```

```bash
llm-scan scan . --rules-dir ./my-rules
```

## CLI Reference

```
llm-scan scan [OPTIONS] [TARGET]

Options:
  -f, --format [text|json|sarif]    Output format (default: text)
  -s, --severity LEVEL              Minimum severity to report (default: low)
  -c, --config PATH                 Config file path
  --rules-dir PATH                  Additional rules directory (repeatable)
  --exclude PATTERN                 Glob exclusion pattern (repeatable)
  --fail-on LEVEL                   Exit 1 if findings >= this severity
  -o, --output PATH                 Write results to file
  -q, --quiet                       Suppress banner and summary
  --rule RULE_ID                    Enable only specific rules (repeatable)
  --disable-rule RULE_ID            Disable specific rules (repeatable)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, rule authoring guide, and PR process.

## License

[Apache 2.0](LICENSE) — © LLM Security Scanner Contributors
