# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

If you discover a security vulnerability in llm-security-scanner, please report it responsibly:

1. **Email**: Send details to **security@llm-security-scanner.dev** (or open a [GitHub Security Advisory](https://github.com/llm-security-scanner/llm-security-scanner/security/advisories/new))
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. **Response time**: We aim to acknowledge within **48 hours** and provide a fix within **7 days** for critical issues.

## What Qualifies

- Vulnerabilities in the scanner itself (e.g., YAML parsing, path traversal in file discovery)
- Bypasses that allow malicious code to evade detection
- Rule logic flaws that produce dangerous false negatives
- Dependency vulnerabilities with exploitable impact

## What Does NOT Qualify

- Detection rule gaps (missing patterns) — please open a regular issue
- Performance issues
- Cosmetic bugs in output formatting

## Disclosure Policy

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We will credit reporters in the release notes unless anonymity is requested.
