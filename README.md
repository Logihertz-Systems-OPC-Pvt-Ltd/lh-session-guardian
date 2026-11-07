# lh-session-guardian

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-session-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-session-guardian/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise jwt token policy & session cookie auditor developed by **Logihertz Systems (OPC) Private Limited**.

Audits OAuth2/OIDC JWT configurations, token payloads, and HTTP Set-Cookie policies for alg: none bypasses, weak HMAC signing keys, missing exp/aud/iss claims, and absent HttpOnly, Secure, or SameSite flags.

---

## Key Features

- **JWT Cryptographic Verification**: Flags `alg: none`, weak HMAC signing keys, and symmetric/asymmetric algorithm confusion vulnerabilities.
- **Cookie Security Attribute Auditing**: Verifies that session cookies enforce `HttpOnly`, `Secure`, and `SameSite=Lax|Strict` attributes.
- **Header Injection & Traversal Defense**: Detects dangerous JWT header parameters (`jku`, `x5u`, `kid`) vulnerable to directory traversal or SSRF.
- **Session Lifecycle Governance**: Flags missing token expiration (`exp`), excessive session TTLs, and missing refresh token rotation.
- **Multi-Format Reporting**: Outputs rich terminal tables, structured JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-SES-001` | `CRITICAL` | Insecure JWT Algorithm (`alg: none` or Symmetric/Asymmetric confusion risk) |
| `LH-SES-002` | `CRITICAL` | Weak, Default, or Hardcoded JWT HMAC Signing Secret (< 256-bit or dictionary word) |
| `LH-SES-003` | `HIGH` | Missing or Unenforced JWT Expiration (`exp`) or Excessive Session Lifetime (> 24h) |
| `LH-SES-004` | `HIGH` | Missing Cookie `HttpOnly` or `Secure` Flag on authenticated session cookie |
| `LH-SES-005` | `HIGH` | Missing or Unsafe Cookie `SameSite` Attribute (SameSite=None without Secure) |
| `LH-SES-006` | `HIGH` | Session Fixation Vulnerability or Missing Session ID Regeneration on privilege change |
| `LH-SES-007` | `HIGH` | Dangerous JWT Header Injection (`jku`, `x5u`, or `kid` path traversal vector) |
| `LH-SES-008` | `MEDIUM` | Missing JWT Audience (`aud`), Issuer (`iss`), or Replay Token ID (`jti`) |
| `LH-SES-009` | `HIGH` | Missing Refresh Token Rotation or Revocation Blacklist mechanism |
| `LH-SES-010` | `LOW` | Sensitive PII/Credentials in JWT Payload or Missing `__Host-` cookie prefix |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-session-guardian.git
cd lh-session-guardian

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-session` (also accessible via `lh-session`, `lh-session-guardian`).

```bash
# Scan a JWT token string or token file
lh-session scan token.jwt

# Audit web server session cookie configurations
lh-session scan session-config.yaml --format json

# Export findings to OASIS SARIF v2.1.0
lh-session scan ./auth-configs/ --format sarif --output session-results.sarif

# List all session guardian detection rules
lh-session rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
