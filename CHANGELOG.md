# Changelog

All notable changes to `lh-session-guardian` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-07

### Added
- **Initial Release**: Production-ready clean-room release of `lh-session-guardian` developed by **Logihertz Systems (OPC) Private Limited**.
- **Core Parser Capabilities**: Ingestion and offline static evaluation of JWT token strings, OAuth2/OIDC metadata (`.json`), web server configurations, and session manifests (`.yaml`).
- **Security Rule Registry**: Complete 10-rule detection catalog spanning `LH-SES-001` through `LH-SES-010`.
- **Reporting Engine**: Multi-format exporters including colorized Rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0 for GitHub Code Scanning integration.
- **Command-Line Interface**: Executable entrypoints (`lh-session`, `lh-session-guardian`) supporting `--format`, `--output`, `--min-severity`, and `--fail-on` flags.
- **Zero-Daemon Architecture**: Pure Python 3.11+ clean-room implementation with zero background daemons, zero external database requirements, and zero outbound network telemetry.
