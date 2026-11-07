# ==============================================================================
# Product:       lh-session-guardian (lh-session)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Integration tests for lh-session-guardian CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_session_guardian import __version__
from lh_session_guardian.cli import app

runner = CliRunner()
TEST_ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_version() -> None:
    """Test --version option."""
    result = runner.invoke(app, ["--version"], env=TEST_ENV)
    assert result.exit_code == 0
    assert f"lh-session-guardian v{__version__}" in result.output


def test_cli_rules() -> None:
    """Test rules command output."""
    result = runner.invoke(app, ["rules"], env=TEST_ENV)
    assert result.exit_code == 0
    assert "lh-session-guardian Rule Catalog" in result.output
    assert "LH-SES-001" in result.output
    assert "LH-SES-010" in result.output


def test_cli_scan_clean(sample_clean_yaml: Path) -> None:
    """Test scan command on compliant target exits 0."""
    result = runner.invoke(app, ["scan", str(sample_clean_yaml)], env=TEST_ENV)
    assert result.exit_code == 0
    assert "Session & JWT Security Posture Compliant" in result.output


def test_cli_scan_malicious_fails(sample_malicious_yaml: Path) -> None:
    """Test scan command on insecure target exits 1 due to high/critical findings."""
    result = runner.invoke(app, ["scan", str(sample_malicious_yaml)], env=TEST_ENV)
    assert result.exit_code == 1
    assert "lh-session-guardian Report" in result.output
    assert "LH-SES-001" in result.output


def test_cli_scan_min_severity_filter(sample_malicious_yaml: Path) -> None:
    """Test scan with --min-severity critical filters out lower severity findings."""
    result = runner.invoke(
        app,
        ["scan", str(sample_malicious_yaml), "--min-severity", "critical", "--format", "json"],
        env=TEST_ENV,
    )
    assert result.exit_code == 1
    parsed = json.loads(result.output)
    severities = {f["severity"] for f in parsed["findings"]}
    assert severities == {"CRITICAL"}


def test_cli_scan_json_format(sample_malicious_yaml: Path) -> None:
    """Test scan with --format json."""
    result = runner.invoke(
        app,
        ["scan", str(sample_malicious_yaml), "--format", "json"],
        env=TEST_ENV,
    )
    assert result.exit_code == 1
    parsed = json.loads(result.output)
    assert parsed["scanner"] == "lh-session-guardian"
    assert "findings" in parsed


def test_cli_scan_sarif_format(sample_malicious_yaml: Path) -> None:
    """Test scan with --format sarif."""
    result = runner.invoke(
        app,
        ["scan", str(sample_malicious_yaml), "--format", "sarif"],
        env=TEST_ENV,
    )
    assert result.exit_code == 1
    parsed = json.loads(result.output)
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["tool"]["driver"]["name"] == "lh-session-guardian"


def test_cli_scan_output_files(sample_malicious_yaml: Path, tmp_path: Path) -> None:
    """Test scan with --output writing to json, table, and sarif files."""
    # JSON output file
    json_file = tmp_path / "report.json"
    res_json = runner.invoke(
        app,
        ["scan", str(sample_malicious_yaml), "--format", "json", "--output", str(json_file)],
        env=TEST_ENV,
    )
    assert res_json.exit_code == 1
    assert json_file.exists()
    parsed_json = json.loads(json_file.read_text(encoding="utf-8"))
    assert parsed_json["scanner"] == "lh-session-guardian"

    # Table output file
    table_file = tmp_path / "report.txt"
    res_table = runner.invoke(
        app,
        ["scan", str(sample_malicious_yaml), "--format", "table", "--output", str(table_file)],
        env=TEST_ENV,
    )
    assert res_table.exit_code == 1
    assert table_file.exists()
    assert "lh-session-guardian Report" in table_file.read_text(encoding="utf-8")

    # SARIF output file
    sarif_file = tmp_path / "report.sarif"
    res_sarif = runner.invoke(
        app,
        ["scan", str(sample_malicious_yaml), "--format", "sarif", "--output", str(sarif_file)],
        env=TEST_ENV,
    )
    assert res_sarif.exit_code == 1
    assert sarif_file.exists()
    parsed_sarif = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert parsed_sarif["version"] == "2.1.0"
