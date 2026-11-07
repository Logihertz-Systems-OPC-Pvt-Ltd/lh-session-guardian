# ==============================================================================
# Product:       lh-session-guardian (lh-session)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for exporters module: Rich table, JSON, and OASIS SARIF v2.1.0."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from lh_session_guardian.exporters import (
    export_json,
    export_sarif,
    render_table_report,
    severity_to_sarif_level,
    severity_to_style,
)
from lh_session_guardian.models import FindingSeverity
from lh_session_guardian.session_analyzer import audit_session_target


def test_severity_mappings() -> None:
    """Test severity to style and SARIF level conversions."""
    assert severity_to_style(FindingSeverity.CRITICAL) == "bold red"
    assert severity_to_style(FindingSeverity.HIGH) == "red"
    assert severity_to_style(FindingSeverity.MEDIUM) == "yellow"
    assert severity_to_style(FindingSeverity.LOW) == "blue"

    assert severity_to_sarif_level(FindingSeverity.CRITICAL) == "error"
    assert severity_to_sarif_level(FindingSeverity.HIGH) == "error"
    assert severity_to_sarif_level(FindingSeverity.MEDIUM) == "warning"
    assert severity_to_sarif_level(FindingSeverity.LOW) == "note"

    assert FindingSeverity.from_string("critical") == FindingSeverity.CRITICAL
    assert FindingSeverity.from_string("unknown") == FindingSeverity.LOW


def test_render_table_clean(sample_clean_yaml: Path) -> None:
    """Test rendering table for a compliant report."""
    report = audit_session_target(sample_clean_yaml)
    console = Console(record=True, width=120)
    render_table_report(report, console=console)
    output = console.export_text()
    assert "Session & JWT Security Posture Compliant" in output
    assert "No session fixation or JWT vulnerabilities" in output


def test_render_table_with_findings(sample_malicious_yaml: Path) -> None:
    """Test rendering table for a report with findings."""
    report = audit_session_target(sample_malicious_yaml)
    console = Console(record=True, width=140)
    render_table_report(report, console=console)
    output = console.export_text()
    assert "lh-session-guardian Report" in output
    assert "LH-SES-001" in output
    assert "Session Audit Summary" in output


def test_export_json(sample_malicious_yaml: Path) -> None:
    """Test JSON export format and structure."""
    report = audit_session_target(sample_malicious_yaml)
    raw_json = export_json(report)
    parsed = json.loads(raw_json)

    assert parsed["schema_version"] == "1.0.0"
    assert parsed["scanner"] == "lh-session-guardian"
    assert parsed["findings_count"] == len(report.findings)
    assert parsed["risk_score"] == report.risk_score
    assert "summary" in parsed
    assert len(parsed["findings"]) > 0

    first_finding = parsed["findings"][0]
    assert "rule_id" in first_finding
    assert "severity" in first_finding
    assert "category" in first_finding
    assert "remediation" in first_finding


def test_export_sarif(sample_malicious_yaml: Path) -> None:
    """Test OASIS SARIF v2.1.0 export format and schema compliance."""
    report = audit_session_target(sample_malicious_yaml)
    raw_sarif = export_sarif(report)
    parsed = json.loads(raw_sarif)

    assert parsed["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in parsed["$schema"]
    assert len(parsed["runs"]) == 1

    run = parsed["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "lh-session-guardian"
    assert len(driver["rules"]) == 10

    results = run["results"]
    assert len(results) == len(report.findings)
    assert results[0]["ruleId"].startswith("LH-SES-")
    assert results[0]["level"] in ["error", "warning", "note"]
    assert "physicalLocation" in results[0]["locations"][0]
