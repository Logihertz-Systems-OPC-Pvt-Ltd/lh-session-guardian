# ==============================================================================
# Product:       lh-session-guardian (lh-session)
# Module:        tests.test_session_analyzer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for session_analyzer module and detection rules (LH-SES-001 through LH-SES-010)."""

from __future__ import annotations

from pathlib import Path

from lh_session_guardian.models import (
    AuditFinding,
    CookieConfig,
    FindingSeverity,
    RawJwtToken,
    TokenPolicy,
)
from lh_session_guardian.session_analyzer import (
    SessionAnalyzer,
    audit_session_target,
    calculate_risk_score,
)


def test_clean_target_produces_no_findings(sample_clean_yaml: Path) -> None:
    """Test that a strictly configured session policy produces 0 findings."""
    report = audit_session_target(sample_clean_yaml)
    assert report.findings_count == 0
    assert len(report.findings) == 0
    assert report.risk_score == 0
    assert report.policies_analyzed == 1
    assert report.cookies_analyzed == 1
    # --------------------------------------------------------------------------
    # --- Rule LH-SES-001 (CRITICAL):
    #     Insecure JWT Algorithm ('alg: none' or Confusion Risk)
    # ---
    # Evaluates security posture against insecure jwt algorithm ('alg: none' or
    # confusion risk).
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ses_001_insecure_algorithms() -> None:
    """Test LH-SES-001: none algorithm in token or key confusion in policy."""
    # 1. Token with alg: none
    tok = RawJwtToken(token_id="tok-none", header={"alg": "none"}, payload={"sub": "user"})
    analyzer1 = SessionAnalyzer([], [tok], [])
    findings1 = analyzer1._check_lh_ses_001()
    assert len(findings1) == 1
    assert findings1[0].rule_id == "LH-SES-001"
    assert findings1[0].severity == FindingSeverity.CRITICAL

    # 2. Policy mixing HS256 and RS256
    pol = TokenPolicy(
        policy_id="p-01",
        name="Key Confusion Policy",
        target_service="auth",
        allowed_algorithms=["HS256", "RS256"],
    )
    analyzer2 = SessionAnalyzer([pol], [], [])
    findings2 = analyzer2._check_lh_ses_001()
    assert len(findings2) == 1
    assert findings2[0].rule_id == "LH-SES-001"
    # --------------------------------------------------------------------------
    # --- Rule LH-SES-002 (CRITICAL):
    #     Weak, Default, or Hardcoded JWT HMAC Signing Secret
    # ---
    # Evaluates security posture against weak, default, or hardcoded jwt hmac
    # signing secret.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ses_002_weak_secret_and_cracked_token() -> None:
    """Test LH-SES-002: Weak dictionary secret and offline cracked token."""
    pol = TokenPolicy(
        policy_id="p-02",
        name="Weak Secret Policy",
        target_service="auth",
        hmac_secret="jwt-secret",
    )
    analyzer = SessionAnalyzer([pol], [], [])
    findings = analyzer._check_lh_ses_002()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-SES-002"
    assert findings[0].severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-SES-003 (HIGH):
    #     Missing or Unenforced JWT Expiration or Excessive TTL
    # ---
    # Evaluates security posture against missing or unenforced jwt expiration or
    # excessive ttl.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ses_003_missing_exp_and_excessive_ttl() -> None:
    """Test LH-SES-003: verify_exp=False or access token TTL > 3600s."""
    pol = TokenPolicy(
        policy_id="p-03",
        name="Long TTL Policy",
        target_service="auth",
        verify_exp=False,
        access_token_ttl_seconds=86400,
    )
    tok = RawJwtToken(
        token_id="tok-no-exp",
        header={"alg": "HS256"},
        payload={"sub": "123"},
    )
    analyzer = SessionAnalyzer([pol], [tok], [])
    findings = analyzer._check_lh_ses_003()
    assert len(findings) == 2
    assert all(f.rule_id == "LH-SES-003" for f in findings)
    assert all(f.severity == FindingSeverity.HIGH for f in findings)
    # --------------------------------------------------------------------------
    # --- Rule LH-SES-004 (HIGH):
    #     Missing Cookie HttpOnly or Secure Flag on Session Cookie
    # ---
    # Evaluates security posture against missing cookie httponly or secure flag on
    # session cookie.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ses_004_missing_httponly_or_secure() -> None:
    """Test LH-SES-004: Missing HttpOnly or Secure flag on session cookie."""
    cookie = CookieConfig(
        cookie_name="session_id",
        http_only=False,
        secure=False,
        same_site="Lax",
    )
    analyzer = SessionAnalyzer([], [], [cookie])
    findings = analyzer._check_lh_ses_004()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-SES-004"
    assert findings[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-SES-005: Missing or Unsafe Cookie SameSite Attribute (HIGH) ---
    # Evaluates security posture against missing or unsafe cookie samesite
    # attribute.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ses_005_missing_or_unsafe_samesite() -> None:
    """Test LH-SES-005: SameSite missing or SameSite=None without Secure."""
    c1 = CookieConfig(cookie_name="auth_token", http_only=True, secure=True, same_site="")
    c2 = CookieConfig(cookie_name="auth_sid", http_only=True, secure=False, same_site="None")
    analyzer = SessionAnalyzer([], [], [c1, c2])
    findings = analyzer._check_lh_ses_005()
    assert len(findings) == 2
    assert all(f.rule_id == "LH-SES-005" for f in findings)
    assert all(f.severity == FindingSeverity.HIGH for f in findings)
    # --------------------------------------------------------------------------
    # --- Rule LH-SES-006 (HIGH):
    #     Session Fixation Vulnerability or Missing Regeneration
    # ---
    # Evaluates security posture against session fixation vulnerability or missing
    # regeneration.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ses_006_session_fixation() -> None:
    """Test LH-SES-006: Missing session regeneration on login or URL session ID."""
    pol = TokenPolicy(
        policy_id="p-06",
        name="Fixation Policy",
        target_service="portal",
        regenerate_on_login=False,
        accept_url_session_id=True,
        session_id_entropy_bits=64,
    )
    analyzer = SessionAnalyzer([pol], [], [])
    findings = analyzer._check_lh_ses_006()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-SES-006"
    assert findings[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-SES-007 (HIGH):
    #     Dangerous JWT Header Injection (jku, x5u, kid Path Traversal)
    # ---
    # Evaluates security posture against dangerous jwt header injection (jku, x5u,
    # kid path traversal).
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ses_007_header_injection() -> None:
    """Test LH-SES-007: Dangerous JKU header or kid path traversal."""
    tok = RawJwtToken(
        token_id="tok-inj",
        header={"alg": "RS256", "kid": "../../etc/passwd", "jku": "http://evil.com/keys.json"},
        payload={"sub": "admin"},
    )
    analyzer = SessionAnalyzer([], [tok], [])
    findings = analyzer._check_lh_ses_007()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-SES-007"
    assert findings[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-SES-008 (MEDIUM):
    #     Missing JWT Audience (aud), Issuer (iss), or Replay Token ID
    # ---
    # Evaluates security posture against missing jwt audience (aud), issuer (iss),
    # or replay token id.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ses_008_missing_iss_aud_jti() -> None:
    """Test LH-SES-008: Missing audience, issuer, or replay ID."""
    tok = RawJwtToken(
        token_id="tok-no-aud",
        header={"alg": "HS256"},
        payload={"sub": "user-1", "exp": 1800000000},
    )
    analyzer = SessionAnalyzer([], [tok], [])
    findings = analyzer._check_lh_ses_008()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-SES-008"
    assert findings[0].severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-SES-009 (HIGH):
    #     Missing Refresh Token Rotation or Revocation Blacklist
    # ---
    # Evaluates security posture against missing refresh token rotation or
    # revocation blacklist.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ses_009_refresh_token_rotation() -> None:
    """Test LH-SES-009: Missing refresh token rotation or revocation blacklist."""
    pol = TokenPolicy(
        policy_id="p-09",
        name="No Rotation Policy",
        target_service="oauth",
        refresh_token_rotation=False,
        revocation_check=False,
        detect_reuse=False,
    )
    analyzer = SessionAnalyzer([pol], [], [])
    findings = analyzer._check_lh_ses_009()
    assert len(findings) == 1
    assert findings[0].rule_id == "LH-SES-009"
    assert findings[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-SES-010 (LOW):
    #     Sensitive PII in JWT Payload or Missing __Host- Cookie Prefix
    # ---
    # Evaluates security posture against sensitive pii in jwt payload or missing
    # __host- cookie prefix.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_ses_010_sensitive_payload_and_missing_prefix() -> None:
    """Test LH-SES-010: Password inside JWT payload or missing __Host- cookie prefix."""
    tok = RawJwtToken(
        token_id="tok-leaked",
        header={"alg": "HS256"},
        payload={"sub": "alice", "password": "plaintext-password-123"},
    )
    cookie = CookieConfig(
        cookie_name="session_id",  # Lacks __Host- or __Secure-
        http_only=True,
        secure=True,
        same_site="Strict",
    )
    analyzer = SessionAnalyzer([], [tok], [cookie])
    findings = analyzer._check_lh_ses_010()
    assert len(findings) == 2
    assert all(f.rule_id == "LH-SES-010" for f in findings)
    assert all(f.severity == FindingSeverity.LOW for f in findings)


def test_malicious_yaml_triggers_complete_rule_catalog(sample_malicious_yaml: Path) -> None:
    """Test sample_malicious_yaml triggers expected rules."""
    report = audit_session_target(sample_malicious_yaml)
    detected_rules = {f.rule_id for f in report.findings}
    expected = {
        "LH-SES-001",
        "LH-SES-002",
        "LH-SES-003",
        "LH-SES-004",
        "LH-SES-005",
        "LH-SES-006",
        "LH-SES-007",
        "LH-SES-008",
        "LH-SES-009",
        "LH-SES-010",
    }
    assert expected.issubset(detected_rules)
    assert report.risk_score > 60


def test_tokens_json_triggers_rules(sample_tokens_json: Path) -> None:
    """Test sample_tokens_json triggers cracked secret, kid traversal, etc."""
    report = audit_session_target(sample_tokens_json)
    detected_rules = {f.rule_id for f in report.findings}
    assert "LH-SES-001" in detected_rules  # alg: none
    assert "LH-SES-002" in detected_rules  # cracked secret
    assert "LH-SES-007" in detected_rules  # kid traversal
    assert "LH-SES-010" in detected_rules  # leaked password in payload


def test_calculate_risk_score() -> None:
    """Test calculate_risk_score with various combinations and 100 cap."""
    assert calculate_risk_score([]) == 0

    findings = [
        AuditFinding(
            rule_id="LH-SES-001",
            severity=FindingSeverity.CRITICAL,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
        AuditFinding(
            rule_id="LH-SES-004",
            severity=FindingSeverity.HIGH,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
        AuditFinding(
            rule_id="LH-SES-008",
            severity=FindingSeverity.MEDIUM,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
        AuditFinding(
            rule_id="LH-SES-010",
            severity=FindingSeverity.LOW,
            category="Test",
            target_resource="res",
            title="T",
            description="D",
            remediation="R",
        ),
    ]
    # 25 + 15 + 5 + 2 = 47
    assert calculate_risk_score(findings) == 47

    # Cap test at 100
    many_crits = [findings[0]] * 10
    assert calculate_risk_score(many_crits) == 100
