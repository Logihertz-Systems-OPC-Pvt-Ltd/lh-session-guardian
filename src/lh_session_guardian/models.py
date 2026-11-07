# ==============================================================================
# Product:       lh-session-guardian (lh-session)
# Module:        src.lh_session_guardian.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and rule definitions for lh-session-guardian."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity ratings for session and JWT security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparison."""
        ranks = {
            FindingSeverity.CRITICAL: 4,
            FindingSeverity.HIGH: 3,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
        }
        return ranks.get(self, 0)

    @classmethod
    def from_string(cls, val: str) -> FindingSeverity:
        """Convert string to FindingSeverity case-insensitively."""
        normalized = val.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.LOW

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


@dataclass
class TokenPolicy:
    """Parsed JWT token policy or OAuth2/OIDC session manifest definition."""

    policy_id: str = ""
    name: str = ""
    target_service: str = ""
    allowed_algorithms: list[str] = field(default_factory=list)
    hmac_secret: str = ""
    access_token_ttl_seconds: int | None = None
    refresh_token_ttl_seconds: int | None = None
    verify_exp: bool | None = None
    verify_iss: bool | None = None
    verify_aud: bool | None = None
    verify_jti: bool | None = None
    expected_issuer: str = ""
    expected_audience: str = ""
    regenerate_on_login: bool | None = None
    accept_url_session_id: bool | None = None
    session_id_entropy_bits: int | None = None
    allow_jku: bool | None = None
    allow_x5u: bool | None = None
    allow_jwk_header: bool | None = None
    refresh_token_rotation: bool | None = None
    revocation_check: bool | None = None
    detect_reuse: bool | None = None
    csrf_protection: bool | None = None
    source_file: str = ""
    line_number: int = 0


@dataclass
class RawJwtToken:
    """Decoded raw JWT token record."""

    token_id: str = ""
    raw_token: str = ""
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    source_file: str = ""
    line_number: int = 0


@dataclass
class CookieConfig:
    """Parsed cookie directive or Set-Cookie header configuration."""

    cookie_name: str = ""
    http_only: bool | None = None
    secure: bool | None = None
    same_site: str = ""
    domain: str = ""
    path: str = ""
    max_age: int | None = None
    has_host_prefix: bool = False
    has_secure_prefix: bool = False
    source_file: str = ""
    line_number: int = 0


@dataclass
class AuditFinding:
    """Security finding or vulnerability detected in tokens or session configs."""

    rule_id: str
    severity: FindingSeverity
    category: str
    target_resource: str
    title: str
    description: str
    remediation: str
    evidence: str = ""


@dataclass
class AuditReport:
    """Consolidated session guardian audit report."""

    target: str
    files_scanned: int = 0
    policies_analyzed: int = 0
    tokens_analyzed: int = 0
    cookies_analyzed: int = 0
    findings_count: int = 0
    findings: list[AuditFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    risk_score: int = 0


@dataclass(frozen=True)
class AuditRuleDefinition:
    """Static metadata for session guardian audit rules."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    remediation: str


RULES_REGISTRY: dict[str, AuditRuleDefinition] = {
    "LH-SES-001": AuditRuleDefinition(
        rule_id="LH-SES-001",
        title="Insecure JWT Algorithm or Symmetric/Asymmetric Confusion",
        severity=FindingSeverity.CRITICAL,
        category="Algorithm Security",
        description=(
            "Token allows 'none' algorithm, lacks explicit algorithm whitelist, or mixes HMAC "
            "(HS256) and Asymmetric (RS256) algorithms enabling public key forgery."
        ),
        remediation=(
            "Enforce a strict algorithm whitelist restricting verification to asymmetric "
            "RS256/ES256 or symmetric HS256 exclusively, and reject 'none'."
        ),
    ),
    "LH-SES-002": AuditRuleDefinition(
        rule_id="LH-SES-002",
        title="Weak, Default, or Hardcoded JWT HMAC Signing Secret",
        severity=FindingSeverity.CRITICAL,
        category="Secret Strength",
        description=(
            "JWT signing secret is shorter than 32 bytes (256 bits), low entropy, or a "
            "well-known default dictionary word susceptible to offline brute-force cracking."
        ),
        remediation=(
            "Generate cryptographically secure 256-bit or 512-bit signing secrets and inject "
            "them from a hardened secrets manager."
        ),
    ),
    "LH-SES-003": AuditRuleDefinition(
        rule_id="LH-SES-003",
        title="Missing Expiration Validation or Excessive Access Token TTL",
        severity=FindingSeverity.HIGH,
        category="Token Lifetime",
        description=(
            "Token lacks 'exp' claim validation (verify_exp: false) or access token lifetime "
            "exceeds 3600 seconds (1 hour), expanding exposure windows."
        ),
        remediation=(
            "Enforce strict 'exp' claim validation and restrict access token lifetimes to 15-60 "
            "minutes, relying on refresh tokens for renewal."
        ),
    ),
    "LH-SES-004": AuditRuleDefinition(
        rule_id="LH-SES-004",
        title="Missing Cookie HttpOnly or Secure Flag on Auth Cookies",
        severity=FindingSeverity.HIGH,
        category="Cookie Hygiene",
        description=(
            "Session or authentication cookie omits HttpOnly (allowing JavaScript XSS theft) or "
            "Secure (exposing session tokens over unencrypted plaintext HTTP)."
        ),
        remediation=(
            "Set HttpOnly and Secure flags on all authentication and session state cookies."
        ),
    ),
    "LH-SES-005": AuditRuleDefinition(
        rule_id="LH-SES-005",
        title="Missing or Unsafe Cookie SameSite Attribute",
        severity=FindingSeverity.HIGH,
        category="CSRF Defense",
        description=(
            "Session cookie lacks SameSite=Lax/Strict, or uses SameSite=None without Secure or "
            "anti-CSRF token verification."
        ),
        remediation=(
            "Configure SameSite=Lax or SameSite=Strict on session cookies, and enforce explicit "
            "CSRF protection tokens if SameSite=None is required."
        ),
    ),
    "LH-SES-006": AuditRuleDefinition(
        rule_id="LH-SES-006",
        title="Session Fixation or Missing Regeneration on Privilege Change",
        severity=FindingSeverity.HIGH,
        category="Session Fixation",
        description=(
            "Session configuration fails to regenerate session IDs upon login/privilege change, "
            "accepts session IDs via URL query strings, or uses low entropy IDs."
        ),
        remediation=(
            "Regenerate session identifiers upon user authentication, disable URL session ID "
            "acceptance, and use >= 128 bits of cryptographic entropy."
        ),
    ),
    "LH-SES-007": AuditRuleDefinition(
        rule_id="LH-SES-007",
        title="Dangerous JWT Header Injection (jku, x5u, kid Traversal/SQLi)",
        severity=FindingSeverity.HIGH,
        category="Header Injection",
        description=(
            "JWT header contains untrusted key URLs (jku, x5u), embedded jwk keys, or kid "
            "parameters vulnerable to directory traversal or SQL injection."
        ),
        remediation=(
            "Sanitize 'kid' lookups against a fixed key store, reject arbitrary jku/x5u headers, "
            "and disable embedded 'jwk' header parsing."
        ),
    ),
    "LH-SES-008": AuditRuleDefinition(
        rule_id="LH-SES-008",
        title="Missing JWT Audience, Issuer, or Replay ID Validation",
        severity=FindingSeverity.MEDIUM,
        category="Anti-Replay",
        description=(
            "Token verification policy omits strict audience ('aud'), issuer ('iss'), or unique "
            "token ID ('jti') validation, enabling cross-service token replay."
        ),
        remediation=(
            "Enforce strict issuer ('iss') and audience ('aud') verification and register 'jti' "
            "claims to prevent cross-service replaying."
        ),
    ),
    "LH-SES-009": AuditRuleDefinition(
        rule_id="LH-SES-009",
        title="Missing Refresh Token Rotation or Revocation Blacklist",
        severity=FindingSeverity.HIGH,
        category="Token Lifecycle",
        description=(
            "OAuth2/session policy does not rotate refresh tokens upon use, lacks token "
            "revocation blacklists, or permits refresh lifetimes > 30 days without reuse detection."
        ),
        remediation=(
            "Implement one-time-use refresh token rotation with family invalidation on reuse, "
            "and maintain an active revocation blacklist."
        ),
    ),
    "LH-SES-010": AuditRuleDefinition(
        rule_id="LH-SES-010",
        title="Sensitive Data in JWT Payload or Missing Cookie Prefix",
        severity=FindingSeverity.LOW,
        category="Data Leakage",
        description=(
            "JWT payload contains sensitive credentials or PII (password, ssn, secret), or "
            "production session cookies omit __Host- or __Secure- prefixes."
        ),
        remediation=(
            "Remove passwords and confidential PII from unencrypted JWT payloads, and prefix "
            "sensitive cookies with '__Host-' or '__Secure-'."
        ),
    ),
}
