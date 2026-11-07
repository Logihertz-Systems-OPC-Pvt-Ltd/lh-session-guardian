# ==============================================================================
# Product:       lh-session-guardian (lh-session)
# Module:        src.lh_session_guardian.session_analyzer
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Security analyzer implementing rules LH-SES-001 through LH-SES-010."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from pathlib import Path

from lh_session_guardian.models import (
    RULES_REGISTRY,
    AuditFinding,
    AuditReport,
    CookieConfig,
    FindingSeverity,
    RawJwtToken,
    TokenPolicy,
)
from lh_session_guardian.session_parser import find_session_files, parse_session_file

KNOWN_WEAK_SECRETS = {
    "secret",
    "jwt-secret",
    "changeme",
    "your-256-bit-secret",
    "password",
    "123456",
    "test",
    "admin",
    "token",
    "secretkey",
    "privatekey",
    "supersecret",
    "mysecret",
    "default",
    "development",
    "app-secret",
}

SENSITIVE_PAYLOAD_KEYS = {
    "password",
    "passwd",
    "secret",
    "ssn",
    "credit_card",
    "pin",
    "cvv",
    "api_key",
    "private_key",
}

AUTH_COOKIE_SUBSTRINGS = {
    "session",
    "token",
    "auth",
    "sid",
    "jwt",
    "id",
    "connect.sid",
    "phpsessid",
    "jsessionid",
}


def _is_auth_cookie(name: str) -> bool:
    """Return True if cookie name appears to be an authentication or session identifier."""
    name_lower = name.lower()
    return any(sub in name_lower for sub in AUTH_COOKIE_SUBSTRINGS)


class SessionAnalyzer:
    """Audit engine evaluating policies, tokens, and cookies against detection rules."""

    def __init__(
        self,
        policies: list[TokenPolicy],
        tokens: list[RawJwtToken],
        cookies: list[CookieConfig],
    ) -> None:
        self.policies = policies
        self.tokens = tokens
        self.cookies = cookies

    def analyze(self) -> list[AuditFinding]:
        """Execute all rules and return consolidated findings."""
        findings: list[AuditFinding] = []
        findings.extend(self._check_lh_ses_001())
        findings.extend(self._check_lh_ses_002())
        findings.extend(self._check_lh_ses_003())
        findings.extend(self._check_lh_ses_004())
        findings.extend(self._check_lh_ses_005())
        findings.extend(self._check_lh_ses_006())
        findings.extend(self._check_lh_ses_007())
        findings.extend(self._check_lh_ses_008())
        findings.extend(self._check_lh_ses_009())
        findings.extend(self._check_lh_ses_010())
        return findings

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

    def _check_lh_ses_001(self) -> list[AuditFinding]:
        """LH-SES-001 (CRITICAL): Insecure JWT Algorithm or Symmetric/Asymmetric Confusion."""
        rule = RULES_REGISTRY["LH-SES-001"]
        findings: list[AuditFinding] = []

        # Check raw tokens
        for t in self.tokens:
            alg = str(t.header.get("alg", "")).strip().lower()
            if alg in ["none", ""]:
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"token:{t.token_id}",
                        title=f"{rule.title} - Token {t.token_id}",
                        description=(
                            f"JWT token uses unverified '{alg or 'empty'}' algorithm, "
                            f"allowing signature verification bypass."
                        ),
                        remediation=rule.remediation,
                        evidence=f"Header alg: '{t.header.get('alg')}'",
                    )
                )

        # Check policies
        for p in self.policies:
            algs_lower = [a.lower() for a in p.allowed_algorithms]
            allows_none = "none" in algs_lower
            has_hs = any(a.startswith("hs") for a in algs_lower)
            has_asym = any(a.startswith(("rs", "es", "ps")) for a in algs_lower)
            key_confusion = has_hs and has_asym
            missing_whitelist = len(p.allowed_algorithms) == 0 and bool(p.hmac_secret)

            if allows_none or key_confusion or missing_whitelist:
                ev_items: list[str] = []
                if allows_none:
                    ev_items.append("allowed_algorithms includes 'none'")
                if key_confusion:
                    ev_items.append("mixes HMAC and Asymmetric algorithms (key confusion)")
                if missing_whitelist:
                    ev_items.append("missing allowed_algorithms whitelist")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_service})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Token policy for service '{p.target_service}' permits insecure "
                            f"algorithms or key confusion attacks."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_ses_002(self) -> list[AuditFinding]:
        """LH-SES-002 (CRITICAL): Weak, Default, or Hardcoded JWT HMAC Signing Secret."""
        rule = RULES_REGISTRY["LH-SES-002"]
        findings: list[AuditFinding] = []

        # Check policies / env secrets
        for p in self.policies:
            sec = p.hmac_secret.strip()
            if sec:
                sec_lower = sec.lower()
                is_weak = sec_lower in KNOWN_WEAK_SECRETS
                is_short = len(sec) < 32  # Less than 256 bits

                if is_weak or is_short:
                    ev_items: list[str] = []
                    if is_weak:
                        ev_items.append(f"matches default dictionary secret: '{sec_lower}'")
                    if is_short:
                        ev_items.append(f"length {len(sec)} chars (< 32 bytes / 256 bits)")

                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            target_resource=f"{p.name} ({p.target_service})",
                            title=f"{rule.title} - {p.name}",
                            description=(
                                f"Signing secret in '{p.name}' is cryptographically weak, "
                                f"permitting offline token forging."
                            ),
                            remediation=rule.remediation,
                            evidence=" | ".join(ev_items),
                        )
                    )

        # Check tokens against weak secret dictionary
        for t in self.tokens:
            alg = str(t.header.get("alg", "")).upper()
            if alg in ["HS256", "HS384", "HS512"] and t.signature:
                parts = t.raw_token.split(".")
                if len(parts) >= 3:
                    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
                    hash_func = (
                        hashlib.sha256
                        if alg == "HS256"
                        else (hashlib.sha384 if alg == "HS384" else hashlib.sha512)
                    )
                    for weak_sec in KNOWN_WEAK_SECRETS:
                        digest = hmac.new(
                            weak_sec.encode("utf-8"), signing_input, hash_func
                        ).digest()
                        computed_sig = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
                        target_sig = parts[2].rstrip("=")
                        if hmac.compare_digest(computed_sig, target_sig):
                            findings.append(
                                AuditFinding(
                                    rule_id=rule.rule_id,
                                    severity=rule.severity,
                                    category=rule.category,
                                    target_resource=f"token:{t.token_id}",
                                    title=f"{rule.title} - Cracked Token {t.token_id}",
                                    description=(
                                        f"Token signature was verified using known weak "
                                        f"dictionary secret '{weak_sec}'."
                                    ),
                                    remediation=rule.remediation,
                                    evidence=f"Cracked with secret: '{weak_sec}' (alg: {alg})",
                                )
                            )
                            break
        return findings

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

    def _check_lh_ses_003(self) -> list[AuditFinding]:
        """LH-SES-003 (HIGH): Missing Expiration Validation or Excessive Access Token TTL."""
        rule = RULES_REGISTRY["LH-SES-003"]
        findings: list[AuditFinding] = []

        # Check policies
        for p in self.policies:
            unenforced = p.verify_exp is False
            excessive = p.access_token_ttl_seconds is not None and p.access_token_ttl_seconds > 3600

            if unenforced or excessive:
                ev_items: list[str] = []
                if unenforced:
                    ev_items.append("verify_exp=False")
                if excessive:
                    ev_items.append(
                        f"access_token_ttl_seconds={p.access_token_ttl_seconds} (> 3600s)"
                    )

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_service})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Token policy for '{p.target_service}' fails to validate expiration "
                            f"or permits excessive token lifetime."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )

        # Check tokens
        for t in self.tokens:
            exp = t.payload.get("exp")
            iat = t.payload.get("iat")

            if exp is None:
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"token:{t.token_id}",
                        title=f"{rule.title} - Token {t.token_id}",
                        description="JWT payload omits mandatory 'exp' expiration claim.",
                        remediation=rule.remediation,
                        evidence="Missing 'exp' claim in payload",
                    )
                )
            elif isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
                ttl = exp - iat
                if ttl > 3600:
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            target_resource=f"token:{t.token_id}",
                            title=f"{rule.title} - Token {t.token_id}",
                            description=(
                                f"Token lifespan of {ttl} seconds exceeds safe 1-hour limit."
                            ),
                            remediation=rule.remediation,
                            evidence=f"exp ({exp}) - iat ({iat}) = {ttl}s (> 3600s)",
                        )
                    )
        return findings

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

    def _check_lh_ses_004(self) -> list[AuditFinding]:
        """LH-SES-004 (HIGH): Missing Cookie HttpOnly or Secure Flag on Auth Cookies."""
        rule = RULES_REGISTRY["LH-SES-004"]
        findings: list[AuditFinding] = []

        for c in self.cookies:
            if _is_auth_cookie(c.cookie_name):
                missing_httponly = c.http_only is not True
                missing_secure = c.secure is not True

                if missing_httponly or missing_secure:
                    ev_items: list[str] = []
                    if missing_httponly:
                        ev_items.append("HttpOnly missing (XSS risk)")
                    if missing_secure:
                        ev_items.append("Secure flag missing (cleartext interception risk)")

                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            target_resource=f"cookie:{c.cookie_name}",
                            title=f"{rule.title} - Cookie {c.cookie_name}",
                            description=(
                                f"Auth cookie '{c.cookie_name}' lacks critical browser hygiene "
                                f"flags, exposing it to theft."
                            ),
                            remediation=rule.remediation,
                            evidence=" | ".join(ev_items),
                        )
                    )
        return findings

    # --------------------------------------------------------------------------
    # --- Rule LH-SES-005: Missing or Unsafe Cookie SameSite Attribute (HIGH) ---
    # Evaluates security posture against missing or unsafe cookie samesite
    # attribute.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_lh_ses_005(self) -> list[AuditFinding]:
        """LH-SES-005 (HIGH): Missing or Unsafe Cookie SameSite Attribute."""
        rule = RULES_REGISTRY["LH-SES-005"]
        findings: list[AuditFinding] = []

        for c in self.cookies:
            if _is_auth_cookie(c.cookie_name):
                same_site_lower = c.same_site.lower().strip()
                missing_samesite = same_site_lower == ""
                unsafe_none = same_site_lower == "none" and c.secure is not True

                if missing_samesite or unsafe_none:
                    ev_items: list[str] = []
                    if missing_samesite:
                        ev_items.append("SameSite attribute omitted")
                    if unsafe_none:
                        ev_items.append("SameSite=None configured without Secure flag")

                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            target_resource=f"cookie:{c.cookie_name}",
                            title=f"{rule.title} - Cookie {c.cookie_name}",
                            description=(
                                f"Cookie '{c.cookie_name}' has missing or unsafe SameSite "
                                f"configuration, creating CSRF exposure."
                            ),
                            remediation=rule.remediation,
                            evidence=" | ".join(ev_items),
                        )
                    )
        return findings

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

    def _check_lh_ses_006(self) -> list[AuditFinding]:
        """LH-SES-006 (HIGH): Session Fixation or Missing Regeneration on Privilege Change."""
        rule = RULES_REGISTRY["LH-SES-006"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            no_regen = p.regenerate_on_login is False
            url_sid = p.accept_url_session_id is True
            low_entropy = p.session_id_entropy_bits is not None and p.session_id_entropy_bits < 128

            if no_regen or url_sid or low_entropy:
                ev_items: list[str] = []
                if no_regen:
                    ev_items.append("regenerate_on_login=False (session fixation)")
                if url_sid:
                    ev_items.append("accept_url_session_id=True (query string leakage)")
                if low_entropy:
                    ev_items.append(
                        f"session_id_entropy_bits={p.session_id_entropy_bits} (< 128 bits)"
                    )

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_service})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Session management for '{p.target_service}' exhibits session "
                            f"fixation weaknesses or URL token leakage."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_ses_007(self) -> list[AuditFinding]:
        """LH-SES-007 (HIGH): Dangerous JWT Header Injection (jku, x5u, kid Traversal/SQLi)."""
        rule = RULES_REGISTRY["LH-SES-007"]
        findings: list[AuditFinding] = []

        # Check policies
        for p in self.policies:
            dangerous_policy = (
                p.allow_jku is True or p.allow_x5u is True or p.allow_jwk_header is True
            )
            if dangerous_policy:
                ev_items: list[str] = []
                if p.allow_jku:
                    ev_items.append("allow_jku=True (untrusted key URL)")
                if p.allow_x5u:
                    ev_items.append("allow_x5u=True (untrusted cert URL)")
                if p.allow_jwk_header:
                    ev_items.append("allow_jwk_header=True (embedded key trust)")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_service})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Token verification policy '{p.name}' permits dangerous dynamic "
                            f"key loading headers."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )

        # Check tokens
        traversal_pattern = re.compile(
            r"(\.\./|\.\.\\|/etc/|/var/|'|\"|--|;|\bUNION\b)", re.IGNORECASE
        )
        for t in self.tokens:
            has_jku = "jku" in t.header
            has_x5u = "x5u" in t.header
            has_jwk = "jwk" in t.header
            kid = str(t.header.get("kid", ""))
            has_kid_injection = bool(kid and traversal_pattern.search(kid))

            if has_jku or has_x5u or has_jwk or has_kid_injection:
                ev_items: list[str] = []
                if has_jku:
                    ev_items.append(f"jku='{t.header['jku']}'")
                if has_x5u:
                    ev_items.append(f"x5u='{t.header['x5u']}'")
                if has_jwk:
                    ev_items.append("embedded jwk header present")
                if has_kid_injection:
                    ev_items.append(f"kid='{kid}' contains injection/traversal payload")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"token:{t.token_id}",
                        title=f"{rule.title} - Token {t.token_id}",
                        description=(
                            f"JWT header in token {t.token_id} contains untrusted key pointers "
                            f"or injection syntax."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_ses_008(self) -> list[AuditFinding]:
        """LH-SES-008 (MEDIUM): Missing JWT Audience, Issuer, or Replay ID Validation."""
        rule = RULES_REGISTRY["LH-SES-008"]
        findings: list[AuditFinding] = []

        # Check policies
        for p in self.policies:
            no_iss = p.verify_iss is False
            no_aud = p.verify_aud is False
            no_jti = p.verify_jti is False

            if no_iss or no_aud or no_jti:
                ev_items: list[str] = []
                if no_iss:
                    ev_items.append("verify_iss=False")
                if no_aud:
                    ev_items.append("verify_aud=False")
                if no_jti:
                    ev_items.append("verify_jti=False")

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_service})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"Token verification policy for '{p.target_service}' skips anti-replay "
                            f"claims validation."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )

        # Check tokens
        for t in self.tokens:
            missing_claims: list[str] = []
            if "iss" not in t.payload:
                missing_claims.append("iss")
            if "aud" not in t.payload:
                missing_claims.append("aud")
            if "jti" not in t.payload:
                missing_claims.append("jti")

            if missing_claims:
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"token:{t.token_id}",
                        title=f"{rule.title} - Token {t.token_id}",
                        description=(
                            f"Token {t.token_id} payload omits standard anti-replay claims: "
                            f"{', '.join(missing_claims)}."
                        ),
                        remediation=rule.remediation,
                        evidence=f"Missing claims: {', '.join(missing_claims)}",
                    )
                )
        return findings

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

    def _check_lh_ses_009(self) -> list[AuditFinding]:
        """LH-SES-009 (HIGH): Missing Refresh Token Rotation or Revocation Blacklist."""
        rule = RULES_REGISTRY["LH-SES-009"]
        findings: list[AuditFinding] = []

        for p in self.policies:
            no_rotation = p.refresh_token_rotation is False
            no_revocation = p.revocation_check is False
            no_reuse_detection = p.detect_reuse is False
            long_ttl = (
                p.refresh_token_ttl_seconds is not None
                and p.refresh_token_ttl_seconds > 2592000
                and p.detect_reuse is not True
            )

            if no_rotation or no_revocation or no_reuse_detection or long_ttl:
                ev_items: list[str] = []
                if no_rotation:
                    ev_items.append("refresh_token_rotation=False")
                if no_revocation:
                    ev_items.append("revocation_check=False")
                if no_reuse_detection:
                    ev_items.append("detect_reuse=False")
                if long_ttl:
                    ev_items.append(
                        f"refresh_token_ttl_seconds={p.refresh_token_ttl_seconds} (> 30 days) "
                        f"without reuse detection"
                    )

                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"{p.name} ({p.target_service})",
                        title=f"{rule.title} - {p.name}",
                        description=(
                            f"OAuth2/session policy for '{p.target_service}' lacks refresh token "
                            f"rotation or revocation enforcement."
                        ),
                        remediation=rule.remediation,
                        evidence=" | ".join(ev_items),
                    )
                )
        return findings

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

    def _check_lh_ses_010(self) -> list[AuditFinding]:
        """LH-SES-010 (LOW): Sensitive Data in JWT Payload or Missing Cookie Prefix."""
        rule = RULES_REGISTRY["LH-SES-010"]
        findings: list[AuditFinding] = []

        # Check tokens for sensitive data
        for t in self.tokens:
            leaked_keys = [
                k for k in t.payload if any(sk in k.lower() for sk in SENSITIVE_PAYLOAD_KEYS)
            ]
            if leaked_keys:
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        target_resource=f"token:{t.token_id}",
                        title=f"{rule.title} - Token {t.token_id}",
                        description=(
                            f"Token payload exposes sensitive credential or PII keys: "
                            f"{', '.join(leaked_keys)}."
                        ),
                        remediation=rule.remediation,
                        evidence=f"Sensitive keys present in payload: {', '.join(leaked_keys)}",
                    )
                )

        # Check cookies for missing prefixes
        for c in self.cookies:
            if _is_auth_cookie(c.cookie_name):
                if not (c.has_host_prefix or c.has_secure_prefix):
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            target_resource=f"cookie:{c.cookie_name}",
                            title=f"{rule.title} - Cookie {c.cookie_name}",
                            description=(
                                f"Auth cookie '{c.cookie_name}' omits recommended '__Host-' "
                                f"or '__Secure-' security prefix."
                            ),
                            remediation=rule.remediation,
                            evidence="Cookie name lacks __Host- or __Secure- prefix",
                        )
                    )
        return findings


def calculate_risk_score(findings: list[AuditFinding]) -> int:
    """Calculate consolidated session risk score from findings (0-100)."""
    if not findings:
        return 0

    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    raw_score = crit * 25 + hi * 15 + med * 5 + lo * 2
    return min(100, raw_score)


def audit_session_target(target: Path) -> AuditReport:
    """Ingest session definitions and evaluate against complete rule catalog."""
    files = find_session_files(target)

    all_policies: list[TokenPolicy] = []
    all_tokens: list[RawJwtToken] = []
    all_cookies: list[CookieConfig] = []

    for f in files:
        policies, tokens, cookies = parse_session_file(f)
        all_policies.extend(policies)
        all_tokens.extend(tokens)
        all_cookies.extend(cookies)

    analyzer = SessionAnalyzer(all_policies, all_tokens, all_cookies)
    findings = analyzer.analyze()

    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    summary = {
        "critical": crit,
        "high": hi,
        "medium": med,
        "low": lo,
    }

    risk_score = calculate_risk_score(findings)

    return AuditReport(
        target=str(target),
        files_scanned=len(files),
        policies_analyzed=len(all_policies),
        tokens_analyzed=len(all_tokens),
        cookies_analyzed=len(all_cookies),
        findings_count=len(findings),
        findings=findings,
        summary=summary,
        risk_score=risk_score,
    )
