# ==============================================================================
# Product:       lh-session-guardian (lh-session)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures for lh-session-guardian test suite."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

import pytest
import yaml


def create_test_jwt(header: dict, payload: dict, secret: str = "", alg: str = "HS256") -> str:
    """Helper to generate a base64url-encoded test JWT token."""
    header_json = json.dumps(header).encode("utf-8")
    payload_json = json.dumps(payload).encode("utf-8")

    b64_header = base64.urlsafe_b64encode(header_json).decode("ascii").rstrip("=")
    b64_payload = base64.urlsafe_b64encode(payload_json).decode("ascii").rstrip("=")
    signing_input = f"{b64_header}.{b64_payload}"

    if alg.lower() == "none" or not secret:
        return f"{signing_input}."

    digest = hmac.new(
        secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    sig = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{signing_input}.{sig}"


@pytest.fixture
def sample_clean_yaml(tmp_path: Path) -> Path:
    """Fixture providing compliant JWT and session policy in YAML format."""
    file_path = tmp_path / "compliant_session.yaml"
    data = {
        "policies": [
            {
                "policy_id": "pol-clean-01",
                "name": "Strict Production Auth Policy",
                "target_service": "identity-gateway",
                "allowed_algorithms": ["RS256"],
                "access_token_ttl_seconds": 900,
                "refresh_token_ttl_seconds": 604800,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_jti": True,
                "expected_issuer": "https://auth.logihertz.com",
                "expected_audience": "https://api.logihertz.com",
                "regenerate_on_login": True,
                "accept_url_session_id": False,
                "session_id_entropy_bits": 256,
                "allow_jku": False,
                "allow_x5u": False,
                "allow_jwk_header": False,
                "refresh_token_rotation": True,
                "revocation_check": True,
                "detect_reuse": True,
                "csrf_protection": True,
            }
        ],
        "cookies": [
            {
                "cookie_name": "__Host-session_id",
                "httponly": True,
                "secure": True,
                "samesite": "Strict",
                "path": "/",
            }
        ],
    }
    file_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_malicious_yaml(tmp_path: Path) -> Path:
    """Fixture providing policies triggering rules LH-SES-001 through LH-SES-010."""
    file_path = tmp_path / "insecure_session.yaml"
    data = {
        "policies": [
            # LH-SES-001: Key confusion (HS256 and RS256 allowed together)
            {
                "policy_id": "pol-01",
                "name": "Confused Algorithms Policy",
                "target_service": "api-gateway",
                "allowed_algorithms": ["HS256", "RS256"],
            },
            # LH-SES-002: Weak dictionary signing secret
            {
                "policy_id": "pol-02",
                "name": "Default Secret Policy",
                "target_service": "legacy-auth",
                "hmac_secret": "secret",
            },
            # LH-SES-003: Missing exp verification and excessive TTL
            {
                "policy_id": "pol-03",
                "name": "No Exp Policy",
                "target_service": "user-service",
                "verify_exp": False,
                "access_token_ttl_seconds": 7200,
            },
            # LH-SES-006: Session fixation & URL session ID
            {
                "policy_id": "pol-06",
                "name": "Fixation Prone Session",
                "target_service": "web-portal",
                "regenerate_on_login": False,
                "accept_url_session_id": True,
                "session_id_entropy_bits": 64,
            },
            # LH-SES-007: Dangerous JKU header allowed
            {
                "policy_id": "pol-07",
                "name": "Dynamic Key Policy",
                "target_service": "sso-broker",
                "allow_jku": True,
                "allow_x5u": True,
            },
            # LH-SES-008: Missing audience and issuer verification
            {
                "policy_id": "pol-08",
                "name": "Unverified Replay Policy",
                "target_service": "internal-bus",
                "verify_iss": False,
                "verify_aud": False,
                "verify_jti": False,
            },
            # LH-SES-009: Missing refresh token rotation and revocation check
            {
                "policy_id": "pol-09",
                "name": "Static Refresh Policy",
                "target_service": "oauth-server",
                "refresh_token_rotation": False,
                "revocation_check": False,
                "detect_reuse": False,
                "refresh_token_ttl_seconds": 5000000,
            },
        ],
        "cookies": [
            # LH-SES-004: Missing HttpOnly and Secure
            {
                "cookie_name": "session_id",
                "httponly": False,
                "secure": False,
                "samesite": "Lax",
            },
            # LH-SES-005: SameSite=None without Secure
            {
                "cookie_name": "auth_token",
                "httponly": True,
                "secure": False,
                "samesite": "None",
            },
            # LH-SES-010: Missing __Host- prefix
            {
                "cookie_name": "app_sid",
                "httponly": True,
                "secure": True,
                "samesite": "Strict",
            },
        ],
    }
    file_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_tokens_json(tmp_path: Path) -> Path:
    """Fixture providing raw JWT tokens triggering detection rules."""
    file_path = tmp_path / "tokens.json"

    # Token 1: alg: none (LH-SES-001)
    tok_none = create_test_jwt(
        header={"alg": "none", "typ": "JWT"},
        payload={"sub": "user-001", "name": "Eve"},
        alg="none",
    )

    # Token 2: Weak cracked secret 'changeme' (LH-SES-002)
    tok_weak = create_test_jwt(
        header={"alg": "HS256", "typ": "JWT"},
        payload={"sub": "admin", "iat": 1700000000, "exp": 1700000900},
        secret="changeme",
        alg="HS256",
    )

    # Token 3: kid path traversal (LH-SES-007)
    tok_kid = create_test_jwt(
        header={"alg": "HS256", "kid": "../../etc/passwd"},
        payload={"sub": "hacker", "jti": "tok-kid-01"},
        secret="a" * 32,
    )

    # Token 4: Sensitive password payload (LH-SES-010)
    tok_leaked = create_test_jwt(
        header={"alg": "HS256"},
        payload={"sub": "bob", "password": "super-secret-password-123"},
        secret="b" * 32,
    )

    records = [
        {"token_raw": tok_none},
        {"token_raw": tok_weak},
        {"token_raw": tok_kid},
        {"token_raw": tok_leaked},
    ]
    file_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_nginx_conf(tmp_path: Path) -> Path:
    """Fixture providing Nginx configuration file with Set-Cookie headers."""
    conf_file = tmp_path / "nginx.conf"
    content = (
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_name auth.example.com;\n"
        '    add_header Set-Cookie "sid=abc12345; Path=/; HttpOnly; SameSite=Lax";\n'
        '    add_header Set-Cookie "insecure_token=xyz; Path=/";\n'
        "}\n"
    )
    conf_file.write_text(content, encoding="utf-8")
    return conf_file


@pytest.fixture
def sample_env_file(tmp_path: Path) -> Path:
    """Fixture providing .env file with weak JWT secrets."""
    env_file = tmp_path / ".env"
    content = (
        "# Environment Variables\n"
        "JWT_SECRET=jwt-secret\n"
        "SESSION_SECRET=123456\n"
        "API_KEY=live_pk_somevalidkey1234567890\n"
    )
    env_file.write_text(content, encoding="utf-8")
    return env_file
