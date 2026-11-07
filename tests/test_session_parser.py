# ==============================================================================
# Product:       lh-session-guardian (lh-session)
# Module:        tests.test_session_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Tests for session_parser module."""

from __future__ import annotations

from pathlib import Path

from lh_session_guardian.session_parser import (
    decode_jwt,
    find_session_files,
    parse_conf_file,
    parse_env_file,
    parse_json_file,
    parse_session_file,
    parse_set_cookie_header,
    parse_yaml_file,
)


def test_decode_jwt_valid() -> None:
    """Test decoding valid JWT string."""
    raw = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    tok = decode_jwt(raw, "test.txt", 1)
    assert tok is not None
    assert tok.header.get("alg") == "HS256"
    assert tok.payload.get("sub") == "1234567890"
    assert tok.signature == "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


def test_decode_jwt_invalid() -> None:
    """Test decode_jwt handles malformed strings gracefully."""
    assert decode_jwt("not.a.jwt") is None
    assert decode_jwt("singlepart") is None


def test_parse_yaml_clean(sample_clean_yaml: Path) -> None:
    """Test parsing compliant YAML policy."""
    policies, tokens, cookies = parse_yaml_file(sample_clean_yaml)
    assert len(policies) == 1
    assert len(cookies) == 1
    p = policies[0]
    assert p.target_service == "identity-gateway"
    assert p.allowed_algorithms == ["RS256"]
    assert p.verify_exp is True
    assert p.refresh_token_rotation is True

    c = cookies[0]
    assert c.cookie_name == "__Host-session_id"
    assert c.http_only is True
    assert c.secure is True
    assert c.same_site == "Strict"


def test_parse_yaml_malicious(sample_malicious_yaml: Path) -> None:
    """Test parsing insecure YAML manifest."""
    policies, tokens, cookies = parse_yaml_file(sample_malicious_yaml)
    assert len(policies) == 7
    assert len(cookies) == 3


def test_parse_json_tokens(sample_tokens_json: Path) -> None:
    """Test parsing JSON file with raw JWT tokens."""
    policies, tokens, cookies = parse_json_file(sample_tokens_json)
    assert len(tokens) == 4
    assert len(policies) == 0


def test_parse_ndjson(tmp_path: Path) -> None:
    """Test parsing newline-delimited JSON (NDJSON)."""
    ndjson_file = tmp_path / "stream.jsonl"
    lines = [
        '{"cookie_name": "sid1", "httponly": true, "secure": true}',
        '{"cookie_name": "sid2", "httponly": false, "secure": false}',
    ]
    ndjson_file.write_text("\n".join(lines), encoding="utf-8")
    policies, tokens, cookies = parse_json_file(ndjson_file)
    assert len(cookies) == 2
    assert cookies[0].http_only is True
    assert cookies[1].http_only is False


def test_parse_conf_file(sample_nginx_conf: Path) -> None:
    """Test parsing Nginx configuration for Set-Cookie headers."""
    policies, tokens, cookies = parse_conf_file(sample_nginx_conf)
    assert len(cookies) == 2
    c1 = [c for c in cookies if c.cookie_name == "sid"][0]
    assert c1.http_only is True
    assert c1.same_site == "Lax"


def test_parse_env_file(sample_env_file: Path) -> None:
    """Test parsing .env file for JWT secrets."""
    policies, tokens, cookies = parse_env_file(sample_env_file)
    assert len(policies) == 2
    secrets = {p.hmac_secret for p in policies}
    assert "jwt-secret" in secrets
    assert "123456" in secrets


def test_parse_set_cookie_header() -> None:
    """Test parse_set_cookie_header utility."""
    header_val = (
        "__Host-id=secretval; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600; "
        "Domain=example.com"
    )
    c = parse_set_cookie_header(header_val, "test.conf", 1)
    assert c.cookie_name == "__Host-id"
    assert c.has_host_prefix is True
    assert c.http_only is True
    assert c.secure is True
    assert c.same_site == "Strict"
    assert c.max_age == 3600
    assert c.domain == "example.com"


def test_find_session_files(tmp_path: Path) -> None:
    """Test finding supported session files in a target directory."""
    (tmp_path / "auth.yaml").write_text("name: a", encoding="utf-8")
    (tmp_path / "tokens.json").write_text("[]", encoding="utf-8")
    (tmp_path / "nginx.conf").write_text("server {}", encoding="utf-8")
    (tmp_path / ".env").write_text("JWT_SECRET=x", encoding="utf-8")
    (tmp_path / "ignored.bin").write_text("data", encoding="utf-8")

    files = find_session_files(tmp_path)
    file_names = [f.name for f in files]
    assert "auth.yaml" in file_names
    assert "tokens.json" in file_names
    assert "nginx.conf" in file_names
    assert ".env" in file_names
    assert "ignored.bin" not in file_names


def test_parse_session_file_dispatcher(sample_clean_yaml: Path) -> None:
    """Test parse_session_file dispatcher."""
    policies, tokens, cookies = parse_session_file(sample_clean_yaml)
    assert len(policies) == 1
    assert len(cookies) == 1


def test_parse_conf_proxy_flags(tmp_path: Path) -> None:
    """Test parsing Nginx proxy_cookie_flags and auth_jwt."""
    conf = tmp_path / "gateway.conf"
    content = (
        "server {\n"
        "    proxy_cookie_flags session_id httponly secure samesite=strict;\n"
        "    proxy_cookie_flags auth_id samesite=none;\n"
        '    auth_jwt_secret "secretkey123";\n'
        "}\n"
    )
    conf.write_text(content, encoding="utf-8")
    policies, tokens, cookies = parse_conf_file(conf)
    assert len(cookies) == 2
    assert cookies[0].http_only is True
    assert cookies[0].secure is True
    assert cookies[0].same_site == "Strict"
    assert cookies[1].same_site == "None"
    assert len(policies) == 1
    assert policies[0].hmac_secret == "secretkey123"


def test_parse_single_json_items(tmp_path: Path) -> None:
    """Test parsing single JSON object files."""
    f1 = tmp_path / "pol.json"
    f1.write_text(
        '{"policy_id": "p1", "name": "Single Pol", "allowed_algorithms": ["RS256"]}',
        encoding="utf-8",
    )
    p1, _, _ = parse_json_file(f1)
    assert len(p1) == 1
    assert p1[0].policy_id == "p1"

    f2 = tmp_path / "cookie.json"
    f2.write_text(
        '{"cookie_name": "app_sid", "httponly": "yes", "secure": "1", "samesite": "Lax"}',
        encoding="utf-8",
    )
    _, _, c2 = parse_json_file(f2)
    assert len(c2) == 1
    assert c2[0].cookie_name == "app_sid"
    assert c2[0].http_only is True
    assert c2[0].secure is True
