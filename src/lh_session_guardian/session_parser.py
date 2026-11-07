# ==============================================================================
# Product:       lh-session-guardian (lh-session)
# Module:        src.lh_session_guardian.session_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parsers for JWT token policies, raw JWT tokens, cookies, and server configs."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

import yaml

from lh_session_guardian.models import CookieConfig, RawJwtToken, TokenPolicy

JWT_TOKEN_PATTERN = re.compile(
    r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*(?=[^A-Za-z0-9_-]|$)"
)


def decode_jwt(raw: str, source_file: str = "", line_no: int = 1) -> RawJwtToken | None:
    """Decode a raw dot-separated JWT token into header and payload dictionaries."""
    parts = raw.strip().split(".")
    if len(parts) < 2:
        return None

    def _b64_decode(segment: str) -> dict[str, Any]:
        padded = segment + "=" * (-len(segment) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="replace")
        obj = json.loads(decoded)
        return obj if isinstance(obj, dict) else {}

    try:
        header = _b64_decode(parts[0])
        payload = _b64_decode(parts[1])
        sig = parts[2] if len(parts) > 2 else ""
        token_id = str(payload.get("jti") or payload.get("sub") or f"jwt-{line_no}")
        return RawJwtToken(
            token_id=token_id,
            raw_token=raw.strip(),
            header=header,
            payload=payload,
            signature=sig,
            source_file=source_file,
            line_number=line_no,
        )
    except Exception:
        return None


def _extract_bool(data: dict[str, Any], aliases: list[str]) -> bool | None:
    """Extract boolean value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                s = val.strip().lower()
                if s in ["true", "yes", "1", "on", "enabled", "strict", "required"]:
                    return True
                if s in ["false", "no", "0", "off", "disabled", "optional", "none"]:
                    return False
            if isinstance(val, int):
                return bool(val)
    return None


def _extract_str(data: dict[str, Any], aliases: list[str], default: str = "") -> str:
    """Extract string value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if val is not None:
                return str(val).strip()
    return default


def _extract_int(data: dict[str, Any], aliases: list[str]) -> int | None:
    """Extract integer value checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            try:
                return int(val)
            except (ValueError, TypeError):
                continue
    return None


def _extract_list(data: dict[str, Any], aliases: list[str]) -> list[str]:
    """Extract string list checking case-insensitive alias keys."""
    normalized = {k.strip().lower().replace("_", " "): v for k, v in data.items()}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized:
            val = normalized[norm_alias]
            if isinstance(val, list):
                return [str(x).strip() for x in val if x is not None]
            if isinstance(val, str):
                return [x.strip() for x in val.split(",") if x.strip()]
    return []


POLICY_KEYS = {
    "policy_id",
    "name",
    "target_service",
    "allowed_algorithms",
    "algorithms",
    "algs",
    "hmac_secret",
    "jwt_secret",
    "secret",
    "secret_key",
    "access_token_ttl",
    "access_token_ttl_seconds",
    "token_ttl",
    "verify_exp",
    "verify_iss",
    "verify_aud",
    "verify_jti",
    "regenerate_on_login",
    "accept_url_session_id",
    "session_id_entropy_bits",
    "allow_jku",
    "allow_x5u",
    "allow_jwk_header",
    "refresh_token_rotation",
    "revocation_check",
    "detect_reuse",
    "csrf_protection",
}


def _is_policy_dict(data: dict[str, Any]) -> bool:
    """Return True if dict contains recognized policy/configuration keys."""
    normalized_keys = {k.strip().lower() for k in data.keys()}
    return bool(normalized_keys.intersection(POLICY_KEYS))


def _dict_to_token_policy(data: dict[str, Any], source_file: str, line_no: int) -> TokenPolicy:
    """Convert parsed dictionary into a TokenPolicy object."""
    policy_id = _extract_str(data, ["policy_id", "id", "name", "rule_id"], f"pol-{line_no}")
    name = _extract_str(data, ["name", "title", "description"], policy_id)
    svc = _extract_str(data, ["target_service", "service", "app", "audience", "realm"], "auth")

    allowed_algs = _extract_list(
        data, ["allowed_algorithms", "algorithms", "algs", "supported_algorithms"]
    )
    secret = _extract_str(
        data, ["hmac_secret", "jwt_secret", "secret", "secret_key", "signing_key", "key"]
    )

    access_ttl = _extract_int(
        data,
        [
            "access_token_ttl_seconds",
            "access_token_ttl",
            "token_ttl",
            "ttl",
            "expires_in",
            "max_age",
        ],
    )
    refresh_ttl = _extract_int(
        data, ["refresh_token_ttl_seconds", "refresh_token_ttl", "refresh_ttl"]
    )

    verify_exp = _extract_bool(data, ["verify_exp", "check_exp", "enforce_exp", "require_exp"])
    verify_iss = _extract_bool(data, ["verify_iss", "check_iss", "enforce_iss", "require_iss"])
    verify_aud = _extract_bool(data, ["verify_aud", "check_aud", "enforce_aud", "require_aud"])
    verify_jti = _extract_bool(data, ["verify_jti", "check_jti", "enforce_jti", "require_jti"])

    expected_iss = _extract_str(data, ["expected_issuer", "issuer", "iss"])
    expected_aud = _extract_str(data, ["expected_audience", "audience", "aud"])

    regen = _extract_bool(
        data, ["regenerate_on_login", "regenerate_session", "session_regeneration"]
    )
    accept_url_sid = _extract_bool(
        data, ["accept_url_session_id", "allow_url_session_id", "url_session_id"]
    )
    entropy = _extract_int(
        data, ["session_id_entropy_bits", "session_entropy", "entropy_bits", "entropy"]
    )

    allow_jku = _extract_bool(data, ["allow_jku", "trust_jku", "enable_jku"])
    allow_x5u = _extract_bool(data, ["allow_x5u", "trust_x5u", "enable_x5u"])
    allow_jwk = _extract_bool(data, ["allow_jwk_header", "trust_jwk", "enable_jwk"])

    rotate_refresh = _extract_bool(
        data, ["refresh_token_rotation", "rotate_refresh_tokens", "token_rotation"]
    )
    revocation = _extract_bool(data, ["revocation_check", "blacklist_enabled", "check_revocation"])
    detect_reuse = _extract_bool(data, ["detect_reuse", "detect_token_reuse", "family_revocation"])
    csrf = _extract_bool(data, ["csrf_protection", "csrf_enabled", "enable_csrf"])

    return TokenPolicy(
        policy_id=policy_id,
        name=name,
        target_service=svc,
        allowed_algorithms=allowed_algs,
        hmac_secret=secret,
        access_token_ttl_seconds=access_ttl,
        refresh_token_ttl_seconds=refresh_ttl,
        verify_exp=verify_exp,
        verify_iss=verify_iss,
        verify_aud=verify_aud,
        verify_jti=verify_jti,
        expected_issuer=expected_iss,
        expected_audience=expected_aud,
        regenerate_on_login=regen,
        accept_url_session_id=accept_url_sid,
        session_id_entropy_bits=entropy,
        allow_jku=allow_jku,
        allow_x5u=allow_x5u,
        allow_jwk_header=allow_jwk,
        refresh_token_rotation=rotate_refresh,
        revocation_check=revocation,
        detect_reuse=detect_reuse,
        csrf_protection=csrf,
        source_file=source_file,
        line_number=line_no,
    )


def _dict_to_cookie_config(data: dict[str, Any], source_file: str, line_no: int) -> CookieConfig:
    """Convert parsed dictionary into a CookieConfig object."""
    c_name = _extract_str(data, ["cookie_name", "name", "cookie"], f"cookie-{line_no}")
    http_only = _extract_bool(data, ["http_only", "httponly"])
    secure = _extract_bool(data, ["secure"])
    same_site = _extract_str(data, ["same_site", "samesite"], "")
    domain = _extract_str(data, ["domain"])
    path = _extract_str(data, ["path"], "/")
    max_age = _extract_int(data, ["max_age", "maxage", "expires"])

    has_host = c_name.startswith("__Host-")
    has_secure = c_name.startswith("__Secure-")

    return CookieConfig(
        cookie_name=c_name,
        http_only=http_only,
        secure=secure,
        same_site=same_site,
        domain=domain,
        path=path,
        max_age=max_age,
        has_host_prefix=has_host,
        has_secure_prefix=has_secure,
        source_file=source_file,
        line_number=line_no,
    )


def parse_set_cookie_header(header_val: str, source_file: str, line_no: int) -> CookieConfig:
    # --- Multi-Format Parsing & Normalization Engine ---
    # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
    # applies fallback decoders, recovers from malformed lines, and standardizes
    # raw configuration attributes into typed domain model instances.
    """Parse a Set-Cookie HTTP header value into CookieConfig."""
    parts = [p.strip() for p in header_val.split(";") if p.strip()]
    if not parts:
        return CookieConfig(source_file=source_file, line_number=line_no)

    first_pair = parts[0].split("=", 1)
    name = first_pair[0].strip()

    http_only = False
    secure = False
    same_site = ""
    domain = ""
    path = ""
    max_age: int | None = None

    for attr in parts[1:]:
        attr_lower = attr.lower()
        if attr_lower == "httponly":
            http_only = True
        elif attr_lower == "secure":
            secure = True
        elif attr_lower.startswith("samesite="):
            same_site = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("domain="):
            domain = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("path="):
            path = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("max-age="):
            try:
                max_age = int(attr.split("=", 1)[1].strip())
            except ValueError:
                continue

    return CookieConfig(
        cookie_name=name,
        http_only=http_only,
        secure=secure,
        same_site=same_site,
        domain=domain,
        path=path,
        max_age=max_age,
        has_host_prefix=name.startswith("__Host-"),
        has_secure_prefix=name.startswith("__Secure-"),
        source_file=source_file,
        line_number=line_no,
    )


def parse_yaml_file(
    path: Path,
) -> tuple[list[TokenPolicy], list[RawJwtToken], list[CookieConfig]]:
    """Parse YAML manifest for session policies, raw tokens, or cookie configs."""
    policies: list[TokenPolicy] = []
    tokens: list[RawJwtToken] = []
    cookies: list[CookieConfig] = []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        loaded = yaml.safe_load(content)

        # Look for raw JWTs embedded in text
        for idx, m in enumerate(JWT_TOKEN_PATTERN.finditer(content), start=1):
            tok = decode_jwt(m.group(0), str(path), idx)
            if tok:
                tokens.append(tok)

        if isinstance(loaded, list):
            for idx, item in enumerate(loaded, start=1):
                if isinstance(item, dict):
                    if "cookie_name" in item or "samesite" in item or "httponly" in item:
                        cookies.append(_dict_to_cookie_config(item, str(path), idx))
                    elif _is_policy_dict(item):
                        policies.append(_dict_to_token_policy(item, str(path), idx))
        elif isinstance(loaded, dict):
            if "cookies" in loaded and isinstance(loaded["cookies"], list):
                for idx, c in enumerate(loaded["cookies"], start=1):
                    if isinstance(c, dict):
                        cookies.append(_dict_to_cookie_config(c, str(path), idx))
            if "policies" in loaded and isinstance(loaded["policies"], list):
                for idx, p in enumerate(loaded["policies"], start=1):
                    if isinstance(p, dict):
                        policies.append(_dict_to_token_policy(p, str(path), idx))
            elif "cookie_name" in loaded or "samesite" in loaded:
                cookies.append(_dict_to_cookie_config(loaded, str(path), 1))
            elif _is_policy_dict(loaded):
                policies.append(_dict_to_token_policy(loaded, str(path), 1))
    except Exception:
        return policies, tokens, cookies

    return policies, tokens, cookies


def parse_json_file(
    path: Path,
) -> tuple[list[TokenPolicy], list[RawJwtToken], list[CookieConfig]]:
    """Parse JSON or NDJSON files for session policies, tokens, or cookie configs."""
    policies: list[TokenPolicy] = []
    tokens: list[RawJwtToken] = []
    cookies: list[CookieConfig] = []

    try:
        content = path.read_text(encoding="utf-8", errors="replace").strip()
        if not content:
            return [], [], []

        # Find raw JWTs
        for idx, m in enumerate(JWT_TOKEN_PATTERN.finditer(content), start=1):
            tok = decode_jwt(m.group(0), str(path), idx)
            if tok:
                tokens.append(tok)

        if content.startswith("["):
            loaded = json.loads(content)
            if isinstance(loaded, list):
                for idx, item in enumerate(loaded, start=1):
                    if isinstance(item, dict):
                        if "cookie_name" in item or "samesite" in item:
                            cookies.append(_dict_to_cookie_config(item, str(path), idx))
                        elif _is_policy_dict(item):
                            policies.append(_dict_to_token_policy(item, str(path), idx))
                return policies, tokens, cookies
        elif content.startswith("{"):
            try:
                loaded = json.loads(content)
                if isinstance(loaded, dict):
                    if "cookies" in loaded and isinstance(loaded["cookies"], list):
                        for idx, c in enumerate(loaded["cookies"], start=1):
                            if isinstance(c, dict):
                                cookies.append(_dict_to_cookie_config(c, str(path), idx))
                    elif "policies" in loaded and isinstance(loaded["policies"], list):
                        for idx, p in enumerate(loaded["policies"], start=1):
                            if isinstance(p, dict):
                                policies.append(_dict_to_token_policy(p, str(path), idx))
                    elif "cookie_name" in loaded or "samesite" in loaded:
                        cookies.append(_dict_to_cookie_config(loaded, str(path), 1))
                    elif _is_policy_dict(loaded):
                        policies.append(_dict_to_token_policy(loaded, str(path), 1))
                    return policies, tokens, cookies
            except json.JSONDecodeError:
                _ = None

        # NDJSON fallback
        for idx, line in enumerate(content.splitlines(), start=1):
            clean = line.strip()
            if clean:
                try:
                    obj = json.loads(clean)
                    if isinstance(obj, dict):
                        if "cookie_name" in obj or "samesite" in obj:
                            cookies.append(_dict_to_cookie_config(obj, str(path), idx))
                        elif _is_policy_dict(obj):
                            policies.append(_dict_to_token_policy(obj, str(path), idx))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return policies, tokens, cookies

    return policies, tokens, cookies


def parse_conf_file(
    path: Path,
) -> tuple[list[TokenPolicy], list[RawJwtToken], list[CookieConfig]]:
    """Parse Nginx/web server configuration for Set-Cookie and JWT directives."""
    policies: list[TokenPolicy] = []
    tokens: list[RawJwtToken] = []
    cookies: list[CookieConfig] = []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")

        # Find raw JWTs
        for idx, m in enumerate(JWT_TOKEN_PATTERN.finditer(content), start=1):
            tok = decode_jwt(m.group(0), str(path), idx)
            if tok:
                tokens.append(tok)

        # Regex for Set-Cookie header directives in Nginx / Apache
        cookie_header_pattern = re.compile(
            r"""(?:add_header|header\s+always\s+set)\s+Set-Cookie\s+["']?([^;"'\n]+(?:;[^"'\n]+)*)["']?""",
            re.IGNORECASE,
        )

        for idx, m in enumerate(cookie_header_pattern.finditer(content), start=1):
            cookie_str = m.group(1).strip()
            cookies.append(parse_set_cookie_header(cookie_str, str(path), idx))

        # Check for proxy_cookie_flags (Nginx)
        proxy_flags_pattern = re.compile(
            r"proxy_cookie_flags\s+([^\s;]+)\s+([^;]+);", re.IGNORECASE
        )
        for idx, m in enumerate(proxy_flags_pattern.finditer(content), start=1):
            c_name = m.group(1).strip()
            flags = m.group(2).lower()
            http_only = "httponly" in flags
            secure = "secure" in flags
            same_site = ""
            if "samesite=strict" in flags:
                same_site = "Strict"
            elif "samesite=lax" in flags:
                same_site = "Lax"
            elif "samesite=none" in flags:
                same_site = "None"

            cookies.append(
                CookieConfig(
                    cookie_name=c_name,
                    http_only=http_only,
                    secure=secure,
                    same_site=same_site,
                    has_host_prefix=c_name.startswith("__Host-"),
                    has_secure_prefix=c_name.startswith("__Secure-"),
                    source_file=str(path),
                    line_number=idx,
                )
            )

        # Check for auth_jwt / jwt_secret directives in conf
        jwt_secret_pattern = re.compile(
            r"""(?:auth_jwt_key_file|auth_jwt_secret|jwt_secret)\s+["']?([^;"'\n]+)["']?""",
            re.IGNORECASE,
        )
        for idx, m in enumerate(jwt_secret_pattern.finditer(content), start=1):
            sec = m.group(1).strip()
            policies.append(
                TokenPolicy(
                    policy_id=f"conf-jwt-{idx}",
                    name=f"Nginx JWT Config {idx}",
                    target_service="nginx",
                    hmac_secret=sec,
                    source_file=str(path),
                    line_number=idx,
                )
            )
    except Exception:
        return policies, tokens, cookies

    return policies, tokens, cookies


def parse_env_file(
    path: Path,
) -> tuple[list[TokenPolicy], list[RawJwtToken], list[CookieConfig]]:
    """Parse .env or config files for JWT secrets and raw tokens."""
    policies: list[TokenPolicy] = []
    tokens: list[RawJwtToken] = []
    cookies: list[CookieConfig] = []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")

        # Find raw JWTs
        for idx, m in enumerate(JWT_TOKEN_PATTERN.finditer(content), start=1):
            tok = decode_jwt(m.group(0), str(path), idx)
            if tok:
                tokens.append(tok)

        for idx, line in enumerate(content.splitlines(), start=1):
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("#"):
                continue

            if "=" in line_clean:
                k, v = line_clean.split("=", 1)
                k_clean = k.strip().lower()
                v_clean = v.strip().strip("\"'")

                if any(
                    s in k_clean
                    for s in [
                        "jwt_secret",
                        "secret_key",
                        "signing_key",
                        "token_secret",
                        "session_secret",
                    ]
                ):
                    policies.append(
                        TokenPolicy(
                            policy_id=f"env-{idx}",
                            name=f"Env Secret {k.strip()}",
                            target_service="env",
                            hmac_secret=v_clean,
                            source_file=str(path),
                            line_number=idx,
                        )
                    )
    except Exception:
        return policies, tokens, cookies

    return policies, tokens, cookies


def parse_session_file(
    path: Path,
) -> tuple[list[TokenPolicy], list[RawJwtToken], list[CookieConfig]]:
    """Dispatch file parsing based on extension."""
    suffix = path.suffix.lower()
    if suffix in [".yaml", ".yml"]:
        return parse_yaml_file(path)
    if suffix in [".json", ".jsonl", ".ndjson"]:
        return parse_json_file(path)
    if suffix in [".conf", ".nginx", ".vhost"]:
        return parse_conf_file(path)
    if suffix in [".env", ".properties", ".txt"]:
        return parse_env_file(path)

    # Fallback to YAML/JSON
    p, t, c = parse_yaml_file(path)
    if p or t or c:
        return p, t, c
    return parse_env_file(path)


def find_session_files(target: Path) -> list[Path]:
    """Find all relevant JWT policies, configs, and session files in path."""
    if target.is_file():
        return [target]

    supported_suffixes = {
        ".yaml",
        ".yml",
        ".json",
        ".jsonl",
        ".ndjson",
        ".conf",
        ".env",
        ".properties",
        ".txt",
    }
    found: list[Path] = []
    ignored_parts = {".git", ".venv", "node_modules", "__pycache__"}

    for p in target.rglob("*"):
        if p.is_file():
            if any(ign in p.parts for ign in ignored_parts):
                continue
            if p.suffix.lower() in supported_suffixes or p.name.startswith(".env"):
                found.append(p)

    return sorted(found)
