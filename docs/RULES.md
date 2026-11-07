# Security Rules Reference: lh-session-guardian

An enterprise jwt token policy & web session security auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-session-guardian`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-SES-001` | `CRITICAL` | Cryptography | Insecure JWT Algorithm ('alg: none' or Confusion Risk) |
| `LH-SES-002` | `CRITICAL` | Key Management | Weak, Default, or Hardcoded JWT HMAC Signing Secret |
| `LH-SES-003` | `HIGH` | Lifecycle | Missing or Unenforced JWT Expiration or Excessive TTL |
| `LH-SES-004` | `HIGH` | Cookie Security | Missing Cookie HttpOnly or Secure Flag on Session Cookie |
| `LH-SES-005` | `HIGH` | Cookie Security | Missing or Unsafe Cookie SameSite Attribute |
| `LH-SES-006` | `HIGH` | Session Fixation | Session Fixation Vulnerability or Missing Regeneration |
| `LH-SES-007` | `HIGH` | Header Injection | Dangerous JWT Header Injection (jku, x5u, kid Path Traversal) |
| `LH-SES-008` | `MEDIUM` | Token Claims | Missing JWT Audience (aud), Issuer (iss), or Replay Token ID |
| `LH-SES-009` | `HIGH` | Lifecycle | Missing Refresh Token Rotation or Revocation Blacklist |
| `LH-SES-010` | `LOW` | Privacy & Hygiene | Sensitive PII in JWT Payload or Missing __Host- Cookie Prefix |

---

## Granular Rule Specifications

### `LH-SES-001`: Insecure JWT Algorithm ('alg: none' or Confusion Risk)

- **Severity**: `CRITICAL`
- **Category**: `Cryptography`
- **Description**: JWT header uses alg: none or allows asymmetric/symmetric algorithm confusion (RS256 vs HS256).
- **Remediation**: Enforce strict algorithm allowlists on verification and reject unsigned tokens unconditionally.

---

### `LH-SES-002`: Weak, Default, or Hardcoded JWT HMAC Signing Secret

- **Severity**: `CRITICAL`
- **Category**: `Key Management`
- **Description**: HMAC secret is shorter than 256 bits, uses common dictionary word, or is hardcoded.
- **Remediation**: Generate cryptographically secure 256-bit+ random secret and externalize to secret manager.

---

### `LH-SES-003`: Missing or Unenforced JWT Expiration or Excessive TTL

- **Severity**: `HIGH`
- **Category**: `Lifecycle`
- **Description**: Token lacks exp claim or specifies excessive expiration lifetime (> 24 hours).
- **Remediation**: Enforce short access token lifetimes (<= 15 minutes) and require refresh token rotation.

---

### `LH-SES-004`: Missing Cookie HttpOnly or Secure Flag on Session Cookie

- **Severity**: `HIGH`
- **Category**: `Cookie Security`
- **Description**: Session cookie missing HttpOnly flag (vulnerable to XSS theft) or Secure flag over HTTPS.
- **Remediation**: Set HttpOnly and Secure flags on all authentication and session management cookies.

---

### `LH-SES-005`: Missing or Unsafe Cookie SameSite Attribute

- **Severity**: `HIGH`
- **Category**: `Cookie Security`
- **Description**: Session cookie lacks SameSite attribute or is set to SameSite=None without Secure.
- **Remediation**: Configure SameSite=Lax or SameSite=Strict on session cookies to defend against CSRF attacks.

---

### `LH-SES-006`: Session Fixation Vulnerability or Missing Regeneration

- **Severity**: `HIGH`
- **Category**: `Session Fixation`
- **Description**: Session identifier not regenerated upon user authentication or privilege elevation.
- **Remediation**: Regenerate session ID immediately upon successful login and revoke pre-auth session identifier.

---

### `LH-SES-007`: Dangerous JWT Header Injection (jku, x5u, kid Path Traversal)

- **Severity**: `HIGH`
- **Category**: `Header Injection`
- **Description**: JWT header contains unvalidated jku/x5u URL or kid parameter susceptible to path traversal.
- **Remediation**: Validate jku/x5u URLs against trusted domain allowlists and sanitize kid parameter against directory traversal.

---

### `LH-SES-008`: Missing JWT Audience (aud), Issuer (iss), or Replay Token ID

- **Severity**: `MEDIUM`
- **Category**: `Token Claims`
- **Description**: JWT omits aud, iss, or jti claims, leaving token susceptible to cross-service replay.
- **Remediation**: Mandate and validate aud, iss, and jti claims on every token issuance and verification.

---

### `LH-SES-009`: Missing Refresh Token Rotation or Revocation Blacklist

- **Severity**: `HIGH`
- **Category**: `Lifecycle`
- **Description**: Refresh tokens reusable indefinitely without rotation or invalidation upon reuse.
- **Remediation**: Implement one-time use refresh token rotation with family invalidation on detected reuse.

---

### `LH-SES-010`: Sensitive PII in JWT Payload or Missing __Host- Cookie Prefix

- **Severity**: `LOW`
- **Category**: `Privacy & Hygiene`
- **Description**: Sensitive PII (passwords, SSN) in JWT payload or production auth cookies lack __Host- prefix.
- **Remediation**: Store sensitive PII server-side and apply __Host- prefix to critical session cookies.

---
