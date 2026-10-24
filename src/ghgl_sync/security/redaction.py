"""Secret redaction for logs, audit details, error messages and reports.

Defense in depth: values are scrubbed by *pattern* (token formats, PEM blocks,
URL userinfo, auth headers) and by *key name* (anything called token/secret/...).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "private_key",
    "privatekey",
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "signature",
    "credential",
    "database_url",
)

_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
_PEM_PARTIAL = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.S)
_GH_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")
_GH_PAT = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b")
_GL_TOKEN = re.compile(r"\bgl[a-z]{2,6}-[A-Za-z0-9_\-]{10,}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*")
_HMAC = re.compile(r"\bsha(?:256|1)=[0-9a-fA-F]{40,64}\b")
_AUTH_SCHEME = re.compile(r"(?i)\b(bearer|basic|token)(\s+)[A-Za-z0-9._~+/=\-]{8,}")
_URL_USERINFO = re.compile(r"(?i)(\b[a-z][a-z0-9+.\-]*://)[^/\s@]+@")
_KV_SECRET = re.compile(
    r"(?i)\b((?:[A-Za-z_]*(?:token|secret|password|passwd|api_?key))\s*[=:]\s*)[^\s,;'\"&]+"
)


def redact_text(text: str) -> str:
    """Scrub secrets from free text."""
    out = _PEM.sub(REDACTED, text)
    out = _PEM_PARTIAL.sub(REDACTED, out)
    out = _URL_USERINFO.sub(lambda m: f"{m.group(1)}{REDACTED}@", out)
    out = _JWT.sub(REDACTED, out)
    out = _GH_PAT.sub(REDACTED, out)
    out = _GH_TOKEN.sub(REDACTED, out)
    out = _GL_TOKEN.sub(REDACTED, out)
    out = _HMAC.sub(REDACTED, out)
    out = _AUTH_SCHEME.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", out)
    return _KV_SECRET.sub(lambda m: f"{m.group(1)}{REDACTED}", out)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def redact_obj(value: Any, *, _key: str | None = None) -> Any:
    """Recursively redact a JSON-like structure. Sensitive keys lose their whole value."""
    if _key is not None and is_sensitive_key(_key):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {str(k): redact_obj(v, _key=str(k)) for k, v in value.items()}
    if isinstance(value, bytes | bytearray):
        return REDACTED
    if isinstance(value, Sequence):
        return [redact_obj(v) for v in value]
    return value
