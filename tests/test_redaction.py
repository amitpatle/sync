from __future__ import annotations

import pytest

from ghgl_sync.security.redaction import REDACTED, redact_obj, redact_text

GH_PAT = "ghp_" + "A1b2C3d4E5" * 4
GH_SRV = "ghs_" + "Z9y8X7w6V5" * 4
FINE = "github_pat_" + "11ABCDEFG0" * 6
GL = "glpat-" + "abcDEF123_-" * 2
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjMifQ.c2lnbmF0dXJlX2J5dGVz"
PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
SECRETS = [GH_PAT, GH_SRV, FINE, GL, JWT, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "hunter2hunter2"]


@pytest.mark.parametrize(
    "text",
    [
        f"token {GH_PAT} leaked",
        f"clone https://x-access-token:{GH_SRV}@github.com/o/r.git failed",
        f"pat={FINE}",
        f"gitlab {GL}",
        f"Authorization: Bearer {JWT}",
        f"key: {PEM} end",
        "truncated key -----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        "password=hunter2hunter2 and more",
        "sig sha256=" + "ab" * 32,
    ],
)
def test_redact_text_removes_secrets(text: str) -> None:
    out = redact_text(text)
    assert REDACTED in out
    for secret in SECRETS:
        assert secret not in out
    assert "ab" * 32 not in out


def test_redact_text_leaves_normal_text_alone() -> None:
    msg = "repo octo/hello synced 12 commits in 3.2s (branch main)"
    assert redact_text(msg) == msg


def test_redact_obj_by_key_and_nested() -> None:
    obj = {
        "Authorization": "Bearer whatever1234",
        "headers": {"X-Hub-Signature-256": "sha256=" + "0" * 64},
        "items": [{"private_key": PEM}, {"note": f"see {GH_PAT}"}],
        "count": 3,
        "token_expiry": "2099",  # key contains "token" -> whole value redacted
    }
    out = redact_obj(obj)
    assert out["Authorization"] == REDACTED
    assert out["headers"]["X-Hub-Signature-256"] == REDACTED
    assert out["items"][0]["private_key"] == REDACTED
    assert GH_PAT not in str(out)
    assert out["count"] == 3
    assert out["token_expiry"] == REDACTED


def test_redact_obj_bytes_are_never_emitted() -> None:
    assert redact_obj({"blob": b"secret-bytes"}) == {"blob": REDACTED}
