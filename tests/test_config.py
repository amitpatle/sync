from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from ghgl_sync.config import ConfigError, Settings

from .conftest import make_settings


def test_defaults_are_conservative() -> None:
    s = make_settings()
    assert s.fork_policy == "exclude"
    assert s.archived_policy == "sync_readonly"
    assert s.target_visibility("public") == "private"
    assert s.target_visibility("internal") == "private"
    assert s.target_visibility("something-new") == "private"  # fail closed


def test_secret_not_in_repr() -> None:
    s = make_settings(database_url=SecretStr("postgresql://u:topsecretpw@h/db"))
    assert "topsecretpw" not in repr(s)
    assert "topsecretpw" not in str(s.model_dump())


@pytest.mark.parametrize(
    "overrides",
    [
        {"visibility_private": "public"},
        {"visibility_private": "internal"},
        {"visibility_internal": "public"},
    ],
)
def test_visibility_widening_is_rejected(overrides: dict[str, str]) -> None:
    with pytest.raises(ValidationError, match="widens"):
        make_settings(**overrides)


def test_visibility_may_be_preserved_or_narrowed() -> None:
    s = make_settings(visibility_public="public", visibility_internal="internal")
    assert s.target_visibility("public") == "public"
    assert s.target_visibility("internal") == "internal"


def test_owners_parsed_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GHGL_DATABASE_URL", "postgresql://x")
    monkeypatch.setenv("GHGL_GITHUB_APP_ID", "7")
    monkeypatch.setenv("GHGL_GITHUB_ALLOWED_OWNERS", "Alice, my-ORG ,")
    s = Settings(_env_file=None)
    assert s.github_allowed_owners == ["alice", "my-org"]


@pytest.mark.parametrize(
    "url", ["http://api.github.com", "https://127.0.0.1", "https://u:p@api.github.com"]
)
def test_unsafe_github_url_rejected(url: str) -> None:
    with pytest.raises(ValidationError):
        make_settings(github_api_url=url)


def test_private_key_sources(tmp_path: Path, rsa_pem: str) -> None:
    with pytest.raises(ConfigError, match="no GitHub App private key"):
        make_settings().load_github_private_key()
    with pytest.raises(ConfigError, match="only one"):
        make_settings(
            github_app_private_key=SecretStr("x"), github_app_private_key_file=tmp_path / "k"
        ).load_github_private_key()
    key_file = tmp_path / "k.pem"
    key_file.write_text(rsa_pem)
    os.chmod(key_file, 0o644)
    with pytest.raises(ConfigError, match="world-readable"):
        make_settings(github_app_private_key_file=key_file).load_github_private_key()
    os.chmod(key_file, 0o600)
    loaded = make_settings(github_app_private_key_file=key_file).load_github_private_key()
    assert loaded.get_secret_value() == rsa_pem
    with pytest.raises(ConfigError, match="cannot read"):
        make_settings(github_app_private_key_file=tmp_path / "missing").load_github_private_key()
