"""Application configuration. All secrets are SecretStr and never rendered by repr/logs."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from ghgl_sync.security.urls import validate_base_url

Visibility = Literal["private", "internal", "public"]
VISIBILITY_RANK: dict[str, int] = {"private": 0, "internal": 1, "public": 2}


class ConfigError(RuntimeError):
    """Invalid or incomplete configuration (messages never contain secret values)."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GHGL_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    database_url: SecretStr

    github_api_url: str = "https://api.github.com"
    github_api_version: str = "2022-11-28"
    github_app_id: int
    github_app_private_key: SecretStr | None = None
    github_app_private_key_file: Path | None = None
    # Owners (users/orgs) explicitly authorized for sync. Empty = every installation.
    github_allowed_owners: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Escape hatches for GitHub Enterprise Server on private networks / local testing.
    allow_private_network_hosts: bool = False
    allow_insecure_http: bool = False

    fork_policy: Literal["exclude", "include"] = "exclude"
    archived_policy: Literal["sync_readonly", "skip"] = "sync_readonly"
    missing_scans_before_source_deleted: int = Field(default=3, ge=1)

    # GitLab visibility chosen for each GitHub visibility. Widening is rejected (see validator).
    visibility_private: Visibility = "private"
    visibility_internal: Visibility = "private"
    visibility_public: Visibility = "private"

    http_timeout_seconds: float = Field(default=30.0, gt=0)
    max_rate_limit_wait_seconds: int = Field(default=900, ge=0)
    log_level: str = "INFO"

    @field_validator("github_allowed_owners", mode="before")
    @classmethod
    def _split_owners(cls, v: object) -> object:
        if isinstance(v, str):
            return [p.strip().lower() for p in v.split(",") if p.strip()]
        if isinstance(v, list):
            return [str(p).strip().lower() for p in v if str(p).strip()]
        return v

    @model_validator(mode="after")
    def _validate(self) -> Settings:
        self.github_api_url = validate_base_url(
            self.github_api_url,
            allow_http=self.allow_insecure_http,
            allow_private_hosts=self.allow_private_network_hosts,
        )
        # A private repo must never become internal/public; internal must never become public.
        ceilings = {
            "private": self.visibility_private,
            "internal": self.visibility_internal,
            "public": self.visibility_public,
        }
        for source, target in ceilings.items():
            if VISIBILITY_RANK[target] > VISIBILITY_RANK[source]:
                raise ValueError(
                    f"visibility policy widens {source} -> {target}; this is not permitted"
                )
        return self

    def target_visibility(self, github_visibility: str) -> Visibility:
        mapping: dict[str, Visibility] = {
            "private": self.visibility_private,
            "internal": self.visibility_internal,
            "public": self.visibility_public,
        }
        try:
            return mapping[github_visibility]
        except KeyError:
            return "private"  # unknown visibility: fail closed

    def load_github_private_key(self) -> SecretStr:
        if self.github_app_private_key and self.github_app_private_key_file:
            raise ConfigError("set only one of GITHUB_APP_PRIVATE_KEY / _FILE")
        if self.github_app_private_key:
            return self.github_app_private_key
        if self.github_app_private_key_file:
            path = self.github_app_private_key_file
            try:
                if os.name == "posix" and path.stat().st_mode & 0o004:
                    raise ConfigError(f"private key file {path} is world-readable; chmod 600 it")
                return SecretStr(path.read_text(encoding="utf-8"))
            except OSError as exc:
                raise ConfigError(f"cannot read private key file {path}: {exc.strerror}") from exc
        raise ConfigError("no GitHub App private key configured")
