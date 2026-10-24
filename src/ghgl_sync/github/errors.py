"""Typed GitHub errors. `classification` and `retryable` feed the retry/dead-letter logic."""

from __future__ import annotations


class GitHubError(Exception):
    classification = "github_error"
    retryable = False


class AuthError(GitHubError):
    """Credentials rejected (expired/revoked token, bad app key). Alert, do not retry blindly."""

    classification = "auth"


class PermissionDenied(GitHubError):
    """Authenticated but not authorized (missing permission or SSO). Not retryable."""

    classification = "permission"


class NotFound(GitHubError):
    classification = "not_found"


class Gone(GitHubError):
    classification = "gone"


class ClientError(GitHubError):
    """Other 4xx: our request was invalid."""

    classification = "client_error"


class ProtocolError(GitHubError):
    """Unexpected/malicious response shape (e.g. pagination link to a foreign origin)."""

    classification = "protocol"


class RateLimited(GitHubError):
    classification = "rate_limited"
    retryable = True

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class TransientError(GitHubError):
    classification = "transient"
    retryable = True
