"""Structured JSON logging. Every record passes through the redactor before emission."""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import sys
import traceback
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, TextIO

from ghgl_sync.security.redaction import redact_obj, redact_text

_correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "ghgl_correlation_id", default=None
)

_STANDARD_ATTRS = frozenset(
    logging.LogRecord("x", 0, "x", 0, "", None, None).__dict__.keys() | {"message", "asctime"}
)


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def current_correlation_id() -> str | None:
    return _correlation_id.get()


@contextlib.contextmanager
def correlation_context(correlation_id: str | None = None) -> Iterator[str]:
    cid = correlation_id or new_correlation_id()
    token = _correlation_id.set(cid)
    try:
        yield cid
    finally:
        _correlation_id.reset(token)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        cid = current_correlation_id()
        if cid:
            payload["correlation_id"] = cid
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                payload[key] = redact_obj(value, _key=key)
        if record.exc_info:
            payload["exc"] = redact_text("".join(traceback.format_exception(*record.exc_info)))
        return json.dumps(payload, default=str, sort_keys=True)


def configure_logging(level: str = "INFO", stream: TextIO | None = None) -> None:
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # httpx logs full URLs at INFO; keep it quiet.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
