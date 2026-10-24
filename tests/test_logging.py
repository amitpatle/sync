from __future__ import annotations

import io
import json
import logging

from ghgl_sync.logging_setup import configure_logging, correlation_context

TOKEN = "ghp_" + "Q1w2E3r4T5" * 4
URL = "https://user:p4ssw0rdp4ss@example.com/x.git"


def _emit() -> tuple[str, list[dict[str, object]]]:
    stream = io.StringIO()
    configure_logging("DEBUG", stream)
    log = logging.getLogger("test")
    with correlation_context("abc123"):
        log.info("using %s", TOKEN, extra={"authorization": f"Bearer {TOKEN}", "remote": URL})
        try:
            raise RuntimeError(f"failed with {TOKEN} at {URL}")
        except RuntimeError:
            log.exception("boom")
    raw = stream.getvalue()
    return raw, [json.loads(line) for line in raw.splitlines()]


def test_logs_are_json_with_correlation_id() -> None:
    _, records = _emit()
    assert len(records) == 2
    assert all(r["correlation_id"] == "abc123" for r in records)
    assert records[0]["level"] == "INFO"


def test_logs_never_contain_secrets() -> None:
    raw, _ = _emit()
    assert TOKEN not in raw
    assert "p4ssw0rdp4ss" not in raw
    assert "[REDACTED]" in raw


def test_correlation_id_absent_outside_context() -> None:
    stream = io.StringIO()
    configure_logging("INFO", stream)
    logging.getLogger("t").info("hello")
    assert "correlation_id" not in json.loads(stream.getvalue())
