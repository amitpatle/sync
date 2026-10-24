"""PostgreSQL connections (psycopg 3). All SQL is parameterized."""

from __future__ import annotations

import psycopg
from psycopg.rows import DictRow, dict_row
from pydantic import SecretStr

Connection = psycopg.Connection[DictRow]


def connect(database_url: SecretStr) -> Connection:
    return psycopg.connect(database_url.get_secret_value(), row_factory=dict_row)
