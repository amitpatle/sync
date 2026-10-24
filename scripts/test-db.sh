#!/usr/bin/env bash
# Start a throwaway local PostgreSQL for tests (Debian/Ubuntu: apt install postgresql).
# CI uses a service container instead. Usage: scripts/test-db.sh && pytest
set -euo pipefail
PGBIN="$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -1)"
DATA="${GHGL_TEST_PGDATA:-/tmp/ghgl-pgdata}"
PORT="${GHGL_TEST_PGPORT:-5433}"
if [ ! -d "$DATA" ]; then
  mkdir -p "$DATA" && chown postgres:postgres "$DATA"
  su postgres -c "$PGBIN/initdb -D $DATA -A trust -U postgres >/dev/null"
fi
if ! su postgres -c "$PGBIN/pg_ctl -D $DATA status" >/dev/null 2>&1; then
  su postgres -c "$PGBIN/pg_ctl -D $DATA -o '-p $PORT -k /tmp' -l /tmp/ghgl-pg.log start -w" >/dev/null
fi
psql -h /tmp -p "$PORT" -U postgres -tAc "select 1 from pg_database where datname='ghgl_test'" \
  | grep -q 1 || psql -h /tmp -p "$PORT" -U postgres -c "create database ghgl_test" >/dev/null
echo "test database ready: postgresql://postgres@/ghgl_test?host=/tmp&port=$PORT"
