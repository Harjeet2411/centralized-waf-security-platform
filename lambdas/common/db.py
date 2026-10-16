"""PostgreSQL access for Lambdas (psycopg 3, sync). One connection per warm container.

Connection string: SAS_DB_SECRET_ARN (Secrets Manager JSON with host/port/username/password/dbname, the RDS
format) in AWS, or SAS_LAMBDA_DATABASE_URL locally / in tests.
"""

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

from common.aws import get_secret

_conn: psycopg.Connection | None = None


def _dsn() -> str:
    if url := os.environ.get("SAS_LAMBDA_DATABASE_URL"):
        return url
    secret = json.loads(get_secret(os.environ["SAS_DB_SECRET_ARN"]))
    return psycopg.conninfo.make_conninfo(
        host=secret["host"], port=secret.get("port", 5432), user=secret["username"],
        password=secret["password"], dbname=secret.get("dbname", "sas_waf"), sslmode="require",
    )


def connection() -> psycopg.Connection:
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg.connect(_dsn(), row_factory=dict_row, autocommit=False)
    return _conn


@contextmanager
def transaction() -> Iterator[psycopg.Cursor]:
    """Commit on success, roll back on any exception."""
    conn = connection()
    try:
        with conn.cursor() as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def reset() -> None:
    """Drop the cached connection (tests)."""
    global _conn
    if _conn is not None and not _conn.closed:
        _conn.close()
    _conn = None


def upsert_health(cur: psycopg.Cursor, *, component: str, account_id: str | None, status: str, detail: str,
                  error: str | None = None, affected_modules: list[str] | None = None, success: bool) -> None:
    cur.execute(
        """
        INSERT INTO platform_health (component, account_id, status, detail, error, affected_modules, last_success,
                                     last_check)
        VALUES (%(component)s, %(account_id)s, %(status)s, %(detail)s, %(error)s, %(modules)s,
                CASE WHEN %(success)s THEN now() END, now())
        ON CONFLICT ON CONSTRAINT uq_platform_health_component_account DO UPDATE SET
            status = EXCLUDED.status, detail = EXCLUDED.detail, error = EXCLUDED.error,
            affected_modules = EXCLUDED.affected_modules,
            last_success = COALESCE(EXCLUDED.last_success, platform_health.last_success),
            last_check = EXCLUDED.last_check
        """,
        {"component": component, "account_id": account_id, "status": status, "detail": detail, "error": error,
         "modules": affected_modules or [], "success": success},
    )
