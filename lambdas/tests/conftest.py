"""Lambda tests run against the same Postgres 16 test database as the backend (docker-compose.yml), migrated
with the backend's Alembic migration - the single source of schema truth."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

TEST_DB = os.environ.get("SAS_TEST_DB", "sas:sas_local_dev@localhost:5433/sas_waf_test")
os.environ.update({
    "SAS_LAMBDA_DATABASE_URL": f"postgresql://{TEST_DB}",
    "SAS_DISCOVERY_EXTERNAL_ID": "test-external-id",
    "SAS_WATERMARK_LAG_SECONDS": "0",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
})

from common import db  # noqa: E402

BACKEND = Path(__file__).resolve().parents[2] / "backend"
CLEANUP_ORDER = [
    "platform_health", "drift_events", "changes", "threat_intelligence", "detections", "entity_relationships",
    "waf_events", "managed_rule_versions", "rules", "endpoints", "approvals", "simulations", "campaigns",
    "entities", "allow_list_entries", "web_acls", "applications", "users", "accounts",
]


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    env = {**os.environ, "SAS_DATABASE_URL": f"postgresql+asyncpg://{TEST_DB}", "SAS_ENVIRONMENT": "test"}
    for target in (["downgrade", "base"], ["upgrade", "head"]):
        subprocess.run([sys.executable, "-m", "alembic", *target], cwd=BACKEND, env=env, check=True,  # noqa: S603
                       capture_output=True)
    yield
    db.reset()


@pytest.fixture(autouse=True)
def clean_tables():
    yield
    with db.transaction() as cur:
        for table in CLEANUP_ORDER:
            cur.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed list


@pytest.fixture
def account():
    acct = {"account_id": "123456789012", "discovery_role_arn": "arn:aws:iam::123456789012:role/SASWafDiscoveryRole",
            "regions": ["eu-west-1"]}
    with db.transaction() as cur:
        cur.execute(
            "INSERT INTO accounts (account_id, name, environment, owner, discovery_role_arn, response_role_arn,"
            " regions)"
            " VALUES (%s, 'prod-payments-04', 'production', 'payments', %s, 'arn:r', %s)",
            (acct["account_id"], acct["discovery_role_arn"], acct["regions"]),
        )
    return acct


def query(sql: str, params=()) -> list[dict]:
    with db.transaction() as cur:
        cur.execute(sql, params)
        return cur.fetchall()
