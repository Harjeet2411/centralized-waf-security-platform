"""Migration 0001 vs docs/BACKEND_SCHEMA.md guarantees: ORM parity, audit immutability, GiST CIDR guardrail
lookups, CHECK constraints, and the RBAC seed matching the PRD matrix."""

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.database import engine
from app.models import Base


async def test_orm_models_match_migration():
    def diff(sync_conn):
        ctx = MigrationContext.configure(sync_conn, opts={"compare_type": True})
        return compare_metadata(ctx, Base.metadata)

    async with engine.connect() as conn:
        changes = await conn.run_sync(diff)
    # alembic_version is Alembic's own table, not part of the model metadata.
    changes = [c for c in changes if not (c[0] == "remove_table" and c[1].name == "alembic_version")]
    assert changes == []


AUDIT_ROW = (
    "INSERT INTO audit_events (audit_code, user_email, user_role, account_id, region, action, target_resource,"
    " previous_state, new_state, reason, risk_level, approver, execution_status, aws_request_id,"
    " verification_status) VALUES (:code, 'a@sas.test', 'Security Admin', '123456789012', 'us-east-1',"
    " 'TEST', 'arn:test', '{}', '{}', 'test', 'LOW', 'b@sas.test', 'EXECUTED', 'req-1', 'VERIFIED')"
)


@pytest.mark.parametrize("statement", [
    "UPDATE audit_events SET reason = 'tampered' WHERE audit_code = :code",
    "DELETE FROM audit_events WHERE audit_code = :code",
    "TRUNCATE audit_events",
])
async def test_audit_events_are_append_only(db, statement):
    code = f"AUD-{statement.split()[0]}"
    await db.execute(text(AUDIT_ROW), {"code": code})
    await db.commit()
    with pytest.raises(DBAPIError, match="append-only"):
        await db.execute(text(statement), {"code": code})
    await db.rollback()
    assert await db.scalar(text("SELECT count(*) FROM audit_events WHERE audit_code = :c"), {"c": code}) == 1


async def test_allow_list_gist_cidr_containment(db):
    await db.execute(text(
        "INSERT INTO allow_list_entries (cidr_or_value, ip_network, name, category, owner, reason, created_by) VALUES"
        " ('10.0.0.0/8', '10.0.0.0/8', 'Corp NAT', 'INTERNAL_NETWORK', 'netops', 'egress', 'test'),"
        " ('203.0.113.0/24', '203.0.113.0/24', 'Payments', 'PAYMENT_GATEWAY', 'payments', 'PSP', 'test'),"
        " ('198.51.100.0/24', '198.51.100.0/24', 'Retired', 'PARTNER_API', 'x', 'old', 'test')"
    ))
    await db.execute(text("UPDATE allow_list_entries SET is_active = false WHERE name = 'Retired'"))
    query = text("SELECT name FROM allow_list_entries WHERE is_active AND CAST(:ip AS inet) <<= ip_network")
    assert (await db.scalars(query, {"ip": "10.20.30.40"})).all() == ["Corp NAT"]
    assert (await db.scalars(query, {"ip": "203.0.113.7"})).all() == ["Payments"]
    assert (await db.scalars(query, {"ip": "198.51.100.9"})).all() == []  # inactive entry never protects
    assert (await db.scalars(query, {"ip": "185.220.101.42"})).all() == []
    indexdef = await db.scalar(text("SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_allow_list_cidr'"))
    assert "gist" in indexdef and "inet_ops" in indexdef


@pytest.mark.parametrize("account_id", ["12345", "12345678901a", "1234567890123"])
async def test_account_id_check_constraint(db, account_id):
    with pytest.raises(DBAPIError):  # CHECK violation or varchar(12) overflow
        await db.execute(text(
            "INSERT INTO accounts (account_id, name, environment, owner, discovery_role_arn, response_role_arn)"
            " VALUES (:a, 'x', 'production', 'o', 'arn:d', 'arn:r')"
        ), {"a": account_id})
    await db.rollback()


PRD_MATRIX = {
    "Security Admin": {"VIEW", "INVESTIGATE", "SIMULATE", "CREATE_CHANGE", "APPROVE", "EXECUTE", "ROLLBACK",
                       "MANAGE_TI", "MANAGE_USERS"},
    "Security Analyst": {"VIEW", "INVESTIGATE", "SIMULATE", "CREATE_CHANGE", "APPROVE:TEMP_BLOCK", "MANAGE_TI"},
    "SOC Analyst": {"VIEW", "INVESTIGATE", "SIMULATE", "CREATE_CHANGE"},
    "AWS Administrator": {"VIEW", "INVESTIGATE", "SIMULATE", "CREATE_CHANGE", "APPROVE:INFRA", "EXECUTE", "ROLLBACK"},
    "Application Owner": {"VIEW", "INVESTIGATE:SCOPED", "SIMULATE", "CREATE_CHANGE:SCOPED", "APPROVE:APP_RULES"},
    "Auditor": {"VIEW", "INVESTIGATE"},
    "Executive": {"VIEW"},
    "Read Only": {"VIEW"},
}


async def test_role_seed_matches_prd_matrix(db):
    rows = (await db.execute(text("SELECT name, permissions FROM roles"))).all()
    assert {name: set(perms) for name, perms in rows} == PRD_MATRIX
