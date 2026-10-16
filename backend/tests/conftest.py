"""Test harness: real PostgreSQL 16 (sas_waf_test) + Redis 7 (db 15) from docker-compose.yml.

Env must be set before any app import so Settings / the engine bind to the test database.
"""

import json
import os
import secrets
import uuid
from pathlib import Path

import pytest

TEST_DB_URL = os.environ.get(
    "SAS_TEST_DATABASE_URL", "postgresql+asyncpg://sas:sas_local_dev@localhost:5433/sas_waf_test"
)
os.environ.update({
    "SAS_ENVIRONMENT": "test",
    "SAS_DATABASE_URL": TEST_DB_URL,
    "SAS_REDIS_URL": os.environ.get("SAS_TEST_REDIS_URL", "redis://localhost:6379/15"),
    "SAS_COOKIE_SECURE": "false",
    "SAS_OIDC_ISSUER": "https://idp.test",
    "SAS_OIDC_CLIENT_ID": "sas-test-client",
    "SAS_OIDC_CLIENT_SECRET": "test-secret",
    "SAS_OIDC_REDIRECT_URI": "http://test/api/v1/auth/callback",
    "SAS_OIDC_REQUIRE_MFA": "true",
    "SAS_FRONTEND_URL": "http://frontend.test",
})

import httpx  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import text  # noqa: E402

from alembic import command  # noqa: E402
from app.database import SessionLocal, redis_client  # noqa: E402
from app.main import app  # noqa: E402

BACKEND_DIR = Path(__file__).resolve().parents[1]

# Everything except roles (seeded by the migration), child-first. audit_events is handled separately.
CLEANUP_ORDER = [
    "engine_state", "approval_decisions", "platform_health", "drift_events", "changes", "threat_intelligence",
    "detections", "entity_relationships",
    "waf_events", "managed_rule_versions", "rules", "endpoints", "approvals", "simulations", "campaigns",
    "entities", "allow_list_entries", "web_acls", "applications", "users",
]


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    yield


@pytest.fixture(autouse=True)
async def clean_state():
    yield
    async with SessionLocal() as session:
        # Test-only: audit rows reference approvals/accounts and are immutable by design, so the harness
        # suspends the immutability triggers just for its own cleanup.
        await session.execute(text("ALTER TABLE audit_events DISABLE TRIGGER USER"))
        await session.execute(text("DELETE FROM audit_events"))
        await session.execute(text("ALTER TABLE audit_events ENABLE TRIGGER USER"))
        for table in CLEANUP_ORDER:
            await session.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - fixed table list
        await session.execute(text("DELETE FROM accounts"))
        await session.commit()
    await redis_client.flushdb()


@pytest.fixture
async def db():
    async with SessionLocal() as session:
        yield session


@pytest.fixture
async def client():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def create_user(role: str, *, active: bool = True, scoped: list[str] | None = None) -> dict:
    async with SessionLocal() as session:
        row = (await session.execute(text(
            "INSERT INTO users (email, full_name, role_id, sso_subject_id, scoped_account_ids, is_active) "
            "SELECT :email, :name, id, :sub, :scoped, :active FROM roles WHERE name = :role RETURNING id"
        ), {
            "email": f"{uuid.uuid4().hex[:8]}@sas.test", "name": f"Test {role}", "sub": f"sub-{uuid.uuid4().hex}",
            "scoped": scoped or [], "active": active, "role": role,
        })).one()
        await session.commit()
        query = text("SELECT id, sso_subject_id FROM users WHERE id = :id")
        user = (await session.execute(query, {"id": row.id})).one()
    return {"id": user.id, "sub": user.sso_subject_id}


async def login_as(role: str, *, mfa: bool = True, **kwargs) -> dict[str, str]:
    """Create a user + server-side session directly in Redis; returns the cookie dict for httpx."""
    user = await create_user(role, **kwargs)
    session_id = secrets.token_urlsafe(16)
    await redis_client.set(f"session:user:{session_id}", json.dumps({"user_id": str(user["id"]), "mfa": mfa}))
    return {"sas_session": session_id}


async def user_email(cookies: dict[str, str]) -> str:
    raw = json.loads(await redis_client.get(f"session:user:{cookies['sas_session']}"))
    async with SessionLocal() as session:
        return await session.scalar(text("SELECT email FROM users WHERE id = :id"), {"id": raw["user_id"]})
