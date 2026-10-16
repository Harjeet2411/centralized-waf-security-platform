"""ORM models. DDL authority is alembic/versions/0001_initial_schema.py: CHECK constraints and the
audit trigger live there; these classes mirror columns, keys and indexes so autogenerate stays clean
(tests/test_schema.py asserts no drift between the two)."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from app.models.inventory import (  # noqa: E402
    Account,
    Application,
    Endpoint,
    ManagedRuleVersion,
    PlatformHealth,
    Role,
    Rule,
    User,
    WebAcl,
)
from app.models.response import (  # noqa: E402
    AllowListEntry,
    Approval,
    AuditEvent,
    Change,
    DriftEvent,
    Simulation,
)
from app.models.telemetry import (  # noqa: E402
    Campaign,
    Detection,
    Entity,
    EntityRelationship,
    ThreatIntelligence,
    WafEvent,
)

__all__ = [
    "Base", "Account", "Application", "Endpoint", "ManagedRuleVersion", "PlatformHealth", "Role", "Rule",
    "User", "WebAcl", "AllowListEntry", "Approval", "AuditEvent", "Change", "DriftEvent", "Simulation",
    "Campaign", "Detection", "Entity", "EntityRelationship", "ThreatIntelligence", "WafEvent",
]
