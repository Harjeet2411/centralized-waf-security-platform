"""Append-only audit trail (Rule #6). Rows are only ever INSERTed; the DB trigger rejects UPDATE/DELETE/TRUNCATE.
The caller owns the transaction so the audit row commits atomically with the change it describes."""

import json
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditEvent

NOT_APPLICABLE = "N/A"


def _text(value) -> str:
    if value is None:
        return NOT_APPLICABLE
    return value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)


def record(db: AsyncSession, *, actor_email: str, actor_role: str, account_id: str, region: str, action: str,
           target_resource: str, previous_state=None, new_state=None, reason: str, risk_level: str,
           approver: str | None = None, approval_id: uuid.UUID | None = None, execution_status: str,
           aws_request_id: str | None = None, verification_status: str | None = None,
           rollback_available: bool = False) -> AuditEvent:
    event = AuditEvent(
        audit_code=f"AUD-{datetime.now(UTC):%Y%m%d%H%M%S}-{secrets.token_hex(3).upper()}",
        # clock_timestamp(), not now(): several audit rows commit in one transaction and must stay ordered.
        timestamp=func.clock_timestamp(),
        user_email=actor_email, user_role=actor_role, account_id=account_id, region=region, action=action,
        target_resource=target_resource[:512], previous_state=_text(previous_state), new_state=_text(new_state),
        reason=reason, risk_level=risk_level, approver=approver or NOT_APPLICABLE, approval_id=approval_id,
        execution_status=execution_status, aws_request_id=aws_request_id or NOT_APPLICABLE,
        verification_status=verification_status or NOT_APPLICABLE, rollback_available=rollback_available,
    )
    db.add(event)
    return event
