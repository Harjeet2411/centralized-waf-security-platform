"""Milestone 4: controlled response.

* approval_decisions - one row per approver per approval (multi-person policies: Security Admin + Application
  Owner, two-person attach). A person can fill at most one slot.
* changes.rollback_available - false for changes the ResponseRole can't undo (e.g. enabling logging: deleting a
  logging configuration is explicitly denied).
* approvals.allow_list_check widened to VARCHAR(32): BACKEND_SCHEMA.md declares VARCHAR(16) yet allows
  'BLOCKED_PROTECTED_ENTITY' (24 chars), which therefore could never be stored.
* enforce_allow_list() trigger - defense in depth behind guardrail_service (Rule #3): an IP block approval can
  never be inserted or moved forward while its target (or any address in proposed_state.add) overlaps an active
  allow-list CIDR, whatever the application does.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-17
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

STATEMENTS = [
    """CREATE TABLE approval_decisions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        approval_id UUID NOT NULL REFERENCES approvals(id) ON DELETE RESTRICT,
        slot INTEGER NOT NULL,
        decided_by VARCHAR(255) NOT NULL,
        decided_by_role VARCHAR(64) NOT NULL,
        decision VARCHAR(16) NOT NULL CHECK (decision IN ('APPROVE', 'REJECT')),
        comment TEXT,
        decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT uq_approval_decisions_person UNIQUE (approval_id, decided_by)
    )""",
    "ALTER TABLE changes ADD COLUMN rollback_available BOOLEAN NOT NULL DEFAULT TRUE",
    "ALTER TABLE approvals ALTER COLUMN allow_list_check TYPE VARCHAR(32)",
    """CREATE OR REPLACE FUNCTION enforce_allow_list() RETURNS TRIGGER AS $$
    DECLARE
        candidate TEXT;
        net INET;
    BEGIN
        IF NEW.action_type NOT IN ('TEMP_BLOCK_IP', 'PERM_BLOCK_IP')
           OR NEW.status NOT IN ('PENDING', 'APPROVED', 'EXECUTED', 'VERIFIED') THEN
            RETURN NEW;
        END IF;
        FOR candidate IN
            SELECT NEW.target
            UNION ALL
            SELECT jsonb_array_elements_text(COALESCE(NEW.proposed_state::jsonb -> 'add', '[]'::jsonb))
        LOOP
            BEGIN
                net := candidate::inet;
            EXCEPTION WHEN others THEN
                RAISE EXCEPTION 'DENIED: block target % is not an IP/CIDR', candidate;
            END;
            IF EXISTS (SELECT 1 FROM allow_list_entries a
                       WHERE a.is_active AND a.ip_network IS NOT NULL AND a.ip_network && net) THEN
                RAISE EXCEPTION 'DENIED: Protected Entity (%)', candidate;
            END IF;
        END LOOP;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql""",
    """CREATE TRIGGER trg_approvals_allow_list
        BEFORE INSERT OR UPDATE OF status, target, proposed_state ON approvals
        FOR EACH ROW EXECUTE FUNCTION enforce_allow_list()""",
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_approvals_allow_list ON approvals")
    op.execute("DROP FUNCTION IF EXISTS enforce_allow_list()")
    op.execute("ALTER TABLE changes DROP COLUMN IF EXISTS rollback_available")
    op.execute("ALTER TABLE approvals ALTER COLUMN allow_list_check TYPE VARCHAR(16)")
    op.execute("DROP TABLE IF EXISTS approval_decisions")
