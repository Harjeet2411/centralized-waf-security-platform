"""Milestone 3: columns and state the detection / drift / scoring / TI engines need.

* web_acls.current_config - latest full WebACL snapshot (full sync); drift = baseline_config vs current_config.
* accounts.score_evidence - per-dimension evidence behind accounts.security_score (Rule #1).
* waf_events.ingested_at - insertion time; engines process by ingestion watermark so late-arriving
  S3 logs / sampled windows are never skipped.
* engine_state - per-engine watermark + last-run detail.
* detections.fingerprint - type + subject identity so a recurring detection updates instead of duplicating.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-17
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

STATEMENTS = [
    "ALTER TABLE web_acls ADD COLUMN current_config JSONB NOT NULL DEFAULT '{}'::jsonb",
    "ALTER TABLE accounts ADD COLUMN score_evidence JSONB NOT NULL DEFAULT '{}'::jsonb",
    "ALTER TABLE waf_events ADD COLUMN ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()",
    "CREATE INDEX idx_waf_events_ingested ON waf_events(ingested_at)",
    "ALTER TABLE detections ADD COLUMN fingerprint VARCHAR(64)",
    "CREATE INDEX idx_detections_fingerprint ON detections(fingerprint)",
    """CREATE TABLE engine_state (
        engine VARCHAR(64) PRIMARY KEY,
        watermark TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
        last_run_at TIMESTAMPTZ,
        detail JSONB NOT NULL DEFAULT '{}'::jsonb
    )""",
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS engine_state")
    op.execute("DROP INDEX IF EXISTS idx_detections_fingerprint")
    op.execute("ALTER TABLE detections DROP COLUMN IF EXISTS fingerprint")
    op.execute("DROP INDEX IF EXISTS idx_waf_events_ingested")
    op.execute("ALTER TABLE waf_events DROP COLUMN IF EXISTS ingested_at")
    op.execute("ALTER TABLE accounts DROP COLUMN IF EXISTS score_evidence")
    op.execute("ALTER TABLE web_acls DROP COLUMN IF EXISTS current_config")
