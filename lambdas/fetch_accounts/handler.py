"""sas-fetch-accounts: first state of the sync machine. Emits every registered account for the Map fan-out.

Event (from EventBridge or the /api/v1/refresh trigger): {"mode": "full" | "telemetry"}.
Accounts that were UNAVAILABLE are retried every run; that is how they recover.
"""

from common import db

MODES = {"full", "telemetry"}


def lambda_handler(event: dict, _context) -> dict:
    mode = event.get("mode", "telemetry")
    if mode not in MODES:
        raise ValueError(f"unknown sync mode {mode!r}")
    with db.transaction() as cur:
        cur.execute("SELECT account_id, discovery_role_arn, regions FROM accounts ORDER BY account_id")
        accounts = [
            {"account_id": r["account_id"], "discovery_role_arn": r["discovery_role_arn"],
             "regions": list(r["regions"])}
            for r in cur.fetchall()
        ]
    return {"mode": mode, "accounts": accounts}
