"""sas-mark-account-degraded: ASL Catch target when an account's collector failed after retries.

Event: {"account": {...}, "mode": ..., "error": {"Error": "<exception class>", "Cause": "<json>"}}
AccountAccessError (role can't be assumed) -> UNAVAILABLE with confidence NONE (Rule #4: we know nothing
current about that account). Anything else -> DEGRADED; previous data stays but is flagged stale.
Returns normally so the other 38 accounts' Map iterations are unaffected.
"""

import json

from common import db

UNREACHABLE_ERRORS = {"AccountAccessError"}


def lambda_handler(event: dict, _context) -> dict:
    account_id = event["account"]["account_id"]
    error = event.get("error", {})
    error_type = error.get("Error", "Unknown")
    try:
        message = json.loads(error.get("Cause", "{}")).get("errorMessage", "")
    except (TypeError, ValueError):
        message = str(error.get("Cause", ""))
    status = "UNAVAILABLE" if error_type in UNREACHABLE_ERRORS else "DEGRADED"
    detail = f"{error_type}: {message}"[:4000]

    with db.transaction() as cur:
        if status == "UNAVAILABLE":
            cur.execute(
                "UPDATE accounts SET status = %s, last_error = %s, score_confidence = 'NONE',"
                " visibility_level = 'none',"
                " updated_at = now() WHERE account_id = %s",
                (status, detail, account_id),
            )
        else:
            cur.execute(
                "UPDATE accounts SET status = %s, last_error = %s, updated_at = now() WHERE account_id = %s",
                (status, detail, account_id),
            )
        db.upsert_health(
            cur, component="collector", account_id=account_id, status=status, detail=f"{event.get('mode')} sync failed",
            error=detail, affected_modules=["all"], success=False,
        )
    return {"account_id": account_id, "status": status, "error": error_type}
