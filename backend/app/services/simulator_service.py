"""Rule Impact Simulator + False Positive Analyzer (FR-16, FR-17). Read-only against waf_events: never touches AWS.

A "potential false positive" is a matched request we have no evidence is hostile: classified LEGITIMATE, or
UNKNOWN with no attack technique. On SAMPLED data every count is a lower bound; results say so.
"""

import ipaddress
import json
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Simulation
from app.services.guardrail_service import parse_block_target


class Proposal(BaseModel):
    type: Literal["BLOCK_IPS", "BLOCK_JA4", "RULE_ACTION", "RATE_LIMIT"]
    targets: list[str] = Field(default_factory=list, max_length=500)
    ja4: str | None = Field(None, max_length=64)
    webacl_id: str | None = None
    rule_name: str | None = Field(None, max_length=255)
    new_action: Literal["BLOCK", "COUNT"] | None = None
    limit: int | None = Field(None, ge=10, le=2_000_000_000)

    @model_validator(mode="after")
    def _required_fields(self) -> "Proposal":
        needs = {
            "BLOCK_IPS": ["targets"], "BLOCK_JA4": ["ja4"],
            "RULE_ACTION": ["webacl_id", "rule_name", "new_action"], "RATE_LIMIT": ["webacl_id", "limit"],
        }[self.type]
        missing = [f for f in needs if not getattr(self, f)]
        if missing:
            raise ValueError(f"{self.type} requires {', '.join(missing)}")
        return self


class SimulationRequest(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    proposal: Proposal
    window_hours: int = Field(24, ge=1, le=720)


def _match_clause(p: Proposal) -> tuple[str, dict]:
    if p.type == "BLOCK_IPS":
        nets = [str(parse_block_target(t)) for t in p.targets]
        return "client_ip <<= ANY(CAST(:nets AS cidr[]))", {"nets": nets}
    if p.type == "BLOCK_JA4":
        return "ja4 = :ja4", {"ja4": p.ja4}
    if p.type == "RULE_ACTION":
        flipped = "COUNT" if p.new_action == "BLOCK" else "BLOCK"  # requests the rule currently lets count / blocks
        return ("(matched_rule_name = :rule OR matched_rule_name LIKE :rule_prefix) AND action = :flipped",
                {"rule": p.rule_name, "rule_prefix": f"{p.rule_name}:%", "flipped": flipped})
    # RATE_LIMIT: requests beyond `limit` per IP per 5-minute bucket (the default WAF evaluation window)
    return "rate_rank > :limit", {"limit": p.limit}


def _impact(fp: int, would_block: int) -> str:
    if fp == 0:
        return "NONE"
    rate = fp / would_block if would_block else 1
    return "LOW" if rate < 0.001 else "MEDIUM" if rate < 0.01 else "HIGH"


def _risk_reduction(malicious: int, would_block: int) -> str:
    if malicious >= 100 or (would_block and malicious / would_block >= 0.8 and malicious >= 10):
        return "HIGH"
    return "MEDIUM" if malicious >= 10 else "LOW"


async def simulate(db: AsyncSession, req: SimulationRequest, actor: str,
                   account_scope: frozenset[str] | None = None) -> dict:
    p = req.proposal
    since = datetime.now(UTC) - timedelta(hours=req.window_hours)
    match, params = _match_clause(p)
    scope_sql = ""
    if p.webacl_id:
        scope_sql += " AND webacl_id = CAST(:webacl_id AS uuid)"
        params["webacl_id"] = p.webacl_id
    if account_scope is not None:
        scope_sql += " AND account_id = ANY(:scope)"
        params["scope"] = list(account_scope)
    rate_rank = ("row_number() OVER (PARTITION BY client_ip, date_bin('5 minutes', timestamp, TIMESTAMPTZ 'epoch')"
                 " ORDER BY timestamp)" if p.type == "RATE_LIMIT" else "0")
    sql = f"""
        WITH scoped AS (
            SELECT e.*, {rate_rank} AS rate_rank FROM waf_events e WHERE e.timestamp > :since {scope_sql}
        ), matched AS (
            SELECT s.*, (s.classification = 'LEGITIMATE' OR (s.classification = 'UNKNOWN'
                         AND s.attack_techniques = '{{}}')) AS fp_candidate,
                   EXISTS (SELECT 1 FROM allow_list_entries a WHERE a.is_active AND a.ip_network IS NOT NULL
                           AND s.client_ip <<= a.ip_network) AS protected
            FROM scoped s WHERE {match}
        )
        SELECT (SELECT count(*) FROM scoped) AS evaluated, count(*) AS matched,
               count(*) FILTER (WHERE fp_candidate) AS fp,
               count(*) FILTER (WHERE classification IN ('MALICIOUS', 'SUSPICIOUS')) AS malicious,
               count(*) FILTER (WHERE protected) AS protected_hits,
               coalesce(array_agg(DISTINCT account_id), '{{}}') AS accounts,
               coalesce(array_agg(DISTINCT webacl_id), '{{}}') AS webacls,
               count(*) FILTER (WHERE source = 'FULL_LOG') AS full_log,
               count(*) FILTER (WHERE source = 'SAMPLED') AS sampled
        FROM matched
    """  # noqa: S608 - interpolated fragments are fixed strings chosen above; values are bound
    params["since"] = since
    row = (await db.execute(text(sql), params)).mappings().one()
    samples = [dict(r) | {"timestamp": r["timestamp"].isoformat(), "client_ip": str(r["client_ip"])}
               for r in (await db.execute(text(f"""
        WITH scoped AS (SELECT e.*, {rate_rank} AS rate_rank FROM waf_events e WHERE e.timestamp > :since {scope_sql})
        SELECT timestamp, client_ip, http_method, uri, action, matched_rule_name, classification, source
        FROM scoped WHERE {match} AND (classification = 'LEGITIMATE' OR (classification = 'UNKNOWN'
              AND attack_techniques = '{{}}'))
        ORDER BY timestamp DESC LIMIT 10
    """), params)).mappings()]  # noqa: S608

    blocking = not (p.type == "RULE_ACTION" and p.new_action == "COUNT")
    would_block = row["matched"] if blocking else 0
    would_allow = row["evaluated"] - would_block
    fp = row["fp"] if blocking else 0
    result = {
        "evaluated_requests": row["evaluated"], "would_block": would_block, "would_allow": would_allow,
        "newly_allowed": 0 if blocking else row["matched"],
        "potential_false_positives": fp, "fp_rate_percent": round(100.0 * fp / would_block, 3) if would_block else 0.0,
        "malicious_matched": row["malicious"],
        "legitimate_impact": _impact(fp, would_block),
        "risk_reduction": _risk_reduction(row["malicious"], would_block) if blocking else "LOW",
        "allow_list_passed": row["protected_hits"] == 0, "protected_requests_matched": row["protected_hits"],
        "affected_accounts": list(row["accounts"]), "affected_webacls": [str(w) for w in row["webacls"]],
        "visibility": {"FULL_LOG": row["full_log"], "SAMPLED": row["sampled"]},
        "visibility_note": ("Includes sampled requests: counts are lower bounds (GetSampledRequests)."
                            if row["sampled"] else None),
        "false_positive_samples": samples, "window_hours": req.window_hours,
    }
    sim = Simulation(
        title=req.title, proposed_action=p.type, target_webacl_ids=[w for w in row["webacls"]],
        target_accounts=list(row["accounts"]), target_apps=[], proposed_statement=json.loads(p.model_dump_json()),
        evaluated_requests=row["evaluated"], would_block=would_block, would_allow=would_allow,
        potential_false_positives=fp, fp_rate_percent=result["fp_rate_percent"],
        legitimate_impact=result["legitimate_impact"], risk_reduction=result["risk_reduction"],
        allow_list_passed=result["allow_list_passed"], created_by=actor,
    )
    db.add(sim)
    await db.flush()
    return {"id": str(sim.id), "title": req.title, "proposal": json.loads(p.model_dump_json()), **result}


async def false_positive_candidates(db: AsyncSession, webacl_id: str, window_hours: int = 168) -> list[dict]:
    """Managed (sub-)rules blocking traffic we have no evidence is hostile -> exclusion / scope-down candidates."""
    rows = await db.execute(text("""
        SELECT matched_rule_name, count(*) AS blocked, count(DISTINCT client_ip) AS distinct_ips,
               count(DISTINCT uri) AS distinct_uris, (array_agg(DISTINCT uri))[1:5] AS sample_uris
        FROM waf_events
        WHERE webacl_id = CAST(:w AS uuid) AND action = 'BLOCK' AND timestamp > :since
          AND (classification = 'LEGITIMATE' OR (classification = 'UNKNOWN' AND attack_techniques = '{}'))
          AND matched_rule_name IS NOT NULL
        GROUP BY matched_rule_name ORDER BY count(*) DESC LIMIT 25
    """), {"w": webacl_id, "since": datetime.now(UTC) - timedelta(hours=window_hours)})
    out = []
    for r in rows.mappings():
        rule, _, sub_rule = r["matched_rule_name"].partition(":")
        out.append({**dict(r), "rule_name": rule, "sub_rule": sub_rule or None,
                    "suggested_remediation": "ADD_EXCEPTION (RuleActionOverride COUNT for the sub-rule)" if sub_rule
                    else "Scope-down statement or COUNT while tuning"})
    return out


def validate_ip_targets(targets: list[str]) -> list[str]:
    return [str(parse_block_target(t)) for t in targets]


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def assert_simulation_covers(sim: Simulation | None, op: str, targets: list[str], max_age_hours: int = 24) -> None:
    """Lifecycle step SIMULATE: the approval must cite a recent, guardrail-clean simulation of the same change."""
    if sim is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "A simulation of this change is required")
    if sim.created_at < datetime.now(UTC) - timedelta(hours=max_age_hours):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Simulation is older than 24h; re-run it")
    if not sim.allow_list_passed:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Simulation matched protected (allow-listed) traffic")
    expected = {"ip_set_add": "BLOCK_IPS", "set_rule_action": "RULE_ACTION", "set_rate_limit": "RATE_LIMIT",
                "add_exception": "RULE_ACTION"}.get(op)
    if expected and sim.proposed_action != expected:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            f"Simulation {sim.proposed_action} does not match change type {expected}")
    if op == "ip_set_add":
        simulated = {str(ipaddress.ip_network(t, strict=False)) for t in sim.proposed_statement.get("targets", [])}
        if not set(targets) <= simulated:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Block targets were not all simulated")
