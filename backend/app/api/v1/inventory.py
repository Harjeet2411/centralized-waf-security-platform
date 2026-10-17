"""Read APIs behind the WAF Security, Entities, Investigation and Campaign views (Milestone 3)."""

import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import any_, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Account, Campaign, Endpoint, Entity, Rule, WebAcl
from app.schemas import contract as c
from app.security import Principal, require
from app.services.bootstrap_service import campaigns_out, entities_out, rule_out

router = APIRouter(tags=["inventory"])

EVENT_FILTER = {  # entity type -> waf_events predicate
    "IP": "client_ip = CAST(:value AS inet)", "JA4": "ja4 = :value", "JA3": "ja3 = :value",
    "ASN": "asn = :value", "USER_AGENT": "user_agent = :value",
}


def _scope_filter(principal: Principal, permission: str):
    """None = all accounts; else the account ids this principal may see for `permission`."""
    return principal.account_scope(permission)


@router.get("/webacls", response_model=list[c.WebACLDetailOut])
async def list_webacls(
    account_id: str | None = None, _: Principal = Depends(require("VIEW")), db: AsyncSession = Depends(get_db)
):
    query = select(WebAcl, Account.name).join(Account, Account.account_id == WebAcl.account_id).order_by(WebAcl.name)
    if account_id:
        query = query.where(WebAcl.account_id == account_id)
    rows = (await db.execute(query)).all()
    ids = [w.id for w, _ in rows]
    rules: dict = defaultdict(list)
    for r in (await db.scalars(select(Rule).where(Rule.webacl_id.in_(ids)).order_by(Rule.priority))).all():
        rules[r.webacl_id].append(rule_out(r))
    drift = dict((await db.execute(text(
        "SELECT webacl_id, count(*) FROM drift_events WHERE status <> 'RESOLVED' AND webacl_id = ANY(:ids)"
        " GROUP BY webacl_id"), {"ids": ids})).all())
    managed = {wid: (cur, tot) for wid, cur, tot in (await db.execute(text(
        "SELECT webacl_id, count(*) FILTER (WHERE version_status = 'CURRENT'), count(*) FROM managed_rule_versions"
        " WHERE webacl_id = ANY(:ids) GROUP BY webacl_id"), {"ids": ids})).all()}
    out = []
    for w, account_name in rows:
        current, total = managed.get(w.id, (0, 0))
        out.append(c.WebACLDetailOut(
            id=str(w.id), account_id=w.account_id, account_name=account_name, name=w.name, arn=w.arn, scope=w.scope,
            default_action=w.default_action, security_score=float(w.security_score),
            managed_rule_health=round(100.0 * current / total, 2) if total else 0.0, drift_count=drift.get(w.id, 0),
            rule_count=len(rules[w.id]), logging_enabled=w.logging_enabled, region=w.region,
            score_confidence=w.score_confidence, visibility_level=w.visibility_level, score_evidence=w.score_evidence,
            requests_24h=w.requests_24h,
            rules=rules[w.id],
        ))
    return out


@router.get("/endpoints", response_model=list[c.EndpointOut])
async def list_endpoints(
    account_id: str | None = None, waf_status: str | None = None, internet_facing: bool | None = None,
    _: Principal = Depends(require("VIEW")), db: AsyncSession = Depends(get_db),
):
    query = (select(Endpoint, WebAcl.arn, Account.name)
             .join(Account, Account.account_id == Endpoint.account_id)
             .outerjoin(WebAcl, WebAcl.id == Endpoint.webacl_id).order_by(Endpoint.name))
    if account_id:
        query = query.where(Endpoint.account_id == account_id)
    if waf_status:
        query = query.where(Endpoint.waf_status == waf_status.upper())
    if internet_facing is not None:
        query = query.where(Endpoint.internet_facing == internet_facing)
    return [
        c.EndpointOut(
            id=str(ep.id), account_id=ep.account_id, account_name=account_name, name=ep.name,
            type=c.ENDPOINT_TYPE[ep.type], dns_name=ep.dns_name, internet_facing=ep.internet_facing,
            waf_enabled=ep.webacl_id is not None, waf_arn=arn, logging_enabled=ep.logging_enabled,
            status=ep.waf_status.lower(), region=ep.region, visibility_level=ep.visibility_level,
        )
        for ep, arn, account_name in (await db.execute(query)).all()
    ]


@router.get("/entities", response_model=c.Page)
async def list_entities(
    type: str | None = Query(None, description="IP | ASN | JA3 | JA4 | USER_AGENT"),  # noqa: A002
    risk_level: str | None = None, q: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
    _: Principal = Depends(require("VIEW")), db: AsyncSession = Depends(get_db),
):
    query = select(Entity)
    if type:
        query = query.where(Entity.type == type.upper())
    if risk_level:
        query = query.where(Entity.risk_level == risk_level.upper())
    if q:
        like = f"%{q.replace('%', r'\%').replace('_', r'\_')}%"
        query = query.where(Entity.value.ilike(like) | Entity.organization.ilike(like) | Entity.asn.ilike(like))
    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    rows = (await db.scalars(
        query.order_by(Entity.final_risk.desc(), Entity.last_seen.desc()).limit(limit).offset(offset)
    )).all()
    return c.Page(items=await entities_out(db, rows), total=total, limit=limit, offset=offset)


@router.get("/entities/{entity_id}", response_model=c.EntityDetailOut)
async def entity_detail(
    entity_id: uuid.UUID, principal: Principal = Depends(require("INVESTIGATE")), db: AsyncSession = Depends(get_db)
):
    entity = await db.get(Entity, entity_id)
    scope = _scope_filter(principal, "INVESTIGATE")
    if entity is None or (scope is not None and not set(entity.targeted_accounts or []) & scope):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Entity not found")
    [entity_contract] = await entities_out(db, [entity])
    predicate = EVENT_FILTER.get(entity.type)
    since = datetime.now(UTC) - timedelta(days=7)
    params = {"value": entity.value, "since": since}

    nodes = {str(entity.id): c.GraphNode(id=str(entity.id), type=c.ENTITY_TYPE[entity.type], label=entity.value,
                                         risk_level=c.RISK_LEVEL[entity.risk_level])}
    edges: list[c.GraphEdge] = []
    rels = (await db.execute(text(
        "SELECT r.source_entity_id, r.target_entity_id, r.relationship_type, r.observation_count,"
        " s.type AS s_type, s.value AS s_value, s.risk_level AS s_risk,"
        " t.type AS t_type, t.value AS t_value, t.risk_level AS t_risk"
        " FROM entity_relationships r JOIN entities s ON s.id = r.source_entity_id"
        " JOIN entities t ON t.id = r.target_entity_id"
        " WHERE r.source_entity_id = :id OR r.target_entity_id = :id"
        "  OR (r.relationship_type = 'USES_JA4' AND r.target_entity_id IN ("  # second hop: IPs sharing this IP's JA4
        "      SELECT target_entity_id FROM entity_relationships WHERE source_entity_id = :id"
        "      AND relationship_type = 'USES_JA4'))"
        " ORDER BY r.observation_count DESC LIMIT 200"), {"id": entity.id})).mappings().all()
    for r in rels:
        for side in ("s", "t"):
            node_id = str(r["source_entity_id" if side == "s" else "target_entity_id"])
            nodes.setdefault(node_id, c.GraphNode(id=node_id, type=c.ENTITY_TYPE[r[f"{side}_type"]],
                                                  label=r[f"{side}_value"], risk_level=c.RISK_LEVEL[r[f"{side}_risk"]]))
        edges.append(c.GraphEdge(source=str(r["source_entity_id"]), target=str(r["target_entity_id"]),
                                 type=r["relationship_type"], count=r["observation_count"]))

    timeline, recent, visibility, explanations = [], [], {}, []
    if predicate:
        by_webacl = (await db.execute(text(
            f"SELECT e.webacl_id, w.name, count(*) FILTER (WHERE e.action = 'BLOCK') AS blocked,"  # noqa: S608
            f" count(*) FILTER (WHERE e.action = 'ALLOW') AS allowed,"
            f" count(*) FILTER (WHERE e.action = 'ALLOW' AND e.classification = 'MALICIOUS') AS malicious_allowed"
            f" FROM waf_events e JOIN web_acls w ON w.id = e.webacl_id WHERE {predicate} AND e.timestamp > :since"
            f" GROUP BY e.webacl_id, w.name"), params)).mappings().all()
        for row in by_webacl:
            node_id = f"webacl:{row['webacl_id']}"
            nodes.setdefault(node_id, c.GraphNode(id=node_id, type="webacl", label=row["name"]))
            for kind, count in (("BLOCKED", row["blocked"]), ("MALICIOUS_ALLOWED", row["malicious_allowed"]),
                                ("ALLOWED", row["allowed"] - row["malicious_allowed"])):
                if count:
                    edges.append(c.GraphEdge(source=str(entity.id), target=node_id, type=kind, count=count))
        timeline = [dict(r) | {"bucket": r["bucket"].isoformat()} for r in (await db.execute(text(
            f"SELECT date_trunc('hour', timestamp) AS bucket,"  # noqa: S608
            f" count(*) FILTER (WHERE action = 'BLOCK') AS \"BLOCK\", count(*) FILTER (WHERE action = 'ALLOW') AS"
            f" \"ALLOW\", count(*) FILTER (WHERE action = 'COUNT') AS \"COUNT\""
            f" FROM waf_events WHERE {predicate} AND timestamp > :since GROUP BY 1 ORDER BY 1"), params)).mappings()]
        recent = [dict(r) | {"timestamp": r["timestamp"].isoformat(), "client_ip": str(r["client_ip"])}
                  for r in (await db.execute(text(
                      f"SELECT timestamp, client_ip, http_method, host, uri, action, matched_rule_name, ja4,"  # noqa: S608
                      f" source, classification, account_id FROM waf_events WHERE {predicate}"
                      f" ORDER BY timestamp DESC LIMIT 50"), params)).mappings()]
        visibility = dict((await db.execute(text(
            f"SELECT source, count(*) FROM waf_events WHERE {predicate} AND timestamp > :since"  # noqa: S608
            f" GROUP BY source"), params)).all())
        for row in by_webacl:
            if not row["allowed"]:
                continue
            webacl = await db.get(WebAcl, row["webacl_id"])
            matched = [m for (m,) in (await db.execute(text(
                f"SELECT DISTINCT matched_rule_name FROM waf_events WHERE {predicate}"  # noqa: S608
                f" AND webacl_id = :w AND action IN ('ALLOW', 'COUNT') AND timestamp > :since"
                f" AND matched_rule_name IS NOT NULL"), params | {"w": row["webacl_id"]})).all()]
            count_rules = [n for (n,) in (await db.execute(
                select(Rule.name).where(Rule.webacl_id == row["webacl_id"], Rule.action == "COUNT"))).all()]
            drift = [dict(d) for d in (await db.execute(text(
                "SELECT drift_code, drift_type, severity, expected_state, actual_state FROM drift_events"
                " WHERE webacl_id = :w AND status <> 'RESOLVED' ORDER BY detected_at DESC"),
                {"w": row["webacl_id"]})).mappings()]
            explanations.append(c.AllowedExplanation(
                webacl_id=str(row["webacl_id"]), webacl_name=row["name"], allowed_requests=row["allowed"],
                default_action=webacl.default_action, matched_rules=matched, count_mode_rules=count_rules,
                open_drift=drift,
            ))

    for campaign_id, code, risk in (await db.execute(
        select(Campaign.id, Campaign.campaign_code, Campaign.risk_level).where(entity.id == any_(Campaign.entity_ids))
    )).all():
        node_id = f"campaign:{campaign_id}"
        nodes[node_id] = c.GraphNode(id=node_id, type="campaign", label=code, risk_level=c.RISK_LEVEL[risk])
        edges.append(c.GraphEdge(source=str(entity.id), target=node_id, type="CAMPAIGN_MEMBER", count=1))

    return c.EntityDetailOut(
        entity=entity_contract, graph={"nodes": [n.model_dump() for n in nodes.values()],
                                       "edges": [e.model_dump() for e in edges]},
        timeline=timeline, recent_events=recent, allowed_explanations=explanations, visibility=visibility,
        recommended_action=entity.recommended_action,
    )


@router.get("/campaigns", response_model=list[c.CampaignOut])
async def list_campaigns(
    status_filter: str | None = Query(None, alias="status"), _: Principal = Depends(require("VIEW")),
    db: AsyncSession = Depends(get_db),
):
    query = select(Campaign).order_by(Campaign.last_active.desc()).limit(500)
    if status_filter:
        query = query.where(Campaign.status == status_filter.upper())
    return await campaigns_out(db, (await db.scalars(query)).all())


@router.get("/campaigns/{campaign_id}", response_model=c.CampaignDetailOut)
async def campaign_detail(
    campaign_id: uuid.UUID, principal: Principal = Depends(require("INVESTIGATE")), db: AsyncSession = Depends(get_db)
):
    campaign = await db.get(Campaign, campaign_id)
    scope = _scope_filter(principal, "INVESTIGATE")
    if campaign is None or (scope is not None and not set(campaign.targeted_accounts or []) & scope):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Campaign not found")
    members = (await db.scalars(
        select(Entity).where(Entity.id.in_(campaign.entity_ids)).order_by(Entity.final_risk.desc())
    )).all()
    [campaign_contract] = await campaigns_out(db, [campaign])
    return c.CampaignDetailOut(
        campaign=campaign_contract, correlation_evidence=list(campaign.correlation_evidence),
        members=await entities_out(db, members), targeted_uris=list(campaign.targeted_uris or []),
        techniques=list(campaign.techniques or []),
    )
