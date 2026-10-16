"""GET /api/v1/bootstrap: hydrates the frontend store from PostgreSQL. No synthetic values: every field is
a column, a SQL aggregate over real rows, or an explicit "no data yet" (0 / "" / empty list)."""

from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import any_, case, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Account,
    Approval,
    Campaign,
    Detection,
    DriftEvent,
    Endpoint,
    Entity,
    ManagedRuleVersion,
    PlatformHealth,
    Rule,
    ThreatIntelligence,
    WebAcl,
)
from app.schemas import contract as c
from app.services.approval_service import approval_out

ENTITY_LIMIT = 500  # highest-risk entities only; full list is paginated via /api/v1/entities (M3)
FEED_LIMIT = 200


def _pct(numerator: int, denominator: int) -> float:
    return round(100.0 * numerator / denominator, 2) if denominator else 0.0


def _age(ts: datetime | None, now: datetime) -> str:
    if ts is None:
        return "no sync yet"
    minutes = int((now - ts).total_seconds() // 60)
    return f"{minutes} min ago" if minutes < 120 else f"{minutes // 60} h ago"



POSTURE_KEYS = {  # WAF score dimension -> SecurityPosture key in src/types/index.ts ("count_exposure" is contract+)
    "coverage": ("waf_coverage", "WAF Coverage"), "blocking": ("rule_effectiveness", "Blocking Effectiveness"),
    "malicious_allowed": ("threat_exposure", "Malicious Allowed"),
    "count_exposure": ("count_exposure", "COUNT Exposure"),
    "drift": ("config_hygiene", "Configuration Drift"),
    "managed_versions": ("managed_rule_health", "Managed Rule Currency"),
    "logging": ("logging_visibility", "Logging Visibility"),
}


def build_posture(accounts, exposed: dict, protected: dict) -> list[dict]:
    """Platform posture = mean of scored accounts' dimensions; coverage is recomputed globally from endpoints."""
    scored = [a for a in accounts if (a.score_evidence or {}).get("dimensions")]
    if not scored:
        return []
    total_exposed, total_protected = sum(exposed.values()), sum(protected.values())
    out = []
    for dim, (key, label) in POSTURE_KEYS.items():
        if dim == "coverage":
            value = _pct(total_protected, total_exposed) if total_exposed else 100.0
            why = [{"label": "Internet-facing endpoints with a WebACL", "value": total_protected, "positive": True},
                   {"label": "Internet-facing endpoints without a WebACL", "value": total_exposed - total_protected,
                    "positive": False}]
        else:
            values = [a.score_evidence["dimensions"][dim]["value"] for a in scored]
            value = round(sum(values) / len(values), 2)
            why = [{"label": a.name, "value": a.score_evidence["dimensions"][dim]["value"],
                    "positive": a.score_evidence["dimensions"][dim]["value"] >= 70} for a in scored[:10]]
        out.append({"key": key, "label": label, "value": value, "why": why, "evidence_count": len(scored)})
    overall = sum(float(a.security_score) for a in scored) / len(scored)
    out.append({"key": "overall", "label": "Overall WAF Security Score", "value": round(overall, 2), "why": [],
                "evidence_count": len(scored)})
    return out

def rule_out(r: Rule) -> c.WafRuleOut:
    return c.WafRuleOut(
        id=str(r.id), webacl_id=str(r.webacl_id), name=r.name,
        type="managed" if r.type == "MANAGED" else "custom", action=r.action, priority=r.priority,
        managed_group=r.managed_group_name, managed_version=r.current_version, latest_version=r.available_version,
        match_count=r.matches_24h, blocked=r.blocked_24h, counted=r.counted_24h,
        allowed=max(0, r.matches_24h - r.blocked_24h - r.counted_24h),
        false_positives=r.false_positives_30d, effectiveness=float(r.effectiveness),
        scope_down=r.scope_down_statement, rate_limit=r.rate_limit,
        version_status=c.lower(r.version_status), last_modified=c.iso(r.updated_at), rule_type=r.type,
    )

async def entities_out(db: AsyncSession, entities) -> list[c.EntityOut]:
    """Map Entity rows to the contract, loading their TI results and campaign membership."""
    entity_ids = [e.id for e in entities]
    ti_by_entity: dict = defaultdict(list)
    campaigns_by_entity: dict = defaultdict(list)
    if entity_ids:
        ti_rows = await db.scalars(select(ThreatIntelligence).where(ThreatIntelligence.entity_id.in_(entity_ids)))
        for ti in ti_rows.all():
            ti_by_entity[ti.entity_id].append(c.ThreatIntelOut(
                source=c.TI_SOURCE[ti.provider], score=float(ti.score), classification=ti.classification,
                confidence=c.confidence_band(ti.confidence), timestamp=c.iso(ti.last_checked),
                expires_at=c.iso(ti.expires_at),
            ))
        for entity_id, code in (await db.execute(
            select(Entity.id, Campaign.campaign_code)
            .join(Campaign, Entity.id == any_(Campaign.entity_ids))
            .where(Entity.id.in_(entity_ids))
        )).all():
            campaigns_by_entity[entity_id].append(code)

    return [
        c.EntityOut(
            id=str(e.id), type=c.ENTITY_TYPE[e.type], value=e.value, label=e.organization or e.value,
            threat_score=float(e.threat_score), confidence=c.confidence_band(e.confidence),
            risk_level=c.RISK_LEVEL[e.risk_level], country=e.country, asn=e.asn, organization=e.organization,
            ja3=e.ja3, ja4=e.ja4, user_agent=e.user_agent, first_seen=c.iso(e.first_seen), last_seen=c.iso(e.last_seen),
            request_count=e.request_count, uri_diversity=len(e.targeted_uris or []),
            not_found_ratio=float(e.meta.get("not_found_ratio", 0.0)), applications=list(e.targeted_apps or []),
            webacls=list(e.meta.get("webacls", [])), campaigns=campaigns_by_entity.get(e.id, []),
            techniques=list(e.attack_techniques or []), threat_intel=ti_by_entity.get(e.id, []),
            confidence_score=float(e.confidence), business_impact=float(e.business_impact),
            final_risk=float(e.final_risk), classification=e.classification, is_allow_listed=e.is_allow_listed,
        )
        for e in entities
    ]



async def campaigns_out(db: AsyncSession, campaigns) -> list[c.CampaignOut]:
    member_counts: dict = defaultdict(dict)
    webacl_counts: dict = {}
    if campaigns:
        member_q = (
            select(Campaign.id, Entity.type, func.count())
            .select_from(Campaign).join(Entity, Entity.id == any_(Campaign.entity_ids))
            .where(Campaign.id.in_([cp.id for cp in campaigns]))
            .group_by(Campaign.id, Entity.type)
        )
        for campaign_id, etype, n in (await db.execute(member_q)).all():
            member_counts[campaign_id][etype] = n
        webacl_counts = dict((await db.execute(text(
            "SELECT cp.id, count(DISTINCT we.webacl_id) FROM campaigns cp "
            "JOIN entities e ON e.id = ANY(cp.entity_ids) AND e.type = 'IP' "
            "JOIN waf_events we ON we.client_ip = e.value::inet "
            " AND we.timestamp BETWEEN cp.start_time AND cp.last_active "
            "WHERE cp.id = ANY(:ids) GROUP BY cp.id"
        ), {"ids": [cp.id for cp in campaigns]})).all())

    return [
        c.CampaignOut(
            id=str(cp.id), name=cp.name, type=c.DETECTION_TYPE.get(cp.type, cp.type.lower()),
            risk_level=c.RISK_LEVEL[cp.risk_level], confidence=c.confidence_band(cp.confidence),
            first_seen=c.iso(cp.start_time), last_seen=c.iso(cp.last_active),
            ip_count=member_counts[cp.id].get("IP", 0), asn_count=len(cp.asns or []),
            country_count=len(cp.countries or []), ja4_count=member_counts[cp.id].get("JA4", 0),
            application_count=len(cp.targeted_apps or []), webacl_count=webacl_counts.get(cp.id, 0),
            account_count=len(cp.targeted_accounts or []), technique_count=len(cp.techniques or []),
            waf_action_breakdown={
                "BLOCK": cp.blocked_requests, "ALLOW": cp.allowed_requests,
                "COUNT": max(0, cp.total_requests - cp.blocked_requests - cp.allowed_requests),
            },
            description=cp.attack_story, status=c.CAMPAIGN_STATUS[cp.status], campaign_code=cp.campaign_code,
            recommended_action=cp.recommended_action,
        )
        for cp in campaigns
    ]



async def build_bootstrap(db: AsyncSession) -> c.BootstrapOut:
    now = datetime.now(UTC)
    accounts = (await db.scalars(select(Account).order_by(Account.name))).all()
    account_names = {a.account_id: a.name for a in accounts}

    # --- endpoints + per-account coverage ---------------------------------------------------------
    endpoint_rows = (
        await db.execute(
            select(Endpoint, WebAcl.arn).outerjoin(WebAcl, Endpoint.webacl_id == WebAcl.id).order_by(Endpoint.name)
        )
    ).all()
    exposed: dict[str, int] = defaultdict(int)
    protected: dict[str, int] = defaultdict(int)
    endpoint_count: dict[str, int] = defaultdict(int)
    endpoints_out = []
    for ep, waf_arn in endpoint_rows:
        endpoint_count[ep.account_id] += 1
        if ep.internet_facing:
            exposed[ep.account_id] += 1
            protected[ep.account_id] += ep.webacl_id is not None
        endpoints_out.append(c.EndpointOut(
            id=str(ep.id), account_id=ep.account_id, account_name=account_names.get(ep.account_id, ""),
            name=ep.name, type=c.ENDPOINT_TYPE[ep.type], dns_name=ep.dns_name, internet_facing=ep.internet_facing,
            waf_enabled=ep.webacl_id is not None, waf_arn=waf_arn, logging_enabled=ep.logging_enabled,
            status=ep.waf_status.lower(), region=ep.region, visibility_level=ep.visibility_level,
        ))

    # --- web ACLs with derived rule/drift/managed-version aggregates ------------------------------
    rule_counts = dict((await db.execute(select(Rule.webacl_id, func.count()).group_by(Rule.webacl_id))).all())
    drift_counts = dict((await db.execute(
        select(DriftEvent.webacl_id, func.count()).where(DriftEvent.status != "RESOLVED").group_by(DriftEvent.webacl_id)
    )).all())
    managed_health = {
        webacl_id: _pct(current, total)
        for webacl_id, current, total in (await db.execute(
            select(
                ManagedRuleVersion.webacl_id,
                func.count().filter(ManagedRuleVersion.version_status == "CURRENT"),
                func.count(),
            ).group_by(ManagedRuleVersion.webacl_id)
        )).all()
    }
    webacls = (await db.scalars(select(WebAcl).order_by(WebAcl.name))).all()
    webacl_count: dict[str, int] = defaultdict(int)
    webacls_out = []
    for w in webacls:
        webacl_count[w.account_id] += 1
        webacls_out.append(c.WebACLOut(
            id=str(w.id), account_id=w.account_id, account_name=account_names.get(w.account_id, ""), name=w.name,
            arn=w.arn, scope=w.scope, default_action=w.default_action, security_score=float(w.security_score),
            managed_rule_health=managed_health.get(w.id, 0.0), drift_count=drift_counts.get(w.id, 0),
            rule_count=rule_counts.get(w.id, 0), logging_enabled=w.logging_enabled, region=w.region,
            score_confidence=w.score_confidence, visibility_level=w.visibility_level, score_evidence=w.score_evidence,
        ))

    accounts_out = [
        c.AWSAccountOut(
            id=str(a.id), account_id=a.account_id, name=a.name, environment=c.ACCOUNT_ENV[a.environment],
            owner=a.owner, status=a.status.lower(), last_discovered=c.iso(a.last_discovered),
            waf_coverage=_pct(protected[a.account_id], exposed[a.account_id]),
            security_score=float(a.security_score), endpoint_count=endpoint_count[a.account_id],
            webacl_count=webacl_count[a.account_id], logging_visibility=a.visibility_level,
            region=(a.regions or ["us-east-1"])[0], score_confidence=a.score_confidence, regions=list(a.regions or []),
        )
        for a in accounts
    ]

    # --- rules grouped by web ACL -----------------------------------------------------------------
    rules_out: dict[str, list[c.WafRuleOut]] = defaultdict(list)
    for r in (await db.scalars(select(Rule).order_by(Rule.webacl_id, Rule.priority))).all():
        rules_out[str(r.webacl_id)].append(rule_out(r))

    # --- entities + campaigns ----------------------------------------------------------------------
    entities = (await db.scalars(
        select(Entity).order_by(Entity.final_risk.desc(), Entity.last_seen.desc()).limit(ENTITY_LIMIT)
    )).all()
    entities_list = await entities_out(db, entities)
    campaigns = (await db.scalars(select(Campaign).order_by(Campaign.last_active.desc()).limit(FEED_LIMIT))).all()
    campaigns_list = await campaigns_out(db, campaigns)

    detections_out = [
        c.DetectionOut(
            id=str(d.id), type=c.DETECTION_TYPE[d.type], severity=d.severity.lower(), title=d.title,
            description=d.description, timestamp=c.iso(d.timestamp), entity_ids=[str(x) for x in d.entity_ids],
            campaign_id=str(d.campaign_id) if d.campaign_id else None, evidence_count=len(d.evidence),
            confidence=float(d.confidence), affected_apps=list(d.applications), affected_accounts=list(d.accounts),
            status="correlated" if d.status == "OPEN" and d.campaign_id else c.DETECTION_STATUS[d.status],
            evidence=[c.DetectionEvidenceOut(**ev) for ev in d.evidence], recommended_action=d.recommended_action,
        )
        for d in (await db.scalars(select(Detection).order_by(Detection.timestamp.desc()).limit(FEED_LIMIT))).all()
    ]

    drift_out = [
        c.DriftEventOut(
            id=str(dr.id), webacl_id=str(dr.webacl_id), webacl_name=dr.webacl_name, account_id=dr.account_id,
            drift_type=dr.drift_type, severity=dr.severity.lower(),
            description=f"{dr.drift_type.replace('_', ' ').title()} on {dr.webacl_name}",
            expected=dr.expected_state, actual=dr.actual_state, detected_at=c.iso(dr.detected_at),
            status=c.DRIFT_STATUS[dr.status], drift_code=dr.drift_code,
        )
        for dr in (await db.scalars(select(DriftEvent).order_by(DriftEvent.detected_at.desc()).limit(FEED_LIMIT))).all()
    ]

    pending_first = case((Approval.status == "PENDING", 0), else_=1)
    approvals_out = [approval_out(ap) for ap in (await db.scalars(
        select(Approval).order_by(pending_first, Approval.requested_at.desc()).limit(FEED_LIMIT)
    )).all()]

    return c.BootstrapOut(
        accounts=accounts_out, endpoints=endpoints_out, webacls=webacls_out, rules=dict(rules_out),
        entities=entities_list, campaigns=campaigns_list, detections=detections_out, drift_events=drift_out,
        approvals=approvals_out, platform_health=await build_platform_health(db, accounts, now),
        posture_dimensions=build_posture(accounts, exposed, protected), generated_at=now.isoformat(),
    )


async def build_platform_health(db: AsyncSession, accounts, now: datetime) -> c.PlatformHealthOut:
    rows = (await db.scalars(select(PlatformHealth))).all()
    components = {r.component: r for r in rows if r.account_id is None}
    collectors = {r.account_id: r for r in rows if r.component == "collector" and r.account_id}

    def component(name: str) -> c.ComponentHealthOut:
        row = components.get(name)
        if row is None:
            return c.ComponentHealthOut(status="unavailable", detail="No health report received yet", last_check="")
        return c.ComponentHealthOut(status=row.status.lower(), detail=row.detail, last_check=c.iso(row.last_check))

    collectors_out = []
    for a in accounts:
        row = collectors.get(a.account_id)
        collectors_out.append(c.CollectorHealthOut(
            account_id=a.account_id, account_name=a.name,
            status=(row.status if row else a.status).lower(),
            last_success=c.iso(row.last_success if row else a.last_discovered),
            error=row.error if row else a.last_error,
            affected_modules=list(row.affected_modules) if row else [],
        ))

    # The database is answering this very request, so it is healthy by construction.
    database = c.ComponentHealthOut(status="healthy", detail="PostgreSQL reachable", last_check=now.isoformat())
    parts = [component(n) for n in ("aws_api", "queue", "workers", "threat_intel")]
    statuses = [p.status for p in parts] + [col.status for col in collectors_out]
    overall = "critical" if "unavailable" in statuses else "degraded" if "degraded" in statuses else "healthy"
    last_sync = max((a.last_discovered for a in accounts if a.last_discovered), default=None)
    return c.PlatformHealthOut(
        overall=overall, collectors=collectors_out, aws_api=parts[0], queue=parts[1], workers=parts[2],
        database=database, threat_intel=parts[3], last_sync=c.iso(last_sync), data_freshness=_age(last_sync, now),
    )
