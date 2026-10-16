"""Controlled Response Engine: the 12-step lifecycle for every AWS-changing action (Rule #2).

DETECT/UNDERSTAND/CORRELATE/SCORE happen upstream (engines + investigation). This module enforces
SIMULATE -> CHECK GUARDRAILS -> REQUEST APPROVAL -> APPROVE -> EXECUTE -> VERIFY -> AUDIT -> ROLLBACK.

Tiered approval policy (PRD FR-19, CLAUDE.md section 9):
  TEMP_BLOCK_IP <= 1h                          -> Security Analyst (APPROVE:TEMP_BLOCK) or Security Admin
  TEMP_BLOCK_IP > 1h, PERM_BLOCK_IP, REMOVE_BLOCK -> Security Admin
  MODIFY_RULE, MODIFY_RATE_LIMIT, ADD_EXCEPTION, REMEDIATE_DRIFT -> Security Admin + Application Owner (scoped)
  ATTACH_WAF                                   -> Security Admin + (Application Owner or AWS Administrator)
Requesters never approve their own change, one person fills at most one slot, approvers need an MFA session.
"""

import asyncio
import ipaddress
import json
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Account, Approval, ApprovalDecision, Change, DriftEvent, Endpoint, Rule, Simulation, WebAcl
from app.schemas import contract as c
from app.security import Principal
from app.services import audit_service, guardrail_service, rbac_service
from app.services.aws_executor import ExecutionError, ExecutionResult, WafExecutor, assume_response_role
from app.services.simulator_service import assert_simulation_covers

ActionType = Literal["TEMP_BLOCK_IP", "PERM_BLOCK_IP", "REMOVE_BLOCK", "MODIFY_RULE", "ADD_EXCEPTION",
                     "MODIFY_RATE_LIMIT", "ATTACH_WAF", "REMEDIATE_DRIFT"]
BLOCK_ACTIONS = {"TEMP_BLOCK_IP", "PERM_BLOCK_IP"}
BLOCKLIST_RULE_PREFIX = "SAS-Platform-Block"  # the WebACL rule referencing the platform-managed IP set
# SIMULATE is mandatory where the change can newly block or newly allow traffic. REMEDIATE_DRIFT restores an
# already-approved baseline and ATTACH_WAF/REMOVE_BLOCK have no historical traffic to replay; their lifecycle shows
# SIMULATE as "skipped" (a simulation can still be attached).
SIMULATION_REQUIRED = {"TEMP_BLOCK_IP", "PERM_BLOCK_IP", "MODIFY_RULE", "MODIFY_RATE_LIMIT", "ADD_EXCEPTION"}
WEBACL_OPS = {"set_rule_action", "set_rate_limit", "add_exception", "restore_rule"}

ExecutorFactory = Callable[[str, str, str, str], WafExecutor]  # (role_arn, account_id, approval_code, approver)


def default_executor_factory(role_arn: str, account_id: str, approval_code: str, approver: str) -> WafExecutor:
    return WafExecutor(assume_response_role(role_arn, account_id, approval_code, approver))


# --- policy ---------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Slot:
    label: str
    qualifiers: frozenset[str]  # APPROVE qualifiers that satisfy this slot ("*" = unqualified = Security Admin)

    def accepts(self, principal: Principal, account_id: str) -> bool:
        held = rbac_service.qualifiers(principal.permissions, "APPROVE") & self.qualifiers
        if held == {"APP_RULES"} and account_id not in principal.scoped_account_ids:
            return False  # an Application Owner approves only for accounts they own
        return bool(held)


ADMIN = Slot("Security Admin", frozenset({"*"}))


def policy(action_type: str, ttl_hours: int | None) -> list[Slot]:
    if action_type == "TEMP_BLOCK_IP" and ttl_hours is not None and ttl_hours <= 1:
        return [Slot("Security Analyst or Security Admin", frozenset({"*", "TEMP_BLOCK"}))]
    if action_type in ("TEMP_BLOCK_IP", "PERM_BLOCK_IP", "REMOVE_BLOCK"):
        return [ADMIN]
    if action_type == "ATTACH_WAF":
        return [ADMIN, Slot("Application Owner or AWS Administrator", frozenset({"APP_RULES", "INFRA"}))]
    return [ADMIN, Slot("Application Owner", frozenset({"APP_RULES"}))]


# --- request ------------------------------------------------------------------------------------------

class ApprovalRequest(BaseModel):
    action_type: ActionType
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    reason: str = Field(min_length=10, max_length=2000)
    target: str | None = Field(None, max_length=255)
    targets: list[str] = Field(default_factory=list, max_length=200)  # extra IPs/CIDRs (campaign blocks)
    ttl_hours: int | None = Field(None, ge=1, le=168)
    simulation_id: uuid.UUID | None = None
    webacl_id: uuid.UUID | None = None
    rule_name: str | None = Field(None, max_length=255)
    action: Literal["BLOCK", "COUNT", "ALLOW", "CAPTCHA", "CHALLENGE"] | None = None
    limit: int | None = Field(None, ge=10, le=2_000_000_000)
    excluded_rule: str | None = Field(None, max_length=255)
    resource_arn: str | None = Field(None, max_length=512)
    drift_id: uuid.UUID | None = None


def _ref(acl: WebAcl) -> dict:
    return {"name": acl.name, "id": acl.webacl_id, "scope": acl.scope,
            "region": "us-east-1" if acl.scope == "CLOUDFRONT" else acl.region, "arn": acl.arn}


def _require(value, name: str):
    if value in (None, "", []):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"{name} is required for this action")
    return value


async def _webacl(db: AsyncSession, req: ApprovalRequest) -> WebAcl:
    acl = await db.get(WebAcl, _require(req.webacl_id, "webacl_id"))
    if acl is None or acl.account_id != req.account_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "WebACL not found in that account")
    return acl


async def _blocklist_ip_set(db: AsyncSession, acl: WebAcl) -> dict:
    rules = (await db.scalars(select(Rule).where(Rule.webacl_id == acl.id, Rule.type == "IP_SET",
                                                 Rule.name.ilike(f"{BLOCKLIST_RULE_PREFIX}%")))).all()
    for rule in rules:
        arn = rule.statement.get("IPSetReferenceStatement", {}).get("ARN", "")
        # arn:aws:wafv2:<region>:<account>:<regional|global>/ipset/<name>/<id>
        parts = arn.split(":")
        if len(parts) == 6 and "/ipset/" in parts[5]:
            scope_part, _, name, set_id = parts[5].split("/")
            scope = "CLOUDFRONT" if scope_part == "global" else "REGIONAL"
            return {"name": name, "id": set_id, "scope": scope, "arn": arn,
                    "region": "us-east-1" if scope == "CLOUDFRONT" else parts[3], "rule": rule.name}
    raise HTTPException(status.HTTP_409_CONFLICT,
                        f"WebACL {acl.name} has no '{BLOCKLIST_RULE_PREFIX}*' IP-set rule. Provision the platform "
                        "blocklist rule (IP set referenced by a BLOCK rule) before requesting IP blocks.")


async def build_proposal(db: AsyncSession, req: ApprovalRequest) -> tuple[dict, dict, str, str]:
    """-> (proposed_state, previous_state summary, target, risk_level)"""
    t = req.action_type
    if t in BLOCK_ACTIONS or t == "REMOVE_BLOCK":
        if t == "TEMP_BLOCK_IP" and req.ttl_hours is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "TEMP_BLOCK_IP requires ttl_hours")
        acl = await _webacl(db, req)
        targets = [str(guardrail_service.parse_block_target(x))
                   for x in [_require(req.target, "target"), *req.targets]]
        ip_set = await _blocklist_ip_set(db, acl)
        op = "ip_set_remove" if t == "REMOVE_BLOCK" else "ip_set_add"
        proposed = {"op": op, "ip_set": ip_set, ("remove" if op == "ip_set_remove" else "add"): targets,
                    "webacl": _ref(acl)}
        risk = {"PERM_BLOCK_IP": "HIGH", "TEMP_BLOCK_IP": "MEDIUM", "REMOVE_BLOCK": "MEDIUM"}[t]
        return proposed, {"ip_set": ip_set["name"], "rule": ip_set["rule"]}, targets[0], risk
    if t in ("MODIFY_RULE", "MODIFY_RATE_LIMIT", "ADD_EXCEPTION"):
        acl = await _webacl(db, req)
        rule = await db.scalar(select(Rule).where(Rule.webacl_id == acl.id,
                                                  Rule.name == _require(req.rule_name, "rule_name")))
        if rule is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found in WebACL")
        base = {"webacl": _ref(acl), "rule_name": rule.name}
        if t == "MODIFY_RULE":
            action = _require(req.action, "action")
            risk = "HIGH" if action in ("COUNT", "ALLOW") else "MEDIUM"  # weakening is riskier than tightening
            return ({**base, "op": "set_rule_action", "action": action}, {"rule": rule.name, "action": rule.action},
                    rule.name, risk)
        if t == "MODIFY_RATE_LIMIT":
            if rule.type != "RATE_BASED":
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Rule is not rate-based")
            return ({**base, "op": "set_rate_limit", "limit": _require(req.limit, "limit")},
                    {"rule": rule.name, "limit": rule.rate_limit}, rule.name, "MEDIUM")
        if rule.type != "MANAGED":
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Exceptions apply to managed rule groups")
        return ({**base, "op": "add_exception", "excluded_rule": _require(req.excluded_rule, "excluded_rule")},
                {"rule": rule.name, "excluded_rules": list(rule.excluded_rules or [])}, rule.name, "HIGH")
    if t == "ATTACH_WAF":
        acl = await _webacl(db, req)
        endpoint = await db.scalar(select(Endpoint).where(
            Endpoint.resource_arn == _require(req.resource_arn, "resource_arn"), Endpoint.account_id == req.account_id))
        if endpoint is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Endpoint not found in that account")
        if endpoint.type == "CLOUDFRONT" or acl.scope != "REGIONAL" or acl.region != endpoint.region:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                "Only regional WebACL -> same-region ALB/API Gateway attachments are automated; "
                                "CloudFront attachment needs cloudfront:UpdateDistribution, which is denied by design.")
        return ({"op": "associate", "webacl_arn": acl.arn, "resource_arn": endpoint.resource_arn,
                 "region": endpoint.region, "webacl": _ref(acl)},
                {"resource": endpoint.name, "waf_status": endpoint.waf_status}, endpoint.resource_arn, "HIGH")
    # REMEDIATE_DRIFT
    drift = await db.get(DriftEvent, _require(req.drift_id, "drift_id"))
    if drift is None or drift.account_id != req.account_id or drift.status == "RESOLVED":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Open drift event not found")
    acl = await db.get(WebAcl, drift.webacl_id)
    expected = json.loads(drift.expected_state)
    if drift.drift_type == "RULE_ACTION_CHANGED" and expected.get("rule") != "DefaultAction":
        proposed = {"op": "set_rule_action", "webacl": _ref(acl), "rule_name": expected["rule"],
                    "action": expected["action"]}
    elif drift.drift_type == "RULE_REMOVED":
        rule = next((r for r in acl.baseline_config.get("Rules", []) if r["Name"] == expected["rule"]), None)
        if rule is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Baseline no longer contains that rule")
        proposed = {"op": "restore_rule", "webacl": _ref(acl), "rule": rule}
    elif drift.drift_type == "LOGGING_DISABLED":
        proposed = {"op": "put_logging", "webacl": _ref(acl), "log_destination": expected["logging_destination"]}
    elif drift.drift_type == "ASSOCIATION_REMOVED":
        proposed = {"op": "associate", "webacl_arn": acl.arn, "resource_arn": expected["resource_arn"],
                    "region": acl.region, "webacl": _ref(acl)}
    else:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            f"{drift.drift_type} remediation is not automated; change it via MODIFY_RULE or manually")
    proposed["drift_id"] = str(drift.id)
    return proposed, json.loads(drift.actual_state), f"{acl.name}:{drift.drift_code}", drift.severity


async def create_approval(db: AsyncSession, req: ApprovalRequest, principal: Principal) -> Approval:
    scope = principal.account_scope("CREATE_CHANGE")
    if scope is not None and req.account_id not in scope:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is outside your scope")
    account = await db.scalar(select(Account).where(Account.account_id == req.account_id))
    if account is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found")

    proposed, previous, target, risk = await build_proposal(db, req)
    block_targets = proposed.get("add", [])
    if block_targets:  # CHECK GUARDRAILS before anything is stored; denial is itself audited
        matches = await guardrail_service.protected_matches(
            db, [ipaddress.ip_network(x) for x in block_targets])
        if matches:
            audit_service.record(
                db, actor_email=principal.email, actor_role=principal.role, account_id=req.account_id,
                region=proposed["ip_set"]["region"], action="GUARDRAIL_DENIED",
                target_resource=", ".join(block_targets),
                new_state={"protected": matches}, reason=req.reason, risk_level=risk, execution_status="DENIED",
            )
            await db.commit()
            await guardrail_service.verify_not_allowlisted(db, [ipaddress.ip_network(x) for x in block_targets])

    simulation = await db.get(Simulation, req.simulation_id) if req.simulation_id else None
    if req.action_type in SIMULATION_REQUIRED:
        assert_simulation_covers(simulation, proposed["op"], block_targets)

    slots = policy(req.action_type, req.ttl_hours)
    summary = {}
    if simulation:
        summary = {"summary": f"{simulation.would_block} would block, {simulation.potential_false_positives} "
                              f"potential false positives ({float(simulation.fp_rate_percent):.3f}%)",
                   "affected_accounts": len(simulation.target_accounts),
                   "affected_webacls": len(simulation.target_webacl_ids), "affected_apps": len(simulation.target_apps),
                   "potential_false_positives": simulation.potential_false_positives,
                   "risk_reduction": simulation.risk_reduction, "legitimate_impact": simulation.legitimate_impact}
    approval = Approval(
        approval_code=f"APR-{datetime.now(UTC):%Y%m%d}-{secrets.token_hex(3).upper()}",
        action_type=req.action_type, title=f"{req.action_type.replace('_', ' ').title()}: {target}"[:255],
        target=target[:255], account_id=req.account_id, account_name=account.name,
        webacl_id=req.webacl_id, webacl_name=proposed.get("webacl", {}).get("name", ""), application="",
        requested_by=principal.email, requested_by_role=principal.role, reason=req.reason, risk_level=risk,
        ttl_hours=req.ttl_hours, allow_list_check="PASSED", simulation_id=simulation.id if simulation else None,
        simulation_summary=summary,
        impact_scope=(f"{len(simulation.target_accounts)} account(s), {len(simulation.target_webacl_ids)} WebACL(s)"
                      if simulation else f"1 account ({account.name})"),
        required_approver_role=" + ".join(s.label for s in slots), status="PENDING",
        previous_state=json.dumps(previous, default=str), proposed_state=json.dumps(proposed, default=str),
    )
    db.add(approval)
    await db.flush()
    audit_service.record(
        db, actor_email=principal.email, actor_role=principal.role, account_id=req.account_id,
        region=proposed.get("webacl", {}).get("region", account.regions[0] if account.regions else "us-east-1"),
        action="APPROVAL_REQUESTED", target_resource=target, previous_state=previous, new_state=proposed,
        reason=req.reason, risk_level=risk, approval_id=approval.id, execution_status="PENDING_APPROVAL",
    )
    await db.commit()
    notify(approval)
    return approval


def notify(approval: Approval) -> None:
    """SNS (+ email subscriptions). Best effort: a notification outage must never block the lifecycle."""
    from app.config import get_settings  # local: avoid boto3 import cost on every request path

    topic = get_settings().sns_topic_arn
    if not topic:
        return
    try:
        import boto3

        boto3.client("sns", region_name=get_settings().aws_region).publish(
            TopicArn=topic, Subject=f"[SAS WAF] Approval required: {approval.approval_code}"[:100],
            Message=json.dumps({"approval_code": approval.approval_code, "action_type": approval.action_type,
                                "target": approval.target, "account": approval.account_name,
                                "risk_level": approval.risk_level, "required": approval.required_approver_role,
                                "requested_by": approval.requested_by}),
        )
    except Exception:  # noqa: BLE001, S110 - best-effort notification, failure is logged by boto3
        pass


# --- decide / execute -------------------------------------------------------------------------------------

def _region(proposed: dict) -> str:
    return proposed.get("region") or proposed.get("webacl", {}).get("region") or "us-east-1"


async def decide(db: AsyncSession, approval_id: uuid.UUID, decision: str, comment: str | None, principal: Principal,
                 executor_factory: ExecutorFactory) -> Approval:
    approval = await db.scalar(select(Approval).where(Approval.id == approval_id).with_for_update())
    if approval is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")
    if approval.status != "PENDING":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Approval is {approval.status}")
    if approval.requested_by == principal.email:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Requesters cannot approve or reject their own change")
    if not principal.mfa:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Approvals require an MFA-authenticated session")
    proposed = json.loads(approval.proposed_state)
    slots = policy(approval.action_type, approval.ttl_hours)
    decisions = (await db.scalars(select(ApprovalDecision).where(ApprovalDecision.approval_id == approval.id))).all()
    if any(d.decided_by == principal.email for d in decisions):
        raise HTTPException(status.HTTP_409_CONFLICT, "You already decided on this approval")
    filled = {d.slot for d in decisions if d.decision == "APPROVE"}
    open_slots = [i for i in range(len(slots)) if i not in filled]
    slot = next((i for i in open_slots if slots[i].accepts(principal, approval.account_id)), None)
    if slot is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Your role cannot satisfy the remaining approval: "
                            + ", ".join(slots[i].label for i in open_slots))

    region = _region(proposed)
    if decision == "REJECT":
        approval.status = "REJECTED"
        db.add(ApprovalDecision(approval_id=approval.id, slot=slot, decided_by=principal.email,
                                decided_by_role=principal.role, decision="REJECT", comment=comment))
        audit_service.record(db, actor_email=principal.email, actor_role=principal.role,
                             account_id=approval.account_id, region=region, action="APPROVAL_REJECTED",
                             target_resource=approval.target, reason=comment or approval.reason,
                             risk_level=approval.risk_level, approver=principal.email, approval_id=approval.id,
                             execution_status="REJECTED")
        await db.commit()
        return approval

    if approval.action_type in BLOCK_ACTIONS:  # guardrails re-checked: the allow-list may have changed since request
        nets = [ipaddress.ip_network(x) for x in proposed.get("add", [])]
        matches = await guardrail_service.protected_matches(db, nets)
        if matches:
            approval.status, approval.allow_list_check = "REJECTED", "BLOCKED_PROTECTED_ENTITY"
            audit_service.record(db, actor_email=principal.email, actor_role=principal.role,
                                 account_id=approval.account_id, region=region, action="GUARDRAIL_DENIED",
                                 target_resource=approval.target, new_state={"protected": matches},
                                 reason=approval.reason, risk_level=approval.risk_level, approval_id=approval.id,
                                 execution_status="DENIED")
            await db.commit()
            await guardrail_service.verify_not_allowlisted(db, nets)

    db.add(ApprovalDecision(approval_id=approval.id, slot=slot, decided_by=principal.email,
                            decided_by_role=principal.role, decision="APPROVE", comment=comment))
    approvers = [d.decided_by for d in decisions if d.decision == "APPROVE"] + [principal.email]
    audit_service.record(db, actor_email=principal.email, actor_role=principal.role, account_id=approval.account_id,
                         region=region, action="APPROVAL_GRANTED", target_resource=approval.target,
                         reason=comment or approval.reason, risk_level=approval.risk_level, approver=principal.email,
                         approval_id=approval.id, execution_status="APPROVED" if len(approvers) == len(slots)
                         else f"AWAITING_{len(slots) - len(approvers)}_MORE")
    if len(approvers) < len(slots):
        await db.commit()
        return approval

    approval.status, approval.approved_by, approval.approved_at = "APPROVED", ", ".join(approvers), datetime.now(UTC)
    await db.commit()
    await execute(db, approval, proposed, principal, executor_factory)
    return approval


async def execute(db: AsyncSession, approval: Approval, proposed: dict, principal: Principal,
                  executor_factory: ExecutorFactory) -> None:
    account = await db.scalar(select(Account).where(Account.account_id == approval.account_id))
    region = _region(proposed)
    try:
        executor = await asyncio.to_thread(executor_factory, account.response_role_arn, account.account_id,
                                           approval.approval_code, principal.email)
        result: ExecutionResult = await asyncio.to_thread(executor.execute, proposed)
    except Exception as exc:  # noqa: BLE001 - any AWS/STS failure must be audited, never swallowed silently
        approval.verification_status = "FAILED"
        audit_service.record(db, actor_email=principal.email, actor_role=principal.role,
                             account_id=approval.account_id, region=region, action="AWS_EXECUTE",
                             target_resource=approval.target, new_state={"error": str(exc)[:1000]},
                             reason=approval.reason, risk_level=approval.risk_level,
                             approver=approval.approved_by, approval_id=approval.id, execution_status="FAILED")
        await db.commit()
        code = status.HTTP_409_CONFLICT if isinstance(exc, ExecutionError) else status.HTTP_502_BAD_GATEWAY
        raise HTTPException(code, f"Execution failed: {exc}") from exc

    now = datetime.now(UTC)
    ttl_active = approval.action_type == "TEMP_BLOCK_IP" and result.verified
    change = Change(
        approval_id=approval.id, account_id=approval.account_id, webacl_id=approval.webacl_id,
        previous_state_json=result.previous_state, new_state_json=result.new_state,
        aws_lock_token_before=result.lock_token_before, aws_lock_token_after=result.lock_token_after,
        aws_request_id=result.aws_request_id, execution_status="EXECUTED",
        verification_status="VERIFIED" if result.verified else "FAILED",
        ttl_status="ACTIVE" if ttl_active else None,
        expires_at=now + timedelta(hours=approval.ttl_hours) if ttl_active else None,
        rollback_available=result.rollback_available,
    )
    db.add(change)
    approval.status = "VERIFIED" if result.verified else "EXECUTED"
    approval.verification_status = "VERIFIED" if result.verified else "FAILED"
    approval.aws_request_id = result.aws_request_id
    approval.expires_at = change.expires_at
    for action, exec_status, verification in (("AWS_EXECUTE", "EXECUTED", None),
                                              ("AWS_VERIFY", "EXECUTED", approval.verification_status)):
        audit_service.record(db, actor_email=principal.email, actor_role=principal.role,
                             account_id=approval.account_id, region=region, action=action,
                             target_resource=approval.target, previous_state=result.previous_state,
                             new_state=result.new_state, reason=approval.reason, risk_level=approval.risk_level,
                             approver=approval.approved_by, approval_id=approval.id, execution_status=exec_status,
                             aws_request_id=result.aws_request_id, verification_status=verification,
                             rollback_available=result.rollback_available)
    if result.verified:
        await _move_baseline(db, approval, proposed, result)
        if proposed.get("drift_id"):
            drift = await db.get(DriftEvent, uuid.UUID(proposed["drift_id"]))
            drift.status = "REMEDIATING"  # the next drift run resolves it once AWS state matches the baseline
    await db.commit()


async def _move_baseline(db: AsyncSession, approval: Approval, proposed: dict, result: ExecutionResult) -> None:
    """An approved, verified WebACL change becomes the new drift baseline; anything else would re-flag it."""
    if approval.webacl_id is None and "webacl" not in proposed:
        return
    acl = await db.get(WebAcl, approval.webacl_id) if approval.webacl_id else await db.scalar(
        select(WebAcl).where(WebAcl.arn == proposed["webacl"]["arn"]))
    if acl is None or not acl.baseline_config:
        return
    baseline = dict(acl.baseline_config)
    op = proposed["op"]
    if op in WEBACL_OPS:
        baseline = {**result.new_state, "_logging_destination": baseline.get("_logging_destination"),
                    "_associated_resources": baseline.get("_associated_resources", [])}
    elif op == "put_logging":
        baseline["_logging_destination"] = proposed["log_destination"]
    elif op == "associate":
        resources = set(baseline.get("_associated_resources", []))
        resources.add(proposed["resource_arn"]) if result.new_state.get("webacl_arn") else resources.discard(
            proposed["resource_arn"])
        baseline["_associated_resources"] = sorted(resources)
    else:
        return
    acl.baseline_config = json.loads(json.dumps(baseline, default=str))


async def rollback(db: AsyncSession, change_id: uuid.UUID, principal: Principal, executor_factory: ExecutorFactory,
                   reason: str = "Manual rollback", system: bool = False) -> Change:
    change = await db.scalar(select(Change).where(Change.id == change_id).with_for_update())
    if change is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Change not found")
    if change.execution_status != "EXECUTED":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Change is {change.execution_status}")
    if not change.rollback_available:
        raise HTTPException(status.HTTP_409_CONFLICT, "This change type cannot be rolled back by the platform")
    if not system and not principal.mfa:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Rollback requires an MFA-authenticated session")
    approval = await db.get(Approval, change.approval_id)
    proposed = json.loads(approval.proposed_state)
    account = await db.scalar(select(Account).where(Account.account_id == change.account_id))
    region = _region(proposed)
    try:
        executor = await asyncio.to_thread(executor_factory, account.response_role_arn, account.account_id,
                                           approval.approval_code, principal.email)
        result = await asyncio.to_thread(executor.rollback, proposed, change.previous_state_json,
                                         change.new_state_json)
    except Exception as exc:  # noqa: BLE001
        audit_service.record(db, actor_email=principal.email, actor_role=principal.role, account_id=change.account_id,
                             region=region, action="ROLLBACK", target_resource=approval.target,
                             new_state={"error": str(exc)[:1000]}, reason=reason, risk_level=approval.risk_level,
                             approver=approval.approved_by, approval_id=approval.id, execution_status="FAILED")
        await db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Rollback failed: {exc}") from exc

    audit_service.record(db, actor_email=principal.email, actor_role=principal.role, account_id=change.account_id,
                         region=region, action="TTL_EXPIRY" if system else "ROLLBACK", target_resource=approval.target,
                         previous_state=result.previous_state, new_state=result.new_state, reason=reason,
                         risk_level=approval.risk_level, approver=approval.approved_by, approval_id=approval.id,
                         execution_status="ROLLED_BACK" if result.verified else "EXECUTED",
                         aws_request_id=result.aws_request_id,
                         verification_status="VERIFIED" if result.verified else "FAILED")
    if not result.verified:
        await db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Rollback applied but not verified: {result.detail}")
    change.execution_status, change.rolled_back_at, change.rolled_back_by = "ROLLED_BACK", datetime.now(UTC), \
        principal.email
    if change.ttl_status:
        change.ttl_status = "REMOVED"
    approval.status = "EXPIRED" if system else "ROLLED_BACK"
    if proposed["op"] in WEBACL_OPS or proposed["op"] == "associate":
        await _move_baseline(db, approval, proposed, result)
    await db.commit()
    return change


# --- views -----------------------------------------------------------------------------------------------

LIFECYCLE = ["DETECT", "UNDERSTAND", "CORRELATE", "SCORE", "SIMULATE", "CHECK GUARDRAILS", "REQUEST APPROVAL",
             "APPROVE", "EXECUTE", "VERIFY", "AUDIT", "ROLLBACK IF REQUIRED"]


def lifecycle(approval: Approval) -> list[dict]:
    s, v = approval.status, approval.verification_status
    executed = s in ("EXECUTED", "VERIFIED", "ROLLED_BACK", "EXPIRED")
    state = dict.fromkeys(LIFECYCLE[:4], "completed")
    state["SIMULATE"] = "completed" if approval.simulation_id else "skipped"
    state["CHECK GUARDRAILS"] = "blocked" if approval.allow_list_check == "BLOCKED_PROTECTED_ENTITY" else "completed"
    state["REQUEST APPROVAL"] = "completed"
    state["APPROVE"] = {"PENDING": "active", "REJECTED": "blocked"}.get(s, "completed")
    state["EXECUTE"] = "completed" if executed else ("blocked" if s == "APPROVED" and v == "FAILED" else "pending")
    state["VERIFY"] = "completed" if v == "VERIFIED" else ("blocked" if executed and v == "FAILED" else "pending")
    state["AUDIT"] = "completed" if executed else "pending"
    state["ROLLBACK IF REQUIRED"] = "completed" if s in ("ROLLED_BACK", "EXPIRED") else "pending"
    return [{"step": step, "state": state[step]} for step in LIFECYCLE]


def approval_out(ap: Approval) -> c.ApprovalOut:
    summary = ap.simulation_summary or {}
    status_ = "failed" if ap.verification_status == "FAILED" else c.APPROVAL_STATUS[ap.status]
    stage = "guardrails" if ap.allow_list_check == "BLOCKED_PROTECTED_ENTITY" else c.LIFECYCLE_STAGE[ap.status]
    return c.ApprovalOut(
        id=str(ap.id), action_type=ap.action_type, target=ap.target, reason=ap.reason, status=status_,
        requested_by=ap.requested_by, requested_at=c.iso(ap.requested_at), approver=ap.approved_by,
        approved_at=c.iso(ap.approved_at) or None, simulation_result=summary.get("summary"),
        impact=c.ApprovalImpactOut(
            affected_accounts=int(summary.get("affected_accounts", 0)),
            affected_webacls=int(summary.get("affected_webacls", 0)),
            affected_apps=int(summary.get("affected_apps", 0)),
            potential_fp=int(summary.get("potential_false_positives", 0)),
            security_gain=str(summary.get("risk_reduction", "")), fp_risk=str(summary.get("legitimate_impact", "")),
        ),
        lifecycle_stage=stage, approval_code=ap.approval_code, status_detail=ap.status, risk_level=ap.risk_level,
        allow_list_check=ap.allow_list_check, verification_status=ap.verification_status,
        aws_request_id=ap.aws_request_id, required_approver_role=ap.required_approver_role,
        expires_at=c.iso(ap.expires_at) or None,
    )


async def active_blocks(db: AsyncSession) -> list[dict]:
    rows = await db.execute(text(
        "SELECT ch.id, ch.account_id, ch.expires_at, ch.ttl_status, ch.executed_at, ap.approval_code, ap.target,"
        " ap.action_type FROM changes ch JOIN approvals ap ON ap.id = ch.approval_id"
        " WHERE ch.execution_status = 'EXECUTED' AND ap.action_type IN ('TEMP_BLOCK_IP', 'PERM_BLOCK_IP')"
        " ORDER BY ch.executed_at DESC"))
    return [dict(r) for r in rows.mappings()]
