"""Static guarantees on the IaC: least privilege on the StackSet roles and a well-formed sync state machine."""

import json
from pathlib import Path

import pytest
from cfnlint.decode import cfn_yaml

INFRA = Path(__file__).resolve().parents[2] / "infra"
TEMPLATE = cfn_yaml.load(str(INFRA / "stacksets" / "cross-account-waf-roles.yaml"))
ASL = json.loads((INFRA / "central_account" / "step_functions.asl.json").read_text())

READ_PREFIXES = ("List", "Get", "Describe")


def _policy_statements(role: str) -> list[dict]:
    return [s for p in TEMPLATE["Resources"][role]["Properties"]["Policies"] for s in p["PolicyDocument"]["Statement"]]


def _actions(statement: dict) -> list[str]:
    actions = statement["Action"]
    return [actions] if isinstance(actions, str) else list(actions)


def test_discovery_role_is_read_only():
    for statement in _policy_statements("SASWafDiscoveryRole"):
        assert statement["Effect"] == "Allow"
        for action in _actions(statement):
            service, name = action.split(":")
            assert name.startswith(READ_PREFIXES) or action == "apigateway:GET", action


def test_discovery_trust_requires_external_id_from_central_collector():
    [trust] = TEMPLATE["Resources"]["SASWafDiscoveryRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    assert "sts:ExternalId" in trust["Condition"]["StringEquals"]
    assert "SASLambdaCollectorExecutionRole" in str(trust["Principal"]["AWS"])


def test_response_role_denies_destructive_actions():
    denied = {a for s in _policy_statements("SASWafResponseRole") if s["Effect"] == "Deny" for a in _actions(s)}
    assert {"wafv2:DeleteWebACL", "wafv2:DeleteRuleGroup", "wafv2:DeleteIPSet", "iam:*", "organizations:*",
            "s3:Delete*"} <= denied
    allowed = {a for s in _policy_statements("SASWafResponseRole") if s["Effect"] == "Allow" for a in _actions(s)}
    assert not any(a.split(":")[1].startswith(("Delete", "Create")) for a in allowed)
    assert not any(a.endswith("*") for a in allowed)


def test_response_trust_binds_session_to_approval_and_approver():
    [trust] = TEMPLATE["Resources"]["SASWafResponseRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    assert "SASFastAPIResponseExecutorRole" in str(trust["Principal"]["AWS"])
    cond = trust["Condition"]
    assert "sts:ExternalId" in cond["StringEquals"]
    assert cond["StringLike"]["aws:RequestTag/sas:approval-id"] == "APR-*"
    assert cond["StringLike"]["sts:SourceIdentity"] == "*@*"


def _walk(states: dict):
    for name, state in states.items():
        yield name, state, states
        if state["Type"] == "Map":
            yield from _walk(state["ItemProcessor"]["States"])
        if state["Type"] == "Parallel":
            for branch in state["Branches"]:
                yield from _walk(branch["States"])


def test_asl_transitions_resolve():
    for name, state, scope in _walk(ASL["States"]):
        targets = [state.get("Next")] + [c["Next"] for c in state.get("Catch", [])]
        for target in filter(None, targets):
            assert target in scope, f"{name} -> {target} missing"
        assert state.get("End") or state.get("Next"), name


def test_asl_fan_out_and_retry_placement():
    fan_out = ASL["States"]["PerAccountFanOut"]
    assert fan_out["MaxConcurrency"] == 20
    assert "Retry" not in fan_out  # a Map-level retry would re-run all 39 accounts
    task = fan_out["ItemProcessor"]["States"]["CollectAccountWafData"]
    throttle = task["Retry"][0]
    assert throttle["ErrorEquals"] == ["WAFLimitsExceededException", "ThrottlingException"]
    assert (throttle["IntervalSeconds"], throttle["MaxAttempts"], throttle["BackoffRate"]) == (2, 4, 2.5)
    assert task["Catch"][0] == {"ErrorEquals": ["States.ALL"], "ResultPath": "$.error", "Next": "MarkAccountDegraded"}


@pytest.mark.parametrize("error_class", ["WAFLimitsExceededException", "ThrottlingException"])
def test_asl_retry_names_match_python_exceptions(error_class):
    from common import aws
    assert hasattr(aws, error_class)  # Lambda errorType == Python class name
