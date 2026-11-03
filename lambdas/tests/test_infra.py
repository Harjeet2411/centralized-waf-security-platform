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
            _service, name = action.split(":")
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
        assert state["Type"] in ("Succeed", "Fail") or state.get("End") or state.get("Next"), name


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


# --- central account stacks (Milestone 6) ------------------------------------------------------------------

PLATFORM = cfn_yaml.load(str(INFRA / "central_account" / "platform.yaml"))
APP = cfn_yaml.load(str(INFRA / "central_account" / "app.yaml"))
LAMBDA_PACKAGES = sorted(p.parent.name for p in Path(__file__).resolve().parents[1].glob("*/handler.py"))


def _of_type(template: dict, resource_type: str) -> dict:
    return {k: v for k, v in template["Resources"].items() if v["Type"] == resource_type}


def test_every_lambda_package_is_deployed():
    handlers = sorted(f["Properties"]["Handler"].split(".")[0]
                      for f in _of_type(PLATFORM, "AWS::Lambda::Function").values())
    assert handlers == LAMBDA_PACKAGES
    for fn in _of_type(PLATFORM, "AWS::Lambda::Function").values():
        props = fn["Properties"]
        assert props["Runtime"] == "python3.12" and props["Architectures"] == ["x86_64"]  # matches build.py wheels
        assert "VpcConfig" in props


def test_collector_role_name_matches_stackset_trust():
    assert PLATFORM["Resources"]["CollectorRole"]["Properties"]["RoleName"] == "SASLambdaCollectorExecutionRole"
    collector = PLATFORM["Resources"]["AccountCollectorFunction"]["Properties"]
    assert collector["Role"] == {"Fn::GetAtt": ["CollectorRole", "Arn"]}
    assert collector["Timeout"] < ASL["States"]["PerAccountFanOut"]["ItemProcessor"]["States"][
        "CollectAccountWafData"]["TimeoutSeconds"]
    assert APP["Resources"]["TaskRole"]["Properties"]["RoleName"] == "SASFastAPIResponseExecutorRole"
    [statement] = [s for s in APP["Resources"]["TaskRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
                   if s.get("Sid") == "AssumeResponseRoleWithApprovalContext"]
    assert set(statement["Action"]) == {"sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"}


def test_state_machine_substitutions_cover_the_asl():
    import re
    placeholders = set(re.findall(r"\$\{(\w+)\}", json.dumps(ASL)))
    subs = PLATFORM["Resources"]["SyncStateMachine"]["Properties"]["DefinitionSubstitutions"]
    assert placeholders == set(subs)


def test_sync_schedules():
    rules = {r["Properties"]["ScheduleExpression"]: json.loads(r["Properties"]["Targets"][0]["Input"])
             for r in _of_type(PLATFORM, "AWS::Events::Rule").values()}
    assert rules == {"rate(30 minutes)": {"mode": "telemetry"}, "rate(6 hours)": {"mode": "full"}}


def test_five_private_api_endpoints():
    services = {e["Properties"]["ServiceName"]["Fn::Sub"].rsplit(".", 1)[1]
                for e in _of_type(PLATFORM, "AWS::EC2::VPCEndpoint").values()
                if e["Properties"]["VpcEndpointType"] == "Interface"}
    assert services == {"sts", "wafv2", "monitoring", "logs", "states"}


def test_data_stores_encrypted_and_private():
    db = PLATFORM["Resources"]["Database"]
    props = db["Properties"]
    assert props["MultiAZ"] and props["StorageEncrypted"] and props["DeletionProtection"]
    assert props["PubliclyAccessible"] is False and db["DeletionPolicy"] == "Snapshot"
    redis = PLATFORM["Resources"]["Redis"]["Properties"]
    assert redis["TransitEncryptionEnabled"] and redis["AtRestEncryptionEnabled"]
    data_routes = [r for r in _of_type(PLATFORM, "AWS::EC2::Route").values()
                   if r["Properties"]["RouteTableId"] == {"Ref": "DataRouteTable"}]
    assert data_routes == []  # data tier has no route to the internet


def test_buckets_block_public_access_and_audit_archive_is_locked():
    for template in (PLATFORM, APP):
        for name, bucket in _of_type(template, "AWS::S3::Bucket").items():
            block = bucket["Properties"]["PublicAccessBlockConfiguration"]
            assert all(block.values()), name
            assert "BucketEncryption" in bucket["Properties"], name
    archive = PLATFORM["Resources"]["AuditArchiveBucket"]
    assert archive["Properties"]["ObjectLockConfiguration"]["Rule"]["DefaultRetention"] == {
        "Mode": "COMPLIANCE", "Years": 7}
    assert archive["DeletionPolicy"] == "Retain"
    assert PLATFORM["Resources"]["WafLogBucket"]["Properties"]["BucketName"]["Fn::Sub"].startswith("aws-waf-logs-")


def test_alb_only_reachable_through_cloudfront_and_waf_protected():
    listener = APP["Resources"]["HttpsListener"]["Properties"]
    assert listener["DefaultActions"][0]["FixedResponseConfig"]["StatusCode"] == "403"
    rule = APP["Resources"]["FromCloudFrontRule"]["Properties"]
    assert rule["Conditions"][0]["HttpHeaderConfig"]["HttpHeaderName"] == "X-Origin-Verify"
    origins = APP["Resources"]["Distribution"]["Properties"]["DistributionConfig"]["Origins"]
    api = next(o for o in origins if o["Id"] == "api")
    assert api["OriginCustomHeaders"][0]["HeaderName"] == "X-Origin-Verify"
    assert api["CustomOriginConfig"]["OriginProtocolPolicy"] == "https-only"
    assert APP["Resources"]["AlbWebAclAssociation"]["Properties"]["ResourceArn"] == {"Ref": "LoadBalancer"}


def test_ttl_worker_scheduled_with_same_image():
    target = APP["Resources"]["TtlExpirySchedule"]["Properties"]["Targets"][0]
    command = json.loads(target["Input"])["containerOverrides"][0]["command"]
    assert command == ["python", "-m", "app.workers.ttl_expiry"]
    assert target["EcsParameters"]["TaskDefinitionArn"] == {"Ref": "TaskDefinition"}
    container = APP["Resources"]["TaskDefinition"]["Properties"]["ContainerDefinitions"][0]
    assert container["ReadonlyRootFilesystem"] is True
    secrets = {s["Name"] for s in container["Secrets"]}
    assert {"SAS_DB_USER", "SAS_DB_PASSWORD", "SAS_RESPONSE_EXTERNAL_ID", "SAS_OIDC_CLIENT_SECRET"} <= secrets
