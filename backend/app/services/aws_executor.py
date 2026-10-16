"""Executes approved WAF changes through SASWafResponseRole (synchronous boto3; call via asyncio.to_thread).

Every operation: snapshot current state + LockToken -> apply with that LockToken -> capture the AWS RequestId ->
wait -> re-read and verify the LockToken rotated and the intended state is present (Rule #7). Nothing is
reported VERIFIED on optimism. Rollback applies the *inverse* of our own change to the current state (remove the
IPs we added, restore the one rule we touched) instead of replaying an old snapshot, so unrelated changes made
since are never clobbered.

Operations (`proposed["op"]`): ip_set_add, ip_set_remove, set_rule_action, set_rate_limit, add_exception,
restore_rule, put_logging, associate.
"""

import copy
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from app.config import get_settings

BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "standard"}, connect_timeout=5, read_timeout=20)
IP_SET_LIMIT = 10_000
# Top-level WebACL keys UpdateWebACL accepts; anything GetWebACL returns outside this list must not be sent back.
UPDATE_WEB_ACL_KEYS = ("DefaultAction", "Description", "Rules", "VisibilityConfig", "DataProtectionConfig",
                       "CustomResponseBodies", "CaptchaConfig", "ChallengeConfig", "TokenDomains", "AssociationConfig")
SOURCE_IDENTITY_SAFE = re.compile(r"[^\w+=,.@-]")

ClientFactory = Callable[[str, str], object]


class ExecutionError(Exception):
    pass


@dataclass
class ExecutionResult:
    aws_request_id: str
    previous_state: dict
    new_state: dict
    verified: bool
    detail: str
    lock_token_before: str | None = None
    lock_token_after: str | None = None
    rollback_available: bool = True
    extra: dict = field(default_factory=dict)


def assume_response_role(role_arn: str, account_id: str, approval_code: str, approver_email: str) -> ClientFactory:
    """Session carries the approval code (session tag) and approver (SourceIdentity -> CloudTrail); the trust
    policy in infra/stacksets requires both plus the response ExternalId."""
    settings = get_settings()
    creds = boto3.client("sts", region_name=settings.aws_region, config=BOTO_CONFIG).assume_role(
        RoleArn=role_arn, RoleSessionName=f"sas-{approval_code}"[:64], DurationSeconds=900,
        ExternalId=settings.response_external_id.get_secret_value(),
        SourceIdentity=SOURCE_IDENTITY_SAFE.sub("_", approver_email)[:64],
        Tags=[{"Key": "sas:approval-id", "Value": approval_code}],
    )["Credentials"]
    session = boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                            aws_session_token=creds["SessionToken"])
    return lambda service, region: session.client(service, region_name=region, config=BOTO_CONFIG)


def effective_action(rule: dict) -> str:
    if "Action" in rule:
        return next(iter(rule["Action"])).upper()
    return "COUNT" if "Count" in rule.get("OverrideAction", {}) else "BLOCK"


def _find_rule(acl: dict, name: str) -> dict:
    for rule in acl.get("Rules", []):
        if rule["Name"] == name:
            return rule
    raise ExecutionError(f"Rule {name!r} not found in WebACL {acl.get('Name')}")


class WafExecutor:
    def __init__(self, clients: ClientFactory, wait_seconds: float | None = None):
        self.clients = clients
        self.wait = get_settings().verify_wait_seconds if wait_seconds is None else wait_seconds

    # --- IP sets ----------------------------------------------------------------------------------------

    def _update_ip_set(self, ref: dict, add: set[str], remove: set[str]) -> ExecutionResult:
        wafv2 = self.clients("wafv2", ref["region"])
        key = {"Name": ref["name"], "Scope": ref["scope"], "Id": ref["id"]}
        for attempt in range(2):  # one retry on a concurrent writer (WAFOptimisticLockException)
            got = wafv2.get_ip_set(**key)
            before, token = list(got["IPSet"]["Addresses"]), got["LockToken"]
            after = sorted((set(before) | add) - remove)
            if len(after) > IP_SET_LIMIT:
                raise ExecutionError(f"IP set {ref['name']} would exceed {IP_SET_LIMIT} addresses")
            params = {**key, "Addresses": after, "LockToken": token}
            if got["IPSet"].get("Description"):
                params["Description"] = got["IPSet"]["Description"]  # UpdateIPSet would otherwise clear it
            try:
                resp = wafv2.update_ip_set(**params)
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "WAFOptimisticLockException" or attempt:
                    raise
        time.sleep(self.wait)
        check = wafv2.get_ip_set(**key)
        present = set(check["IPSet"]["Addresses"])
        verified = check["LockToken"] != token and add <= present and not (remove & present)
        return ExecutionResult(
            aws_request_id=resp["ResponseMetadata"]["RequestId"], previous_state={"Addresses": before},
            new_state={"Addresses": after}, verified=verified, lock_token_before=token,
            lock_token_after=resp.get("NextLockToken"),
            detail="IP set converged" if verified else "IP set did not converge to the requested state",
        )

    # --- WebACL rules -----------------------------------------------------------------------------------

    def _update_web_acl(self, ref: dict, mutate: Callable[[dict], None],
                        check: Callable[[dict], bool]) -> ExecutionResult:
        wafv2 = self.clients("wafv2", ref["region"])
        key = {"Name": ref["name"], "Scope": ref["scope"], "Id": ref["id"]}
        got = wafv2.get_web_acl(**key)
        before, token = got["WebACL"], got["LockToken"]
        acl = copy.deepcopy(before)
        mutate(acl)
        params = {**key, "LockToken": token, **{k: acl[k] for k in UPDATE_WEB_ACL_KEYS if k in acl}}
        resp = wafv2.update_web_acl(**params)
        time.sleep(self.wait)
        after = wafv2.get_web_acl(**key)
        verified = after["LockToken"] != token and check(after["WebACL"])
        return ExecutionResult(
            aws_request_id=resp["ResponseMetadata"]["RequestId"], previous_state=before, new_state=after["WebACL"],
            verified=verified, lock_token_before=token, lock_token_after=resp.get("NextLockToken"),
            detail="WebACL converged" if verified else "WebACL did not converge to the requested state",
        )

    def _set_rule_action(self, p: dict) -> ExecutionResult:
        name, action = p["rule_name"], p["action"].upper()

        def mutate(acl):
            rule = _find_rule(acl, name)
            if "OverrideAction" in rule:  # rule-group reference: only BLOCK (=None override) or COUNT exist
                if action not in ("BLOCK", "COUNT"):
                    raise ExecutionError(f"Rule group {name} supports only BLOCK or COUNT")
                rule["OverrideAction"] = {"None": {}} if action == "BLOCK" else {"Count": {}}
            else:
                rule["Action"] = {action.title(): {}}

        return self._update_web_acl(p["webacl"], mutate, lambda acl: effective_action(_find_rule(acl, name)) == action)

    def _set_rate_limit(self, p: dict) -> ExecutionResult:
        name, limit = p["rule_name"], int(p["limit"])

        def mutate(acl):
            statement = _find_rule(acl, name)["Statement"]
            if "RateBasedStatement" not in statement:
                raise ExecutionError(f"Rule {name} is not rate-based")
            statement["RateBasedStatement"]["Limit"] = limit

        return self._update_web_acl(
            p["webacl"], mutate, lambda acl: _find_rule(acl, name)["Statement"]["RateBasedStatement"]["Limit"] == limit
        )

    def _add_exception(self, p: dict) -> ExecutionResult:
        name, sub_rule = p["rule_name"], p["excluded_rule"]

        def overrides(acl):
            statement = _find_rule(acl, name)["Statement"].get("ManagedRuleGroupStatement")
            if statement is None:
                raise ExecutionError(f"Rule {name} is not a managed rule group")
            return statement

        def mutate(acl):
            statement = overrides(acl)
            existing = [o for o in statement.get("RuleActionOverrides", []) if o["Name"] != sub_rule]
            statement["RuleActionOverrides"] = [*existing, {"Name": sub_rule, "ActionToUse": {"Count": {}}}]

        return self._update_web_acl(p["webacl"], mutate, lambda acl: any(
            o["Name"] == sub_rule and "Count" in o["ActionToUse"]
            for o in overrides(acl).get("RuleActionOverrides", [])))

    def _restore_rule(self, p: dict) -> ExecutionResult:
        rule = p["rule"]

        def mutate(acl):
            if any(r["Name"] == rule["Name"] for r in acl.get("Rules", [])):
                raise ExecutionError(f"Rule {rule['Name']} already exists")
            if any(r["Priority"] == rule["Priority"] for r in acl.get("Rules", [])):
                raise ExecutionError(f"Priority {rule['Priority']} is taken; restore manually")
            acl["Rules"] = [*acl.get("Rules", []), rule]

        return self._update_web_acl(p["webacl"], mutate,
                                    lambda acl: any(r["Name"] == rule["Name"] for r in acl.get("Rules", [])))

    # --- logging / association ------------------------------------------------------------------------

    def _put_logging(self, p: dict) -> ExecutionResult:
        ref = p["webacl"]
        wafv2 = self.clients("wafv2", ref["region"])
        try:
            previous = wafv2.get_logging_configuration(ResourceArn=ref["arn"])["LoggingConfiguration"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise
            previous = None
        resp = wafv2.put_logging_configuration(
            LoggingConfiguration={"ResourceArn": ref["arn"], "LogDestinationConfigs": [p["log_destination"]]}
        )
        time.sleep(self.wait)
        current = wafv2.get_logging_configuration(ResourceArn=ref["arn"])["LoggingConfiguration"]
        verified = current.get("LogDestinationConfigs") == [p["log_destination"]]
        return ExecutionResult(
            aws_request_id=resp["ResponseMetadata"]["RequestId"], previous_state={"LoggingConfiguration": previous},
            new_state={"LoggingConfiguration": current}, verified=verified,
            detail="Logging enabled" if verified else "Logging configuration did not converge",
            rollback_available=False,  # DeleteLoggingConfiguration is explicitly denied to the ResponseRole
        )

    def _associate(self, p: dict, webacl_arn: str | None = None) -> ExecutionResult:
        wafv2 = self.clients("wafv2", p["region"])
        target = webacl_arn if webacl_arn is not None else p["webacl_arn"]
        previous = wafv2.get_web_acl_for_resource(ResourceArn=p["resource_arn"]).get("WebACL", {}).get("ARN")
        if target:
            resp = wafv2.associate_web_acl(WebACLArn=target, ResourceArn=p["resource_arn"])
        else:
            resp = wafv2.disassociate_web_acl(ResourceArn=p["resource_arn"])
        time.sleep(self.wait)
        current = wafv2.get_web_acl_for_resource(ResourceArn=p["resource_arn"]).get("WebACL", {}).get("ARN")
        verified = current == (target or None)
        return ExecutionResult(
            aws_request_id=resp["ResponseMetadata"]["RequestId"], previous_state={"webacl_arn": previous},
            new_state={"webacl_arn": current}, verified=verified,
            detail="Association converged" if verified else "Association did not converge",
        )

    # --- dispatch -----------------------------------------------------------------------------------------

    def execute(self, proposed: dict) -> ExecutionResult:
        op = proposed["op"]
        if op == "ip_set_add":
            return self._update_ip_set(proposed["ip_set"], set(proposed["add"]), set())
        if op == "ip_set_remove":
            return self._update_ip_set(proposed["ip_set"], set(), set(proposed["remove"]))
        handlers = {"set_rule_action": self._set_rule_action, "set_rate_limit": self._set_rate_limit,
                    "add_exception": self._add_exception, "restore_rule": self._restore_rule,
                    "put_logging": self._put_logging, "associate": self._associate}
        if op not in handlers:
            raise ExecutionError(f"Unsupported operation {op}")
        return handlers[op](proposed)

    def rollback(self, proposed: dict, previous_state: dict, new_state: dict) -> ExecutionResult:
        op = proposed["op"]
        if op in ("ip_set_add", "ip_set_remove"):
            before, after = set(previous_state["Addresses"]), set(new_state["Addresses"])
            return self._update_ip_set(proposed["ip_set"], add=before - after, remove=after - before)
        if op in ("set_rule_action", "set_rate_limit", "add_exception", "restore_rule"):
            name = proposed["rule"]["Name"] if op == "restore_rule" else proposed["rule_name"]
            old_rule = next((r for r in previous_state.get("Rules", []) if r["Name"] == name), None)

            def mutate(acl):
                others = [r for r in acl.get("Rules", []) if r["Name"] != name]
                acl["Rules"] = others + ([old_rule] if old_rule else [])

            def check(acl):
                current = next((r for r in acl.get("Rules", []) if r["Name"] == name), None)
                return current == old_rule

            return self._update_web_acl(proposed["webacl"], mutate, check)
        if op == "associate":
            return self._associate(proposed, webacl_arn=previous_state.get("webacl_arn") or "")
        raise ExecutionError(f"Rollback is not available for {op}")
