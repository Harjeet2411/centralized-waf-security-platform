"""Stateful in-memory WAFv2 for executor tests: LockTokens rotate on every write, stale tokens raise
WAFOptimisticLockException, `silent` swallows writes (to prove verification catches non-convergence) and `deny`
raises AccessDenied (to prove failures are audited)."""

import copy
import itertools

from botocore.exceptions import ClientError

from app.services.aws_executor import UPDATE_WEB_ACL_KEYS, WafExecutor

ACCOUNT = "123456789012"
IPSET_ARN = f"arn:aws:wafv2:eu-west-1:{ACCOUNT}:regional/ipset/sas-platform-blocklist/ips-1"
WEBACL_ARN = f"arn:aws:wafv2:eu-west-1:{ACCOUNT}:regional/webacl/prod-payments-waf/r-1"

BASE_ACL = {
    "Name": "prod-payments-waf", "Id": "r-1", "ARN": WEBACL_ARN, "Capacity": 700, "DefaultAction": {"Allow": {}},
    "Description": "payments", "LabelNamespace": "awswaf:123456789012:webacl:prod-payments-waf:",
    "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "pp"},
    "Rules": [
        {"Name": "SAS-Platform-Blocklist", "Priority": 0, "Action": {"Block": {}},
         "Statement": {"IPSetReferenceStatement": {"ARN": IPSET_ARN}},
         "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "bl"}},
        {"Name": "AWS-SQLi", "Priority": 1, "OverrideAction": {"None": {}},
         "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesSQLiRuleSet"}},
         "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "sq"}},
        {"Name": "Custom-Checkout-RateLimit", "Priority": 2, "Action": {"Count": {}},
         "Statement": {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}},
         "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "rl"}},
    ],
}


def _error(code: str, op: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


class FakeWafv2:
    def __init__(self):
        self._tokens = itertools.count(1)
        self._requests = itertools.count(1)
        self.ip_set = {"Addresses": ["192.0.2.0/32"], "Description": "SAS platform blocklist", "LockToken": self._tok()}
        self.acl = {"WebACL": copy.deepcopy(BASE_ACL), "LockToken": self._tok()}
        self.associations: dict[str, str] = {}
        self.logging: dict[str, str] = {}
        self.silent = False
        self.deny = False
        self.calls: list[str] = []

    def _tok(self) -> str:
        return f"lock-{next(self._tokens)}"

    def _meta(self) -> dict:
        return {"ResponseMetadata": {"RequestId": f"req-{next(self._requests)}"}}

    def _guard(self, op):
        self.calls.append(op)
        if self.deny:
            raise _error("AccessDeniedException", op)

    def get_ip_set(self, Name, Scope, Id):  # noqa: N803
        self._guard("GetIPSet")
        return {"IPSet": {"Name": Name, "Id": Id, "ARN": IPSET_ARN, "Addresses": list(self.ip_set["Addresses"]),
                          "IPAddressVersion": "IPV4", "Description": self.ip_set["Description"]},
                "LockToken": self.ip_set["LockToken"]}

    def update_ip_set(self, Name, Scope, Id, Addresses, LockToken, Description=None):  # noqa: N803
        self._guard("UpdateIPSet")
        if LockToken != self.ip_set["LockToken"]:
            raise _error("WAFOptimisticLockException", "UpdateIPSet")
        if not self.silent:
            self.ip_set = {"Addresses": list(Addresses), "Description": Description or "", "LockToken": self._tok()}
        return {"NextLockToken": self.ip_set["LockToken"], **self._meta()}

    def get_web_acl(self, Name, Scope, Id):  # noqa: N803
        self._guard("GetWebACL")
        return copy.deepcopy(self.acl)

    def update_web_acl(self, Name, Scope, Id, LockToken, **params):  # noqa: N803
        self._guard("UpdateWebACL")
        unexpected = set(params) - set(UPDATE_WEB_ACL_KEYS)
        assert not unexpected, f"UpdateWebACL got read-only keys {unexpected}"
        if LockToken != self.acl["LockToken"]:
            raise _error("WAFOptimisticLockException", "UpdateWebACL")
        if not self.silent:
            self.acl = {"WebACL": {**self.acl["WebACL"], **copy.deepcopy(params)}, "LockToken": self._tok()}
        return {"NextLockToken": self.acl["LockToken"], **self._meta()}

    def get_web_acl_for_resource(self, ResourceArn):  # noqa: N803
        self._guard("GetWebACLForResource")
        arn = self.associations.get(ResourceArn)
        return {"WebACL": {"ARN": arn, "Name": "x", "Id": "x"}} if arn else {}

    def associate_web_acl(self, WebACLArn, ResourceArn):  # noqa: N803
        self._guard("AssociateWebACL")
        if not self.silent:
            self.associations[ResourceArn] = WebACLArn
        return self._meta()

    def disassociate_web_acl(self, ResourceArn):  # noqa: N803
        self._guard("DisassociateWebACL")
        self.associations.pop(ResourceArn, None)
        return self._meta()

    def get_logging_configuration(self, ResourceArn):  # noqa: N803
        self._guard("GetLoggingConfiguration")
        if ResourceArn not in self.logging:
            raise _error("WAFNonexistentItemException", "GetLoggingConfiguration")
        return {"LoggingConfiguration": {"ResourceArn": ResourceArn,
                                         "LogDestinationConfigs": [self.logging[ResourceArn]]}}

    def put_logging_configuration(self, LoggingConfiguration):  # noqa: N803
        self._guard("PutLoggingConfiguration")
        self.logging[LoggingConfiguration["ResourceArn"]] = LoggingConfiguration["LogDestinationConfigs"][0]
        return {"LoggingConfiguration": LoggingConfiguration, **self._meta()}

    def rule(self, name: str) -> dict:
        return next(r for r in self.acl["WebACL"]["Rules"] if r["Name"] == name)


class FakeExecutorFactory:
    """Stands in for assume_response_role: records the session identity the executor would carry."""

    def __init__(self, waf: FakeWafv2):
        self.waf = waf
        self.sessions: list[dict] = []

    def __call__(self, role_arn, account_id, approval_code, approver):
        self.sessions.append({"role_arn": role_arn, "account_id": account_id, "approval_code": approval_code,
                              "approver": approver})
        return WafExecutor(lambda service, region: self.waf, wait_seconds=0)
