"""STS cross-account sessions, client factory and throttling classification.

Error class names matter: Step Functions retries match on the Lambda errorType, which is the Python exception
class name. ClientErrors for WAF throttling are re-raised as these classes so the ASL Retry block catches them.
"""

import os
from collections.abc import Callable
from functools import lru_cache

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# Standard retry mode with headroom: 39 accounts x 20 concurrent maps hit WAFv2 per-account TPS limits.
BOTO_CONFIG = Config(retries={"max_attempts": 8, "mode": "standard"}, connect_timeout=5, read_timeout=30)
SESSION_NAME = "sas-waf-discovery"


class WAFLimitsExceededException(Exception):  # noqa: N818 - name must match the ASL Retry ErrorEquals
    pass


class ThrottlingException(Exception):  # noqa: N818
    pass


class AccountAccessError(Exception):
    """sts:AssumeRole into the account's SASWafDiscoveryRole failed."""


THROTTLE_CODES = {"ThrottlingException", "Throttling", "TooManyRequestsException", "RequestLimitExceeded"}

ClientFactory = Callable[[str, str], object]  # (service, region) -> boto3 client


def raise_if_throttled(exc: ClientError) -> None:
    code = exc.response.get("Error", {}).get("Code", "")
    if code == "WAFLimitsExceededException":
        raise WAFLimitsExceededException(str(exc)) from exc
    if code in THROTTLE_CODES:
        raise ThrottlingException(str(exc)) from exc


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "Unknown")


@lru_cache(maxsize=8)
def get_secret(secret_arn: str) -> str:
    return boto3.client("secretsmanager", config=BOTO_CONFIG).get_secret_value(SecretId=secret_arn)["SecretString"]


def discovery_external_id() -> str:
    if value := os.environ.get("SAS_DISCOVERY_EXTERNAL_ID"):
        return value
    return get_secret(os.environ["SAS_DISCOVERY_EXTERNAL_ID_SECRET_ARN"])


def assume_discovery_role(role_arn: str, account_id: str) -> ClientFactory:
    """Assume SASWafDiscoveryRole and return a (service, region) -> client factory bound to that session."""
    try:
        creds = boto3.client("sts", config=BOTO_CONFIG).assume_role(
            RoleArn=role_arn, RoleSessionName=f"{SESSION_NAME}-{account_id}", ExternalId=discovery_external_id(),
            DurationSeconds=900,
        )["Credentials"]
    except ClientError as exc:
        raise AccountAccessError(f"AssumeRole {role_arn} failed: {error_code(exc)}") from exc
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    @lru_cache(maxsize=64)
    def client(service: str, region: str):
        return session.client(service, region_name=region, config=BOTO_CONFIG)

    return client
