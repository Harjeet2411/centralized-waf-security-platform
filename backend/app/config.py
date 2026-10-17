from functools import lru_cache
from typing import Literal
from urllib.parse import quote_plus

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SAS_", env_file=".env", extra="ignore")

    environment: Literal["local", "test", "staging", "production"] = "local"
    database_url: str = "postgresql+asyncpg://sas:sas_local_dev@localhost:5433/sas_waf"
    redis_url: str = "redis://localhost:6379/0"

    frontend_url: str = "http://localhost:5000"
    cors_origins: list[str] = ["http://localhost:5000"]

    session_cookie_name: str = "sas_session"
    session_ttl_seconds: int = 28_800  # 8h, matches Redis key session:user:{id}
    cookie_secure: bool = True

    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: SecretStr = SecretStr("")
    oidc_redirect_uri: str = ""
    oidc_scopes: str = "openid email profile"
    oidc_require_mfa: bool = True

    refresh_freshness_seconds: int = 3_600  # /api/v1/refresh: data younger than this is "ready"

    # Controlled response (Milestone 4)
    aws_region: str = "us-east-1"
    response_external_id: SecretStr = SecretStr("")  # sts:ExternalId of SASWafResponseRole (Secrets Manager)
    sns_topic_arn: str = ""  # approval notifications; empty = disabled
    verify_wait_seconds: float = 2.0  # Rule #7: pause before re-reading AWS state
    ttl_expiring_window_minutes: int = 15
    sync_state_machine_arn: str = ""  # /api/v1/refresh starts this Step Functions state machine

    # Local demo only (docker-compose): POST /api/v1/auth/demo-login signs in as this pre-seeded user without
    # the IdP. Refused in staging/production by _guard_insecure_settings.
    demo_login_email: str = ""

    # ECS injects the RDS secret's username/password as separate env vars and cannot compose a URL; when
    # SAS_DB_HOST is set, database_url is built from these parts (TLS required).
    db_host: str = ""
    db_port: int = 5432
    db_name: str = "sas_waf"
    db_user: str = ""
    db_password: SecretStr = SecretStr("")

    @model_validator(mode="after")
    def _compose_database_url(self) -> "Settings":
        if self.db_host:
            user, password = quote_plus(self.db_user), quote_plus(self.db_password.get_secret_value())
            self.database_url = (f"postgresql+asyncpg://{user}:{password}@{self.db_host}:{self.db_port}/"
                                 f"{self.db_name}?ssl=require")
        return self

    @model_validator(mode="after")
    def _guard_insecure_settings(self) -> "Settings":
        deployed = self.environment in ("staging", "production")
        if deployed and not self.cookie_secure:
            raise ValueError("SAS_COOKIE_SECURE=false is only allowed in local/test environments")
        if deployed and not self.oidc_require_mfa:
            raise ValueError("SAS_OIDC_REQUIRE_MFA=false is only allowed in local/test environments")
        if deployed and self.demo_login_email:
            raise ValueError("SAS_DEMO_LOGIN_EMAIL is only allowed in local/test environments")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
