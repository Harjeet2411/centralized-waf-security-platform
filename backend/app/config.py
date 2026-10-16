from functools import lru_cache
from typing import Literal

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

    @model_validator(mode="after")
    def _guard_insecure_settings(self) -> "Settings":
        deployed = self.environment in ("staging", "production")
        if deployed and not self.cookie_secure:
            raise ValueError("SAS_COOKIE_SECURE=false is only allowed in local/test environments")
        if deployed and not self.oidc_require_mfa:
            raise ValueError("SAS_OIDC_REQUIRE_MFA=false is only allowed in local/test environments")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
