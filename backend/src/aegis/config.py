from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"

    # Runtime connection. Must be the aegis_app role, never the owner or a superuser.
    database_url: str

    jwt_private_key_path: Path
    jwt_issuer: str = "aegis"
    jwt_audience: str = "aegis-api"
    access_token_ttl_seconds: int = 900

    approval_ttl_seconds: int = 86_400
    max_body_bytes: int = 65_536
