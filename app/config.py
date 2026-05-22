"""Settings — loaded from environment / .env.

Keep this tiny on purpose: the chain, encryption, and repository code do not
depend on a settings framework. Only the FastAPI app and CLI scripts use these.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = Field(
        default="postgresql+asyncpg://audit:audit@localhost:55432/audit",
        description="Async DB URL used by the FastAPI app and seed/tamper/verify scripts.",
    )
    alembic_database_url: str = Field(
        default="postgresql+psycopg://audit:audit@localhost:55432/audit",
        description="Sync DB URL used by Alembic.",
    )
    field_encryption_key: str = Field(
        default="change-me-in-production-use-a-32-byte-random-secret",
        description=(
            "Any string — SHA-256 derives a 32-byte AES-256 key. "
            "Rotate by re-encrypting all rows under a new key."
        ),
    )
    demo_org_id: str = Field(
        default="00000000-0000-0000-0000-000000000001",
        description="UUID used by demo scripts as the tenant/organization id.",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
