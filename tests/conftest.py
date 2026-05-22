"""Shared test fixtures — async SQLite in-memory engine + session.

Every test gets a fresh database, so we never have to worry about cross-test
state. The chain code's ``SELECT ... FOR UPDATE`` branch is skipped on SQLite
(see :mod:`app.audit.chain`), but the rest of the logic is dialect-agnostic.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from app import models  # noqa: F401 — registers tables on SQLModel.metadata


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )
    async with eng.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
        await s.rollback()


@pytest.fixture
def org_id():
    from uuid import UUID

    return UUID("00000000-0000-0000-0000-0000000000ff")
