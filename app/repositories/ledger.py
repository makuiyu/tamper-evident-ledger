"""Ledger repository — CRUD + Python-layer append-only guard.

Pattern (see :mod:`docs/threat-model.md` "Two layers of defence"):

- ``_IMMUTABLE_AFTER_INSERT`` lists the columns that must never change.
- :meth:`LedgerRepository.update` checks the diff against that set *before*
  the SQL is emitted, so well-behaved app code gets a clean ``BusinessError``
  with the offending field names — no opaque DB exception.
- The PL/pgSQL trigger in migration ``002`` covers the cases this layer
  can't: raw ``UPDATE``, ``psql`` sessions, ORM bypass, compromised app code.

Reversal flow
-------------
"Editing" a ledger row is a domain-level no-op. Instead, callers create a
*new* row with negative ``amount`` and ``reverses_id`` pointing at the
original. The original is never touched, the audit chain gets two entries
(one for the original, one for the reversal), and the running balance still
adds up.
"""

from __future__ import annotations

from collections.abc import Iterable
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Ledger


class BusinessError(Exception):
    """Raised when a domain rule is violated (e.g. illegal field update).

    Carries a ``detail`` dict so API layers can surface structured info
    (e.g. which fields were rejected) without parsing the message.
    """

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.detail = detail or {}


class LedgerRepository:
    """Encapsulates the append-only semantics around :class:`app.models.Ledger`."""

    #: Fields that must never change after a row is inserted.
    _IMMUTABLE_AFTER_INSERT: frozenset[str] = frozenset({"amount", "currency", "ref"})

    @property
    def immutable_fields(self) -> frozenset[str]:
        return self._IMMUTABLE_AFTER_INSERT

    def update(self, row: Ledger, changes: dict[str, Any]) -> Ledger:
        """Apply ``changes`` in-place; raise if any immutable field is touched.

        Mutable fields (``note_encrypted``, etc.) can still be updated — this
        is the layer where "fix the encrypted note typo" is legal but "edit
        the amount" is not.
        """
        illegal = set(changes) & self._IMMUTABLE_AFTER_INSERT
        if illegal:
            raise BusinessError(
                "Immutable fields on ledger; use the reversal flow instead",
                detail={"immutable_fields": sorted(illegal)},
            )
        for key, value in changes.items():
            setattr(row, key, value)
        return row

    def build_reversal(
        self,
        original: Ledger,
        *,
        ref_suffix: str = "-R",
    ) -> Ledger:
        """Build (but do not persist) a row that reverses ``original``.

        Caller is expected to:

        1. Add the returned row to the session.
        2. Append an audit entry for the reversal.
        3. Commit the transaction.
        """
        return Ledger(
            organization_id=original.organization_id,
            amount=-original.amount,
            currency=original.currency,
            ref=f"{original.ref}{ref_suffix}",
            reverses_id=original.id,
            note_encrypted=None,
        )


# ---------- module-level async helpers ---------------------------------------


async def create(session: AsyncSession, row: Ledger) -> Ledger:
    session.add(row)
    await session.flush()
    return row


async def get(session: AsyncSession, ledger_id: UUID) -> Ledger | None:
    stmt = select(Ledger).where(col(Ledger.id) == ledger_id)
    return (await session.exec(stmt)).first()


async def list_by_org(
    session: AsyncSession,
    *,
    organization_id: UUID,
    limit: int = 200,
) -> list[Ledger]:
    stmt = (
        select(Ledger)
        .where(col(Ledger.organization_id) == organization_id)
        .order_by(col(Ledger.created_at).asc())
        .limit(limit)
    )
    return list((await session.exec(stmt)).all())


async def bulk_create(session: AsyncSession, rows: Iterable[Ledger]) -> list[Ledger]:
    materialised = list(rows)
    session.add_all(materialised)
    await session.flush()
    return materialised


def total_amount(rows: Iterable[Ledger]) -> Decimal:
    """Sum a sequence of rows (handy for sanity-checks in seed scripts)."""
    return sum((row.amount for row in rows), start=Decimal("0"))


__all__ = [
    "BusinessError",
    "LedgerRepository",
    "bulk_create",
    "create",
    "get",
    "list_by_org",
    "total_amount",
]
