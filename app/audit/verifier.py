"""Walk a per-organization chain and report the first broken link.

Single-pass, allocation-light, fully async. Designed to be runnable both
inline (``GET /ledger/verify``) and from a cron / off-site auditor that only
has read access to the DB.
"""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from uuid import UUID

from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.audit.chain import GENESIS_PREV_HASH, compute_hash
from app.models import AuditLog


@dataclass(slots=True, frozen=True)
class VerificationResult:
    """Outcome of :func:`verify_chain`.

    On failure, ``expected_hash`` and ``actual_hash`` carry the recomputed
    vs. stored hash bytes at the broken row. Which *kind* of hash they
    represent depends on ``failure_reason``:

    - ``"link_mismatch"`` — they're prev-hashes (this row's ``prev_hash``
      doesn't match the previous row's ``current_hash``).
    - ``"body_mismatch"`` — they're current-hashes (``SHA-256(prev||body)``
      doesn't match the stored ``current_hash`` — the body or current_hash
      was edited).

    Use ``bool(result)`` as shorthand for ``ok``.
    """

    ok: bool
    rows_checked: int
    broken_at_index: int | None  # 1-based row index of the *first* broken link
    failure_reason: str | None  # "link_mismatch" | "body_mismatch" | None
    expected_hash: bytes | None
    actual_hash: bytes | None
    elapsed_seconds: float

    def __bool__(self) -> bool:  # pragma: no cover — trivial
        return self.ok


async def verify_chain(
    session: AsyncSession,
    *,
    organization_id: UUID,
) -> VerificationResult:
    """Re-derive every link's hash and compare it to what's stored.

    The check is symmetric in both directions:

    - If a row's ``body`` was edited, ``compute_hash(prev, body)`` no longer
      matches the stored ``current_hash`` — broken at that row.
    - If a row's ``prev_hash`` was edited, it no longer matches the previous
      row's ``current_hash`` — broken at that row too.

    Either way we return the **first** broken row, 1-indexed, plus the
    expected vs. actual hash so the operator can see *what* doesn't match.
    See :class:`VerificationResult` for the meaning of those fields under
    each ``failure_reason``.
    """
    started = perf_counter()

    stmt = (
        select(AuditLog)
        .where(col(AuditLog.organization_id) == organization_id)
        .order_by(col(AuditLog.created_at).asc(), col(AuditLog.id).asc())
    )
    rows = list((await session.exec(stmt)).all())

    expected_prev: bytes = GENESIS_PREV_HASH
    for index, row in enumerate(rows, start=1):
        stored_prev: bytes = row.prev_hash if row.prev_hash is not None else GENESIS_PREV_HASH

        # 1. Link check: does this row's prev_hash match the previous row's current_hash?
        if stored_prev != expected_prev:
            return VerificationResult(
                ok=False,
                rows_checked=index,
                broken_at_index=index,
                failure_reason="link_mismatch",
                expected_hash=expected_prev,
                actual_hash=stored_prev,
                elapsed_seconds=perf_counter() - started,
            )

        # 2. Body check: does the stored current_hash match what we recompute?
        recomputed = compute_hash(stored_prev, row.body)
        if recomputed != row.current_hash:
            return VerificationResult(
                ok=False,
                rows_checked=index,
                broken_at_index=index,
                failure_reason="body_mismatch",
                expected_hash=recomputed,
                actual_hash=row.current_hash,
                elapsed_seconds=perf_counter() - started,
            )

        expected_prev = row.current_hash

    return VerificationResult(
        ok=True,
        rows_checked=len(rows),
        broken_at_index=None,
        failure_reason=None,
        expected_hash=None,
        actual_hash=None,
        elapsed_seconds=perf_counter() - started,
    )


__all__ = ["VerificationResult", "verify_chain"]
