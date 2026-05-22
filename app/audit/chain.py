"""SHA-256 hash chain — pure helpers + transactional append.

Design notes
------------
* **Canonical JSON.** Hashing is over ``json.dumps(body, sort_keys=True,
  separators=(",", ":"), default=str)`` so two semantically-equal bodies always
  produce the same digest, regardless of key order / whitespace.
* **Genesis row.** The first link of a chain has ``prev_hash = b""`` (empty
  bytes), stored as ``NULL`` in the DB. The hash function still takes the
  empty bytes as input so the formula is uniform.
* **No reorgs.** A row's ``current_hash`` becomes the next row's ``prev_hash``,
  so any after-the-fact edit of row *N* invalidates every row from *N+1*
  onwards. Detection is O(n) — see :mod:`app.audit.verifier`.
* **Race-free append.** Inside the caller's transaction we ``SELECT ... FOR
  UPDATE`` on the latest row of the chain, blocking concurrent appenders. Two
  parallel writers can't fork the chain even if they hit the same ``COMMIT``
  microsecond.

What this is *not*
------------------
This is a linear hash chain (think Certificate Transparency v1), **not** a
Merkle tree. It gives tamper-evidence but does not let an outside party prove
a single row's inclusion without seeing the chain head. ``docs/threat-model.md``
walks through that trade-off and what to layer on top (RFC 3161 timestamps,
periodic Merkle anchoring, WORM storage).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import AuditLog

# Exported constants so callers and tests can reference them by name.
HASH_BYTES = 32  # SHA-256 produces 32 bytes
GENESIS_PREV_HASH: bytes = b""


def canonicalize(body: dict[str, Any]) -> bytes:
    """Return the canonical JSON encoding used as the hash input.

    ``sort_keys=True`` + ``separators=(",", ":")`` strips every freedom the
    JSON spec gives an encoder, so the bytes are deterministic. ``default=str``
    catches ``UUID``, ``Decimal``, and ``datetime`` without forcing callers to
    pre-stringify their payload.
    """
    return json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        ensure_ascii=False,
    ).encode("utf-8")


def build_body(
    *,
    organization_id: UUID,
    ledger_id: UUID | None,
    action: str,
    payload: dict[str, Any],
    occurred_at: str,
) -> dict[str, Any]:
    """Build the body dict that gets hashed *and* stored in ``audit_log.body``.

    Storing the exact same dict means a verifier can recompute the hash from
    DB state alone — no out-of-band canonicalisation rules.
    """
    return {
        "organization_id": str(organization_id),
        "ledger_id": str(ledger_id) if ledger_id is not None else None,
        "action": action,
        "payload": payload,
        "occurred_at": occurred_at,
    }


def compute_hash(prev_hash: bytes, body: dict[str, Any]) -> bytes:
    """``SHA-256(prev_hash || canonical_body)`` — the link function.

    ``prev_hash`` is the raw 32-byte digest (or ``b""`` for the genesis row),
    *not* a hex string. Mixing the two is the classic foot-gun: stick to bytes.
    """
    return hashlib.sha256(prev_hash + canonicalize(body)).digest()


async def _select_last_row_for_update(
    session: AsyncSession,
    *,
    organization_id: UUID,
) -> AuditLog | None:
    """Lock the chain tip for this org so concurrent appends serialize.

    On Postgres we use ``SELECT ... FOR UPDATE``. On SQLite (used by unit
    tests) row locks don't apply but writes serialise through the file lock,
    so the same semantics fall out for free.
    """
    stmt = (
        select(AuditLog)
        .where(col(AuditLog.organization_id) == organization_id)
        .order_by(col(AuditLog.created_at).desc(), col(AuditLog.id).desc())
        .limit(1)
    )
    dialect = session.bind.dialect.name if session.bind is not None else ""
    if dialect == "postgresql":
        stmt = stmt.with_for_update()
    result = await session.exec(stmt)
    return result.first()


async def append_audit(
    session: AsyncSession,
    *,
    organization_id: UUID,
    ledger_id: UUID | None,
    action: str,
    payload: dict[str, Any],
    occurred_at: str | None = None,
) -> AuditLog:
    """Append a new link to the chain. Caller controls ``commit``.

    Steps:

    1. ``SELECT ... FOR UPDATE`` the chain tip (None for genesis).
    2. Build the canonical body and compute the new hash.
    3. ``INSERT`` the new row. The ``UNIQUE(organization_id, current_hash)``
       constraint is a backstop against accidental duplicate appends.
    """
    if occurred_at is None:
        from datetime import UTC, datetime

        occurred_at = datetime.now(UTC).isoformat()

    last = await _select_last_row_for_update(session, organization_id=organization_id)
    prev_hash: bytes = last.current_hash if last is not None else GENESIS_PREV_HASH

    body = build_body(
        organization_id=organization_id,
        ledger_id=ledger_id,
        action=action,
        payload=payload,
        occurred_at=occurred_at,
    )
    current_hash = compute_hash(prev_hash, body)

    log = AuditLog(
        organization_id=organization_id,
        ledger_id=ledger_id,
        body=body,
        prev_hash=prev_hash if last is not None else None,  # NULL for genesis
        current_hash=current_hash,
    )
    session.add(log)
    await session.flush()
    return log


# Re-exported for callers who only want the raw SQL fragment (e.g. analytics).
SELECT_CHAIN_ORDERED = text(
    """
    SELECT id, prev_hash, current_hash, body, created_at
    FROM audit_log
    WHERE organization_id = :organization_id
    ORDER BY created_at ASC, id ASC
    """
)


__all__ = [
    "GENESIS_PREV_HASH",
    "HASH_BYTES",
    "SELECT_CHAIN_ORDERED",
    "append_audit",
    "build_body",
    "canonicalize",
    "compute_hash",
]
