"""ORM models — generic Ledger + AuditLog hash-chain entry.

Both models are deliberately small so the extracted patterns stay readable.
Production-grade additions (soft delete, tenant table FK, partitioning, etc.)
have been omitted; see ``docs/threat-model.md`` for what is and isn't covered.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy import Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel

# JSONB on Postgres, JSON on SQLite — keeps unit tests dialect-independent.
_JSONB_VARIANT = JSONB().with_variant(sa.JSON(), "sqlite")


def _now_utc() -> datetime:
    """UTC-naive-aware ``now()`` helper.

    Kept local to the module so the file has no cross-package dependency.
    """
    from datetime import UTC, datetime as _dt

    return _dt.now(UTC)


class Ledger(SQLModel, table=True):
    """A generic financial / compliance entry.

    Fields tagged as *immutable* are guarded by **two** layers:

    1. ``app.repositories.ledger.LedgerRepository._IMMUTABLE_AFTER_INSERT``
    2. PL/pgSQL trigger ``trg_ledger_append_only`` (migration ``002``)

    To "edit" a row, insert a new reversing row (negative ``amount``) that
    references the original via ``reverses_id``.
    """

    __tablename__ = "ledger"

    id: UUID = Field(
        default_factory=uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )
    organization_id: UUID = Field(nullable=False, index=True)

    # ----- immutable fields (enforced at app + DB layer) -----
    amount: Decimal = Field(
        sa_type=sa.Numeric(18, 2),  # type: ignore[call-overload]
        nullable=False,
        description="Signed amount; reversals carry a negative value.",
    )
    currency: str = Field(max_length=8, nullable=False)
    ref: str = Field(
        max_length=64,
        nullable=False,
        description="External reference (invoice no., transaction id, ...).",
    )

    # ----- mutable fields -----
    note_encrypted: bytes | None = Field(
        default=None,
        sa_type=sa.LargeBinary,  # type: ignore[call-overload]
        description="AES-256-GCM ciphertext: nonce(12) | ciphertext | tag.",
    )
    reverses_id: UUID | None = Field(
        default=None,
        foreign_key="ledger.id",
        description="If set, this row reverses the referenced original row.",
    )
    created_at: datetime = Field(
        default_factory=_now_utc,
        sa_type=sa.DateTime(timezone=True),  # type: ignore[call-overload]
        nullable=False,
    )


class AuditLog(SQLModel, table=True):
    """One link in the per-organization hash chain.

    Invariants (enforced by ``app.audit.chain.append_audit``):

    - First row of a chain has ``prev_hash = NULL``.
    - Every subsequent row has ``prev_hash`` = previous row's ``current_hash``.
    - ``current_hash = SHA256(prev_hash_bytes || canonical_body_bytes)``.
    - ``UNIQUE(organization_id, current_hash)`` makes accidental duplicates
      impossible and gives an O(1) lookup from hash to row.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "current_hash",
            name="uq_audit_log_current_hash",
        ),
        Index(
            "idx_audit_log_org_time",
            "organization_id",
            sa.text("created_at DESC"),
        ),
    )

    id: UUID = Field(
        default_factory=uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )
    organization_id: UUID = Field(nullable=False, index=True)
    ledger_id: UUID | None = Field(
        default=None,
        foreign_key="ledger.id",
        description="Subject of the audited action. NULL for org-level events.",
    )

    body: dict[str, Any] = Field(
        default_factory=dict,
        sa_type=_JSONB_VARIANT,  # type: ignore[call-overload]
        sa_column_kwargs={"nullable": False},
        description="Canonical-JSON body that was hashed.",
    )

    prev_hash: bytes | None = Field(
        default=None,
        sa_type=sa.LargeBinary,  # type: ignore[call-overload]
        description="32-byte SHA-256 of previous row, or NULL for genesis.",
    )
    current_hash: bytes = Field(
        sa_type=sa.LargeBinary,  # type: ignore[call-overload]
        nullable=False,
        description="SHA-256(prev_hash || canonical_body).",
    )

    created_at: datetime = Field(
        default_factory=_now_utc,
        sa_type=sa.DateTime(timezone=True),  # type: ignore[call-overload]
        nullable=False,
        index=True,
    )


__all__ = ["AuditLog", "Ledger"]
