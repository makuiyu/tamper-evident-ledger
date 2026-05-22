"""HTTP surface — POST /ledger, GET /ledger, GET /ledger/verify.

Each handler is tiny on purpose: the interesting code lives in
:mod:`app.audit`, :mod:`app.security`, :mod:`app.repositories`. This file is
just the wiring you'd drop into your own FastAPI app.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlmodel.ext.asyncio.session import AsyncSession

from app.audit import append_audit, verify_chain
from app.config import settings
from app.db import get_db
from app.models import Ledger
from app.repositories.ledger import (
    BusinessError,
    create as create_ledger,
    list_by_org,
)
from app.security import decrypt_field, encrypt_field

router = APIRouter(prefix="/ledger", tags=["ledger"])


# ---------- schemas -----------------------------------------------------------


class LedgerCreate(BaseModel):
    amount: Decimal = Field(..., description="Signed amount; reversals carry a negative value.")
    currency: str = Field(..., min_length=3, max_length=8)
    ref: str = Field(..., min_length=1, max_length=64)
    note: str | None = Field(default=None, description="Plaintext note; encrypted server-side.")


class LedgerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    amount: Decimal
    currency: str
    ref: str
    note: str | None
    reverses_id: UUID | None
    created_at: datetime


class VerifyResponse(BaseModel):
    ok: bool
    rows_checked: int
    broken_at_index: int | None
    failure_reason: str | None
    expected_hash_hex: str | None
    actual_hash_hex: str | None
    elapsed_seconds: float


# ---------- helpers -----------------------------------------------------------


def _default_org_id() -> UUID:
    """Return the demo org id from settings.

    A real app would derive this from the JWT / session; we keep it global so
    the demo is single-tenant by default.
    """
    return UUID(settings.demo_org_id)


def _to_out(row: Ledger) -> LedgerOut:
    return LedgerOut(
        id=row.id,
        organization_id=row.organization_id,
        amount=row.amount,
        currency=row.currency,
        ref=row.ref,
        note=decrypt_field(row.note_encrypted),
        reverses_id=row.reverses_id,
        created_at=row.created_at,
    )


# ---------- routes ------------------------------------------------------------


@router.post("", response_model=LedgerOut, status_code=status.HTTP_201_CREATED)
async def post_ledger(
    body: LedgerCreate,
    db: AsyncSession = Depends(get_db),
) -> LedgerOut:
    """Create a new ledger entry and append a matching audit-chain link.

    Both writes share one transaction so an audit row can never exist without
    its ledger row, or vice versa.
    """
    org_id = _default_org_id()

    row = Ledger(
        organization_id=org_id,
        amount=body.amount,
        currency=body.currency,
        ref=body.ref,
        note_encrypted=encrypt_field(body.note),
    )
    await create_ledger(db, row)

    audit_payload: dict[str, Any] = {
        "amount": str(body.amount),
        "currency": body.currency,
        "ref": body.ref,
        "has_note": body.note is not None,
    }
    await append_audit(
        db,
        organization_id=org_id,
        ledger_id=row.id,
        action="ledger.create",
        payload=audit_payload,
    )
    return _to_out(row)


@router.get("", response_model=list[LedgerOut])
async def list_ledger(db: AsyncSession = Depends(get_db)) -> list[LedgerOut]:
    rows = await list_by_org(db, organization_id=_default_org_id())
    return [_to_out(r) for r in rows]


@router.get("/verify", response_model=VerifyResponse)
async def get_verify(db: AsyncSession = Depends(get_db)) -> VerifyResponse:
    """Re-derive every hash and report the first broken link, if any."""
    result = await verify_chain(db, organization_id=_default_org_id())
    return VerifyResponse(
        ok=result.ok,
        rows_checked=result.rows_checked,
        broken_at_index=result.broken_at_index,
        failure_reason=result.failure_reason,
        expected_hash_hex=(
            result.expected_hash.hex() if result.expected_hash is not None else None
        ),
        actual_hash_hex=(
            result.actual_hash.hex() if result.actual_hash is not None else None
        ),
        elapsed_seconds=result.elapsed_seconds,
    )


# ---------- exception handlers ------------------------------------------------


def install_exception_handlers(app: Any) -> None:
    """Wire :class:`BusinessError` into FastAPI as a 409 with structured detail."""

    @app.exception_handler(BusinessError)
    async def _handle_business_error(_request: Any, exc: BusinessError) -> None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"message": str(exc), **exc.detail},
        )
