"""Repository-layer immutability + reversal tests.

These cover the *first* line of defence (the Python ``LedgerRepository``
guard). The second line (PL/pgSQL trigger) is dialect-dependent and only
loaded on a real Postgres — see the integration target ``make tamper`` for
that path.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.models import Ledger
from app.repositories.ledger import (
    BusinessError,
    LedgerRepository,
    bulk_create,
    create,
    list_by_org,
    total_amount,
)


def _make_row(org_id, amount="100.00", ref="INV-0001", currency="USD") -> Ledger:
    return Ledger(
        organization_id=org_id,
        amount=Decimal(amount),
        currency=currency,
        ref=ref,
    )


def test_immutable_fields_set_matches_design() -> None:
    repo = LedgerRepository()
    assert repo.immutable_fields == frozenset({"amount", "currency", "ref"})


def test_update_allows_mutable_fields(org_id) -> None:
    repo = LedgerRepository()
    row = _make_row(org_id)
    repo.update(row, {"note_encrypted": b"\x00" * 32})
    assert row.note_encrypted == b"\x00" * 32


@pytest.mark.parametrize("field,value", [
    ("amount", Decimal("999.99")),
    ("currency", "EUR"),
    ("ref", "HACKED"),
])
def test_update_rejects_immutable_field(org_id, field, value) -> None:
    repo = LedgerRepository()
    row = _make_row(org_id)
    with pytest.raises(BusinessError) as excinfo:
        repo.update(row, {field: value})
    assert field in excinfo.value.detail["immutable_fields"]


def test_update_rejects_mixed_legal_and_illegal(org_id) -> None:
    repo = LedgerRepository()
    row = _make_row(org_id)
    with pytest.raises(BusinessError) as excinfo:
        repo.update(row, {"note_encrypted": b"x", "amount": Decimal("1")})
    # Even one illegal field aborts the whole update — no partial application.
    assert excinfo.value.detail["immutable_fields"] == ["amount"]
    # And the legal field was NOT applied.
    assert row.note_encrypted is None


def test_build_reversal_negates_amount_and_links_back(org_id) -> None:
    repo = LedgerRepository()
    original = _make_row(org_id, amount="250.00", ref="INV-0007")
    reversal = repo.build_reversal(original)
    assert reversal.amount == Decimal("-250.00")
    assert reversal.currency == original.currency
    assert reversal.ref == "INV-0007-R"
    assert reversal.reverses_id == original.id
    # Crucially: the original is untouched.
    assert original.amount == Decimal("250.00")
    assert original.ref == "INV-0007"


@pytest.mark.asyncio
async def test_create_and_list_round_trip(session, org_id) -> None:
    await create(session, _make_row(org_id, amount="100.00", ref="INV-0001"))
    await create(session, _make_row(org_id, amount="-25.00", ref="PAY-0001"))
    await session.commit()

    rows = await list_by_org(session, organization_id=org_id)
    assert len(rows) == 2
    assert {r.ref for r in rows} == {"INV-0001", "PAY-0001"}


@pytest.mark.asyncio
async def test_bulk_create_persists_in_order(session, org_id) -> None:
    rows = [
        _make_row(org_id, amount="10", ref="A"),
        _make_row(org_id, amount="20", ref="B"),
        _make_row(org_id, amount="30", ref="C"),
    ]
    await bulk_create(session, rows)
    await session.commit()

    listed = await list_by_org(session, organization_id=org_id)
    assert [r.ref for r in listed] == ["A", "B", "C"]
    assert total_amount(listed) == Decimal("60")
