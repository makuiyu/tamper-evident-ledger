"""Hash-chain tests — in-memory + SQLite.

Covers:

- Pure hash helpers (``canonicalize`` is dict-order-stable, ``compute_hash``
  is deterministic, ``build_body`` produces JSON-safe types).
- ``append_audit`` writes valid links across many appends.
- ``verify_chain`` reports OK on a clean chain, and broken-at-N when a row
  is tampered with after the fact.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.audit import append_audit, verify_chain
from app.audit.chain import (
    GENESIS_PREV_HASH,
    HASH_BYTES,
    build_body,
    canonicalize,
    compute_hash,
)
from app.models import AuditLog


# --- pure helpers ------------------------------------------------------------


def test_canonicalize_is_key_order_stable() -> None:
    a = canonicalize({"b": 1, "a": 2, "c": 3})
    b = canonicalize({"a": 2, "b": 1, "c": 3})
    assert a == b


def test_canonicalize_uses_compact_separators() -> None:
    # No spaces around commas / colons — every byte counts for the hash input.
    body = {"a": 1, "b": [1, 2]}
    assert canonicalize(body) == b'{"a":1,"b":[1,2]}'


def test_canonicalize_handles_uuid_and_decimal() -> None:
    from decimal import Decimal

    value_uuid = uuid4()
    out = canonicalize({"id": value_uuid, "amount": Decimal("12.34")})
    parsed = json.loads(out)
    assert parsed["id"] == str(value_uuid)
    assert parsed["amount"] == "12.34"


def test_compute_hash_is_deterministic_and_sized() -> None:
    body = {"action": "create", "ref": "INV-1"}
    h1 = compute_hash(GENESIS_PREV_HASH, body)
    h2 = compute_hash(GENESIS_PREV_HASH, body)
    assert h1 == h2
    assert len(h1) == HASH_BYTES


def test_compute_hash_changes_when_prev_changes() -> None:
    body = {"action": "create"}
    a = compute_hash(GENESIS_PREV_HASH, body)
    b = compute_hash(b"\x01" * 32, body)
    assert a != b


def test_compute_hash_changes_when_body_changes() -> None:
    a = compute_hash(GENESIS_PREV_HASH, {"action": "a"})
    b = compute_hash(GENESIS_PREV_HASH, {"action": "b"})
    assert a != b


def test_build_body_round_trips_through_canonicalize() -> None:
    body = build_body(
        organization_id=uuid4(),
        ledger_id=uuid4(),
        action="ledger.create",
        payload={"amount": "100"},
        occurred_at=datetime(2026, 5, 22, tzinfo=UTC).isoformat(),
    )
    # canonicalize must not raise on the dict shape we produce.
    raw = canonicalize(body)
    parsed = json.loads(raw)
    assert parsed["action"] == "ledger.create"
    assert parsed["payload"] == {"amount": "100"}


# --- DB-backed ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_append_audit_builds_a_valid_chain(session, org_id) -> None:
    rows: list[AuditLog] = []
    for i in range(5):
        row = await append_audit(
            session,
            organization_id=org_id,
            ledger_id=None,
            action="ledger.create",
            payload={"ref": f"INV-{i:04d}"},
            occurred_at=datetime(2026, 5, 22, 10, i, tzinfo=UTC).isoformat(),
        )
        rows.append(row)
    await session.flush()

    assert rows[0].prev_hash is None
    for prev, curr in zip(rows[:-1], rows[1:], strict=True):
        assert curr.prev_hash == prev.current_hash


@pytest.mark.asyncio
async def test_verify_chain_ok_on_clean_chain(session, org_id) -> None:
    for i in range(3):
        await append_audit(
            session,
            organization_id=org_id,
            ledger_id=None,
            action="ledger.create",
            payload={"ref": f"INV-{i:04d}"},
            occurred_at=datetime(2026, 5, 22, 10, i, tzinfo=UTC).isoformat(),
        )
    await session.commit()

    result = await verify_chain(session, organization_id=org_id)
    assert result.ok is True
    assert result.rows_checked == 3
    assert result.broken_at_index is None


@pytest.mark.asyncio
async def test_verify_chain_detects_tampered_body(session, org_id) -> None:
    rows: list[AuditLog] = []
    for i in range(4):
        rows.append(
            await append_audit(
                session,
                organization_id=org_id,
                ledger_id=None,
                action="ledger.create",
                payload={"ref": f"INV-{i:04d}"},
                occurred_at=datetime(2026, 5, 22, 10, i, tzinfo=UTC).isoformat(),
            )
        )
    await session.commit()

    # Tamper directly with the ORM object's body (bypassing every guard).
    # We rebind to a NEW dict so SQLAlchemy treats this as a value change,
    # not an in-place mutation of an existing dict (which it can miss for JSON).
    from sqlalchemy.orm.attributes import flag_modified

    target = rows[2]
    body = dict(target.body)
    body["payload"] = {"ref": "TAMPERED"}
    target.body = body
    flag_modified(target, "body")
    session.add(target)
    await session.commit()

    result = await verify_chain(session, organization_id=org_id)
    assert result.ok is False
    assert result.broken_at_index == 3  # 1-based — third row tampered
    assert result.failure_reason == "body_mismatch"


@pytest.mark.asyncio
async def test_verify_chain_detects_tampered_prev_hash(session, org_id) -> None:
    rows: list[AuditLog] = []
    for i in range(3):
        rows.append(
            await append_audit(
                session,
                organization_id=org_id,
                ledger_id=None,
                action="ledger.create",
                payload={"ref": f"INV-{i:04d}"},
                occurred_at=datetime(2026, 5, 22, 10, i, tzinfo=UTC).isoformat(),
            )
        )
    await session.commit()

    # Flip a bit in the prev_hash of the last row.
    target = rows[-1]
    bad = bytearray(target.prev_hash or b"\x00" * 32)
    bad[0] ^= 0x01
    target.prev_hash = bytes(bad)
    session.add(target)
    await session.commit()

    result = await verify_chain(session, organization_id=org_id)
    assert result.ok is False
    assert result.broken_at_index == 3
    assert result.failure_reason == "link_mismatch"
    assert result.expected_hash != result.actual_hash


@pytest.mark.asyncio
async def test_verify_chain_empty_org_is_ok(session, org_id) -> None:
    result = await verify_chain(session, organization_id=org_id)
    assert result.ok is True
    assert result.rows_checked == 0
