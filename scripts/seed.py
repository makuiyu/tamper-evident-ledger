"""Insert 10 ledger rows with a valid hash chain.

Each row gets its own audit-chain link. Output is a 10-row table + a final
verification result so you see "valid" right away.
"""

from __future__ import annotations

import asyncio
import sys
from decimal import Decimal
from uuid import UUID

from app.audit import append_audit, verify_chain
from app.config import settings
from app.db import session_scope
from app.models import Ledger
from app.repositories.ledger import create as create_ledger
from app.security import encrypt_field

SEED_ROWS: list[dict[str, object]] = [
    {"amount": Decimal("100.00"), "currency": "USD", "ref": "INV-0001", "note": "Initial deposit"},
    {"amount": Decimal("250.50"), "currency": "USD", "ref": "INV-0002", "note": "Q1 retainer"},
    {"amount": Decimal("-75.25"), "currency": "USD", "ref": "PAY-0001", "note": "Vendor payout"},
    {"amount": Decimal("500.00"), "currency": "USD", "ref": "INV-0003", "note": "Grant tranche A"},
    {"amount": Decimal("1200.00"), "currency": "USD", "ref": "INV-0004", "note": "Donor: Acme Co."},
    {"amount": Decimal("-340.00"), "currency": "USD", "ref": "PAY-0002", "note": "Equipment"},
    {"amount": Decimal("80.00"), "currency": "USD", "ref": "INV-0005", "note": "Interest"},
    {"amount": Decimal("-200.00"), "currency": "USD", "ref": "PAY-0003", "note": "Office rent"},
    {"amount": Decimal("960.75"), "currency": "USD", "ref": "INV-0006", "note": "Grant tranche B"},
    {"amount": Decimal("-150.00"), "currency": "USD", "ref": "PAY-0004", "note": "Travel"},
]


async def main() -> int:
    org_id = UUID(settings.demo_org_id)

    async with session_scope() as session:
        for entry in SEED_ROWS:
            row = Ledger(
                organization_id=org_id,
                amount=entry["amount"],  # type: ignore[arg-type]
                currency=entry["currency"],  # type: ignore[arg-type]
                ref=entry["ref"],  # type: ignore[arg-type]
                note_encrypted=encrypt_field(entry["note"]),  # type: ignore[arg-type]
            )
            await create_ledger(session, row)
            await append_audit(
                session,
                organization_id=org_id,
                ledger_id=row.id,
                action="ledger.create",
                payload={
                    "amount": str(entry["amount"]),
                    "currency": entry["currency"],
                    "ref": entry["ref"],
                    "has_note": entry["note"] is not None,
                },
            )

    async with session_scope() as session:
        result = await verify_chain(session, organization_id=org_id)

    if result.ok:
        print(f"OK  {len(SEED_ROWS)} entries inserted, chain valid "
              f"({result.rows_checked} rows, {result.elapsed_seconds:.4f}s)")
        return 0
    print(f"FAIL chain broken at row #{result.broken_at_index}")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
