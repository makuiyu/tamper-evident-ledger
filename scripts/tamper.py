"""Simulated tamper — raw SQL bypassing every defence except the chain.

The point of this script is to show what survives when an attacker has full
DB access:

1. They UPDATE ``ledger`` row #5's amount (the business record).
2. They UPDATE the matching ``audit_log`` row #5's body to "cover their
   tracks" — making it look like the new amount was the original.

To do (1) we need to bypass the ``BEFORE UPDATE`` trigger from migration 002.
We use ``SET LOCAL session_replication_role = replica`` — the textbook way
a superuser disables triggers for a transaction. To do (2) we don't even
need that, because ``audit_log`` is only protected by triggers (not by the
Python repo), and we're going around the app anyway.

After both edits, the ledger row matches the audit-log body — the two
sources of truth agree on the new (false) amount. But the **chain** is now
broken: editing audit_log row #5's body changes what its ``current_hash``
should be, and the row #6's ``prev_hash`` no longer matches.

That's the proof. The chain catches what every other layer missed.

Re-run ``make verify`` after this to see the chain report a break at row #5.
"""

from __future__ import annotations

import asyncio
import json
import sys
from decimal import Decimal
from uuid import UUID

from sqlalchemy import text

from app.config import settings
from app.db import session_scope
from app.repositories.ledger import list_by_org

ROW_INDEX_1_BASED = 5  # tamper with the 5th oldest row


async def main() -> int:
    org_id = UUID(settings.demo_org_id)

    async with session_scope() as session:
        rows = await list_by_org(session, organization_id=org_id)
        if len(rows) < ROW_INDEX_1_BASED:
            print(
                f"FAIL only {len(rows)} ledger rows exist for org {org_id}; "
                f"run `make seed` first."
            )
            return 1

        target = rows[ROW_INDEX_1_BASED - 1]
        new_amount = target.amount + Decimal("999.00")

        print(f"Tampering: ledger row #{ROW_INDEX_1_BASED} (id={target.id})")
        print(f"   ref:           {target.ref}")
        print(f"   amount before: {target.amount}")
        print(f"   amount after:  {new_amount}")

        bind = session.bind
        dialect = bind.dialect.name if bind is not None else ""

        # ---- Step 1: UPDATE ledger.amount, bypassing the BEFORE UPDATE trigger.
        try:
            if dialect == "postgresql":
                await session.execute(
                    text("SET LOCAL session_replication_role = replica")
                )
            await session.execute(
                text("UPDATE ledger SET amount = :a WHERE id = :id").bindparams(
                    a=new_amount,
                    id=target.id,
                )
            )
        except Exception as exc:  # pragma: no cover — depends on PG perms
            print(f"FAIL raw UPDATE on ledger refused: {exc}")
            print("     (Run as a role with session_replication_role privileges")
            print("      to simulate a DBA with superuser access.)")
            return 1

        # ---- Step 2: rewrite the matching audit_log body to "cover the tracks".
        # The audit row body still claims the original amount. To make the two
        # sources of truth agree on the new (false) value, the attacker also
        # edits the audit row. The CHAIN catches this even when the trigger
        # and repository guards have been bypassed.
        result = await session.execute(
            text(
                """
                SELECT id, body FROM audit_log
                WHERE organization_id = :org_id
                  AND ledger_id = :ledger_id
                ORDER BY created_at ASC, id ASC
                LIMIT 1
                """
            ).bindparams(org_id=org_id, ledger_id=target.id)
        )
        audit_row = result.first()
        if audit_row is None:
            print("FAIL no matching audit_log row found for the tampered ledger row.")
            return 1
        audit_id, raw_body = audit_row
        # SQLite returns the JSON column as a string; Postgres JSONB returns a dict.
        body = json.loads(raw_body) if isinstance(raw_body, str) else dict(raw_body)
        body["payload"]["amount"] = str(new_amount)
        body_json = json.dumps(body)
        if dialect == "postgresql":
            # Cast the bound string to JSONB so it lands in the JSONB column cleanly.
            await session.execute(
                text(
                    "UPDATE audit_log SET body = CAST(:b AS jsonb) WHERE id = :id"
                ).bindparams(b=body_json, id=audit_id)
            )
        else:
            await session.execute(
                text(
                    "UPDATE audit_log SET body = :b WHERE id = :id"
                ).bindparams(b=body_json, id=audit_id)
            )

    print()
    print("OK  Tamper applied to both ledger and audit_log.")
    print("    Run `make verify` — the chain should be reported broken at row #5.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
