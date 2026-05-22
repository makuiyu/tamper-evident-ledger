"""Walk the chain for the demo org and print a green/red result.

Use it from cron / a CI job / an off-site auditor — anywhere with read access
to the DB. No application context needed beyond the DB URL.
"""

from __future__ import annotations

import asyncio
import sys
from uuid import UUID

from app.audit import verify_chain
from app.config import settings
from app.db import session_scope


async def main() -> int:
    org_id = UUID(settings.demo_org_id)
    async with session_scope() as session:
        result = await verify_chain(session, organization_id=org_id)

    if result.ok:
        print(
            f"OK  Chain valid ({result.rows_checked} records, "
            f"{result.elapsed_seconds:.4f}s)"
        )
        return 0

    label = (
        "prev_hash"
        if result.failure_reason == "link_mismatch"
        else "current_hash (body edited)"
    )
    print(f"FAIL Chain broken at row #{result.broken_at_index} ({result.failure_reason})")
    if result.expected_hash is not None:
        print(f"     expected {label}: {result.expected_hash.hex()}")
    if result.actual_hash is not None:
        print(f"     actual   {label}: {result.actual_hash.hex()}")
    print(f"     rows_checked: {result.rows_checked}, elapsed: {result.elapsed_seconds:.4f}s")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
