"""Repository layer — first defence against illegal updates.

The DB trigger in ``migrations/alembic/versions/002_append_only_triggers.py``
is the *second* and load-bearing line of defence. This Python layer just gives
the application developer a fast, friendly error (with a list of offending
fields) before the SQL ever leaves the process.
"""

from app.repositories.ledger import (
    BusinessError,
    LedgerRepository,
    create,
    get,
    list_by_org,
)

__all__ = [
    "BusinessError",
    "LedgerRepository",
    "create",
    "get",
    "list_by_org",
]
