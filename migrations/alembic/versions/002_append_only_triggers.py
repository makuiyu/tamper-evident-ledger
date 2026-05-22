"""Append-only PL/pgSQL triggers on ledger.

Revision ID: 002_append_only_triggers
Revises: 001_create_ledger
Create Date: 2026-05-22

Phase 2 of defence in depth: the Python ``LedgerRepository`` catches
well-behaved app code, but anyone with a DB credential (a DBA, a leaked
service account, a compromised admin tool) can issue raw SQL that bypasses
the repo entirely. This migration installs a ``BEFORE UPDATE`` trigger that
raises an exception at the database layer if any immutable column changes.

Dialect handling
----------------
The trigger uses PL/pgSQL and only installs on Postgres. On SQLite (used by
unit tests) we skip — the Repository layer is the only defence there, which
is fine because tests don't simulate a hostile DBA.

Idempotency
-----------
- Function is created with ``CREATE OR REPLACE``.
- Trigger is dropped first (``DROP TRIGGER IF EXISTS``) then re-created.
- ``downgrade()`` drops both safely.
"""

from __future__ import annotations

from alembic import op

# revision identifiers
revision: str = "002_append_only_triggers"
down_revision: str | None = "001_create_ledger"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_LEDGER_FN = """
CREATE OR REPLACE FUNCTION prevent_ledger_amount_update() RETURNS trigger AS $$
BEGIN
    IF NEW.amount IS DISTINCT FROM OLD.amount
       OR NEW.currency IS DISTINCT FROM OLD.currency
       OR NEW.ref IS DISTINCT FROM OLD.ref
    THEN
        RAISE EXCEPTION
            'ledger append-only: amount/currency/ref are immutable; use a reversal row (ledger %)',
            OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

_LEDGER_TRIGGER = """
DROP TRIGGER IF EXISTS trg_ledger_append_only ON ledger;
CREATE TRIGGER trg_ledger_append_only
BEFORE UPDATE ON ledger
FOR EACH ROW EXECUTE FUNCTION prevent_ledger_amount_update();
"""

_AUDIT_FN = """
CREATE OR REPLACE FUNCTION prevent_audit_log_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'audit_log is append-only: row % cannot be UPDATEd or DELETEd',
        OLD.id
        USING ERRCODE = 'check_violation';
END;
$$ LANGUAGE plpgsql;
"""

_AUDIT_TRIGGER_UPDATE = """
DROP TRIGGER IF EXISTS trg_audit_log_no_update ON audit_log;
CREATE TRIGGER trg_audit_log_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_update();
"""

_AUDIT_TRIGGER_DELETE = """
DROP TRIGGER IF EXISTS trg_audit_log_no_delete ON audit_log;
CREATE TRIGGER trg_audit_log_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_update();
"""


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite (used in unit tests) has no PL/pgSQL — the Repository layer
        # is the only defence and that's intentional. Production runs on PG.
        return
    op.execute(_LEDGER_FN)
    op.execute(_LEDGER_TRIGGER)
    op.execute(_AUDIT_FN)
    op.execute(_AUDIT_TRIGGER_UPDATE)
    op.execute(_AUDIT_TRIGGER_DELETE)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_delete ON audit_log;")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_update ON audit_log;")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_log_update();")
    op.execute("DROP TRIGGER IF EXISTS trg_ledger_append_only ON ledger;")
    op.execute("DROP FUNCTION IF EXISTS prevent_ledger_amount_update();")
