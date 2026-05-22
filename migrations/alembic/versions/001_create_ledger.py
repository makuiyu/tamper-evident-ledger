"""Create ledger + audit_log tables.

Revision ID: 001_create_ledger
Revises:
Create Date: 2026-05-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "001_create_ledger"
down_revision: str | None = None
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "ledger",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("amount", sa.Numeric(18, 2), nullable=False),
        sa.Column("currency", sa.String(8), nullable=False),
        sa.Column("ref", sa.String(64), nullable=False),
        sa.Column("note_encrypted", sa.LargeBinary, nullable=True),
        sa.Column("reverses_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["reverses_id"], ["ledger.id"], name="fk_ledger_reverses_id"),
    )
    op.create_index("ix_ledger_organization_id", "ledger", ["organization_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ledger_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "body",
            postgresql.JSONB().with_variant(sa.JSON(), "sqlite"),
            nullable=False,
        ),
        sa.Column("prev_hash", sa.LargeBinary, nullable=True),
        sa.Column("current_hash", sa.LargeBinary, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["ledger_id"], ["ledger.id"], name="fk_audit_log_ledger_id"),
        sa.UniqueConstraint(
            "organization_id",
            "current_hash",
            name="uq_audit_log_current_hash",
        ),
    )
    op.create_index("ix_audit_log_organization_id", "audit_log", ["organization_id"])
    op.create_index(
        "idx_audit_log_org_time",
        "audit_log",
        ["organization_id", sa.text("created_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("idx_audit_log_org_time", table_name="audit_log")
    op.drop_index("ix_audit_log_organization_id", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index("ix_ledger_organization_id", table_name="ledger")
    op.drop_table("ledger")
