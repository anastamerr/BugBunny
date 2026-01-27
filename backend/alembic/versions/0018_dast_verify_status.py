"""Add new DAST verification status labels

Revision ID: 0018_dast_verify_status
Revises: 0017_dast_auth_support
Create Date: 2026-01-27
"""

from alembic import op

revision = "0018_dast_verify_status"
down_revision = "0017_dast_auth_support"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name if bind is not None else ""
    if dialect == "postgresql":
        op.execute(
            "ALTER TYPE dast_verification_status ADD VALUE IF NOT EXISTS 'not_confirmed'"
        )
        op.execute(
            "ALTER TYPE dast_verification_status ADD VALUE IF NOT EXISTS 'inconclusive'"
        )


def downgrade() -> None:
    # Enum value removal is not supported in PostgreSQL without a full rebuild.
    pass
