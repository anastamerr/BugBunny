"""Add bad_request DAST verification status

Revision ID: 0020_dast_bad_request_status
Revises: 0019_sast_metadata_fields
Create Date: 2026-01-31
"""

from alembic import op

revision = "0020_dast_bad_request_status"
down_revision = "0019_sast_metadata_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name if bind is not None else ""
    if dialect == "postgresql":
        op.execute(
            "ALTER TYPE dast_verification_status ADD VALUE IF NOT EXISTS 'bad_request'"
        )


def downgrade() -> None:
    # Enum value removal is not supported in PostgreSQL without a full rebuild.
    pass
