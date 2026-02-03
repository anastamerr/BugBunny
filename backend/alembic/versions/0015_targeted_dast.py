"""Add targeted DAST verification fields

Revision ID: 0015_targeted_dast
Revises: 0014_scan_pause
Create Date: 2025-01-26
"""

from alembic import op
import sqlalchemy as sa

revision = "0015_targeted_dast"
down_revision = "0014_scan_pause"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add dast_verified field to findings table
    op.add_column(
        "findings",
        sa.Column(
            "dast_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    # Add dast_confirmed_count field to scans table
    op.add_column(
        "scans",
        sa.Column(
            "dast_confirmed_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )


def downgrade() -> None:
    op.drop_column("findings", "dast_verified")
    op.drop_column("scans", "dast_confirmed_count")
