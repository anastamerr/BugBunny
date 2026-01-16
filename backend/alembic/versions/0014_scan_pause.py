"""Add scan pause flag

Revision ID: 0014_scan_pause
Revises: 0013_fix_metadata
Create Date: 2025-01-04
"""

from alembic import op
import sqlalchemy as sa

revision = "0014_scan_pause"
down_revision = "0013_fix_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "is_paused",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "is_paused")
