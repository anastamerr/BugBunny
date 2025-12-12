"""Add metrics history table

Revision ID: 0002_metrics_history
Revises: 0001_initial
Create Date: 2025-12-12
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_metrics_history"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "metrics_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("table_name", sa.String(), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_metrics_history_table_name", "metrics_history", ["table_name"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_metrics_history_table_name", table_name="metrics_history")
    op.drop_table("metrics_history")

