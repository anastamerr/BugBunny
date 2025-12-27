"""Add reachability analysis fields

Revision ID: 0010_reachability_analysis
Revises: 0009_dast_support
Create Date: 2025-12-27
"""

from alembic import op
import sqlalchemy as sa

revision = "0010_reachability_analysis"
down_revision = "0009_dast_support"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "is_reachable",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )
    op.add_column(
        "findings",
        sa.Column(
            "reachability_score",
            sa.Float(),
            nullable=True,
            server_default=sa.text("1.0"),
        ),
    )
    op.add_column(
        "findings",
        sa.Column("reachability_reason", sa.Text(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("entry_points", sa.JSON(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("call_path", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "call_path")
    op.drop_column("findings", "entry_points")
    op.drop_column("findings", "reachability_reason")
    op.drop_column("findings", "reachability_score")
    op.drop_column("findings", "is_reachable")
