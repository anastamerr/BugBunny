"""Add autofix metadata to findings

Revision ID: 0013_fix_metadata
Revises: 0012_scan_report_url
Create Date: 2025-01-03
"""

from alembic import op
import sqlalchemy as sa

revision = "0013_fix_metadata"
down_revision = "0012_scan_report_url"
branch_labels = None
depends_on = None


def upgrade() -> None:
    fix_status_enum = sa.Enum(
        "generated",
        "pr_opened",
        "failed",
        name="fix_status",
    )
    fix_status_enum.create(op.get_bind(), checkfirst=True)

    op.add_column(
        "findings",
        sa.Column("fix_status", fix_status_enum, nullable=True),
    )
    op.add_column("findings", sa.Column("fix_summary", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("fix_patch", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("fix_pr_url", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("fix_branch", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("fix_error", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("fix_confidence", sa.Float(), nullable=True))
    op.add_column(
        "findings",
        sa.Column("fix_generated_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "fix_generated_at")
    op.drop_column("findings", "fix_confidence")
    op.drop_column("findings", "fix_error")
    op.drop_column("findings", "fix_branch")
    op.drop_column("findings", "fix_pr_url")
    op.drop_column("findings", "fix_patch")
    op.drop_column("findings", "fix_summary")
    op.drop_column("findings", "fix_status")

    fix_status_enum = sa.Enum(
        "generated",
        "pr_opened",
        "failed",
        name="fix_status",
    )
    fix_status_enum.drop(op.get_bind(), checkfirst=True)
