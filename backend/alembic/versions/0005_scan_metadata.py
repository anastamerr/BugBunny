"""Add scan metadata

Revision ID: 0005_scan_metadata
Revises: 0004_scans_findings
Create Date: 2025-12-25
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_scan_metadata"
down_revision = "0004_scans_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    scan_trigger_enum = sa.Enum("manual", "webhook", name="scan_trigger")
    scan_trigger_enum.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "scans",
        sa.Column(
            "trigger",
            scan_trigger_enum,
            nullable=False,
            server_default=sa.text("'manual'"),
        ),
    )
    op.add_column("scans", sa.Column("pr_number", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("pr_url", sa.String(), nullable=True))
    op.add_column("scans", sa.Column("commit_sha", sa.String(), nullable=True))
    op.add_column("scans", sa.Column("commit_url", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "commit_url")
    op.drop_column("scans", "commit_sha")
    op.drop_column("scans", "pr_url")
    op.drop_column("scans", "pr_number")
    op.drop_column("scans", "trigger")
    scan_trigger_enum = sa.Enum("manual", "webhook", name="scan_trigger")
    scan_trigger_enum.drop(op.get_bind(), checkfirst=True)
