"""Add resolution notes to bugs

Revision ID: 0003_bug_resolution_notes
Revises: 0002_metrics_history
Create Date: 2025-12-12
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_bug_resolution_notes"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("bug_reports", sa.Column("resolution_notes", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("bug_reports", "resolution_notes")

