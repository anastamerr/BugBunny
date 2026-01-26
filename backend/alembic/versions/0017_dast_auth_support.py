"""Add DAST auth fields to scans

Revision ID: 0017_dast_auth_support
Revises: 0016_dast_verification_status
Create Date: 2025-02-02
"""

from alembic import op
import sqlalchemy as sa

revision = "0017_dast_auth_support"
down_revision = "0016_dast_verification_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("dast_auth_headers", sa.JSON(), nullable=True))
    op.add_column("scans", sa.Column("dast_cookies", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "dast_cookies")
    op.drop_column("scans", "dast_auth_headers")
