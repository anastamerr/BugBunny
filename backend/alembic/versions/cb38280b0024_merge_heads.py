"""merge heads

Revision ID: cb38280b0024
Revises: 0020_dast_bad_request_status, 7b1cbd749581
Create Date: 2026-01-31 19:38:23.425542

"""

from alembic import op
import sqlalchemy as sa


revision = 'cb38280b0024'
down_revision = ('0020_dast_bad_request_status', '7b1cbd749581')
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

