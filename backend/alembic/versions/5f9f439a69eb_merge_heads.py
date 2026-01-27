"""merge heads

Revision ID: 5f9f439a69eb
Revises: 0018_scanguard_scan_v2, da851f3eb96e
Create Date: 2026-01-27 15:26:38.524616

"""

from alembic import op
import sqlalchemy as sa


revision = '5f9f439a69eb'
down_revision = ('0018_scanguard_scan_v2', 'da851f3eb96e')
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

