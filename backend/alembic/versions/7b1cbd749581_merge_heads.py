"""merge heads

Revision ID: 7b1cbd749581
Revises: 0019_sast_metadata_fields, da851f3eb96e
Create Date: 2026-01-31 18:08:33.664557

"""

from alembic import op
import sqlalchemy as sa


revision = '7b1cbd749581'
down_revision = ('0019_sast_metadata_fields', 'da851f3eb96e')
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

