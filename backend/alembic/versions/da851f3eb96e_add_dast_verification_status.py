"""add_dast_verification_status

Revision ID: da851f3eb96e
Revises: 0017_dast_auth_support
Create Date: 2026-01-26 21:08:33.614914

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'da851f3eb96e'
down_revision = '0017_dast_auth_support'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create enum type first
    dast_verification_status_enum = sa.Enum(
        'verified',
        'unverified_url',
        'commit_mismatch',
        'verification_error',
        'not_applicable',
        name='dast_verification_status_enum'
    )
    dast_verification_status_enum.create(op.get_bind(), checkfirst=True)

    # Add dast_verification_status column to scans table
    op.add_column(
        'scans',
        sa.Column(
            'dast_verification_status',
            dast_verification_status_enum,
            nullable=False,
            server_default='not_applicable'
        )
    )


def downgrade() -> None:
    # Remove dast_verification_status column and enum type
    op.drop_column('scans', 'dast_verification_status')
    op.execute('DROP TYPE IF EXISTS dast_verification_status_enum')

