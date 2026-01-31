"""Add SAST metadata fields for endpoint extraction

Revision ID: 0019_sast_metadata_fields
Revises: 0018_dast_verify_status
Create Date: 2026-01-31
"""

from alembic import op
import sqlalchemy as sa

revision = "0019_sast_metadata_fields"
down_revision = "0018_dast_verify_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("sast_vuln_type", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("sast_endpoint", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("sast_http_method", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("sast_parameter", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "sast_parameter")
    op.drop_column("findings", "sast_http_method")
    op.drop_column("findings", "sast_endpoint")
    op.drop_column("findings", "sast_vuln_type")
