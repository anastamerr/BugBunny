"""Add scan telemetry fields

Revision ID: 0006_scan_telemetry
Revises: 0005_scan_metadata
Create Date: 2025-12-25
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_scan_telemetry"
down_revision = "0005_scan_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("detected_languages", sa.JSON(), nullable=True))
    op.add_column("scans", sa.Column("rulesets", sa.JSON(), nullable=True))
    op.add_column("scans", sa.Column("scanned_files", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("semgrep_version", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "semgrep_version")
    op.drop_column("scans", "scanned_files")
    op.drop_column("scans", "rulesets")
    op.drop_column("scans", "detected_languages")
