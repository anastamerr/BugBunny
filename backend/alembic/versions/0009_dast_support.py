"""Add DAST support fields

Revision ID: 0009_dast_support
Revises: 0008_user_settings
Create Date: 2025-12-26
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0009_dast_support"
down_revision = "0008_user_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    scan_type_enum = sa.Enum("sast", "dast", "both", name="scan_type")
    scan_type_enum.create(op.get_bind(), checkfirst=True)

    finding_type_enum = sa.Enum("sast", "dast", name="finding_type")
    finding_type_enum.create(op.get_bind(), checkfirst=True)

    op.alter_column("scans", "repo_url", nullable=True)
    op.add_column(
        "scans",
        sa.Column(
            "scan_type",
            scan_type_enum,
            nullable=False,
            server_default="sast",
        ),
    )
    op.add_column("scans", sa.Column("target_url", sa.String(), nullable=True))
    op.add_column(
        "scans",
        sa.Column("dast_findings", sa.Integer(), nullable=False, server_default="0"),
    )

    op.add_column(
        "findings",
        sa.Column(
            "finding_type",
            finding_type_enum,
            nullable=False,
            server_default="sast",
        ),
    )
    op.add_column("findings", sa.Column("matched_at", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("endpoint", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("curl_command", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("evidence", sa.JSON(), nullable=True))
    op.add_column("findings", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("remediation", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("cve_ids", sa.JSON(), nullable=True))
    op.add_column("findings", sa.Column("cwe_ids", sa.JSON(), nullable=True))
    op.add_column(
        "findings",
        sa.Column(
            "confirmed_exploitable",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("findings", "confirmed_exploitable")
    op.drop_column("findings", "cwe_ids")
    op.drop_column("findings", "cve_ids")
    op.drop_column("findings", "remediation")
    op.drop_column("findings", "description")
    op.drop_column("findings", "evidence")
    op.drop_column("findings", "curl_command")
    op.drop_column("findings", "endpoint")
    op.drop_column("findings", "matched_at")
    op.drop_column("findings", "finding_type")

    op.drop_column("scans", "dast_findings")
    op.drop_column("scans", "target_url")
    op.drop_column("scans", "scan_type")
    op.alter_column("scans", "repo_url", nullable=False)

    finding_type_enum = sa.Enum("sast", "dast", name="finding_type")
    finding_type_enum.drop(op.get_bind(), checkfirst=True)

    scan_type_enum = sa.Enum("sast", "dast", "both", name="scan_type")
    scan_type_enum.drop(op.get_bind(), checkfirst=True)
