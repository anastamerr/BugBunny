"""Add v2 SAST/DAST scan tables

Revision ID: 0018_scanguard_scan_v2
Revises: 0017_dast_auth_support
Create Date: 2026-01-27
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0018_scanguard_scan_v2"
down_revision = "0017_dast_auth_support"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_jobs_v2",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column(
            "scan_type",
            sa.Enum(
                "sast",
                "dast",
                "both",
                name="scan_job_v2_type",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "running",
                "completed",
                "failed",
                name="scan_job_v2_status",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.Column("repo_url", sa.String(), nullable=True),
        sa.Column("branch", sa.String(), nullable=True),
        sa.Column("target_url", sa.String(), nullable=True),
        sa.Column("auth_present", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("metrics", sa.JSON(), nullable=True),
    )

    op.create_table(
        "sast_findings_v2",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_jobs_v2.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("file_path", sa.String(), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("cwe_ids", sa.JSON(), nullable=True),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("raw", sa.JSON(), nullable=False),
    )

    op.create_table(
        "dast_alerts_v2",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_jobs_v2.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("plugin_id", sa.String(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("risk", sa.String(), nullable=False),
        sa.Column("confidence", sa.String(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("param", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("cwe_id", sa.Integer(), nullable=True),
        sa.Column("raw", sa.JSON(), nullable=False),
    )

    op.create_table(
        "correlations_v2",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_jobs_v2.id"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "sast_finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sast_findings_v2.id"),
            nullable=False,
        ),
        sa.Column(
            "matched_dast_alert_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dast_alerts_v2.id"),
            nullable=True,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "CONFIRMED_EXPLOITABLE",
                "UNVERIFIED_NO_MATCH",
                "COULD_NOT_TEST_AUTH_REQUIRED",
                "COULD_NOT_TEST_UNREACHABLE",
                "COULD_NOT_TEST_RATE_LIMITED",
                "COULD_NOT_TEST_INSUFFICIENT_COVERAGE",
                "COULD_NOT_TEST_TIMEOUT",
                "COULD_NOT_TEST_TOOL_ERROR",
                name="verification_status_v2",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("correlation_score", sa.Float(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("correlations_v2")
    op.drop_table("dast_alerts_v2")
    op.drop_table("sast_findings_v2")
    op.drop_table("scan_jobs_v2")
