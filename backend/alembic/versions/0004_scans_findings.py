"""Add scans and findings

Revision ID: 0004_scans_findings
Revises: 0003_bug_resolution_notes
Create Date: 2025-12-25
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004_scans_findings"
down_revision = "0003_bug_resolution_notes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("repo_url", sa.String(), nullable=False),
        sa.Column(
            "branch",
            sa.String(),
            nullable=False,
            server_default=sa.text("'main'"),
        ),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "cloning",
                "scanning",
                "analyzing",
                "completed",
                "failed",
                name="scan_status",
            ),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column(
            "total_findings",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "filtered_findings",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("rule_message", sa.Text(), nullable=True),
        sa.Column(
            "semgrep_severity",
            sa.Enum("ERROR", "WARNING", "INFO", name="semgrep_severity"),
            nullable=False,
        ),
        sa.Column(
            "ai_severity",
            sa.Enum("critical", "high", "medium", "low", "info", name="ai_severity"),
            nullable=True,
        ),
        sa.Column(
            "is_false_positive",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("ai_reasoning", sa.Text(), nullable=True),
        sa.Column("ai_confidence", sa.Float(), nullable=True),
        sa.Column("exploitability", sa.Text(), nullable=True),
        sa.Column("file_path", sa.String(), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("code_snippet", sa.Text(), nullable=True),
        sa.Column("context_snippet", sa.Text(), nullable=True),
        sa.Column("function_name", sa.String(), nullable=True),
        sa.Column("class_name", sa.String(), nullable=True),
        sa.Column(
            "is_test_file",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "is_generated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("imports", sa.JSON(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("new", "confirmed", "dismissed", name="finding_status"),
            nullable=False,
            server_default=sa.text("'new'"),
        ),
        sa.Column("priority_score", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    op.drop_table("scans")
