"""Initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2025-12-12
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bug_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("bug_id", sa.String(), nullable=True),
        sa.Column(
            "source",
            sa.Enum("github", "jira", "manual", name="bug_source"),
            nullable=True,
        ),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("reporter", sa.String(), nullable=True),
        sa.Column("labels", sa.JSON(), nullable=True),
        sa.Column("stack_trace", sa.String(), nullable=True),
        sa.Column(
            "classified_type",
            sa.Enum("bug", "feature", "question", name="bug_type"),
            nullable=True,
        ),
        sa.Column("classified_component", sa.String(), nullable=True),
        sa.Column(
            "classified_severity",
            sa.Enum("critical", "high", "medium", "low", name="bug_severity"),
            nullable=True,
        ),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column(
            "is_duplicate",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "duplicate_of_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("bug_reports.id"),
            nullable=True,
        ),
        sa.Column("duplicate_score", sa.Float(), nullable=True),
        sa.Column("assigned_team", sa.String(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("new", "triaged", "assigned", "resolved", name="bug_status"),
            nullable=True,
        ),
        sa.Column("embedding_id", sa.String(), nullable=True),
        sa.UniqueConstraint("bug_id"),
    )
    op.create_index("ix_bug_reports_bug_id", "bug_reports", ["bug_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_bug_reports_bug_id", table_name="bug_reports")
    op.drop_table("bug_reports")

