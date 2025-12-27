"""Add user settings for integrations

Revision ID: 0008_user_settings
Revises: 0007_user_repos
Create Date: 2025-12-26
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0008_user_settings"
down_revision = "0007_user_repos"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_settings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("github_token", sa.Text(), nullable=True),
        sa.Column("github_webhook_secret", sa.Text(), nullable=True),
        sa.Column("github_allowlist", sa.JSON(), nullable=True),
        sa.Column(
            "enable_scan_push",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "enable_scan_pr",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "enable_issue_ingest",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "enable_issue_comment_ingest",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("user_id", name="uq_user_settings_user_id"),
    )
    op.create_index(
        "ix_user_settings_user_id", "user_settings", ["user_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_user_settings_user_id", table_name="user_settings")
    op.drop_table("user_settings")
