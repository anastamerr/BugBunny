"""Add repositories and user-scoped scans

Revision ID: 0007_user_repos
Revises: 0006_scan_telemetry
Create Date: 2025-12-26
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0007_user_repos"
down_revision = "0006_scan_telemetry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("repo_url", sa.String(), nullable=False),
        sa.Column("repo_full_name", sa.String(), nullable=True),
        sa.Column("default_branch", sa.String(), nullable=False, server_default="main"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("user_id", "repo_url", name="uq_repo_user_url"),
    )
    op.create_index(
        "ix_repositories_user_id", "repositories", ["user_id"], unique=False
    )

    op.add_column("scans", sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("scans", sa.Column("repo_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_index("ix_scans_user_id", "scans", ["user_id"], unique=False)
    op.create_foreign_key(
        "fk_scans_repo_id",
        "scans",
        "repositories",
        ["repo_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_scans_repo_id", "scans", type_="foreignkey")
    op.drop_index("ix_scans_user_id", table_name="scans")
    op.drop_column("scans", "repo_id")
    op.drop_column("scans", "user_id")

    op.drop_index("ix_repositories_user_id", table_name="repositories")
    op.drop_table("repositories")
