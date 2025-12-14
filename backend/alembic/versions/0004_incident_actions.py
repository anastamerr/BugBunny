"""Add incident actions (playbooks)

Revision ID: 0004_incident_actions
Revises: 0003_bug_resolution_notes
Create Date: 2025-12-14
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004_incident_actions"
down_revision = "0003_bug_resolution_notes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incident_actions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("data_incidents.id"),
            nullable=False,
        ),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("owner_team", sa.String(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("todo", "doing", "done", name="incident_action_status"),
            nullable=False,
            server_default="todo",
        ),
        sa.Column(
            "source",
            sa.Enum("generated", "manual", name="incident_action_source"),
            nullable=False,
            server_default="generated",
        ),
        sa.Column("sort_order", sa.Integer(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_incident_actions_incident_id",
        "incident_actions",
        ["incident_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_incident_actions_incident_id", table_name="incident_actions")
    op.drop_table("incident_actions")
    op.execute("DROP TYPE IF EXISTS incident_action_source")
    op.execute("DROP TYPE IF EXISTS incident_action_status")

