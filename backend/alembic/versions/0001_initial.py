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
        "data_incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("incident_id", sa.String(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("table_name", sa.String(), nullable=False),
        sa.Column(
            "incident_type",
            sa.Enum(
                "SCHEMA_DRIFT",
                "NULL_SPIKE",
                "VOLUME_ANOMALY",
                "FRESHNESS",
                "DISTRIBUTION_DRIFT",
                "VALIDATION_FAILURE",
                name="incident_type",
            ),
            nullable=True,
        ),
        sa.Column(
            "severity",
            sa.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", name="severity"),
            nullable=True,
        ),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("affected_columns", sa.JSON(), nullable=True),
        sa.Column("anomaly_score", sa.Float(), nullable=True),
        sa.Column("downstream_systems", sa.JSON(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("ACTIVE", "INVESTIGATING", "RESOLVED", name="status"),
            nullable=True,
        ),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolution_notes", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.UniqueConstraint("incident_id"),
    )
    op.create_index(
        "ix_data_incidents_incident_id", "data_incidents", ["incident_id"], unique=True
    )
    op.create_index(
        "ix_data_incidents_table_name", "data_incidents", ["table_name"], unique=False
    )

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
            "is_data_related",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "correlated_incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("data_incidents.id"),
            nullable=True,
        ),
        sa.Column("correlation_score", sa.Float(), nullable=True),
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

    op.create_table(
        "correlations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "bug_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("bug_reports.id"),
            nullable=True,
        ),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("data_incidents.id"),
            nullable=True,
        ),
        sa.Column("correlation_score", sa.Float(), nullable=True),
        sa.Column("temporal_score", sa.Float(), nullable=True),
        sa.Column("component_score", sa.Float(), nullable=True),
        sa.Column("keyword_score", sa.Float(), nullable=True),
        sa.Column("explanation", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )

    op.create_table(
        "resolution_patterns",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("incident_type", sa.String(), nullable=True),
        sa.Column("affected_table", sa.String(), nullable=True),
        sa.Column("symptom_keywords", sa.JSON(), nullable=True),
        sa.Column("resolution_action", sa.String(), nullable=True),
        sa.Column("resolution_time_avg", sa.Float(), nullable=True),
        sa.Column(
            "occurrence_count",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=True,
        ),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("embedding_id", sa.String(), nullable=True),
    )

    op.create_table(
        "bug_predictions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("data_incidents.id"),
            nullable=True,
        ),
        sa.Column("predicted_bug_count", sa.Integer(), nullable=True),
        sa.Column("predicted_components", sa.JSON(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("prediction_window_hours", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.Column("actual_bug_count", sa.Integer(), nullable=True),
        sa.Column("was_accurate", sa.Boolean(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("bug_predictions")
    op.drop_table("resolution_patterns")
    op.drop_table("correlations")
    op.drop_index("ix_bug_reports_bug_id", table_name="bug_reports")
    op.drop_table("bug_reports")
    op.drop_index("ix_data_incidents_table_name", table_name="data_incidents")
    op.drop_index("ix_data_incidents_incident_id", table_name="data_incidents")
    op.drop_table("data_incidents")

