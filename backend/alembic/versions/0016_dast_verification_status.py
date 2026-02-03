"""Add DAST verification status to findings

Revision ID: 0016_dast_verification_status
Revises: 0015_targeted_dast
Create Date: 2025-02-02
"""

from alembic import op
import sqlalchemy as sa

revision = "0016_dast_verification_status"
down_revision = "0015_targeted_dast"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name if bind is not None else ""
    dast_status_enum = sa.Enum(
        "not_run",
        "confirmed_exploitable",
        "attempted_not_reproduced",
        "blocked_auth_required",
        "blocked_rate_limit",
        "inconclusive_mapping",
        "error_timeout",
        "error_tooling",
        name="dast_verification_status",
    )
    use_enum = dialect == "postgresql"
    if use_enum:
        dast_status_enum.create(bind, checkfirst=True)

    op.add_column(
        "findings",
        sa.Column(
            "dast_verification_status",
            dast_status_enum if use_enum else sa.String(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name if bind is not None else ""
    op.drop_column("findings", "dast_verification_status")

    dast_status_enum = sa.Enum(
        "not_run",
        "confirmed_exploitable",
        "attempted_not_reproduced",
        "blocked_auth_required",
        "blocked_rate_limit",
        "inconclusive_mapping",
        "error_timeout",
        "error_tooling",
        name="dast_verification_status",
    )
    if dialect == "postgresql":
        dast_status_enum.drop(bind, checkfirst=True)
