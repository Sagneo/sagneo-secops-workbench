"""Deterministic detections, alerts, and triage history.

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rule_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(16), nullable=False),
        sa.Column("version", sa.String(16), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("source_type", sa.String(24), nullable=False),
        sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("definition", sa.Text(), nullable=False),
        sa.Column("loaded_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("rule_id", "version"),
    )
    op.create_index("ix_rule_versions_rule_id", "rule_versions", ["rule_id"])
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("stable_identity", sa.String(64), nullable=False),
        sa.Column(
            "rule_version_id",
            sa.String(36),
            sa.ForeignKey("rule_versions.id"),
            nullable=False,
        ),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("trigger_summary", sa.Text(), nullable=False),
        sa.Column("scope_impact", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity_rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("false_positive_context", sa.Text(), nullable=False, server_default=""),
        sa.Column("disposition_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("recommended_action", sa.Text(), nullable=False, server_default=""),
        sa.Column("analyst_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "assigned_to_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("stable_identity"),
    )
    for name, columns, unique in (
        ("ix_alerts_stable_identity", ["stable_identity"], True),
        ("ix_alerts_rule_version_id", ["rule_version_id"], False),
        ("ix_alerts_asset_id", ["asset_id"], False),
        ("ix_alerts_status", ["status"], False),
        ("ix_alerts_severity", ["severity"], False),
    ):
        op.create_index(name, "alerts", columns, unique=unique)
    op.create_table(
        "alert_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "alert_id",
            sa.String(36),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_id", sa.String(36), sa.ForeignKey("events.id"), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.UniqueConstraint("alert_id", "event_id"),
        sa.UniqueConstraint("alert_id", "position"),
    )
    op.create_index("ix_alert_events_alert_id", "alert_events", ["alert_id"])
    op.create_index("ix_alert_events_event_id", "alert_events", ["event_id"])
    op.create_table(
        "alert_history",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "alert_id",
            sa.String(36),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "actor_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("from_status", sa.String(16), nullable=True),
        sa.Column("to_status", sa.String(16), nullable=True),
        sa.Column("detail", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alert_history_alert_id", "alert_history", ["alert_id"])


def downgrade() -> None:
    op.drop_table("alert_history")
    op.drop_table("alert_events")
    op.drop_table("alerts")
    op.drop_table("rule_versions")
