"""Cases, reviewer-gated collection, and evidence verification.

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incident_cases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("opened_by_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("resolution", sa.Text(), nullable=False, server_default=""),
        sa.Column("closure_summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("no_collection_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incident_cases_asset_id", "incident_cases", ["asset_id"])
    op.create_index("ix_incident_cases_status", "incident_cases", ["status"])
    op.create_table(
        "case_alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "case_id",
            sa.String(36),
            sa.ForeignKey("incident_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id"), nullable=False),
        sa.Column("linked_by_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("case_id", "alert_id"),
    )
    op.create_index("ix_case_alerts_case_id", "case_alerts", ["case_id"])
    op.create_index("ix_case_alerts_alert_id", "case_alerts", ["alert_id"])
    op.create_table(
        "case_timeline_entries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "case_id",
            sa.String(36),
            sa.ForeignKey("incident_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "actor_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("entry_type", sa.String(24), nullable=False),
        sa.Column("detail", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_case_timeline_entries_case_id", "case_timeline_entries", ["case_id"])
    op.create_index("ix_case_timeline_entries_entry_type", "case_timeline_entries", ["entry_type"])
    op.create_table(
        "collection_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "case_id",
            sa.String(36),
            sa.ForeignKey("incident_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target_asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("profile_id", sa.String(32), nullable=False),
        sa.Column("profile_version", sa.String(16), nullable=False),
        sa.Column("profile_digest", sa.String(64), nullable=False),
        sa.Column("adapter", sa.String(24), nullable=False),
        sa.Column("limits_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("requested_by_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("reviewed_by_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("reviewer_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("result_summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("error_summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_collection_requests_case_id", "collection_requests", ["case_id"])
    op.create_index(
        "ix_collection_requests_target_asset_id",
        "collection_requests",
        ["target_asset_id"],
    )
    op.create_index("ix_collection_requests_status", "collection_requests", ["status"])
    op.create_table(
        "collection_history",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "request_id",
            sa.String(36),
            sa.ForeignKey("collection_requests.id", ondelete="CASCADE"),
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
    op.create_index("ix_collection_history_request_id", "collection_history", ["request_id"])
    op.create_table(
        "evidence_bundles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "request_id",
            sa.String(36),
            sa.ForeignKey("collection_requests.id"),
            nullable=False,
        ),
        sa.Column(
            "case_id",
            sa.String(36),
            sa.ForeignKey("incident_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target_asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("adapter", sa.String(24), nullable=False),
        sa.Column("profile_id", sa.String(32), nullable=False),
        sa.Column("profile_version", sa.String(16), nullable=False),
        sa.Column("profile_digest", sa.String(64), nullable=False),
        sa.Column("root_reference", sa.String(255), nullable=False),
        sa.Column("manifest_json", sa.Text(), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("collection_status", sa.String(16), nullable=False),
        sa.Column("total_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("request_id"),
    )
    op.create_index(
        "ix_evidence_bundles_request_id", "evidence_bundles", ["request_id"], unique=True
    )
    op.create_index("ix_evidence_bundles_case_id", "evidence_bundles", ["case_id"])
    op.create_table(
        "evidence_artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "bundle_id",
            sa.String(36),
            sa.ForeignKey("evidence_bundles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relative_path", sa.String(160), nullable=False),
        sa.Column("artifact_type", sa.String(32), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.UniqueConstraint("bundle_id", "relative_path"),
    )
    op.create_index("ix_evidence_artifacts_bundle_id", "evidence_artifacts", ["bundle_id"])
    op.create_table(
        "verification_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "bundle_id",
            sa.String(36),
            sa.ForeignKey("evidence_bundles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("incident_cases.id"), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reason_codes_json", sa.Text(), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("verifier_version", sa.String(16), nullable=False),
        sa.Column("independent", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_verification_runs_bundle_id", "verification_runs", ["bundle_id"])
    op.create_index("ix_verification_runs_case_id", "verification_runs", ["case_id"])
    op.create_index("ix_verification_runs_status", "verification_runs", ["status"])
    op.create_table(
        "evidence_alert_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "alert_id",
            sa.String(36),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "verification_run_id",
            sa.String(36),
            sa.ForeignKey("verification_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.UniqueConstraint("alert_id"),
        sa.UniqueConstraint("verification_run_id"),
    )
    op.create_index("ix_evidence_alert_links_alert_id", "evidence_alert_links", ["alert_id"])
    op.create_index(
        "ix_evidence_alert_links_verification_run_id",
        "evidence_alert_links",
        ["verification_run_id"],
    )


def downgrade() -> None:
    op.drop_table("evidence_alert_links")
    op.drop_table("verification_runs")
    op.drop_table("evidence_artifacts")
    op.drop_table("evidence_bundles")
    op.drop_table("collection_history")
    op.drop_table("collection_requests")
    op.drop_table("case_timeline_entries")
    op.drop_table("case_alerts")
    op.drop_table("incident_cases")
