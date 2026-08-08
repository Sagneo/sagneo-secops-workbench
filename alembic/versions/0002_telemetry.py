"""Thin assets, source batches, events, and parser errors.

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("hostname", sa.String(64), nullable=False),
        sa.Column("operating_system", sa.String(64), nullable=False),
        sa.Column("lab_ip", sa.String(45), nullable=False),
        sa.Column("purpose_owner", sa.String(96), nullable=False),
        sa.Column("criticality", sa.String(16), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("hostname"),
        sa.UniqueConstraint("lab_ip"),
    )
    op.create_index("ix_assets_hostname", "assets", ["hostname"], unique=True)
    op.create_table(
        "source_batches",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_type", sa.String(24), nullable=False),
        sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("parser_version", sa.String(32), nullable=False),
        sa.Column("source_reference", sa.String(255), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("total_records", sa.Integer(), nullable=False),
        sa.Column("accepted_records", sa.Integer(), nullable=False),
        sa.Column("duplicate_records", sa.Integer(), nullable=False),
        sa.Column("error_records", sa.Integer(), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("earliest_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("latest_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("source_type", "content_digest"),
    )
    op.create_index("ix_source_batches_source_type", "source_batches", ["source_type"])
    op.create_index("ix_source_batches_status", "source_batches", ["status"])
    op.create_table(
        "events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("stable_identity", sa.String(64), nullable=False),
        sa.Column("source_type", sa.String(24), nullable=False),
        sa.Column(
            "source_batch_id",
            sa.String(36),
            sa.ForeignKey("source_batches.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("timestamp_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("actor", sa.String(64), nullable=True),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("summary", sa.String(255), nullable=False),
        sa.Column("normalized_data", sa.Text(), nullable=False),
        sa.Column("raw_reference", sa.String(255), nullable=False),
        sa.UniqueConstraint("stable_identity"),
    )
    op.create_index("ix_events_stable_identity", "events", ["stable_identity"], unique=True)
    op.create_index("ix_events_source_type", "events", ["source_type"])
    op.create_index("ix_events_source_batch_id", "events", ["source_batch_id"])
    op.create_index("ix_events_asset_id", "events", ["asset_id"])
    op.create_index("ix_events_timestamp_utc", "events", ["timestamp_utc"])
    op.create_table(
        "parser_errors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "source_batch_id",
            sa.String(36),
            sa.ForeignKey("source_batches.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("line_number", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(32), nullable=False),
        sa.Column("detail", sa.String(160), nullable=False),
    )
    op.create_index("ix_parser_errors_source_batch_id", "parser_errors", ["source_batch_id"])


def downgrade() -> None:
    op.drop_table("parser_errors")
    op.drop_table("events")
    op.drop_table("source_batches")
    op.drop_table("assets")
