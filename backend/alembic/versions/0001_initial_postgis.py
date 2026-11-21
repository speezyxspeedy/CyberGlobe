"""Initial Alembic migration enabling PostGIS and creating core CyberTrace tables."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial_postgis"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS postgis;")
    op.create_table(
        "roles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=32), nullable=False, unique=True),
        sa.Column("permissions", postgresql.JSONB(), nullable=False),
    )
    op.create_table(
        "cases",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("title", sa.String(length=180), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("priority", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("assigned_analyst", sa.String(length=120), nullable=False),
        sa.Column("tags", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "threat_events",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=False),
        sa.Column("destination_ip", sa.String(length=45), nullable=False),
        sa.Column("source_port", sa.Integer(), nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=24), nullable=False),
        sa.Column("source_location", postgresql.JSONB(), nullable=False),
        sa.Column("destination_location", postgresql.JSONB(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("case_id", sa.String(length=64), sa.ForeignKey("cases.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.execute(
        "ALTER TABLE threat_events ADD COLUMN IF NOT EXISTS geometry geometry(LINESTRING, 4326);"
    )


def downgrade() -> None:
    op.drop_table("threat_events")
    op.drop_table("cases")
    op.drop_table("roles")
