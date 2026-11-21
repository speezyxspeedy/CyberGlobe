"""SQLAlchemy + PostGIS models for CyberTrace Globe (self-hosted PostgreSQL deployment)."""
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base
from geoalchemy2 import Geometry

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String(32), unique=True, nullable=False)  # Viewer, Analyst, Admin
    permissions = Column(JSONB, nullable=False, default=dict)


class User(Base):
    __tablename__ = "users"
    id = Column(String(64), primary_key=True)
    email = Column(String(254), unique=True, nullable=False)
    display_name = Column(String(120), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class CamerasNotRequired(Base):
    """Explicit placeholder compliance table per specification indicating zero camera telemetry."""
    __tablename__ = "cameras_not_required"
    id = Column(Integer, primary_key=True)
    policy_note = Column(String(255), nullable=False, default="Network forensics only; no camera feeds collected.")
    verified_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Asset(Base):
    __tablename__ = "assets"
    id = Column(String(64), primary_key=True)
    name = Column(String(140), nullable=False)
    ip_or_internal_id = Column(String(64), nullable=False)
    location_label = Column(String(120), nullable=False)
    asset_type = Column(String(40), nullable=False)
    criticality = Column(String(16), nullable=False)
    open_ports = Column(JSONB, nullable=False, default=list)
    risk_score = Column(Integer, nullable=False, default=0)
    geometry = Column(Geometry(geometry_type="POINT", srid=4326), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class IpIntelligenceRecord(Base):
    __tablename__ = "ip_intelligence"
    ip = Column(String(45), primary_key=True)
    approx_country = Column(String(80), nullable=False)
    approx_region = Column(String(80), nullable=True)
    approx_city = Column(String(80), nullable=True)
    accuracy_radius_km = Column(Integer, nullable=False, default=25)
    asn = Column(String(32), nullable=True)
    asn_name = Column(String(120), nullable=True)
    isp = Column(String(160), nullable=True)
    connection_type = Column(String(32), nullable=False, default="unknown")
    vpn_probability = Column(Float, nullable=False, default=0.0)
    abuse_confidence = Column(Integer, nullable=False, default=0)
    abuse_report_count = Column(Integer, nullable=False, default=0)
    blocked = Column(Boolean, nullable=False, default=False)
    is_demo_data = Column(Boolean, nullable=False, default=True)
    geometry = Column(Geometry(geometry_type="POINT", srid=4326), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class Case(Base):
    __tablename__ = "cases"
    id = Column(String(64), primary_key=True)
    title = Column(String(180), nullable=False)
    description = Column(Text, nullable=False)
    priority = Column(String(16), nullable=False)
    status = Column(String(24), nullable=False, default="open")
    assigned_analyst = Column(String(120), nullable=False)
    tags = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class ThreatEvent(Base):
    __tablename__ = "threat_events"
    id = Column(String(64), primary_key=True)
    event_type = Column(String(48), nullable=False)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False)
    source_port = Column(Integer, nullable=False)
    destination_port = Column(Integer, nullable=False)
    protocol = Column(String(24), nullable=False)
    source_location = Column(JSONB, nullable=False)
    destination_location = Column(JSONB, nullable=False)
    geometry = Column(Geometry(geometry_type="LINESTRING", srid=4326), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    confidence = Column(Integer, nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    event_metadata = Column("metadata", JSONB, nullable=False, default=dict)
    status = Column(String(24), nullable=False, default="new")
    case_id = Column(String(64), ForeignKey("cases.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String(64), primary_key=True)
    event_id = Column(String(64), ForeignKey("threat_events.id"), nullable=False)
    severity = Column(String(16), nullable=False)
    title = Column(String(200), nullable=False)
    acknowledged = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class CaseEvent(Base):
    __tablename__ = "case_events"
    id = Column(Integer, primary_key=True)
    case_id = Column(String(64), ForeignKey("cases.id"), nullable=False)
    event_id = Column(String(64), ForeignKey("threat_events.id"), nullable=False)
    linked_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class EvidenceFile(Base):
    __tablename__ = "evidence_files"
    id = Column(String(64), primary_key=True)
    case_id = Column(String(64), ForeignKey("cases.id"), nullable=False)
    file_name = Column(String(200), nullable=False)
    file_type = Column(String(64), nullable=False)
    file_size = Column(Integer, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    collected_by = Column(String(120), nullable=False)
    collected_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    source_system = Column(String(120), nullable=False)
    access_history = Column(JSONB, nullable=False, default=list)
    integrity_status = Column(String(24), nullable=False, default="verified")


class InvestigatorNote(Base):
    __tablename__ = "investigator_notes"
    id = Column(String(64), primary_key=True)
    case_id = Column(String(64), ForeignKey("cases.id"), nullable=False)
    author_name = Column(String(120), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String(64), primary_key=True)
    actor_name = Column(String(120), nullable=False)
    role = Column(String(24), nullable=False)
    action = Column(String(120), nullable=False)
    target_type = Column(String(64), nullable=False)
    target_id = Column(String(128), nullable=False)
    details = Column(Text, nullable=False)
    entry_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(String(64), primary_key=True)
    user_id = Column(String(64), ForeignKey("users.id"), nullable=False)
    channel = Column(String(64), nullable=False)
    filter_criteria = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ApiKeyMetadata(Base):
    __tablename__ = "api_keys_metadata"
    id = Column(String(64), primary_key=True)
    provider = Column(String(64), nullable=False)
    key_fingerprint = Column(String(64), nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)
    last_verified_at = Column(DateTime(timezone=True), nullable=True)
