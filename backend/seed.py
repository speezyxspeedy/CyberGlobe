"""Seed script populating PostgreSQL/PostGIS with labeled CyberTrace DEMO DATA."""
import os
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Role, Asset, Case, CamerasNotRequired


def get_engine_url() -> str:
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "cybertrace")
    user = os.getenv("POSTGRES_USER", "cybertrace_app")
    password = os.getenv("POSTGRES_PASSWORD", "")
    return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{db}"


def seed() -> None:
    engine = create_engine(get_engine_url())
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        for idx, role_name in enumerate(["Viewer", "Analyst", "Admin"], start=1):
            if not session.query(Role).filter_by(name=role_name).first():
                session.add(Role(id=idx, name=role_name, permissions={"role": role_name}))

        if not session.query(CamerasNotRequired).first():
            session.add(CamerasNotRequired())

        if not session.query(Asset).filter_by(id="asset-mum-ssh-01").first():
            session.add(
                Asset(
                    id="asset-mum-ssh-01",
                    name="Mumbai Core Bastion (MUM-SSH-01)",
                    ip_or_internal_id="10.14.0.12",
                    location_label="Mumbai, Maharashtra, India",
                    asset_type="cloud_vm",
                    criticality="critical",
                    open_ports=[22, 443],
                    risk_score=91,
                )
            )

        if not session.query(Case).filter_by(id="CASE-2026-012").first():
            session.add(
                Case(
                    id="CASE-2026-012",
                    title="Case #12 — Coordinated Mumbai SSH Brute-Force & C2 Callback Chain",
                    description="Seeded DEMO DATA investigation case.",
                    priority="critical",
                    status="investigating",
                    assigned_analyst="A. Kulkarni",
                    tags=["ssh-brute-force", "malware-c2", "demo-data"],
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
            )
        session.commit()
    print("CyberTrace Globe PostgreSQL/PostGIS demo seed complete.")


if __name__ == "__main__":
    seed()
