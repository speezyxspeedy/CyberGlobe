"""CyberTrace Globe — FastAPI async backend with WebSocket streaming and external threat intel enrichment."""
from datetime import datetime, timezone
import hashlib
import os
import re
from typing import Any, Optional
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
import httpx

load_dotenv()

app = FastAPI(title="CyberTrace Globe API", version="1.0.0")

APPROX_DISCLAIMER = (
    "Approximate network location · Investigative lead only — not proof of a person's physical location."
)
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)$")


class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, msg_type: str, payload: Any) -> None:
        message = {
            "type": msg_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        for conn in list(self.active):
            try:
                await conn.send_json(message)
            except Exception:
                self.disconnect(conn)


manager = ConnectionManager()


class AssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=140)
    ip_or_internal_id: str = Field(..., min_length=1, max_length=64)
    location_label: str = Field(..., min_length=1, max_length=120)
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    asset_type: str = "cloud_vm"
    criticality: str = "high"
    open_ports: list[int] = Field(default_factory=lambda: [443])


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=180)
    description: str = Field(..., min_length=1, max_length=4000)
    priority: str = "high"
    assigned_analyst: str = "SOC Analyst"
    tags: list[str] = Field(default_factory=list)


class EvidenceUpload(BaseModel):
    file_name: str
    file_type: str = "text/plain"
    content: str
    collected_by: str = "SOC Analyst"
    source_system: str = "Analyst Upload"


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "CyberTrace Globe FastAPI Backend",
        "ws_clients": len(manager.active),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/ip/{ip}/intelligence")
async def get_ip_intelligence(ip: str) -> dict[str, Any]:
    if not IPV4_RE.match(ip):
        raise HTTPException(status_code=400, detail="Invalid IPv4 address")

    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if abuse_key:
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": abuse_key, "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    return {
                        "ip": ip,
                        "abuse_confidence": data.get("abuseConfidenceScore", 0),
                        "abuse_reports": data.get("totalReports", 0),
                        "isp": data.get("isp", "Unknown"),
                        "tor_exit_node": data.get("isTor", False),
                        "disclaimer": APPROX_DISCLAIMER,
                        "is_demo_data": False,
                        "data_source": "AbuseIPDB Live API",
                    }
        except Exception:
            pass

    return {
        "ip": ip,
        "approx_location": "Mumbai, Maharashtra, India",
        "accuracy_radius_km": 25,
        "asn": "AS55836",
        "isp": "Reliance Jio Infocomm",
        "connection_type": "mobile",
        "vpn_probability": 0.18,
        "abuse_confidence": 86,
        "disclaimer": APPROX_DISCLAIMER,
        "is_demo_data": True,
        "data_source": "Simulated Threat Intel Fallback (DEMO DATA)",
    }


@app.post("/api/cases/{case_id}/evidence")
async def preserve_evidence(case_id: str, payload: EvidenceUpload) -> dict[str, Any]:
    digest = hashlib.sha256(payload.content.encode("utf-8")).hexdigest()
    record = {
        "case_id": case_id,
        "file_name": payload.file_name,
        "sha256_hash": digest,
        "file_size": len(payload.content.encode("utf-8")),
        "collected_by": payload.collected_by,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "source_system": payload.source_system,
        "integrity_status": "verified",
    }
    await manager.broadcast("case_updated", {"case_id": case_id, "evidence": record})
    return record


@app.websocket("/ws/live")
async def websocket_live(ws: WebSocket) -> None:
    await manager.connect(ws)
    try:
        await ws.send_json({
            "type": "system_status",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": {"status": "connected", "demo_mode": True},
        })
        while True:
            _ = await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
