# CyberTrace Globe — Real-Time Network Threat Intelligence & Digital Forensics Platform

CyberTrace Globe is a dark-themed 3D cyber threat intelligence and digital forensics command center built on **CesiumJS**, **React + TypeScript**, **Express / FastAPI**, **WebSockets (`/ws/live`)**, **Firebase/Firestore** (AI Studio live persistence), and **PostgreSQL + PostGIS + Redis** (self-hosted Docker Compose stack).

## Forensic & Security Principles

- **Approximate Geolocation Only**: Every IP marker displays a confidence radius circle in kilometers alongside explicit notices: *"Approximate network location · Investigative lead only — not proof of a person's physical location or identity."*
- **Anonymization Awareness**: Flags VPN, proxy, Tor exit nodes, datacenter/hosting, and mobile CGNAT probabilities without claiming to reveal physical addresses behind anonymizers.
- **Evidence Integrity**: Uploaded evidence and ingested logs are preserved with deterministic **SHA-256** hashes and immutable chain-of-custody records.
- **Privacy & RBAC**: Internal RFC1918 IP addresses are masked in UI displays. Role-based access control supports **Viewer** (read-only), **Analyst**, and **Admin** — enforced server-side, not only in UI.
- **DEMO DATA Labeling**: All simulated scenarios are visibly labeled `DEMO DATA` in the HUD badge, tooltips, and all exports. Fake data is never presented as live telemetry.
- **No Secrets in Client**: `GEMINI_API_KEY` and `ABUSEIPDB_API_KEY` remain server-side only, never sent to the browser.
- **Defensive Use Only**: This platform helps defenders understand who is touching their assets. It never targets third parties, scans, or exploits.

---

## Quick Start (Google AI Studio / Local Node Full-Stack)

```bash
npm install
npm run dev
```

The full-stack server runs on `http://localhost:3000` with:
- Interactive CesiumJS 3D Globe & 2D Map (`NaturalEarthII` bundled local tiles + optional CARTO Dark Vector Tiles)
- All 11 independent toggleable threat layers
- Live WebSocket event streaming on `ws://localhost:3000/ws/live`
- Server-side Gemini Forensic Analyst (`POST /api/analysis/query`) using `GEMINI_API_KEY`
- Optional live AbuseIPDB enrichment via `ABUSEIPDB_API_KEY` (graceful DEMO DATA fallback when unset)

## Self-Hosted Docker Compose Deployment (FastAPI + PostgreSQL/PostGIS + Redis)

```bash
cp .env.example .env
# edit .env — set POSTGRES_PASSWORD, JWT_SECRET, optionally GEMINI_API_KEY and ABUSEIPDB_API_KEY
docker compose up --build
```

Run database migrations and seed realistic demo data:

```bash
docker compose exec backend alembic upgrade head
docker compose exec backend python seed.py
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GEMINI_API_KEY` | Recommended | — | Gemini Forensic Analyst API (server-side only, never sent to browser) |
| `ABUSEIPDB_API_KEY` | Optional | — | Live IP reputation enrichment; falls back to labeled DEMO DATA if unset |
| `DATABASE_URL` | Docker only | see compose | Full PostgreSQL DSN `postgresql://user:pass@host:5432/db` |
| `REDIS_URL` | Docker only | `redis://redis:6379` | Redis URL for enrichment cache |
| `JWT_SECRET` | Docker only | — | Min 32-char random string for API auth tokens |
| `CESIUM_ION_TOKEN` | Optional | — | Cesium Ion token for high-res terrain/imagery (omit to use bundled NaturalEarthII) |
| `MAXMIND_DB_PATH` | Optional | — | Local path to MaxMind GeoLite2-City.mmdb for offline geolocation |
| `DEMO_MODE` | Optional | `true` | Set `false` in production to disable demo data seeding |
| `PORT` | Optional | `3000` | Node.js server listen port |
| `POSTGRES_HOST` | Docker | `postgres` | PostgreSQL hostname |
| `POSTGRES_PORT` | Docker | `5432` | PostgreSQL port |
| `POSTGRES_DB` | Docker | `cybertrace` | Database name |
| `POSTGRES_USER` | Docker | `cybertrace_app` | Database user |
| `POSTGRES_PASSWORD` | Docker | — | Database password (required) |
| `REDIS_HOST` | Docker | `redis` | Redis hostname |
| `REDIS_PORT` | Docker | `6379` | Redis port |
| `BACKEND_PORT` | Docker | `8000` | FastAPI backend port |

---

## Architecture

```mermaid
flowchart LR
    A["Log Sources\n(SSH / RDP / UFW / Nginx\nDNS / NetFlow / Windows\nSyslog / CSV / JSON)"]
    B["Ingest API\nPOST /api/logs/ingest"]
    C["Normalize\nlogParser.ts\nFootprintEvent"]
    D["Enrich Pipeline\n1 Classify IP\n2 GeoIP+ASN\n3 Anonymizer flags\n4 AbuseIPDB rep\n5 Reverse DNS"]
    E["Risk Engine\nriskEngine.ts\nRDP detections"]
    F["Correlate\n15-min window\nby srcIp + asset"]
    G["Store\nPostgreSQL+PostGIS\nRedis cache"]
    H["WebSocket Broadcast\n/ws/live"]
    I["CesiumJS Globe\nReact UI"]
    J["Inspector Panel\nCase / Evidence\nForensic AI"]

    A --> B --> C --> D --> E --> F --> G --> H --> I
    I --> J
    H -.->|heartbeat 15s| I
```

---

## Data Model

| Collection / Table | Key Fields | Notes |
|---|---|---|
| `events` | `id` (uuid v7), `ts`, `srcIp`, `dstIp`, `geo` (geography Point 4326), `severity`, `rawHash` | GiST index on geo; partitioned by month |
| `assets` | `id`, `name`, `ipOrInternalId` (masked), `latitude`, `longitude`, `criticality` | RBAC-gated by `ownerId` |
| `cases` | `id`, `title`, `priority`, `status`, `linkedEventIds`, `linkedIps` | Closed cases require Admin to mutate |
| `evidence` | `id`, `caseId`, `sha256Hash`, `integrityStatus`, `accessHistory` | Append-only; update/delete denied |
| `notes` | `id`, `caseId`, `authorId`, `content` | Append-only |
| `audit_log` | `id`, `actorId`, `action`, `targetType`, `entryHash` | Append-only; SHA-256 chained |
| `users` | `uid`, `displayName`, `role` (Viewer/Analyst/Admin) | PII split to `/users/{uid}/private` |

> PostGIS `geography(Point, 4326)` on events enables radius queries by km; GiST index required. Partition events by month with `events_YYYY_MM` child tables. Retention policy: configurable via `RETENTION_DAYS` env.

---

## Layer Catalogue

All 11 layers are independently toggleable. Each has a colour token defined in `src/styles/tokens.css`.

| # | Layer ID | Colour | Geometry | Toggled By |
|---|---|---|---|---|
| 1 | `attackSources` | `--layer-attack-sources` (#FF4D5E) | Point + radius ellipse | Severity filter |
| 2 | `targetAssets` | `--layer-target-assets` (#4DB8FF) | Point + label | Asset criticality |
| 3 | `attackArcs` | `--layer-attack-arcs` (#FF9F43) | Geodesic polyline (great-circle) | Event category filter |
| 4 | `portScans` | `--layer-port-scans` (#F5D547) | Point (source) | Category: port_scan |
| 5 | `bruteForce` | `--layer-brute-force` (#FF4D5E) | Point + halo | Category: ssh_brute_force |
| 6 | `malwareC2` | `--layer-malware-c2` (#c084fc) | Point | Category: malware_c2 |
| 7 | `dataExfiltration` | `--layer-data-exfil` (#FF9F43) | Arc (thicker) | Category: data_exfiltration |
| 8 | `vpnProxyTor` | `--layer-vpn-proxy-tor` (#a78bfa) | Outer ring on source point | connectionType VPN/Proxy/Tor |
| 9 | `threatReputation` | `--layer-threat-reputation` (#fb923c) | Reputation halo | abuseConfidence ≥ 70 |
| 10 | `globalHeatmap` | `--layer-global-heatmap` (#3DDC97) | Filled ellipse (region) | geoRiskMatrix entries |
| 11 | `geoRiskMatrix` | `--layer-geo-risk-matrix` (#3DDC97) | Ellipse + label | Country-level risk aggregation |

---

## WebSocket Message Schema

All messages on `ws://localhost:3000/ws/live` follow:

```json
{
  "type": "<WsMessageType>",
  "timestamp": "2026-11-21T09:00:00.000Z",
  "payload": { ... }
}
```

| `type` | Direction | Payload shape | Purpose |
|---|---|---|---|
| `threat.new` / `threat_event_created` | Server→Client | `ThreatEvent` | New correlated threat event |
| `threat.update` / `threat_event_updated` | Server→Client | `ThreatEvent` (partial) | Status/case linkage update |
| `alert` / `alert_created` | Server→Client | `{id, eventId, severity, title, sourceIp, timestamp}` | High/Critical alert notification |
| `case.update` / `case_updated` | Server→Client | `InvestigationCase` | Case mutation (notes, evidence, status) |
| `layer.toggle` / `layer_refresh` | Server→Client | `{layer: LayerKey, asset?: ProtectedAsset}` | Layer data refresh trigger |
| `ip_intelligence_updated` | Server→Client | `IpIntelligence` | Enrichment result available |
| `heartbeat` / `system_status` | Server→Client | `{status, clients, demoMode, activeEvents}` | Keepalive / connection health |

**Example — new threat event:**
```json
{
  "type": "threat_event_created",
  "timestamp": "2026-11-21T09:14:03.211Z",
  "payload": {
    "id": "evt-live-1732172043211",
    "eventType": "ssh_brute_force",
    "sourceIp": "203.0.113.45",
    "severity": "high",
    "riskScore": 74,
    "isDemoData": true
  }
}
```

**Reconnect / backoff policy (client-side):**
1. On close or error: wait 1 s, then reconnect.
2. On second failure: wait 2 s, then reconnect.
3. Subsequent failures: exponential backoff capped at 30 s.
4. After 10 failed attempts: show offline state; stop auto-reconnect until user action.
5. On `Space` key (or offline-state button): reset backoff counter and retry immediately.

---

## Log Format Cookbook

One sample line per supported format with its parsed output:

### SSH (`/var/log/auth.log`)
```
Nov 20 22:14:09 mum-ssh-01 sshd[4410]: Failed password for invalid user admin from 203.0.113.45 port 54120 ssh2
```
→ `eventType: ssh_brute_force | srcIp: 203.0.113.45 | port: 22 | user: admin`

### UFW / iptables Firewall
```
Nov 20 22:14:15 edge-fw kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.204 DST=10.20.4.18 LEN=60 PROTO=TCP SPT=49012 DPT=5432
```
→ `eventType: port_scan | srcIp: 198.51.100.204 | dstIp: 10.20.4.18 (masked) | dstPort: 5432 | action: BLOCKED`

### Nginx / Apache Combined Access Log
```
192.0.2.134 - - [20/Nov/2026:22:15:00 +0000] "GET /wp-login.php HTTP/1.1" 403 1842 "-" "curl/8.4.0"
```
→ `eventType: port_scan | srcIp: 192.0.2.134 | url: /wp-login.php | status: 403`

### BIND DNS Query Log
```
20-Nov-2026 22:16:00 client 198.51.100.77#51234: query: c2-sync-beacon.example.net IN A
```
→ `eventType: malware_c2 | srcIp: 198.51.100.77 | domain: c2-sync-beacon.example.net`

### Windows Security / Event Log (RDP)
```
EventID:4625 Logon Type: 10 Account Name: administrator Source Network Address: 203.0.113.45
```
→ `kind: auth_fail | srcIp: 203.0.113.45 | user: administrator | eventId: 4625`

### NetFlow / IPFIX CSV
```
timestamp,source_ip,destination_ip,destination_port,protocol,bytes,event_type,action
2026-11-20T22:00:00Z,203.0.113.45,10.14.0.12,22,SSH,2048,ssh_brute_force,FAILED
```
→ `eventType: ssh_brute_force | srcIp: 203.0.113.45 | dstPort: 22 | bytes: 2048`

### JSONL (Structured Log)
```json
{"source_ip":"192.0.2.211","destination_ip":"10.32.8.44","destination_port":443,"protocol":"TCP","bytes_transferred":900000000,"event_type":"data_exfiltration","action":"EGRESS_SPIKE"}
```
→ `eventType: data_exfiltration | bytes: 900 MB | dstPort: 443`

### Generic Syslog
```
2026-11-20T22:19:00Z host-fw DENY src=203.0.113.50 dst=10.0.0.5 dport=3389 proto=TCP bytes=64
```
→ `eventType: ssh_brute_force (port 3389) | action: DENIED`

---

## RBAC Matrix

| Endpoint | Viewer | Analyst | Admin |
|---|---|---|---|
| `GET /api/health` | ✓ | ✓ | ✓ |
| `GET /api/events` | ✓ | ✓ | ✓ |
| `GET /api/events/:id` | ✓ | ✓ | ✓ |
| `PATCH /api/events/:id` | ✗ | ✓ | ✓ |
| `GET /api/ip/:ip/intelligence` | ✓ | ✓ | ✓ |
| `POST /api/ip/:ip/block` | ✗ | ✓ | ✓ |
| `GET /api/assets` | ✓ | ✓ | ✓ |
| `POST /api/assets` | ✗ | ✓ | ✓ |
| `GET /api/cases` | ✓ | ✓ | ✓ |
| `POST /api/cases` | ✗ | ✓ | ✓ |
| `PATCH /api/cases/:id` | ✗ | ✓ own | ✓ |
| `POST /api/cases/:id/notes` | ✗ | ✓ | ✓ |
| `POST /api/cases/:id/evidence` | ✗ | ✓ | ✓ |
| `POST /api/logs/ingest` | ✗ | ✓ | ✓ |
| `GET /api/reports/:case_id` | ✓ | ✓ | ✓ |
| `POST /api/analysis/query` | ✓ | ✓ | ✓ |
| `WS /ws/live` (read) | ✓ | ✓ | ✓ |
| Reopen closed cases | ✗ | ✗ | ✓ |
| Delete assets | ✗ | ✗ | ✓ |

---

## Security Hardening

- **Rate limiting**: 60 req/min per IP on all API routes; 10 req/min on `/api/logs/ingest` and `/api/analysis/query` (configure via `RATE_LIMIT_*` env vars).
- **Input size limits**: JSON body capped at 4 MB; log upload payload capped at 50 MB; binary content rejected (magic-byte check).
- **Upload MIME / magic checks**: Log uploads are rejected if the first 512 bytes contain non-printable characters (binary content mismatch).
- **CSP**: `Content-Security-Policy: default-src 'self'; script-src 'self'; connect-src 'self' wss: https://api.cesium.com; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'` (run in report-only first).
- **CORS**: Allowlist set to `APP_URL` env var only. Wildcard `*` is never permitted.
- **Firestore rules**: Default-deny global safety net; all mutations require `email_verified`; role escalation blocked; evidence and audit logs are append-only (no update/delete).
- **No secrets in client**: API keys checked only in `server.ts` / `main.py` environment. The browser never receives them.
- **RBAC enforcement**: All mutation endpoints call `requireWriteRole()` server-side; role from `x-user-role` header is validated against an allowlist (`Viewer`/`Analyst`/`Admin`).
- **Audit log**: Every read of evidence and every case/event mutation is recorded with SHA-256 chained `entryHash`.

---

## Troubleshooting

**Cesium asset 404s (imagery tiles not loading)**
> Ensure `cesium` npm package is fully installed: `npm install`. Vite config must alias `cesium` and copy `Build/Cesium/` assets to `public/cesium/`. Check browser console for the exact URL that returns 404.

**WebSocket disconnects behind reverse proxies (Nginx/Traefik)**
> Add `proxy_read_timeout 3600s; proxy_send_timeout 3600s;` and `Connection: Upgrade; Upgrade: websocket` headers to your proxy config. The client implements exponential backoff reconnect automatically.

**PostGIS extension missing (`ERROR: type "geography" does not exist`)**
> Run `CREATE EXTENSION IF NOT EXISTS postgis;` as a superuser before running Alembic migrations, or add it to `docker-entrypoint-initdb.d/`.

**Alembic head mismatch (`alembic.util.exc.CommandError: Can't locate revision …`)**
> Run `docker compose exec backend alembic stamp head` to mark the current DB state, then `alembic upgrade head` to apply pending migrations.

**`DEMO DATA` badge not visible**
> Check that `statistics.hasDemoData` is `true` in `/api/statistics/global` response. This is set when any event in the store has `isDemoData: true`.

---

## REST & WebSocket API Endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Service health & live WebSocket client metrics |
| `GET` | `/api/layers` | Available toggleable geospatial threat layers |
| `GET` | `/api/events` / `/api/events/:id` | Query & inspect correlated threat events |
| `GET` | `/api/ip/:ip/intelligence` | IP geolocation lead, ASN, VPN/Tor, & AbuseIPDB reputation |
| `GET` | `/api/asn/:asn/summary` | ASN-level threat aggregation |
| `GET` / `POST` | `/api/assets` | List & manually register protected target assets |
| `GET` / `POST` | `/api/cases` / `/api/cases/:id` | Forensic investigation case management |
| `POST` | `/api/cases/:id/evidence` | Preserve evidence artifact with SHA-256 chain of custody |
| `POST` | `/api/cases/:id/notes` | Append timestamped investigator notes |
| `POST` | `/api/logs/ingest` & `/api/logs/upload` | Multi-format log parsing (SSH, UFW, Nginx, DNS, Windows, NetFlow, CSV, JSON, JSONL, Syslog) |
| `POST` | `/api/analysis/query` | Server-side Gemini Forensic Analyst query |
| `GET` | `/api/reports/:case_id` | Generate Markdown forensic investigation report |
| `GET` | `/api/statistics/global` & `/api/statistics/region/:region_id` | Global KPIs & Geographic Risk Matrix |
| `WS` | `/ws/live` | Real-time threat, alert, case, and layer broadcast stream |

---

## Running Tests

```bash
# Unit tests (riskEngine, logParser, rdpParser, caseLogic, Firestore rules)
npx --yes tsx --test src/lib/riskEngine.test.ts src/lib/logParser.test.ts src/lib/caseLogic.test.ts src/lib/rdpParser.test.ts firestore.rules.test.ts

# Integration tests (ingest → enrich → WS broadcast with fake provider)
npm run test:integration

# E2E (Playwright): globe load, layer toggle, event select, case create, evidence SHA-256
npm run test:e2e

# Lint
npm run lint
```

---

## Screenshots

> *[Globe view — Attack arcs and geographic risk matrix, 1920×1080]*
> *[Inspector panel — IP intelligence with confidence radius notice]*
> *[Cases workspace — Evidence chain of custody with SHA-256]*

---

## Legal and Ethical Use

CyberTrace Globe is built exclusively for **defensive and investigative use** by authorized security personnel on networks and systems they are permitted to monitor.

**Permitted uses:**
- Network security monitoring of your own or client infrastructure
- Security Operations Center (SOC) threat triage and incident response
- Digital forensics investigations under legal authority
- Security education and research in controlled environments

**Prohibited uses:**
- Targeting networks, systems, or individuals without explicit authorization
- Attempting to identify or de-anonymize specific individuals from IP geolocation data
- Using approximate location data as evidence of a person's physical location or identity
- Any activity that violates applicable computer crime, privacy, or surveillance laws

**Geolocation data notice:** IP geolocation is approximate network routing data only. Confidence radius circles represent the uncertainty range. This data is an investigative lead, not proof of a person's physical location, identity, or activity.

**VPN / Tor / anonymizer notice:** The platform flags anonymizer probability scores. It does not claim to unmask VPN users or identify individuals behind shared egress points.
