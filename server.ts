import 'dotenv/config';
import express from 'express';
import http from 'node:http';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {WebSocketServer, WebSocket} from 'ws';
import {GoogleGenAI, Type} from '@google/genai';
import {buildDemoDataset, computeGlobalStatistics, DEMO_IP_PROFILES} from './src/lib/demoScenario.ts';
import {parseLogs, maskPrivateIp, sha256Hex} from './src/lib/logParser.ts';
import {calculateRiskScore} from './src/lib/riskEngine.ts';
import {generateCaseMarkdownReport} from './src/lib/caseLogic.ts';
import {
  APPROX_LOCATION_DISCLAIMER,
  type AuditLogEntry,
  type CaseNote,
  type EvidenceFile,
  type InvestigationCase,
  type IpIntelligence,
  type ProtectedAsset,
  type ThreatEvent,
  type UserRole,
  type WsMessage,
  type WsMessageType,
} from './src/types/forensics.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT ?? 3000);
const IS_PROD = process.env.NODE_ENV === 'production';

// Server-authoritative state initialized with realistic labeled DEMO DATA
const store = buildDemoDataset();

function isValidIpv4(ip: string): boolean {
  return /^(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)$/.test(ip);
}

function isSafeRole(role: unknown): UserRole {
  if (role === 'Admin' || role === 'Analyst' || role === 'Viewer') return role;
  return 'Analyst';
}

function requireWriteRole(req: express.Request, res: express.Response): UserRole | null {
  const role = isSafeRole(req.header('x-user-role'));
  if (role === 'Viewer') {
    res.status(403).json({error: 'Viewer role is read-only. Switch to Analyst or Admin to perform mutations.'});
    return null;
  }
  return role;
}

function recordAudit(actorName: string, role: UserRole, action: string, targetType: string, targetId: string, details: string): AuditLogEntry {
  const id = `aud-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const timestamp = new Date().toISOString();
  const entry: AuditLogEntry = {
    id,
    actorId: actorName.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').slice(0, 64) || 'analyst',
    actorName,
    role,
    action,
    targetType,
    targetId,
    details,
    entryHash: sha256Hex(`${id}:${actorName}:${action}:${targetType}:${targetId}:${timestamp}`),
    timestamp,
  };
  store.auditLogs.unshift(entry);
  if (store.auditLogs.length > 250) store.auditLogs.pop();
  return entry;
}

function enrichOrSynthesizeIp(ip: string): IpIntelligence {
  if (store.ipIntel[ip]) {
    return store.ipIntel[ip];
  }
  // Deterministic simulated fallback if external feeds are unavailable
  const hash = sha256Hex(ip);
  const seedIdx = parseInt(hash.slice(0, 4), 16) % DEMO_IP_PROFILES.length;
  const template = DEMO_IP_PROFILES[seedIdx];
  const latOffset = ((parseInt(hash.slice(4, 6), 16) / 255) - 0.5) * 4;
  const lonOffset = ((parseInt(hash.slice(6, 8), 16) / 255) - 0.5) * 4;
  const abuseScore = 40 + (parseInt(hash.slice(8, 10), 16) % 55);
  const intel: IpIntelligence = {
    ip,
    approxLocation: {
      country: template.country,
      countryCode: template.countryCode,
      region: template.region,
      city: template.city,
      latitude: Number((template.lat + latOffset).toFixed(4)),
      longitude: Number((template.lon + lonOffset).toFixed(4)),
      accuracyRadiusKm: Math.max(20, template.radiusKm + 10),
      disclaimer: APPROX_LOCATION_DISCLAIMER,
    },
    asn: template.asn,
    asnName: template.asnName,
    isp: template.isp,
    organization: template.isp,
    connectionType: template.connectionType,
    vpnProbability: template.vpnProb,
    proxyProbability: template.proxyProb,
    torExitNode: template.tor,
    abuseConfidenceScore: abuseScore,
    abuseReportCount: 15 + (parseInt(hash.slice(10, 12), 16) % 240),
    attackCategories: template.categories,
    lastReportedAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
    historicalEventCount: 1,
    relatedEventIds: [],
    relatedCaseIds: [],
    riskScore: Math.min(96, abuseScore + 8),
    riskLevel: abuseScore >= 75 ? 'critical' : abuseScore >= 55 ? 'high' : 'medium',
    confidence: 78,
    recommendedAction:
      'Correlate with endpoint & firewall telemetry before attribution; monitor ASN behavior and apply rate-limiting if anomalous.',
    blocked: false,
    dataSource: 'Simulated GeoLite2 + Reputation Fallback (DEMO DATA)',
    isDemoData: true,
    enrichedAt: new Date().toISOString(),
  };
  store.ipIntel[ip] = intel;
  return intel;
}

async function startServer() {
  const app = express();
  app.use(express.json({limit: '4mb'}));

  const server = http.createServer(app);
  const wss = new WebSocketServer({noServer: true});

  server.on('upgrade', (request, socket, head) => {
    const pathname = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`).pathname;
    if (pathname === '/ws/live') {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    } else {
      socket.destroy();
    }
  });

  function broadcast<T>(type: WsMessageType, payload: T) {
    const msg: WsMessage<T> = {
      type,
      timestamp: new Date().toISOString(),
      payload,
    };
    const serialized = JSON.stringify(msg);
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(serialized);
      }
    });
  }

  wss.on('connection', (ws) => {
    const statusMsg: WsMessage = {
      type: 'system_status',
      timestamp: new Date().toISOString(),
      payload: {
        status: 'connected',
        clients: wss.clients.size,
        demoMode: true,
        activeEvents: store.events.length,
      },
    };
    ws.send(JSON.stringify(statusMsg));
  });

  // Periodic live simulated threat stream (clearly labeled DEMO DATA) every 22s so live updates appear without reload
  const liveEventTemplates = [
    {
      eventType: 'ssh_brute_force' as const,
      sourceIp: '203.0.113.45',
      assetId: 'asset-mum-ssh-01',
      port: 22,
      proto: 'SSH/TCP',
      title: 'Live SSH Credential Burst Detected (Mumbai Bastion)',
      desc: 'Automated SSH authentication burst detected from AS55836 targeting admin accounts (DEMO DATA).',
      attempts: 184,
      targetUsername: 'root',
    },
    {
      eventType: 'port_scan' as const,
      sourceIp: '198.51.100.204',
      assetId: 'asset-iad-api-01',
      port: 8443,
      proto: 'TCP/SYN',
      title: 'Live Multi-Port Reconnaissance Sweep (US-East)',
      desc: 'Rapid SYN probing across 140 service ports on US-East API Gateway (DEMO DATA).',
      portsScanned: 140,
    },
    {
      eventType: 'malware_c2' as const,
      sourceIp: '198.51.100.77',
      assetId: 'asset-sfo-wks-19',
      port: 8443,
      proto: 'HTTPS/TLS',
      title: 'Live C2 Heartbeat Beacon Observed (WKS-SFO-FIN-19)',
      desc: 'Periodic outbound encrypted check-in to flagged C2 infrastructure (DEMO DATA).',
      c2Domain: 'cdn-telemetry-sync.example.net',
    },
    {
      eventType: 'data_exfiltration' as const,
      sourceIp: '192.0.2.211',
      assetId: 'asset-fra-db-02',
      port: 443,
      proto: 'HTTPS/TCP',
      title: 'Live Anomalous Outbound Burst (Frankfurt DB)',
      desc: 'Unscheduled 310 MB encrypted outbound transfer flagged by NetFlow sensor (DEMO DATA).',
      bytesTransferred: 325_058_560,
    },
  ];
  let liveTickIndex = 0;

  const liveInterval = setInterval(() => {
    if (wss.clients.size === 0) return;
    const tpl = liveEventTemplates[liveTickIndex % liveEventTemplates.length];
    liveTickIndex++;
    const intel = enrichOrSynthesizeIp(tpl.sourceIp);
    const asset = store.assets.find((a) => a.id === tpl.assetId) ?? store.assets[0];
    const assessment = calculateRiskScore({
      eventType: tpl.eventType,
      abuseConfidence: intel.abuseConfidenceScore,
      failedAuthCount: tpl.attempts,
      portsScanned: tpl.portsScanned,
      outboundBytes: tpl.bytesTransferred,
      hasMalwareC2Indicator: tpl.eventType === 'malware_c2',
      connectionType: intel.connectionType,
      vpnProbability: intel.vpnProbability,
      unusualGeoOrigin: true,
      correlatedSourceCount: 2,
    });

    const newEvent: ThreatEvent = {
      id: `evt-live-${Date.now()}`,
      eventType: tpl.eventType,
      sourceIp: tpl.sourceIp,
      destinationIp: asset.ipOrInternalId,
      maskedDestinationIp: maskPrivateIp(asset.ipOrInternalId),
      targetAssetId: asset.id,
      targetAssetName: asset.name,
      sourcePort: 45000 + (liveTickIndex * 137) % 15000,
      destinationPort: tpl.port,
      protocol: tpl.proto,
      sourceLocation: intel.approxLocation,
      destinationLocation: {
        country: asset.country,
        countryCode: asset.countryCode,
        city: asset.locationLabel.split(',')[0],
        latitude: asset.latitude,
        longitude: asset.longitude,
      },
      timestamp: new Date().toISOString(),
      confidence: assessment.confidence,
      severity: assessment.riskLevel,
      riskScore: assessment.riskScore,
      riskAssessment: assessment,
      title: tpl.title,
      description: tpl.desc,
      status: 'new',
      caseId: null,
      asn: intel.asn,
      isp: intel.isp,
      connectionType: intel.connectionType,
      vpnProbability: intel.vpnProbability,
      abuseConfidence: intel.abuseConfidenceScore,
      isDemoData: true,
      dataSource: 'Live WebSocket Stream (DEMO DATA)',
      metadata: {
        attempts: tpl.attempts,
        portsScanned: tpl.portsScanned,
        bytesTransferred: tpl.bytesTransferred,
        c2Domain: tpl.c2Domain,
        targetUsername: tpl.targetUsername,
        rawLogRef: `ws-stream:${Date.now()}`,
        evidenceSha256: sha256Hex(`live:${Date.now()}:${tpl.sourceIp}`),
        ingestionSource: 'live-sensor-stream',
        action: 'DETECTED',
      },
    };

    store.events.unshift(newEvent);
    if (store.events.length > 80) store.events.pop();
    intel.lastSeenAt = newEvent.timestamp;
    intel.relatedEventIds = [newEvent.id, ...intel.relatedEventIds].slice(0, 30);

    broadcast('threat_event_created', newEvent);
    if (newEvent.severity === 'critical' || newEvent.severity === 'high') {
      broadcast('alert_created', {
        id: `alert-${newEvent.id}`,
        eventId: newEvent.id,
        severity: newEvent.severity,
        title: newEvent.title,
        sourceIp: newEvent.sourceIp,
        timestamp: newEvent.timestamp,
      });
    }
  }, 22_000);

  server.on('close', () => clearInterval(liveInterval));

  // ==================== REST API ENDPOINTS ====================

  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'CyberTrace Globe API',
      demoMode: true,
      websocketClients: wss.clients.size,
      eventsCount: store.events.length,
      assetsCount: store.assets.length,
      casesCount: store.cases.length,
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/layers', (_req, res) => {
    res.json({
      layers: [
        {id: 'attackSources', name: 'Attack Sources', defaultEnabled: true},
        {id: 'targetAssets', name: 'Target Assets', defaultEnabled: true},
        {id: 'attackArcs', name: 'Attack Arcs', defaultEnabled: true},
        {id: 'portScans', name: 'Port Scan Detection', defaultEnabled: true},
        {id: 'bruteForce', name: 'Brute-Force Detection', defaultEnabled: true},
        {id: 'malwareC2', name: 'Malware C2 Traffic', defaultEnabled: true},
        {id: 'dataExfiltration', name: 'Data Exfiltration', defaultEnabled: true},
        {id: 'vpnProxyTor', name: 'VPN / Proxy / Tor Exposure', defaultEnabled: true},
        {id: 'threatReputation', name: 'Threat Reputation', defaultEnabled: false},
        {id: 'globalHeatmap', name: 'Global Threat Heatmap', defaultEnabled: true},
        {id: 'geoRiskMatrix', name: 'Geographic Risk Matrix', defaultEnabled: false},
      ],
    });
  });

  app.get('/api/events', (req, res) => {
    const {severity, eventType, country, asn, protocol, minConfidence, q} = req.query;
    let list = [...store.events];
    if (typeof severity === 'string' && severity) {
      const allowed = severity.split(',');
      list = list.filter((e) => allowed.includes(e.severity));
    }
    if (typeof eventType === 'string' && eventType) {
      const allowed = eventType.split(',');
      list = list.filter((e) => allowed.includes(e.eventType));
    }
    if (typeof country === 'string' && country) {
      list = list.filter(
        (e) =>
          e.sourceLocation.country.toLowerCase().includes(country.toLowerCase()) ||
          e.sourceLocation.countryCode.toLowerCase() === country.toLowerCase()
      );
    }
    if (typeof asn === 'string' && asn) {
      list = list.filter((e) => e.asn.toLowerCase().includes(asn.toLowerCase()));
    }
    if (typeof protocol === 'string' && protocol) {
      list = list.filter((e) => e.protocol.toLowerCase().includes(protocol.toLowerCase()));
    }
    if (typeof minConfidence === 'string' && !Number.isNaN(Number(minConfidence))) {
      list = list.filter((e) => e.confidence >= Number(minConfidence));
    }
    if (typeof q === 'string' && q.trim()) {
      const needle = q.trim().toLowerCase();
      list = list.filter(
        (e) =>
          e.sourceIp.toLowerCase().includes(needle) ||
          e.title.toLowerCase().includes(needle) ||
          e.sourceLocation.city.toLowerCase().includes(needle) ||
          e.sourceLocation.country.toLowerCase().includes(needle) ||
          e.asn.toLowerCase().includes(needle) ||
          e.targetAssetName.toLowerCase().includes(needle)
      );
    }
    res.json({events: list, total: list.length, isDemoData: list.some((e) => e.isDemoData)});
  });

  app.get('/api/events/:id', (req, res) => {
    const ev = store.events.find((e) => e.id === req.params.id);
    if (!ev) return res.status(404).json({error: 'Threat event not found'});
    return res.json(ev);
  });

  app.patch('/api/events/:id', (req, res) => {
    const role = requireWriteRole(req, res);
    if (!role) return;
    const ev = store.events.find((e) => e.id === req.params.id);
    if (!ev) return res.status(404).json({error: 'Threat event not found'});
    const validStatuses = ['new', 'reviewed', 'suspicious', 'confirmed', 'false_positive', 'escalated'];
    if (req.body.status && validStatuses.includes(req.body.status)) {
      ev.status = req.body.status;
    }
    if (typeof req.body.caseId === 'string' || req.body.caseId === null) {
      ev.caseId = req.body.caseId;
      if (req.body.caseId) {
        const targetCase = store.cases.find((c) => c.id === req.body.caseId);
        if (targetCase && !targetCase.linkedEventIds.includes(ev.id)) {
          targetCase.linkedEventIds.push(ev.id);
          if (!targetCase.linkedIps.includes(ev.sourceIp)) targetCase.linkedIps.push(ev.sourceIp);
          targetCase.updatedAt = new Date().toISOString();
          broadcast('case_updated', targetCase);
        }
      }
    }
    const actor = String(req.header('x-user-name') || 'SOC Analyst');
    recordAudit(actor, role, 'EVENT_STATUS_UPDATED', 'threat_event', ev.id, `Status set to ${ev.status}`);
    broadcast('threat_event_updated', ev);
    return res.json(ev);
  });

  app.get('/api/ip/:ip/intelligence', async (req, res) => {
    const ip = req.params.ip.trim();
    if (!isValidIpv4(ip)) {
      return res.status(400).json({error: 'Invalid IPv4 address format'});
    }
    const intel = enrichOrSynthesizeIp(ip);

    // Optional live AbuseIPDB enrichment when API key is configured server-side
    const abuseKey = process.env.ABUSEIPDB_API_KEY?.trim();
    if (abuseKey) {
      try {
        const resp = await fetch(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
          {
            headers: {Key: abuseKey, Accept: 'application/json'},
            signal: AbortSignal.timeout(4000),
          }
        );
        if (resp.ok) {
          const body = (await resp.json()) as {
            data?: {
              abuseConfidenceScore?: number;
              totalReports?: number;
              isp?: string;
              lastReportedAt?: string;
              isTor?: boolean;
            };
          };
          if (body.data) {
            intel.abuseConfidenceScore = body.data.abuseConfidenceScore ?? intel.abuseConfidenceScore;
            intel.abuseReportCount = body.data.totalReports ?? intel.abuseReportCount;
            if (body.data.isp) intel.isp = body.data.isp;
            if (body.data.lastReportedAt) intel.lastReportedAt = body.data.lastReportedAt;
            if (typeof body.data.isTor === 'boolean') intel.torExitNode = body.data.isTor;
            intel.dataSource = 'AbuseIPDB Live API + GeoLite2';
            intel.isDemoData = false;
            intel.enrichedAt = new Date().toISOString();
            broadcast('ip_intelligence_updated', intel);
          }
        }
      } catch {
        // Graceful fallback to simulated threat-intelligence data
      }
    }

    return res.json(intel);
  });

  app.post('/api/ip/:ip/block', (req, res) => {
    const role = requireWriteRole(req, res);
    if (!role) return;
    const ip = req.params.ip.trim();
    if (!isValidIpv4(ip)) return res.status(400).json({error: 'Invalid IPv4 address'});
    const intel = enrichOrSynthesizeIp(ip);
    intel.blocked = Boolean(req.body.blocked ?? true);
    intel.enrichedAt = new Date().toISOString();
    const actor = String(req.header('x-user-name') || 'SOC Analyst');
    recordAudit(
      actor,
      role,
      intel.blocked ? 'IP_BLOCKED' : 'IP_UNBLOCKED',
      'ip',
      ip,
      `${intel.blocked ? 'Blocked' : 'Removed block on'} ${ip} (${intel.asn})`
    );
    broadcast('ip_intelligence_updated', intel);
    return res.json(intel);
  });

  app.get('/api/asn/:asn/summary', (req, res) => {
    const asnParam = req.params.asn.trim().toUpperCase();
    const matchingIps = Object.values(store.ipIntel).filter((i) => i.asn.toUpperCase() === asnParam);
    const matchingEvents = store.events.filter((e) => e.asn.toUpperCase() === asnParam);
    if (matchingIps.length === 0 && matchingEvents.length === 0) {
      return res.status(404).json({error: `No intelligence records found for ${asnParam}`});
    }
    const avgRisk = Math.round(
      matchingEvents.reduce((acc, e) => acc + e.riskScore, 0) / Math.max(1, matchingEvents.length)
    );
    return res.json({
      asn: asnParam,
      asnName: matchingIps[0]?.asnName ?? matchingEvents[0]?.isp ?? asnParam,
      isp: matchingIps[0]?.isp ?? matchingEvents[0]?.isp ?? 'Unknown ISP',
      observedIps: matchingIps.length,
      totalEvents: matchingEvents.length,
      avgRiskScore: avgRisk,
      blockedCount: matchingIps.filter((i) => i.blocked).length,
      ips: matchingIps,
      events: matchingEvents,
      isDemoData: true,
    });
  });

  app.get('/api/assets', (_req, res) => {
    res.json({assets: store.assets, total: store.assets.length});
  });

  app.post('/api/assets', (req, res) => {
    const role = requireWriteRole(req, res);
    if (!role) return;
    const {name, ipOrInternalId, locationLabel, country, countryCode, latitude, longitude, assetType, criticality, openPorts} =
      req.body;
    if (!name || !ipOrInternalId || !locationLabel) {
      return res.status(400).json({error: 'Asset name, IP/Internal ID, and location label are required.'});
    }
    const lat = Number(latitude);
    const lon = Number(longitude);
    if (!Number.isFinite(lat) || lat < -90 || lat > 90 || !Number.isFinite(lon) || lon < -180 || lon > 180) {
      return res.status(400).json({error: 'Valid latitude (-90..90) and longitude (-180..180) are required.'});
    }
    const newAsset: ProtectedAsset = {
      id: `asset-${Date.now()}`,
      name: String(name).trim().slice(0, 140),
      ipOrInternalId: String(ipOrInternalId).trim().slice(0, 64),
      maskedInternalIp: maskPrivateIp(String(ipOrInternalId).trim()),
      locationLabel: String(locationLabel).trim().slice(0, 120),
      country: String(country || locationLabel.split(',').pop() || 'Global').trim(),
      countryCode: String(countryCode || 'US').trim().toUpperCase().slice(0, 2),
      latitude: lat,
      longitude: lon,
      assetType: assetType || 'cloud_vm',
      criticality: criticality || 'high',
      openPorts: Array.isArray(openPorts)
        ? openPorts.map(Number).filter((p) => Number.isInteger(p) && p > 0 && p <= 65535)
        : [443],
      associatedAlertCount: 0,
      riskScore: criticality === 'critical' ? 65 : criticality === 'high' ? 48 : 25,
      isDemoData: false,
    };
    store.assets.push(newAsset);
    const actor = String(req.header('x-user-name') || 'SOC Analyst');
    recordAudit(actor, role, 'ASSET_CREATED', 'asset', newAsset.id, `Registered protected asset ${newAsset.name}`);
    broadcast('layer_refresh', {layer: 'targetAssets', asset: newAsset});
    return res.status(201).json(newAsset);
  });

  app.get('/api/cases', (_req, res) => {
    res.json({cases: store.cases, total: store.cases.length});
  });

  app.get('/api/cases/:id', (req, res) => {
    const found = store.cases.find((c) => c.id === req.params.id);
    if (!found) return res.status(404).json({error: 'Case not found'});
    return res.json(found);
  });

  app.post('/api/cases', (req, res) => {
    const role = requireWriteRole(req, res);
    if (!role) return;
    const {title, description, priority, status, assignedAnalyst, tags, linkedEventIds, linkedIps} = req.body;
    if (!title || !description) {
      return res.status(400).json({error: 'Case title and description are required.'});
    }
    const nowIso = new Date().toISOString();
    const caseNum = String(store.cases.length + 16).padStart(3, '0');
    const newCase: InvestigationCase = {
      id: `CASE-2026-${caseNum}`,
      title: String(title).trim().slice(0, 180),
      description: String(description).trim().slice(0, 4000),
      priority: priority || 'high',
      status: status || 'open',
      assignedAnalyst: String(assignedAnalyst || req.header('x-user-name') || 'SOC Analyst').trim(),
      tags: Array.isArray(tags) ? tags.map(String).slice(0, 10) : [],
      linkedEventIds: Array.isArray(linkedEventIds) ? linkedEventIds.map(String) : [],
      linkedIps: Array.isArray(linkedIps) ? linkedIps.map(String) : [],
      linkedDomains: [],
      linkedHashes: [],
      linkedAssetIds: [],
      linkedUsers: [],
      notes: [],
      evidence: [],
      createdAt: nowIso,
      updatedAt: nowIso,
      isDemoData: false,
    };
    store.cases.unshift(newCase);
    const actor = String(req.header('x-user-name') || 'SOC Analyst');
    recordAudit(actor, role, 'CASE_CREATED', 'case', newCase.id, `Created forensic case "${newCase.title}"`);
    broadcast('case_updated', newCase);
    return res.status(201).json(newCase);
  });

  app.patch('/api/cases/:id', (req, res) => {
    const role = requireWriteRole(req, res);
    if (!role) return;
    const found = store.cases.find((c) => c.id === req.params.id);
    if (!found) return res.status(404).json({error: 'Case not found'});
    if (found.status === 'closed' && role !== 'Admin') {
      return res.status(403).json({error: 'Closed cases are terminal and require Admin role to reopen or modify.'});
    }
    if (req.body.status) found.status = req.body.status;
    if (req.body.priority) found.priority = req.body.priority;
    if (req.body.assignedAnalyst) found.assignedAnalyst = String(req.body.assignedAnalyst);
    if (Array.isArray(req.body.tags)) found.tags = req.body.tags.map(String).slice(0, 10);
    found.updatedAt = new Date().toISOString();
    const actor = String(req.header('x-user-name') || 'SOC Analyst');
    recordAudit(actor, role, 'CASE_UPDATED', 'case', found.id, `Updated status=${found.status}, priority=${found.priority}`);
    broadcast('case_updated', found);
    return res.json(found);
  });

  app.post('/api/cases/:id/notes', (req, res) => {
    const role = requireWriteRole(req, res);
    if (!role) return;
    const found = store.cases.find((c) => c.id === req.params.id);
    if (!found) return res.status(404).json({error: 'Case not found'});
    const content = String(req.body.content || '').trim();
    if (!content) return res.status(400).json({error: 'Note content is required.'});
    const authorName = String(req.body.authorName || req.header('x-user-name') || 'SOC Analyst').trim();
    const note: CaseNote = {
      id: `note-${Date.now()}`,
      caseId: found.id,
      authorId: authorName.toLowerCase().replace(/[^a-z0-9_-]+/g, '-'),
      authorName,
      content: content.slice(0, 3000),
      createdAt: new Date().toISOString(),
    };
    found.notes.unshift(note);
    found.updatedAt = note.createdAt;
    recordAudit(authorName, role, 'CASE_NOTE_ADDED', 'case', found.id, `Added forensic note ${note.id}`);
    broadcast('case_updated', found);
    return res.status(201).json(note);
  });

  app.post('/api/cases/:id/evidence', (req, res) => {
    const role = requireWriteRole(req, res);
    if (!role) return;
    const found = store.cases.find((c) => c.id === req.params.id);
    if (!found) return res.status(404).json({error: 'Case not found'});
    const {fileName, fileType, content, sourceSystem} = req.body;
    if (!fileName || typeof content !== 'string') {
      return res.status(400).json({error: 'Evidence fileName and text/metadata content are required.'});
    }
    const collectedBy = String(req.body.collectedBy || req.header('x-user-name') || 'SOC Analyst').trim();
    const nowIso = new Date().toISOString();
    const sha256Hash = sha256Hex(content);
    const ev: EvidenceFile = {
      id: `EV-${Date.now().toString().slice(-6)}`,
      caseId: found.id,
      fileName: String(fileName).trim().slice(0, 200),
      fileType: String(fileType || 'text/plain').slice(0, 64),
      fileSize: Buffer.byteLength(content, 'utf8'),
      sha256Hash,
      collectedBy,
      collectedAt: nowIso,
      sourceSystem: String(sourceSystem || 'Analyst Evidence Upload').slice(0, 120),
      integrityStatus: 'verified',
      accessHistory: [{accessedBy: collectedBy, accessedAt: nowIso, action: 'UPLOADED_AND_SHA256_HASHED'}],
      previewSnippet: content.slice(0, 260),
      isDemoData: false,
    };
    found.evidence.unshift(ev);
    if (!found.linkedHashes.includes(sha256Hash)) found.linkedHashes.push(sha256Hash);
    found.updatedAt = nowIso;
    recordAudit(collectedBy, role, 'EVIDENCE_UPLOADED', 'evidence', ev.id, `Preserved ${ev.fileName} (SHA-256: ${sha256Hash.slice(0, 16)}...)`);
    broadcast('case_updated', found);
    return res.status(201).json(ev);
  });

  const handleLogIngest = (req: express.Request, res: express.Response) => {
    const role = requireWriteRole(req, res);
    if (!role) return;
    const rawLogs = String(req.body.rawLogs || req.body.content || '').trim();
    if (!rawLogs) {
      return res.status(400).json({error: 'Log payload (rawLogs) is required.'});
    }
    const format = req.body.format || 'auto';
    const source = String(req.body.source || 'log_ingest_api');
    const parsed = parseLogs(rawLogs, format, source);
    if (parsed.length === 0) {
      return res.status(400).json({error: 'No valid network events with IPv4 addresses could be extracted from the supplied logs.'});
    }

    const createdEvents: ThreatEvent[] = [];
    for (const rec of parsed.slice(0, 50)) {
      const intel = enrichOrSynthesizeIp(rec.sourceIp);
      const asset =
        store.assets.find((a) => a.ipOrInternalId === rec.destinationIp) ??
        store.assets[0];
      const assessment = calculateRiskScore({
        eventType: rec.eventType,
        abuseConfidence: intel.abuseConfidenceScore,
        failedAuthCount: rec.eventType === 'ssh_brute_force' ? 64 : undefined,
        portsScanned: rec.eventType === 'port_scan' ? 45 : undefined,
        outboundBytes: rec.bytesTransferred,
        hasMalwareC2Indicator: rec.eventType === 'malware_c2',
        connectionType: intel.connectionType,
        vpnProbability: intel.vpnProbability,
        correlatedSourceCount: 2,
        evidenceRefs: [rec.rawLogRef],
      });

      const threatEvent: ThreatEvent = {
        id: `evt-ing-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
        eventType: rec.eventType,
        sourceIp: rec.sourceIp,
        destinationIp: rec.destinationIp,
        maskedDestinationIp: rec.maskedDestinationIp,
        targetAssetId: asset.id,
        targetAssetName: asset.name,
        sourcePort: rec.sourcePort,
        destinationPort: rec.destinationPort,
        protocol: rec.protocol,
        sourceLocation: intel.approxLocation,
        destinationLocation: {
          country: asset.country,
          countryCode: asset.countryCode,
          city: asset.locationLabel.split(',')[0],
          latitude: asset.latitude,
          longitude: asset.longitude,
        },
        timestamp: rec.timestamp,
        confidence: Math.round((rec.confidence + assessment.confidence) / 2),
        severity: assessment.riskLevel,
        riskScore: assessment.riskScore,
        riskAssessment: assessment,
        title: rec.title,
        description: rec.description,
        status: 'new',
        caseId: null,
        asn: intel.asn,
        isp: intel.isp,
        connectionType: intel.connectionType,
        vpnProbability: intel.vpnProbability,
        abuseConfidence: intel.abuseConfidenceScore,
        isDemoData: false,
        dataSource: `Ingested Log (${rec.ingestionSource})`,
        metadata: {
          bytesTransferred: rec.bytesTransferred,
          targetUsername: rec.username,
          userAgent: rec.userAgent,
          domain: rec.domain,
          url: rec.url,
          rawLogRef: rec.rawLogRef,
          evidenceSha256: rec.evidenceSha256,
          ingestionSource: rec.ingestionSource,
          action: rec.action,
        },
      };
      store.events.unshift(threatEvent);
      createdEvents.push(threatEvent);
      broadcast('threat_event_created', threatEvent);
    }

    const actor = String(req.header('x-user-name') || 'SOC Analyst');
    recordAudit(
      actor,
      role,
      'LOGS_INGESTED',
      'log_batch',
      parsed[0].evidenceSha256.slice(0, 16),
      `Ingested ${createdEvents.length} normalized events from ${source}`
    );

    return res.status(201).json({
      ingestedCount: createdEvents.length,
      evidenceSha256: parsed[0].evidenceSha256,
      events: createdEvents,
    });
  };

  app.post('/api/logs/ingest', handleLogIngest);
  app.post('/api/logs/upload', handleLogIngest);

  app.get('/api/reports/:case_id', (req, res) => {
    const found = store.cases.find((c) => c.id === req.params.case_id);
    if (!found) return res.status(404).json({error: 'Case not found'});
    const linkedEvents = store.events.filter(
      (e) => found.linkedEventIds.includes(e.id) || e.caseId === found.id
    );
    const markdown = generateCaseMarkdownReport(found, linkedEvents);
    res.json({
      caseId: found.id,
      title: found.title,
      markdown,
      linkedEventsCount: linkedEvents.length,
      generatedAt: new Date().toISOString(),
    });
  });

  app.get('/api/statistics/global', (_req, res) => {
    res.json(computeGlobalStatistics(store.events, store.assets, store.ipIntel));
  });

  app.get('/api/statistics/region/:region_id', (req, res) => {
    const regionId = req.params.region_id.toLowerCase();
    const stats = computeGlobalStatistics(store.events, store.assets, store.ipIntel);
    const region = stats.geoRiskMatrix.find(
      (r) => r.regionId === regionId || r.countryCode.toLowerCase() === regionId || r.country.toLowerCase() === regionId
    );
    if (!region) return res.status(404).json({error: `Region ${regionId} not found`});
    const regionEvents = store.events.filter((e) => e.sourceLocation.countryCode.toLowerCase() === region.countryCode.toLowerCase());
    return res.json({region, events: regionEvents});
  });

  app.get('/api/audit-logs', (_req, res) => {
    res.json({logs: store.auditLogs});
  });

  // Server-side Gemini Forensic Analyst endpoint
  app.post('/api/analysis/query', async (req, res) => {
    const question = String(req.body.question || '').trim();
    if (!question) {
      return res.status(400).json({error: 'Please enter a forensic investigation question.'});
    }
    const apiKey = process.env.GEMINI_API_KEY?.trim();
    if (!apiKey) {
      return res.status(503).json({
        error: 'Gemini API key is not configured on the server. Add GEMINI_API_KEY in Settings > Secrets to run AI forensic analysis.',
      });
    }

    const selectedEventId = req.body.selectedEventId ? String(req.body.selectedEventId) : null;
    const selectedCaseId = req.body.selectedCaseId ? String(req.body.selectedCaseId) : null;
    const selectedIp = req.body.selectedIp ? String(req.body.selectedIp) : null;
    const activeFilters = req.body.filters ?? {};

    const contextPayload = {
      forensicRules: [
        'NEVER invent facts, IPs, hashes, or log entries not present in the supplied telemetry.',
        'Clearly separate verified evidence, correlation-based inference, and DEMO DATA.',
        'NEVER present IP geolocation as proof of a person physical location or identity; always cite accuracy radius km and anonymization caveats.',
        'If evidence is insufficient, explicitly list missing logs/artifacts under evidenceGaps.',
      ],
      activeFilters,
      selectedEvent: selectedEventId ? store.events.find((e) => e.id === selectedEventId) ?? null : null,
      selectedCase: selectedCaseId ? store.cases.find((c) => c.id === selectedCaseId) ?? null : null,
      selectedIpIntel: selectedIp ? store.ipIntel[selectedIp] ?? null : null,
      recentEvents: store.events.slice(0, 18).map((e) => ({
        id: e.id,
        eventType: e.eventType,
        severity: e.severity,
        riskScore: e.riskScore,
        sourceIp: e.sourceIp,
        approxLocation: `${e.sourceLocation.city}, ${e.sourceLocation.country} (±${e.sourceLocation.accuracyRadiusKm} km)`,
        asn: e.asn,
        isp: e.isp,
        connectionType: e.connectionType,
        vpnProbability: e.vpnProbability,
        targetAsset: e.targetAssetName,
        maskedDestinationIp: e.maskedDestinationIp,
        timestamp: e.timestamp,
        status: e.status,
        caseId: e.caseId,
        isDemoData: e.isDemoData,
        metadata: e.metadata,
      })),
      assets: store.assets.map((a) => ({
        id: a.id,
        name: a.name,
        location: a.locationLabel,
        type: a.assetType,
        criticality: a.criticality,
        riskScore: a.riskScore,
      })),
      cases: store.cases.map((c) => ({
        id: c.id,
        title: c.title,
        priority: c.priority,
        status: c.status,
        linkedIps: c.linkedIps,
        linkedEventIds: c.linkedEventIds,
        evidenceCount: c.evidence.length,
        notesCount: c.notes.length,
        isDemoData: c.isDemoData,
      })),
    };

    try {
      const ai = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });

      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `Investigator Question: ${question}\n\nForensic Telemetry Context (JSON):\n${JSON.stringify(contextPayload)}`,
        config: {
          systemInstruction:
            'You are a Principal Digital Forensics & Incident Response (DFIR) Analyst inside CyberTrace Globe. Analyze ONLY the supplied telemetry context. Never fabricate IPs, timestamps, usernames, or conclusions. Explicitly distinguish verified telemetry, correlation-based inference, and simulated DEMO DATA. Always remind analysts that IP geolocation is an approximate network lead with an uncertainty radius and never proves an individual physical location.',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              summary: {type: Type.STRING, description: 'Concise executive incident summary grounded strictly in supplied data.'},
              likelyAttackChain: {
                type: Type.ARRAY,
                items: {type: Type.STRING},
                description: 'Ordered kill-chain steps inferred from correlated events.',
              },
              indicatorsOfCompromise: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    type: {type: Type.STRING},
                    value: {type: Type.STRING},
                    context: {type: Type.STRING},
                    isDemoData: {type: Type.BOOLEAN},
                  },
                },
              },
              riskAssessment: {type: Type.STRING, description: 'Overall risk posture and impact assessment.'},
              evidenceGaps: {
                type: Type.ARRAY,
                items: {type: Type.STRING},
                description: 'Specific missing logs, PCAPs, EDR captures, or auth records needed.',
              },
              recommendedActions: {
                type: Type.ARRAY,
                items: {type: Type.STRING},
                description: 'Concrete prioritized containment and forensic response actions.',
              },
              confidenceLevel: {type: Type.STRING, description: 'low, medium, or high'},
              verifiedEvidence: {
                type: Type.ARRAY,
                items: {type: Type.STRING},
                description: 'Facts directly verified from log/telemetry fields.',
              },
              correlationInferences: {
                type: Type.ARRAY,
                items: {type: Type.STRING},
                description: 'Analytic inferences derived by correlating multiple events.',
              },
              demoDataNotice: {
                type: Type.STRING,
                description: 'Explicit notice if simulated DEMO DATA was included in the analyzed records.',
              },
              sourcesUsed: {
                type: Type.ARRAY,
                items: {type: Type.STRING},
                description: 'Event IDs, case IDs, and asset IDs referenced.',
              },
            },
            required: [
              'summary',
              'likelyAttackChain',
              'indicatorsOfCompromise',
              'riskAssessment',
              'evidenceGaps',
              'recommendedActions',
              'confidenceLevel',
              'verifiedEvidence',
              'correlationInferences',
              'demoDataNotice',
              'sourcesUsed',
            ],
          },
        },
      });

      const rawText = (response.text ?? '{}').trim();
      const parsed = JSON.parse(rawText);
      const normalizedConfidence =
        parsed.confidenceLevel === 'high' || parsed.confidenceLevel === 'low' ? parsed.confidenceLevel : 'medium';

      return res.json({
        ...parsed,
        confidenceLevel: normalizedConfidence,
        generatedAt: new Date().toISOString(),
      });
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : 'Gemini analysis request failed';
      console.error('Gemini Forensic Analyst error:', msg);
      return res.status(502).json({
        error: `Forensic AI analysis failed: ${msg}`,
      });
    }
  });

  // ==================== STATIC / VITE SERVING ====================
  if (!IS_PROD) {
    const {createServer: createViteServer} = await import('vite');
    const vite = await createViteServer({
      server: {middlewareMode: true},
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`CyberTrace Globe full-stack server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start CyberTrace Globe server:', err);
  process.exit(1);
});
