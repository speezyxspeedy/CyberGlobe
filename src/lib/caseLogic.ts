import type {
  EvidenceFile,
  InvestigationCase,
  ProtectedAsset,
  ThreatEvent,
} from '../types/forensics';
import {APPROX_LOCATION_DISCLAIMER} from '../types/forensics';
import {sha256Hex} from './logParser';

export interface RelationshipNode {
  id: string;
  label: string;
  kind: 'ip' | 'domain' | 'url' | 'user' | 'device' | 'alert' | 'case';
  riskLevel?: string;
}

export interface RelationshipEdge {
  source: string;
  target: string;
  label: string;
}

export interface RelationshipGraphData {
  nodes: RelationshipNode[];
  edges: RelationshipEdge[];
}

export function buildRelationshipGraph(
  forensicCase: InvestigationCase,
  events: ThreatEvent[],
  assets: ProtectedAsset[]
): RelationshipGraphData {
  const nodesMap = new Map<string, RelationshipNode>();
  const edges: RelationshipEdge[] = [];

  const caseNodeId = `case:${forensicCase.id}`;
  nodesMap.set(caseNodeId, {
    id: caseNodeId,
    label: forensicCase.title.slice(0, 32),
    kind: 'case',
    riskLevel: forensicCase.priority,
  });

  const linkedEvents = events.filter(
    (e) => forensicCase.linkedEventIds.includes(e.id) || e.caseId === forensicCase.id
  );

  for (const ev of linkedEvents) {
    const alertId = `alert:${ev.id}`;
    nodesMap.set(alertId, {
      id: alertId,
      label: `${ev.eventType.replace(/_/g, ' ')} (${ev.riskScore})`,
      kind: 'alert',
      riskLevel: ev.severity,
    });
    edges.push({source: alertId, target: caseNodeId, label: 'linked_to'});

    const ipId = `ip:${ev.sourceIp}`;
    if (!nodesMap.has(ipId)) {
      nodesMap.set(ipId, {
        id: ipId,
        label: ev.sourceIp,
        kind: 'ip',
        riskLevel: ev.severity,
      });
    }
    edges.push({source: ipId, target: alertId, label: 'originates'});

    if (ev.metadata.c2Domain || ev.metadata.domain) {
      const dom = ev.metadata.c2Domain ?? ev.metadata.domain!;
      const domId = `domain:${dom}`;
      if (!nodesMap.has(domId)) {
        nodesMap.set(domId, {id: domId, label: dom, kind: 'domain'});
      }
      edges.push({source: ipId, target: domId, label: 'resolves'});
      if (ev.metadata.url) {
        const urlId = `url:${ev.metadata.url}`;
        if (!nodesMap.has(urlId)) {
          nodesMap.set(urlId, {id: urlId, label: ev.metadata.url, kind: 'url'});
        }
        edges.push({source: domId, target: urlId, label: 'hosts'});
      }
    }

    if (ev.metadata.targetUsername) {
      const userId = `user:${ev.metadata.targetUsername}`;
      if (!nodesMap.has(userId)) {
        nodesMap.set(userId, {id: userId, label: ev.metadata.targetUsername, kind: 'user'});
      }
      edges.push({source: alertId, target: userId, label: 'targets_user'});
    }

    const asset = assets.find((a) => a.id === ev.targetAssetId);
    const deviceLabel = ev.metadata.infectedEndpoint ?? asset?.name ?? ev.targetAssetName;
    const deviceId = `device:${deviceLabel}`;
    if (!nodesMap.has(deviceId)) {
      nodesMap.set(deviceId, {id: deviceId, label: deviceLabel, kind: 'device'});
    }
    edges.push({source: alertId, target: deviceId, label: 'affects_asset'});
  }

  for (const ip of forensicCase.linkedIps) {
    const ipId = `ip:${ip}`;
    if (!nodesMap.has(ipId)) {
      nodesMap.set(ipId, {id: ipId, label: ip, kind: 'ip'});
      edges.push({source: ipId, target: caseNodeId, label: 'indicator'});
    }
  }

  for (const dom of forensicCase.linkedDomains) {
    const domId = `domain:${dom}`;
    if (!nodesMap.has(domId)) {
      nodesMap.set(domId, {id: domId, label: dom, kind: 'domain'});
      edges.push({source: domId, target: caseNodeId, label: 'indicator'});
    }
  }

  return {
    nodes: Array.from(nodesMap.values()),
    edges,
  };
}

export function verifyEvidenceIntegrity(evidence: EvidenceFile, rawContent?: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(evidence.sha256Hash)) return false;
  if (rawContent !== undefined) {
    return sha256Hex(rawContent) === evidence.sha256Hash;
  }
  return evidence.integrityStatus === 'verified';
}

export function generateCaseMarkdownReport(
  forensicCase: InvestigationCase,
  linkedEvents: ThreatEvent[]
): string {
  const lines: string[] = [
    `# CyberTrace Globe — Forensic Investigation Report`,
    ``,
    `- **Case ID:** ${forensicCase.id}`,
    `- **Title:** ${forensicCase.title}`,
    `- **Priority:** ${forensicCase.priority.toUpperCase()}`,
    `- **Status:** ${forensicCase.status.toUpperCase()}`,
    `- **Assigned Analyst:** ${forensicCase.assignedAnalyst}`,
    `- **Created At:** ${forensicCase.createdAt}`,
    `- **Updated At:** ${forensicCase.updatedAt}`,
    `- **Data Classification:** ${forensicCase.isDemoData ? 'DEMO DATA (Simulated Scenario)' : 'Operational Telemetry'}`,
    ``,
    `> **Forensic Geolocation Notice:** ${APPROX_LOCATION_DISCLAIMER}`,
    ``,
    `## Executive Summary`,
    forensicCase.description,
    ``,
    `## Linked Indicators`,
    `- **IP Addresses:** ${forensicCase.linkedIps.join(', ') || 'None'}`,
    `- **Domains:** ${forensicCase.linkedDomains.join(', ') || 'None'}`,
    `- **File Hashes:** ${forensicCase.linkedHashes.join(', ') || 'None'}`,
    `- **Target Users:** ${forensicCase.linkedUsers.join(', ') || 'None'}`,
    `- **Tags:** ${forensicCase.tags.join(', ') || 'None'}`,
    ``,
    `## Correlated Threat Events (${linkedEvents.length})`,
  ];

  if (linkedEvents.length === 0) {
    lines.push(`_No correlated threat events linked yet._`);
  } else {
    lines.push(`| Timestamp | Event Type | Source IP | Approx. Location (±Radius) | Target Asset | Risk Score | Status |`);
    lines.push(`| --- | --- | --- | --- | --- | --- | --- |`);
    for (const ev of linkedEvents) {
      lines.push(
        `| ${ev.timestamp} | ${ev.eventType} | ${ev.sourceIp} | ${ev.sourceLocation.city}, ${ev.sourceLocation.country} (±${ev.sourceLocation.accuracyRadiusKm} km) | ${ev.targetAssetName} | ${ev.riskScore}/100 (${ev.severity}) | ${ev.status} |`
      );
    }
  }

  lines.push(``, `## Chain of Custody & Preserved Evidence (${forensicCase.evidence.length})`);
  if (forensicCase.evidence.length === 0) {
    lines.push(`_No evidence artifacts uploaded._`);
  } else {
    for (const ev of forensicCase.evidence) {
      lines.push(
        `- **${ev.fileName}** (\`${ev.id}\`) — ${ev.fileType}, ${ev.fileSize} bytes`,
        `  - SHA-256: \`${ev.sha256Hash}\``,
        `  - Collected By: ${ev.collectedBy} at ${ev.collectedAt} from ${ev.sourceSystem}`,
        `  - Integrity Status: **${ev.integrityStatus.toUpperCase()}**`
      );
    }
  }

  lines.push(``, `## Investigator Notes (${forensicCase.notes.length})`);
  if (forensicCase.notes.length === 0) {
    lines.push(`_No notes recorded._`);
  } else {
    for (const note of forensicCase.notes) {
      lines.push(`### ${note.authorName} — ${note.createdAt}`, note.content, ``);
    }
  }

  lines.push(
    ``,
    `## Limitations and Legal Notices`,
    ``,
    `> **Approximate geolocation notice:** ${APPROX_LOCATION_DISCLAIMER}`,
    ``,
    `- IP geolocation data in this report is derived from network routing databases (MaxMind GeoLite2 or equivalent). Accuracy varies by country, ISP, and use of anonymizing infrastructure.`,
    `- Confidence radius values are estimates of the maximum likely distance between the mapped coordinate and the actual network egress point. They are **not** error bars on a person's physical location.`,
    `- VPN, proxy, Tor exit node, and datacenter/hosting flags are probabilistic. A high flag probability does not confirm that an individual is using an anonymizer.`,
    `- Event timestamps are recorded in UTC. Local-time correlation requires knowledge of the asset's configured timezone.`,
    `- This report was generated by an automated system. All findings should be validated by a qualified analyst before use in legal, disciplinary, or enforcement proceedings.`,
    `- SHA-256 hashes verify evidence integrity at time of collection. They do not authenticate the source or exclude the possibility of evidence fabrication prior to ingestion.`,
    ``,
    `---`,
    ``,
    `_Report generated by CyberTrace Globe · ${new Date().toISOString()} · ${forensicCase.isDemoData ? 'DEMO DATA — simulated scenario' : 'Operational telemetry'}_`,
  );

  return lines.join('\n');
}

export function exportEventsToCsv(events: ThreatEvent[]): string {
  const headers = [
    'id',
    'timestamp',
    'event_type',
    'severity',
    'risk_score',
    'confidence',
    'status',
    'source_ip',
    'approx_city',
    'approx_country',
    'accuracy_radius_km',
    'asn',
    'isp',
    'connection_type',
    'destination_masked',
    'target_asset',
    'protocol',
    'destination_port',
    'is_demo_data',
  ];

  const escapeCsv = (val: unknown) => {
    const str = String(val ?? '');
    if (/[",\n]/.test(str)) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const rows = events.map((ev) =>
    [
      ev.id,
      ev.timestamp,
      ev.eventType,
      ev.severity,
      ev.riskScore,
      ev.confidence,
      ev.status,
      ev.sourceIp,
      ev.sourceLocation.city,
      ev.sourceLocation.country,
      ev.sourceLocation.accuracyRadiusKm,
      ev.asn,
      ev.isp,
      ev.connectionType,
      ev.maskedDestinationIp,
      ev.targetAssetName,
      ev.protocol,
      ev.destinationPort,
      ev.isDemoData,
    ]
      .map(escapeCsv)
      .join(',')
  );

  return [headers.join(','), ...rows].join('\n');
}
