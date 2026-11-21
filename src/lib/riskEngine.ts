import type {
  ConnectionType,
  RiskAssessment,
  RiskFactor,
  Severity,
  ThreatCategory,
} from '../types/forensics';

export interface RiskScoringInput {
  eventType: ThreatCategory;
  abuseConfidence: number; // 0 - 100
  failedAuthCount?: number;
  portsScanned?: number;
  unusualGeoOrigin?: boolean;
  connectionType: ConnectionType;
  vpnProbability: number; // 0 - 1
  outboundBytes?: number;
  hasMalwareC2Indicator?: boolean;
  historicalEventsCount?: number;
  targetedAssetCount?: number;
  offHoursAnomaly?: boolean;
  correlatedSourceCount?: number;
  evidenceRefs?: string[];
}

export function classifyRiskLevel(score: number): Severity {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  return 'low';
}

export function buildRecommendedAction(
  eventType: ThreatCategory,
  riskLevel: Severity,
  connectionType: ConnectionType
): string {
  const anonymizerNote =
    connectionType === 'vpn' || connectionType === 'proxy' || connectionType === 'tor'
      ? ' Note anonymizer/shared egress — avoid attributing to an individual without endpoint telemetry.'
      : '';

  switch (eventType) {
    case 'ssh_brute_force':
      return riskLevel === 'critical' || riskLevel === 'high'
        ? `Block IP at perimeter firewall, enforce key-only SSH/MFA, reset targeted credentials, and audit auth logs for any successful sessions.${anonymizerNote}`
        : `Rate-limit source subnet, monitor authentication logs, and verify fail2ban policy coverage.${anonymizerNote}`;
    case 'port_scan':
      return `Add source IP to watchlist, verify exposed port surface on target asset, tighten ingress ACLs, and correlate with follow-on exploit attempts.${anonymizerNote}`;
    case 'malware_c2':
      return `Isolate suspected internal endpoint immediately, block C2 IP/domain at DNS & egress firewall, capture volatile memory/EDR triage, and hunt for lateral movement.${anonymizerNote}`;
    case 'data_exfiltration':
      return `Contain source host, revoke active session tokens, inspect DLP/proxy logs for transferred object scope, and initiate incident response escalation.${anonymizerNote}`;
    case 'ddos':
      return `Enable upstream rate-limiting/WAF scrubbing rules, drop malformed flows at edge, and coordinate with ISP/CDN mitigation.${anonymizerNote}`;
    case 'phishing':
      return `Quarantine matching emails, revoke compromised sessions, block phishing domain indicators, and notify targeted users.${anonymizerNote}`;
    case 'vpn_abuse':
      return `Require step-up MFA, verify impossible-travel session context, and review corporate VPN gateway access policies.${anonymizerNote}`;
    case 'anomalous_login':
      return `Challenge active session with MFA, verify user travel/device posture, and inspect post-authentication API activity.${anonymizerNote}`;
  }
}

export function calculateRiskScore(input: RiskScoringInput): RiskAssessment {
  const factors: RiskFactor[] = [];
  const reasons: string[] = [];

  // 1. Threat Reputation (AbuseIPDB or simulated reputation) - up to 28 pts
  const abuseClamped = Math.max(0, Math.min(100, input.abuseConfidence));
  const abusePts = Math.round((abuseClamped / 100) * 28);
  factors.push({
    name: 'Threat Reputation',
    weight: 28,
    contribution: abusePts,
    detail: `Abuse confidence ${abuseClamped}%`,
  });
  if (abuseClamped >= 65) {
    reasons.push(`High external abuse reputation score (${abuseClamped}/100)`);
  }

  // 2. Failed Authentication Intensity - up to 24 pts
  const failedAuth = Math.max(0, input.failedAuthCount ?? 0);
  const authPts = failedAuth >= 300 ? 24 : failedAuth >= 100 ? 18 : failedAuth >= 25 ? 12 : failedAuth > 0 ? 5 : 0;
  if (authPts > 0) {
    factors.push({
      name: 'Failed Authentication Volume',
      weight: 24,
      contribution: authPts,
      detail: `${failedAuth} failed authentication attempts`,
    });
    if (failedAuth >= 25) {
      reasons.push(`Sustained authentication failure burst (${failedAuth} attempts)`);
    }
  }

  // 3. Port-Scan Intensity - up to 16 pts
  const ports = Math.max(0, input.portsScanned ?? 0);
  const scanPts = ports >= 500 ? 16 : ports >= 100 ? 12 : ports >= 20 ? 7 : ports > 0 ? 3 : 0;
  if (scanPts > 0) {
    factors.push({
      name: 'Port-Scan Reconnaissance',
      weight: 16,
      contribution: scanPts,
      detail: `${ports} distinct ports probed`,
    });
    if (ports >= 20) {
      reasons.push(`Multi-port reconnaissance sweep (${ports} ports targeted)`);
    }
  }

  // 4. Malware / C2 Indicators - up to 28 pts
  const c2Pts = input.hasMalwareC2Indicator || input.eventType === 'malware_c2' ? 28 : 0;
  if (c2Pts > 0) {
    factors.push({
      name: 'Malware C2 Beacon Indicator',
      weight: 28,
      contribution: c2Pts,
      detail: 'Periodic outbound callback to flagged C2 infrastructure',
    });
    reasons.push('Outbound command-and-control beaconing pattern detected');
  }

  // 5. Outbound Data Volume (Exfiltration) - up to 28 pts
  const bytes = Math.max(0, input.outboundBytes ?? 0);
  const mb = bytes / (1024 * 1024);
  const exfilPts = mb >= 1024 ? 28 : mb >= 250 ? 22 : mb >= 50 ? 14 : mb >= 10 ? 6 : 0;
  if (exfilPts > 0) {
    factors.push({
      name: 'Outbound Transfer Volume',
      weight: 28,
      contribution: exfilPts,
      detail: `${mb >= 1024 ? `${(mb / 1024).toFixed(2)} GB` : `${mb.toFixed(1)} MB`} outbound transfer`,
    });
    if (mb >= 50) {
      reasons.push(`Anomalous outbound data volume (${mb >= 1024 ? `${(mb / 1024).toFixed(2)} GB` : `${mb.toFixed(0)} MB`})`);
    }
  }

  // 6. Anonymization / Hosting Risk (VPN, Proxy, Tor, Datacenter) - up to 12 pts
  const vpnClamped = Math.max(0, Math.min(1, input.vpnProbability));
  const anonBase =
    input.connectionType === 'tor'
      ? 12
      : input.connectionType === 'proxy' || input.connectionType === 'vpn'
        ? 9
        : input.connectionType === 'hosting' || input.connectionType === 'datacenter'
          ? 6
          : 2;
  const anonPts = Math.min(12, Math.round(anonBase * 0.65 + vpnClamped * 5));
  factors.push({
    name: 'Network Anonymization & Hosting',
    weight: 12,
    contribution: anonPts,
    detail: `${input.connectionType} (anonymization prob. ${Math.round(vpnClamped * 100)}%)`,
  });
  if (input.connectionType === 'tor' || vpnClamped >= 0.65) {
    reasons.push(`Traffic routed via ${input.connectionType.toUpperCase()} / anonymizing infrastructure`);
  }

  // 7. Unusual Geographic Origin - up to 8 pts
  const geoPts = input.unusualGeoOrigin ? 8 : 0;
  if (geoPts > 0) {
    factors.push({
      name: 'Unusual Geographic Origin',
      weight: 8,
      contribution: geoPts,
      detail: 'Origin outside normal organizational traffic baseline',
    });
    reasons.push('Unusual approximate geographic origin relative to asset baseline');
  }

  // 8. Historical IP Behavior - up to 8 pts
  const hist = Math.max(0, input.historicalEventsCount ?? 0);
  const histPts = hist >= 20 ? 8 : hist >= 5 ? 6 : hist >= 2 ? 3 : 0;
  if (histPts > 0) {
    factors.push({
      name: 'Historical Repeat Offender',
      weight: 8,
      contribution: histPts,
      detail: `${hist} prior recorded security events`,
    });
    if (hist >= 5) {
      reasons.push(`Repeat source across ${hist} historical events`);
    }
  }

  // 9. Multi-Asset Targeting - up to 8 pts
  const assetCount = Math.max(1, input.targetedAssetCount ?? 1);
  const assetPts = assetCount >= 4 ? 8 : assetCount >= 2 ? 5 : 0;
  if (assetPts > 0) {
    factors.push({
      name: 'Multi-Asset Targeting',
      weight: 8,
      contribution: assetPts,
      detail: `${assetCount} protected assets targeted`,
    });
    reasons.push(`Cross-asset targeting (${assetCount} distinct targets)`);
  }

  // 10. Time-Based Anomaly - up to 6 pts
  const timePts = input.offHoursAnomaly ? 6 : 0;
  if (timePts > 0) {
    factors.push({
      name: 'Temporal Anomaly',
      weight: 6,
      contribution: timePts,
      detail: 'Activity observed outside scheduled maintenance/business window',
    });
  }

  // 11. Multi-Source Correlation - up to 8 pts
  const corr = Math.max(1, input.correlatedSourceCount ?? 1);
  const corrPts = corr >= 3 ? 8 : corr === 2 ? 5 : 0;
  if (corrPts > 0) {
    factors.push({
      name: 'Cross-Source Correlation',
      weight: 8,
      contribution: corrPts,
      detail: `Corroborated across ${corr} telemetry sources`,
    });
    reasons.push(`Correlated across ${corr} independent telemetry feeds`);
  }

  // Baseline for high-impact event types without granular counters
  const categoryFloor: Record<ThreatCategory, number> = {
    malware_c2: 26,
    data_exfiltration: 24,
    ssh_brute_force: 22,
    ddos: 20,
    phishing: 16,
    anomalous_login: 14,
    vpn_abuse: 12,
    port_scan: 8,
  };

  const rawSum =
    factors.reduce((sum, f) => sum + f.contribution, 0) +
    Math.round(categoryFloor[input.eventType] * 0.65);
  const riskScore = Math.max(5, Math.min(100, rawSum));
  const riskLevel = classifyRiskLevel(riskScore);

  // Confidence rises with corroborating signals, drops slightly with heavy anonymization
  const signalCount = factors.filter((f) => f.contribution > 0).length;
  const anonPenalty = input.connectionType === 'tor' ? 8 : vpnClamped > 0.7 ? 5 : 0;
  const confidence = Math.max(
    45,
    Math.min(98, 56 + signalCount * 5 + (corr > 1 ? 6 : 0) - anonPenalty)
  );

  if (reasons.length === 0) {
    reasons.push(`Classified as ${input.eventType.replace(/_/g, ' ')} telemetry signal`);
  }

  return {
    riskScore,
    riskLevel,
    confidence,
    reasons,
    factors,
    evidenceRefs: input.evidenceRefs ?? [],
    recommendedAction: buildRecommendedAction(input.eventType, riskLevel, input.connectionType),
  };
}
