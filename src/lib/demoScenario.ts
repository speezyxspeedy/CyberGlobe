import type {
  AuditLogEntry,
  GeoRiskEntry,
  GlobalStatistics,
  InvestigationCase,
  IpIntelligence,
  ProtectedAsset,
  Severity,
  ThreatCategory,
  ThreatEvent,
} from '../types/forensics';
import {APPROX_LOCATION_DISCLAIMER} from '../types/forensics';
import {maskPrivateIp, sha256Hex} from './logParser';
import {calculateRiskScore} from './riskEngine';

const NOW = Date.now();
const minsAgo = (m: number) => new Date(NOW - m * 60_000).toISOString();

export const DEMO_ASSETS: ProtectedAsset[] = [
  {
    id: 'asset-mum-ssh-01',
    name: 'Mumbai Core Bastion (MUM-SSH-01)',
    ipOrInternalId: '10.14.0.12',
    maskedInternalIp: maskPrivateIp('10.14.0.12'),
    locationLabel: 'Mumbai, Maharashtra, India',
    country: 'India',
    countryCode: 'IN',
    latitude: 19.076,
    longitude: 72.8777,
    assetType: 'cloud_vm',
    criticality: 'critical',
    openPorts: [22, 443],
    associatedAlertCount: 5,
    riskScore: 91,
    isDemoData: true,
  },
  {
    id: 'asset-iad-api-01',
    name: 'US-East Payments API Gateway',
    ipOrInternalId: '10.20.4.18',
    maskedInternalIp: maskPrivateIp('10.20.4.18'),
    locationLabel: 'Ashburn, Virginia, United States',
    country: 'United States',
    countryCode: 'US',
    latitude: 39.0438,
    longitude: -77.4874,
    assetType: 'api',
    criticality: 'critical',
    openPorts: [443, 8443],
    associatedAlertCount: 4,
    riskScore: 88,
    isDemoData: true,
  },
  {
    id: 'asset-fra-db-02',
    name: 'Frankfurt Ledger Primary DB',
    ipOrInternalId: '10.32.8.44',
    maskedInternalIp: maskPrivateIp('10.32.8.44'),
    locationLabel: 'Frankfurt, Hesse, Germany',
    country: 'Germany',
    countryCode: 'DE',
    latitude: 50.1109,
    longitude: 8.6821,
    assetType: 'database',
    criticality: 'critical',
    openPorts: [5432, 443],
    associatedAlertCount: 3,
    riskScore: 93,
    isDemoData: true,
  },
  {
    id: 'asset-lon-web-03',
    name: 'London Customer Portal Cluster',
    ipOrInternalId: '10.40.2.10',
    maskedInternalIp: maskPrivateIp('10.40.2.10'),
    locationLabel: 'London, United Kingdom',
    country: 'United Kingdom',
    countryCode: 'GB',
    latitude: 51.5072,
    longitude: -0.1276,
    assetType: 'web_server',
    criticality: 'high',
    openPorts: [80, 443],
    associatedAlertCount: 3,
    riskScore: 76,
    isDemoData: true,
  },
  {
    id: 'asset-sin-fw-01',
    name: 'Singapore Edge Firewall & VPN',
    ipOrInternalId: '10.50.1.1',
    maskedInternalIp: maskPrivateIp('10.50.1.1'),
    locationLabel: 'Singapore',
    country: 'Singapore',
    countryCode: 'SG',
    latitude: 1.3521,
    longitude: 103.8198,
    assetType: 'firewall',
    criticality: 'high',
    openPorts: [443, 500, 4500],
    associatedAlertCount: 2,
    riskScore: 72,
    isDemoData: true,
  },
  {
    id: 'asset-sfo-wks-19',
    name: 'San Francisco Finance Workstation #19',
    ipOrInternalId: '10.60.19.87',
    maskedInternalIp: maskPrivateIp('10.60.19.87'),
    locationLabel: 'San Francisco, California, United States',
    country: 'United States',
    countryCode: 'US',
    latitude: 37.7749,
    longitude: -122.4194,
    assetType: 'workstation',
    criticality: 'high',
    openPorts: [445],
    associatedAlertCount: 2,
    riskScore: 89,
    isDemoData: true,
  },
  {
    id: 'asset-tyo-mail-01',
    name: 'Tokyo Corporate Mail Relay',
    ipOrInternalId: '10.72.3.25',
    maskedInternalIp: maskPrivateIp('10.72.3.25'),
    locationLabel: 'Tokyo, Japan',
    country: 'Japan',
    countryCode: 'JP',
    latitude: 35.6762,
    longitude: 139.6503,
    assetType: 'email_server',
    criticality: 'medium',
    openPorts: [25, 465, 587],
    associatedAlertCount: 2,
    riskScore: 64,
    isDemoData: true,
  },
];

interface SeedSourceSpec {
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  radiusKm: number;
  asn: string;
  asnName: string;
  isp: string;
  connectionType: IpIntelligence['connectionType'];
  vpnProb: number;
  proxyProb: number;
  tor: boolean;
  abuseScore: number;
  reports: number;
  categories: string[];
  blocked?: boolean;
}

export const DEMO_IP_PROFILES: SeedSourceSpec[] = [
  {
    ip: '203.0.113.45',
    country: 'India',
    countryCode: 'IN',
    region: 'Maharashtra',
    city: 'Mumbai',
    lat: 19.12,
    lon: 72.86,
    radiusKm: 25,
    asn: 'AS55836',
    asnName: 'RELIANCEJIO-IN',
    isp: 'Reliance Jio Infocomm',
    connectionType: 'mobile',
    vpnProb: 0.18,
    proxyProb: 0.12,
    tor: false,
    abuseScore: 86,
    reports: 318,
    categories: ['SSH Brute-Force', 'Credential Stuffing'],
    blocked: false,
  },
  {
    ip: '198.51.100.77',
    country: 'Russia',
    countryCode: 'RU',
    region: 'Moscow Oblast',
    city: 'Moscow',
    lat: 55.7558,
    lon: 37.6173,
    radiusKm: 40,
    asn: 'AS49505',
    asnName: 'SELECTEL-MSK',
    isp: 'Selectel Datacenter Hosting',
    connectionType: 'hosting',
    vpnProb: 0.62,
    proxyProb: 0.45,
    tor: false,
    abuseScore: 95,
    reports: 842,
    categories: ['Malware C2', 'Port Scan', 'SSH Brute-Force'],
    blocked: true,
  },
  {
    ip: '192.0.2.134',
    country: 'Netherlands',
    countryCode: 'NL',
    region: 'North Holland',
    city: 'Amsterdam',
    lat: 52.3676,
    lon: 4.9041,
    radiusKm: 35,
    asn: 'AS20473',
    asnName: 'AS-CHOOPA',
    isp: 'Vultr Holdings LLC (Cloud Exit)',
    connectionType: 'tor',
    vpnProb: 0.94,
    proxyProb: 0.89,
    tor: true,
    abuseScore: 91,
    reports: 615,
    categories: ['Tor Exit Node', 'Data Exfiltration', 'Proxy Abuse'],
    blocked: true,
  },
  {
    ip: '198.51.100.204',
    country: 'China',
    countryCode: 'CN',
    region: 'Guangdong',
    city: 'Shenzhen',
    lat: 22.5431,
    lon: 114.0579,
    radiusKm: 30,
    asn: 'AS4134',
    asnName: 'CHINANET-BACKBONE',
    isp: 'China Telecom Backbone',
    connectionType: 'datacenter',
    vpnProb: 0.34,
    proxyProb: 0.51,
    tor: false,
    abuseScore: 88,
    reports: 497,
    categories: ['Port Scan', 'Web Exploit Recon'],
    blocked: false,
  },
  {
    ip: '203.0.113.189',
    country: 'Brazil',
    countryCode: 'BR',
    region: 'Sao Paulo',
    city: 'Sao Paulo',
    lat: -23.5505,
    lon: -46.6333,
    radiusKm: 28,
    asn: 'AS28573',
    asnName: 'CLARO-BR',
    isp: 'Claro S.A. Broadband',
    connectionType: 'residential',
    vpnProb: 0.22,
    proxyProb: 0.64,
    tor: false,
    abuseScore: 79,
    reports: 194,
    categories: ['Botnet Proxy', 'DDoS Flood'],
    blocked: false,
  },
  {
    ip: '192.0.2.88',
    country: 'Romania',
    countryCode: 'RO',
    region: 'Bucharest',
    city: 'Bucharest',
    lat: 44.4268,
    lon: 26.1025,
    radiusKm: 45,
    asn: 'AS9009',
    asnName: 'M247-EUROPE',
    isp: 'M247 Europe SRL (Commercial VPN)',
    connectionType: 'vpn',
    vpnProb: 0.96,
    proxyProb: 0.72,
    tor: false,
    abuseScore: 74,
    reports: 263,
    categories: ['VPN Abuse', 'Anomalous Login'],
    blocked: false,
  },
  {
    ip: '198.51.100.51',
    country: 'United States',
    countryCode: 'US',
    region: 'Texas',
    city: 'Dallas',
    lat: 32.7767,
    lon: -96.797,
    radiusKm: 22,
    asn: 'AS14061',
    asnName: 'DIGITALOCEAN-ASN',
    isp: 'DigitalOcean Cloud Hosting',
    connectionType: 'hosting',
    vpnProb: 0.58,
    proxyProb: 0.41,
    tor: false,
    abuseScore: 82,
    reports: 311,
    categories: ['SSH Brute-Force', 'API Credential Stuffing'],
    blocked: true,
  },
  {
    ip: '203.0.113.99',
    country: 'Nigeria',
    countryCode: 'NG',
    region: 'Lagos',
    city: 'Lagos',
    lat: 6.5244,
    lon: 3.3792,
    radiusKm: 50,
    asn: 'AS29465',
    asnName: 'MTN-NIGERIA',
    isp: 'MTN Nigeria CGNAT Mobile',
    connectionType: 'mobile',
    vpnProb: 0.27,
    proxyProb: 0.35,
    tor: false,
    abuseScore: 68,
    reports: 119,
    categories: ['Phishing', 'Anomalous Login'],
    blocked: false,
  },
  {
    ip: '192.0.2.211',
    country: 'Hong Kong',
    countryCode: 'HK',
    region: 'Hong Kong',
    city: 'Hong Kong',
    lat: 22.3193,
    lon: 114.1694,
    radiusKm: 18,
    asn: 'AS45102',
    asnName: 'ALIBABA-CN-NET',
    isp: 'Alibaba Cloud International',
    connectionType: 'datacenter',
    vpnProb: 0.69,
    proxyProb: 0.58,
    tor: false,
    abuseScore: 93,
    reports: 530,
    categories: ['Data Exfiltration', 'Malware C2'],
    blocked: true,
  },
  {
    ip: '198.51.100.142',
    country: 'Germany',
    countryCode: 'DE',
    region: 'Bavaria',
    city: 'Nuremberg',
    lat: 49.4521,
    lon: 11.0767,
    radiusKm: 32,
    asn: 'AS24940',
    asnName: 'HETZNER-AS',
    isp: 'Hetzner Online GmbH',
    connectionType: 'proxy',
    vpnProb: 0.81,
    proxyProb: 0.88,
    tor: false,
    abuseScore: 71,
    reports: 176,
    categories: ['Port Scan', 'Proxy Relay'],
    blocked: false,
  },
  {
    ip: '203.0.113.17',
    country: 'South Korea',
    countryCode: 'KR',
    region: 'Seoul',
    city: 'Seoul',
    lat: 37.5665,
    lon: 126.978,
    radiusKm: 20,
    asn: 'AS4766',
    asnName: 'KIXS-AS-KR',
    isp: 'Korea Telecom Hosting',
    connectionType: 'datacenter',
    vpnProb: 0.31,
    proxyProb: 0.24,
    tor: false,
    abuseScore: 63,
    reports: 98,
    categories: ['Port Scan', 'SSH Probe'],
    blocked: false,
  },
  {
    ip: '192.0.2.47',
    country: 'Ukraine',
    countryCode: 'UA',
    region: 'Kyiv',
    city: 'Kyiv',
    lat: 50.4501,
    lon: 30.5234,
    radiusKm: 38,
    asn: 'AS15895',
    asnName: 'KYIVSTAR-AS',
    isp: 'Kyivstar Telecom Hosting',
    connectionType: 'hosting',
    vpnProb: 0.74,
    proxyProb: 0.61,
    tor: false,
    abuseScore: 84,
    reports: 288,
    categories: ['SSH Brute-Force', 'Malware Staging'],
    blocked: false,
  },
];

function makeEvent(params: {
  id: string;
  eventType: ThreatCategory;
  sourceSpec: SeedSourceSpec;
  asset: ProtectedAsset;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  minutesAgo: number;
  title: string;
  description: string;
  status: ThreatEvent['status'];
  caseId: string | null;
  metadata: ThreatEvent['metadata'];
  unusualGeoOrigin?: boolean;
  offHoursAnomaly?: boolean;
  correlatedSourceCount?: number;
  targetedAssetCount?: number;
}): ThreatEvent {
  const assessment = calculateRiskScore({
    eventType: params.eventType,
    abuseConfidence: params.sourceSpec.abuseScore,
    failedAuthCount: params.metadata.attempts,
    portsScanned: params.metadata.portsScanned,
    unusualGeoOrigin: params.unusualGeoOrigin,
    connectionType: params.sourceSpec.connectionType,
    vpnProbability: params.sourceSpec.vpnProb,
    outboundBytes: params.metadata.bytesTransferred,
    hasMalwareC2Indicator: params.eventType === 'malware_c2',
    historicalEventsCount: Math.max(2, Math.round(params.sourceSpec.reports / 40)),
    targetedAssetCount: params.targetedAssetCount ?? 2,
    offHoursAnomaly: params.offHoursAnomaly,
    correlatedSourceCount: params.correlatedSourceCount ?? 2,
    evidenceRefs: [params.metadata.rawLogRef ?? `telemetry:${params.id}`],
  });

  return {
    id: params.id,
    eventType: params.eventType,
    sourceIp: params.sourceSpec.ip,
    destinationIp: params.asset.ipOrInternalId,
    maskedDestinationIp: maskPrivateIp(params.asset.ipOrInternalId),
    targetAssetId: params.asset.id,
    targetAssetName: params.asset.name,
    sourcePort: params.sourcePort,
    destinationPort: params.destinationPort,
    protocol: params.protocol,
    sourceLocation: {
      country: params.sourceSpec.country,
      countryCode: params.sourceSpec.countryCode,
      region: params.sourceSpec.region,
      city: params.sourceSpec.city,
      latitude: params.sourceSpec.lat,
      longitude: params.sourceSpec.lon,
      accuracyRadiusKm: params.sourceSpec.radiusKm,
      disclaimer: APPROX_LOCATION_DISCLAIMER,
    },
    destinationLocation: {
      country: params.asset.country,
      countryCode: params.asset.countryCode,
      city: params.asset.locationLabel.split(',')[0],
      latitude: params.asset.latitude,
      longitude: params.asset.longitude,
    },
    timestamp: minsAgo(params.minutesAgo),
    confidence: assessment.confidence,
    severity: assessment.riskLevel,
    riskScore: assessment.riskScore,
    riskAssessment: assessment,
    title: params.title,
    description: params.description,
    status: params.status,
    caseId: params.caseId,
    asn: params.sourceSpec.asn,
    isp: params.sourceSpec.isp,
    connectionType: params.sourceSpec.connectionType,
    vpnProbability: params.sourceSpec.vpnProb,
    abuseConfidence: params.sourceSpec.abuseScore,
    isDemoData: true,
    dataSource: 'CyberTrace Simulated Telemetry (DEMO DATA)',
    metadata: {
      ...params.metadata,
      evidenceSha256: params.metadata.evidenceSha256 ?? sha256Hex(`${params.id}:${params.sourceSpec.ip}:${params.asset.id}`),
    },
  };
}

export function buildDemoDataset(): {
  assets: ProtectedAsset[];
  events: ThreatEvent[];
  ipIntel: Record<string, IpIntelligence>;
  cases: InvestigationCase[];
  auditLogs: AuditLogEntry[];
} {
  const byIp = (ip: string) => DEMO_IP_PROFILES.find((p) => p.ip === ip)!;
  const byAsset = (id: string) => DEMO_ASSETS.find((a) => a.id === id)!;

  const events: ThreatEvent[] = [
    makeEvent({
      id: 'evt-1001',
      eventType: 'ssh_brute_force',
      sourceSpec: byIp('203.0.113.45'),
      asset: byAsset('asset-mum-ssh-01'),
      sourcePort: 54120,
      destinationPort: 22,
      protocol: 'SSH/TCP',
      minutesAgo: 6,
      title: 'High-Velocity SSH Brute-Force on Mumbai Bastion',
      description: '512 failed SSH authentication attempts in 140s targeting root and deploy accounts on MUM-SSH-01.',
      status: 'escalated',
      caseId: 'CASE-2026-012',
      unusualGeoOrigin: false,
      offHoursAnomaly: true,
      correlatedSourceCount: 3,
      targetedAssetCount: 2,
      metadata: {
        attempts: 512,
        failureRate: 99.6,
        timeWindowSec: 140,
        targetUsername: 'deploy-ops',
        targetService: 'OpenSSH 9.6',
        rawLogRef: 'auth.log:line:4192',
        ingestionSource: 'sshd-journald',
        action: 'AUTH_FAILED',
      },
    }),
    makeEvent({
      id: 'evt-1002',
      eventType: 'malware_c2',
      sourceSpec: byIp('198.51.100.77'),
      asset: byAsset('asset-sfo-wks-19'),
      sourcePort: 49812,
      destinationPort: 8443,
      protocol: 'HTTPS/TLS',
      minutesAgo: 12,
      title: 'Suspected Cobalt-Style C2 Beacon from Finance Workstation',
      description: 'Periodic 45-second jittered outbound HTTPS callbacks from WKS-SFO-19 to flagged hosting infrastructure.',
      status: 'confirmed',
      caseId: 'CASE-2026-012',
      unusualGeoOrigin: true,
      offHoursAnomaly: true,
      correlatedSourceCount: 3,
      targetedAssetCount: 2,
      metadata: {
        infectedEndpoint: 'WKS-SFO-FIN-19',
        c2Domain: 'cdn-telemetry-sync.example.net',
        callbackFrequencySec: 45,
        malwareFamily: 'Sliver / Beacon-Variant (Demo)',
        firstSeen: minsAgo(95),
        lastSeen: minsAgo(12),
        bytesTransferred: 18_400_000,
        rawLogRef: 'zeek-ssl.log:uid:C8k92m1',
        ingestionSource: 'zeek-sensor-us-west',
        action: 'BEACON_DETECTED',
      },
    }),
    makeEvent({
      id: 'evt-1003',
      eventType: 'data_exfiltration',
      sourceSpec: byIp('192.0.2.211'),
      asset: byAsset('asset-fra-db-02'),
      sourcePort: 58302,
      destinationPort: 443,
      protocol: 'HTTPS/TCP',
      minutesAgo: 19,
      title: 'Anomalous 1.84 GB Outbound Transfer from Frankfurt Ledger DB',
      description: 'Unscheduled bulk encrypted transfer from internal DB replica proxy to unfamiliar cloud storage relay.',
      status: 'escalated',
      caseId: 'CASE-2026-014',
      unusualGeoOrigin: true,
      offHoursAnomaly: true,
      correlatedSourceCount: 3,
      targetedAssetCount: 1,
      metadata: {
        infectedEndpoint: 'FRA-DB-REPLICA-02',
        c2Domain: 's3-archive-mirror.example.org',
        bytesTransferred: 1_975_684_956,
        durationSec: 412,
        possibleDataTypes: ['SQL dump archive', 'Billing ledger CSV', 'PII records (suspected)'],
        rawLogRef: 'netflow-eu-central:flow:99124',
        ingestionSource: 'netflow-v9',
        action: 'LARGE_EGRESS_ALERT',
      },
    }),
    makeEvent({
      id: 'evt-1004',
      eventType: 'port_scan',
      sourceSpec: byIp('198.51.100.204'),
      asset: byAsset('asset-iad-api-01'),
      sourcePort: 41002,
      destinationPort: 443,
      protocol: 'TCP/SYN',
      minutesAgo: 28,
      title: 'Aggressive SYN Port Sweep Against US-East API Gateway',
      description: '642 distinct TCP ports probed across Ashburn ingress subnet within 90 seconds.',
      status: 'suspicious',
      caseId: 'CASE-2026-015',
      unusualGeoOrigin: true,
      offHoursAnomaly: false,
      correlatedSourceCount: 2,
      targetedAssetCount: 3,
      metadata: {
        portsScanned: 642,
        portsTargeted: [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200],
        durationSec: 90,
        scanIntensity: 'aggressive',
        rawLogRef: 'ufw-iad-edge.log:line:8821',
        ingestionSource: 'perimeter-firewall',
        action: 'SYN_SCAN_BLOCKED',
      },
    }),
    makeEvent({
      id: 'evt-1005',
      eventType: 'vpn_abuse',
      sourceSpec: byIp('192.0.2.88'),
      asset: byAsset('asset-sin-fw-01'),
      sourcePort: 51920,
      destinationPort: 443,
      protocol: 'TLS/VPN',
      minutesAgo: 34,
      title: 'Impossible-Travel Commercial VPN Login to Singapore Gateway',
      description: 'Corporate VPN authentication attempted via M247 commercial VPN exit 14 minutes after Mumbai office login.',
      status: 'suspicious',
      caseId: 'CASE-2026-012',
      unusualGeoOrigin: true,
      offHoursAnomaly: true,
      correlatedSourceCount: 2,
      targetedAssetCount: 2,
      metadata: {
        attempts: 38,
        failureRate: 84.2,
        timeWindowSec: 300,
        targetUsername: 'r.sharma@corp.example',
        targetService: 'WireGuard / SSL-VPN',
        rawLogRef: 'vpn-gw-sin.log:line:1148',
        ingestionSource: 'edge-vpn-syslog',
        action: 'MFA_CHALLENGE_FAILED',
      },
    }),
    makeEvent({
      id: 'evt-1006',
      eventType: 'data_exfiltration',
      sourceSpec: byIp('192.0.2.134'),
      asset: byAsset('asset-lon-web-03'),
      sourcePort: 60412,
      destinationPort: 443,
      protocol: 'HTTPS/TOR',
      minutesAgo: 47,
      title: 'Bulk API Export Routed Through Tor Exit Node',
      description: '420 MB of customer export endpoints scraped sequentially over an identified Tor exit node.',
      status: 'confirmed',
      caseId: 'CASE-2026-014',
      unusualGeoOrigin: true,
      offHoursAnomaly: true,
      correlatedSourceCount: 3,
      targetedAssetCount: 2,
      metadata: {
        infectedEndpoint: 'LON-PORTAL-API-03',
        bytesTransferred: 440_401_920,
        durationSec: 265,
        possibleDataTypes: ['Customer order exports', 'API JSON payloads'],
        url: '/api/v2/export/invoices',
        domain: 'portal.corp.example',
        rawLogRef: 'nginx-lon-03.log:line:94102',
        ingestionSource: 'nginx-waf',
        action: 'RATE_LIMIT_BREACH',
      },
    }),
    makeEvent({
      id: 'evt-1007',
      eventType: 'ssh_brute_force',
      sourceSpec: byIp('198.51.100.51'),
      asset: byAsset('asset-iad-api-01'),
      sourcePort: 38890,
      destinationPort: 22,
      protocol: 'SSH/TCP',
      minutesAgo: 62,
      title: 'Distributed SSH Credential Stuffing on US-East Infrastructure',
      description: '340 failed SSH login attempts from cloud hosting range using automated dictionary lists.',
      status: 'reviewed',
      caseId: 'CASE-2026-015',
      unusualGeoOrigin: false,
      offHoursAnomaly: false,
      correlatedSourceCount: 2,
      targetedAssetCount: 3,
      metadata: {
        attempts: 340,
        failureRate: 100,
        timeWindowSec: 210,
        targetUsername: 'ubuntu',
        targetService: 'OpenSSH',
        rawLogRef: 'sshd-iad.log:line:2290',
        ingestionSource: 'sshd-journald',
        action: 'BLOCKED_FAIL2BAN',
      },
    }),
    makeEvent({
      id: 'evt-1008',
      eventType: 'ddos',
      sourceSpec: byIp('203.0.113.189'),
      asset: byAsset('asset-lon-web-03'),
      sourcePort: 44129,
      destinationPort: 443,
      protocol: 'HTTP/2',
      minutesAgo: 88,
      title: 'HTTP/2 Rapid Reset Flood Targeting London Portal',
      description: 'Spike of 14,200 requests/sec from residential proxy swarm triggering WAF mitigation.',
      status: 'reviewed',
      caseId: null,
      unusualGeoOrigin: true,
      offHoursAnomaly: false,
      correlatedSourceCount: 2,
      targetedAssetCount: 1,
      metadata: {
        attempts: 14200,
        durationSec: 180,
        bytesTransferred: 92_000_000,
        url: '/checkout/session',
        userAgent: 'Mozilla/5.0 (compatible; FloodAgent-Sim/1.0)',
        rawLogRef: 'waf-lon-edge:event:77312',
        ingestionSource: 'edge-waf',
        action: 'SCRUBBED',
      },
    }),
    makeEvent({
      id: 'evt-1009',
      eventType: 'phishing',
      sourceSpec: byIp('203.0.113.99'),
      asset: byAsset('asset-tyo-mail-01'),
      sourcePort: 52214,
      destinationPort: 587,
      protocol: 'SMTP/TLS',
      minutesAgo: 115,
      title: 'Targeted Executive Credential-Harvesting Campaign',
      description: 'SPF/DKIM-failed spear-phishing batch spoofing finance invoice portal delivered to Tokyo mail relay.',
      status: 'new',
      caseId: null,
      unusualGeoOrigin: true,
      offHoursAnomaly: false,
      correlatedSourceCount: 2,
      targetedAssetCount: 1,
      metadata: {
        attempts: 42,
        targetUsername: 'ap-finance-group',
        domain: 'verify-payroll-secure.example.biz',
        url: 'https://verify-payroll-secure.example.biz/sso',
        rawLogRef: 'postfix-tyo.log:line:6120',
        ingestionSource: 'mail-gateway',
        action: 'QUARANTINED',
      },
    }),
    makeEvent({
      id: 'evt-1010',
      eventType: 'port_scan',
      sourceSpec: byIp('198.51.100.142'),
      asset: byAsset('asset-fra-db-02'),
      sourcePort: 55210,
      destinationPort: 5432,
      protocol: 'TCP',
      minutesAgo: 148,
      title: 'Database & Cache Port Enumeration via Proxy Relay',
      description: '185 service ports probed targeting PostgreSQL (5432), Redis (6379), and admin consoles in Frankfurt.',
      status: 'suspicious',
      caseId: 'CASE-2026-014',
      unusualGeoOrigin: false,
      offHoursAnomaly: true,
      correlatedSourceCount: 2,
      targetedAssetCount: 2,
      metadata: {
        portsScanned: 185,
        portsTargeted: [5432, 6379, 27017, 9090, 22, 443],
        durationSec: 120,
        scanIntensity: 'moderate',
        rawLogRef: 'fw-fra-02.log:line:3019',
        ingestionSource: 'perimeter-firewall',
        action: 'DROPPED',
      },
    }),
    makeEvent({
      id: 'evt-1011',
      eventType: 'ssh_brute_force',
      sourceSpec: byIp('192.0.2.47'),
      asset: byAsset('asset-fra-db-02'),
      sourcePort: 46118,
      destinationPort: 22,
      protocol: 'SSH/TCP',
      minutesAgo: 190,
      title: 'SSH Root Spray Against Frankfurt Infrastructure',
      description: '275 failed root and postgres SSH authentication attempts observed from Eastern European hosting block.',
      status: 'confirmed',
      caseId: 'CASE-2026-014',
      unusualGeoOrigin: true,
      offHoursAnomaly: true,
      correlatedSourceCount: 2,
      targetedAssetCount: 2,
      metadata: {
        attempts: 275,
        failureRate: 100,
        timeWindowSec: 195,
        targetUsername: 'postgres',
        targetService: 'OpenSSH',
        rawLogRef: 'auth-fra.log:line:9104',
        ingestionSource: 'sshd-journald',
        action: 'AUTH_FAILED',
      },
    }),
    makeEvent({
      id: 'evt-1012',
      eventType: 'anomalous_login',
      sourceSpec: byIp('203.0.113.17'),
      asset: byAsset('asset-mum-ssh-01'),
      sourcePort: 49904,
      destinationPort: 443,
      protocol: 'HTTPS',
      minutesAgo: 240,
      title: 'Off-Hours Admin Console Login from New ASN',
      description: 'Privileged API token used from previously unseen South Korean datacenter ASN targeting Mumbai management plane.',
      status: 'new',
      caseId: 'CASE-2026-012',
      unusualGeoOrigin: true,
      offHoursAnomaly: true,
      correlatedSourceCount: 2,
      targetedAssetCount: 1,
      metadata: {
        attempts: 14,
        failureRate: 71.4,
        timeWindowSec: 180,
        targetUsername: 'svc-ci-mumbai',
        targetService: 'Admin API',
        url: '/api/v1/admin/keys',
        rawLogRef: 'api-audit-mum.jsonl:line:512',
        ingestionSource: 'api-gateway',
        action: 'STEP_UP_REQUIRED',
      },
    }),
    makeEvent({
      id: 'evt-1013',
      eventType: 'malware_c2',
      sourceSpec: byIp('192.0.2.134'),
      asset: byAsset('asset-mum-ssh-01'),
      sourcePort: 50291,
      destinationPort: 443,
      protocol: 'HTTPS/TOR',
      minutesAgo: 310,
      title: 'Suspicious Outbound Staging Callback from Bastion Subnet',
      description: 'Short-lived encrypted outbound check-in from staging container to known Tor exit relay.',
      status: 'suspicious',
      caseId: 'CASE-2026-012',
      unusualGeoOrigin: true,
      offHoursAnomaly: true,
      correlatedSourceCount: 2,
      targetedAssetCount: 2,
      metadata: {
        infectedEndpoint: 'MUM-STAGE-NODE-04',
        c2Domain: 'update-pkg-relay.example.onion.ws',
        callbackFrequencySec: 120,
        malwareFamily: 'Linux.Dropper.Sim',
        firstSeen: minsAgo(360),
        lastSeen: minsAgo(310),
        bytesTransferred: 6_200_000,
        rawLogRef: 'zeek-conn-mum.log:line:889',
        ingestionSource: 'zeek-sensor-in-west',
        action: 'ALERTED',
      },
    }),
    makeEvent({
      id: 'evt-1014',
      eventType: 'port_scan',
      sourceSpec: byIp('203.0.113.45'),
      asset: byAsset('asset-sin-fw-01'),
      sourcePort: 44102,
      destinationPort: 4500,
      protocol: 'UDP/IKE',
      minutesAgo: 420,
      title: 'IKE/VPN Gateway Reconnaissance Sweep',
      description: '48 UDP/TCP VPN and management ports probed on Singapore edge firewall.',
      status: 'reviewed',
      caseId: null,
      unusualGeoOrigin: false,
      offHoursAnomaly: false,
      correlatedSourceCount: 1,
      targetedAssetCount: 2,
      metadata: {
        portsScanned: 48,
        portsTargeted: [500, 4500, 1194, 443, 22],
        durationSec: 65,
        scanIntensity: 'moderate',
        rawLogRef: 'fw-sin.log:line:2102',
        ingestionSource: 'perimeter-firewall',
        action: 'DROPPED',
      },
    }),
  ];

  const ipIntel: Record<string, IpIntelligence> = {};
  for (const spec of DEMO_IP_PROFILES) {
    const related = events.filter((e) => e.sourceIp === spec.ip);
    const maxRisk = related.length > 0 ? Math.max(...related.map((e) => e.riskScore)) : Math.min(95, spec.abuseScore);
    const primaryEvent = related[0];
    ipIntel[spec.ip] = {
      ip: spec.ip,
      approxLocation: {
        country: spec.country,
        countryCode: spec.countryCode,
        region: spec.region,
        city: spec.city,
        latitude: spec.lat,
        longitude: spec.lon,
        accuracyRadiusKm: spec.radiusKm,
        disclaimer: APPROX_LOCATION_DISCLAIMER,
      },
      asn: spec.asn,
      asnName: spec.asnName,
      isp: spec.isp,
      organization: spec.isp,
      connectionType: spec.connectionType,
      vpnProbability: spec.vpnProb,
      proxyProbability: spec.proxyProb,
      torExitNode: spec.tor,
      abuseConfidenceScore: spec.abuseScore,
      abuseReportCount: spec.reports,
      attackCategories: spec.categories,
      lastReportedAt: minsAgo(18),
      lastSeenAt: primaryEvent?.timestamp ?? minsAgo(25),
      historicalEventCount: Math.max(related.length, Math.round(spec.reports / 25)),
      relatedEventIds: related.map((e) => e.id),
      relatedCaseIds: Array.from(new Set(related.map((e) => e.caseId).filter(Boolean) as string[])),
      riskScore: maxRisk,
      riskLevel: primaryEvent?.severity ?? (maxRisk >= 80 ? 'critical' : maxRisk >= 60 ? 'high' : 'medium'),
      confidence: primaryEvent?.confidence ?? 84,
      recommendedAction:
        primaryEvent?.riskAssessment.recommendedAction ??
        'Monitor source ASN, enforce rate-limits, and correlate with endpoint telemetry.',
      blocked: Boolean(spec.blocked),
      dataSource: 'Simulated MaxMind GeoLite2 + AbuseIPDB Feed (DEMO DATA)',
      isDemoData: true,
      enrichedAt: minsAgo(2),
    };
  }

  const cases: InvestigationCase[] = [
    {
      id: 'CASE-2026-012',
      title: 'Case #12 — Coordinated Mumbai SSH Brute-Force & C2 Callback Chain',
      description:
        'Multi-vector intrusion investigation correlating sustained SSH brute-force attacks against MUM-SSH-01 (203.0.113.45), impossible-travel VPN access via AS9009, and Cobalt-style HTTPS beaconing from WKS-SFO-FIN-19.',
      priority: 'critical',
      status: 'investigating',
      assignedAnalyst: 'A. Kulkarni (Lead Forensics)',
      tags: ['ssh-brute-force', 'malware-c2', 'mumbai', 'vpn-abuse'],
      linkedEventIds: ['evt-1001', 'evt-1002', 'evt-1005', 'evt-1012', 'evt-1013'],
      linkedIps: ['203.0.113.45', '198.51.100.77', '192.0.2.88', '192.0.2.134'],
      linkedDomains: ['cdn-telemetry-sync.example.net', 'update-pkg-relay.example.onion.ws'],
      linkedHashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      linkedAssetIds: ['asset-mum-ssh-01', 'asset-sfo-wks-19', 'asset-sin-fw-01'],
      linkedUsers: ['deploy-ops', 'r.sharma@corp.example', 'svc-ci-mumbai'],
      notes: [
        {
          id: 'note-101',
          caseId: 'CASE-2026-012',
          authorId: 'analyst-demo-1',
          authorName: 'A. Kulkarni',
          content:
            'Confirmed 512 failed SSH attempts against MUM-SSH-01 from 203.0.113.45 (AS55836 mobile CGNAT). No successful password logins observed, but svc-ci-mumbai token activity 4 hours earlier warrants immediate key rotation.',
          createdAt: minsAgo(24),
        },
        {
          id: 'note-102',
          caseId: 'CASE-2026-012',
          authorId: 'analyst-demo-2',
          authorName: 'M. Chen',
          content:
            'WKS-SFO-FIN-19 isolated at EDR tier. Preserved Zeek SSL metadata and firewall flow capture with SHA-256 chain-of-custody verification.',
          createdAt: minsAgo(9),
        },
      ],
      evidence: [
        {
          id: 'EV-2026-081',
          caseId: 'CASE-2026-012',
          fileName: 'mum-ssh-01_auth_excerpt.log',
          fileType: 'text/plain',
          fileSize: 48_320,
          sha256Hash: sha256Hex('EV-2026-081:mum-ssh-01_auth_excerpt.log:demo'),
          collectedBy: 'A. Kulkarni',
          collectedAt: minsAgo(22),
          sourceSystem: 'MUM-SSH-01 (journald)',
          integrityStatus: 'verified',
          accessHistory: [
            {accessedBy: 'A. Kulkarni', accessedAt: minsAgo(22), action: 'COLLECTED_AND_HASHED'},
            {accessedBy: 'M. Chen', accessedAt: minsAgo(11), action: 'HASH_VERIFIED'},
          ],
          previewSnippet:
            'Nov 20 22:51:04 mum-ssh-01 sshd[8821]: Failed password for deploy-ops from 203.0.113.45 port 54120 ssh2',
          isDemoData: true,
        },
        {
          id: 'EV-2026-082',
          caseId: 'CASE-2026-012',
          fileName: 'wks-sfo-19_zeek_ssl_metadata.jsonl',
          fileType: 'application/jsonl',
          fileSize: 124_900,
          sha256Hash: sha256Hex('EV-2026-082:wks-sfo-19_zeek_ssl_metadata.jsonl:demo'),
          collectedBy: 'M. Chen',
          collectedAt: minsAgo(10),
          sourceSystem: 'Zeek Sensor US-West',
          integrityStatus: 'verified',
          accessHistory: [{accessedBy: 'M. Chen', accessedAt: minsAgo(10), action: 'COLLECTED_AND_HASHED'}],
          previewSnippet:
            '{"ts":"2026-11-20T22:48:11Z","id.orig_h":"10.60.19.87","id.resp_h":"198.51.100.77","server_name":"cdn-telemetry-sync.example.net"}',
          isDemoData: true,
        },
      ],
      createdAt: minsAgo(180),
      updatedAt: minsAgo(6),
      isDemoData: true,
    },
    {
      id: 'CASE-2026-014',
      title: 'Case #14 — Frankfurt Ledger DB Egress Anomaly & Tor API Scraping',
      description:
        'Investigation into 1.84 GB unscheduled outbound transfer from Frankfurt DB replica proxy to AS45102 alongside 420 MB invoice export via Tor exit node 192.0.2.134.',
      priority: 'critical',
      status: 'escalated',
      assignedAnalyst: 'E. Lindqvist (IR Lead)',
      tags: ['data-exfiltration', 'tor-exit', 'frankfurt', 'gdpr-review'],
      linkedEventIds: ['evt-1003', 'evt-1006', 'evt-1010', 'evt-1011'],
      linkedIps: ['192.0.2.211', '192.0.2.134', '198.51.100.142', '192.0.2.47'],
      linkedDomains: ['s3-archive-mirror.example.org', 'portal.corp.example'],
      linkedHashes: ['9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'],
      linkedAssetIds: ['asset-fra-db-02', 'asset-lon-web-03'],
      linkedUsers: ['postgres'],
      notes: [
        {
          id: 'note-103',
          caseId: 'CASE-2026-014',
          authorId: 'analyst-demo-3',
          authorName: 'E. Lindqvist',
          content:
            'Blocked destination IP 192.0.2.211 and Tor exit 192.0.2.134 at EU edge firewalls. Rotating database replica service credentials and preserving NetFlow v9 evidence.',
          createdAt: minsAgo(14),
        },
      ],
      evidence: [
        {
          id: 'EV-2026-091',
          caseId: 'CASE-2026-014',
          fileName: 'fra_db_egress_netflow_summary.csv',
          fileType: 'text/csv',
          fileSize: 82_410,
          sha256Hash: sha256Hex('EV-2026-091:fra_db_egress_netflow_summary.csv:demo'),
          collectedBy: 'E. Lindqvist',
          collectedAt: minsAgo(16),
          sourceSystem: 'EU-Central NetFlow Collector',
          integrityStatus: 'verified',
          accessHistory: [{accessedBy: 'E. Lindqvist', accessedAt: minsAgo(16), action: 'COLLECTED_AND_HASHED'}],
          previewSnippet: 'src_ip,dst_ip,dst_port,proto,bytes,duration\n10.32.8.44,192.0.2.211,443,TCP,1975684956,412',
          isDemoData: true,
        },
      ],
      createdAt: minsAgo(150),
      updatedAt: minsAgo(14),
      isDemoData: true,
    },
    {
      id: 'CASE-2026-015',
      title: 'Case #15 — US-East Perimeter Reconnaissance & Credential Spray',
      description:
        'Tracking aggressive 642-port SYN scan from AS4134 followed by automated SSH dictionary attacks against Ashburn API infrastructure.',
      priority: 'high',
      status: 'open',
      assignedAnalyst: 'D. Patel (SOC Tier 2)',
      tags: ['port-scan', 'recon', 'us-east'],
      linkedEventIds: ['evt-1004', 'evt-1007'],
      linkedIps: ['198.51.100.204', '198.51.100.51'],
      linkedDomains: [],
      linkedHashes: [],
      linkedAssetIds: ['asset-iad-api-01'],
      linkedUsers: ['ubuntu'],
      notes: [],
      evidence: [],
      createdAt: minsAgo(90),
      updatedAt: minsAgo(28),
      isDemoData: true,
    },
  ];

  const auditLogs: AuditLogEntry[] = [
    {
      id: 'aud-001',
      actorId: 'system-seed',
      actorName: 'CyberTrace Engine',
      role: 'Admin',
      action: 'DEMO_SCENARIO_INITIALIZED',
      targetType: 'system',
      targetId: 'global-demo',
      details: 'Loaded 14 simulated global threat events, 7 protected assets, and 3 forensic cases (DEMO DATA).',
      entryHash: sha256Hex('aud-001:DEMO_SCENARIO_INITIALIZED'),
      timestamp: minsAgo(180),
    },
    {
      id: 'aud-002',
      actorId: 'analyst-demo-1',
      actorName: 'A. Kulkarni',
      role: 'Analyst',
      action: 'EVIDENCE_PRESERVED',
      targetType: 'evidence',
      targetId: 'EV-2026-081',
      details: 'Preserved mum-ssh-01_auth_excerpt.log with verified SHA-256 chain of custody.',
      entryHash: sha256Hex('aud-002:EV-2026-081'),
      timestamp: minsAgo(22),
    },
    {
      id: 'aud-003',
      actorId: 'analyst-demo-3',
      actorName: 'E. Lindqvist',
      role: 'Admin',
      action: 'IP_BLOCK_POLICY_APPLIED',
      targetType: 'ip',
      targetId: '192.0.2.211',
      details: 'Applied perimeter block policy for high-risk egress IP 192.0.2.211 (AS45102).',
      entryHash: sha256Hex('aud-003:192.0.2.211'),
      timestamp: minsAgo(15),
    },
  ];

  return {assets: [...DEMO_ASSETS], events, ipIntel, cases, auditLogs};
}

export function computeGlobalStatistics(
  events: ThreatEvent[],
  assets: ProtectedAsset[],
  ipIntel: Record<string, IpIntelligence>
): GlobalStatistics {
  const categoryLabels: Record<ThreatCategory, string> = {
    ssh_brute_force: 'Brute Force',
    port_scan: 'Port Scan',
    malware_c2: 'Malware C2',
    data_exfiltration: 'Exfiltration',
    phishing: 'Phishing',
    ddos: 'DDoS',
    vpn_abuse: 'VPN / Proxy',
    anomalous_login: 'Anomalous Login',
  };

  const severityBreakdown: Record<Severity, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  const catCounts = new Map<ThreatCategory, number>();
  const attackedAssetIds = new Set<string>();
  const uniqueIps = new Set<string>();
  const geoMap = new Map<
    string,
    {
      country: string;
      countryCode: string;
      topCity: string;
      lat: number;
      lon: number;
      events: ThreatEvent[];
      ips: Set<string>;
      assets: Set<string>;
    }
  >();
  const asnMap = new Map<string, {asn: string; asnName: string; count: number; totalRisk: number}>();
  const connMap = new Map<IpIntelligence['connectionType'], number>();

  let totalExfilBytes = 0;

  for (const ev of events) {
    severityBreakdown[ev.severity]++;
    catCounts.set(ev.eventType, (catCounts.get(ev.eventType) ?? 0) + 1);
    attackedAssetIds.add(ev.targetAssetId);
    uniqueIps.add(ev.sourceIp);
    if (ev.eventType === 'data_exfiltration' || ev.metadata.bytesTransferred) {
      totalExfilBytes += ev.metadata.bytesTransferred ?? 0;
    }

    const cc = ev.sourceLocation.countryCode;
    const existingGeo = geoMap.get(cc);
    if (existingGeo) {
      existingGeo.events.push(ev);
      existingGeo.ips.add(ev.sourceIp);
      existingGeo.assets.add(ev.targetAssetId);
    } else {
      geoMap.set(cc, {
        country: ev.sourceLocation.country,
        countryCode: cc,
        topCity: ev.sourceLocation.city,
        lat: ev.sourceLocation.latitude,
        lon: ev.sourceLocation.longitude,
        events: [ev],
        ips: new Set([ev.sourceIp]),
        assets: new Set([ev.targetAssetId]),
      });
    }

    const intel = ipIntel[ev.sourceIp];
    const asnEntry = asnMap.get(ev.asn) ?? {
      asn: ev.asn,
      asnName: intel?.asnName ?? ev.isp,
      count: 0,
      totalRisk: 0,
    };
    asnEntry.count++;
    asnEntry.totalRisk += ev.riskScore;
    asnMap.set(ev.asn, asnEntry);

    connMap.set(ev.connectionType, (connMap.get(ev.connectionType) ?? 0) + 1);
  }

  const geoRiskMatrix: GeoRiskEntry[] = Array.from(geoMap.values())
    .map((g) => {
      const avgRisk = Math.round(
        g.events.reduce((acc, e) => acc + e.riskScore, 0) / Math.max(1, g.events.length)
      );
      const blockedIps = Array.from(g.ips).filter((ip) => ipIntel[ip]?.blocked).length;
      const criticalCount = g.events.filter((e) => e.severity === 'critical').length;
      const riskTrend: GeoRiskEntry['riskTrend'] =
        avgRisk >= 80 ? 'rising' : avgRisk >= 60 ? 'stable' : 'declining';
      return {
        regionId: g.countryCode.toLowerCase(),
        country: g.country,
        countryCode: g.countryCode,
        topCity: g.topCity,
        latitude: g.lat,
        longitude: g.lon,
        attackVolume: g.events.length,
        uniqueAttackerIps: g.ips.size,
        targetedAssets: g.assets.size,
        blockedIps,
        avgRiskScore: avgRisk,
        criticalCount,
        riskTrend,
        trendDeltaPct: riskTrend === 'rising' ? 18 : riskTrend === 'stable' ? 4 : -9,
      };
    })
    .sort((a, b) => b.avgRiskScore - a.avgRiskScore);

  const blockedIps = Object.values(ipIntel).filter((i) => i.blocked).length;

  // Build 8 timeline buckets across the last 8 hours
  const nowMs = Date.now();
  const timelineSeries = Array.from({length: 8}, (_, idx) => {
    const hoursBack = 7 - idx;
    const bucketStart = nowMs - (hoursBack + 1) * 3600_000;
    const bucketEnd = nowMs - hoursBack * 3600_000;
    const label = new Date(bucketEnd).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
    const inBucket = events.filter((e) => {
      const t = new Date(e.timestamp).getTime();
      return t >= bucketStart && t <= bucketEnd;
    });
    return {
      bucket: label,
      total: inBucket.length,
      critical: inBucket.filter((e) => e.severity === 'critical').length,
      high: inBucket.filter((e) => e.severity === 'high').length,
    };
  });

  return {
    activeThreats: events.filter((e) => e.status !== 'false_positive').length,
    criticalAlerts: severityBreakdown.critical,
    attackedAssets: attackedAssetIds.size,
    suspiciousIps: uniqueIps.size,
    blockedIps,
    exfiltrationVolumeGb: Number((totalExfilBytes / (1024 * 1024 * 1024)).toFixed(2)),
    categoryBreakdown: (Object.keys(categoryLabels) as ThreatCategory[]).map((category) => ({
      category,
      label: categoryLabels[category],
      count: catCounts.get(category) ?? 0,
    })),
    severityBreakdown,
    geoRiskMatrix,
    timelineSeries,
    topAsns: Array.from(asnMap.values())
      .map((a) => ({
        asn: a.asn,
        asnName: a.asnName,
        events: a.count,
        avgRisk: Math.round(a.totalRisk / Math.max(1, a.count)),
      }))
      .sort((a, b) => b.events - a.events)
      .slice(0, 8),
    connectionTypeBreakdown: Array.from(connMap.entries()).map(([type, count]) => ({
      type,
      count,
    })),
    hasDemoData: events.some((e) => e.isDemoData) || assets.some((a) => a.isDemoData),
    generatedAt: new Date().toISOString(),
  };
}
