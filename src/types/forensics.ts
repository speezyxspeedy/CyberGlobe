export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type ThreatCategory =
  | 'ssh_brute_force'
  | 'port_scan'
  | 'malware_c2'
  | 'data_exfiltration'
  | 'phishing'
  | 'ddos'
  | 'vpn_abuse'
  | 'anomalous_login';

export type EventReviewStatus =
  | 'new'
  | 'reviewed'
  | 'suspicious'
  | 'confirmed'
  | 'false_positive'
  | 'escalated';

export type ConnectionType =
  | 'residential'
  | 'mobile'
  | 'datacenter'
  | 'hosting'
  | 'vpn'
  | 'proxy'
  | 'tor';

export type AssetType =
  | 'web_server'
  | 'database'
  | 'api'
  | 'cloud_vm'
  | 'firewall'
  | 'email_server'
  | 'workstation';

export type CaseStatus = 'open' | 'investigating' | 'contained' | 'escalated' | 'closed';

export type UserRole = 'Viewer' | 'Analyst' | 'Admin';

export interface GeoPointApprox {
  country: string;
  countryCode: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  accuracyRadiusKm: number;
  disclaimer: string;
}

export interface RiskFactor {
  name: string;
  weight: number;
  contribution: number;
  detail: string;
}

export interface RiskAssessment {
  riskScore: number;
  riskLevel: Severity;
  confidence: number;
  reasons: string[];
  factors: RiskFactor[];
  evidenceRefs: string[];
  recommendedAction: string;
}

export interface IpIntelligence {
  ip: string;
  approxLocation: GeoPointApprox;
  asn: string;
  asnName: string;
  isp: string;
  organization: string;
  connectionType: ConnectionType;
  vpnProbability: number;
  proxyProbability: number;
  torExitNode: boolean;
  abuseConfidenceScore: number;
  abuseReportCount: number;
  attackCategories: string[];
  lastReportedAt: string;
  lastSeenAt: string;
  historicalEventCount: number;
  relatedEventIds: string[];
  relatedCaseIds: string[];
  riskScore: number;
  riskLevel: Severity;
  confidence: number;
  recommendedAction: string;
  blocked: boolean;
  dataSource: string;
  isDemoData: boolean;
  enrichedAt: string;
}

export interface ProtectedAsset {
  id: string;
  name: string;
  ipOrInternalId: string;
  maskedInternalIp?: string;
  locationLabel: string;
  country: string;
  countryCode: string;
  latitude: number;
  longitude: number;
  assetType: AssetType;
  criticality: Severity;
  openPorts: number[];
  associatedAlertCount: number;
  riskScore: number;
  isDemoData: boolean;
  ownerId?: string;
}

export interface ThreatEvent {
  id: string;
  eventType: ThreatCategory;
  sourceIp: string;
  destinationIp: string;
  maskedDestinationIp: string;
  targetAssetId: string;
  targetAssetName: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  sourceLocation: GeoPointApprox;
  destinationLocation: {
    country: string;
    countryCode: string;
    city: string;
    latitude: number;
    longitude: number;
  };
  timestamp: string;
  confidence: number;
  severity: Severity;
  riskScore: number;
  riskAssessment: RiskAssessment;
  title: string;
  description: string;
  status: EventReviewStatus;
  caseId: string | null;
  asn: string;
  isp: string;
  connectionType: ConnectionType;
  vpnProbability: number;
  abuseConfidence: number;
  isDemoData: boolean;
  dataSource: string;
  metadata: {
    attempts?: number;
    failureRate?: number;
    timeWindowSec?: number;
    targetUsername?: string;
    targetService?: string;
    portsScanned?: number;
    portsTargeted?: number[];
    scanIntensity?: 'low' | 'moderate' | 'aggressive' | 'burst';
    durationSec?: number;
    infectedEndpoint?: string;
    c2Domain?: string;
    callbackFrequencySec?: number;
    malwareFamily?: string;
    firstSeen?: string;
    lastSeen?: string;
    bytesTransferred?: number;
    possibleDataTypes?: string[];
    userAgent?: string;
    rawLogRef?: string;
    evidenceSha256?: string;
    ingestionSource?: string;
    action?: string;
    url?: string;
    domain?: string;
  };
}

export interface CaseNote {
  id: string;
  caseId: string;
  authorId: string;
  authorName: string;
  content: string;
  createdAt: string;
}

export interface EvidenceAccessLog {
  accessedBy: string;
  accessedAt: string;
  action: string;
}

export interface EvidenceFile {
  id: string;
  caseId: string;
  fileName: string;
  fileType: string;
  fileSize: number;
  sha256Hash: string;
  collectedBy: string;
  collectedAt: string;
  sourceSystem: string;
  integrityStatus: 'verified' | 'pending' | 'tampered';
  accessHistory: EvidenceAccessLog[];
  previewSnippet?: string;
  isDemoData?: boolean;
}

export interface InvestigationCase {
  id: string;
  title: string;
  description: string;
  priority: Severity;
  status: CaseStatus;
  assignedAnalyst: string;
  ownerId?: string;
  tags: string[];
  linkedEventIds: string[];
  linkedIps: string[];
  linkedDomains: string[];
  linkedHashes: string[];
  linkedAssetIds: string[];
  linkedUsers: string[];
  notes: CaseNote[];
  evidence: EvidenceFile[];
  createdAt: string;
  updatedAt: string;
  isDemoData: boolean;
}

export interface AuditLogEntry {
  id: string;
  actorId: string;
  actorName: string;
  role: UserRole;
  action: string;
  targetType: string;
  targetId: string;
  details: string;
  entryHash: string;
  timestamp: string;
}

export interface GeoRiskEntry {
  regionId: string;
  country: string;
  countryCode: string;
  topCity: string;
  latitude: number;
  longitude: number;
  attackVolume: number;
  uniqueAttackerIps: number;
  targetedAssets: number;
  blockedIps: number;
  avgRiskScore: number;
  criticalCount: number;
  riskTrend: 'rising' | 'stable' | 'declining';
  trendDeltaPct: number;
}

export interface GlobalStatistics {
  activeThreats: number;
  criticalAlerts: number;
  attackedAssets: number;
  suspiciousIps: number;
  blockedIps: number;
  exfiltrationVolumeGb: number;
  categoryBreakdown: Array<{category: ThreatCategory; label: string; count: number}>;
  severityBreakdown: Record<Severity, number>;
  geoRiskMatrix: GeoRiskEntry[];
  timelineSeries: Array<{bucket: string; total: number; critical: number; high: number}>;
  topAsns: Array<{asn: string; asnName: string; events: number; avgRisk: number}>;
  connectionTypeBreakdown: Array<{type: ConnectionType; count: number}>;
  hasDemoData: boolean;
  generatedAt: string;
}

export type LayerKey =
  | 'attackSources'
  | 'targetAssets'
  | 'attackArcs'
  | 'portScans'
  | 'bruteForce'
  | 'malwareC2'
  | 'dataExfiltration'
  | 'vpnProxyTor'
  | 'threatReputation'
  | 'globalHeatmap'
  | 'geoRiskMatrix';

export type LayerVisibility = Record<LayerKey, boolean>;

export interface FilterState {
  search: string;
  severities: Severity[];
  categories: ThreatCategory[];
  country: string;
  asn: string;
  protocol: string;
  minConfidence: number;
  timeRangeHours: number;
}

export interface ForensicAiResponse {
  summary: string;
  likelyAttackChain: string[];
  indicatorsOfCompromise: Array<{type: string; value: string; context: string; isDemoData: boolean}>;
  riskAssessment: string;
  evidenceGaps: string[];
  recommendedActions: string[];
  confidenceLevel: 'low' | 'medium' | 'high';
  verifiedEvidence: string[];
  correlationInferences: string[];
  demoDataNotice: string;
  sourcesUsed: string[];
  generatedAt: string;
}

export type WsMessageType =
  | 'threat_event_created'
  | 'threat_event_updated'
  | 'alert_created'
  | 'ip_intelligence_updated'
  | 'entity_position_update'
  | 'case_updated'
  | 'layer_refresh'
  | 'system_status';

export interface WsMessage<T = unknown> {
  type: WsMessageType;
  timestamp: string;
  payload: T;
}

export const APPROX_LOCATION_DISCLAIMER =
  'Approximate network location · Investigative lead only — not proof of a person’s physical location or identity.';
