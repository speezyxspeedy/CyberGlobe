import {create} from 'zustand';
import type {
  AuditLogEntry,
  EventReviewStatus,
  FilterState,
  GeoRiskEntry,
  GlobalStatistics,
  InvestigationCase,
  IpIntelligence,
  LayerKey,
  LayerVisibility,
  ProtectedAsset,
  Severity,
  ThreatCategory,
  ThreatEvent,
  UserRole,
  WsMessage,
  GitHubAuditEvent,
  GitHubConnectionStatus,
  GitHubDeveloperActivity,
  GitHubRepository,
  GitHubScanReport,
  GitHubSecretAlert,
  GitHubVulnerability,
  GitHubWorkflowRun,
} from '../types/forensics';
import {
  persistAssetToFirestore,
  persistAuditLogToFirestore,
  persistCaseNoteToFirestore,
  persistCaseToFirestore,
  persistEvidenceToFirestore,
} from '../lib/firebase';

export type ActiveWorkspaceTab = 'globe' | 'investigations' | 'analytics' | 'ingestion' | 'analyst' | 'github';

export type SelectedEntity =
  | {kind: 'event'; eventId: string}
  | {kind: 'ip'; ip: string}
  | {kind: 'asset'; assetId: string}
  | {kind: 'region'; regionId: string}
  | {kind: 'case'; caseId: string}
  | null;

export interface FlyToTarget {
  latitude: number;
  longitude: number;
  height?: number;
  label?: string;
  nonce: number;
}

export interface LiveAlertItem {
  id: string;
  eventId: string;
  severity: Severity;
  title: string;
  sourceIp: string;
  timestamp: string;
}

interface ForensicsStore {
  events: ThreatEvent[];
  assets: ProtectedAsset[];
  cases: InvestigationCase[];
  ipIntel: Record<string, IpIntelligence>;
  statistics: GlobalStatistics | null;
  auditLogs: AuditLogEntry[];
  liveAlerts: LiveAlertItem[];

  loading: boolean;
  error: string | null;
  wsStatus: 'connecting' | 'connected' | 'disconnected';
  toastMessage: string | null;

  activeTab: ActiveWorkspaceTab;
  selectedEntity: SelectedEntity;
  activeCaseId: string | null;
  flyToTarget: FlyToTarget | null;

  globeMode: '3D' | '2D';
  imageryMode: 'natural_earth' | 'dark_carto';
  leftSidebarOpen: boolean;
  alertFeedOpen: boolean;
  addAssetModalOpen: boolean;

  timelineMode: 'live' | 'replay';
  replayProgress: number; // 0..100
  isPlaying: boolean;
  playbackSpeed: 1 | 2 | 4;

  userRole: UserRole;
  userName: string;
  userUid: string | null;
  userEmail: string | null;

  layers: LayerVisibility;
  filters: FilterState;

  // Actions
  setActiveTab: (tab: ActiveWorkspaceTab) => void;
  setSelectedEntity: (entity: SelectedEntity) => void;
  setActiveCaseId: (id: string | null) => void;
  flyTo: (latitude: number, longitude: number, height?: number, label?: string) => void;
  setGlobeMode: (mode: '3D' | '2D') => void;
  setImageryMode: (mode: 'natural_earth' | 'dark_carto') => void;
  setLeftSidebarOpen: (open: boolean) => void;
  setAlertFeedOpen: (open: boolean) => void;
  setAddAssetModalOpen: (open: boolean) => void;
  setTimelineMode: (mode: 'live' | 'replay') => void;
  setReplayProgress: (pct: number) => void;
  setIsPlaying: (playing: boolean) => void;
  setPlaybackSpeed: (speed: 1 | 2 | 4) => void;
  setUserRole: (role: UserRole) => void;
  setAuthUser: (uid: string | null, name: string | null, email: string | null) => void;
  clearToast: () => void;

  toggleLayer: (layer: LayerKey) => void;
  setFilter: <K extends keyof FilterState>(key: K, value: FilterState[K]) => void;
  resetFilters: () => void;

  bootstrapData: () => Promise<void>;
  refreshStatistics: () => Promise<void>;
  fetchIpIntelligence: (ip: string) => Promise<IpIntelligence | null>;
  updateEventStatus: (eventId: string, status: EventReviewStatus, caseId?: string | null) => Promise<void>;
  toggleBlockIp: (ip: string, blocked: boolean) => Promise<void>;
  createAsset: (payload: Omit<ProtectedAsset, 'id' | 'associatedAlertCount' | 'riskScore' | 'isDemoData'>) => Promise<ProtectedAsset | null>;
  createCase: (payload: {
    title: string;
    description: string;
    priority: Severity;
    assignedAnalyst: string;
    tags: string[];
    linkedEventIds?: string[];
    linkedIps?: string[];
  }) => Promise<InvestigationCase | null>;
  updateCase: (caseId: string, updates: Partial<Pick<InvestigationCase, 'status' | 'priority' | 'assignedAnalyst' | 'tags'>>) => Promise<void>;
  addCaseNote: (caseId: string, content: string) => Promise<void>;
  uploadCaseEvidence: (caseId: string, payload: {fileName: string; fileType: string; content: string; sourceSystem: string}) => Promise<void>;
  ingestLogs: (rawLogs: string, format: string, source: string) => Promise<{ingestedCount: number; evidenceSha256: string; events: ThreatEvent[]} | null>;
  handleWsMessage: (msg: WsMessage) => void;
  setWsStatus: (status: 'connecting' | 'connected' | 'disconnected') => void;

  githubStatus: GitHubConnectionStatus | null;
  githubRepositories: GitHubRepository[];
  githubSecrets: GitHubSecretAlert[];
  githubVulnerabilities: GitHubVulnerability[];
  githubWorkflows: GitHubWorkflowRun[];
  githubDeveloperActivities: GitHubDeveloperActivity[];
  githubAuditEvents: GitHubAuditEvent[];
  githubScanReport: GitHubScanReport | null;
  githubLoading: boolean;

  fetchGitHubData: () => Promise<void>;
  triggerGitHubScan: () => Promise<GitHubScanReport | null>;
  linkRepoToAsset: (repoId: string, assetId: string) => Promise<void>;
  connectGitHub: (orgName?: string) => Promise<void>;
  disconnectGitHub: (deleteData?: boolean) => Promise<void>;
}

const DEFAULT_LAYERS: LayerVisibility = {
  attackSources: true,
  targetAssets: true,
  attackArcs: true,
  portScans: true,
  bruteForce: true,
  malwareC2: true,
  dataExfiltration: true,
  vpnProxyTor: true,
  threatReputation: false,
  globalHeatmap: true,
  geoRiskMatrix: false,
  githubRepos: true,
  exposedSecrets: true,
  supplyChain: true,
  developerActivity: true,
};

const DEFAULT_FILTERS: FilterState = {
  search: '',
  severities: ['low', 'medium', 'high', 'critical'],
  categories: [
    'ssh_brute_force',
    'port_scan',
    'malware_c2',
    'data_exfiltration',
    'phishing',
    'ddos',
    'vpn_abuse',
    'anomalous_login',
  ],
  country: '',
  asn: '',
  protocol: '',
  minConfidence: 0,
  timeRangeHours: 24,
};

export const useForensicsStore = create<ForensicsStore>((set, get) => {
  const authHeaders = () => ({
    'Content-Type': 'application/json',
    'x-user-role': get().userRole,
    'x-user-name': get().userName,
  });

  const showToast = (msg: string) => {
    set({toastMessage: msg});
    setTimeout(() => {
      if (get().toastMessage === msg) set({toastMessage: null});
    }, 4500);
  };

  return {
    events: [],
    assets: [],
    cases: [],
    ipIntel: {},
    statistics: null,
    auditLogs: [],
    liveAlerts: [],

    loading: true,
    error: null,
    wsStatus: 'connecting',
    toastMessage: null,

    githubStatus: null,
    githubRepositories: [],
    githubSecrets: [],
    githubVulnerabilities: [],
    githubWorkflows: [],
    githubDeveloperActivities: [],
    githubAuditEvents: [],
    githubScanReport: null,
    githubLoading: false,

    activeTab: 'globe',
    selectedEntity: null,
    activeCaseId: 'CASE-2026-012',
    flyToTarget: null,

    globeMode: '3D',
    imageryMode: 'natural_earth',
    leftSidebarOpen: true,
    alertFeedOpen: true,
    addAssetModalOpen: false,

    timelineMode: 'live',
    replayProgress: 100,
    isPlaying: false,
    playbackSpeed: 1,

    userRole: 'Analyst',
    userName: 'A. Kulkarni',
    userUid: null,
    userEmail: null,

    layers: {...DEFAULT_LAYERS},
    filters: {...DEFAULT_FILTERS},

    setActiveTab: (activeTab) => set({activeTab}),
    setSelectedEntity: (selectedEntity) => set({selectedEntity}),
    setActiveCaseId: (activeCaseId) => set({activeCaseId}),
    flyTo: (latitude, longitude, height = 3_800_000, label) =>
      set({flyToTarget: {latitude, longitude, height, label, nonce: Date.now()}}),
    setGlobeMode: (globeMode) => set({globeMode}),
    setImageryMode: (imageryMode) => set({imageryMode}),
    setLeftSidebarOpen: (leftSidebarOpen) => set({leftSidebarOpen}),
    setAlertFeedOpen: (alertFeedOpen) => set({alertFeedOpen}),
    setAddAssetModalOpen: (addAssetModalOpen) => set({addAssetModalOpen}),
    setTimelineMode: (timelineMode) =>
      set({
        timelineMode,
        replayProgress: timelineMode === 'live' ? 100 : 25,
        isPlaying: timelineMode === 'replay',
      }),
    setReplayProgress: (replayProgress) => set({replayProgress: Math.max(0, Math.min(100, replayProgress))}),
    setIsPlaying: (isPlaying) => set({isPlaying}),
    setPlaybackSpeed: (playbackSpeed) => set({playbackSpeed}),
    setUserRole: (userRole) => {
      set({userRole});
      showToast(`Active RBAC role switched to ${userRole}`);
    },
    setAuthUser: (userUid, name, userEmail) =>
      set((state) => ({
        userUid,
        userName: name || state.userName,
        userEmail,
        userRole: userEmail === 'gshubh349@gmail.com' ? 'Admin' : state.userRole,
      })),
    clearToast: () => set({toastMessage: null}),

    toggleLayer: (layer) =>
      set((state) => ({
        layers: {...state.layers, [layer]: !state.layers[layer]},
      })),

    setFilter: (key, value) =>
      set((state) => ({
        filters: {...state.filters, [key]: value},
      })),

    resetFilters: () => set({filters: {...DEFAULT_FILTERS}}),

    bootstrapData: async () => {
      set({loading: true, error: null});
      try {
        const [evRes, astRes, caseRes, statRes, audRes] = await Promise.all([
          fetch('/api/events'),
          fetch('/api/assets'),
          fetch('/api/cases'),
          fetch('/api/statistics/global'),
          fetch('/api/audit-logs'),
        ]);
        if (!evRes.ok || !astRes.ok || !caseRes.ok || !statRes.ok) {
          throw new Error('Failed to load telemetry from CyberTrace API');
        }
        const [evJson, astJson, caseJson, statJson, audJson] = await Promise.all([
          evRes.json(),
          astRes.json(),
          caseRes.json(),
          statRes.json(),
          audRes.ok ? audRes.json() : Promise.resolve({logs: []}),
        ]);

        const events: ThreatEvent[] = evJson.events ?? [];
        const cases: InvestigationCase[] = caseJson.cases ?? [];
        const liveAlerts: LiveAlertItem[] = events
          .filter((e) => e.severity === 'critical' || e.severity === 'high')
          .slice(0, 8)
          .map((e) => ({
            id: `alert-${e.id}`,
            eventId: e.id,
            severity: e.severity,
            title: e.title,
            sourceIp: e.sourceIp,
            timestamp: e.timestamp,
          }));

        set({
          events,
          assets: astJson.assets ?? [],
          cases,
          activeCaseId: cases[0]?.id ?? null,
          statistics: statJson,
          auditLogs: audJson.logs ?? [],
          liveAlerts,
          loading: false,
        });

        void get().fetchGitHubData();
      } catch (err) {
        set({
          loading: false,
          error: err instanceof Error ? err.message : 'Unable to connect to telemetry server',
        });
      }
    },

    refreshStatistics: async () => {
      try {
        const [statRes, audRes] = await Promise.all([
          fetch('/api/statistics/global'),
          fetch('/api/audit-logs'),
        ]);
        if (statRes.ok) {
          const statistics = await statRes.json();
          set({statistics});
        }
        if (audRes.ok) {
          const aud = await audRes.json();
          set({auditLogs: aud.logs ?? []});
        }
      } catch {
        // Ignore transient background refresh errors
      }
    },

    fetchIpIntelligence: async (ip: string) => {
      try {
        const res = await fetch(`/api/ip/${encodeURIComponent(ip)}/intelligence`);
        if (!res.ok) return null;
        const intel: IpIntelligence = await res.json();
        set((state) => ({
          ipIntel: {...state.ipIntel, [ip]: intel},
        }));
        return intel;
      } catch {
        return null;
      }
    },

    updateEventStatus: async (eventId, status, caseId) => {
      try {
        const res = await fetch(`/api/events/${encodeURIComponent(eventId)}`, {
          method: 'PATCH',
          headers: authHeaders(),
          body: JSON.stringify({status, ...(caseId !== undefined ? {caseId} : {})}),
        });
        const data = await res.json();
        if (!res.ok) {
          showToast(data.error || 'Unable to update event');
          return;
        }
        set((state) => ({
          events: state.events.map((e) => (e.id === eventId ? data : e)),
        }));
        showToast(`Event ${eventId} marked as ${status.replace('_', ' ')}`);
        void persistAuditLogToFirestore('EVENT_STATUS_UPDATED', 'threat_event', eventId, `Status set to ${status}`).catch(() => {});
        void get().refreshStatistics();
      } catch {
        showToast('Network error updating event status');
      }
    },

    toggleBlockIp: async (ip, blocked) => {
      try {
        const res = await fetch(`/api/ip/${encodeURIComponent(ip)}/block`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({blocked}),
        });
        const data = await res.json();
        if (!res.ok) {
          showToast(data.error || 'Unable to update IP block state');
          return;
        }
        set((state) => ({
          ipIntel: {...state.ipIntel, [ip]: data},
        }));
        showToast(blocked ? `Applied block policy for ${ip}` : `Removed block policy for ${ip}`);
        void persistAuditLogToFirestore(blocked ? 'IP_BLOCKED' : 'IP_UNBLOCKED', 'ip', ip, `Policy updated for ${ip}`).catch(() => {});
        void get().refreshStatistics();
      } catch {
        showToast('Network error updating IP block policy');
      }
    },

    createAsset: async (payload) => {
      try {
        const res = await fetch('/api/assets', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          showToast(data.error || 'Failed to register asset');
          return null;
        }
        set((state) => ({
          assets: state.assets.some((a) => a.id === data.id) ? state.assets : [...state.assets, data],
          addAssetModalOpen: false,
        }));
        showToast(`Registered protected asset "${data.name}"`);
        void persistAssetToFirestore(data).catch(() => {});
        void get().refreshStatistics();
        return data;
      } catch {
        showToast('Network error creating asset');
        return null;
      }
    },

    createCase: async (payload) => {
      try {
        const res = await fetch('/api/cases', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          showToast(data.error || 'Failed to create investigation case');
          return null;
        }
        set((state) => ({
          cases: state.cases.some((c) => c.id === data.id) ? state.cases : [data, ...state.cases],
          activeCaseId: data.id,
        }));
        showToast(`Created investigation case ${data.id}`);
        void persistCaseToFirestore(data).catch(() => {});
        void get().refreshStatistics();
        return data;
      } catch {
        showToast('Network error creating case');
        return null;
      }
    },

    updateCase: async (caseId, updates) => {
      try {
        const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}`, {
          method: 'PATCH',
          headers: authHeaders(),
          body: JSON.stringify(updates),
        });
        const data = await res.json();
        if (!res.ok) {
          showToast(data.error || 'Unable to update case');
          return;
        }
        set((state) => ({
          cases: state.cases.map((c) => (c.id === caseId ? data : c)),
        }));
        showToast(`Updated case ${caseId}`);
        void get().refreshStatistics();
      } catch {
        showToast('Network error updating case');
      }
    },

    addCaseNote: async (caseId, content) => {
      try {
        const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/notes`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({content, authorName: get().userName}),
        });
        const note = await res.json();
        if (!res.ok) {
          showToast(note.error || 'Failed to add note');
          return;
        }
        set((state) => ({
          cases: state.cases.map((c) =>
            c.id === caseId
              ? {...c, notes: c.notes.some((n) => n.id === note.id) ? c.notes : [note, ...c.notes]}
              : c
          ),
        }));
        showToast('Investigator note recorded');
        void persistCaseNoteToFirestore(caseId, note).catch(() => {});
        void get().refreshStatistics();
      } catch {
        showToast('Network error adding note');
      }
    },

    uploadCaseEvidence: async (caseId, payload) => {
      try {
        const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/evidence`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({...payload, collectedBy: get().userName}),
        });
        const ev = await res.json();
        if (!res.ok) {
          showToast(ev.error || 'Failed to preserve evidence');
          return;
        }
        set((state) => ({
          cases: state.cases.map((c) =>
            c.id === caseId
              ? {
                  ...c,
                  evidence: c.evidence.some((e) => e.id === ev.id) ? c.evidence : [ev, ...c.evidence],
                  linkedHashes: c.linkedHashes.includes(ev.sha256Hash)
                    ? c.linkedHashes
                    : [...c.linkedHashes, ev.sha256Hash],
                }
              : c
          ),
        }));
        showToast(`Evidence preserved with SHA-256 ${ev.sha256Hash.slice(0, 12)}…`);
        void persistEvidenceToFirestore(caseId, ev).catch(() => {});
        void get().refreshStatistics();
      } catch {
        showToast('Network error uploading evidence');
      }
    },

    ingestLogs: async (rawLogs, format, source) => {
      try {
        const res = await fetch('/api/logs/ingest', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({rawLogs, format, source}),
        });
        const data = await res.json();
        if (!res.ok) {
          showToast(data.error || 'Failed to ingest logs');
          return null;
        }
        const incomingEvents: ThreatEvent[] = data.events ?? [];
        set((state) => {
          const existingIds = new Set(state.events.map((e) => e.id));
          const merged = [...incomingEvents.filter((e) => !existingIds.has(e.id)), ...state.events];
          return {events: merged};
        });
        showToast(`Ingested ${data.ingestedCount} normalized threat events`);
        void get().refreshStatistics();
        return data;
      } catch {
        showToast('Network error during log ingestion');
        return null;
      }
    },

    handleWsMessage: (msg) => {
      const state = get();
      switch (msg.type) {
        case 'threat_event_created': {
          const ev = msg.payload as ThreatEvent;
          if (state.events.some((e) => e.id === ev.id)) return;
          set({events: [ev, ...state.events].slice(0, 100)});
          void state.refreshStatistics();
          break;
        }
        case 'threat_event_updated': {
          const ev = msg.payload as ThreatEvent;
          set({events: state.events.map((e) => (e.id === ev.id ? ev : e))});
          break;
        }
        case 'alert_created': {
          const alert = msg.payload as LiveAlertItem;
          if (state.liveAlerts.some((a) => a.id === alert.id)) return;
          set({liveAlerts: [alert, ...state.liveAlerts].slice(0, 15)});
          break;
        }
        case 'ip_intelligence_updated': {
          const intel = msg.payload as IpIntelligence;
          set({ipIntel: {...state.ipIntel, [intel.ip]: intel}});
          break;
        }
        case 'case_updated': {
          const updated = msg.payload as InvestigationCase;
          const exists = state.cases.some((c) => c.id === updated.id);
          set({
            cases: exists
              ? state.cases.map((c) => (c.id === updated.id ? updated : c))
              : [updated, ...state.cases],
          });
          break;
        }
        case 'layer_refresh': {
          const p = msg.payload as {layer?: string; asset?: ProtectedAsset};
          if (p.asset && !state.assets.some((a) => a.id === p.asset!.id)) {
            set({assets: [...state.assets, p.asset]});
          }
          break;
        }
        default:
          break;
      }
    },

    setWsStatus: (wsStatus) => set({wsStatus}),

    fetchGitHubData: async () => {
      try {
        set({ githubLoading: true });
        const [statRes, repoRes, secRes, vulnRes, wfRes, devRes, audRes] = await Promise.all([
          fetch('/api/github/connection/status'),
          fetch('/api/github/repositories'),
          fetch('/api/github/secrets'),
          fetch('/api/github/vulnerabilities'),
          fetch('/api/github/workflows'),
          fetch('/api/github/developer-activity'),
          fetch('/api/github/audit-events'),
        ]);

        const [status, repoData, secData, vulnData, wfData, devData, audData] = await Promise.all([
          statRes.ok ? statRes.json() : null,
          repoRes.ok ? repoRes.json() : { repositories: [] },
          secRes.ok ? secRes.json() : { secrets: [] },
          vulnRes.ok ? vulnRes.json() : { vulnerabilities: [] },
          wfRes.ok ? wfRes.json() : { workflows: [] },
          devRes.ok ? devRes.json() : { activities: [] },
          audRes.ok ? audRes.json() : { auditEvents: [] },
        ]);

        set({
          githubStatus: status,
          githubRepositories: repoData.repositories || [],
          githubSecrets: secData.secrets || [],
          githubVulnerabilities: vulnData.vulnerabilities || [],
          githubWorkflows: wfData.workflows || [],
          githubDeveloperActivities: devData.activities || [],
          githubAuditEvents: audData.auditEvents || [],
          githubLoading: false,
        });
      } catch {
        set({ githubLoading: false });
      }
    },

    triggerGitHubScan: async () => {
      try {
        set({ githubLoading: true });
        const res = await fetch('/api/github/scan', {
          method: 'POST',
          headers: authHeaders(),
        });
        if (!res.ok) {
          const err = await res.json();
          showToast(`GitHub Scan Failed: ${err.error || 'Server error'}`);
          set({ githubLoading: false });
          return null;
        }
        const data = await res.json();
        set({ githubScanReport: data.scanReport });
        await get().fetchGitHubData();
        showToast(`GitHub CodeSec Scan Complete. Risk Score: ${data.scanReport.overallOrgRiskScore}/100`);
        return data.scanReport;
      } catch {
        set({ githubLoading: false });
        return null;
      }
    },

    linkRepoToAsset: async (repoId: string, assetId: string) => {
      try {
        const res = await fetch(`/api/github/repositories/${encodeURIComponent(repoId)}/link-asset`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ assetId }),
        });
        if (res.ok) {
          await get().fetchGitHubData();
          showToast(`Linked repository ${repoId} to asset`);
        }
      } catch {
        showToast('Failed to link asset');
      }
    },

    connectGitHub: async (orgName = 'ApexCyber-Global-Org') => {
      try {
        const res = await fetch('/api/github/connect', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ organizationName: orgName }),
        });
        if (res.ok) {
          await get().fetchGitHubData();
          showToast(`Connected GitHub organization: ${orgName}`);
        }
      } catch {
        showToast('Failed to connect GitHub');
      }
    },

    disconnectGitHub: async (deleteData = false) => {
      try {
        const res = await fetch('/api/github/disconnect', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ deleteData }),
        });
        if (res.ok) {
          await get().fetchGitHubData();
          showToast('Disconnected GitHub organization');
        }
      } catch {
        showToast('Failed to disconnect GitHub');
      }
    },
  };
});

export function selectFilteredEvents(
  events: ThreatEvent[],
  filters: FilterState,
  layers: LayerVisibility,
  timelineMode: 'live' | 'replay',
  replayProgress: number
): ThreatEvent[] {
  const nowMs = Date.now();
  const minTimeMs = nowMs - filters.timeRangeHours * 3600_000;

  // Map category layer visibility
  const categoryAllowedByLayer = (cat: ThreatCategory): boolean => {
    if (cat === 'port_scan' && !layers.portScans) return false;
    if (cat === 'ssh_brute_force' && !layers.bruteForce) return false;
    if (cat === 'malware_c2' && !layers.malwareC2) return false;
    if (cat === 'data_exfiltration' && !layers.dataExfiltration) return false;
    if (cat === 'vpn_abuse' && !layers.vpnProxyTor) return false;
    return true;
  };

  let filtered = events.filter((e) => {
    if (!categoryAllowedByLayer(e.eventType)) return false;
    if (!filters.severities.includes(e.severity)) return false;
    if (!filters.categories.includes(e.eventType)) return false;
    if (e.confidence < filters.minConfidence) return false;
    const t = new Date(e.timestamp).getTime();
    if (t < minTimeMs) return false;
    if (
      filters.country &&
      !e.sourceLocation.country.toLowerCase().includes(filters.country.toLowerCase()) &&
      e.sourceLocation.countryCode.toLowerCase() !== filters.country.toLowerCase()
    ) {
      return false;
    }
    if (filters.asn && !e.asn.toLowerCase().includes(filters.asn.toLowerCase())) return false;
    if (filters.protocol && !e.protocol.toLowerCase().includes(filters.protocol.toLowerCase())) return false;
    if (filters.search.trim()) {
      const q = filters.search.trim().toLowerCase();
      const match =
        e.sourceIp.toLowerCase().includes(q) ||
        e.title.toLowerCase().includes(q) ||
        e.sourceLocation.city.toLowerCase().includes(q) ||
        e.sourceLocation.country.toLowerCase().includes(q) ||
        e.asn.toLowerCase().includes(q) ||
        e.isp.toLowerCase().includes(q) ||
        e.targetAssetName.toLowerCase().includes(q) ||
        e.eventType.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  if (timelineMode === 'replay' && filtered.length > 0) {
    const sortedAsc = [...filtered].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
    const cutoffCount = Math.max(1, Math.ceil((replayProgress / 100) * sortedAsc.length));
    filtered = sortedAsc.slice(0, cutoffCount).reverse();
  }

  return filtered;
}

export function formatCategoryLabel(cat: ThreatCategory): string {
  const map: Record<ThreatCategory, string> = {
    ssh_brute_force: 'Brute Force',
    port_scan: 'Port Scan',
    malware_c2: 'Malware C2',
    data_exfiltration: 'Data Exfiltration',
    phishing: 'Phishing',
    ddos: 'DDoS',
    vpn_abuse: 'VPN / Proxy Abuse',
    anomalous_login: 'Anomalous Login',
  };
  return map[cat];
}

export function severityTextColor(sev: Severity): string {
  switch (sev) {
    case 'critical':
      return 'text-red-400';
    case 'high':
      return 'text-orange-400';
    case 'medium':
      return 'text-amber-300';
    case 'low':
      return 'text-emerald-400';
  }
}

export function severityHex(sev: Severity): string {
  switch (sev) {
    case 'critical':
      return '#ef4444';
    case 'high':
      return '#f97316';
    case 'medium':
      return '#f59e0b';
    case 'low':
      return '#10b981';
  }
}

export type RegionLookup = GeoRiskEntry;
