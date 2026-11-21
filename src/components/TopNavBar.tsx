import {useState} from 'react';
import {
  Activity,
  BarChart3,
  Briefcase,
  FileUp,
  GitBranch,
  Globe,
  LogIn,
  LogOut,
  Search,
  ShieldAlert,
  Sparkles,
  UserCheck,
} from 'lucide-react';
import {useForensicsStore, type ActiveWorkspaceTab} from '../store/useForensicsStore';
import {signInWithGoogle, signOutUser} from '../lib/firebase';
import type {UserRole} from '../types/forensics';

const NAV_TABS: Array<{id: ActiveWorkspaceTab; label: string; icon: typeof Globe}> = [
  {id: 'globe', label: 'Globe', icon: Globe},
  {id: 'investigations', label: 'Cases', icon: Briefcase},
  {id: 'github', label: 'CodeSec', icon: GitBranch},
  {id: 'analytics', label: 'Analytics', icon: BarChart3},
  {id: 'ingestion', label: 'Log Ingest', icon: FileUp},
  {id: 'analyst', label: 'Forensic AI', icon: Sparkles},
];

export function TopNavBar() {
  const activeTab = useForensicsStore((s) => s.activeTab);
  const setActiveTab = useForensicsStore((s) => s.setActiveTab);
  const filters = useForensicsStore((s) => s.filters);
  const setFilter = useForensicsStore((s) => s.setFilter);
  const events = useForensicsStore((s) => s.events);
  const assets = useForensicsStore((s) => s.assets);
  const statistics = useForensicsStore((s) => s.statistics);
  const wsStatus = useForensicsStore((s) => s.wsStatus);
  const userRole = useForensicsStore((s) => s.userRole);
  const setUserRole = useForensicsStore((s) => s.setUserRole);
  const userName = useForensicsStore((s) => s.userName);
  const userUid = useForensicsStore((s) => s.userUid);
  const flyTo = useForensicsStore((s) => s.flyTo);
  const setSelectedEntity = useForensicsStore((s) => s.setSelectedEntity);
  const fetchIpIntelligence = useForensicsStore((s) => s.fetchIpIntelligence);
  const alertFeedOpen = useForensicsStore((s) => s.alertFeedOpen);
  const setAlertFeedOpen = useForensicsStore((s) => s.setAlertFeedOpen);

  const [authBusy, setAuthBusy] = useState(false);

  const handleGlobalSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const q = filters.search.trim().toLowerCase();
    if (!q) return;

    const matchedEvent = events.find(
      (ev) =>
        ev.sourceIp.toLowerCase().includes(q) ||
        ev.sourceLocation.city.toLowerCase().includes(q) ||
        ev.sourceLocation.country.toLowerCase().includes(q) ||
        ev.asn.toLowerCase().includes(q) ||
        ev.id.toLowerCase().includes(q) ||
        ev.title.toLowerCase().includes(q)
    );
    if (matchedEvent) {
      setActiveTab('globe');
      setSelectedEntity({kind: 'event', eventId: matchedEvent.id});
      void fetchIpIntelligence(matchedEvent.sourceIp);
      flyTo(
        matchedEvent.sourceLocation.latitude,
        matchedEvent.sourceLocation.longitude,
        2_800_000,
        matchedEvent.sourceIp
      );
      return;
    }

    const matchedAsset = assets.find(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.locationLabel.toLowerCase().includes(q) ||
        a.ipOrInternalId.toLowerCase().includes(q)
    );
    if (matchedAsset) {
      setActiveTab('globe');
      setSelectedEntity({kind: 'asset', assetId: matchedAsset.id});
      flyTo(matchedAsset.latitude, matchedAsset.longitude, 2_400_000, matchedAsset.name);
    }
  };

  const handleSignIn = async () => {
    setAuthBusy(true);
    try {
      await signInWithGoogle();
    } catch {
      // Popup canceled or blocked in sandbox
    } finally {
      setAuthBusy(false);
    }
  };

  const handleSignOut = async () => {
    setAuthBusy(true);
    try {
      await signOutUser();
    } finally {
      setAuthBusy(false);
    }
  };

  const criticalCount = statistics?.criticalAlerts ?? 0;

  return (
    <header className="z-30 flex h-14 w-full shrink-0 items-center justify-between gap-4 border-b border-slate-800/90 bg-[#070B14]/95 px-4">
      {/* Zone 1: Brand + Mandatory DEMO DATA indicator */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          type="button"
          onClick={() => setActiveTab('globe')}
          className="flex items-center gap-2 text-left text-base font-bold tracking-tight text-white whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
        >
          <ShieldAlert className="h-5 w-5 text-cyan-400" aria-hidden="true" />
          <span>CyberTrace Globe</span>
        </button>

        {statistics?.hasDemoData && (
          <span
            className="border border-amber-500/50 bg-amber-500/15 px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wider text-amber-300 whitespace-nowrap shrink-0"
            data-testid="demo-data-badge"
          >
            DEMO DATA
          </span>
        )}
      </div>

      {/* Zone 2: Primary workspace navigation + global fly-to search */}
      <div className="flex min-w-0 flex-1 items-center justify-center gap-4">
        <nav aria-label="Primary Workspace" className="flex items-center gap-1 overflow-x-auto">
          {NAV_TABS.map(({id, label, icon: Icon}) => {
            const active = activeTab === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => setActiveTab(id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 ${
                  active
                    ? 'border-b-2 border-cyan-400 text-cyan-300'
                    : 'text-slate-400 hover:text-slate-100'
                }`}
              >
                <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                <span>{label}</span>
              </button>
            );
          })}
        </nav>

        <form onSubmit={handleGlobalSearchSubmit} className="hidden lg:flex relative w-64 xl:w-80 shrink-0">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" aria-hidden="true" />
          <input
            type="search"
            value={filters.search}
            onChange={(e) => setFilter('search', e.target.value)}
            placeholder="Search IP, city, ASN, asset & Enter…"
            aria-label="Global threat search"
            className="w-full border border-slate-800 bg-[#0B1221] py-1.5 pl-8 pr-3 text-xs text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
          />
        </form>
      </div>

      {/* Zone 3: Live stream status, alert toggle, RBAC role & account */}
      <div className="flex items-center gap-3 shrink-0">
        <div
          className="hidden sm:flex items-center gap-1.5 font-mono text-[11px] text-slate-300 whitespace-nowrap"
          title="Live WebSocket stream status"
        >
          <span
            className={`inline-block h-2 w-2 rounded-full ${
              wsStatus === 'connected'
                ? 'bg-emerald-400'
                : wsStatus === 'connecting'
                  ? 'bg-amber-400'
                  : 'bg-red-500'
            }`}
          />
          <span>{wsStatus === 'connected' ? 'LIVE' : wsStatus.toUpperCase()}</span>
        </div>

        <button
          type="button"
          onClick={() => {
            setActiveTab('globe');
            setAlertFeedOpen(!alertFeedOpen);
          }}
          aria-label="Toggle critical alerts feed"
          className="flex items-center gap-1.5 border border-slate-800 bg-[#0B1221] px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:border-red-500/60 hover:text-white whitespace-nowrap shrink-0"
        >
          <Activity className="h-3.5 w-3.5 text-red-400" aria-hidden="true" />
          <span className="font-mono text-red-300">{criticalCount}</span>
          <span className="hidden md:inline text-slate-400">Critical</span>
        </button>

        <label className="hidden md:flex items-center gap-1.5 text-xs text-slate-400">
          <span className="sr-only">RBAC Role</span>
          <UserCheck className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
          <select
            aria-label="Select RBAC role"
            value={userRole}
            onChange={(e) => setUserRole(e.target.value as UserRole)}
            className="border border-slate-800 bg-[#0B1221] px-2 py-1 text-xs font-medium text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            <option value="Viewer">Viewer</option>
            <option value="Analyst">Analyst</option>
            <option value="Admin">Admin</option>
          </select>
        </label>

        {userUid ? (
          <button
            type="button"
            onClick={handleSignOut}
            disabled={authBusy}
            className="flex items-center gap-1.5 border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 whitespace-nowrap shrink-0"
            title={`Signed in as ${userName}`}
          >
            <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
            <span className="hidden sm:inline max-w-[90px] truncate">{userName}</span>
          </button>
        ) : (
          <button
            type="button"
            onClick={handleSignIn}
            disabled={authBusy}
            className="flex items-center gap-1.5 bg-cyan-500 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-cyan-400 transition-colors whitespace-nowrap shrink-0"
          >
            <LogIn className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Sign In</span>
          </button>
        )}
      </div>
    </header>
  );
}
