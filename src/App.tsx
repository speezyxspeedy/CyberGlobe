import {useEffect} from 'react';
import {onAuthStateChanged} from 'firebase/auth';
import {auth} from './lib/firebase';
import {useForensicsStore} from './store/useForensicsStore';
import {ErrorBoundary} from './components/ErrorBoundary';
import {TopNavBar} from './components/TopNavBar';
import {CyberGlobe} from './components/CyberGlobe';
import {LeftControlSidebar} from './components/LeftControlSidebar';
import {KpiStrip} from './components/KpiStrip';
import {RightInspectorPanel} from './components/RightInspectorPanel';
import {BottomTimelineBar} from './components/BottomTimelineBar';
import {AddAssetModal} from './components/AddAssetModal';
import {CasesWorkspace} from './components/CasesWorkspace';
import {AnalyticsView} from './components/AnalyticsView';
import {LogIngestionView} from './components/LogIngestionView';
import {ForensicAnalystView} from './components/ForensicAnalystView';
import {GitHubCodeSecView} from './components/GitHubCodeSecView';
import type {WsMessage} from './types/forensics';

function CyberTraceWorkspace() {
  const activeTab = useForensicsStore((s) => s.activeTab);
  const bootstrapData = useForensicsStore((s) => s.bootstrapData);
  const handleWsMessage = useForensicsStore((s) => s.handleWsMessage);
  const setWsStatus = useForensicsStore((s) => s.setWsStatus);
  const setAuthUser = useForensicsStore((s) => s.setAuthUser);
  const toastMessage = useForensicsStore((s) => s.toastMessage);
  const clearToast = useForensicsStore((s) => s.clearToast);
  const error = useForensicsStore((s) => s.error);

  // Initial telemetry bootstrap
  useEffect(() => {
    void bootstrapData();
  }, [bootstrapData]);

  // Firebase Auth state synchronization
  useEffect(() => {
    const unsub = onAuthStateChanged(auth, (user) => {
      if (user) {
        setAuthUser(user.uid, user.displayName || user.email?.split('@')[0] || 'Investigator', user.email);
      } else {
        setAuthUser(null, null, null);
      }
    });
    return () => unsub();
  }, [setAuthUser]);

  // Real-time WebSocket client (/ws/live) with automatic backoff reconnect
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let disposed = false;

    const connect = () => {
      if (disposed) return;
      setWsStatus('connecting');
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${proto}//${window.location.host}/ws/live`;
      try {
        ws = new WebSocket(url);
      } catch {
        setWsStatus('disconnected');
        return;
      }

      ws.onopen = () => {
        if (!disposed) setWsStatus('connected');
      };

      ws.onmessage = (event) => {
        try {
          const parsed = JSON.parse(String(event.data)) as WsMessage;
          handleWsMessage(parsed);
        } catch {
          // Ignore malformed frame
        }
      };

      ws.onclose = () => {
        if (disposed) return;
        setWsStatus('disconnected');
        reconnectTimer = setTimeout(connect, 4000);
      };

      ws.onerror = () => {
        ws?.close();
      };
    };

    connect();
    return () => {
      disposed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [handleWsMessage, setWsStatus]);

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-[#050811] text-slate-100">
      <TopNavBar />

      {error && (
        <div className="z-30 flex items-center justify-between border-b border-red-500/40 bg-red-950/70 px-4 py-2 text-xs text-red-200">
          <span>{error}</span>
          <button
            type="button"
            onClick={() => void bootstrapData()}
            className="border border-red-400/50 px-2.5 py-0.5 text-[11px] font-medium hover:bg-red-500/20"
          >
            Retry
          </button>
        </div>
      )}

      <div className="relative flex-1 overflow-hidden">
        {/* Persistent 3D Globe Canvas Layer */}
        <div
          className={`absolute inset-0 ${activeTab === 'globe' ? 'visible opacity-100' : 'invisible pointer-events-none opacity-0'}`}
          aria-hidden={activeTab !== 'globe'}
        >
          <CyberGlobe />
          {activeTab === 'globe' && (
            <>
              <KpiStrip />
              <LeftControlSidebar />
              <RightInspectorPanel />
              <BottomTimelineBar />
            </>
          )}
        </div>

        {/* Secondary Dedicated Workspaces */}
        {activeTab === 'investigations' && <CasesWorkspace />}
        {activeTab === 'github' && <GitHubCodeSecView />}
        {activeTab === 'analytics' && <AnalyticsView />}
        {activeTab === 'ingestion' && <LogIngestionView />}
        {activeTab === 'analyst' && <ForensicAnalystView />}
      </div>

      <AddAssetModal />

      {/* Non-intrusive SOC Toast */}
      {toastMessage && (
        <div
          role="status"
          className="fixed bottom-16 left-1/2 z-50 flex -translate-x-1/2 items-center gap-3 border border-cyan-500/60 bg-[#070B14]/95 px-4 py-2 text-xs text-cyan-100 shadow-2xl"
        >
          <span>{toastMessage}</span>
          <button
            type="button"
            onClick={clearToast}
            aria-label="Dismiss notification"
            className="text-slate-400 hover:text-white"
          >
            ×
          </button>
        </div>
      )}
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <CyberTraceWorkspace />
    </ErrorBoundary>
  );
}
