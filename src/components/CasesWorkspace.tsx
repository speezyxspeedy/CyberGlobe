import {useMemo, useState} from 'react';
import {
  CheckCircle2,
  Download,
  FileText,
  GitBranch,
  History,
  Plus,
  Printer,
  ShieldCheck,
  Upload,
} from 'lucide-react';
import {
  formatCategoryLabel,
  severityTextColor,
  useForensicsStore,
} from '../store/useForensicsStore';
import {buildRelationshipGraph, generateCaseMarkdownReport} from '../lib/caseLogic';
import type {CaseStatus, Severity} from '../types/forensics';

const NODE_COLORS: Record<string, string> = {
  ip: '#f97316',
  domain: '#a855f7',
  url: '#ec4899',
  user: '#f59e0b',
  device: '#06b6d4',
  alert: '#ef4444',
  case: '#10b981',
};

export function CasesWorkspace() {
  const cases = useForensicsStore((s) => s.cases);
  const events = useForensicsStore((s) => s.events);
  const assets = useForensicsStore((s) => s.assets);
  const auditLogs = useForensicsStore((s) => s.auditLogs);
  const activeCaseId = useForensicsStore((s) => s.activeCaseId);
  const setActiveCaseId = useForensicsStore((s) => s.setActiveCaseId);
  const createCase = useForensicsStore((s) => s.createCase);
  const updateCase = useForensicsStore((s) => s.updateCase);
  const addCaseNote = useForensicsStore((s) => s.addCaseNote);
  const uploadCaseEvidence = useForensicsStore((s) => s.uploadCaseEvidence);
  const setSelectedEntity = useForensicsStore((s) => s.setSelectedEntity);
  const setActiveTab = useForensicsStore((s) => s.setActiveTab);
  const userRole = useForensicsStore((s) => s.userRole);
  const userName = useForensicsStore((s) => s.userName);

  const [subTab, setSubTab] = useState<'overview' | 'graph' | 'evidence' | 'audit'>('overview');
  const [showNewCaseForm, setShowNewCaseForm] = useState(false);

  // New Case Form
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newPriority, setNewPriority] = useState<Severity>('high');
  const [newAnalyst, setNewAnalyst] = useState(userName);
  const [newTags, setNewTags] = useState('');

  // Note Form
  const [noteText, setNoteText] = useState('');

  // Evidence Upload Form
  const [evName, setEvName] = useState('');
  const [evSource, setEvSource] = useState('SIEM / Endpoint Triage');
  const [evContent, setEvContent] = useState('');
  const [evType, setEvType] = useState('text/plain');

  const selectedCase = cases.find((c) => c.id === activeCaseId) ?? cases[0] ?? null;

  const linkedEvents = useMemo(() => {
    if (!selectedCase) return [];
    return events.filter(
      (e) => selectedCase.linkedEventIds.includes(e.id) || e.caseId === selectedCase.id
    );
  }, [selectedCase, events]);

  const graphData = useMemo(() => {
    if (!selectedCase) return {nodes: [], edges: []};
    return buildRelationshipGraph(selectedCase, events, assets);
  }, [selectedCase, events, assets]);

  // Compute deterministic layered graph layout across 7 entity columns: IP -> Domain -> URL -> User -> Device -> Alert -> Case
  const graphLayout = useMemo(() => {
    const colOrder = ['ip', 'domain', 'url', 'alert', 'user', 'device', 'case'];
    const grouped = new Map<string, typeof graphData.nodes>();
    colOrder.forEach((k) => grouped.set(k, []));
    graphData.nodes.forEach((n) => {
      const bucket = grouped.get(n.kind) ?? [];
      bucket.push(n);
      grouped.set(n.kind, bucket);
    });
    const activeCols = colOrder.filter((k) => (grouped.get(k)?.length ?? 0) > 0);
    const width = 920;
    const height = 340;
    const positions = new Map<string, {x: number; y: number}>();
    activeCols.forEach((col, cIdx) => {
      const colNodes = grouped.get(col) ?? [];
      const x = activeCols.length === 1 ? width / 2 : 85 + (cIdx * (width - 170)) / Math.max(1, activeCols.length - 1);
      colNodes.forEach((n, nIdx) => {
        const y = colNodes.length === 1 ? height / 2 : 52 + (nIdx * (height - 104)) / Math.max(1, colNodes.length - 1);
        positions.set(n.id, {x, y});
      });
    });
    return {positions, width, height};
  }, [graphData]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim() || !newDesc.trim()) return;
    const created = await createCase({
      title: newTitle.trim(),
      description: newDesc.trim(),
      priority: newPriority,
      assignedAnalyst: newAnalyst.trim() || userName,
      tags: newTags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean)
        .slice(0, 10),
    });
    if (created) {
      setNewTitle('');
      setNewDesc('');
      setNewTags('');
      setShowNewCaseForm(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !noteText.trim()) return;
    await addCaseNote(selectedCase.id, noteText.trim());
    setNoteText('');
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setEvName(file.name);
    setEvType(file.type || 'text/plain');
    const reader = new FileReader();
    reader.onload = () => {
      setEvContent(typeof reader.result === 'string' ? reader.result : '');
    };
    reader.readAsText(file);
  };

  const handleUploadEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !evName.trim() || !evContent.trim()) return;
    await uploadCaseEvidence(selectedCase.id, {
      fileName: evName.trim(),
      fileType: evType,
      content: evContent,
      sourceSystem: evSource.trim() || 'Analyst Upload',
    });
    setEvName('');
    setEvContent('');
  };

  const handleExportMarkdown = () => {
    if (!selectedCase) return;
    const md = generateCaseMarkdownReport(selectedCase, linkedEvents);
    const blob = new Blob([md], {type: 'text/markdown'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedCase.id}-forensic-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportPdfPrint = () => {
    if (!selectedCase) return;
    window.print();
  };

  return (
    <div className="flex h-full w-full overflow-hidden bg-[#050811] text-slate-200">
      {/* Left Case List Column */}
      <aside className="flex w-80 shrink-0 flex-col border-r border-slate-800 bg-[#070B14]">
        <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
          <div>
            <h1 className="text-sm font-semibold text-white">Investigation Cases</h1>
            <p className="text-[11px] text-slate-400">{cases.length} active dossiers</p>
          </div>
          <button
            type="button"
            disabled={userRole === 'Viewer'}
            onClick={() => setShowNewCaseForm((v) => !v)}
            className="flex items-center gap-1 bg-cyan-500 px-2.5 py-1.5 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-40"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            <span>New Case</span>
          </button>
        </div>

        {showNewCaseForm && (
          <form onSubmit={handleCreateCase} className="space-y-2.5 border-b border-slate-800 bg-[#0B1221] p-3.5 text-xs">
            <div className="font-semibold text-cyan-300">Open New Forensic Case</div>
            <input
              type="text"
              required
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="Case title…"
              aria-label="Case title"
              className="w-full border border-slate-700 bg-[#070B14] px-2.5 py-1.5 text-xs text-white focus:border-cyan-400 focus:outline-none"
            />
            <textarea
              required
              rows={3}
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="Incident scope and initial findings…"
              aria-label="Case description"
              className="w-full border border-slate-700 bg-[#070B14] px-2.5 py-1.5 text-xs text-white focus:border-cyan-400 focus:outline-none"
            />
            <div className="grid grid-cols-2 gap-2">
              <select
                aria-label="Case priority"
                value={newPriority}
                onChange={(e) => setNewPriority(e.target.value as Severity)}
                className="border border-slate-700 bg-[#070B14] px-2 py-1.5 text-xs text-white"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <input
                type="text"
                value={newAnalyst}
                onChange={(e) => setNewAnalyst(e.target.value)}
                placeholder="Assigned analyst"
                aria-label="Assigned analyst"
                className="border border-slate-700 bg-[#070B14] px-2 py-1.5 text-xs text-white"
              />
            </div>
            <input
              type="text"
              value={newTags}
              onChange={(e) => setNewTags(e.target.value)}
              placeholder="Tags (comma-separated)"
              aria-label="Case tags"
              className="w-full border border-slate-700 bg-[#070B14] px-2.5 py-1.5 text-xs text-white"
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowNewCaseForm(false)}
                className="border border-slate-700 px-2.5 py-1 text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="bg-cyan-500 px-3 py-1 font-semibold text-slate-950 hover:bg-cyan-400"
              >
                Create Case
              </button>
            </div>
          </form>
        )}

        <div className="flex-1 divide-y divide-slate-800/80 overflow-y-auto">
          {cases.map((c) => {
            const active = selectedCase?.id === c.id;
            return (
              <button
                key={c.id}
                type="button"
                onClick={() => setActiveCaseId(c.id)}
                className={`w-full px-4 py-3 text-left transition-colors ${
                  active ? 'bg-cyan-500/10 text-white' : 'hover:bg-slate-900/60'
                }`}
              >
                <div className="flex items-center justify-between gap-2 font-mono text-[11px]">
                  <span className="text-cyan-300">{c.id}</span>
                  <span className={`uppercase font-semibold ${severityTextColor(c.priority)}`}>
                    {c.priority}
                  </span>
                </div>
                <div className="mt-1 line-clamp-2 text-xs font-medium text-slate-100">{c.title}</div>
                <div className="mt-1.5 flex items-center gap-2 text-[11px] text-slate-400">
                  <span className="capitalize">{c.status}</span>
                  <span>·</span>
                  <span>{c.linkedEventIds.length} events</span>
                  <span>·</span>
                  <span>{c.evidence.length} artifacts</span>
                </div>
              </button>
            );
          })}
        </div>
      </aside>

      {/* Main Case Detail Workspace */}
      <main className="flex-1 overflow-y-auto p-6">
        {!selectedCase ? (
          <div className="flex h-full items-center justify-center text-sm text-slate-500">
            Select or create an investigation case to begin.
          </div>
        ) : (
          <div className="mx-auto max-w-5xl space-y-6">
            {/* Case Header */}
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
              <div className="max-w-2xl">
                <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
                  <span className="text-cyan-400">{selectedCase.id}</span>
                  <span>·</span>
                  <span>Assigned: {selectedCase.assignedAnalyst}</span>
                  {selectedCase.isDemoData && (
                    <>
                      <span>·</span>
                      <span className="text-amber-300">DEMO DATA</span>
                    </>
                  )}
                </div>
                <h2 className="mt-1 text-xl font-bold text-white">{selectedCase.title}</h2>
                <p className="mt-2 text-sm leading-relaxed text-slate-300">{selectedCase.description}</p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <select
                  aria-label="Case lifecycle status"
                  disabled={userRole === 'Viewer'}
                  value={selectedCase.status}
                  onChange={(e) => void updateCase(selectedCase.id, {status: e.target.value as CaseStatus})}
                  className="border border-slate-700 bg-[#0B1221] px-2.5 py-1.5 text-xs font-medium text-white"
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="contained">Contained</option>
                  <option value="escalated">Escalated</option>
                  <option value="closed">Closed</option>
                </select>
                <button
                  type="button"
                  onClick={handleExportMarkdown}
                  className="flex items-center gap-1.5 border border-slate-700 bg-[#0B1221] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-cyan-400"
                >
                  <Download className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Export MD</span>
                </button>
                <button
                  type="button"
                  onClick={handleExportPdfPrint}
                  className="flex items-center gap-1.5 border border-slate-700 bg-[#0B1221] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-cyan-400"
                >
                  <Printer className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Export PDF</span>
                </button>
              </div>
            </div>

            {/* Sub-section Tabs */}
            <div className="flex items-center gap-1 border-b border-slate-800">
              {[
                {id: 'overview', label: 'Timeline & Notes', icon: FileText},
                {id: 'graph', label: 'Relationship Graph', icon: GitBranch},
                {id: 'evidence', label: `Chain of Custody (${selectedCase.evidence.length})`, icon: ShieldCheck},
                {id: 'audit', label: `Audit Trail (${auditLogs.length})`, icon: History},
              ].map(({id, label, icon: Icon}) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setSubTab(id as typeof subTab)}
                  className={`flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium transition-colors ${
                    subTab === id
                      ? 'border-b-2 border-cyan-400 text-cyan-300'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>{label}</span>
                </button>
              ))}
            </div>

            {/* OVERVIEW: LINKED INDICATORS + EVENT TIMELINE + NOTES */}
            {subTab === 'overview' && (
              <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
                <div className="space-y-6 lg:col-span-2">
                  {/* Event Timeline */}
                  <section>
                    <h3 className="text-xs font-semibold text-slate-400">
                      Correlated Event Timeline ({linkedEvents.length})
                    </h3>
                    <div className="mt-2.5 divide-y divide-slate-800 border border-slate-800 bg-[#080E1C]">
                      {linkedEvents.map((ev) => (
                        <div key={ev.id} className="flex items-start justify-between gap-4 p-3.5">
                          <div className="min-w-0">
                            <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400">
                              <span>{new Date(ev.timestamp).toLocaleString()}</span>
                              <span>·</span>
                              <span className={severityTextColor(ev.severity)}>
                                {ev.severity.toUpperCase()} ({ev.riskScore})
                              </span>
                            </div>
                            <button
                              type="button"
                              onClick={() => {
                                setSelectedEntity({kind: 'event', eventId: ev.id});
                                setActiveTab('globe');
                              }}
                              className="mt-1 text-left text-xs font-semibold text-white hover:text-cyan-300"
                            >
                              {ev.title}
                            </button>
                            <div className="mt-1 font-mono text-[11px] text-slate-400">
                              {ev.sourceIp} ({ev.sourceLocation.city} ±{ev.sourceLocation.accuracyRadiusKm} km) → {ev.targetAssetName}
                            </div>
                          </div>
                          <span className="font-mono text-[11px] text-cyan-300 shrink-0">
                            {formatCategoryLabel(ev.eventType)}
                          </span>
                        </div>
                      ))}
                      {linkedEvents.length === 0 && (
                        <div className="p-4 text-xs text-slate-500">
                          No events linked yet. Select any event on the 3D Globe to link it to this case.
                        </div>
                      )}
                    </div>
                  </section>

                  {/* Investigator Notes */}
                  <section>
                    <h3 className="text-xs font-semibold text-slate-400">Investigator Notes</h3>
                    <form onSubmit={handleAddNote} className="mt-2 flex gap-2">
                      <input
                        type="text"
                        disabled={userRole === 'Viewer'}
                        value={noteText}
                        onChange={(e) => setNoteText(e.target.value)}
                        placeholder="Record forensic observation, pivot hypothesis, or containment step…"
                        aria-label="Add investigator note"
                        className="flex-1 border border-slate-800 bg-[#080E1C] px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-cyan-400 focus:outline-none disabled:opacity-40"
                      />
                      <button
                        type="submit"
                        disabled={userRole === 'Viewer' || !noteText.trim()}
                        className="bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-40"
                      >
                        Add Note
                      </button>
                    </form>
                    <div className="mt-3 space-y-2.5">
                      {selectedCase.notes.map((n) => (
                        <div key={n.id} className="border border-slate-800 bg-[#080E1C] p-3.5">
                          <div className="flex items-center justify-between text-[11px] text-slate-400">
                            <span className="font-semibold text-cyan-300">{n.authorName}</span>
                            <span className="font-mono">{new Date(n.createdAt).toLocaleString()}</span>
                          </div>
                          <p className="mt-1.5 text-xs leading-relaxed text-slate-200">{n.content}</p>
                        </div>
                      ))}
                    </div>
                  </section>
                </div>

                {/* Right Indicator Summary */}
                <div className="space-y-4">
                  <div className="border border-slate-800 bg-[#080E1C] p-4 text-xs space-y-3">
                    <h3 className="font-semibold text-white">Linked Indicators</h3>
                    <div>
                      <div className="text-[11px] text-slate-500">IP Addresses</div>
                      <div className="mt-1 space-y-1 font-mono text-[11px] text-orange-300">
                        {selectedCase.linkedIps.length > 0 ? selectedCase.linkedIps.map((ip) => <div key={ip}>{ip}</div>) : 'None'}
                      </div>
                    </div>
                    <div>
                      <div className="text-[11px] text-slate-500">Domains</div>
                      <div className="mt-1 space-y-1 font-mono text-[11px] text-purple-300">
                        {selectedCase.linkedDomains.length > 0 ? selectedCase.linkedDomains.map((d) => <div key={d}>{d}</div>) : 'None'}
                      </div>
                    </div>
                    <div>
                      <div className="text-[11px] text-slate-500">SHA-256 Artifact Hashes</div>
                      <div className="mt-1 space-y-1 font-mono text-[10px] text-emerald-300 break-all">
                        {selectedCase.linkedHashes.length > 0 ? selectedCase.linkedHashes.map((h) => <div key={h}>{h}</div>) : 'None'}
                      </div>
                    </div>
                    <div>
                      <div className="text-[11px] text-slate-500">Users / Accounts</div>
                      <div className="mt-1 font-mono text-[11px] text-slate-300">
                        {selectedCase.linkedUsers.join(' · ') || 'None'}
                      </div>
                    </div>
                    <div>
                      <div className="text-[11px] text-slate-500">Tags</div>
                      <div className="mt-1 text-[11px] text-slate-400">
                        {selectedCase.tags.join(' · ') || 'No tags'}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* RELATIONSHIP GRAPH: IP -> DOMAIN -> URL -> USER -> DEVICE -> ALERT -> CASE */}
            {subTab === 'graph' && (
              <section className="border border-slate-800 bg-[#080E1C] p-4">
                <div className="flex flex-wrap items-center justify-between gap-2 pb-3">
                  <div>
                    <h3 className="text-sm font-semibold text-white">Entity Relationship Graph</h3>
                    <p className="text-xs text-slate-400">
                      Forensic correlation map: IP → Domain → URL → Alert → User / Device → Case
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400">
                    {Object.entries(NODE_COLORS).map(([kind, hex]) => (
                      <span key={kind} className="flex items-center gap-1 capitalize">
                        <span className="inline-block h-2.5 w-2.5" style={{backgroundColor: hex}} />
                        {kind}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="overflow-x-auto border border-slate-800 bg-[#050811]">
                  <svg
                    viewBox={`0 0 ${graphLayout.width} ${graphLayout.height}`}
                    className="h-[340px] w-full min-w-[700px]"
                    role="img"
                    aria-label="Forensic entity relationship graph"
                  >
                    {graphData.edges.map((edge, idx) => {
                      const src = graphLayout.positions.get(edge.source);
                      const dst = graphLayout.positions.get(edge.target);
                      if (!src || !dst) return null;
                      return (
                        <g key={`${edge.source}-${edge.target}-${idx}`}>
                          <line
                            x1={src.x}
                            y1={src.y}
                            x2={dst.x}
                            y2={dst.y}
                            stroke="#334155"
                            strokeWidth={1.5}
                          />
                        </g>
                      );
                    })}
                    {graphData.nodes.map((node) => {
                      const pos = graphLayout.positions.get(node.id);
                      if (!pos) return null;
                      const color = NODE_COLORS[node.kind] || '#06b6d4';
                      return (
                        <g key={node.id} transform={`translate(${pos.x}, ${pos.y})`}>
                          <rect
                            x={-68}
                            y={-18}
                            width={136}
                            height={36}
                            fill="#0B1221"
                            stroke={color}
                            strokeWidth={1.4}
                          />
                          <text
                            y={-3}
                            textAnchor="middle"
                            fill={color}
                            fontSize={9}
                            fontFamily="JetBrains Mono, monospace"
                          >
                            {node.kind.toUpperCase()}
                          </text>
                          <text
                            y={11}
                            textAnchor="middle"
                            fill="#f1f5f9"
                            fontSize={10}
                            fontFamily="Plus Jakarta Sans, sans-serif"
                          >
                            {node.label.length > 19 ? `${node.label.slice(0, 18)}…` : node.label}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                </div>
              </section>
            )}

            {/* EVIDENCE & CHAIN OF CUSTODY */}
            {subTab === 'evidence' && (
              <div className="space-y-6">
                <form
                  onSubmit={handleUploadEvidence}
                  className="space-y-3 border border-slate-800 bg-[#080E1C] p-4 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <h3 className="font-semibold text-white">Preserve New Evidence Artifact (SHA-256)</h3>
                    <label className="cursor-pointer border border-slate-700 bg-[#0B1221] px-3 py-1 text-cyan-300 hover:border-cyan-400">
                      <span className="flex items-center gap-1.5">
                        <Upload className="h-3.5 w-3.5" aria-hidden="true" />
                        Load File (log, csv, json, txt)
                      </span>
                      <input
                        type="file"
                        accept=".log,.txt,.csv,.json,.jsonl"
                        onChange={handleFileSelect}
                        className="sr-only"
                      />
                    </label>
                  </div>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <input
                      type="text"
                      required
                      disabled={userRole === 'Viewer'}
                      value={evName}
                      onChange={(e) => setEvName(e.target.value)}
                      placeholder="Artifact filename (e.g. ssh_triage.log)"
                      aria-label="Evidence filename"
                      className="border border-slate-700 bg-[#050811] px-2.5 py-2 text-xs text-white"
                    />
                    <input
                      type="text"
                      disabled={userRole === 'Viewer'}
                      value={evSource}
                      onChange={(e) => setEvSource(e.target.value)}
                      placeholder="Source system (e.g. Zeek Sensor)"
                      aria-label="Evidence source system"
                      className="border border-slate-700 bg-[#050811] px-2.5 py-2 text-xs text-white"
                    />
                  </div>
                  <textarea
                    rows={3}
                    required
                    disabled={userRole === 'Viewer'}
                    value={evContent}
                    onChange={(e) => setEvContent(e.target.value)}
                    placeholder="Paste log excerpt, PCAP metadata summary, or structured JSON artifact (full raw packet captures are excluded by policy)…"
                    aria-label="Evidence content"
                    className="w-full border border-slate-700 bg-[#050811] px-2.5 py-2 font-mono text-xs text-slate-200"
                  />
                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={userRole === 'Viewer'}
                      className="bg-cyan-500 px-4 py-1.5 font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-40"
                    >
                      Hash &amp; Preserve Evidence
                    </button>
                  </div>
                </form>

                <div className="overflow-x-auto border border-slate-800 bg-[#080E1C]">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-800 bg-[#0B1221] text-[11px] text-slate-400">
                      <tr>
                        <th className="px-3.5 py-2.5">Evidence ID &amp; File</th>
                        <th className="px-3.5 py-2.5">Collected By / Source</th>
                        <th className="px-3.5 py-2.5">SHA-256 Digest</th>
                        <th className="px-3.5 py-2.5 text-right">Size</th>
                        <th className="px-3.5 py-2.5">Integrity</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {selectedCase.evidence.map((ev) => (
                        <tr key={ev.id} className="hover:bg-slate-900/40">
                          <td className="px-3.5 py-3">
                            <div className="font-mono text-[11px] text-cyan-300">{ev.id}</div>
                            <div className="font-medium text-white">{ev.fileName}</div>
                            <div className="text-[10px] text-slate-500">{ev.fileType}</div>
                          </td>
                          <td className="px-3.5 py-3">
                            <div className="text-slate-200">{ev.collectedBy}</div>
                            <div className="text-[11px] text-slate-400">{ev.sourceSystem}</div>
                            <div className="font-mono text-[10px] text-slate-500">
                              {new Date(ev.collectedAt).toLocaleString()}
                            </div>
                          </td>
                          <td className="px-3.5 py-3 font-mono text-[10px] text-emerald-300 max-w-[220px] break-all">
                            {ev.sha256Hash}
                          </td>
                          <td className="px-3.5 py-3 text-right font-mono text-slate-300">
                            {(ev.fileSize / 1024).toFixed(1)} KB
                          </td>
                          <td className="px-3.5 py-3">
                            <span className="flex items-center gap-1 font-mono text-[11px] text-emerald-400">
                              <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                              {ev.integrityStatus.toUpperCase()}
                            </span>
                            <div className="mt-0.5 text-[10px] text-slate-500">
                              {ev.accessHistory.length} custody event(s)
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* IMMUTABLE AUDIT LOGS */}
            {subTab === 'audit' && (
              <div className="overflow-x-auto border border-slate-800 bg-[#080E1C]">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-800 bg-[#0B1221] text-[11px] text-slate-400">
                    <tr>
                      <th className="px-3.5 py-2.5">Timestamp</th>
                      <th className="px-3.5 py-2.5">Actor / Role</th>
                      <th className="px-3.5 py-2.5">Action</th>
                      <th className="px-3.5 py-2.5">Details</th>
                      <th className="px-3.5 py-2.5">Entry Hash</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {auditLogs.map((log) => (
                      <tr key={log.id}>
                        <td className="px-3.5 py-2.5 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="px-3.5 py-2.5">
                          <span className="text-slate-200">{log.actorName}</span>
                          <span className="ml-1.5 font-mono text-[10px] text-cyan-400">({log.role})</span>
                        </td>
                        <td className="px-3.5 py-2.5 font-mono text-[11px] text-amber-300">{log.action}</td>
                        <td className="px-3.5 py-2.5 text-slate-300">{log.details}</td>
                        <td className="px-3.5 py-2.5 font-mono text-[10px] text-slate-500">
                          {log.entryHash.slice(0, 16)}…
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
