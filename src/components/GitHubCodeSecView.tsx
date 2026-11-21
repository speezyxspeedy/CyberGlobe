import { useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ExternalLink,
  GitBranch,
  Github,
  GitPullRequest,
  Globe,
  Key,
  Layers,
  Lock,
  Package,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trash2,
  Unlink,
  User,
  Users,
} from 'lucide-react';
import { useForensicsStore } from '../store/useForensicsStore';
import type { GitHubRepository, GitHubSecretAlert, GitHubVulnerability, GitHubDeveloperActivity, Severity } from '../types/forensics';

type CodeSecSubTab = 'repos' | 'secrets' | 'supply_chain' | 'developer' | 'audit' | 'copilot';

export function GitHubCodeSecView() {
  const [subTab, setSubTab] = useState<CodeSecSubTab>('repos');
  const [searchFilter, setSearchFilter] = useState('');
  const [linkingRepoId, setLinkingRepoId] = useState<string | null>(null);
  const [selectedAssetId, setSelectedAssetId] = useState<string>('');
  const [copilotQuestion, setCopilotQuestion] = useState('');
  const [copilotLoading, setCopilotLoading] = useState(false);
  const [copilotResponse, setCopilotResponse] = useState<string | null>(null);

  const githubStatus = useForensicsStore((s) => s.githubStatus);
  const githubRepositories = useForensicsStore((s) => s.githubRepositories);
  const githubSecrets = useForensicsStore((s) => s.githubSecrets);
  const githubVulnerabilities = useForensicsStore((s) => s.githubVulnerabilities);
  const githubWorkflows = useForensicsStore((s) => s.githubWorkflows);
  const githubDeveloperActivities = useForensicsStore((s) => s.githubDeveloperActivities);
  const githubAuditEvents = useForensicsStore((s) => s.githubAuditEvents);
  const githubScanReport = useForensicsStore((s) => s.githubScanReport);
  const githubLoading = useForensicsStore((s) => s.githubLoading);
  const triggerGitHubScan = useForensicsStore((s) => s.triggerGitHubScan);
  const linkRepoToAsset = useForensicsStore((s) => s.linkRepoToAsset);
  const disconnectGitHub = useForensicsStore((s) => s.disconnectGitHub);
  const connectGitHub = useForensicsStore((s) => s.connectGitHub);
  const assets = useForensicsStore((s) => s.assets);
  const flyTo = useForensicsStore((s) => s.flyTo);
  const setActiveTab = useForensicsStore((s) => s.setActiveTab);

  const handleScanClick = async () => {
    await triggerGitHubScan();
  };

  const handleLinkSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!linkingRepoId) return;
    await linkRepoToAsset(linkingRepoId, selectedAssetId);
    setLinkingRepoId(null);
    setSelectedAssetId('');
  };

  const handleAskCopilot = async (promptText: string) => {
    const q = promptText.trim();
    if (!q) return;
    setCopilotLoading(true);
    setCopilotResponse(null);
    try {
      const res = await fetch('/api/analysis/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question: q,
          message: q,
          filters: { githubSecQuery: true },
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setCopilotResponse(data.reply || 'No analysis available.');
      } else {
        const err = await res.json();
        setCopilotResponse(`Analysis error: ${err.error || 'Server error'}`);
      }
    } catch (err: any) {
      setCopilotResponse(`Network error: ${err?.message || 'Unable to connect to AI server'}`);
    } finally {
      setCopilotLoading(false);
    }
  };

  const filteredRepos = githubRepositories.filter((r) =>
    r.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
    r.language.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <div className="flex h-full w-full flex-col overflow-y-auto bg-[#050811] text-slate-100 p-4 lg:p-6 space-y-6">
      {/* 1. Header & Organization Connection Bar */}
      <div className="border border-slate-800 bg-[#070B14] p-4 lg:p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center border border-slate-700 bg-slate-900/80">
              <Github className="h-6 w-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-white tracking-wide">
                  {githubStatus?.orgName || 'ApexCyber-Global-Org'}
                </h1>
                <span className="border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-400">
                  {githubStatus?.connected ? 'Connected (GitHub App)' : 'Disconnected'}
                </span>
                <span className="border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-400">
                  DEMO DATA
                </span>
              </div>
              <p className="mt-1 text-xs text-slate-400">
                Installation ID: <span className="font-mono text-cyan-300">{githubStatus?.installationId || 'gh-inst-49210492'}</span> · Storage:{' '}
                <span className="font-mono text-slate-300">{githubStatus?.tokenStorageMode || 'encrypted_at_rest_aes_256_gcm'}</span> · Retention:{' '}
                <span className="font-mono text-slate-300">{githubStatus?.retentionPolicyDays || 90} days</span>
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleScanClick}
              disabled={githubLoading}
              className="flex items-center gap-1.5 border border-cyan-500/80 bg-cyan-500/20 px-3 py-1.5 text-xs font-semibold text-cyan-100 hover:bg-cyan-500/30 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${githubLoading ? 'animate-spin' : ''}`} />
              <span>{githubLoading ? 'Scanning CodeSec...' : 'Trigger Security Scan'}</span>
            </button>

            {githubStatus?.connected ? (
              <button
                type="button"
                onClick={() => disconnectGitHub(false)}
                className="flex items-center gap-1.5 border border-slate-700 bg-slate-900/60 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-red-500/60 hover:text-red-300 transition-colors"
              >
                <Unlink className="h-3.5 w-3.5" />
                <span>Disconnect</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={() => connectGitHub()}
                className="flex items-center gap-1.5 border border-emerald-500/60 bg-emerald-500/20 px-3 py-1.5 text-xs font-semibold text-emerald-100 hover:bg-emerald-500/30 transition-colors"
              >
                <ShieldCheck className="h-3.5 w-3.5" />
                <span>Connect GitHub</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => disconnectGitHub(true)}
              className="flex items-center gap-1.5 border border-red-500/40 bg-red-950/30 px-3 py-1.5 text-xs font-medium text-red-300 hover:bg-red-900/40 transition-colors"
            >
              <Trash2 className="h-3.5 w-3.5" />
              <span>Revoke &amp; Delete Data</span>
            </button>
          </div>
        </div>

        {/* Security & Data Governance Notice */}
        <div className="mt-4 border-t border-slate-800/80 pt-3 flex flex-wrap items-center justify-between text-[11px] text-slate-400 gap-2">
          <div className="flex items-center gap-1.5 text-slate-300">
            <Lock className="h-3.5 w-3.5 text-cyan-400" />
            <span>Least-Privilege Scopes: read-only access to contents, actions, security_events, dependabot, and secret_scanning.</span>
          </div>
          <div className="flex items-center gap-1.5 text-amber-300/90 font-mono text-[10px]">
            <span>⚠️ Zero Password Storage · Ephemeral Telemetry Index · Secrets Masked at Ingestion</span>
          </div>
        </div>
      </div>

      {/* 2. CodeSec KPI Summary Strip */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="border border-slate-800 bg-[#070B14] p-3.5">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Monitored Repos</div>
          <div className="mt-1 text-2xl font-bold font-mono text-white">{githubRepositories.length}</div>
          <div className="mt-1 text-[10px] text-cyan-400">All 6 repositories protected</div>
        </div>

        <div className="border border-red-900/50 bg-red-950/20 p-3.5">
          <div className="text-[11px] font-medium text-red-300 uppercase tracking-wider flex items-center gap-1">
            <Key className="h-3 w-3" />
            <span>Exposed Secrets</span>
          </div>
          <div className="mt-1 text-2xl font-bold font-mono text-red-400">{githubSecrets.length}</div>
          <div className="mt-1 text-[10px] text-red-300/80">1 Leaked AWS Key (Masked)</div>
        </div>

        <div className="border border-orange-900/50 bg-orange-950/20 p-3.5">
          <div className="text-[11px] font-medium text-orange-300 uppercase tracking-wider flex items-center gap-1">
            <Package className="h-3 w-3" />
            <span>Supply-Chain CVEs</span>
          </div>
          <div className="mt-1 text-2xl font-bold font-mono text-orange-400">{githubVulnerabilities.length}</div>
          <div className="mt-1 text-[10px] text-orange-300/80">CVE-2022-23529 (Critical RCE)</div>
        </div>

        <div className="border border-yellow-900/50 bg-yellow-950/20 p-3.5">
          <div className="text-[11px] font-medium text-yellow-300 uppercase tracking-wider flex items-center gap-1">
            <User className="h-3 w-3" />
            <span>Developer Anomalies</span>
          </div>
          <div className="mt-1 text-2xl font-bold font-mono text-yellow-400">{githubDeveloperActivities.length}</div>
          <div className="mt-1 text-[10px] text-yellow-300/80">Off-hours commit &amp; force push</div>
        </div>

        <div className="border border-red-900/60 bg-[#070B14] p-3.5">
          <div className="text-[11px] font-medium text-slate-300 uppercase tracking-wider">Org Risk Index</div>
          <div className="mt-1 text-2xl font-bold font-mono text-red-400">
            {githubScanReport?.overallOrgRiskScore || 84}<span className="text-xs text-slate-500 font-normal">/100</span>
          </div>
          <div className="mt-1 text-[10px] text-red-400 font-semibold uppercase">CRITICAL POSTURE</div>
        </div>
      </div>

      {/* 3. Sub-Tab Navigation Bar */}
      <div className="flex border-b border-slate-800 bg-[#070B14]/60">
        <button
          type="button"
          onClick={() => setSubTab('repos')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            subTab === 'repos'
              ? 'border-cyan-400 text-cyan-200 bg-cyan-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitBranch className="h-3.5 w-3.5" />
          <span>Repositories &amp; Risk ({githubRepositories.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('secrets')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            subTab === 'secrets'
              ? 'border-red-400 text-red-200 bg-red-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Key className="h-3.5 w-3.5 text-red-400" />
          <span>Secret Scanning ({githubSecrets.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('supply_chain')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            subTab === 'supply_chain'
              ? 'border-orange-400 text-orange-200 bg-orange-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Package className="h-3.5 w-3.5 text-orange-400" />
          <span>Supply Chain &amp; CVEs ({githubVulnerabilities.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('developer')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            subTab === 'developer'
              ? 'border-yellow-400 text-yellow-200 bg-yellow-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <User className="h-3.5 w-3.5 text-yellow-400" />
          <span>Developer Anomalies ({githubDeveloperActivities.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('audit')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            subTab === 'audit'
              ? 'border-cyan-400 text-cyan-200 bg-cyan-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="h-3.5 w-3.5" />
          <span>Audit Logs ({githubAuditEvents.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setSubTab('copilot')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
            subTab === 'copilot'
              ? 'border-purple-400 text-purple-200 bg-purple-500/10'
              : 'border-transparent text-purple-400 hover:text-purple-200'
          }`}
        >
          <Sparkles className="h-3.5 w-3.5 text-purple-400" />
          <span>Gemini CodeSec Copilot</span>
        </button>
      </div>

      {/* 4. Sub-Tab Content Views */}

      {/* SUB-TAB A: Repositories & Risk Scores */}
      {subTab === 'repos' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="relative w-72">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                placeholder="Filter repositories..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="w-full border border-slate-800 bg-[#070B14] pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <div className="text-xs text-slate-400">
              Showing <span className="text-cyan-400 font-mono">{filteredRepos.length}</span> connected repositories
            </div>
          </div>

          <div className="border border-slate-800 bg-[#070B14] overflow-hidden">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-[#0B1221] text-[11px] uppercase tracking-wider text-slate-400">
                  <th className="p-3">Repository</th>
                  <th className="p-3">Language</th>
                  <th className="p-3">Risk Score</th>
                  <th className="p-3">Exposed Secrets</th>
                  <th className="p-3">CVEs</th>
                  <th className="p-3">Branch Protection</th>
                  <th className="p-3">Blast Radius</th>
                  <th className="p-3">Linked Cloud Asset</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                {filteredRepos.map((repo) => {
                  const isCrit = repo.riskScore >= 80;
                  const isHigh = repo.riskScore >= 60;
                  return (
                    <tr key={repo.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="p-3 font-sans font-semibold text-white">
                        <div className="flex items-center gap-1.5">
                          <GitBranch className="h-3.5 w-3.5 text-slate-400" />
                          <span>{repo.name}</span>
                          <span className="border border-slate-700 px-1 py-0.2 text-[9px] text-slate-400 uppercase">
                            {repo.visibility}
                          </span>
                        </div>
                      </td>
                      <td className="p-3 text-slate-300 font-sans">{repo.language}</td>
                      <td className="p-3">
                        <span
                          className={`px-2 py-0.5 font-bold ${
                            isCrit
                              ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                              : isHigh
                              ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
                              : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          }`}
                        >
                          {repo.riskScore}/100
                        </span>
                      </td>
                      <td className="p-3">
                        {repo.exposedSecretCount > 0 ? (
                          <span className="text-red-400 font-bold flex items-center gap-1">
                            <AlertOctagon className="h-3 w-3" />
                            {repo.exposedSecretCount} leaked
                          </span>
                        ) : (
                          <span className="text-slate-500">0</span>
                        )}
                      </td>
                      <td className="p-3">
                        {repo.vulnerabilityCount?.critical || repo.vulnerabilityCount?.high ? (
                          <span className="text-orange-400 font-bold">
                            {repo.vulnerabilityCount.critical} crit · {repo.vulnerabilityCount.high} high
                          </span>
                        ) : (
                          <span className="text-emerald-400">Clean</span>
                        )}
                      </td>
                      <td className="p-3 font-sans">
                        {repo.branchProtection?.enabled ? (
                          <span className="text-emerald-400 flex items-center gap-1">
                            <ShieldCheck className="h-3 w-3" />
                            Active ({repo.branchProtection.requireApprovals} approvals)
                          </span>
                        ) : (
                          <span className="text-red-400 font-semibold flex items-center gap-1">
                            <ShieldAlert className="h-3 w-3" />
                            Disabled / Bypassable
                          </span>
                        )}
                      </td>
                      <td className="p-3">
                        <span className="text-cyan-300 font-bold">{repo.blastRadiusScore}/100</span>
                      </td>
                      <td className="p-3 font-sans text-slate-300">
                        {repo.linkedAssetName || 'Unmapped'}
                      </td>
                      <td className="p-3 text-right">
                        <div className="flex items-center justify-end gap-1.5 font-sans">
                          {repo.locationCoordinates && (
                            <button
                              type="button"
                              onClick={() => {
                                setActiveTab('globe');
                                flyTo(
                                  repo.locationCoordinates!.latitude,
                                  repo.locationCoordinates!.longitude,
                                  2_800_000,
                                  repo.name
                                );
                              }}
                              className="border border-slate-700 bg-slate-800/60 px-2 py-1 text-[10px] text-cyan-300 hover:border-cyan-400"
                            >
                              Fly-To
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => {
                              setLinkingRepoId(repo.id);
                              setSelectedAssetId(repo.linkedAssetId || '');
                            }}
                            className="border border-cyan-500/50 bg-cyan-500/10 px-2 py-1 text-[10px] text-cyan-200 hover:bg-cyan-500/20"
                          >
                            Link Asset
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Link Asset Modal / Drawer */}
          {linkingRepoId && (
            <div className="border border-cyan-500/60 bg-[#070B14] p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-white">
                  Map Repository to Cloud / Production Asset: <span className="font-mono text-cyan-300">{linkingRepoId}</span>
                </h3>
                <button
                  type="button"
                  onClick={() => setLinkingRepoId(null)}
                  className="text-slate-400 hover:text-white text-xs"
                >
                  ✕ Close
                </button>
              </div>
              <p className="text-[11px] text-slate-400">
                Linking a repository to a deployed cloud server establishes systemic attack blast radius and draws live CI/CD pipeline workflow arcs on the 3D Globe.
              </p>
              <form onSubmit={handleLinkSubmit} className="flex items-center gap-3">
                <select
                  value={selectedAssetId}
                  onChange={(e) => setSelectedAssetId(e.target.value)}
                  className="border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-white focus:border-cyan-500 focus:outline-none"
                >
                  <option value="">-- Select Target Cloud Asset --</option>
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.locationLabel}) · Criticality: {a.criticality.toUpperCase()}
                    </option>
                  ))}
                </select>
                <button
                  type="submit"
                  className="border border-cyan-500 bg-cyan-500/20 px-3 py-1.5 text-xs font-semibold text-cyan-100 hover:bg-cyan-500/30"
                >
                  Save Mapping
                </button>
              </form>
            </div>
          )}
        </div>
      )}

      {/* SUB-TAB B: Secret Exposure Detection */}
      {subTab === 'secrets' && (
        <div className="space-y-4">
          <div className="border border-red-900/60 bg-red-950/20 p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <AlertOctagon className="h-6 w-6 text-red-400 flex-shrink-0" />
              <div>
                <h2 className="text-sm font-bold text-red-200">Zero-Plaintext Secret Scanning Policy Enforced</h2>
                <p className="text-xs text-red-300/80 mt-0.5">
                  Raw credentials are never stored, displayed, or sent to the frontend. Telemetry exposes only credential type, masked fingerprint, and remediation guidance.
                </p>
              </div>
            </div>
            <span className="border border-red-500/40 bg-red-500/20 px-2.5 py-1 text-[11px] font-mono font-bold text-red-300">
              {githubSecrets.length} ACTIONABLE ALERT
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {githubSecrets.map((sec) => (
              <div key={sec.id} className="border border-red-500/50 bg-[#070B14] p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <Key className="h-4 w-4 text-red-400" />
                    <span className="font-bold text-white text-sm">{sec.secretTypeLabel}</span>
                    <span className="border border-red-500/50 bg-red-500/10 px-2 py-0.5 text-[10px] font-mono text-red-300 uppercase">
                      CRITICAL EXPOSURE
                    </span>
                  </div>
                  <span className="font-mono text-xs text-slate-400">
                    Detected: {new Date(sec.detectedAt).toUTCString()}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="space-y-2">
                    <div>
                      <span className="text-slate-400">Masked Credential Fingerprint:</span>
                      <div className="mt-1 font-mono font-bold text-red-400 bg-red-950/30 border border-red-500/30 px-3 py-1.5 text-sm">
                        {sec.maskedFingerprint}
                      </div>
                    </div>
                    <div>
                      <span className="text-slate-400">Repository &amp; Location:</span>
                      <div className="mt-1 font-mono text-cyan-300">
                        {sec.repositoryName} &rarr; {sec.filePath}:{sec.line}
                      </div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div>
                      <span className="text-slate-400">Commit SHA &amp; Author:</span>
                      <div className="mt-1 font-mono text-slate-200">
                        {sec.commitSha.slice(0, 10)} by <span className="text-amber-300">{sec.commitAuthor}</span>
                      </div>
                    </div>
                    <div>
                      <span className="text-slate-400">Status:</span>
                      <div className="mt-1 font-bold text-red-400 uppercase">
                        {sec.status} &mdash; Immediate Revocation Required
                      </div>
                    </div>
                  </div>
                </div>

                <div className="border-t border-slate-800 pt-3">
                  <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wide">
                    Mandatory Remediation Playbook:
                  </h4>
                  <ul className="mt-2 space-y-1.5 text-xs text-slate-300">
                    {sec.remediationPlan.map((step, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="font-mono text-cyan-400 font-bold">{idx + 1}.</span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUB-TAB C: Supply Chain & Dependencies */}
      {subTab === 'supply_chain' && (
        <div className="space-y-4">
          <div className="border border-slate-800 bg-[#070B14] p-4">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider">
              Dependabot Alerts &amp; Third-Party GitHub Actions Posture
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Monitors vulnerable dependencies, CVE severities, fix availability, and detects unpinned third-party CI/CD Actions across repositories.
            </p>
          </div>

          <div className="space-y-3">
            {githubVulnerabilities.map((vuln) => (
              <div key={vuln.id} className="border border-orange-500/40 bg-[#070B14] p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-orange-400 text-sm">{vuln.cveId}</span>
                    <span className="border border-orange-500/50 bg-orange-500/10 px-2 py-0.5 text-[10px] font-mono text-orange-300 uppercase">
                      {vuln.severity} SEVERITY
                    </span>
                    <span className="font-mono text-xs text-slate-300">
                      Package: <strong className="text-white">{vuln.packageName}</strong> (v{vuln.currentVersion})
                    </span>
                  </div>
                  <span className="text-xs font-mono text-emerald-400 border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5">
                    Patched: v{vuln.fixedVersion || 'Under Review'}
                  </span>
                </div>

                <p className="text-xs text-slate-300">{vuln.summary}</p>
                <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono pt-1">
                  <span>Repository: <strong className="text-cyan-300">{vuln.repositoryName}</strong> &rarr; {vuln.manifestPath}</span>
                  <span className="text-amber-400">{vuln.exploitAvailable ? '⚠️ Public Exploit Available' : 'No Public PoC'}</span>
                </div>
              </div>
            ))}
          </div>

          <div className="border border-slate-800 bg-[#070B14] p-4 space-y-3">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider">
              Third-Party CI/CD Workflow Actions
            </h3>
            <div className="divide-y divide-slate-800 text-xs">
              {githubWorkflows.map((wf) => (
                <div key={wf.id} className="py-2.5 flex items-center justify-between">
                  <div>
                    <span className="font-semibold text-white">{wf.name}</span>{' '}
                    <span className="font-mono text-slate-400">({wf.repositoryName} &bull; {wf.headBranch})</span>
                    <div className="mt-1 text-[11px] text-slate-400">
                      Unpinned Actions:{' '}
                      <span className="font-mono text-amber-300">{wf.unpinnedActions.join(', ') || 'None (Pinned to SHA)'}</span>
                    </div>
                  </div>
                  <div className="text-right font-mono text-[11px]">
                    <span className="text-emerald-400 uppercase font-semibold">{wf.conclusion}</span>
                    <div className="text-slate-500">Runner: {wf.runnerType}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB D: Developer Activity & Insider Risk */}
      {subTab === 'developer' && (
        <div className="space-y-4">
          <div className="border border-yellow-900/50 bg-yellow-950/20 p-4">
            <h2 className="text-xs font-bold text-yellow-200 uppercase tracking-wider">
              Developer Activity Anomaly Analysis
            </h2>
            <p className="text-xs text-yellow-300/80 mt-1">
              Objective, telemetry-grounded heuristic flags without speculative accusations: off-hours commits (00:00 - 06:00 UTC), branch-protection bypasses, force-pushes, and modifications to authentication/infrastructure files.
            </p>
          </div>

          <div className="space-y-3">
            {githubDeveloperActivities.map((act) => (
              <div key={act.id} className="border border-yellow-500/40 bg-[#070B14] p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <User className="h-4 w-4 text-yellow-400" />
                    <span className="font-bold text-white text-xs">{act.actor || act.username}</span>
                    <span className="border border-yellow-500/50 bg-yellow-500/10 px-2 py-0.5 text-[10px] font-mono text-yellow-300">
                      Anomaly Score: {act.anomalyScore}/100
                    </span>
                    {act.isOffHours && (
                      <span className="border border-amber-500/50 bg-amber-500/10 px-2 py-0.5 text-[10px] font-mono text-amber-300">
                        OFF-HOURS COMMIT
                      </span>
                    )}
                  </div>
                  <span className="font-mono text-xs text-slate-400">
                    Timestamp: {new Date(act.timestamp).toUTCString()}
                  </span>
                </div>

                <div className="text-xs text-slate-200">
                  <span className="font-semibold text-yellow-300">Finding:</span> {act.anomalyReason}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono text-[11px] text-slate-400">
                  <div>
                    Modified Files:{' '}
                    <span className="text-cyan-300">{act.filesChanged.join(', ')}</span>
                  </div>
                  <div>
                    Source IP:{' '}
                    <span className="text-slate-200">{act.ipAddress || '198.51.100.77'} ({act.location?.city}, {act.location?.country})</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUB-TAB E: Audit Logs */}
      {subTab === 'audit' && (
        <div className="space-y-4">
          <div className="border border-slate-800 bg-[#070B14] p-4 flex items-center justify-between">
            <div>
              <h2 className="text-xs font-bold text-white uppercase tracking-wider">Immutable Security Audit Trail</h2>
              <p className="text-xs text-slate-400 mt-0.5">Cryptographically logged events for permissions, repository membership, and branch protection policy overrides.</p>
            </div>
            <span className="font-mono text-xs text-cyan-400 border border-cyan-500/30 bg-cyan-500/10 px-2 py-1">
              APPEND-ONLY INDEX
            </span>
          </div>

          <div className="border border-slate-800 bg-[#070B14] overflow-hidden">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-[#0B1221] text-[11px] uppercase tracking-wider text-slate-400 font-mono">
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Actor</th>
                  <th className="p-3">Action</th>
                  <th className="p-3">Repository</th>
                  <th className="p-3">Source IP</th>
                  <th className="p-3">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                {githubAuditEvents.map((aud) => (
                  <tr key={aud.id} className="hover:bg-slate-900/50">
                    <td className="p-3 text-slate-400">{new Date(aud.timestamp).toLocaleTimeString()}</td>
                    <td className="p-3 font-semibold text-amber-300">{aud.actor}</td>
                    <td className="p-3 text-cyan-300">{aud.action}</td>
                    <td className="p-3 text-white">{aud.repositoryName}</td>
                    <td className="p-3 text-slate-300">{aud.ipAddress}</td>
                    <td className="p-3 font-sans text-slate-300">{aud.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SUB-TAB F: Gemini CodeSec Copilot */}
      {subTab === 'copilot' && (
        <div className="space-y-4">
          <div className="border border-purple-900/60 bg-purple-950/20 p-4">
            <div className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-purple-400" />
              <h2 className="text-sm font-bold text-purple-200">Gemini DFIR CodeSec Intelligence Assistant</h2>
            </div>
            <p className="text-xs text-purple-300/80 mt-1">
              Natural language queries grounded strictly in authorized GitHub code, dependency, secret, and developer telemetry.
            </p>
          </div>

          <div className="border border-slate-800 bg-[#070B14] p-4 space-y-3">
            <label className="text-xs font-semibold text-slate-300">Quick CodeSec Investigation Prompts:</label>
            <div className="flex flex-wrap gap-2">
              {[
                'Which repositories are most risky?',
                'Are there any leaked secrets?',
                'Which developer activity looks unusual?',
                'Which dependencies are vulnerable?',
                'What is the blast radius if payments-engine is compromised?',
                'Create a remediation plan for this leaked AWS key.',
                'Create an executive security report for our GitHub organization.',
              ].map((chip) => (
                <button
                  key={chip}
                  type="button"
                  onClick={() => {
                    setCopilotQuestion(chip);
                    void handleAskCopilot(chip);
                  }}
                  className="border border-slate-700 bg-slate-900/80 px-2.5 py-1 text-xs text-slate-200 hover:border-purple-400 hover:text-purple-200 transition-colors"
                >
                  {chip}
                </button>
              ))}
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                void handleAskCopilot(copilotQuestion);
              }}
              className="flex gap-2 pt-2"
            >
              <input
                type="text"
                placeholder="Ask Gemini DFIR about connected GitHub repositories and security posture..."
                value={copilotQuestion}
                onChange={(e) => setCopilotQuestion(e.target.value)}
                className="flex-1 border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-purple-500 focus:outline-none"
              />
              <button
                type="submit"
                disabled={copilotLoading}
                className="border border-purple-500 bg-purple-600/30 px-4 py-2 text-xs font-semibold text-purple-100 hover:bg-purple-600/40 disabled:opacity-50"
              >
                {copilotLoading ? 'Analyzing...' : 'Ask Copilot'}
              </button>
            </form>
          </div>

          {copilotResponse && (
            <div className="border border-purple-500/40 bg-[#070B14] p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div className="flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-purple-400" />
                  <span className="text-xs font-bold text-purple-200">Gemini DFIR CodeSec Findings</span>
                </div>
                <span className="text-[10px] font-mono text-slate-400">Model: Gemini 3.1 Flash-Lite</span>
              </div>
              <div className="prose prose-invert max-w-none text-xs text-slate-200 leading-relaxed whitespace-pre-wrap font-sans">
                {copilotResponse}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
