import {
  ChevronLeft,
  ChevronRight,
  Compass,
  Filter,
  Globe2,
  Layers,
  Map as MapIcon,
  Plus,
  RotateCcw,
} from 'lucide-react';
import {useForensicsStore, selectFilteredEvents} from '../store/useForensicsStore';
import type {LayerKey, Severity, ThreatCategory} from '../types/forensics';

const LAYER_ITEMS: Array<{key: LayerKey; label: string; group: string; colorToken: string}> = [
  {key: 'attackSources',    label: 'Attack Sources',          group: 'Core',          colorToken: '#FF4D5E'},
  {key: 'targetAssets',     label: 'Target Assets',           group: 'Core',          colorToken: '#4DB8FF'},
  {key: 'attackArcs',       label: 'Attack Arcs',             group: 'Core',          colorToken: '#FF9F43'},
  {key: 'portScans',        label: 'Port Scan Detection',     group: 'Detectors',     colorToken: '#F5D547'},
  {key: 'bruteForce',       label: 'Brute-Force Detection',   group: 'Detectors',     colorToken: '#FF4D5E'},
  {key: 'malwareC2',        label: 'Malware C2 Traffic',      group: 'Detectors',     colorToken: '#c084fc'},
  {key: 'dataExfiltration', label: 'Data Exfiltration',       group: 'Detectors',     colorToken: '#FF9F43'},
  {key: 'vpnProxyTor',      label: 'VPN / Proxy / Tor',       group: 'Intelligence',  colorToken: '#a78bfa'},
  {key: 'threatReputation', label: 'Threat Reputation',       group: 'Intelligence',  colorToken: '#fb923c'},
  {key: 'globalHeatmap',    label: 'Global Threat Heatmap',   group: 'Intelligence',  colorToken: '#3DDC97'},
  {key: 'geoRiskMatrix',    label: 'Geographic Risk Matrix',  group: 'Intelligence',  colorToken: '#3DDC97'},
  {key: 'githubRepos',      label: 'GitHub Vault Repositories', group: 'CodeSec',      colorToken: '#38bdf8'},
  {key: 'exposedSecrets',   label: 'Exposed Secrets (Masked)', group: 'CodeSec',      colorToken: '#ef4444'},
  {key: 'supplyChain',      label: 'Supply Chain CVEs',         group: 'CodeSec',      colorToken: '#f97316'},
  {key: 'developerActivity',label: 'Developer Anomalies',       group: 'CodeSec',      colorToken: '#eab308'},
];

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

const CATEGORIES: Array<{id: ThreatCategory; label: string}> = [
  {id: 'ssh_brute_force', label: 'Brute Force'},
  {id: 'port_scan', label: 'Port Scan'},
  {id: 'malware_c2', label: 'Malware C2'},
  {id: 'data_exfiltration', label: 'Exfiltration'},
  {id: 'vpn_abuse', label: 'VPN / Proxy'},
  {id: 'anomalous_login', label: 'Anomalous Login'},
  {id: 'ddos', label: 'DDoS'},
  {id: 'phishing', label: 'Phishing'},
];

const CAMERA_PRESETS = [
  {label: 'Global', lat: 26.0, lon: 46.0, height: 17_500_000},
  {label: 'Mumbai / IN', lat: 19.076, lon: 72.8777, height: 2_600_000},
  {label: 'US-East', lat: 39.0438, lon: -77.4874, height: 3_200_000},
  {label: 'Europe / FRA', lat: 50.1109, lon: 8.6821, height: 3_200_000},
  {label: 'APAC / SIN', lat: 12.0, lon: 112.0, height: 5_200_000},
];

export function LeftControlSidebar() {
  const open = useForensicsStore((s) => s.leftSidebarOpen);
  const setOpen = useForensicsStore((s) => s.setLeftSidebarOpen);
  const layers = useForensicsStore((s) => s.layers);
  const toggleLayer = useForensicsStore((s) => s.toggleLayer);
  const filters = useForensicsStore((s) => s.filters);
  const setFilter = useForensicsStore((s) => s.setFilter);
  const resetFilters = useForensicsStore((s) => s.resetFilters);
  const flyTo = useForensicsStore((s) => s.flyTo);
  const globeMode = useForensicsStore((s) => s.globeMode);
  const setGlobeMode = useForensicsStore((s) => s.setGlobeMode);
  const imageryMode = useForensicsStore((s) => s.imageryMode);
  const setImageryMode = useForensicsStore((s) => s.setImageryMode);
  const setAddAssetModalOpen = useForensicsStore((s) => s.setAddAssetModalOpen);
  const userRole = useForensicsStore((s) => s.userRole);
  const events = useForensicsStore((s) => s.events);
  const timelineMode = useForensicsStore((s) => s.timelineMode);
  const replayProgress = useForensicsStore((s) => s.replayProgress);

  // Compute per-layer event counts for the sparkline badge
  const filteredAll = selectFilteredEvents(events, filters, layers, timelineMode, replayProgress);
  const layerCounts: Record<LayerKey, number> = {
    attackSources:    filteredAll.length,
    targetAssets:     useForensicsStore.getState().assets.length,
    attackArcs:       filteredAll.length,
    portScans:        filteredAll.filter((e) => e.eventType === 'port_scan').length,
    bruteForce:       filteredAll.filter((e) => e.eventType === 'ssh_brute_force').length,
    malwareC2:        filteredAll.filter((e) => e.eventType === 'malware_c2').length,
    dataExfiltration: filteredAll.filter((e) => e.eventType === 'data_exfiltration').length,
    vpnProxyTor:      filteredAll.filter((e) => ['vpn', 'proxy', 'tor'].includes(e.connectionType)).length,
    threatReputation: filteredAll.filter((e) => e.abuseConfidence >= 70).length,
    globalHeatmap:    useForensicsStore.getState().statistics?.geoRiskMatrix.length ?? 0,
    geoRiskMatrix:    useForensicsStore.getState().statistics?.geoRiskMatrix.length ?? 0,
    githubRepos:      useForensicsStore.getState().githubRepositories.length,
    exposedSecrets:   useForensicsStore.getState().githubSecrets.length,
    supplyChain:      useForensicsStore.getState().githubVulnerabilities.length,
    developerActivity:useForensicsStore.getState().githubDeveloperActivities.length,
  };

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label="Open layers and filters sidebar"
        className="absolute left-3 top-20 z-20 flex items-center gap-1.5 border border-slate-700/90 bg-[#070B14]/95 px-3 py-2 text-xs font-medium text-slate-200 hover:border-cyan-400"
      >
        <Layers className="h-4 w-4 text-cyan-400" aria-hidden="true" />
        <span>Layers &amp; Filters</span>
        <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
      </button>
    );
  }

  const toggleSeverity = (sev: Severity) => {
    const exists = filters.severities.includes(sev);
    const next = exists
      ? filters.severities.filter((s) => s !== sev)
      : [...filters.severities, sev];
    setFilter('severities', next.length > 0 ? next : [sev]);
  };

  const toggleCategory = (cat: ThreatCategory) => {
    const exists = filters.categories.includes(cat);
    const next = exists
      ? filters.categories.filter((c) => c !== cat)
      : [...filters.categories, cat];
    setFilter('categories', next.length > 0 ? next : [cat]);
  };

  return (
    <aside
      aria-label="Threat Layers and Filters"
      className="absolute bottom-20 left-3 top-[4.5rem] z-20 flex w-72 flex-col border border-slate-800/90 bg-[#070B14]/92 text-slate-200 shadow-2xl"
    >
      <div className="flex items-center justify-between border-b border-slate-800 px-3.5 py-2.5">
        <div className="flex items-center gap-2 text-xs font-semibold text-white">
          <Layers className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          <span>Command Layers &amp; Filters</span>
        </div>
        <button
          type="button"
          onClick={() => setOpen(false)}
          aria-label="Collapse layers sidebar"
          className="p-1 text-slate-400 hover:text-white"
        >
          <ChevronLeft className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-3.5 py-3 space-y-5">
        {/* Projection & Base Imagery */}
        <section>
          <div className="flex items-center justify-between">
            <h2 className="text-[11px] font-semibold text-slate-400">Globe Projection &amp; Imagery</h2>
          </div>
          <div className="mt-2 grid grid-cols-2 gap-1.5">
            <button
              type="button"
              onClick={() => setGlobeMode('3D')}
              className={`flex items-center justify-center gap-1.5 border py-1.5 text-xs font-medium transition-colors ${
                globeMode === '3D'
                  ? 'border-cyan-500 bg-cyan-500/15 text-cyan-300'
                  : 'border-slate-800 bg-[#0B1221] text-slate-400 hover:text-white'
              }`}
            >
              <Globe2 className="h-3.5 w-3.5" aria-hidden="true" />
              <span>3D Globe</span>
            </button>
            <button
              type="button"
              onClick={() => setGlobeMode('2D')}
              className={`flex items-center justify-center gap-1.5 border py-1.5 text-xs font-medium transition-colors ${
                globeMode === '2D'
                  ? 'border-cyan-500 bg-cyan-500/15 text-cyan-300'
                  : 'border-slate-800 bg-[#0B1221] text-slate-400 hover:text-white'
              }`}
            >
              <MapIcon className="h-3.5 w-3.5" aria-hidden="true" />
              <span>2D Map</span>
            </button>
          </div>
          <div className="mt-1.5 grid grid-cols-2 gap-1.5">
            <button
              type="button"
              onClick={() => setImageryMode('natural_earth')}
              className={`border py-1 text-[11px] font-medium transition-colors ${
                imageryMode === 'natural_earth'
                  ? 'border-cyan-500/70 bg-cyan-500/10 text-cyan-200'
                  : 'border-slate-800 bg-[#0B1221] text-slate-400 hover:text-white'
              }`}
            >
              Tactical Earth
            </button>
            <button
              type="button"
              onClick={() => setImageryMode('dark_carto')}
              className={`border py-1 text-[11px] font-medium transition-colors ${
                imageryMode === 'dark_carto'
                  ? 'border-cyan-500/70 bg-cyan-500/10 text-cyan-200'
                  : 'border-slate-800 bg-[#0B1221] text-slate-400 hover:text-white'
              }`}
            >
              Dark Vector Tiles
            </button>
          </div>
        </section>

        {/* Camera Focus Presets */}
        <section>
          <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-400">
            <Compass className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
            <span>Quick Sector Fly-To</span>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {CAMERA_PRESETS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => flyTo(preset.lat, preset.lon, preset.height, preset.label)}
                className="border border-slate-800 bg-[#0B1221] px-2 py-1 text-[11px] text-slate-300 hover:border-cyan-500/60 hover:text-cyan-200 transition-colors"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </section>

        {/* 11 Independent Threat Layers */}
        <section>
          <div className="flex items-center justify-between">
            <h2 className="text-[11px] font-semibold text-slate-400">Threat Layers (11)</h2>
            <button
              type="button"
              onClick={() => setAddAssetModalOpen(true)}
              disabled={userRole === 'Viewer'}
              className="flex items-center gap-1 text-[11px] font-medium text-cyan-400 hover:text-cyan-300 disabled:opacity-40"
            >
              <Plus className="h-3 w-3" aria-hidden="true" />
              <span>Add Asset</span>
            </button>
          </div>
          <div className="mt-2 space-y-1">
            {LAYER_ITEMS.map((item) => (
              <label
                key={item.key}
                className="flex cursor-pointer items-center justify-between py-1 text-xs text-slate-300 hover:text-white"
              >
                <span className="flex items-center gap-2 min-w-0">
                  {/* Colour chip */}
                  <span
                    className="inline-block h-2 w-2 shrink-0 rounded-sm"
                    style={{backgroundColor: item.colorToken, opacity: layers[item.key] ? 1 : 0.3}}
                    aria-hidden="true"
                  />
                  <span className="truncate">{item.label}</span>
                </span>
                <span className="flex items-center gap-2 shrink-0">
                  {/* Event count badge */}
                  <span className="font-mono text-[10px] text-slate-500 tabular-nums w-6 text-right">
                    {layerCounts[item.key] > 0 ? layerCounts[item.key] : ''}
                  </span>
                  <input
                    type="checkbox"
                    checked={layers[item.key]}
                    onChange={() => toggleLayer(item.key)}
                    className="h-3.5 w-3.5 accent-cyan-400"
                    aria-label={`Toggle ${item.label} layer`}
                  />
                </span>
              </label>
            ))}
          </div>
        </section>

        {/* Multi-Dimensional Filters */}
        <section className="border-t border-slate-800 pt-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-400">
              <Filter className="h-3.5 w-3.5 text-cyan-400" aria-hidden="true" />
              <span>Forensic Filters</span>
            </div>
            <button
              type="button"
              onClick={resetFilters}
              className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-cyan-300"
            >
              <RotateCcw className="h-3 w-3" aria-hidden="true" />
              <span>Reset</span>
            </button>
          </div>

          {/* Severity selector */}
          <div className="mt-2.5">
            <span className="text-[11px] text-slate-400">Severity</span>
            <div className="mt-1 grid grid-cols-4 gap-1">
              {SEVERITIES.map((sev) => {
                const active = filters.severities.includes(sev);
                const colorCls =
                  sev === 'critical'
                    ? 'border-red-500/70 bg-red-500/15 text-red-300'
                    : sev === 'high'
                      ? 'border-orange-500/70 bg-orange-500/15 text-orange-300'
                      : sev === 'medium'
                        ? 'border-amber-500/70 bg-amber-500/15 text-amber-300'
                        : 'border-emerald-500/70 bg-emerald-500/15 text-emerald-300';
                return (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => toggleSeverity(sev)}
                    className={`border py-1 text-[10px] font-semibold capitalize transition-colors ${
                      active ? colorCls : 'border-slate-800 bg-[#0B1221] text-slate-500'
                    }`}
                  >
                    {sev}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Threat category filter */}
          <div className="mt-3">
            <span className="text-[11px] text-slate-400">Attack Categories</span>
            <div className="mt-1 grid grid-cols-2 gap-1">
              {CATEGORIES.map((cat) => {
                const active = filters.categories.includes(cat.id);
                return (
                  <button
                    key={cat.id}
                    type="button"
                    onClick={() => toggleCategory(cat.id)}
                    className={`border px-2 py-1 text-left text-[11px] transition-colors truncate ${
                      active
                        ? 'border-cyan-500/60 bg-cyan-500/10 text-cyan-200'
                        : 'border-slate-800 bg-[#0B1221] text-slate-500'
                    }`}
                  >
                    {cat.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Country / ASN / Protocol / Confidence */}
          <div className="mt-3 space-y-2">
            <div>
              <label htmlFor="filter-country" className="block text-[11px] text-slate-400">
                Country / Code
              </label>
              <input
                id="filter-country"
                type="text"
                value={filters.country}
                onChange={(e) => setFilter('country', e.target.value)}
                placeholder="e.g. India, RU, NL"
                className="mt-1 w-full border border-slate-800 bg-[#0B1221] px-2.5 py-1 text-xs text-slate-200 placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
              />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label htmlFor="filter-asn" className="block text-[11px] text-slate-400">
                  ASN
                </label>
                <input
                  id="filter-asn"
                  type="text"
                  value={filters.asn}
                  onChange={(e) => setFilter('asn', e.target.value)}
                  placeholder="AS55836"
                  className="mt-1 w-full border border-slate-800 bg-[#0B1221] px-2 py-1 font-mono text-xs text-slate-200 placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
                />
              </div>
              <div>
                <label htmlFor="filter-proto" className="block text-[11px] text-slate-400">
                  Protocol
                </label>
                <input
                  id="filter-proto"
                  type="text"
                  value={filters.protocol}
                  onChange={(e) => setFilter('protocol', e.target.value)}
                  placeholder="SSH, TCP"
                  className="mt-1 w-full border border-slate-800 bg-[#0B1221] px-2 py-1 font-mono text-xs text-slate-200 placeholder-slate-600 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>
            <div>
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <label htmlFor="filter-confidence">Min Confidence</label>
                <span className="font-mono text-cyan-300">{filters.minConfidence}%</span>
              </div>
              <input
                id="filter-confidence"
                type="range"
                min={0}
                max={95}
                step={5}
                value={filters.minConfidence}
                onChange={(e) => setFilter('minConfidence', Number(e.target.value))}
                className="mt-1 w-full accent-cyan-400"
              />
            </div>
          </div>
        </section>
      </div>
    </aside>
  );
}
