import {useEffect} from 'react';
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Crosshair,
  ExternalLink,
  Info,
  Shield,
  Sparkles,
  X,
} from 'lucide-react';
import {
  formatCategoryLabel,
  severityHex,
  severityTextColor,
  useForensicsStore,
} from '../store/useForensicsStore';
import {APPROX_LOCATION_DISCLAIMER, type EventReviewStatus} from '../types/forensics';

const REVIEW_STATUSES: Array<{id: EventReviewStatus; label: string}> = [
  {id: 'reviewed', label: 'Reviewed'},
  {id: 'suspicious', label: 'Suspicious'},
  {id: 'confirmed', label: 'Confirmed'},
  {id: 'false_positive', label: 'False Positive'},
  {id: 'escalated', label: 'Escalated'},
];

export function RightInspectorPanel() {
  const selectedEntity = useForensicsStore((s) => s.selectedEntity);
  const setSelectedEntity = useForensicsStore((s) => s.setSelectedEntity);
  const events = useForensicsStore((s) => s.events);
  const assets = useForensicsStore((s) => s.assets);
  const cases = useForensicsStore((s) => s.cases);
  const ipIntel = useForensicsStore((s) => s.ipIntel);
  const statistics = useForensicsStore((s) => s.statistics);
  const fetchIpIntelligence = useForensicsStore((s) => s.fetchIpIntelligence);
  const updateEventStatus = useForensicsStore((s) => s.updateEventStatus);
  const toggleBlockIp = useForensicsStore((s) => s.toggleBlockIp);
  const flyTo = useForensicsStore((s) => s.flyTo);
  const setActiveTab = useForensicsStore((s) => s.setActiveTab);
  const setActiveCaseId = useForensicsStore((s) => s.setActiveCaseId);
  const userRole = useForensicsStore((s) => s.userRole);

  const selectedEvent =
    selectedEntity?.kind === 'event'
      ? events.find((e) => e.id === selectedEntity.eventId) ?? null
      : null;

  const targetIp =
    selectedEntity?.kind === 'ip'
      ? selectedEntity.ip
      : selectedEvent?.sourceIp ?? null;

  useEffect(() => {
    if (targetIp && !ipIntel[targetIp]) {
      void fetchIpIntelligence(targetIp);
    }
  }, [targetIp, ipIntel, fetchIpIntelligence]);

  if (!selectedEntity) return null;

  const intel = targetIp ? ipIntel[targetIp] : null;
  const selectedAsset =
    selectedEntity.kind === 'asset'
      ? assets.find((a) => a.id === selectedEntity.assetId) ?? null
      : null;
  const selectedRegion =
    selectedEntity.kind === 'region'
      ? statistics?.geoRiskMatrix.find((r) => r.regionId === selectedEntity.regionId) ?? null
      : null;

  return (
    <aside
      aria-label="Forensic Investigation Inspector"
      data-testid="right-inspector-panel"
      className="absolute bottom-20 right-3 top-[4.5rem] z-20 flex w-96 max-w-[calc(100vw-1.5rem)] flex-col border border-slate-800/95 bg-[#070B14]/95 text-slate-200 shadow-2xl"
    >
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-xs font-semibold text-white">
            <Shield className="h-4 w-4 text-cyan-400 shrink-0" aria-hidden="true" />
            <span className="truncate">
              {selectedEvent
                ? `Event Inspector · ${selectedEvent.id}`
                : selectedAsset
                  ? 'Protected Asset Inspector'
                  : selectedRegion
                    ? `Region Risk · ${selectedRegion.country}`
                    : `IP Intelligence · ${targetIp}`}
            </span>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setSelectedEntity(null)}
          aria-label="Close forensic inspector"
          className="p-1 text-slate-400 hover:text-white"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4 text-xs">
        {/* EVENT & IP VIEW */}
        {(selectedEvent || intel) && (
          <>
            {/* Mandatory Forensic Geolocation Disclaimer */}
            <div className="border border-amber-500/40 bg-amber-500/10 p-2.5 text-[11px] leading-relaxed text-amber-200">
              <div className="flex items-start gap-2">
                <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" aria-hidden="true" />
                <div>
                  <span className="font-semibold text-amber-100">Approximate Network Location: </span>
                  {APPROX_LOCATION_DISCLAIMER}
                </div>
              </div>
            </div>

            {selectedEvent && (
              <div className="space-y-2 border-b border-slate-800 pb-3">
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span>
                    {formatCategoryLabel(selectedEvent.eventType)} · {selectedEvent.protocol}:{selectedEvent.destinationPort}
                  </span>
                  <span className={`font-mono font-semibold uppercase ${severityTextColor(selectedEvent.severity)}`}>
                    {selectedEvent.severity} ({selectedEvent.riskScore}/100)
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-white">{selectedEvent.title}</h3>
                <p className="text-xs leading-relaxed text-slate-300">{selectedEvent.description}</p>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-slate-400">
                  <span>Confidence: {selectedEvent.confidence}%</span>
                  <span>·</span>
                  <span>Status: {selectedEvent.status.replace('_', ' ')}</span>
                  {selectedEvent.isDemoData && (
                    <>
                      <span>·</span>
                      <span className="text-amber-300">DEMO DATA</span>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* IP Intelligence Core Telemetry */}
            <div className="space-y-2 border-b border-slate-800 pb-3">
              <div className="flex items-center justify-between">
                <h4 className="font-semibold text-white">IP &amp; Network Attribution Lead</h4>
                {targetIp && (
                  <button
                    type="button"
                    onClick={() => {
                      const loc = intel?.approxLocation ?? selectedEvent?.sourceLocation;
                      if (loc) flyTo(loc.latitude, loc.longitude, 1_900_000, targetIp);
                    }}
                    className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                  >
                    <Crosshair className="h-3 w-3" aria-hidden="true" />
                    <span>Center Globe</span>
                  </button>
                )}
              </div>

              <dl className="grid grid-cols-2 gap-x-3 gap-y-2 font-mono text-[11px]">
                <div>
                  <dt className="font-sans text-[10px] text-slate-500">Source IP</dt>
                  <dd className="text-slate-100">{targetIp}</dd>
                </div>
                <div>
                  <dt className="font-sans text-[10px] text-slate-500">Confidence Radius</dt>
                  <dd className="text-amber-300">
                    ±{intel?.approxLocation.accuracyRadiusKm ?? selectedEvent?.sourceLocation.accuracyRadiusKm} km
                  </dd>
                </div>
                <div className="col-span-2">
                  <dt className="font-sans text-[10px] text-slate-500">Approximate Network Region</dt>
                  <dd className="font-sans text-slate-200">
                    {(intel?.approxLocation ?? selectedEvent?.sourceLocation)?.city},{' '}
                    {(intel?.approxLocation ?? selectedEvent?.sourceLocation)?.region},{' '}
                    {(intel?.approxLocation ?? selectedEvent?.sourceLocation)?.country}
                  </dd>
                </div>
                <div>
                  <dt className="font-sans text-[10px] text-slate-500">Coordinates (Approx.)</dt>
                  <dd className="text-slate-300">
                    {(intel?.approxLocation ?? selectedEvent?.sourceLocation)?.latitude.toFixed(3)},{' '}
                    {(intel?.approxLocation ?? selectedEvent?.sourceLocation)?.longitude.toFixed(3)}
                  </dd>
                </div>
                <div>
                  <dt className="font-sans text-[10px] text-slate-500">ASN / ISP</dt>
                  <dd className="truncate text-slate-200" title={intel?.isp ?? selectedEvent?.isp}>
                    {intel?.asn ?? selectedEvent?.asn} · {intel?.isp ?? selectedEvent?.isp}
                  </dd>
                </div>
                <div>
                  <dt className="font-sans text-[10px] text-slate-500">Connection Type</dt>
                  <dd className="uppercase text-cyan-300">
                    {intel?.connectionType ?? selectedEvent?.connectionType}
                  </dd>
                </div>
                <div>
                  <dt className="font-sans text-[10px] text-slate-500">VPN / Proxy / Tor Prob.</dt>
                  <dd className="text-purple-300">
                    {Math.round(((intel?.vpnProbability ?? selectedEvent?.vpnProbability ?? 0) * 100))}%
                    {intel?.torExitNode ? ' (TOR EXIT)' : ''}
                  </dd>
                </div>
                <div>
                  <dt className="font-sans text-[10px] text-slate-500">Abuse Confidence</dt>
                  <dd className="text-orange-300">
                    {intel?.abuseConfidenceScore ?? selectedEvent?.abuseConfidence}% ({intel?.abuseReportCount ?? '—'} reports)
                  </dd>
                </div>
                <div>
                  <dt className="font-sans text-[10px] text-slate-500">Target (Masked)</dt>
                  <dd className="truncate text-slate-300">
                    {selectedEvent?.maskedDestinationIp ?? 'Multiple assets'}
                  </dd>
                </div>
              </dl>
              <p className="text-[10px] text-slate-500">
                Source: {intel?.dataSource ?? selectedEvent?.dataSource}
              </p>
            </div>

            {/* Attack-Type Specific Forensic Telemetry */}
            {selectedEvent && (
              <div className="space-y-1.5 border-b border-slate-800 pb-3">
                <h4 className="font-semibold text-white">Forensic Telemetry Evidence</h4>
                <div className="grid grid-cols-2 gap-2 font-mono text-[11px] text-slate-300">
                  {selectedEvent.metadata.attempts !== undefined && (
                    <div>Attempts: {selectedEvent.metadata.attempts}</div>
                  )}
                  {selectedEvent.metadata.failureRate !== undefined && (
                    <div>Failure Rate: {selectedEvent.metadata.failureRate}%</div>
                  )}
                  {selectedEvent.metadata.targetUsername && (
                    <div>Username: {selectedEvent.metadata.targetUsername}</div>
                  )}
                  {selectedEvent.metadata.portsScanned !== undefined && (
                    <div>Ports Scanned: {selectedEvent.metadata.portsScanned}</div>
                  )}
                  {selectedEvent.metadata.scanIntensity && (
                    <div>Intensity: {selectedEvent.metadata.scanIntensity}</div>
                  )}
                  {selectedEvent.metadata.infectedEndpoint && (
                    <div>Endpoint: {selectedEvent.metadata.infectedEndpoint}</div>
                  )}
                  {selectedEvent.metadata.c2Domain && (
                    <div className="col-span-2 truncate">C2 Domain: {selectedEvent.metadata.c2Domain}</div>
                  )}
                  {selectedEvent.metadata.malwareFamily && (
                    <div className="col-span-2">Family: {selectedEvent.metadata.malwareFamily}</div>
                  )}
                  {selectedEvent.metadata.bytesTransferred !== undefined && selectedEvent.metadata.bytesTransferred > 0 && (
                    <div className="col-span-2">
                      Transfer Volume:{' '}
                      {(selectedEvent.metadata.bytesTransferred / (1024 * 1024)).toFixed(1)} MB
                    </div>
                  )}
                  {selectedEvent.metadata.portsTargeted && (
                    <div className="col-span-2">
                      Ports: {selectedEvent.metadata.portsTargeted.join(', ')}
                    </div>
                  )}
                  {selectedEvent.metadata.possibleDataTypes && (
                    <div className="col-span-2 font-sans text-amber-300">
                      Suspected Data: {selectedEvent.metadata.possibleDataTypes.join(', ')}
                    </div>
                  )}
                  {selectedEvent.metadata.evidenceSha256 && (
                    <div className="col-span-2 truncate text-[10px] text-slate-500">
                      Evidence SHA-256: {selectedEvent.metadata.evidenceSha256}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Transparent Risk Scoring Breakdown */}
            {selectedEvent && (
              <div className="space-y-2 border-b border-slate-800 pb-3">
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-white">Transparent Risk Score Engine</h4>
                  <span
                    className="font-mono text-xs font-bold"
                    style={{color: severityHex(selectedEvent.severity)}}
                  >
                    {selectedEvent.riskScore} / 100
                  </span>
                </div>
                <div className="space-y-1.5">
                  {selectedEvent.riskAssessment.factors.map((f) => (
                    <div key={f.name} className="space-y-0.5">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-slate-300">{f.name}</span>
                        <span className="font-mono text-cyan-300">
                          +{f.contribution}/{f.weight}
                        </span>
                      </div>
                      <div className="h-1 w-full bg-slate-800">
                        <div
                          className="h-1 bg-cyan-400"
                          style={{width: `${Math.min(100, (f.contribution / Math.max(1, f.weight)) * 100)}%`}}
                        />
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mt-2 border border-slate-800 bg-[#0B1221] p-2.5">
                  <div className="text-[11px] font-semibold text-emerald-300">Recommended Action</div>
                  <p className="mt-1 text-[11px] leading-relaxed text-slate-300">
                    {selectedEvent.riskAssessment.recommendedAction}
                  </p>
                </div>
              </div>
            )}

            {/* Investigation Actions */}
            <div className="space-y-2.5">
              {selectedEvent && (
                <div>
                  <span className="block text-[11px] font-semibold text-slate-400">
                    Mark Forensic Disposition
                  </span>
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {REVIEW_STATUSES.map((st) => (
                      <button
                        key={st.id}
                        type="button"
                        disabled={userRole === 'Viewer'}
                        onClick={() => void updateEventStatus(selectedEvent.id, st.id)}
                        className={`border px-2 py-1 text-[11px] font-medium transition-colors disabled:opacity-40 ${
                          selectedEvent.status === st.id
                            ? 'border-cyan-400 bg-cyan-500/20 text-cyan-200'
                            : 'border-slate-800 bg-[#0B1221] text-slate-300 hover:border-slate-600'
                        }`}
                      >
                        {st.label}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {selectedEvent && (
                <div>
                  <label htmlFor="link-case-select" className="block text-[11px] font-semibold text-slate-400">
                    Link to Investigation Case
                  </label>
                  <div className="mt-1 flex gap-1.5">
                    <select
                      id="link-case-select"
                      disabled={userRole === 'Viewer'}
                      value={selectedEvent.caseId ?? ''}
                      onChange={(e) =>
                        void updateEventStatus(
                          selectedEvent.id,
                          selectedEvent.status,
                          e.target.value || null
                        )
                      }
                      className="flex-1 border border-slate-800 bg-[#0B1221] px-2 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
                    >
                      <option value="">Unassigned</option>
                      {cases.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.id} — {c.title.slice(0, 32)}
                        </option>
                      ))}
                    </select>
                    {selectedEvent.caseId && (
                      <button
                        type="button"
                        onClick={() => {
                          setActiveCaseId(selectedEvent.caseId);
                          setActiveTab('investigations');
                        }}
                        aria-label="Open linked case"
                        className="border border-slate-700 bg-slate-900 px-2.5 text-cyan-300 hover:border-cyan-400"
                      >
                        <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    )}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-2 gap-2 pt-1">
                {targetIp && (
                  <button
                    type="button"
                    disabled={userRole === 'Viewer'}
                    onClick={() => void toggleBlockIp(targetIp, !(intel?.blocked ?? false))}
                    className={`flex items-center justify-center gap-1.5 border py-2 text-xs font-semibold transition-colors disabled:opacity-40 ${
                      intel?.blocked
                        ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-300 hover:bg-emerald-500/25'
                        : 'border-red-500/60 bg-red-500/15 text-red-300 hover:bg-red-500/25'
                    }`}
                  >
                    {intel?.blocked ? (
                      <>
                        <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>Unblock IP</span>
                      </>
                    ) : (
                      <>
                        <Ban className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>Block IP</span>
                      </>
                    )}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setActiveTab('analyst')}
                  className="flex items-center justify-center gap-1.5 border border-cyan-500/60 bg-cyan-500/15 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/25"
                >
                  <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Ask Forensic AI</span>
                </button>
              </div>
            </div>
          </>
        )}

        {/* PROTECTED ASSET VIEW */}
        {selectedAsset && (
          <div className="space-y-3">
            <div>
              <div className="text-[11px] text-cyan-400">{selectedAsset.assetType.replace('_', ' ').toUpperCase()}</div>
              <h3 className="mt-0.5 text-sm font-semibold text-white">{selectedAsset.name}</h3>
              <p className="text-xs text-slate-400">{selectedAsset.locationLabel}</p>
            </div>
            <dl className="grid grid-cols-2 gap-2 border-y border-slate-800 py-3 font-mono text-[11px]">
              <div>
                <dt className="font-sans text-[10px] text-slate-500">Address / Internal ID</dt>
                <dd className="text-slate-200">{selectedAsset.maskedInternalIp ?? selectedAsset.ipOrInternalId}</dd>
              </div>
              <div>
                <dt className="font-sans text-[10px] text-slate-500">Criticality</dt>
                <dd className={`uppercase ${severityTextColor(selectedAsset.criticality)}`}>{selectedAsset.criticality}</dd>
              </div>
              <div>
                <dt className="font-sans text-[10px] text-slate-500">Asset Risk Score</dt>
                <dd className="text-white">{selectedAsset.riskScore} / 100</dd>
              </div>
              <div>
                <dt className="font-sans text-[10px] text-slate-500">Open Ports</dt>
                <dd className="text-cyan-300">{selectedAsset.openPorts.join(', ')}</dd>
              </div>
            </dl>
            <div>
              <h4 className="font-semibold text-white">Associated Threat Events</h4>
              <div className="mt-2 space-y-1.5">
                {events
                  .filter((e) => e.targetAssetId === selectedAsset.id)
                  .map((ev) => (
                    <button
                      key={ev.id}
                      type="button"
                      onClick={() => setSelectedEntity({kind: 'event', eventId: ev.id})}
                      className="w-full border border-slate-800 bg-[#0B1221] p-2 text-left hover:border-cyan-500/60"
                    >
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-medium text-white truncate">{ev.title}</span>
                        <span className={`font-mono ${severityTextColor(ev.severity)}`}>{ev.riskScore}</span>
                      </div>
                      <div className="mt-0.5 font-mono text-[10px] text-slate-400">
                        {ev.sourceIp} · {formatCategoryLabel(ev.eventType)}
                      </div>
                    </button>
                  ))}
              </div>
            </div>
          </div>
        )}

        {/* REGION RISK VIEW */}
        {selectedRegion && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white">{selectedRegion.country}</h3>
                <p className="text-xs text-slate-400">Primary Cluster: {selectedRegion.topCity}</p>
              </div>
              <span className="font-mono text-sm font-bold text-orange-300">
                Risk {selectedRegion.avgRiskScore}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-2 border-y border-slate-800 py-3 font-mono text-xs">
              <div>
                <div className="font-sans text-[10px] text-slate-500">Attack Volume</div>
                <div className="text-white">{selectedRegion.attackVolume} events</div>
              </div>
              <div>
                <div className="font-sans text-[10px] text-slate-500">Unique Attacker IPs</div>
                <div className="text-white">{selectedRegion.uniqueAttackerIps}</div>
              </div>
              <div>
                <div className="font-sans text-[10px] text-slate-500">Targeted Assets</div>
                <div className="text-cyan-300">{selectedRegion.targetedAssets}</div>
              </div>
              <div>
                <div className="font-sans text-[10px] text-slate-500">Blocked IPs</div>
                <div className="text-emerald-300">{selectedRegion.blockedIps}</div>
              </div>
            </div>
            <div className="flex items-start gap-2 border border-slate-800 bg-[#0B1221] p-2.5 text-[11px] text-slate-400">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" aria-hidden="true" />
              <span>Regional counts reflect approximate IP network routing and may include VPN/Tor/cloud relays.</span>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}
