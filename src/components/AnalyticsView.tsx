import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {Crosshair, TrendingDown, TrendingUp, Minus} from 'lucide-react';
import {useForensicsStore} from '../store/useForensicsStore';

const BAR_COLORS = ['#ef4444', '#f97316', '#f59e0b', '#06b6d4', '#a855f7', '#38bdf8', '#10b981', '#64748b'];

export function AnalyticsView() {
  const statistics = useForensicsStore((s) => s.statistics);
  const setActiveTab = useForensicsStore((s) => s.setActiveTab);
  const setSelectedEntity = useForensicsStore((s) => s.setSelectedEntity);
  const flyTo = useForensicsStore((s) => s.flyTo);

  if (!statistics) {
    return (
      <div className="flex h-full items-center justify-center bg-[#050811] text-sm text-slate-400">
        Loading threat analytics…
      </div>
    );
  }

  return (
    <main className="h-full w-full overflow-y-auto bg-[#050811] p-6 text-slate-200">
      <div className="mx-auto max-w-6xl space-y-6">
        <div className="flex flex-wrap items-end justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h1 className="text-lg font-bold text-white">Global Threat Analytics &amp; Geographic Risk Matrix</h1>
            <p className="mt-1 text-xs text-slate-400">
              Correlated telemetry distributions across ASNs, anonymization tiers, and approximate network origins.
            </p>
          </div>
          <div className="font-mono text-[11px] text-slate-500">
            Updated {new Date(statistics.generatedAt).toLocaleTimeString()}
          </div>
        </div>

        {/* Top Charts Grid */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <section className="border border-slate-800 bg-[#080E1C] p-4">
            <h2 className="text-xs font-semibold text-slate-300">Event Volume &amp; Criticality Over Time</h2>
            <div className="mt-3 h-60 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={statistics.timelineSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="bucket" stroke="#64748b" tick={{fontSize: 11}} />
                  <YAxis stroke="#64748b" tick={{fontSize: 11}} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{backgroundColor: '#070B14', border: '1px solid #334155', fontSize: '12px'}}
                  />
                  <Area type="monotone" dataKey="total" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.18} name="Total Events" />
                  <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="#ef4444" fillOpacity={0.28} name="Critical" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>

          <section className="border border-slate-800 bg-[#080E1C] p-4">
            <h2 className="text-xs font-semibold text-slate-300">Threat Vector Distribution</h2>
            <div className="mt-3 h-60 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={statistics.categoryBreakdown} layout="vertical" margin={{left: 20}}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis type="number" stroke="#64748b" tick={{fontSize: 11}} allowDecimals={false} />
                  <YAxis type="category" dataKey="label" stroke="#94a3b8" tick={{fontSize: 11}} width={105} />
                  <Tooltip
                    contentStyle={{backgroundColor: '#070B14', border: '1px solid #334155', fontSize: '12px'}}
                  />
                  <Bar dataKey="count" name="Events">
                    {statistics.categoryBreakdown.map((_, idx) => (
                      <Cell key={idx} fill={BAR_COLORS[idx % BAR_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </section>
        </div>

        {/* Geographic Risk Matrix Table */}
        <section className="border border-slate-800 bg-[#080E1C]">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-4 py-3">
            <div>
              <h2 className="text-sm font-semibold text-white">Geographic Risk Matrix</h2>
              <p className="text-[11px] text-slate-400">
                Approximate network routing regions — VPN, Tor, and cloud hosting relays may mask true operator origin.
              </p>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 bg-[#0B1221] text-[11px] text-slate-400">
                <tr>
                  <th className="px-4 py-2.5">Country / Primary City</th>
                  <th className="px-4 py-2.5 text-right">Attack Volume</th>
                  <th className="px-4 py-2.5 text-right">Unique IPs</th>
                  <th className="px-4 py-2.5 text-right">Targeted Assets</th>
                  <th className="px-4 py-2.5 text-right">Blocked IPs</th>
                  <th className="px-4 py-2.5 text-right">Avg Risk</th>
                  <th className="px-4 py-2.5">Trend</th>
                  <th className="px-4 py-2.5 text-right">Globe</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {statistics.geoRiskMatrix.map((row) => (
                  <tr key={row.regionId} className="hover:bg-slate-900/50">
                    <td className="px-4 py-2.5">
                      <span className="font-medium text-white">{row.country}</span>
                      <span className="ml-2 text-slate-400">· {row.topCity}</span>
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-slate-200">{row.attackVolume}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-slate-200">{row.uniqueAttackerIps}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-cyan-300">{row.targetedAssets}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-emerald-400">{row.blockedIps}</td>
                    <td className="px-4 py-2.5 text-right font-mono font-semibold text-orange-300">
                      {row.avgRiskScore}/100
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[11px]">
                      {row.riskTrend === 'rising' ? (
                        <span className="inline-flex items-center gap-1 text-red-400">
                          <TrendingUp className="h-3.5 w-3.5" aria-hidden="true" />+{row.trendDeltaPct}%
                        </span>
                      ) : row.riskTrend === 'declining' ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400">
                          <TrendingDown className="h-3.5 w-3.5" aria-hidden="true" />{row.trendDeltaPct}%
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-amber-300">
                          <Minus className="h-3.5 w-3.5" aria-hidden="true" />+{row.trendDeltaPct}%
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedEntity({kind: 'region', regionId: row.regionId});
                          setActiveTab('globe');
                          flyTo(row.latitude, row.longitude, 3_600_000, row.country);
                        }}
                        className="inline-flex items-center gap-1 border border-slate-700 bg-[#0B1221] px-2 py-1 text-[11px] text-cyan-300 hover:border-cyan-400"
                      >
                        <Crosshair className="h-3 w-3" aria-hidden="true" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Bottom ASN & Anonymization Split */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <section className="border border-slate-800 bg-[#080E1C] p-4">
            <h2 className="text-xs font-semibold text-slate-300">Top Suspicious Autonomous Systems (ASNs)</h2>
            <div className="mt-3 divide-y divide-slate-800/80">
              {statistics.topAsns.map((item) => (
                <div key={item.asn} className="flex items-center justify-between py-2 text-xs">
                  <div>
                    <span className="font-mono text-cyan-300">{item.asn}</span>
                    <span className="ml-2 text-slate-300">{item.asnName}</span>
                  </div>
                  <div className="font-mono text-[11px] text-slate-400">
                    {item.events} events · Avg Risk <span className="text-orange-300">{item.avgRisk}</span>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="border border-slate-800 bg-[#080E1C] p-4">
            <h2 className="text-xs font-semibold text-slate-300">Network Infrastructure &amp; Anonymization Breakdown</h2>
            <div className="mt-3 space-y-2.5">
              {statistics.connectionTypeBreakdown.map((item) => {
                const pct = Math.round((item.count / Math.max(1, statistics.activeThreats)) * 100);
                return (
                  <div key={item.type} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="uppercase text-slate-300">{item.type}</span>
                      <span className="font-mono text-cyan-300">
                        {item.count} ({pct}%)
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-800">
                      <div className="h-1.5 bg-cyan-400" style={{width: `${Math.min(100, pct)}%`}} />
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
