import {useForensicsStore} from '../store/useForensicsStore';

export function KpiStrip() {
  const statistics = useForensicsStore((s) => s.statistics);
  const leftSidebarOpen = useForensicsStore((s) => s.leftSidebarOpen);
  const selectedEntity = useForensicsStore((s) => s.selectedEntity);

  if (!statistics) return null;

  const cards = [
    {label: 'Active Threats', value: String(statistics.activeThreats), accent: 'text-cyan-300'},
    {label: 'Critical Alerts', value: String(statistics.criticalAlerts), accent: 'text-red-400'},
    {label: 'Attacked Assets', value: String(statistics.attackedAssets), accent: 'text-orange-300'},
    {label: 'Suspicious IPs', value: String(statistics.suspiciousIps), accent: 'text-amber-300'},
    {label: 'Blocked IPs', value: String(statistics.blockedIps), accent: 'text-emerald-400'},
    {label: 'Exfil Volume', value: `${statistics.exfiltrationVolumeGb.toFixed(2)} GB`, accent: 'text-purple-300'},
  ];

  return (
    <section
      aria-label="Global Threat KPIs"
      data-testid="kpi-strip"
      className={`pointer-events-auto absolute top-3 z-20 hidden md:grid grid-cols-6 gap-2 transition-all ${
        leftSidebarOpen ? 'left-[19rem]' : 'left-44'
      } ${selectedEntity ? 'right-[25.5rem]' : 'right-3'}`}
    >
      {cards.map((card) => (
        <div
          key={card.label}
          className="border border-slate-800/90 bg-[#070B14]/90 px-3 py-2"
        >
          <div className="truncate text-[11px] text-slate-400">{card.label}</div>
          <div className={`mt-0.5 font-mono text-base font-semibold leading-tight ${card.accent}`}>
            {card.value}
          </div>
        </div>
      ))}
    </section>
  );
}
