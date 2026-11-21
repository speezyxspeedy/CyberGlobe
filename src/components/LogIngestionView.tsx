import {useState} from 'react';
import {CheckCircle2, FileUp, Globe, Play} from 'lucide-react';
import {
  formatCategoryLabel,
  severityTextColor,
  useForensicsStore,
} from '../store/useForensicsStore';
import type {ThreatEvent} from '../types/forensics';

const SAMPLE_LOGS: Record<string, {label: string; format: string; content: string}> = {
  ssh: {
    label: 'SSH Auth Brute-Force',
    format: 'ssh',
    content: [
      'Nov 20 22:41:02 mum-ssh-01 sshd[9112]: Failed password for invalid user admin from 203.0.113.45 port 54901 ssh2',
      'Nov 20 22:41:03 mum-ssh-01 sshd[9114]: Failed password for root from 203.0.113.45 port 54904 ssh2',
      'Nov 20 22:41:06 mum-ssh-01 sshd[9118]: Failed password for deploy-ops from 198.51.100.51 port 41890 ssh2',
    ].join('\n'),
  },
  firewall: {
    label: 'UFW Firewall Port Scan',
    format: 'firewall',
    content: [
      'Nov 20 22:44:10 edge-fw kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.204 DST=10.20.4.18 LEN=60 PROTO=TCP SPT=51204 DPT=5432',
      'Nov 20 22:44:11 edge-fw kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.204 DST=10.20.4.18 LEN=60 PROTO=TCP SPT=51205 DPT=6379',
      'Nov 20 22:44:12 edge-fw kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.142 DST=10.32.8.44 LEN=60 PROTO=TCP SPT=49811 DPT=22',
    ].join('\n'),
  },
  jsonl: {
    label: 'JSONL Exfiltration + C2',
    format: 'jsonl',
    content: [
      '{"timestamp":"2026-11-20T22:47:10Z","source_ip":"192.0.2.211","destination_ip":"10.32.8.44","destination_port":443,"protocol":"HTTPS","bytes_transferred":740000000,"event_type":"data_exfiltration","action":"EGRESS_SPIKE"}',
      '{"timestamp":"2026-11-20T22:48:02Z","source_ip":"198.51.100.77","destination_ip":"10.60.19.87","destination_port":8443,"protocol":"TLS","domain":"cdn-telemetry-sync.example.net","event_type":"malware_c2","action":"BEACON"}',
    ].join('\n'),
  },
  nginx_dns: {
    label: 'Nginx + DNS Mixed',
    format: 'auto',
    content: [
      '192.0.2.134 - - [20/Nov/2026:22:49:10 +0000] "GET /api/v2/export/invoices HTTP/1.1" 403 1924 "-" "python-requests/2.32"',
      '20-Nov-2026 22:49:25 client 198.51.100.77#53102: query: c2-staging-node.example.net IN A',
    ].join('\n'),
  },
};

export function LogIngestionView() {
  const ingestLogs = useForensicsStore((s) => s.ingestLogs);
  const setActiveTab = useForensicsStore((s) => s.setActiveTab);
  const setSelectedEntity = useForensicsStore((s) => s.setSelectedEntity);
  const flyTo = useForensicsStore((s) => s.flyTo);
  const userRole = useForensicsStore((s) => s.userRole);

  const [format, setFormat] = useState('auto');
  const [source, setSource] = useState('analyst_console');
  const [rawLogs, setRawLogs] = useState(SAMPLE_LOGS.ssh.content);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{
    ingestedCount: number;
    evidenceSha256: string;
    events: ThreatEvent[];
  } | null>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setSource(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      setRawLogs(typeof reader.result === 'string' ? reader.result : '');
    };
    reader.readAsText(file);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawLogs.trim()) return;
    setBusy(true);
    const res = await ingestLogs(rawLogs, format, source);
    setBusy(false);
    if (res) setResult(res);
  };

  return (
    <main className="h-full w-full overflow-y-auto bg-[#050811] p-6 text-slate-200">
      <div className="mx-auto max-w-5xl space-y-6">
        <div className="border-b border-slate-800 pb-4">
          <h1 className="text-lg font-bold text-white">Forensic Log Ingestion &amp; Normalization</h1>
          <p className="mt-1 text-xs text-slate-400">
            Ingest Firewall, Nginx/Apache, SSH auth, Windows Security, DNS, NetFlow/Zeek, CSV, JSON, JSONL, or Syslog telemetry. Every batch is preserved with a SHA-256 evidence digest and streamed live to the 3D Globe.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 border border-slate-800 bg-[#080E1C] p-5 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] text-slate-400">Load Sample:</span>
              {Object.entries(SAMPLE_LOGS).map(([key, sample]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => {
                    setFormat(sample.format);
                    setRawLogs(sample.content);
                  }}
                  className="border border-slate-700 bg-[#0B1221] px-2.5 py-1 text-[11px] text-slate-300 hover:border-cyan-400 hover:text-cyan-200"
                >
                  {sample.label}
                </button>
              ))}
            </div>

            <label className="cursor-pointer border border-cyan-500/50 bg-cyan-500/10 px-3 py-1.5 text-cyan-200 hover:bg-cyan-500/20">
              <span className="flex items-center gap-1.5 font-medium">
                <FileUp className="h-3.5 w-3.5" aria-hidden="true" />
                Upload Log File
              </span>
              <input
                type="file"
                accept=".log,.txt,.csv,.json,.jsonl"
                onChange={handleFileUpload}
                className="sr-only"
              />
            </label>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="log-format" className="block text-[11px] text-slate-400">
                Parser Format
              </label>
              <select
                id="log-format"
                value={format}
                onChange={(e) => setFormat(e.target.value)}
                className="mt-1 w-full border border-slate-700 bg-[#050811] px-2.5 py-2 text-xs text-white"
              >
                <option value="auto">Auto-Detect (Mixed)</option>
                <option value="ssh">SSH Auth Log</option>
                <option value="firewall">Firewall (UFW / iptables)</option>
                <option value="nginx">Nginx / Apache Access</option>
                <option value="dns">DNS Query Log</option>
                <option value="windows">Windows Security Event</option>
                <option value="netflow">NetFlow / Zeek</option>
                <option value="csv">CSV</option>
                <option value="json">JSON</option>
                <option value="jsonl">JSONL</option>
                <option value="syslog">Syslog</option>
              </select>
            </div>
            <div>
              <label htmlFor="log-source" className="block text-[11px] text-slate-400">
                Ingestion Source Label
              </label>
              <input
                id="log-source"
                type="text"
                value={source}
                onChange={(e) => setSource(e.target.value)}
                className="mt-1 w-full border border-slate-700 bg-[#050811] px-2.5 py-2 text-xs text-white"
              />
            </div>
          </div>

          <div>
            <label htmlFor="raw-log-input" className="block text-[11px] text-slate-400">
              Raw Telemetry Payload
            </label>
            <textarea
              id="raw-log-input"
              rows={8}
              value={rawLogs}
              onChange={(e) => setRawLogs(e.target.value)}
              className="mt-1 w-full border border-slate-700 bg-[#050811] p-3 font-mono text-xs text-slate-100 focus:border-cyan-400 focus:outline-none"
            />
          </div>

          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-500">
              Private internal destination IPs (RFC1918) are automatically masked in UI readouts.
            </span>
            <button
              type="submit"
              disabled={busy || userRole === 'Viewer' || !rawLogs.trim()}
              className="flex items-center gap-1.5 bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-40"
            >
              <Play className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{busy ? 'Parsing & Correlating…' : 'Parse & Ingest Logs'}</span>
            </button>
          </div>
        </form>

        {/* Ingestion Results */}
        {result && (
          <section className="space-y-3 border border-emerald-500/40 bg-[#080E1C] p-5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-emerald-300">
                <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                <span>Ingested {result.ingestedCount} Correlated Threat Event(s)</span>
              </div>
              <div className="font-mono text-[11px] text-slate-400">
                Evidence SHA-256: <span className="text-emerald-300">{result.evidenceSha256.slice(0, 24)}…</span>
              </div>
            </div>

            <div className="overflow-x-auto border border-slate-800">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 bg-[#0B1221] text-[11px] text-slate-400">
                  <tr>
                    <th className="px-3 py-2">Event Type</th>
                    <th className="px-3 py-2">Source IP</th>
                    <th className="px-3 py-2">Masked Target</th>
                    <th className="px-3 py-2">Protocol</th>
                    <th className="px-3 py-2 text-right">Risk Score</th>
                    <th className="px-3 py-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {result.events.map((ev) => (
                    <tr key={ev.id}>
                      <td className="px-3 py-2.5 text-white">{formatCategoryLabel(ev.eventType)}</td>
                      <td className="px-3 py-2.5 font-mono text-orange-300">{ev.sourceIp}</td>
                      <td className="px-3 py-2.5 font-mono text-slate-300">{ev.maskedDestinationIp}</td>
                      <td className="px-3 py-2.5 font-mono text-slate-400">
                        {ev.protocol}:{ev.destinationPort}
                      </td>
                      <td className={`px-3 py-2.5 text-right font-mono font-semibold ${severityTextColor(ev.severity)}`}>
                        {ev.riskScore}/100 ({ev.severity})
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedEntity({kind: 'event', eventId: ev.id});
                            setActiveTab('globe');
                            flyTo(ev.sourceLocation.latitude, ev.sourceLocation.longitude, 2_800_000, ev.sourceIp);
                          }}
                          className="inline-flex items-center gap-1 border border-slate-700 bg-[#0B1221] px-2.5 py-1 text-[11px] text-cyan-300 hover:border-cyan-400"
                        >
                          <Globe className="h-3 w-3" aria-hidden="true" />
                          <span>View on Globe</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
