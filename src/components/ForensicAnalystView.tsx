import {useState} from 'react';
import {AlertCircle, CheckCircle2, Info, Send, Shield, Sparkles} from 'lucide-react';
import {useForensicsStore} from '../store/useForensicsStore';
import {APPROX_LOCATION_DISCLAIMER, type ForensicAiResponse} from '../types/forensics';

const SUGGESTED_QUESTIONS = [
  'What happened in the last 24 hours?',
  'Which IPs are most suspicious?',
  'Explain this brute-force attack.',
  'Which internal systems may be compromised?',
  'Show all critical alerts near Mumbai.',
  'Create an investigation report for case #12.',
  'What is the likely attack chain?',
  'What evidence is missing?',
];

export function ForensicAnalystView() {
  const selectedEntity = useForensicsStore((s) => s.selectedEntity);
  const activeCaseId = useForensicsStore((s) => s.activeCaseId);
  const filters = useForensicsStore((s) => s.filters);
  const events = useForensicsStore((s) => s.events);

  const [question, setQuestion] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<ForensicAiResponse | null>(null);
  const [lastAsked, setLastAsked] = useState<string | null>(null);

  const runQuery = async (promptText: string) => {
    const trimmed = promptText.trim();
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    setLastAsked(trimmed);

    const selectedEventId = selectedEntity?.kind === 'event' ? selectedEntity.eventId : null;
    const selectedIp =
      selectedEntity?.kind === 'ip'
        ? selectedEntity.ip
        : selectedEventId
          ? events.find((e) => e.id === selectedEventId)?.sourceIp ?? null
          : null;

    try {
      const res = await fetch('/api/analysis/query', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          question: trimmed,
          selectedEventId,
          selectedCaseId: activeCaseId,
          selectedIp,
          filters,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Forensic AI request failed');
        setAnalysis(null);
      } else {
        setAnalysis(data);
      }
    } catch {
      setError('Unable to reach server-side Forensic Analyst endpoint.');
      setAnalysis(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="h-full w-full overflow-y-auto bg-[#050811] p-6 text-slate-200">
      <div className="mx-auto max-w-5xl space-y-6">
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-cyan-400" aria-hidden="true" />
              <h1 className="text-lg font-bold text-white">Forensic Analyst Assistant</h1>
            </div>
            <p className="mt-1 text-xs text-slate-400">
              Grounded DFIR analysis across active telemetry, IP intelligence, protected assets, and case evidence. Strictly separates verified evidence, correlation inferences, and DEMO DATA.
            </p>
          </div>
          <div className="font-mono text-[11px] text-slate-400">
            Context: {events.length} events · Active Case {activeCaseId ?? 'None'}
          </div>
        </div>

        {/* Prompt Input & Quick Questions */}
        <section className="space-y-3 border border-slate-800 bg-[#080E1C] p-5">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void runQuery(question);
            }}
            className="flex gap-2"
          >
            <input
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Ask a digital forensics question grounded in current telemetry…"
              aria-label="Forensic AI question"
              className="flex-1 border border-slate-700 bg-[#050811] px-3.5 py-2.5 text-sm text-white placeholder-slate-500 focus:border-cyan-400 focus:outline-none"
            />
            <button
              type="submit"
              disabled={loading || !question.trim()}
              className="flex items-center gap-1.5 bg-cyan-500 px-5 py-2.5 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-40 whitespace-nowrap"
            >
              <Send className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{loading ? 'Analyzing…' : 'Analyze'}</span>
            </button>
          </form>

          <div className="flex flex-wrap gap-1.5">
            {SUGGESTED_QUESTIONS.map((q) => (
              <button
                key={q}
                type="button"
                disabled={loading}
                onClick={() => {
                  setQuestion(q);
                  void runQuery(q);
                }}
                className="border border-slate-800 bg-[#0B1221] px-2.5 py-1.5 text-xs text-slate-300 hover:border-cyan-400 hover:text-cyan-200 transition-colors"
              >
                {q}
              </button>
            ))}
          </div>
        </section>

        {error && (
          <div className="flex items-start gap-2.5 border border-red-500/50 bg-red-500/10 p-4 text-xs text-red-200">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" aria-hidden="true" />
            <div>
              <div className="font-semibold text-red-100">Analysis Unavailable</div>
              <p className="mt-0.5">{error}</p>
            </div>
          </div>
        )}

        {loading && (
          <div className="space-y-3 border border-slate-800 bg-[#080E1C] p-6">
            <div className="h-4 w-1/3 animate-pulse bg-slate-800" />
            <div className="h-3 w-full animate-pulse bg-slate-800/80" />
            <div className="h-3 w-5/6 animate-pulse bg-slate-800/80" />
            <div className="h-3 w-2/3 animate-pulse bg-slate-800/80" />
          </div>
        )}

        {analysis && !loading && (
          <article className="space-y-5 border border-slate-800 bg-[#080E1C] p-6 text-xs">
            {/* Mandatory Attribution & Demo Notice */}
            <div className="flex items-start gap-2 border border-amber-500/40 bg-amber-500/10 p-3 text-[11px] text-amber-200">
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
              <div>
                <p className="font-semibold text-amber-100">{analysis.demoDataNotice}</p>
                <p className="mt-0.5">{APPROX_LOCATION_DISCLAIMER}</p>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div>
                <div className="text-[11px] text-slate-500">Query: {lastAsked}</div>
                <h2 className="mt-0.5 text-base font-semibold text-white">Forensic Assessment Brief</h2>
              </div>
              <div className="font-mono text-xs text-cyan-300">
                Confidence: <span className="uppercase font-semibold">{analysis.confidenceLevel}</span>
              </div>
            </div>

            <section>
              <h3 className="font-semibold text-white">Incident Summary</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-slate-200">{analysis.summary}</p>
            </section>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <section className="border border-slate-800 bg-[#050811] p-4">
                <h3 className="flex items-center gap-1.5 font-semibold text-emerald-300">
                  <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                  Verified Evidence (Telemetry Facts)
                </h3>
                <ul className="mt-2 list-disc space-y-1 pl-4 text-slate-300">
                  {analysis.verifiedEvidence.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              </section>

              <section className="border border-slate-800 bg-[#050811] p-4">
                <h3 className="flex items-center gap-1.5 font-semibold text-amber-300">
                  <Shield className="h-3.5 w-3.5" aria-hidden="true" />
                  Correlation-Based Inferences
                </h3>
                <ul className="mt-2 list-disc space-y-1 pl-4 text-slate-300">
                  {analysis.correlationInferences.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              </section>
            </div>

            <section>
              <h3 className="font-semibold text-white">Likely Attack Chain</h3>
              <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-slate-300">
                {analysis.likelyAttackChain.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
            </section>

            <section>
              <h3 className="font-semibold text-white">Indicators of Compromise (IoCs)</h3>
              <div className="mt-2 overflow-x-auto border border-slate-800">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-800 bg-[#0B1221] text-[11px] text-slate-400">
                    <tr>
                      <th className="px-3 py-2">Type</th>
                      <th className="px-3 py-2">Value</th>
                      <th className="px-3 py-2">Context</th>
                      <th className="px-3 py-2">Origin</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {analysis.indicatorsOfCompromise.map((ioc, i) => (
                      <tr key={i}>
                        <td className="px-3 py-2 font-mono text-cyan-300">{ioc.type}</td>
                        <td className="px-3 py-2 font-mono text-orange-300">{ioc.value}</td>
                        <td className="px-3 py-2 text-slate-300">{ioc.context}</td>
                        <td className="px-3 py-2 font-mono text-[10px] text-amber-300">
                          {ioc.isDemoData ? 'DEMO DATA' : 'INGESTED'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <section className="border border-slate-800 bg-[#050811] p-4">
                <h3 className="font-semibold text-white">Risk Assessment</h3>
                <p className="mt-1.5 leading-relaxed text-slate-300">{analysis.riskAssessment}</p>
              </section>

              <section className="border border-slate-800 bg-[#050811] p-4">
                <h3 className="font-semibold text-orange-300">Evidence Gaps &amp; Additional Logs Needed</h3>
                <ul className="mt-1.5 list-disc space-y-1 pl-4 text-slate-300">
                  {analysis.evidenceGaps.map((gap, i) => (
                    <li key={i}>{gap}</li>
                  ))}
                </ul>
              </section>
            </div>

            <section>
              <h3 className="font-semibold text-emerald-300">Recommended Containment &amp; Forensic Actions</h3>
              <ol className="mt-2 list-decimal space-y-1 pl-5 text-slate-200">
                {analysis.recommendedActions.map((act, i) => (
                  <li key={i}>{act}</li>
                ))}
              </ol>
            </section>

            <div className="border-t border-slate-800 pt-3 font-mono text-[11px] text-slate-500">
              Sources referenced: {analysis.sourcesUsed.join(', ') || 'Active telemetry snapshot'} · Generated{' '}
              {new Date(analysis.generatedAt).toLocaleString()}
            </div>
          </article>
        )}
      </div>
    </main>
  );
}
