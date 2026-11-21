import {useState, useRef, useEffect} from 'react';
import {
  AlertCircle,
  Bot,
  CheckCircle2,
  Copy,
  Download,
  Info,
  RotateCcw,
  Send,
  Shield,
  Sparkles,
  User,
  FileText,
  MessageSquare,
} from 'lucide-react';
import {useForensicsStore} from '../store/useForensicsStore';
import {APPROX_LOCATION_DISCLAIMER, type ForensicAiResponse} from '../types/forensics';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  structured?: ForensicAiResponse;
  modelUsed?: string;
}

const INITIAL_GREETING: ChatMessage = {
  id: 'msg-welcome',
  role: 'assistant',
  content: `**CyberTrace Globe DFIR Assistant Online**

I am your Principal Digital Forensics & Incident Response (DFIR) analyst grounded directly in your active operational telemetry.

**Active Investigation Context:**
- Real-time ingestion stream & correlated threat events
- Multi-vector detection (SSH, RDP brute force, port sweeps, C2 beacons, data exfiltration)
- Enriched IP intelligence with confidence radii & anonymizer scoring
- Protected target assets & active investigation cases

How can I assist your investigation today? Click a quick inquiry below or type any question.`,
  timestamp: new Date().toISOString(),
};

const SUGGESTED_QUESTIONS = [
  'Summarize all active threats and critical alerts',
  'Investigate high-velocity brute-force attempts',
  'Check for impossible travel & anomalous logins',
  'Which internal systems may be compromised?',
  'List all high-risk Indicators of Compromise (IoCs)',
  'Recommend immediate firewall & containment actions',
];

export function ForensicAnalystView() {
  const selectedEntity = useForensicsStore((s) => s.selectedEntity);
  const activeCaseId = useForensicsStore((s) => s.activeCaseId);
  const filters = useForensicsStore((s) => s.filters);
  const events = useForensicsStore((s) => s.events);
  const assets = useForensicsStore((s) => s.assets);
  const addCaseNote = useForensicsStore((s) => s.addCaseNote);

  const [activeMode, setActiveMode] = useState<'chat' | 'structured'>('chat');
  const [messages, setMessages] = useState<ChatMessage[]>([INITIAL_GREETING]);
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Structured analysis state for the dedicated report tab
  const [structuredData, setStructuredData] = useState<ForensicAiResponse | null>(null);
  const [structuredLoading, setStructuredLoading] = useState(false);
  const [lastStructuredQuery, setLastStructuredQuery] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({behavior: 'smooth'});
  }, [messages, loading]);

  const getEntityContext = () => {
    const selectedEventId = selectedEntity?.kind === 'event' ? selectedEntity.eventId : null;
    const selectedIp =
      selectedEntity?.kind === 'ip'
        ? selectedEntity.ip
        : selectedEventId
          ? events.find((e) => e.id === selectedEventId)?.sourceIp ?? null
          : null;
    return {selectedEventId, selectedIp, selectedCaseId: activeCaseId};
  };

  const handleSendChat = async (userText: string) => {
    const text = userText.trim();
    if (!text || loading) return;

    const userMessage: ChatMessage = {
      id: `msg-${Date.now()}-user`,
      role: 'user',
      content: text,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInputText('');
    setLoading(true);
    setError(null);

    const {selectedEventId, selectedIp, selectedCaseId} = getEntityContext();

    try {
      const res = await fetch('/api/analysis/chat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          message: text,
          messages: messages.map((m) => ({role: m.role, content: m.content})),
          selectedEventId,
          selectedCaseId,
          selectedIp,
          filters,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Forensic AI assistant encountered an error.');
        setMessages((prev) => [
          ...prev,
          {
            id: `msg-${Date.now()}-err`,
            role: 'assistant',
            content: `**Analysis Warning:** ${data.error || 'Unable to complete response. Please check server connection.'}`,
            timestamp: new Date().toISOString(),
          },
        ]);
      } else {
        const assistantMessage: ChatMessage = {
          id: `msg-${Date.now()}-ai`,
          role: 'assistant',
          content: data.reply,
          timestamp: data.timestamp || new Date().toISOString(),
          modelUsed: data.modelUsed,
        };
        setMessages((prev) => [...prev, assistantMessage]);
      }
    } catch {
      setError('Network error connecting to Forensic AI service.');
    } finally {
      setLoading(false);
    }
  };

  const runStructuredAnalysis = async (queryText: string) => {
    const text = queryText.trim();
    if (!text || structuredLoading) return;

    setStructuredLoading(true);
    setError(null);
    setLastStructuredQuery(text);

    const {selectedEventId, selectedIp, selectedCaseId} = getEntityContext();

    try {
      const res = await fetch('/api/analysis/query', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          question: text,
          selectedEventId,
          selectedCaseId,
          selectedIp,
          filters,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Structured analysis failed.');
        setStructuredData(null);
      } else {
        setStructuredData(data);
      }
    } catch {
      setError('Unable to reach structured forensic analysis endpoint.');
    } finally {
      setStructuredLoading(false);
    }
  };

  const handleExportChat = () => {
    const mdLines = [
      `# CyberTrace Globe — Forensic Analyst Chat Transcript`,
      ``,
      `- Generated: ${new Date().toISOString()}`,
      `- Context: ${events.length} Active Events | ${assets.length} Protected Assets`,
      `- Active Case: ${activeCaseId ?? 'Unlinked'}`,
      ``,
      `> **Forensic Geolocation Notice:** ${APPROX_LOCATION_DISCLAIMER}`,
      ``,
      `---`,
      ``,
    ];

    messages.forEach((m) => {
      mdLines.push(`### [${m.role === 'user' ? 'Analyst' : 'Gemini DFIR'}] — ${new Date(m.timestamp).toLocaleTimeString()}`);
      mdLines.push(``);
      mdLines.push(m.content);
      mdLines.push(``);
      mdLines.push(`---`);
      mdLines.push(``);
    });

    const blob = new Blob([mdLines.join('\n')], {type: 'text/markdown'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic-chat-transcript-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSaveToCase = async (content: string) => {
    if (!activeCaseId) {
      alert('No active case selected. Please select a case in the Cases workspace first.');
      return;
    }
    await addCaseNote(activeCaseId, `[AI Forensic Assessment]\n${content.slice(0, 2000)}`);
  };

  return (
    <main className="flex h-full w-full flex-col overflow-hidden bg-[#070B10] text-[#E6EDF5]">
      {/* Top Header & Context Strip */}
      <header className="z-10 flex shrink-0 items-center justify-between border-b border-white/5 bg-[#0D141C] px-6 py-3.5">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-cyan-500/10 text-cyan-400">
            <Bot className="h-5 w-5" aria-hidden="true" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-semibold tracking-wide text-white">Gemini DFIR Forensic Chatbot</h1>
              <span className="rounded bg-emerald-500/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-emerald-300">
                AI SENSOR CONNECTED
              </span>
            </div>
            <p className="text-[11px] text-[#9FB0C3]">
              Grounded DFIR dialogue across {events.length} active events · {assets.length} assets · Case {activeCaseId ?? 'None'}
            </p>
          </div>
        </div>

        {/* Mode Switcher & Tools */}
        <div className="flex items-center gap-2">
          <div className="flex rounded border border-white/10 bg-[#070B10] p-0.5">
            <button
              type="button"
              onClick={() => setActiveMode('chat')}
              className={`flex items-center gap-1.5 rounded px-3 py-1 text-xs font-medium transition-colors ${
                activeMode === 'chat'
                  ? 'bg-cyan-500/20 text-cyan-300 font-semibold'
                  : 'text-[#9FB0C3] hover:text-white'
              }`}
            >
              <MessageSquare className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Interactive Chat</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveMode('structured');
                if (!structuredData && !structuredLoading) {
                  void runStructuredAnalysis('Provide comprehensive incident summary and attack chain');
                }
              }}
              className={`flex items-center gap-1.5 rounded px-3 py-1 text-xs font-medium transition-colors ${
                activeMode === 'structured'
                  ? 'bg-cyan-500/20 text-cyan-300 font-semibold'
                  : 'text-[#9FB0C3] hover:text-white'
              }`}
            >
              <FileText className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Assessment Brief</span>
            </button>
          </div>

          <button
            type="button"
            onClick={handleExportChat}
            className="flex items-center gap-1 rounded border border-white/10 bg-[#16202B] px-2.5 py-1 text-xs text-[#9FB0C3] hover:border-cyan-400 hover:text-white transition-colors"
            title="Export conversation as Markdown"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            <span className="hidden sm:inline">Export</span>
          </button>

          <button
            type="button"
            onClick={() => setMessages([INITIAL_GREETING])}
            className="flex items-center gap-1 rounded border border-white/10 bg-[#16202B] px-2.5 py-1 text-xs text-[#9FB0C3] hover:text-white transition-colors"
            title="Reset conversation"
          >
            <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </div>
      </header>

      {/* Mandatory Forensic Location Disclaimer Banner */}
      <div className="shrink-0 border-b border-amber-500/30 bg-amber-500/10 px-6 py-2 text-[11px] text-amber-200">
        <div className="flex items-center gap-2">
          <Info className="h-3.5 w-3.5 shrink-0 text-amber-400" aria-hidden="true" />
          <span>
            <strong className="text-amber-100">Forensic Notice:</strong> {APPROX_LOCATION_DISCLAIMER}
          </span>
        </div>
      </div>

      {/* ── MODE 1: INTERACTIVE CONVERSATIONAL CHAT ── */}
      {activeMode === 'chat' && (
        <div className="flex flex-1 flex-col overflow-hidden">
          {/* Chat Messages Scrollable Area */}
          <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex gap-3 max-w-4xl ${msg.role === 'user' ? 'ml-auto flex-row-reverse' : ''}`}
              >
                {/* Avatar */}
                <div
                  className={`flex h-7 w-7 shrink-0 items-center justify-center rounded ${
                    msg.role === 'user'
                      ? 'bg-cyan-500 text-slate-950 font-semibold'
                      : 'border border-cyan-500/40 bg-cyan-500/10 text-cyan-300'
                  }`}
                >
                  {msg.role === 'user' ? (
                    <User className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <Bot className="h-4 w-4" aria-hidden="true" />
                  )}
                </div>

                {/* Message Bubble */}
                <div
                  className={`flex flex-col space-y-1.5 rounded p-4 text-xs leading-relaxed ${
                    msg.role === 'user'
                      ? 'border border-cyan-500/30 bg-[#16202B] text-white shadow-lg'
                      : 'border border-white/5 bg-[#0D141C] text-[#E6EDF5] shadow-lg'
                  }`}
                >
                  <div className="flex items-center justify-between gap-4 text-[10px] text-[#9FB0C3]">
                    <span className="font-semibold uppercase tracking-wider">
                      {msg.role === 'user' ? 'SOC Analyst' : 'Gemini DFIR Analyst'}
                    </span>
                    <span className="font-mono">{new Date(msg.timestamp).toLocaleTimeString()}</span>
                  </div>

                  <div className="whitespace-pre-wrap font-sans text-xs text-slate-200 leading-relaxed space-y-2">
                    {msg.content}
                  </div>

                  {msg.role === 'assistant' && msg.id !== 'msg-welcome' && (
                    <div className="mt-2 flex items-center justify-between border-t border-white/5 pt-2 text-[10px] text-[#5A6A7A]">
                      <span>{msg.modelUsed ? `Model: ${msg.modelUsed}` : 'Grounded Telemetry'}</span>
                      {activeCaseId && (
                        <button
                          type="button"
                          onClick={() => void handleSaveToCase(msg.content)}
                          className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition-colors"
                        >
                          <Copy className="h-3 w-3" aria-hidden="true" />
                          <span>Save to Case #{activeCaseId}</span>
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}

            {loading && (
              <div className="flex gap-3 max-w-xl">
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded border border-cyan-500/40 bg-cyan-500/10 text-cyan-300">
                  <Bot className="h-4 w-4 animate-pulse" aria-hidden="true" />
                </div>
                <div className="flex items-center gap-2 rounded border border-white/5 bg-[#0D141C] px-4 py-3 text-xs text-cyan-300">
                  <span className="inline-block h-2 w-2 animate-ping rounded-full bg-cyan-400" />
                  <span>Analyzing active telemetry and correlating kill chain…</span>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Quick Questions Strip */}
          <div className="shrink-0 border-t border-white/5 bg-[#0D141C] px-6 py-2.5">
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
              <span className="shrink-0 text-[11px] font-semibold text-[#5A6A7A]">Inquiries:</span>
              {SUGGESTED_QUESTIONS.map((q) => (
                <button
                  key={q}
                  type="button"
                  disabled={loading}
                  onClick={() => void handleSendChat(q)}
                  className="shrink-0 rounded border border-white/5 bg-[#16202B] px-2.5 py-1 text-[11px] text-[#9FB0C3] hover:border-cyan-400 hover:text-white transition-colors disabled:opacity-40"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>

          {/* Chat Input Bar */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void handleSendChat(inputText);
            }}
            className="shrink-0 border-t border-white/5 bg-[#070B10] p-4"
          >
            <div className="flex gap-2">
              <input
                type="text"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Ask Gemini DFIR to correlate footprints, identify attacker ASNs, or draft response steps…"
                disabled={loading}
                className="flex-1 rounded border border-white/10 bg-[#0D141C] px-4 py-2.5 text-xs text-white placeholder-[#5A6A7A] focus:border-cyan-400 focus:outline-none"
              />
              <button
                type="submit"
                disabled={loading || !inputText.trim()}
                className="flex items-center gap-1.5 rounded bg-cyan-500 px-5 py-2.5 text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-40 transition-colors"
              >
                <Send className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Send</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ── MODE 2: STRUCTURED DFIR ASSESSMENT BRIEF ── */}
      {activeMode === 'structured' && (
        <div className="flex-1 overflow-y-auto px-6 py-6">
          <div className="mx-auto max-w-4xl space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3">
              <div>
                <h2 className="text-base font-semibold text-white">Automated Forensic Incident Assessment</h2>
                <p className="text-xs text-[#9FB0C3]">
                  Query: {lastStructuredQuery ?? 'General incident overview'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => void runStructuredAnalysis('Re-analyze all active threats and correlate kill chain')}
                disabled={structuredLoading}
                className="flex items-center gap-1.5 rounded border border-cyan-500/50 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-40"
              >
                <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
                <span>{structuredLoading ? 'Re-evaluating…' : 'Re-Evaluate Telemetry'}</span>
              </button>
            </div>

            {error && (
              <div className="flex items-start gap-2.5 rounded border border-red-500/50 bg-red-500/10 p-4 text-xs text-red-200">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" aria-hidden="true" />
                <div>
                  <div className="font-semibold text-red-100">Analysis Error</div>
                  <p className="mt-0.5">{error}</p>
                </div>
              </div>
            )}

            {structuredLoading && (
              <div className="space-y-3 rounded border border-white/5 bg-[#0D141C] p-6">
                <div className="h-4 w-1/3 animate-pulse bg-[#16202B]" />
                <div className="h-3 w-full animate-pulse bg-[#16202B]/80" />
                <div className="h-3 w-5/6 animate-pulse bg-[#16202B]/80" />
                <div className="h-3 w-2/3 animate-pulse bg-[#16202B]/80" />
              </div>
            )}

            {structuredData && !structuredLoading && (
              <article className="space-y-5 text-xs">
                {/* Executive Summary */}
                <section className="rounded border border-white/5 bg-[#0D141C] p-5">
                  <div className="flex items-center justify-between border-b border-white/5 pb-2">
                    <h3 className="font-semibold text-white">Executive Incident Summary</h3>
                    <span className="font-mono text-cyan-400 uppercase">Confidence: {structuredData.confidenceLevel}</span>
                  </div>
                  <p className="mt-3 text-sm leading-relaxed text-slate-200">{structuredData.summary}</p>
                </section>

                {/* Evidence & Inferences Split */}
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <section className="rounded border border-white/5 bg-[#0D141C] p-4">
                    <h3 className="flex items-center gap-1.5 font-semibold text-emerald-300">
                      <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                      Verified Telemetry Facts
                    </h3>
                    <ul className="mt-2 list-disc space-y-1 pl-4 text-slate-300">
                      {structuredData.verifiedEvidence.map((item, i) => (
                        <li key={i}>{item}</li>
                      ))}
                    </ul>
                  </section>

                  <section className="rounded border border-white/5 bg-[#0D141C] p-4">
                    <h3 className="flex items-center gap-1.5 font-semibold text-amber-300">
                      <Shield className="h-3.5 w-3.5" aria-hidden="true" />
                      Correlation Inferences
                    </h3>
                    <ul className="mt-2 list-disc space-y-1 pl-4 text-slate-300">
                      {structuredData.correlationInferences.map((item, i) => (
                        <li key={i}>{item}</li>
                      ))}
                    </ul>
                  </section>
                </div>

                {/* Attack Chain */}
                <section className="rounded border border-white/5 bg-[#0D141C] p-4">
                  <h3 className="font-semibold text-white">Inferred Kill-Chain Progression</h3>
                  <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-slate-300">
                    {structuredData.likelyAttackChain.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                </section>

                {/* IoCs Table */}
                <section className="rounded border border-white/5 bg-[#0D141C] p-4">
                  <h3 className="font-semibold text-white">Extracted Indicators of Compromise (IoCs)</h3>
                  <div className="mt-2 overflow-x-auto border border-white/5 rounded">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-white/5 bg-[#16202B] text-[11px] text-[#9FB0C3]">
                        <tr>
                          <th className="px-3 py-2">Type</th>
                          <th className="px-3 py-2">Indicator</th>
                          <th className="px-3 py-2">Context</th>
                          <th className="px-3 py-2">Origin</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5">
                        {structuredData.indicatorsOfCompromise.map((ioc, i) => (
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

                {/* Recommended Actions */}
                <section className="rounded border border-emerald-500/30 bg-[#0D141C] p-4">
                  <h3 className="font-semibold text-emerald-300">Actionable Response &amp; Containment Steps</h3>
                  <ol className="mt-2 list-decimal space-y-1 pl-5 text-slate-200">
                    {structuredData.recommendedActions.map((act, i) => (
                      <li key={i}>{act}</li>
                    ))}
                  </ol>
                </section>
              </article>
            )}
          </div>
        </div>
      )}
    </main>
  );
}
