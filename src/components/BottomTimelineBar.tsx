import {useEffect} from 'react';
import {
  Activity,
  Download,
  History,
  Pause,
  Play,
  Radio,
  X,
} from 'lucide-react';
import {
  selectFilteredEvents,
  severityTextColor,
  useForensicsStore,
} from '../store/useForensicsStore';
import {exportEventsToCsv} from '../lib/caseLogic';

const TIME_RANGES = [
  {hours: 1, label: '1h'},
  {hours: 6, label: '6h'},
  {hours: 24, label: '24h'},
  {hours: 168, label: '7d'},
];

export function BottomTimelineBar() {
  const events = useForensicsStore((s) => s.events);
  const filters = useForensicsStore((s) => s.filters);
  const layers = useForensicsStore((s) => s.layers);
  const setFilter = useForensicsStore((s) => s.setFilter);
  const timelineMode = useForensicsStore((s) => s.timelineMode);
  const setTimelineMode = useForensicsStore((s) => s.setTimelineMode);
  const replayProgress = useForensicsStore((s) => s.replayProgress);
  const setReplayProgress = useForensicsStore((s) => s.setReplayProgress);
  const isPlaying = useForensicsStore((s) => s.isPlaying);
  const setIsPlaying = useForensicsStore((s) => s.setIsPlaying);
  const playbackSpeed = useForensicsStore((s) => s.playbackSpeed);
  const setPlaybackSpeed = useForensicsStore((s) => s.setPlaybackSpeed);
  const alertFeedOpen = useForensicsStore((s) => s.alertFeedOpen);
  const setAlertFeedOpen = useForensicsStore((s) => s.setAlertFeedOpen);
  const setSelectedEntity = useForensicsStore((s) => s.setSelectedEntity);
  const fetchIpIntelligence = useForensicsStore((s) => s.fetchIpIntelligence);
  const flyTo = useForensicsStore((s) => s.flyTo);
  const selectedEntity = useForensicsStore((s) => s.selectedEntity);

  const filteredEvents = selectFilteredEvents(events, filters, layers, timelineMode, replayProgress);

  useEffect(() => {
    if (timelineMode !== 'replay' || !isPlaying) return;
    const timer = setInterval(() => {
      const current = useForensicsStore.getState().replayProgress;
      if (current >= 100) {
        setReplayProgress(5);
      } else {
        setReplayProgress(Math.min(100, current + 3 * playbackSpeed));
      }
    }, 650);
    return () => clearInterval(timer);
  }, [timelineMode, isPlaying, playbackSpeed, setReplayProgress]);

  const downloadFile = (content: string, filename: string, mime: string) => {
    const blob = new Blob([content], {type: mime});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      {/* Floating Live Alert Feed (anchored bottom-right when inspector is closed, or shifted left of inspector) */}
      {alertFeedOpen && (
        <section
          aria-label="Live Threat Alert Feed"
          data-testid="live-alert-feed"
          className={`absolute bottom-20 z-20 flex max-h-64 w-80 flex-col border border-slate-800/95 bg-[#070B14]/94 shadow-2xl transition-transform ${
            selectedEntity ? 'right-[25.5rem] hidden xl:flex' : 'right-3'
          }`}
        >
          <div className="flex items-center justify-between border-b border-slate-800 px-3 py-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-white">
              <Activity className="h-3.5 w-3.5 text-red-400" aria-hidden="true" />
              <span>Live Threat Feed ({filteredEvents.length})</span>
            </div>
            <button
              type="button"
              onClick={() => setAlertFeedOpen(false)}
              aria-label="Close live alert feed"
              className="p-0.5 text-slate-400 hover:text-white"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
          <div className="flex-1 divide-y divide-slate-800/80 overflow-y-auto">
            {filteredEvents.slice(0, 10).map((ev) => (
              <button
                key={ev.id}
                type="button"
                onClick={() => {
                  setSelectedEntity({kind: 'event', eventId: ev.id});
                  void fetchIpIntelligence(ev.sourceIp);
                  flyTo(ev.sourceLocation.latitude, ev.sourceLocation.longitude, 3_000_000, ev.sourceIp);
                }}
                className="w-full px-3 py-2 text-left hover:bg-slate-800/60 transition-colors"
              >
                <div className="flex items-center justify-between gap-2 text-[11px]">
                  <span className="truncate font-medium text-slate-100">{ev.title}</span>
                  <span className={`font-mono text-[10px] font-semibold uppercase shrink-0 ${severityTextColor(ev.severity)}`}>
                    {ev.severity}
                  </span>
                </div>
                <div className="mt-0.5 flex items-center justify-between font-mono text-[10px] text-slate-400">
                  <span>
                    {ev.sourceIp} → {ev.destinationLocation.city}
                  </span>
                  <span>Risk {ev.riskScore}</span>
                </div>
              </button>
            ))}
            {filteredEvents.length === 0 && (
              <div className="px-3 py-5 text-center text-xs text-slate-500">
                No threat events match the active filters.
              </div>
            )}
          </div>
        </section>
      )}

      {/* Bottom Timeline & Playback Control Bar */}
      <footer
        aria-label="Timeline and Playback Controls"
        className="absolute bottom-3 left-3 right-3 z-20 flex flex-wrap items-center justify-between gap-3 border border-slate-800/95 bg-[#070B14]/94 px-3.5 py-2 shadow-2xl"
      >
        {/* Live / Replay Mode Switch */}
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setTimelineMode('live')}
            className={`flex items-center gap-1.5 border px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap ${
              timelineMode === 'live'
                ? 'border-emerald-500/70 bg-emerald-500/15 text-emerald-300'
                : 'border-slate-800 bg-[#0B1221] text-slate-400 hover:text-white'
            }`}
          >
            <Radio className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Live Mode</span>
          </button>
          <button
            type="button"
            onClick={() => setTimelineMode('replay')}
            className={`flex items-center gap-1.5 border px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap ${
              timelineMode === 'replay'
                ? 'border-cyan-500/70 bg-cyan-500/15 text-cyan-300'
                : 'border-slate-800 bg-[#0B1221] text-slate-400 hover:text-white'
            }`}
          >
            <History className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Replay</span>
          </button>
        </div>

        {/* Playback Controls + Timeline Scrubber */}
        <div className="flex min-w-[220px] flex-1 items-center gap-2.5">
          <button
            type="button"
            onClick={() => {
              if (timelineMode === 'live') {
                setTimelineMode('replay');
              } else {
                setIsPlaying(!isPlaying);
              }
            }}
            aria-label={isPlaying ? 'Pause timeline replay' : 'Play timeline replay'}
            className="flex h-7 w-7 items-center justify-center border border-slate-700 bg-[#0B1221] text-cyan-300 hover:border-cyan-400"
          >
            {isPlaying ? <Pause className="h-3.5 w-3.5" aria-hidden="true" /> : <Play className="h-3.5 w-3.5" aria-hidden="true" />}
          </button>

          <input
            type="range"
            aria-label="Timeline replay scrubber"
            min={5}
            max={100}
            value={timelineMode === 'live' ? 100 : replayProgress}
            onChange={(e) => {
              if (timelineMode === 'live') setTimelineMode('replay');
              setReplayProgress(Number(e.target.value));
            }}
            className="flex-1 accent-cyan-400"
          />

          <button
            type="button"
            onClick={() => setPlaybackSpeed(playbackSpeed === 1 ? 2 : playbackSpeed === 2 ? 4 : 1)}
            aria-label="Change playback speed"
            className="border border-slate-800 bg-[#0B1221] px-2 py-1 font-mono text-[11px] text-slate-300 hover:border-cyan-500/60"
          >
            {playbackSpeed}x
          </button>

          <span className="hidden sm:inline font-mono text-[11px] text-slate-400 whitespace-nowrap">
            {filteredEvents.length} / {events.length} events
          </span>
        </div>

        {/* Time-range Selector & Quick Export */}
        <div className="flex items-center gap-2">
          <div className="flex items-center border border-slate-800 bg-[#0B1221]">
            {TIME_RANGES.map((tr) => (
              <button
                key={tr.label}
                type="button"
                onClick={() => setFilter('timeRangeHours', tr.hours)}
                className={`px-2 py-1 font-mono text-[11px] transition-colors ${
                  filters.timeRangeHours === tr.hours
                    ? 'bg-cyan-500/20 text-cyan-300'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {tr.label}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() =>
              downloadFile(
                exportEventsToCsv(filteredEvents),
                `cybertrace-events-${Date.now()}.csv`,
                'text/csv'
              )
            }
            className="hidden md:flex items-center gap-1 border border-slate-800 bg-[#0B1221] px-2 py-1 text-[11px] text-slate-300 hover:border-cyan-500/60 hover:text-white whitespace-nowrap"
          >
            <Download className="h-3 w-3" aria-hidden="true" />
            <span>CSV</span>
          </button>
          <button
            type="button"
            onClick={() =>
              downloadFile(
                JSON.stringify(filteredEvents, null, 2),
                `cybertrace-events-${Date.now()}.json`,
                'application/json'
              )
            }
            className="hidden md:flex items-center gap-1 border border-slate-800 bg-[#0B1221] px-2 py-1 text-[11px] text-slate-300 hover:border-cyan-500/60 hover:text-white whitespace-nowrap"
          >
            <Download className="h-3 w-3" aria-hidden="true" />
            <span>JSON</span>
          </button>
        </div>
      </footer>
    </>
  );
}
