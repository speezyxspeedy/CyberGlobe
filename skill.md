Build, complete and polish CyberTrace Globe, a real-time 3D (CesiumJS) network threat intelligence and digital forensics command center. Use this skill whenever the user mentions CyberTrace, the threat globe, IP/RDP/SSH/DNS/NetFlow footprint mapping, attack arcs, geolocation of suspicious IPs, ASN/VPN/Tor enrichment, forensic case/evidence/chain-of-custody features, SOC dashboards, or wants the globe, UI or README taken to a premium, non-templated, motion-rich level, even if they do not say "skill" or "CyberTrace" explicitly.

CyberTrace Globe: Master Skill

Goal: turn the README's architecture into a finished, production-grade product where any network footprint (an IP, an RDP session, an SSH attempt, a DNS query, a NetFlow record) is ingested, enriched, correlated, and rendered on a 3D globe with cinematic, physically plausible motion. It must look hand-designed by a product studio, not generated.

Read this whole file before writing code. Then follow the phases in order. Do not skip Phase 0.

0. Ground rules (non-negotiable)
Defensive and investigative use only. The platform helps defenders understand who is touching their assets. It never targets third parties, never scans, never exploits.
Approximate geolocation only. Every IP marker carries a confidence radius (km) and the exact notice: "Approximate network location · Investigative lead only — not proof of a person's physical location or identity." Never show a street address or imply identity.
Anonymizers stay anonymous. Flag VPN / proxy / Tor / hosting / CGNAT with probability. Never claim to "unmask" them.
Evidence integrity. SHA-256 on every artifact, append-only chain-of-custody, no silent edits.
Privacy. Mask RFC1918 / link-local / loopback in UI. RBAC: Viewer, Analyst, Admin, enforced server-side, never only in the UI.
Honest data. Anything simulated is labeled DEMO DATA visibly (badge in HUD plus in tooltips and exports). Never present fake data as live.
No secrets in the client. GEMINI_API_KEY, ABUSEIPDB_API_KEY stay server-side.
1. Phase 1: Footprint taxonomy (what "a footprint" means)

Every ingested signal normalizes to one FootprintEvent:

ts
type FootprintEvent = {
  id: string;                    // uuid v7
  ts: string;                    // ISO-8601 UTC
  source: 'ssh'|'rdp'|'ufw'|'nginx'|'dns'|'windows'|'netflow'|'syslog'|'csv'|'json';
  kind: 'auth_fail'|'auth_ok'|'session_open'|'session_close'|'scan'|'http'|'dns_query'|'flow'|'other';
  srcIp: string; srcPort?: number;
  dstIp?: string; dstPort?: number; dstAssetId?: string;
  proto?: 'tcp'|'udp'|'icmp'|string;
  user?: string;                 // account attempted, never password
  bytes?: number; packets?: number;
  geo?: { lat: number; lon: number; radiusKm: number; country: string; city?: string; source: string };
  asn?: { number: number; org: string };
  flags: { vpn?: number; proxy?: number; tor?: boolean; hosting?: number; cgnat?: number; internal?: boolean };
  reputation?: { abuseScore?: number; reports?: number; lastReported?: string; source: string };
  rawHash: string;               // SHA-256 of original log line
  demo: boolean;
};
1.1 RDP footprints (first-class)

Parse and correlate these Windows sources:

Source	Event	Meaning
Security	4625 (LogonType 10 or 3)	Failed RDP / NLA logon
Security	4624 (LogonType 10)	Successful RDP logon
Security	4634 / 4647	Logoff
Security	4776	NTLM credential validation
TerminalServices-RemoteConnectionManager/Operational	1149	RDP auth succeeded (source IP here)
TerminalServices-LocalSessionManager/Operational	21, 22, 23, 24, 25	Session logon, shell start, logoff, disconnect, reconnect
RDP-Client / RdpCoreTS	131, 140	Connection accepted / failed, client IP
NetFlow / firewall	dst port 3389 (and non-standard RDP ports)	Network-layer attempt

Detections to implement in riskEngine.ts:

Brute force: N failures from one IP within T minutes (defaults 10 in 5 min), severity scales with distinct usernames.
Password spray: one IP or ASN, many users, few attempts each.
Success after failures: 4625 burst followed by 4624/1149 from the same IP is Critical.
Impossible travel: same user, two geos, implied speed above 900 km/h (account for confidence radii before flagging).
Off-hours / new-ASN logon for a known user.
Distributed attack: many IPs in one ASN or CIDR hitting one asset.

Equivalent rule sets for SSH (sshd Failed/Accepted password/publickey), Nginx (401/403 bursts, path probing), DNS (DGA entropy, NXDOMAIN storms, tunneling by length and volume), UFW blocks, and NetFlow (port sweeps, beaconing by interval regularity).

1.2 Enrichment pipeline (ordered, cached in Redis, each step optional)
Validate and classify IP (public / RFC1918 / CGNAT 100.64/10 / loopback / reserved).
GeoIP + ASN (MaxMind GeoLite2 offline DB preferred; fall back to a provider). Store radiusKm from the provider's accuracy field; if missing, use country-level 500 km, region 100 km, city 25 km.
Anonymizer flags (Tor exit list refresh every 30 min, datacenter/ASN allowlists, provider VPN lists).
Reputation (AbuseIPDB when key set, else DEMO DATA).
Reverse DNS (async, timeout 1.5 s).
Correlate into a Threat Event (group by srcIp + asset + 15 min window) and broadcast on /ws/live.

Every enrichment result stores source and fetchedAt so the UI can show provenance.

2. Phase 2: Complete the README

The README is the spec. Complete these gaps without changing existing promises:

[ ] .env.example with every variable, comments, and safe defaults.
[ ] Environment variables table (GEMINI_API_KEY, ABUSEIPDB_API_KEY, DATABASE_URL, REDIS_URL, JWT_SECRET, CESIUM_ION_TOKEN optional, MAXMIND_DB_PATH, DEMO_MODE).
[ ] Architecture diagram (Mermaid): ingest → normalize → enrich → correlate → store → WS → globe.
[ ] Data model (events, assets, cases, evidence, notes, audit_log, users) with PostGIS geography(Point,4326) on events.
[ ] Layer catalogue: list all 11 layers with colour token, geometry type and what toggles it.
[ ] WS message schema (threat.new, threat.update, alert, case.update, layer.toggle, heartbeat) with JSON examples and reconnect/backoff rules.
[ ] Log format cookbook: one sample line per supported format plus the parsed output.
[ ] RBAC matrix (endpoint × role).
[ ] Security hardening: rate limiting, input size limits, upload MIME/magic checks, CSP, CORS allowlist, Firestore rules summary.
[ ] Troubleshooting: Cesium asset 404s, WS behind proxies, PostGIS extension missing, Alembic head mismatch.
[ ] Screenshots / GIF slots and a "Legal and ethical use" section.
[ ] Keep the unit test command; add integration and e2e (Playwright) commands.
3. Phase 3: 3D motion and visual direction

The "vibe-coded" look comes from: default Cesium chrome, neon-on-black everywhere, random glows, linear tweens, identical card layouts, emoji icons, and lorem-ipsum numbers. Avoid all of it.

3.1 Art direction: "Quiet Command Room"
Mood: calm, high-stakes, instrument-grade. Think air-traffic control meets editorial cartography. Colour is information, never decoration.
Base: near-black blue-grey (#070B10 bg, #0D141C surfaces, #16202B raised, hairline borders rgba(255,255,255,0.06)).
Signal palette (max 5 semantic hues):
Critical #FF4D5E · High #FF9F43 · Medium #F5D547 · Low/Info #4DB8FF · Safe/Trusted #3DDC97
Neutral data ink #9FB0C3, primary text #E6EDF5.
Type: one UI sans (Inter Tight or Geist) + one mono for data (JetBrains Mono / Geist Mono), tabular numerals everywhere numbers change. Max 4 sizes. Uppercase micro-labels at 10.5 px, letter-spacing 0.08em.
Chrome: no gradient borders, no glassmorphism stacks. One subtle backdrop-blur only on floating inspector panels. 4 px radius grid, 8 px spacing scale.
Icons: one consistent line set (Lucide at 1.5 stroke). No emoji.
Define all of this as CSS variables / design tokens in src/styles/tokens.css and consume only tokens.
3.2 Globe rendering (CesiumJS)
Disable default widgets (baseLayerPicker, geocoder, homeButton, sceneModePicker, navigationHelpButton, animation, timeline, fullscreenButton). Build custom HUD.
Scene: scene.globe.enableLighting = true, showGroundAtmosphere = true, atmosphere hue shifted to cold blue, scene.skyAtmosphere tuned dim, scene.highDynamicRange = true, scene.fog on, scene.globe.depthTestAgainstTerrain = false for arcs, requestRenderMode = true with explicit requestRender() when animating only (battery and GPU friendly).
Imagery: dark, desaturated (NaturalEarthII local tiles, optional CARTO Dark). Apply brightness 0.8, contrast 1.15, saturation 0.4, gamma 0.9 on the imagery layer. Night-side city lights if a texture is available.
Country borders: thin 0.5 px GeoJSON polylines at 8% white, brighten on hover and on regional risk.
Use Primitives, not Entities, for anything over ~500 objects (PolylineCollection, PointPrimitiveCollection, BillboardCollection, GeometryInstance batches). Entities only for the selected/focused item.
3.3 Motion vocabulary (each has a purpose)
Motion	Purpose	Spec
Attack arc	Source → target path	Great-circle with height = clamp(0.18 × distance, 150 km, 2200 km), cubic ease-out growth over 900 ms, then a travelling light head (a 6% length bright segment) looping while the event is "hot". Custom GLSL Material with time, speed, trailLength, fade. Colour by severity.
Impact pulse	Landing on protected asset	Ground ring expanding 0 → 60 km radius, opacity 0.6 → 0 over 1.4 s, easeOutCubic; second ring delayed 220 ms. Max 2 per asset per second (coalesce).
Source beacon	Origin IP	Small steady point + slow 3.2 s breathing halo; confidence-radius circle drawn as dashed, 12% fill, never animated aggressively.
Camera	Focus on event/case	flyTo with EasingFunction.QUARTIC_IN_OUT, duration scaled 1.6–3.2 s by distance, ending pitch −35°, small heading drift for parallax. Never snap. Cancel on user drag.
Idle	Showcase mode	Very slow rotation (0.6°/s) paused on any input, resumes after 12 s idle.
Layer toggle	Show/hide	240 ms opacity crossfade, staggered by 20 ms per item (cap 400 ms total).
New-event ingress	Live feed	Row slides in 160 ms, number counters tween with tabular nums, arc spawns only if viewport can see source or target.

Rules:

Easing: only easeOutCubic, easeInOutQuart, easeOutExpo. No linear for position, no bounce, ever.
Respect prefers-reduced-motion: replace arcs' travelling head with static gradient, disable idle spin and pulses, keep crossfades under 100 ms.
Cap concurrent animated arcs at 250; beyond that, aggregate into thicker "flow bundles" per ASN → asset with a count badge.
Level of detail: arcs thinner and no trail when camera height > 15,000 km; clusters when point density is high (screen-space clustering, 40 px).
60 fps budget: p95 frame < 16 ms on a mid laptop. Measure with scene.debugShowFramesPerSecond in dev and a Playwright perf trace in CI.
3.4 Optional post-processing (subtle, toggleable)
Bloom: contrast 128, brightness −0.3, delta 1, sigma 2.2, stepSize 1, only on the arcs layer, intensity ≤ 0.25.
Vignette via CSS overlay (cheaper than a stage). No scanlines, no CRT, no glitch text.
3.5 HUD and panels
Left rail: layer toggles (11) with colour chip, count, and live sparkline (last 5 min).
Top bar: global KPIs (events/min, critical open, top ASN, DEMO DATA badge), time-range scrubber with Cesium clock bound to replay mode.
Right inspector (slides in 220 ms on selection): IP header, geo lead + radius + the mandatory notice, ASN, flags as probability bars, reputation, event timeline, "Add to case" and "Preserve evidence" actions.
Bottom: collapsible live event ticker (virtualized list, max 200 rows in DOM).
Empty, loading, error and offline states for every panel (skeletons, not spinners).
Keyboard: / search, L layers, C cases, Esc clear selection, [ ] step through events, Space pause live stream.
WCAG AA contrast, visible focus rings, ARIA labels on every control, screen-reader text for map selections.
3.6 Anti-"vibe-coded" checklist (must pass before delivery)
[ ] No default Cesium UI visible.
[ ] Only tokens, no hardcoded colours or magic spacing in components.
[ ] No emoji, no stock gradient hero, no placeholder numbers.
[ ] Every number has units and a time window.
[ ] No more than 5 hues on screen; glow used only for Critical and live arcs.
[ ] Motion has a reason; nothing loops that is not conveying state.
[ ] Consistent component density (compact 32 px rows).
[ ] Real copywriting: terse, specific, analyst voice ("14 failed RDP logons from AS14061 in 4 min", not "Alert detected!").
[ ] Screenshots reviewed at 1280, 1920 and 2560 wide plus a tablet width.
4. Phase 4: Backend and data completeness
Parsers: one module per format, table-driven tests with at least 5 real-shape samples and 3 malformed ones each. Never throw on a bad line; count and report rejects.
Idempotent ingest (dedupe on rawHash), streaming upload (limit 50 MB, abort on binary content mismatch).
WebSocket: auth token on connect, per-role channel filtering, heartbeat 15 s, backpressure (drop oldest non-critical), permessage-deflate.
PostGIS: GiST index on geography, partition events by month, retention policy configurable.
Audit log for every read of evidence and every case mutation.
Reports: Markdown with executive summary, timeline, indicators (IPs, ASNs, users, hashes), evidence table with SHA-256, limitations section repeating the approximate-location notice.
Gemini analyst: system prompt forbids identity or exact-location claims, requires citing event ids, returns structured JSON (findings, confidence, eventIds, caveats).
5. Phase 5: Testing and quality gates
Unit: riskEngine (each detection incl. RDP sequences), logParser (all formats), caseLogic, Firestore rules.
Integration: ingest → enrich → WS broadcast using a fake provider.
E2E (Playwright): load globe, toggle layers, select event, create case, preserve evidence, verify SHA-256 shown.
Visual regression on HUD panels (not the WebGL canvas); canvas verified by pixel-sample smoke test.
Security: dependency audit, CSP report-only first, secret scan, RBAC bypass tests.
Lighthouse on the shell ≥ 90 accessibility.

Definition of done: all gates green, README checklist ticked, anti-vibe checklist passed, DEMO DATA clearly labeled, and a 30-second demo capture recorded.

6. Prompt library (copy, paste, adapt)

Use these as sub-tasks. Replace {{…}} values.

P1: RDP detection engine

Implement RDP footprint ingestion for CyberTrace Globe. Parse Windows Security 4624/4625/4634/4776 and TerminalServices 1149 and LocalSessionManager 21–25 into FootprintEvent. Add detections in riskEngine.ts for brute force ({{10}} failures/{{5}} min), password spray, success-after-failure (Critical) and impossible travel (account for confidence radius). Include table-driven tests with real-shaped samples and malformed lines. Do not log passwords. Return a diff-sized summary of files changed.

P2: Attack arc shader

In the Cesium layer ArcLayer.ts, build great-circle arcs as batched Primitive polylines using a custom GLSL Material with uniforms time, speed, trailLength, fade, color. Height = clamp(0.18 × distance, 150 km, 2200 km). Grow over 900 ms with easeOutCubic, then loop a travelling head. Cap at 250 concurrent, aggregate beyond that. Respect prefers-reduced-motion. Add requestRender() only while animating. Provide a perf note with measured frame times.

P3: Impact pulses and camera

Add ground impact rings on protected assets (0→60 km, 1.4 s, easeOutCubic, second ring +220 ms, coalesce to 2/s per asset) and a focusEvent(id) camera move using QUARTIC_IN_OUT with duration scaled by distance and pitch −35°. Cancel on user input.

P4: Design system pass

Create src/styles/tokens.css and refactor the HUD (left rail, top bar, right inspector, ticker) to use only tokens: Quiet Command Room palette, Geist + Geist Mono with tabular numerals, 4 px radius, 8 px spacing, Lucide 1.5 stroke icons. Add loading, empty, error, offline states. Remove every hardcoded colour. Output a before/after screenshot checklist.

P5: Inspector panel

Build the right-side IP inspector: header with masked-if-internal IP, geo lead with confidence radius km and the mandatory investigative-lead notice, ASN, VPN/Proxy/Tor/Hosting/CGNAT as probability bars, reputation with source and fetchedAt, event timeline (virtualized), actions "Add to case" and "Preserve evidence (SHA-256)". Role-gate actions (Viewer read-only).

P6: README completion

Complete README.md per Phase 2 of the skill: env table, .env.example, Mermaid architecture, data model, layer catalogue, WS schema with examples, log cookbook, RBAC matrix, hardening, troubleshooting, ethics section. Keep all existing sections and commands intact.

P7: Performance audit

Profile the globe with 5,000 events and 250 arcs. Identify entity-vs-primitive misuse, per-frame allocations, and unneeded renders. Fix top 5 issues, report p50/p95 frame time before and after.

P8: Forensic report generator

Implement GET /api/reports/:case_id returning Markdown: executive summary, scope, timeline, indicators table, evidence table with SHA-256 and custody chain, analyst notes, limitations (approximate geolocation notice). Add snapshot tests.

P9: Security review

Review the repo for RBAC bypass, unsafe upload handling, WS auth gaps, secret leakage to the client, Firestore rule holes, and SSRF in enrichment fetchers. Produce a prioritized findings list with fixes and tests.

7. Working method for the agent
Restate the task in one line and name which phase it belongs to.
Read existing code before changing it; follow its patterns.
Change the smallest surface that satisfies the task, then run the tests.
When visuals change, verify against the anti-vibe checklist and report what you checked.
If a request would cross the Ground rules (e.g. "reveal the real address behind this VPN"), decline that part and offer the defensible alternative (confidence radius, ASN, abuse report workflow).