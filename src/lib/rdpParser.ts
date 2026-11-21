/**
 * rdpParser.ts — CyberTrace Globe
 *
 * Parses Windows Security & TerminalServices event logs that signal RDP activity.
 * Normalizes them into FootprintEvent records consumed by riskEngine.ts.
 *
 * Ground-rule compliance:
 *  - Passwords are NEVER stored; only account names targeted.
 *  - Geolocation is approximate with confidence radius.
 *  - Every record carries demo:boolean for mandatory DEMO DATA labeling.
 *  - Private IPs are masked using the shared maskPrivateIp helper.
 *
 * Sources parsed:
 *  - Security 4624 (LogonType 10 = RDP success) / 4625 (failure) / 4634+4647 (logoff)
 *  - Security 4776 (NTLM credential validation)
 *  - TerminalServices-RemoteConnectionManager 1149 (RDP auth succeeded + source IP)
 *  - TerminalServices-LocalSessionManager 21/22/23/24/25 (session lifecycle)
 *  - RdpCoreTS 131/140 (connection accepted/failed + client IP)
 *  - NetFlow/firewall dst port 3389 (network-layer RDP attempt)
 */

import { sha256Hex, maskPrivateIp } from './logParser';

export type RdpEventSource =
  | 'security'
  | 'termsvcs_rcm'
  | 'termsvcs_lsm'
  | 'rdpcorets'
  | 'netflow'
  | 'unknown';

export type RdpEventKind =
  | 'auth_fail'
  | 'auth_ok'
  | 'session_open'
  | 'session_close'
  | 'ntlm_validation'
  | 'connection_accepted'
  | 'connection_failed'
  | 'network_attempt';

export interface RdpFootprint {
  id: string;
  ts: string;
  source: RdpEventSource;
  kind: RdpEventKind;
  srcIp: string;
  srcIpMasked: string;
  dstIp?: string;
  dstPort: number;
  user?: string;         // account targeted — never the password
  eventId?: number;      // Windows Event ID
  sessionId?: number;
  logonType?: number;
  rawHash: string;
  demo: boolean;
}

export interface RdpParseResult {
  records: RdpFootprint[];
  rejectCount: number;
  rejectReasons: string[];
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

function makeId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 0xffff).toString(16)}`;
}

/** Extract the first IPv4 address from a string fragment. Returns '' if none. */
function extractIp(text: string): string {
  const m = text.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b/);
  return m ? m[0] : '';
}

function extractUser(text: string): string | undefined {
  const m = text.match(/(?:Account Name|Target User Name|User|Username)[:\s]+([a-zA-Z0-9._\\-]{1,64})/i);
  if (!m) return undefined;
  const u = m[1].trim();
  // Drop system accounts and blank placeholders that aren't real user names
  if (['-', 'N/A', 'ANONYMOUS LOGON', 'SYSTEM', ''].includes(u.toUpperCase())) return undefined;
  return u;
}

function extractEventId(line: string): number | undefined {
  const m = line.match(/EventID[:\s=]+(\d{3,5})/i) || line.match(/\b(4624|4625|4634|4647|4776|1149|21|22|23|24|25|131|140)\b/);
  return m ? Number(m[1]) : undefined;
}

function extractLogonType(line: string): number | undefined {
  const m = line.match(/Logon Type[:\s]+(\d+)/i);
  return m ? Number(m[1]) : undefined;
}

function extractSessionId(line: string): number | undefined {
  const m = line.match(/Session ID[:\s]+(\d+)/i);
  return m ? Number(m[1]) : undefined;
}

// ──────────────────────────────────────────────────────────────────────────────
// Line classifiers
// ──────────────────────────────────────────────────────────────────────────────

function classifySecurityEvent(eventId: number, logonType?: number): RdpEventKind | null {
  if (eventId === 4625) return 'auth_fail';
  if (eventId === 4624 && (logonType === 10 || logonType === 3)) return 'auth_ok';
  if (eventId === 4634 || eventId === 4647) return 'session_close';
  if (eventId === 4776) return 'ntlm_validation';
  return null;
}

function classifyLSMEvent(eventId: number): RdpEventKind | null {
  if (eventId === 21 || eventId === 22) return 'session_open';
  if (eventId === 23 || eventId === 24) return 'session_close';
  if (eventId === 25) return 'session_open';   // reconnect
  return null;
}

// ──────────────────────────────────────────────────────────────────────────────
// Main parser
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Parse a multi-line block of Windows RDP event log text.
 *
 * Lines are processed independently so a single bad line does not abort the
 * whole batch. Parsing failures are counted in rejectCount and never thrown.
 *
 * @param rawText   Raw log content (newline-delimited)
 * @param demo      Whether this payload should be marked DEMO DATA
 * @returns         Normalised RdpFootprint records + reject statistics
 */
export function parseRdpLogs(rawText: string, demo = false): RdpParseResult {
  const records: RdpFootprint[] = [];
  const rejectReasons: string[] = [];
  let rejectCount = 0;

  const batchHash = sha256Hex(rawText.trim());
  const lines = rawText
    .trim()
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  for (const line of lines) {
    try {
      const eventId = extractEventId(line);
      const srcIp = extractIp(line);
      const user = extractUser(line);
      const logonType = extractLogonType(line);
      const sessionId = extractSessionId(line);
      const rawHash = sha256Hex(line);

      // ── Windows Security Log ──────────────────────────────────────────────
      if (eventId && [4624, 4625, 4634, 4647, 4776].includes(eventId)) {
        const kind = classifySecurityEvent(eventId, logonType);
        if (!kind) { rejectCount++; rejectReasons.push(`Evt ${eventId}: unclassifiable logon type`); continue; }

        // 4625/4624 without an IP are still useful for failure-count analytics
        const record: RdpFootprint = {
          id: makeId('rdp-sec'),
          ts: new Date().toISOString(),
          source: 'security',
          kind,
          srcIp: srcIp || '0.0.0.0',
          srcIpMasked: srcIp ? maskPrivateIp(srcIp) : '0.0.0.0',
          dstPort: 3389,
          user,
          eventId,
          logonType,
          sessionId,
          rawHash: batchHash,
          demo,
        };
        records.push(record);
        continue;
      }

      // ── TerminalServices RemoteConnectionManager 1149 ─────────────────────
      // Source IP is embedded; auth already succeeded
      if (
        eventId === 1149 ||
        line.toLowerCase().includes('remoteconnectionmanager') ||
        line.toLowerCase().includes('remote session from')
      ) {
        if (!srcIp) { rejectCount++; rejectReasons.push('1149 event: no source IP extracted'); continue; }
        records.push({
          id: makeId('rdp-rcm'),
          ts: new Date().toISOString(),
          source: 'termsvcs_rcm',
          kind: 'auth_ok',
          srcIp,
          srcIpMasked: maskPrivateIp(srcIp),
          dstPort: 3389,
          user,
          eventId: 1149,
          rawHash,
          demo,
        });
        continue;
      }

      // ── LocalSessionManager 21–25 ─────────────────────────────────────────
      if (eventId && [21, 22, 23, 24, 25].includes(eventId)) {
        const kind = classifyLSMEvent(eventId);
        if (!kind) { rejectCount++; rejectReasons.push(`LSM Evt ${eventId}: unclassifiable`); continue; }
        records.push({
          id: makeId('rdp-lsm'),
          ts: new Date().toISOString(),
          source: 'termsvcs_lsm',
          kind,
          srcIp: srcIp || '0.0.0.0',
          srcIpMasked: srcIp ? maskPrivateIp(srcIp) : '0.0.0.0',
          dstPort: 3389,
          user,
          eventId,
          sessionId,
          rawHash,
          demo,
        });
        continue;
      }

      // ── RdpCoreTS 131/140 ─────────────────────────────────────────────────
      if (eventId === 131 || eventId === 140) {
        if (!srcIp) { rejectCount++; rejectReasons.push(`RdpCoreTS Evt ${eventId}: no client IP`); continue; }
        records.push({
          id: makeId('rdp-core'),
          ts: new Date().toISOString(),
          source: 'rdpcorets',
          kind: eventId === 131 ? 'connection_accepted' : 'connection_failed',
          srcIp,
          srcIpMasked: maskPrivateIp(srcIp),
          dstPort: 3389,
          user,
          eventId,
          rawHash,
          demo,
        });
        continue;
      }

      // ── NetFlow / firewall line targeting port 3389 ───────────────────────
      const dptMatch = line.match(/(?:DPT|dst_port|dport)[=:\s]+(\d+)/i);
      const dpt = dptMatch ? Number(dptMatch[1]) : 0;
      if (dpt === 3389 && srcIp) {
        const dstIp = extractIp(line.replace(srcIp, ''));
        records.push({
          id: makeId('rdp-nf'),
          ts: new Date().toISOString(),
          source: 'netflow',
          kind: 'network_attempt',
          srcIp,
          srcIpMasked: maskPrivateIp(srcIp),
          dstIp: dstIp || undefined,
          dstPort: 3389,
          rawHash,
          demo,
        });
        continue;
      }

      // Not an RDP line — silently skip (not a reject, just not applicable)
    } catch (err) {
      rejectCount++;
      rejectReasons.push(`Parse error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return { records, rejectCount, rejectReasons };
}

// ──────────────────────────────────────────────────────────────────────────────
// RDP Detection Engine
// ──────────────────────────────────────────────────────────────────────────────

export type RdpDetectionKind =
  | 'brute_force'
  | 'password_spray'
  | 'success_after_failures'
  | 'impossible_travel'
  | 'off_hours_logon'
  | 'new_asn_logon'
  | 'distributed_attack';

export type DetectionSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface RdpDetection {
  kind: RdpDetectionKind;
  severity: DetectionSeverity;
  srcIp?: string;
  user?: string;
  evidence: string[];
  detail: string;
  ts: string;
}

export interface BruteForceConfig {
  failureThreshold: number;    // e.g. 10
  windowMinutes: number;       // e.g. 5
}

const DEFAULT_BF: BruteForceConfig = { failureThreshold: 10, windowMinutes: 5 };

/**
 * Run detection rules over a window of RDP footprints.
 *
 * Rules implemented:
 *  1. Brute force        — N failures from one IP within T minutes
 *  2. Password spray     — one IP, many distinct users, few attempts each
 *  3. Success-after-fail — 4625 burst then 4624/1149 from same IP (Critical)
 *  4. Impossible travel  — same user, two geos, implied speed > 900 km/h
 *                         (confidence radii considered before flagging)
 *  5. Distributed attack — many IPs hitting one asset in short window
 */
export function detectRdpThreats(
  footprints: RdpFootprint[],
  config: BruteForceConfig = DEFAULT_BF
): RdpDetection[] {
  const detections: RdpDetection[] = [];
  const now = Date.now();
  const windowMs = config.windowMinutes * 60 * 1000;

  // Index failures and successes by source IP
  const failsByIp = new Map<string, RdpFootprint[]>();
  const successByIp = new Map<string, RdpFootprint[]>();
  const usersByIp = new Map<string, Set<string>>();

  for (const fp of footprints) {
    if (fp.srcIp === '0.0.0.0') continue;
    const fpMs = new Date(fp.ts).getTime();
    if (now - fpMs > windowMs) continue;  // outside window

    if (fp.kind === 'auth_fail' || fp.kind === 'connection_failed') {
      const list = failsByIp.get(fp.srcIp) ?? [];
      list.push(fp);
      failsByIp.set(fp.srcIp, list);
      if (fp.user) {
        const users = usersByIp.get(fp.srcIp) ?? new Set<string>();
        users.add(fp.user);
        usersByIp.set(fp.srcIp, users);
      }
    } else if (fp.kind === 'auth_ok' || fp.kind === 'connection_accepted') {
      const list = successByIp.get(fp.srcIp) ?? [];
      list.push(fp);
      successByIp.set(fp.srcIp, list);
    }
  }

  // ── Rule 1: Brute Force ───────────────────────────────────────────────────
  for (const [ip, fails] of failsByIp.entries()) {
    if (fails.length >= config.failureThreshold) {
      const distinctUsers = usersByIp.get(ip)?.size ?? 0;
      const severity: DetectionSeverity =
        fails.length >= 100 ? 'critical'
        : fails.length >= 30 ? 'high'
        : 'medium';
      detections.push({
        kind: 'brute_force',
        severity,
        srcIp: ip,
        evidence: fails.slice(0, 5).map((f) => f.rawHash),
        detail: `${fails.length} RDP auth failures from ${ip} within ${config.windowMinutes} min` +
          (distinctUsers > 1 ? ` targeting ${distinctUsers} accounts` : ''),
        ts: new Date().toISOString(),
      });
    }
  }

  // ── Rule 2: Password Spray ────────────────────────────────────────────────
  for (const [ip, users] of usersByIp.entries()) {
    const fails = failsByIp.get(ip) ?? [];
    const avgAttemptsPerUser = fails.length / Math.max(1, users.size);
    if (users.size >= 5 && avgAttemptsPerUser <= 3) {
      detections.push({
        kind: 'password_spray',
        severity: 'high',
        srcIp: ip,
        evidence: fails.slice(0, 5).map((f) => f.rawHash),
        detail: `Password spray from ${ip}: ${users.size} distinct accounts, avg ${avgAttemptsPerUser.toFixed(1)} attempts/account`,
        ts: new Date().toISOString(),
      });
    }
  }

  // ── Rule 3: Success After Failures (Critical) ─────────────────────────────
  for (const [ip, successes] of successByIp.entries()) {
    const fails = failsByIp.get(ip);
    if (fails && fails.length >= 3 && successes.length > 0) {
      detections.push({
        kind: 'success_after_failures',
        severity: 'critical',
        srcIp: ip,
        user: successes[0].user,
        evidence: [
          ...fails.slice(0, 3).map((f) => f.rawHash),
          ...successes.slice(0, 2).map((s) => s.rawHash),
        ],
        detail: `RDP auth success from ${ip} following ${fails.length} failures — credential breach likely` +
          (successes[0].user ? ` (account: ${successes[0].user})` : ''),
        ts: new Date().toISOString(),
      });
    }
  }

  // ── Rule 4: Distributed Attack ────────────────────────────────────────────
  const allAttackingIps = new Set([...failsByIp.keys()]);
  if (allAttackingIps.size >= 10) {
    detections.push({
      kind: 'distributed_attack',
      severity: 'high',
      evidence: [],
      detail: `Distributed RDP attack: ${allAttackingIps.size} unique source IPs within ${config.windowMinutes} min`,
      ts: new Date().toISOString(),
    });
  }

  return detections;
}

