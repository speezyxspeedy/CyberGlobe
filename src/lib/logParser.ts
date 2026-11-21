import type {ThreatCategory} from '../types/forensics';

export type LogFormat =
  | 'auto'
  | 'ssh'
  | 'nginx'
  | 'firewall'
  | 'windows'
  | 'dns'
  | 'netflow'
  | 'json'
  | 'jsonl'
  | 'csv'
  | 'syslog';

export interface ParsedLogRecord {
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  maskedDestinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  eventType: ThreatCategory;
  username?: string;
  action: string;
  bytesTransferred: number;
  userAgent?: string;
  domain?: string;
  url?: string;
  rawLogRef: string;
  evidenceSha256: string;
  ingestionSource: string;
  confidence: number;
  title: string;
  description: string;
}

const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b/g;

export function isPrivateIp(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  return false;
}

export function maskPrivateIp(ip: string): string {
  if (!isPrivateIp(ip)) return ip;
  const parts = ip.split('.');
  return `${parts[0]}.${parts[1]}.x.${parts[3]} (internal-masked)`;
}

/**
 * Pure synchronous SHA-256 implementation (FIPS 180-4) so evidence hashing works
 * identically in browser, Node tests, and server runtime without async overhead.
 */
export function sha256Hex(message: string): string {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const bytes = new TextEncoder().encode(message);
  const bitLen = bytes.length * 8;
  const paddedLen = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(paddedLen - 4, bitLen >>> 0, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((v) => v.toString(16).padStart(8, '0'))
    .join('');
}

function classifyTextLine(line: string, dstPort: number, bytes: number): ThreatCategory {
  const lower = line.toLowerCase();
  if (lower.includes('failed password') || lower.includes('invalid user') || lower.includes('4625') || lower.includes('brute')) {
    return 'ssh_brute_force';
  }
  if (lower.includes('c2') || lower.includes('beacon') || lower.includes('cobalt') || lower.includes('malware') || lower.includes('botnet')) {
    return 'malware_c2';
  }
  if (lower.includes('exfil') || bytes >= 50 * 1024 * 1024) {
    return 'data_exfiltration';
  }
  if (lower.includes('scan') || lower.includes('syn_flood') || lower.includes('nmap') || lower.includes('ufw block')) {
    return 'port_scan';
  }
  if (lower.includes('ddos') || lower.includes('flood')) {
    return 'ddos';
  }
  if (lower.includes('phish') || lower.includes('credential-harvest')) {
    return 'phishing';
  }
  if (lower.includes('vpn') || lower.includes('tor') || lower.includes('proxy')) {
    return 'vpn_abuse';
  }
  if (dstPort === 22 || dstPort === 3389) return 'ssh_brute_force';
  return 'anomalous_login';
}

function parseJsonObject(obj: Record<string, unknown>, rawRef: string, source: string, hash: string): ParsedLogRecord | null {
  const sourceIp = String(obj.source_ip ?? obj.src_ip ?? obj.sourceIp ?? obj.client_ip ?? '');
  if (!sourceIp || !/^\d{1,3}(\.\d{1,3}){3}$/.test(sourceIp)) return null;
  const destinationIp = String(obj.destination_ip ?? obj.dst_ip ?? obj.destinationIp ?? '10.0.1.12');
  const sourcePort = Number(obj.source_port ?? obj.src_port ?? obj.sourcePort ?? 49152);
  const destinationPort = Number(obj.destination_port ?? obj.dst_port ?? obj.destinationPort ?? 443);
  const protocol = String(obj.protocol ?? obj.proto ?? 'TCP').toUpperCase();
  const bytesTransferred = Number(obj.bytes ?? obj.bytes_transferred ?? obj.bytesTransferred ?? 0);
  const username = obj.username ? String(obj.username) : obj.user ? String(obj.user) : undefined;
  const action = String(obj.action ?? obj.result ?? 'observed');
  const rawEventType = String(obj.event_type ?? obj.eventType ?? '');
  const validCategories: ThreatCategory[] = [
    'ssh_brute_force',
    'port_scan',
    'malware_c2',
    'data_exfiltration',
    'phishing',
    'ddos',
    'vpn_abuse',
    'anomalous_login',
  ];
  const eventType: ThreatCategory = validCategories.includes(rawEventType as ThreatCategory)
    ? (rawEventType as ThreatCategory)
    : classifyTextLine(JSON.stringify(obj), destinationPort, bytesTransferred);

  return {
    timestamp: String(obj.timestamp ?? new Date().toISOString()),
    sourceIp,
    destinationIp,
    maskedDestinationIp: maskPrivateIp(destinationIp),
    sourcePort: Number.isFinite(sourcePort) ? sourcePort : 49152,
    destinationPort: Number.isFinite(destinationPort) ? destinationPort : 443,
    protocol,
    eventType,
    username,
    action,
    bytesTransferred: Number.isFinite(bytesTransferred) ? bytesTransferred : 0,
    userAgent: obj.user_agent ? String(obj.user_agent) : undefined,
    domain: obj.domain ? String(obj.domain) : undefined,
    url: obj.url ? String(obj.url) : undefined,
    rawLogRef: rawRef,
    evidenceSha256: hash,
    ingestionSource: source,
    confidence: 86,
    title: `${eventType.replace(/_/g, ' ').toUpperCase()} from ${sourceIp}`,
    description: `Ingested structured record (${source}): ${action} on ${protocol}/${destinationPort}.`,
  };
}

export function parseLogs(
  rawText: string,
  format: LogFormat = 'auto',
  ingestionSource = 'manual_upload'
): ParsedLogRecord[] {
  const trimmed = rawText.trim();
  if (!trimmed) return [];

  const evidenceSha256 = sha256Hex(trimmed);
  const records: ParsedLogRecord[] = [];

  // Try JSON array or single JSON object
  if (format === 'json' || (format === 'auto' && (trimmed.startsWith('[') || trimmed.startsWith('{')))) {
    try {
      const parsed = JSON.parse(trimmed);
      const list = Array.isArray(parsed) ? parsed : [parsed];
      list.forEach((item, idx) => {
        if (item && typeof item === 'object') {
          const rec = parseJsonObject(item as Record<string, unknown>, `json[${idx}]`, ingestionSource, evidenceSha256);
          if (rec) records.push(rec);
        }
      });
      if (records.length > 0) return records;
    } catch {
      // Fall through to JSONL / line-based parsing
    }
  }

  const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

  // CSV check
  if (format === 'csv' || (format === 'auto' && lines.length >= 2 && lines[0].includes(',') && lines[0].toLowerCase().includes('ip'))) {
    const headers = lines[0].split(',').map((h) => h.trim().toLowerCase());
    for (let i = 1; i < lines.length; i++) {
      const cols = lines[i].split(',').map((c) => c.trim().replace(/^"|"$/g, ''));
      const row: Record<string, unknown> = {};
      headers.forEach((h, idx) => {
        row[h] = cols[idx] ?? '';
      });
      const rec = parseJsonObject(row, `csv:line:${i + 1}`, ingestionSource, evidenceSha256);
      if (rec) records.push(rec);
    }
    if (records.length > 0) return records;
  }

  lines.forEach((line, index) => {
    const lineRef = `line:${index + 1}`;

    // JSONL line
    if (line.startsWith('{') && line.endsWith('}')) {
      try {
        const obj = JSON.parse(line) as Record<string, unknown>;
        const rec = parseJsonObject(obj, lineRef, ingestionSource, evidenceSha256);
        if (rec) {
          records.push(rec);
          return;
        }
      } catch {
        // continue to pattern matching
      }
    }

    // SSH auth log pattern
    const sshMatch = line.match(/Failed password for (?:invalid user )?([a-zA-Z0-9._-]+) from (\d+\.\d+\.\d+\.\d+) port (\d+)/i);
    if (sshMatch) {
      const [, username, sourceIp, srcPort] = sshMatch;
      const dstIp = '10.0.1.12';
      records.push({
        timestamp: new Date().toISOString(),
        sourceIp,
        destinationIp: dstIp,
        maskedDestinationIp: maskPrivateIp(dstIp),
        sourcePort: Number(srcPort),
        destinationPort: 22,
        protocol: 'SSH/TCP',
        eventType: 'ssh_brute_force',
        username,
        action: 'AUTH_FAILED',
        bytesTransferred: 1280,
        rawLogRef: lineRef,
        evidenceSha256,
        ingestionSource: `${ingestionSource}:ssh_auth`,
        confidence: 92,
        title: `SSH Failed Authentication (${username}) from ${sourceIp}`,
        description: `Repeated SSH authentication failure targeting account "${username}" on port 22.`,
      });
      return;
    }

    // Firewall / UFW / iptables log pattern
    const fwSrc = line.match(/SRC=(\d+\.\d+\.\d+\.\d+)/i);
    const fwDst = line.match(/DST=(\d+\.\d+\.\d+\.\d+)/i);
    if (fwSrc && fwDst) {
      const proto = line.match(/PROTO=([A-Z0-9]+)/i)?.[1] ?? 'TCP';
      const spt = Number(line.match(/SPT=(\d+)/i)?.[1] ?? 50000);
      const dpt = Number(line.match(/DPT=(\d+)/i)?.[1] ?? 443);
      const len = Number(line.match(/LEN=(\d+)/i)?.[1] ?? 64);
      const action = line.toLowerCase().includes('block') || line.toLowerCase().includes('drop') ? 'BLOCKED' : 'ALLOWED';
      const eventType = classifyTextLine(line, dpt, len);
      records.push({
        timestamp: new Date().toISOString(),
        sourceIp: fwSrc[1],
        destinationIp: fwDst[1],
        maskedDestinationIp: maskPrivateIp(fwDst[1]),
        sourcePort: spt,
        destinationPort: dpt,
        protocol: proto,
        eventType,
        action,
        bytesTransferred: len,
        rawLogRef: lineRef,
        evidenceSha256,
        ingestionSource: `${ingestionSource}:firewall`,
        confidence: 88,
        title: `Firewall ${action} ${proto}/${dpt} from ${fwSrc[1]}`,
        description: `Perimeter firewall recorded ${action.toLowerCase()} connection from ${fwSrc[1]}:${spt} to port ${dpt}.`,
      });
      return;
    }

    // Nginx / Apache combined access log
    const webMatch = line.match(
      /^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)\s+[^"]+"\s+(\d{3})\s+(\d+)\s+"[^"]*"\s+"([^"]*)"/
    );
    if (webMatch) {
      const [, sourceIp, , method, urlPath, statusCode, byteStr, userAgent] = webMatch;
      const bytes = Number(byteStr);
      const dstIp = '10.0.2.24';
      const eventType =
        statusCode === '401' || statusCode === '403'
          ? 'anomalous_login'
          : urlPath.includes('admin') || urlPath.includes('.env') || urlPath.includes('wp-login')
            ? 'port_scan'
            : classifyTextLine(line, 443, bytes);
      records.push({
        timestamp: new Date().toISOString(),
        sourceIp,
        destinationIp: dstIp,
        maskedDestinationIp: maskPrivateIp(dstIp),
        sourcePort: 54321,
        destinationPort: 443,
        protocol: 'HTTPS',
        eventType,
        action: `HTTP_${statusCode}`,
        bytesTransferred: bytes,
        userAgent,
        url: urlPath,
        rawLogRef: lineRef,
        evidenceSha256,
        ingestionSource: `${ingestionSource}:web_access`,
        confidence: 84,
        title: `HTTP ${method} ${urlPath} (${statusCode}) from ${sourceIp}`,
        description: `Web server logged HTTP ${statusCode} for ${method} ${urlPath} (${bytes} bytes).`,
      });
      return;
    }

    // DNS query log
    const dnsMatch = line.match(/client\s+(?:@0x[0-9a-f]+\s+)?(\d+\.\d+\.\d+\.\d+)#(\d+).*?query:\s+([a-zA-Z0-9.-]+)/i);
    if (dnsMatch) {
      const [, sourceIp, srcPort, domain] = dnsMatch;
      const dstIp = '10.0.5.53';
      records.push({
        timestamp: new Date().toISOString(),
        sourceIp,
        destinationIp: dstIp,
        maskedDestinationIp: maskPrivateIp(dstIp),
        sourcePort: Number(srcPort),
        destinationPort: 53,
        protocol: 'DNS/UDP',
        eventType: domain.includes('c2') || domain.includes('onion') || domain.length > 35 ? 'malware_c2' : 'phishing',
        action: 'DNS_QUERY',
        bytesTransferred: 512,
        domain,
        rawLogRef: lineRef,
        evidenceSha256,
        ingestionSource: `${ingestionSource}:dns`,
        confidence: 85,
        title: `Suspicious DNS Lookup (${domain})`,
        description: `Endpoint queried suspicious domain ${domain} via DNS.`,
      });
      return;
    }

    // Generic fallback extracting IPs (Windows Security / NetFlow / Zeek / Syslog)
    const ips = line.match(IPV4_REGEX);
    if (ips && ips.length >= 1) {
      const sourceIp = ips[0];
      const destinationIp = ips[1] ?? '10.0.1.15';
      const bytesMatch = line.match(/bytes[=:\s]+(\d+)/i);
      const portMatch = line.match(/(?:dport|dst_port|port)[=:\s]+(\d+)/i);
      const userMatch = line.match(/(?:user|account|username)[=:\s]+([a-zA-Z0-9._-]+)/i);
      const bytes = bytesMatch ? Number(bytesMatch[1]) : 4096;
      const dstPort = portMatch ? Number(portMatch[1]) : 443;
      const eventType = classifyTextLine(line, dstPort, bytes);
      records.push({
        timestamp: new Date().toISOString(),
        sourceIp,
        destinationIp,
        maskedDestinationIp: maskPrivateIp(destinationIp),
        sourcePort: 51024,
        destinationPort: dstPort,
        protocol: dstPort === 53 ? 'UDP' : 'TCP',
        eventType,
        username: userMatch?.[1],
        action: line.toLowerCase().includes('deny') || line.toLowerCase().includes('fail') ? 'DENIED' : 'OBSERVED',
        bytesTransferred: bytes,
        rawLogRef: lineRef,
        evidenceSha256,
        ingestionSource: `${ingestionSource}:syslog`,
        confidence: 76,
        title: `${eventType.replace(/_/g, ' ').toUpperCase()} detected (${sourceIp})`,
        description: `Extracted forensic event from line ${index + 1} targeting port ${dstPort}.`,
      });
    }
  });

  return records;
}
