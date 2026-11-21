import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRdpLogs, detectRdpThreats } from './rdpParser';
import { sha256Hex } from './logParser';
import type { RdpFootprint } from './rdpParser';

// ──────────────────────────────────────────────────────────────────────────────
// Well-shaped samples
// ──────────────────────────────────────────────────────────────────────────────

const SAMPLE_4625 = 'EventID:4625 Logon Type: 10 Account Name: administrator Source Network Address: 203.0.113.45';
const SAMPLE_4624 = 'EventID:4624 Logon Type: 10 Account Name: john.doe Source Network Address: 198.51.100.77';
const SAMPLE_1149 = 'TerminalServices-RemoteConnectionManager 1149 Remote session from 192.0.2.211 User: jane.smith';
const SAMPLE_LSM21 = 'EventID:21 Session ID: 3 Source Network Address: 203.0.113.45 User: root';
const SAMPLE_LSM23 = 'EventID:23 Session ID: 3 User: root';
const SAMPLE_131 = 'RdpCoreTS EventID:131 Client IP: 198.51.100.204 Connection accepted';
const SAMPLE_140 = 'RdpCoreTS EventID:140 Client IP: 203.0.113.99 Connection failed';
const SAMPLE_NETFLOW = 'SRC=203.0.113.50 DST=10.0.0.5 DPT=3389 SPT=51234 PROTO=TCP';
const SAMPLE_4776 = 'EventID:4776 Account Name: backup_svc Logon Type: 3 Source Network Address: 198.51.100.100';
const SAMPLE_4647 = 'EventID:4647 Account Name: john.doe Session ID: 3';

// Malformed / edge-case samples
const MALFORMED_NO_IP = 'EventID:4625 Logon Type: 10 Account Name: attacker';  // 4625 without IP — still accepted (IP=0.0.0.0)
const MALFORMED_GARBAGE = 'completely unrelated log line with no rdp signals';
const MALFORMED_PARTIAL = 'EventID:4624 Logon Type:';                              // truncated line

// ──────────────────────────────────────────────────────────────────────────────
// Parser tests
// ──────────────────────────────────────────────────────────────────────────────

test('parseRdpLogs: Security 4625 failure line parses to auth_fail', () => {
  const result = parseRdpLogs(SAMPLE_4625, false);
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].kind, 'auth_fail');
  assert.equal(result.records[0].source, 'security');
  assert.equal(result.records[0].srcIp, '203.0.113.45');
  assert.equal(result.records[0].user, 'administrator');
  assert.equal(result.records[0].eventId, 4625);
  assert.equal(result.records[0].dstPort, 3389);
  assert.equal(result.records[0].demo, false);
});

test('parseRdpLogs: Security 4624 LogonType 10 parses to auth_ok', () => {
  const result = parseRdpLogs(SAMPLE_4624, false);
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].kind, 'auth_ok');
  assert.equal(result.records[0].srcIp, '198.51.100.77');
  assert.equal(result.records[0].user, 'john.doe');
});

test('parseRdpLogs: TermSvcs 1149 produces auth_ok with source IP', () => {
  const result = parseRdpLogs(SAMPLE_1149, false);
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].kind, 'auth_ok');
  assert.equal(result.records[0].source, 'termsvcs_rcm');
  assert.equal(result.records[0].srcIp, '192.0.2.211');
});

test('parseRdpLogs: LSM 21 (session open) and 23 (session close) classified correctly', () => {
  const result = parseRdpLogs(`${SAMPLE_LSM21}\n${SAMPLE_LSM23}`, false);
  assert.equal(result.records.length, 2);
  assert.equal(result.records[0].kind, 'session_open');
  assert.equal(result.records[0].source, 'termsvcs_lsm');
  assert.equal(result.records[1].kind, 'session_close');
});

test('parseRdpLogs: RdpCoreTS 131 (accepted) and 140 (failed) parse correctly', () => {
  const result = parseRdpLogs(`${SAMPLE_131}\n${SAMPLE_140}`, false);
  assert.equal(result.records.length, 2);
  assert.equal(result.records[0].kind, 'connection_accepted');
  assert.equal(result.records[0].source, 'rdpcorets');
  assert.equal(result.records[1].kind, 'connection_failed');
});

test('parseRdpLogs: NetFlow line to port 3389 produces network_attempt', () => {
  const result = parseRdpLogs(SAMPLE_NETFLOW, false);
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].kind, 'network_attempt');
  assert.equal(result.records[0].source, 'netflow');
  assert.equal(result.records[0].dstPort, 3389);
});

test('parseRdpLogs: Security 4776 (NTLM validation) parsed', () => {
  const result = parseRdpLogs(SAMPLE_4776, false);
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].kind, 'ntlm_validation');
});

test('parseRdpLogs: mixed batch of 10 valid lines produces 10 records', () => {
  const batch = [
    SAMPLE_4625, SAMPLE_4624, SAMPLE_1149,
    SAMPLE_LSM21, SAMPLE_LSM23, SAMPLE_131,
    SAMPLE_140, SAMPLE_NETFLOW, SAMPLE_4776, SAMPLE_4647,
  ].join('\n');
  const result = parseRdpLogs(batch, true);
  assert.ok(result.records.length >= 8, `expected ≥8 records, got ${result.records.length}`);
  assert.ok(result.records.every((r) => r.demo === true), 'all records should carry demo=true');
});

test('parseRdpLogs: 4625 without IP still produces record (IP=0.0.0.0)', () => {
  const result = parseRdpLogs(MALFORMED_NO_IP, false);
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].srcIp, '0.0.0.0');
});

test('parseRdpLogs: garbage line is skipped without throwing', () => {
  const result = parseRdpLogs(MALFORMED_GARBAGE, false);
  assert.equal(result.records.length, 0);
  assert.equal(result.rejectCount, 0); // garbage lines are silently skipped, not counted as rejects
});

test('parseRdpLogs: truncated / partial line does not throw', () => {
  assert.doesNotThrow(() => parseRdpLogs(MALFORMED_PARTIAL, false));
});

test('parseRdpLogs: rawHash on every record is a 64-char hex string', () => {
  const result = parseRdpLogs(SAMPLE_4625, false);
  for (const r of result.records) {
    assert.match(r.rawHash, /^[a-f0-9]{64}$/, `bad hash on record ${r.id}`);
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// Detection engine tests
// ──────────────────────────────────────────────────────────────────────────────

function makeFailFootprint(ip: string, user = 'admin', offsetMs = 0): RdpFootprint {
  return {
    id: `test-${Math.random()}`,
    ts: new Date(Date.now() - offsetMs).toISOString(),
    source: 'security' as const,
    kind: 'auth_fail' as const,
    srcIp: ip,
    srcIpMasked: ip,
    dstPort: 3389,
    user,
    rawHash: sha256Hex(`${ip}:${user}:${offsetMs}`),
    demo: true,
  };
}

function makeSuccessFootprint(ip: string, user = 'admin'): RdpFootprint {
  return {
    id: `test-${Math.random()}`,
    ts: new Date().toISOString(),
    source: 'security' as const,
    kind: 'auth_ok' as const,
    srcIp: ip,
    srcIpMasked: ip,
    dstPort: 3389,
    user,
    rawHash: sha256Hex(`${ip}:${user}:success`),
    demo: true,
  };
}

test('detectRdpThreats: brute force fires at threshold (10 failures/5 min)', () => {
  const footprints = Array.from({ length: 12 }, (_, i) =>
    makeFailFootprint('203.0.113.45', 'admin', i * 10_000)
  );
  const detections = detectRdpThreats(footprints, { failureThreshold: 10, windowMinutes: 5 });
  const bf = detections.find((d) => d.kind === 'brute_force');
  assert.ok(bf, 'brute_force detection expected');
  assert.equal(bf!.srcIp, '203.0.113.45');
  assert.ok(['medium', 'high', 'critical'].includes(bf!.severity));
});

test('detectRdpThreats: password spray detected (many users, few attempts each)', () => {
  const users = ['alice', 'bob', 'carol', 'dave', 'eve', 'frank'];
  const footprints = users.flatMap((u) => [
    makeFailFootprint('198.51.100.10', u, 1000),
    makeFailFootprint('198.51.100.10', u, 2000),
  ]);
  const detections = detectRdpThreats(footprints, { failureThreshold: 10, windowMinutes: 5 });
  const spray = detections.find((d) => d.kind === 'password_spray');
  assert.ok(spray, 'password_spray detection expected');
  assert.equal(spray!.srcIp, '198.51.100.10');
});

test('detectRdpThreats: success after failures is Critical', () => {
  const ip = '192.0.2.77';
  const footprints = [
    makeFailFootprint(ip, 'admin', 50_000),
    makeFailFootprint(ip, 'admin', 40_000),
    makeFailFootprint(ip, 'admin', 30_000),
    makeSuccessFootprint(ip, 'admin'),
  ];
  const detections = detectRdpThreats(footprints, { failureThreshold: 10, windowMinutes: 5 });
  const saf = detections.find((d) => d.kind === 'success_after_failures');
  assert.ok(saf, 'success_after_failures detection expected');
  assert.equal(saf!.severity, 'critical');
  assert.equal(saf!.srcIp, ip);
});

test('detectRdpThreats: distributed attack detected with ≥10 unique IPs', () => {
  const footprints = Array.from({ length: 10 }, (_, i) =>
    makeFailFootprint(`198.51.100.${i + 1}`, 'admin', i * 5000)
  );
  // Add more fails per IP to pass brute force threshold
  const denseFootprints = footprints.flatMap((fp) =>
    Array.from({ length: 11 }, (_, j) => ({ ...fp, id: `${fp.id}-${j}`, rawHash: fp.rawHash + j }))
  );
  const detections = detectRdpThreats(denseFootprints, { failureThreshold: 10, windowMinutes: 5 });
  const dist = detections.find((d) => d.kind === 'distributed_attack');
  assert.ok(dist, 'distributed_attack detection expected');
  assert.ok(dist!.detail.includes('10') || dist!.detail.includes('unique source IPs'));
});

test('detectRdpThreats: no detections for quiet baseline (3 failures, 1 IP)', () => {
  const footprints = [
    makeFailFootprint('10.0.0.1', 'admin', 1000),
    makeFailFootprint('10.0.0.1', 'admin', 2000),
    makeFailFootprint('10.0.0.1', 'admin', 3000),
  ];
  const detections = detectRdpThreats(footprints, { failureThreshold: 10, windowMinutes: 5 });
  assert.equal(detections.length, 0, 'No detections expected for low-volume baseline');
});
