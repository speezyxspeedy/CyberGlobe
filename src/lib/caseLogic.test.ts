import test from 'node:test';
import assert from 'node:assert/strict';
import {buildDemoDataset} from './demoScenario';
import {
  buildRelationshipGraph,
  exportEventsToCsv,
  generateCaseMarkdownReport,
  verifyEvidenceIntegrity,
} from './caseLogic';
import {sha256Hex} from './logParser';

test('buildRelationshipGraph links IP, domain, user, device, alert, and case nodes', () => {
  const data = buildDemoDataset();
  const case12 = data.cases.find((c) => c.id === 'CASE-2026-012')!;
  const graph = buildRelationshipGraph(case12, data.events, data.assets);
  assert.ok(graph.nodes.some((n) => n.kind === 'case'));
  assert.ok(graph.nodes.some((n) => n.kind === 'ip' && n.label === '203.0.113.45'));
  assert.ok(graph.nodes.some((n) => n.kind === 'domain'));
  assert.ok(graph.nodes.some((n) => n.kind === 'alert'));
  assert.ok(graph.nodes.some((n) => n.kind === 'device'));
  assert.ok(graph.edges.length >= 6);
});

test('verifyEvidenceIntegrity validates SHA-256 against raw content', () => {
  const payload = 'sample forensic log line';
  const hash = sha256Hex(payload);
  const valid = verifyEvidenceIntegrity(
    {
      id: 'EV-1',
      caseId: 'CASE-1',
      fileName: 'test.log',
      fileType: 'text/plain',
      fileSize: payload.length,
      sha256Hash: hash,
      collectedBy: 'Analyst',
      collectedAt: new Date().toISOString(),
      sourceSystem: 'SIEM',
      integrityStatus: 'verified',
      accessHistory: [],
    },
    payload
  );
  assert.equal(valid, true);
  assert.equal(
    verifyEvidenceIntegrity(
      {
        id: 'EV-1',
        caseId: 'CASE-1',
        fileName: 'test.log',
        fileType: 'text/plain',
        fileSize: payload.length,
        sha256Hash: hash,
        collectedBy: 'Analyst',
        collectedAt: new Date().toISOString(),
        sourceSystem: 'SIEM',
        integrityStatus: 'verified',
        accessHistory: [],
      },
      'tampered content'
    ),
    false
  );
});

test('generateCaseMarkdownReport and exportEventsToCsv include forensic notices and fields', () => {
  const data = buildDemoDataset();
  const case12 = data.cases[0];
  const linked = data.events.filter((e) => case12.linkedEventIds.includes(e.id));
  const md = generateCaseMarkdownReport(case12, linked);
  assert.match(md, /Approximate network location/);
  assert.match(md, /SHA-256/);
  assert.match(md, /CASE-2026-012/);
  // Phase 4 requirement: report must include limitations section
  assert.match(md, /Limitations/);
  assert.match(md, /not proof/i);
  assert.match(md, /probabilistic/i);

  const csv = exportEventsToCsv(linked);
  assert.ok(csv.startsWith('id,timestamp,event_type,severity,risk_score'));
  assert.ok(csv.split('\n').length === linked.length + 1);
});
