import test from 'node:test';
import assert from 'node:assert/strict';
import {calculateRiskScore, classifyRiskLevel} from './riskEngine';

test('classifyRiskLevel maps score boundaries accurately', () => {
  assert.equal(classifyRiskLevel(15), 'low');
  assert.equal(classifyRiskLevel(42), 'medium');
  assert.equal(classifyRiskLevel(68), 'high');
  assert.equal(classifyRiskLevel(85), 'critical');
});

test('high-velocity SSH brute-force with high abuse reputation scores critical', () => {
  const result = calculateRiskScore({
    eventType: 'ssh_brute_force',
    abuseConfidence: 86,
    failedAuthCount: 512,
    connectionType: 'mobile',
    vpnProbability: 0.18,
    historicalEventsCount: 12,
    targetedAssetCount: 2,
    offHoursAnomaly: true,
    correlatedSourceCount: 3,
    evidenceRefs: ['auth.log:4192'],
  });
  assert.ok(result.riskScore >= 80, `Expected critical >= 80, got ${result.riskScore}`);
  assert.equal(result.riskLevel, 'critical');
  assert.ok(result.confidence >= 70);
  assert.ok(result.reasons.length >= 2);
  assert.match(result.recommendedAction, /Block IP/i);
});

test('large outbound data exfiltration via Tor exit node flags anonymizer warning', () => {
  const result = calculateRiskScore({
    eventType: 'data_exfiltration',
    abuseConfidence: 91,
    outboundBytes: 1_500_000_000,
    connectionType: 'tor',
    vpnProbability: 0.95,
    unusualGeoOrigin: true,
    correlatedSourceCount: 2,
  });
  assert.equal(result.riskLevel, 'critical');
  assert.match(result.recommendedAction, /anonymizer/i);
  assert.ok(result.factors.some((f) => f.name === 'Outbound Transfer Volume' && f.contribution >= 20));
});

test('low-volume reconnaissance scan stays bounded between low and medium', () => {
  const result = calculateRiskScore({
    eventType: 'port_scan',
    abuseConfidence: 15,
    portsScanned: 8,
    connectionType: 'residential',
    vpnProbability: 0.05,
  });
  assert.ok(result.riskScore < 50, `Expected < 50, got ${result.riskScore}`);
  assert.ok(result.riskLevel === 'low' || result.riskLevel === 'medium');
});
