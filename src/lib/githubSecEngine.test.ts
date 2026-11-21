import test from 'node:test';
import assert from 'node:assert/strict';
import {
  calculateBlastRadius,
  calculateRepositoryRiskScore,
  detectOffHoursActivity,
  isSensitiveFilePath,
  maskSecretValue,
  buildDemoGitHubOrganization,
} from './githubSecEngine';

test('maskSecretValue masks AWS access keys and never exposes plaintext', () => {
  const rawAws = 'AKIAIOSFODNN7EXAMPLE';
  const masked = maskSecretValue(rawAws, 'aws_access_key');
  assert.equal(masked.startsWith('AKIA'), true);
  assert.equal(masked.endsWith('MPLE'), true);
  assert.ok(masked.includes('••••'));
  assert.ok(!masked.includes('FODNN7'));
});

test('maskSecretValue masks GitHub Personal Access Tokens', () => {
  const rawPat = 'ghp_1234567890abcdef1234567890abcdef1234';
  const masked = maskSecretValue(rawPat, 'github_pat');
  assert.equal(masked.startsWith('ghp_'), true);
  assert.equal(masked.endsWith('1234'), true);
  assert.ok(masked.includes('••••'));
  assert.ok(!masked.includes('abcdef123456'));
});

test('isSensitiveFilePath detects workflow, terraform, env, and credential files', () => {
  assert.equal(isSensitiveFilePath('.github/workflows/deploy.yml'), true);
  assert.equal(isSensitiveFilePath('terraform/modules/main.tf'), true);
  assert.equal(isSensitiveFilePath('.env.production'), true);
  assert.equal(isSensitiveFilePath('certs/server.key'), true);
  assert.equal(isSensitiveFilePath('src/components/Header.tsx'), false);
  assert.equal(isSensitiveFilePath('README.md'), false);
});

test('detectOffHoursActivity identifies commits between 00:00 and 06:00 UTC', () => {
  assert.equal(detectOffHoursActivity('2026-11-21T03:42:00.000Z'), true);
  assert.equal(detectOffHoursActivity('2026-11-21T00:15:00.000Z'), true);
  assert.equal(detectOffHoursActivity('2026-11-21T14:30:00.000Z'), false);
  assert.equal(detectOffHoursActivity('2026-11-21T21:00:00.000Z'), false);
});

test('calculateRepositoryRiskScore maps severe conditions to critical risk level', () => {
  const result = calculateRepositoryRiskScore({
    visibility: 'private',
    criticalVulns: 1,
    highVulns: 2,
    mediumVulns: 1,
    exposedSecrets: 1,
    unpinnedActions: 2,
    branchProtectionDisabled: true,
    allowForcePushes: true,
    unusualActivityCount: 1,
  });

  assert.ok(result.riskScore >= 80, `Expected >= 80, got ${result.riskScore}`);
  assert.equal(result.riskLevel, 'critical');
  assert.ok(result.reasons.length >= 4);
});

test('calculateRepositoryRiskScore keeps safe repositories with zero issues bounded low', () => {
  const result = calculateRepositoryRiskScore({
    visibility: 'private',
    criticalVulns: 0,
    highVulns: 0,
    mediumVulns: 0,
    exposedSecrets: 0,
    unpinnedActions: 0,
    branchProtectionDisabled: false,
    allowForcePushes: false,
    unusualActivityCount: 0,
  });

  assert.ok(result.riskScore < 30);
  assert.equal(result.riskLevel, 'low');
});

test('calculateBlastRadius accounts for core production asset linkage and exposed secrets', () => {
  const highBlast = calculateBlastRadius('payments-engine', 'critical', 1, 1);
  const lowBlast = calculateBlastRadius('docs-static-site', 'low', 0, 0);

  assert.ok(highBlast >= 80, `Expected high blast >= 80, got ${highBlast}`);
  assert.ok(lowBlast <= 40, `Expected low blast <= 40, got ${lowBlast}`);
});

test('buildDemoGitHubOrganization adheres to all ground rules and contains DEMO DATA labels', () => {
  const org = buildDemoGitHubOrganization();

  assert.equal(org.status.isDemoData, true);
  assert.ok(org.repositories.length >= 5);
  assert.ok(org.repositories.every((r) => r.isDemoData === true));

  // Verify leaked AWS key presence with masked fingerprint
  const awsAlert = org.secrets.find((s) => s.secretType === 'aws_access_key');
  assert.ok(awsAlert, 'Expected leaked AWS key alert');
  assert.ok(awsAlert!.maskedFingerprint.includes('••••'));
  assert.ok(awsAlert!.remediationPlan.length >= 3);

  // Verify vulnerable dependency
  const vuln = org.vulnerabilities.find((v) => v.packageName === 'jsonwebtoken');
  assert.ok(vuln, 'Expected jsonwebtoken vulnerability');
  assert.equal(vuln!.severity, 'critical');

  // Verify developer activity anomaly
  const devAct = org.developerActivities.find((d) => d.action === 'force_push');
  assert.ok(devAct, 'Expected force_push developer activity');
  assert.equal(devAct!.isOffHours, true);
  assert.ok(devAct!.anomalyScore >= 75);
});
