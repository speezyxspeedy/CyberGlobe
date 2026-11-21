import type {
  GitHubAuditEvent,
  GitHubConnectionStatus,
  GitHubDeveloperActivity,
  GitHubRepository,
  GitHubScanReport,
  GitHubSecretAlert,
  GitHubVulnerability,
  GitHubWorkflowRun,
  Severity,
} from '../types/forensics';
import {classifyRiskLevel} from './riskEngine';

/**
 * Mask raw secret strings so credentials are NEVER exposed in plain text.
 * Returns only the prefix (e.g. "AKIA"), a 12-dot mask, and the trailing 4 characters.
 */
export function maskSecretValue(secret: string, type = 'api_key'): string {
  const trimmed = secret.trim();
  if (trimmed.length <= 8) {
    return '••••••••••••';
  }
  if (type === 'aws_access_key' && trimmed.startsWith('AKIA')) {
    const suffix = trimmed.slice(-4);
    return `AKIA••••••••••••${suffix}`;
  }
  if (type === 'github_pat' && (trimmed.startsWith('ghp_') || trimmed.startsWith('github_pat_'))) {
    const prefix = trimmed.slice(0, 4);
    const suffix = trimmed.slice(-4);
    return `${prefix}••••••••••••${suffix}`;
  }
  const prefix = trimmed.slice(0, 3);
  const suffix = trimmed.slice(-4);
  return `${prefix}••••••••••••${suffix}`;
}

/**
 * Identify sensitive paths (auth, credentials, secrets, CI/CD, infra-as-code).
 */
export function isSensitiveFilePath(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  const sensitivePatterns = [
    /\.github\/workflows\//,
    /\.env(?:\..*)?$/,
    /(?:id_rsa|id_ed25519|\.pem|\.key|\.crt)$/,
    /(?:secret|credential|password|token)/,
    /(?:terraform|tfvars|helm|ansible|k8s|kubernetes|cloudformation)/,
    /(?:auth|login|session|jwt|oauth|saml)/,
    /dockerfile/i,
    /sudoers|passwd|shadow/,
  ];
  return sensitivePatterns.some((pattern) => pattern.test(lower));
}

/**
 * Detect commits outside standard operational windows (00:00 to 06:00).
 */
export function detectOffHoursActivity(timestampIso: string): boolean {
  try {
    const date = new Date(timestampIso);
    const hour = date.getUTCHours();
    return hour >= 0 && hour < 6;
  } catch {
    return false;
  }
}

/**
 * Calculate multi-factor Repository Risk Score (0 - 100).
 */
export function calculateRepositoryRiskScore(input: {
  visibility: 'public' | 'private' | 'internal';
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  exposedSecrets: number;
  unpinnedActions: number;
  branchProtectionDisabled: boolean;
  allowForcePushes: boolean;
  unusualActivityCount: number;
  isStale?: boolean;
}): {riskScore: number; riskLevel: Severity; reasons: string[]} {
  let score = 0;
  const reasons: string[] = [];

  // 1. Exposed Secrets (Highest critical impact: up to 45 pts)
  if (input.exposedSecrets > 0) {
    const secretPts = Math.min(45, input.exposedSecrets * 30);
    score += secretPts;
    reasons.push(`${input.exposedSecrets} exposed secret(s) detected in source tree`);
  }

  // 2. Critical & High CVEs (Up to 35 pts)
  if (input.criticalVulns > 0) {
    const critPts = Math.min(30, input.criticalVulns * 25);
    score += critPts;
    reasons.push(`${input.criticalVulns} Critical severity dependency/code CVE(s)`);
  }
  if (input.highVulns > 0) {
    const highPts = Math.min(15, input.highVulns * 8);
    score += highPts;
    reasons.push(`${input.highVulns} High severity vulnerability alert(s)`);
  }

  // 3. Branch Protection & Integrity Posture (Up to 20 pts)
  if (input.branchProtectionDisabled) {
    score += 15;
    reasons.push('Default branch protection is disabled');
  } else if (input.allowForcePushes) {
    score += 8;
    reasons.push('Branch protection allows force-pushes without admin oversight');
  }

  // 4. CI/CD & Supply Chain Risk (Up to 15 pts)
  if (input.unpinnedActions > 0) {
    score += Math.min(15, input.unpinnedActions * 5);
    reasons.push(`${input.unpinnedActions} unpinned third-party GitHub Action(s)`);
  }

  // 5. Developer Activity Anomaly (Up to 15 pts)
  if (input.unusualActivityCount > 0) {
    score += Math.min(15, input.unusualActivityCount * 8);
    reasons.push('Anomalous developer activity or off-hours sensitive file modifications');
  }

  // 6. Public Exposure Multiplier
  if (input.visibility === 'public') {
    score = Math.round(score * 1.25);
    reasons.push('Public visibility increases exposure surface');
  }

  const finalScore = Math.max(5, Math.min(100, score));
  return {
    riskScore: finalScore,
    riskLevel: classifyRiskLevel(finalScore),
    reasons,
  };
}

/**
 * Calculate blast radius score (0 - 100) if repository or secret is compromised.
 */
export function calculateBlastRadius(
  repoName: string,
  linkedAssetCriticality: Severity | null,
  exposedSecretCount: number,
  criticalVulnCount: number
): number {
  let radius = 25; // baseline

  // Core production services have high systemic blast radius
  if (/auth|payment|gateway|core|infra|terraform/i.test(repoName)) {
    radius += 35;
  }
  if (linkedAssetCriticality === 'critical') {
    radius += 25;
  } else if (linkedAssetCriticality === 'high') {
    radius += 15;
  }
  if (exposedSecretCount > 0) {
    radius += 15;
  }
  if (criticalVulnCount > 0) {
    radius += 10;
  }

  return Math.min(100, radius);
}

/**
 * Build realistic, non-slop Demo GitHub Organization dataset complying with all ground rules.
 */
export function buildDemoGitHubOrganization(): {
  status: GitHubConnectionStatus;
  repositories: GitHubRepository[];
  secrets: GitHubSecretAlert[];
  vulnerabilities: GitHubVulnerability[];
  workflows: GitHubWorkflowRun[];
  developerActivities: GitHubDeveloperActivity[];
  auditEvents: GitHubAuditEvent[];
  lastScanReport: GitHubScanReport;
} {
  const status: GitHubConnectionStatus = {
    connected: true,
    orgName: 'ApexCyber-Global-Org',
    installationId: 'gh-inst-49210492',
    connectedAt: '2026-11-20T14:00:00.000Z',
    lastScanAt: '2026-11-21T10:15:00.000Z',
    selectedRepoCount: 6,
    totalRepoCount: 18,
    permissions: {
      contents: 'read',
      pull_requests: 'read',
      workflows: 'read',
      security_events: 'read',
      secret_scanning: 'read',
      dependabot: 'read',
      administration: 'read',
    },
    retentionPolicyDays: 90,
    dataProcessingPurpose: 'Defensive code supply-chain audit and developer anomaly telemetry.',
    tokenStorageMode: 'encrypted_at_rest_aes_256_gcm',
    isDemoData: true,
  };

  const repositories: GitHubRepository[] = [
    {
      id: 'repo-infra-terraform',
      name: 'infra-cloud-terraform',
      fullName: 'ApexCyber-Global-Org/infra-cloud-terraform',
      owner: 'ApexCyber-Global-Org',
      visibility: 'private',
      language: 'HCL / Terraform',
      defaultBranch: 'main',
      lastActivity: '2026-11-21T03:42:15.000Z',
      riskScore: 92,
      riskLevel: 'critical',
      branchProtection: {
        enabled: false,
        requireApprovals: 0,
        enforceAdmins: false,
        requireSignedCommits: false,
        allowForcePushes: true,
      },
      vulnerabilityCount: {critical: 0, high: 2, medium: 1, low: 0},
      exposedSecretCount: 1,
      thirdPartyActionCount: 3,
      linkedAssetId: 'asset-mum-ssh-01',
      linkedAssetName: 'Bastion SSH Proxy (Mumbai DC-01)',
      blastRadiusScore: 95,
      locationCoordinates: {latitude: 19.076, longitude: 72.8777, city: 'Mumbai', country: 'India'},
      isDemoData: true,
    },
    {
      id: 'repo-payments-engine',
      name: 'payments-engine',
      fullName: 'ApexCyber-Global-Org/payments-engine',
      owner: 'ApexCyber-Global-Org',
      visibility: 'private',
      language: 'Go',
      defaultBranch: 'main',
      lastActivity: '2026-11-21T04:15:30.000Z',
      riskScore: 88,
      riskLevel: 'critical',
      branchProtection: {
        enabled: true,
        requireApprovals: 1,
        enforceAdmins: false,
        requireSignedCommits: false,
        allowForcePushes: true,
      },
      vulnerabilityCount: {critical: 1, high: 1, medium: 2, low: 1},
      exposedSecretCount: 0,
      thirdPartyActionCount: 4,
      linkedAssetId: 'asset-iad-api-01',
      linkedAssetName: 'Core API Gateway (US-East)',
      blastRadiusScore: 90,
      locationCoordinates: {latitude: 39.0438, longitude: -77.4874, city: 'Ashburn', country: 'United States'},
      isDemoData: true,
    },
    {
      id: 'repo-auth-gateway',
      name: 'auth-gateway',
      fullName: 'ApexCyber-Global-Org/auth-gateway',
      owner: 'ApexCyber-Global-Org',
      visibility: 'private',
      language: 'TypeScript / Node.js',
      defaultBranch: 'main',
      lastActivity: '2026-11-20T21:30:00.000Z',
      riskScore: 78,
      riskLevel: 'high',
      branchProtection: {
        enabled: true,
        requireApprovals: 2,
        enforceAdmins: true,
        requireSignedCommits: true,
        allowForcePushes: false,
      },
      vulnerabilityCount: {critical: 1, high: 0, medium: 2, low: 0},
      exposedSecretCount: 0,
      thirdPartyActionCount: 2,
      linkedAssetId: 'asset-fra-db-02',
      linkedAssetName: 'Customer Ledger DB (Frankfurt)',
      blastRadiusScore: 82,
      locationCoordinates: {latitude: 50.1109, longitude: 8.6821, city: 'Frankfurt', country: 'Germany'},
      isDemoData: true,
    },
    {
      id: 'repo-core-api',
      name: 'core-api',
      fullName: 'ApexCyber-Global-Org/core-api',
      owner: 'ApexCyber-Global-Org',
      visibility: 'internal',
      language: 'Python / FastAPI',
      defaultBranch: 'main',
      lastActivity: '2026-11-20T18:45:00.000Z',
      riskScore: 54,
      riskLevel: 'medium',
      branchProtection: {
        enabled: true,
        requireApprovals: 2,
        enforceAdmins: true,
        requireSignedCommits: false,
        allowForcePushes: false,
      },
      vulnerabilityCount: {critical: 0, high: 1, medium: 3, low: 2},
      exposedSecretCount: 0,
      thirdPartyActionCount: 1,
      linkedAssetId: 'asset-iad-api-01',
      linkedAssetName: 'Core API Gateway (US-East)',
      blastRadiusScore: 68,
      locationCoordinates: {latitude: 37.7749, longitude: -122.4194, city: 'San Francisco', country: 'United States'},
      isDemoData: true,
    },
    {
      id: 'repo-frontend-console',
      name: 'frontend-dashboard',
      fullName: 'ApexCyber-Global-Org/frontend-dashboard',
      owner: 'ApexCyber-Global-Org',
      visibility: 'public',
      language: 'TypeScript / React',
      defaultBranch: 'main',
      lastActivity: '2026-11-20T16:10:00.000Z',
      riskScore: 42,
      riskLevel: 'medium',
      branchProtection: {
        enabled: true,
        requireApprovals: 1,
        enforceAdmins: true,
        requireSignedCommits: false,
        allowForcePushes: false,
      },
      vulnerabilityCount: {critical: 0, high: 0, medium: 2, low: 4},
      exposedSecretCount: 0,
      thirdPartyActionCount: 2,
      blastRadiusScore: 35,
      locationCoordinates: {latitude: 1.3521, longitude: 103.8198, city: 'Singapore', country: 'Singapore'},
      isDemoData: true,
    },
    {
      id: 'repo-data-pipeline',
      name: 'data-pipeline',
      fullName: 'ApexCyber-Global-Org/data-pipeline',
      owner: 'ApexCyber-Global-Org',
      visibility: 'private',
      language: 'Scala / Spark',
      defaultBranch: 'main',
      lastActivity: '2026-11-19T11:20:00.000Z',
      riskScore: 28,
      riskLevel: 'low',
      branchProtection: {
        enabled: true,
        requireApprovals: 2,
        enforceAdmins: true,
        requireSignedCommits: true,
        allowForcePushes: false,
      },
      vulnerabilityCount: {critical: 0, high: 0, medium: 1, low: 2},
      exposedSecretCount: 0,
      thirdPartyActionCount: 0,
      blastRadiusScore: 40,
      locationCoordinates: {latitude: 51.5074, longitude: -0.1278, city: 'London', country: 'United Kingdom'},
      isDemoData: true,
    },
  ];

  // Leaked AWS Key in infra-cloud-terraform (NEVER raw secret, masked fingerprint only)
  const secrets: GitHubSecretAlert[] = [
    {
      id: 'sec-alert-aws-01',
      secretType: 'aws_access_key',
      secretTypeLabel: 'AWS IAM Long-Term Access Key',
      repositoryId: 'repo-infra-terraform',
      repositoryName: 'infra-cloud-terraform',
      maskedFingerprint: 'AKIA••••••••••••7X9A',
      filePath: 'terraform/modules/s3_storage/main.tf',
      line: 42,
      commitSha: 'c8f309b1a52098402f1a2384918e982138940123',
      commitAuthor: 'devops-lead',
      commitTimestamp: '2026-11-21T03:41:00.000Z',
      status: 'open',
      exposureRisk: 'critical',
      remediationPlan: [
        'Immediately deactivate and delete Access Key in AWS IAM Console.',
        'Inspect AWS CloudTrail events for API calls made with this access key ID in the last 48 hours.',
        'Rotate associated S3 and EC2 IAM instance profile roles.',
        'Run git-filter-repo or BFG Repo-Cleaner to scrub commit history before next push.',
        'Install pre-commit secret-scanning hooks across developer workstations.',
      ],
      detectedAt: '2026-11-21T03:42:00.000Z',
      isDemoData: true,
    },
  ];

  // Vulnerable dependency (Dependabot alert)
  const vulnerabilities: GitHubVulnerability[] = [
    {
      id: 'vuln-json-web-token-01',
      cveId: 'CVE-2022-23529',
      packageName: 'jsonwebtoken',
      currentVersion: '8.5.1',
      fixedVersion: '9.0.0',
      severity: 'critical',
      repositoryId: 'repo-auth-gateway',
      repositoryName: 'auth-gateway',
      ecosystem: 'npm',
      summary: 'jsonwebtoken insecure KeyObject parameter leads to arbitrary code execution (RCE).',
      exploitAvailable: true,
      manifestPath: 'services/auth/package.json',
      isDemoData: true,
      detectedAt: '2026-11-20T21:30:00.000Z',
    },
    {
      id: 'vuln-golang-crypto-02',
      cveId: 'CVE-2023-39325',
      packageName: 'golang.org/x/net',
      currentVersion: '0.14.0',
      fixedVersion: '0.17.0',
      severity: 'high',
      repositoryId: 'repo-payments-engine',
      repositoryName: 'payments-engine',
      ecosystem: 'go',
      summary: 'HTTP/2 Rapid Reset vulnerability allows remote denial of service (DDoS).',
      exploitAvailable: true,
      manifestPath: 'go.mod',
      isDemoData: true,
      detectedAt: '2026-11-21T02:10:00.000Z',
    },
  ];

  // CI/CD Workflows
  const workflows: GitHubWorkflowRun[] = [
    {
      id: 'wf-run-deploy-prod-01',
      repositoryId: 'repo-payments-engine',
      repositoryName: 'payments-engine',
      name: 'Production Deploy Workflow',
      event: 'push',
      status: 'completed',
      conclusion: 'success',
      headBranch: 'main',
      headSha: 'a4b1c2d3e4f50912',
      actor: 'alex.v (DevOps)',
      runnerType: 'self-hosted',
      unpinnedActions: ['actions/checkout@v2', 'docker/build-push-action@v2'],
      secretsReferenced: ['AWS_PROD_DEPLOY_KEY', 'PAYMENT_VAULT_TOKEN'],
      startedAt: '2026-11-21T03:45:00.000Z',
      completedAt: '2026-11-21T03:51:20.000Z',
      isDemoData: true,
    },
    {
      id: 'wf-run-infra-plan-02',
      repositoryId: 'repo-infra-terraform',
      repositoryName: 'infra-cloud-terraform',
      name: 'Terraform Cloud Apply',
      event: 'push',
      status: 'failed',
      conclusion: 'failure',
      headBranch: 'main',
      headSha: 'c8f309b1a5209840',
      actor: 'devops-lead',
      runnerType: 'github-hosted',
      unpinnedActions: ['hashicorp/setup-terraform@v1'],
      secretsReferenced: ['TF_CLOUD_API_TOKEN', 'AWS_ACCESS_KEY_ID'],
      startedAt: '2026-11-21T03:42:10.000Z',
      completedAt: '2026-11-21T03:44:00.000Z',
      isDemoData: true,
    },
  ];

  // Developer activity anomalies
  const developerActivities: GitHubDeveloperActivity[] = [
    {
      id: 'dev-act-01',
      username: 'alex.v',
      email: 'alex.v@apexcyber.internal',
      repositoryId: 'repo-payments-engine',
      repositoryName: 'payments-engine',
      action: 'force_push',
      commitMessage: 'hotfix: bypass auth validation on webhook endpoint [skip ci]',
      timestamp: '2026-11-21T03:42:00.000Z',
      isOffHours: true,
      filesChanged: ['.github/workflows/deploy.yml', 'services/gateway/webhook.go'],
      sensitiveFilesChanged: ['.github/workflows/deploy.yml'],
      additions: 142,
      deletions: 89,
      anomalyScore: 86,
      anomalyReason: 'Force-push at 03:42 UTC directly modifying production CI/CD pipeline and bypassing branch protection rule.',
      location: {city: 'Frankfurt', country: 'Germany', latitude: 50.1109, longitude: 8.6821},
      isDemoData: true,
    },
    {
      id: 'dev-act-02',
      username: 'devops-lead',
      email: 'devops-lead@apexcyber.internal',
      repositoryId: 'repo-infra-terraform',
      repositoryName: 'infra-cloud-terraform',
      action: 'commit',
      commitMessage: 'feat: add S3 bucket and emergency root credentials',
      timestamp: '2026-11-21T03:41:00.000Z',
      isOffHours: true,
      filesChanged: ['terraform/modules/s3_storage/main.tf'],
      sensitiveFilesChanged: ['terraform/modules/s3_storage/main.tf'],
      additions: 34,
      deletions: 2,
      anomalyScore: 78,
      anomalyReason: 'Off-hours commit introducing long-term AWS access key credentials into version control.',
      location: {city: 'Ashburn', country: 'United States', latitude: 39.0438, longitude: -77.4874},
      isDemoData: true,
    },
  ];

  // Audit Events
  const auditEvents: GitHubAuditEvent[] = [
    {
      id: 'aud-gh-01',
      action: 'repo.add_member',
      actor: 'org-admin',
      org: 'ApexCyber-Global-Org',
      repositoryName: 'infra-cloud-terraform',
      targetUser: 'external-contractor-09',
      timestamp: '2026-11-21T02:15:00.000Z',
      ipAddress: '198.51.100.204',
      approxLocation: 'Amsterdam, Netherlands (VPN egress)',
      details: 'Added external collaborator with Write permission to infra-cloud-terraform.',
      isDemoData: true,
    },
    {
      id: 'aud-gh-02',
      action: 'protected_branch.policy_override',
      actor: 'alex.v',
      org: 'ApexCyber-Global-Org',
      repositoryName: 'payments-engine',
      timestamp: '2026-11-21T03:42:00.000Z',
      ipAddress: '198.51.100.77',
      approxLocation: 'Frankfurt, Germany',
      details: 'Admin override used to force-push commit a4b1c2 to branch main without 2 required peer approvals.',
      isDemoData: true,
    },
  ];

  const lastScanReport: GitHubScanReport = {
    scanId: 'scan-gh-2026-11-21-01',
    startedAt: '2026-11-21T10:14:00.000Z',
    completedAt: '2026-11-21T10:15:30.000Z',
    status: 'completed',
    scannedRepositories: 6,
    criticalIssuesFound: 2,
    secretsExposed: 1,
    vulnerabilitiesFound: 2,
    developerAnomalies: 2,
    overallOrgRiskScore: 84,
    isDemoData: true,
  };

  return {
    status,
    repositories,
    secrets,
    vulnerabilities,
    workflows,
    developerActivities,
    auditEvents,
    lastScanReport,
  };
}
