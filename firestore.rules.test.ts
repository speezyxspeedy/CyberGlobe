import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const rulesPath = path.resolve(process.cwd(), 'firestore.rules');
const blueprintPath = path.resolve(process.cwd(), 'firebase-blueprint.json');
const rules = fs.readFileSync(rulesPath, 'utf8');
const blueprint = JSON.parse(fs.readFileSync(blueprintPath, 'utf8'));

test('firestore.rules enforces default-deny catch-all at top of service block', () => {
  assert.match(rules, /match \/\{document=\*\*\}\s*\{\s*allow read, write: if false;\s*\}/);
});

test('firestore.rules covers every collection declared in firebase-blueprint.json', () => {
  const expectedMatches = [
    'match /users/{userId}',
    'match /private/{docId}',
    'match /assets/{assetId}',
    'match /cases/{caseId}',
    'match /notes/{noteId}',
    'match /evidence/{evidenceId}',
    'match /audit_logs/{logId}',
  ];
  for (const m of expectedMatches) {
    assert.ok(rules.includes(m), `Missing match block: ${m}`);
  }
  assert.equal(Object.keys(blueprint.firestore).length, 7);
});

test('firestore.rules blocks Dirty Dozen adversarial patterns', () => {
  // 1. Email verification enforced before admin email check
  assert.match(rules, /request\.auth\.token\.email_verified == true/);
  // 2. Strict key allowlists (blocks shadow fields)
  assert.ok(rules.includes('data.keys().hasOnly('));
  // 3. Immutable audit logs and evidence
  assert.ok(rules.includes('allow update, delete: if false;'));
  // 4. Terminal state locking for closed cases
  assert.ok(rules.includes("existing().status != 'closed'"));
  // 5. Server timestamp integrity
  assert.ok(rules.includes('incoming().createdAt == request.time'));
  assert.ok(rules.includes('incoming().updatedAt == request.time'));
  // 6. Parent existence Master Gate on subcollections
  assert.ok(rules.includes('exists(/databases/$(database)/documents/cases/$(caseId))'));
  // 7. No DB lookups inside allow list lines
  const listLines = rules.split('\n').filter((line) => line.trim().startsWith('allow list:'));
  assert.ok(listLines.length >= 4);
  for (const line of listLines) {
    assert.equal(line.includes('get('), false, `Forbidden get() in allow list: ${line}`);
    assert.equal(line.includes('exists('), false, `Forbidden exists() in allow list: ${line}`);
    assert.equal(line.includes('isAdmin()'), false, `Forbidden isAdmin() DB lookup in allow list: ${line}`);
  }
});
