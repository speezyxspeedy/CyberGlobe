# CyberTrace Globe — Firestore Security Specification (Phase 0 TDD)

## 1. Data Invariants
1. **Master Gate & Parent Existence**: Every `/cases/{caseId}/notes/{noteId}` and `/cases/{caseId}/evidence/{evidenceId}` write requires the parent `/cases/{caseId}` document to exist and belong to the authenticated owner (or verified Admin).
2. **PII Isolation**: User email addresses are stored exclusively under `/users/{userId}/private/info` and are readable/writable only by `request.auth.uid == userId` or verified Admin. Public `/users/{userId}` profiles contain no PII.
3. **Immutable Evidence & Audit Trails**: Evidence records (`/cases/{caseId}/evidence/{evidenceId}`) and audit logs (`/audit_logs/{logId}`) are append-only: client updates and deletes are strictly forbidden (except Admin review on non-audit items where explicitly defined).
4. **Role Escalation Prevention**: Users creating `/users/{userId}` cannot self-assign `role: "Admin"` unless verified against the bootstrapped Admin check (`email == 'gshubh349@gmail.com' && email_verified == true`). Role field cannot be modified by non-admins on update.
5. **Terminal Case Locking**: Once a case reaches `status: "closed"`, non-admin users cannot mutate its fields.
6. **Temporal & Structural Integrity**: All `createdAt`/`updatedAt` timestamps must match `request.time`. All IDs match `^[a-zA-Z0-9_\-]+$` with max length 128. Every string has an explicit `.size()` bound and every list has a `.size()` bound.

## 2. The "Dirty Dozen" Adversarial Payloads (Must Return PERMISSION_DENIED)
1. **Unauthenticated Case Read**: `GET /cases/case-1` with `auth == null`.
2. **Shadow Field Injection**: `CREATE /cases/case-99` with valid fields + `isVerified: true`.
3. **Identity Spoofing on Create**: `CREATE /cases/case-99` with `ownerId: "victim_uid"` while authenticated as `"attacker_uid"`.
4. **Privilege Escalation on Registration**: `CREATE /users/attacker_uid` with `role: "Admin"`.
5. **Email Spoofing Admin Bypass**: `READ /users/victim/private/info` with `email: "gshubh349@gmail.com"` and `email_verified: false`.
6. **PII Cross-User Read**: `GET /users/victim_uid/private/info` as another signed-in user.
7. **Orphaned Evidence Write**: `CREATE /cases/nonexistent_case/evidence/ev-1` where parent case does not exist.
8. **Evidence Tampering Update**: `UPDATE /cases/case-1/evidence/ev-1` attempting to alter `sha256Hash`.
9. **Audit Log Deletion**: `DELETE /audit_logs/log-1` by any non-admin or admin user (immutable trail).
10. **Terminal State Mutation**: `UPDATE /cases/closed_case` by owner attempting to change `priority` after `status == "closed"`.
11. **Resource Poisoning ID**: `CREATE /assets/<200-char-junk-id>` exceeding 128-char ID regex limit.
12. **Client Timestamp Forgery**: `CREATE /cases/case-2` with backdated `createdAt` not equal to `request.time`.
