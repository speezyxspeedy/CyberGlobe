import {initializeApp} from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut as fbSignOut,
  type User,
} from 'firebase/auth';
import {
  doc,
  getDocFromServer,
  getFirestore,
  serverTimestamp,
  setDoc,
  updateDoc,
} from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';
import type {
  CaseNote,
  EvidenceFile,
  InvestigationCase,
  ProtectedAsset,
  UserRole,
} from '../types/forensics';
import {sha256Hex} from './logParser';

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}
void testConnection();

export async function signInWithGoogle(): Promise<User> {
  const result = await signInWithPopup(auth, googleProvider);
  const user = result.user;
  const role: UserRole = user.email === 'gshubh349@gmail.com' ? 'Admin' : 'Analyst';

  try {
    await setDoc(
      doc(db, 'users', user.uid),
      {
        uid: user.uid,
        displayName: (user.displayName || 'SOC Investigator').slice(0, 120),
        role,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      },
      {merge: false}
    ).catch(async () => {
      await updateDoc(doc(db, 'users', user.uid), {
        displayName: (user.displayName || 'SOC Investigator').slice(0, 120),
        updatedAt: serverTimestamp(),
      });
    });

    if (user.email) {
      await setDoc(
        doc(db, 'users', user.uid, 'private', 'info'),
        {
          uid: user.uid,
          email: user.email.slice(0, 254),
          updatedAt: serverTimestamp(),
        },
        {merge: false}
      ).catch(async () => {
        await updateDoc(doc(db, 'users', user.uid, 'private', 'info'), {
          email: user.email!.slice(0, 254),
          updatedAt: serverTimestamp(),
        });
      });
    }
  } catch (error) {
    // Non-blocking profile sync notice; structured error logged
    console.warn('Profile sync skipped:', error);
  }

  return user;
}

export async function signOutUser(): Promise<void> {
  await fbSignOut(auth);
}

function sanitizeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
}

export async function persistAssetToFirestore(asset: ProtectedAsset): Promise<void> {
  const user = auth.currentUser;
  if (!user || !user.emailVerified) return;
  const safeId = sanitizeId(asset.id);
  const path = `assets/${safeId}`;
  try {
    await setDoc(doc(db, 'assets', safeId), {
      id: safeId,
      ownerId: user.uid,
      name: asset.name.slice(0, 140),
      ipOrInternalId: asset.ipOrInternalId.slice(0, 64),
      locationLabel: asset.locationLabel.slice(0, 120),
      latitude: asset.latitude,
      longitude: asset.longitude,
      assetType: asset.assetType,
      criticality: asset.criticality,
      openPorts: asset.openPorts.slice(0, 32),
      riskScore: Math.max(0, Math.min(100, asset.riskScore)),
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function persistCaseToFirestore(forensicCase: InvestigationCase): Promise<void> {
  const user = auth.currentUser;
  if (!user || !user.emailVerified) return;
  const safeId = sanitizeId(forensicCase.id);
  const path = `cases/${safeId}`;
  try {
    await setDoc(doc(db, 'cases', safeId), {
      id: safeId,
      ownerId: user.uid,
      title: forensicCase.title.slice(0, 180),
      description: forensicCase.description.slice(0, 4000),
      priority: forensicCase.priority,
      status: forensicCase.status,
      assignedAnalyst: forensicCase.assignedAnalyst.slice(0, 120),
      tags: forensicCase.tags.slice(0, 10).map((t) => t.slice(0, 40)),
      linkedEventIds: forensicCase.linkedEventIds.slice(0, 50).map((id) => id.slice(0, 128)),
      linkedIps: forensicCase.linkedIps.slice(0, 50).map((ip) => ip.slice(0, 64)),
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function persistCaseNoteToFirestore(caseId: string, note: CaseNote): Promise<void> {
  const user = auth.currentUser;
  if (!user || !user.emailVerified) return;
  const safeCaseId = sanitizeId(caseId);
  const safeNoteId = sanitizeId(note.id);
  const path = `cases/${safeCaseId}/notes/${safeNoteId}`;
  try {
    await setDoc(doc(db, 'cases', safeCaseId, 'notes', safeNoteId), {
      id: safeNoteId,
      caseId: safeCaseId,
      authorId: user.uid,
      authorName: (note.authorName || user.displayName || 'Analyst').slice(0, 120),
      content: note.content.slice(0, 3000),
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function persistEvidenceToFirestore(caseId: string, ev: EvidenceFile): Promise<void> {
  const user = auth.currentUser;
  if (!user || !user.emailVerified) return;
  const safeCaseId = sanitizeId(caseId);
  const safeEvId = sanitizeId(ev.id);
  const path = `cases/${safeCaseId}/evidence/${safeEvId}`;
  try {
    await setDoc(doc(db, 'cases', safeCaseId, 'evidence', safeEvId), {
      id: safeEvId,
      caseId: safeCaseId,
      ownerId: user.uid,
      fileName: ev.fileName.slice(0, 200),
      fileType: ev.fileType.slice(0, 64),
      fileSize: Math.max(0, Math.min(52428800, ev.fileSize)),
      sha256Hash: ev.sha256Hash,
      collectedBy: ev.collectedBy.slice(0, 120),
      sourceSystem: ev.sourceSystem.slice(0, 120),
      integrityStatus: ev.integrityStatus,
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function persistAuditLogToFirestore(
  action: string,
  targetType: string,
  targetId: string,
  details: string
): Promise<void> {
  const user = auth.currentUser;
  if (!user || !user.emailVerified) return;
  const safeId = sanitizeId(`aud-${Date.now()}-${Math.floor(Math.random() * 999)}`);
  const path = `audit_logs/${safeId}`;
  try {
    await setDoc(doc(db, 'audit_logs', safeId), {
      id: safeId,
      actorId: user.uid,
      actorName: (user.displayName || 'Investigator').slice(0, 120),
      action: action.slice(0, 120),
      targetType: targetType.slice(0, 64),
      targetId: targetId.slice(0, 128),
      details: details.slice(0, 1000),
      entryHash: sha256Hex(`${safeId}:${user.uid}:${action}:${targetId}:${details}`),
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}
