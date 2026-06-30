import { prisma } from '../db.js';

interface EncounterInput {
  id: string;
  patientId?: string | null;
  encounterDate?: string | null;
  status: string;
  noteEnc?: string | null;
  transcriptEnc?: string | null;
  flagsEnc?: string | null;
  signedAt?: string | null;
  signedHash?: string | null;
  signedBy?: string | null;
  clientUpdatedAt: string;
}

interface PatientInput {
  id: string;
  nameEnc?: string | null;
  mrn?: string | null;
  dob?: string | null;
  notesEnc?: string | null;
  clientUpdatedAt: string;
}

export interface PushPayload {
  encounters: EncounterInput[];
  patients: PatientInput[];
}

export interface PushResult {
  pushed: number;
  skipped: number; // already-signed encounters, not modified
}

export async function push(
  providerId: string,
  orgId: string,
  data: PushPayload,
): Promise<PushResult> {
  const result: PushResult = { pushed: 0, skipped: 0 };

  for (const enc of data.encounters) {
    const existing = await prisma.encounter.findFirst({
      where: { id: enc.id, orgId },
      select: { signedAt: true },
    });

    // Signed encounters are immutable on the server.
    // The client's signed_hash is the integrity guarantee — server never decrypts.
    if (existing?.signedAt) {
      result.skipped++;
      continue;
    }

    await prisma.encounter.upsert({
      where: { id: enc.id },
      create: {
        id: enc.id,
        orgId,
        providerId,
        patientId: enc.patientId ?? null,
        encounterDate: enc.encounterDate ? new Date(enc.encounterDate) : null,
        status: enc.status,
        noteEnc: enc.noteEnc ?? null,
        transcriptEnc: enc.transcriptEnc ?? null,
        flagsEnc: enc.flagsEnc ?? null,
        signedAt: enc.signedAt ? new Date(enc.signedAt) : null,
        signedHash: enc.signedHash ?? null,
        signedBy: enc.signedBy ?? null,
        clientUpdatedAt: new Date(enc.clientUpdatedAt),
      },
      update: {
        patientId: enc.patientId ?? null,
        encounterDate: enc.encounterDate ? new Date(enc.encounterDate) : null,
        status: enc.status,
        noteEnc: enc.noteEnc ?? null,
        transcriptEnc: enc.transcriptEnc ?? null,
        flagsEnc: enc.flagsEnc ?? null,
        signedAt: enc.signedAt ? new Date(enc.signedAt) : null,
        signedHash: enc.signedHash ?? null,
        signedBy: enc.signedBy ?? null,
        clientUpdatedAt: new Date(enc.clientUpdatedAt),
        syncedAt: new Date(),
      },
    });
    result.pushed++;
  }

  for (const patient of data.patients) {
    await prisma.patient.upsert({
      where: { id: patient.id },
      create: {
        id: patient.id,
        orgId,
        nameEnc: patient.nameEnc ?? null,
        mrn: patient.mrn ?? null,
        dob: patient.dob ?? null,
        notesEnc: patient.notesEnc ?? null,
        clientUpdatedAt: new Date(patient.clientUpdatedAt),
      },
      update: {
        nameEnc: patient.nameEnc ?? null,
        mrn: patient.mrn ?? null,
        dob: patient.dob ?? null,
        notesEnc: patient.notesEnc ?? null,
        clientUpdatedAt: new Date(patient.clientUpdatedAt),
        syncedAt: new Date(),
      },
    });
    result.pushed++;
  }

  return result;
}

export async function pull(
  providerId: string,
  orgId: string,
  since?: string,
): Promise<{ encounters: unknown[]; patients: unknown[]; cursor: string }> {
  const cursor = since ? new Date(since) : new Date(0);

  const [encounters, patients] = await Promise.all([
    prisma.encounter.findMany({
      where: { orgId, providerId, syncedAt: { gt: cursor } },
      orderBy: { syncedAt: 'asc' },
      take: 1000,
    }),
    prisma.patient.findMany({
      where: { orgId, syncedAt: { gt: cursor } },
      orderBy: { syncedAt: 'asc' },
      take: 1000,
    }),
  ]);

  return {
    encounters,
    patients,
    cursor: new Date().toISOString(),
  };
}
