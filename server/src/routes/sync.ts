import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { push, pull } from '../services/syncService.js';

const EncounterSchema = z.object({
  id: z.string().min(1).max(64),
  patientId: z.string().nullable().optional(),
  encounterDate: z.string().nullable().optional(),
  status: z.string().max(32),
  noteEnc: z.string().nullable().optional(),
  transcriptEnc: z.string().nullable().optional(),
  flagsEnc: z.string().nullable().optional(),
  signedAt: z.string().nullable().optional(),
  signedHash: z.string().nullable().optional(),
  signedBy: z.string().nullable().optional(),
  clientUpdatedAt: z.string(),
});

const PatientSchema = z.object({
  id: z.string().min(1).max(64),
  nameEnc: z.string().nullable().optional(),
  mrn: z.string().max(64).nullable().optional(),
  dob: z.string().max(20).nullable().optional(),
  notesEnc: z.string().nullable().optional(),
  clientUpdatedAt: z.string(),
});

const PushSchema = z.object({
  encounters: z.array(EncounterSchema).max(500),
  patients: z.array(PatientSchema).max(500),
});

export const syncRoutes: FastifyPluginAsync = async (app) => {
  // POST /api/sync/push — client sends local changes
  app.post('/push', async (req, reply) => {
    const parsed = PushSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const provider = req.provider!;
    const result = await push(provider.sub, provider.orgId, parsed.data);
    return result;
  });

  // GET /api/sync/pull?since=<ISO> — client fetches server changes
  app.get('/pull', async (req) => {
    const since = (req.query as Record<string, string>)['since'];
    const provider = req.provider!;
    return pull(provider.sub, provider.orgId, since);
  });
};
