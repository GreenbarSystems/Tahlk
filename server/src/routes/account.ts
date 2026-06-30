import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { prisma } from '../db.js';

const BaaSchema = z.object({
  version:       z.string().max(32),   // e.g. "tahlk-baa-v1"
  signedByName:  z.string().max(120),  // display name of the signer
});

export const accountRoutes: FastifyPluginAsync = async (app) => {
  // POST /api/account/accept-baa
  // Records HIPAA BAA acceptance. Creates an immutable AuditLog entry so
  // acceptance is auditable without relying solely on the Organization row.
  app.post('/accept-baa', async (req, reply) => {
    const parsed = BaaSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const { version, signedByName } = parsed.data;
    const { orgId, sub: providerId } = req.provider!;

    const org = await prisma.organization.findUnique({ where: { id: orgId } });
    if (!org) return reply.code(404).send({ error: 'Organization not found' });

    const acceptedAt = new Date();

    await prisma.$transaction([
      prisma.organization.update({
        where: { id: orgId },
        data:  { baaSignedAt: acceptedAt, baaSignedBy: signedByName },
      }),
      prisma.auditLog.create({
        data: {
          orgId,
          providerId,
          action:    'baa_accepted',
          meta: {
            version,
            signedByName,
            orgName:   org.name,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'] ?? null,
          },
        },
      }),
    ]);

    return { accepted: true, acceptedAt: acceptedAt.toISOString(), version };
  });

  // GET /api/account/me — return org + provider profile for the app to hydrate
  app.get('/me', async (req) => {
    const { orgId, sub: providerId } = req.provider!;
    const [org, provider] = await Promise.all([
      prisma.organization.findUniqueOrThrow({ where: { id: orgId },
        select: { id: true, name: true, tier: true, baaSignedAt: true } }),
      prisma.provider.findUniqueOrThrow({ where: { id: providerId },
        select: { id: true, email: true, name: true, credentials: true, specialty: true, role: true } }),
    ]);
    return { org, provider };
  });
};
