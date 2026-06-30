// Org management — provider invites and roster (admin only).

import type { FastifyPluginAsync, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { nanoid } from 'nanoid';
import { prisma } from '../db.js';
import { sendProviderInviteEmail } from '../services/emailService.js';
import { sha256 } from '../utils/crypto.js';

const InviteSchema = z.object({
  email: z.string().email().max(255),
  role:  z.enum(['provider', 'admin']).default('provider'),
});

// preHandler hook — Fastify skips the route handler automatically when
// this hook sends a reply, making it physically impossible to forget the
// `return` that the old boolean-guard pattern required.
async function requireAdmin(req: FastifyRequest, reply: FastifyReply): Promise<void> {
  if ((req as any).provider?.role !== 'admin') {
    reply.code(403).send({ error: 'Admin role required' });
  }
}

export const orgRoutes: FastifyPluginAsync = async (app) => {
  // POST /api/org/invite — org admin invites a provider by email
  app.post('/invite', { preHandler: requireAdmin }, async (req, reply) => {
    const parsed = InviteSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const { email, role } = parsed.data;
    const { orgId, sub: inviterId } = req.provider!;

    // Prevent inviting an email that already has an account in any org
    const existing = await prisma.provider.findUnique({ where: { email } });
    if (existing) return reply.code(409).send({ error: 'A provider with this email already exists' });

    // Invalidate any pending invite for the same email in this org
    const pending = await prisma.providerInvite.findFirst({
      where: { orgId, email, acceptedAt: null },
    });
    if (pending) {
      await prisma.providerInvite.update({
        where: { id: pending.id },
        data:  { expiresAt: new Date() }, // expire immediately
      });
    }

    const rawToken  = nanoid(48);
    const tokenHash = sha256(rawToken);
    const expiresAt = new Date(Date.now() + 7 * 86_400_000); // 7 days

    await prisma.providerInvite.create({
      data: { orgId, email, tokenHash, role, expiresAt },
    });

    // Fetch org + inviter name for the email
    const [org, inviter] = await Promise.all([
      prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { name: true } }),
      prisma.provider.findUniqueOrThrow({ where: { id: inviterId }, select: { name: true } }),
    ]);

    const inviteUrl = `${process.env.APP_URL}/auth/invite/${rawToken}`;
    sendProviderInviteEmail(email, org.name, inviter.name ?? 'Your administrator', inviteUrl).catch(e =>
      app.log.warn({ err: e }, 'invite email failed'),
    );

    await prisma.auditLog.create({
      data: {
        orgId,
        providerId: inviterId,
        action:    'provider_invited',
        meta:      { email, role, inviteUrl },
        ipAddress: req.ip,
      },
    });

    return { ok: true, email, expiresAt };
  });

  // GET /api/org/providers — list all providers in the org
  app.get('/providers', async (req) => {
    const { orgId } = req.provider!;
    const providers = await prisma.provider.findMany({
      where:  { orgId },
      select: { id: true, email: true, name: true, credentials: true, specialty: true, role: true, createdAt: true },
      orderBy: { createdAt: 'asc' },
    });
    return { providers };
  });

  // GET /api/org/invites — list pending invites (admin only)
  app.get('/invites', { preHandler: requireAdmin }, async (req) => {
    const { orgId } = req.provider!;
    const invites = await prisma.providerInvite.findMany({
      where:   { orgId, acceptedAt: null, expiresAt: { gt: new Date() } },
      select:  { id: true, email: true, role: true, expiresAt: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    });
    return { invites };
  });

  // DELETE /api/org/providers/:id — remove a provider (admin only, cannot self-remove)
  app.delete('/providers/:id', { preHandler: requireAdmin }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const { orgId, sub: requesterId } = req.provider!;

    if (id === requesterId) return reply.code(400).send({ error: 'Cannot remove yourself' });

    const target = await prisma.provider.findFirst({ where: { id, orgId } });
    if (!target) return reply.code(404).send({ error: 'Provider not found in this org' });

    await prisma.$transaction([
      prisma.refreshToken.updateMany({
        where: { providerId: id, revokedAt: null },
        data:  { revokedAt: new Date() },
      }),
      prisma.provider.delete({ where: { id } }),
      prisma.auditLog.create({
        data: {
          orgId,
          providerId: requesterId,
          action:    'provider_removed',
          meta:      { removedProviderId: id, removedEmail: target.email },
          ipAddress: req.ip,
        },
      }),
    ]);

    return { ok: true };
  });

  // GET /api/org/stats — per-provider encounter counts for the last 30 days.
  // Available to all authenticated providers (not admin-only) so the roster
  // switcher can show activity badges without a separate admin request.
  app.get('/stats', async (req) => {
    const { orgId } = req.provider!;
    const since = new Date(Date.now() - 30 * 86_400_000);

    const [providers, counts] = await Promise.all([
      prisma.provider.findMany({
        where:   { orgId },
        select:  { id: true, name: true, email: true, credentials: true, specialty: true, role: true },
        orderBy: { createdAt: 'asc' },
      }),
      prisma.encounter.groupBy({
        by:    ['providerId'],
        where: { orgId, createdAt: { gte: since } },
        _count: { id: true },
      }),
    ]);

    const countMap = Object.fromEntries(counts.map(c => [c.providerId, c._count.id]));

    return {
      providers: providers.map(p => ({
        ...p,
        encounterCount30d: countMap[p.id] ?? 0,
      })),
      since: since.toISOString(),
    };
  });

  // GET /api/org/audit?page=1&limit=50&action= — paginated HIPAA audit log (admin only).
  // Returns raw AuditLog entries; the client resolves provider names from the roster.
  app.get('/audit', { preHandler: requireAdmin }, async (req, reply) => {
    const { orgId } = req.provider!;

    const q      = req.query as Record<string, string>;
    const page   = Math.max(1, parseInt(q['page']  ?? '1',  10));
    const limit  = Math.min(100, Math.max(1, parseInt(q['limit'] ?? '50', 10)));
    const action = q['action'] || undefined;

    const where = { orgId, ...(action ? { action } : {}) };

    const [total, entries] = await Promise.all([
      prisma.auditLog.count({ where }),
      prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip:  (page - 1) * limit,
        take:  limit,
        select: {
          id: true, action: true, meta: true, ipAddress: true, createdAt: true,
          encounterId: true, providerId: true,
        },
      }),
    ]);

    return { entries, total, page, pages: Math.ceil(total / limit) };
  });

  // DELETE /api/org/invites/:id — cancel a pending invite (admin only)
  app.delete('/invites/:id', { preHandler: requireAdmin }, async (req, reply) => {
    const { id }    = req.params as { id: string };
    const { orgId } = req.provider!;

    const invite = await prisma.providerInvite.findFirst({
      where: { id, orgId, acceptedAt: null },
    });
    if (!invite) return reply.code(404).send({ error: 'Invite not found or already accepted' });

    await prisma.providerInvite.update({
      where: { id },
      data:  { expiresAt: new Date() }, // expire immediately = cancel
    });
    return { ok: true };
  });
};
