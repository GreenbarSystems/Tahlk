import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import { prisma } from './db.js';
import { verifyAccessToken } from './plugins/auth.js';
import { authRoutes } from './routes/auth.js';
import { syncRoutes } from './routes/sync.js';
import { billingRoutes, registerWebhookRoute, registerBillingPages } from './routes/billing.js';
import { accountRoutes } from './routes/account.js';
import { encounterRoutes } from './routes/encounters.js';
import { orgRoutes }       from './routes/org.js';

if (!process.env.JWT_SECRET || !process.env.REFRESH_SECRET) {
  console.error('FATAL: JWT_SECRET and REFRESH_SECRET must be set');
  process.exit(1);
}

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL ?? 'info',
    redact: ['req.headers.authorization', 'req.body.password', 'req.body.noteEnc',
             'req.body.transcriptEnc', 'req.body.flagsEnc'],
  },
});

await app.register(helmet);

await app.register(cors, {
  origin: process.env.ALLOWED_ORIGINS?.split(',') ?? [
    'tauri://localhost',
    'http://localhost:5181',
  ],
  credentials: true,
});

await app.register(cookie, { secret: process.env.COOKIE_SECRET });

await app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  keyGenerator: (req) => req.ip,
});

// ── Public routes ──────────────────────────────────────────────────────────

app.get('/health', async (_req, reply) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return { ok: true, db: 'ok', ts: new Date().toISOString() };
  } catch (err: any) {
    return reply.code(503).send({ ok: false, db: 'error', error: err.message, ts: new Date().toISOString() });
  }
});

await app.register(authRoutes, { prefix: '/auth' });

// Stripe webhook — raw body sub-app (must be before global JSON parser applies)
await registerWebhookRoute(app);

// Post-checkout browser landing pages
await registerBillingPages(app);

// ── Protected routes (JWT required) ───────────────────────────────────────

await app.register(
  async (api) => {
    api.addHook('onRequest', verifyAccessToken);
    await api.register(syncRoutes,      { prefix: '/sync' });
    await api.register(billingRoutes,   { prefix: '/billing' });
    await api.register(accountRoutes,   { prefix: '/account' });
    await api.register(encounterRoutes, { prefix: '/encounters' });
    await api.register(orgRoutes,       { prefix: '/org' });
  },
  { prefix: '/api' },
);

// ── Start ──────────────────────────────────────────────────────────────────

const port = Number(process.env.PORT ?? 3001);
await app.listen({ port, host: '0.0.0.0' });
