import type { FastifyPluginAsync, FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  createCheckoutSession,
  createPortalSession,
  getSubscriptionStatus,
  handleWebhookEvent,
} from '../services/billingService.js';

const CheckoutSchema = z.object({
  tier: z.enum(['SOLO', 'PRO', 'FIRM']),
});

// ── Stripe webhook (public, needs raw body for signature verification) ─────
// Registered in a dedicated sub-app with a buffer content-type parser so
// Fastify doesn't pre-parse the body before we hand it to Stripe.

export async function registerWebhookRoute(app: FastifyInstance) {
  await app.register(async (raw) => {
    raw.addContentTypeParser(
      'application/json',
      { parseAs: 'buffer' },
      (_req, body, done) => done(null, body),
    );

    raw.post('/billing/webhook', async (req, reply) => {
      const sig = req.headers['stripe-signature'] as string | undefined;
      if (!sig) return reply.code(400).send({ error: 'Missing Stripe-Signature header' });

      try {
        return await handleWebhookEvent(req.body as Buffer, sig);
      } catch (err: any) {
        req.log.warn({ err }, 'Stripe webhook error');
        return reply.code(400).send({ error: err.message });
      }
    });
  });
}

// ── Protected billing routes (JWT required) ────────────────────────────────

export const billingRoutes: FastifyPluginAsync = async (app) => {
  // GET /api/billing/status
  app.get('/status', async (req, reply) => {
    try {
      return await getSubscriptionStatus(req.provider!.orgId);
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  // POST /api/billing/checkout  { tier: 'SOLO' | 'PRO' | 'FIRM' }
  app.post('/checkout', async (req, reply) => {
    const parsed = CheckoutSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    try {
      return await createCheckoutSession(
        req.provider!.orgId,
        req.provider!.sub,
        parsed.data.tier,
      );
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  // POST /api/billing/portal
  app.post('/portal', async (req, reply) => {
    try {
      return await createPortalSession(req.provider!.orgId);
    } catch (err: any) {
      return reply.code(400).send({ error: err.message });
    }
  });
};

// ── Simple redirect pages (browser lands here after Stripe checkout) ───────

export async function registerBillingPages(app: FastifyInstance) {
  const html = (title: string, body: string) =>
    `<!doctype html><html><head><meta charset="utf-8">
     <title>${title} — Tahlk</title>
     <style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;
     justify-content:center;min-height:100vh;margin:0;background:#f8fafc}
     .card{background:#fff;border-radius:12px;padding:2.5rem 3rem;text-align:center;
     box-shadow:0 4px 24px #0001;max-width:420px}
     h1{color:#11284d;margin-bottom:.5rem}p{color:#6b7280}</style></head>
     <body><div class="card">${body}</div></body></html>`;

  app.get('/billing/success', async (_req, reply) =>
    reply.type('text/html').send(
      html('Payment Successful',
        '<h1>You\'re all set!</h1>' +
        '<p>Your Tahlk subscription is now active.</p>' +
        '<p>Return to the desktop app — your new plan will appear in Settings within a few seconds.</p>'),
    ),
  );

  app.get('/billing/cancel', async (_req, reply) =>
    reply.type('text/html').send(
      html('Checkout Cancelled',
        '<h1>No charge made</h1>' +
        '<p>Your checkout was cancelled. Return to the desktop app to try again.</p>'),
    ),
  );

  app.get('/billing/return', async (_req, reply) =>
    reply.type('text/html').send(
      html('Billing Updated',
        '<h1>Billing updated</h1>' +
        '<p>Return to the Tahlk desktop app. Changes will appear in Settings shortly.</p>'),
    ),
  );
}
