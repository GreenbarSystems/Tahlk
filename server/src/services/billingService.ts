import Stripe from 'stripe';
import { prisma } from '../db.js';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

// Price IDs come from your Stripe dashboard — one per tier per billing period
export const PRICE_IDS = {
  SOLO: process.env.STRIPE_PRICE_ID_SOLO!,
  PRO:  process.env.STRIPE_PRICE_ID_PRO!,
  FIRM: process.env.STRIPE_PRICE_ID_FIRM!,
} as const;

// Reverse map: Stripe price ID → internal tier (populated at startup)
const tierFromPrice = new Map<string, 'SOLO' | 'PRO' | 'FIRM'>();
Object.entries(PRICE_IDS).forEach(([tier, id]) => {
  if (id) tierFromPrice.set(id, tier as 'SOLO' | 'PRO' | 'FIRM');
});

// ── Checkout ───────────────────────────────────────────────────────────────

export async function createCheckoutSession(
  orgId: string,
  providerId: string,
  tier: 'SOLO' | 'PRO' | 'FIRM',
) {
  const org = await prisma.organization.findUniqueOrThrow({ where: { id: orgId } });

  // Reuse existing Stripe customer so subscriptions stay attached to one account
  let customerId = org.stripeCustomerId ?? undefined;
  if (!customerId) {
    const provider = await prisma.provider.findUniqueOrThrow({ where: { id: providerId } });
    const customer = await stripe.customers.create({
      email: provider.email,
      name: org.name,
      metadata: { orgId, providerId },
    });
    customerId = customer.id;
    await prisma.organization.update({
      where: { id: orgId },
      data: { stripeCustomerId: customerId },
    });
  }

  const appUrl = process.env.APP_URL ?? 'https://app.tahlkscribe.com';

  const session = await stripe.checkout.sessions.create({
    customer: customerId,
    mode: 'subscription',
    line_items: [{ price: PRICE_IDS[tier], quantity: 1 }],
    success_url: `${appUrl}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url:  `${appUrl}/billing/cancel`,
    metadata: { orgId, tier },
    subscription_data: { metadata: { orgId, tier } },
    allow_promotion_codes: true,
  });

  return { url: session.url! };
}

// ── Customer portal ────────────────────────────────────────────────────────

export async function createPortalSession(orgId: string) {
  const org = await prisma.organization.findUniqueOrThrow({ where: { id: orgId } });
  if (!org.stripeCustomerId) throw new Error('No billing account found for this organization');

  const appUrl = process.env.APP_URL ?? 'https://app.tahlkscribe.com';

  const session = await stripe.billingPortal.sessions.create({
    customer: org.stripeCustomerId,
    return_url: `${appUrl}/billing/return`,
  });

  return { url: session.url };
}

// ── Subscription status ────────────────────────────────────────────────────

export async function getSubscriptionStatus(orgId: string) {
  const org = await prisma.organization.findUniqueOrThrow({ where: { id: orgId } });

  if (!org.stripeSubId) {
    return { tier: org.tier, status: 'free', currentPeriodEnd: null, cancelAtPeriodEnd: false };
  }

  // Cast through unknown — Stripe v22 types omit current_period_end at top level
  // but the API still returns it on simple subscriptions (no schedule).
  const sub = (await stripe.subscriptions.retrieve(org.stripeSubId)) as unknown as Record<string, any>;
  return {
    tier:              org.tier,
    status:            sub['status'] as string,
    currentPeriodEnd:  sub['current_period_end']
      ? new Date((sub['current_period_end'] as number) * 1000).toISOString()
      : null,
    cancelAtPeriodEnd: Boolean(sub['cancel_at_period_end']),
  };
}

// ── Webhook ────────────────────────────────────────────────────────────────

export async function handleWebhookEvent(payload: Buffer, signature: string) {
  const event = stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET!,
  );

  switch (event.type) {
    // Payment completed → activate subscription
    case 'checkout.session.completed': {
      const session = event.data.object as Stripe.Checkout.Session;
      if (session.mode !== 'subscription') break;

      const orgId = session.metadata?.orgId;
      const tier  = session.metadata?.tier as 'SOLO' | 'PRO' | 'FIRM' | undefined;
      if (!orgId || !tier) break;

      await prisma.organization.update({
        where: { id: orgId },
        data:  { stripeSubId: session.subscription as string, tier },
      });
      break;
    }

    // Plan changed (upgrade / downgrade)
    case 'customer.subscription.updated': {
      const sub   = event.data.object as Stripe.Subscription;
      const orgId = sub.metadata?.orgId;
      if (!orgId) break;

      const priceId = sub.items.data[0]?.price.id;
      const tier    = priceId ? tierFromPrice.get(priceId) : undefined;
      if (tier) {
        await prisma.organization.update({ where: { id: orgId }, data: { tier } });
      }
      break;
    }

    // Subscription ended → drop back to SOLO (free)
    case 'customer.subscription.deleted': {
      const sub   = event.data.object as Stripe.Subscription;
      const orgId = sub.metadata?.orgId;
      if (!orgId) break;

      await prisma.organization.update({
        where: { id: orgId },
        data:  { tier: 'SOLO', stripeSubId: null },
      });
      break;
    }
  }

  return { received: true };
}
