import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import * as bcrypt from 'bcryptjs';
import { SignJWT, jwtVerify } from 'jose';
import { nanoid } from 'nanoid';
import { prisma } from '../db.js';
import { sha256 } from '../utils/crypto.js';
import {
  sendWelcomeEmail,
  sendPasswordResetEmail,
  sendProviderInviteEmail,
} from '../services/emailService.js';

const SECRET = new TextEncoder().encode(process.env.JWT_SECRET!);
const REFRESH_SECRET = new TextEncoder().encode(process.env.REFRESH_SECRET!);

const ACCESS_TTL = '15m';
const REFRESH_TTL_DAYS = 30;
const BCRYPT_ROUNDS = 12;

// Comma-separated list of valid beta access codes; empty = open registration.
const BETA_CODES = new Set(
  (process.env.BETA_CODES ?? '').split(',').map(c => c.trim()).filter(Boolean),
);

// ── Schemas ───────────────────────────────────────────────────────────────────

const RegisterSchema = z.object({
  orgName:   z.string().min(1).max(100),
  email:     z.string().email().max(255),
  password:  z.string().min(12).max(128),
  name:      z.string().max(100).optional(),
  betaCode:  z.string().max(64).optional(),
});

const LoginSchema = z.object({
  email:      z.string().email(),
  password:   z.string(),
  deviceId:   z.string().min(1).max(64),
  deviceName: z.string().max(100).optional(),
});

const RefreshSchema = z.object({
  deviceId: z.string().min(1).max(64),
});

const ForgotSchema = z.object({
  email: z.string().email().max(255),
});

const ResetSchema = z.object({
  token:       z.string().min(1).max(128),
  newPassword: z.string().min(12).max(128),
});

const AcceptInviteSchema = z.object({
  token:    z.string().min(1).max(128),
  name:     z.string().min(1).max(100),
  password: z.string().min(12).max(128),
});

// ── Helpers ───────────────────────────────────────────────────────────────────

async function signAccess(providerId: string, orgId: string, role: string): Promise<string> {
  return new SignJWT({ orgId, role })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(providerId)
    .setIssuedAt()
    .setExpirationTime(ACCESS_TTL)
    .sign(SECRET);
}

async function issueRefreshToken(
  providerId: string,
  deviceId: string,
  deviceName?: string,
): Promise<string> {
  const rawToken  = nanoid(48);
  const tokenHash = sha256(rawToken);
  const expiresAt = new Date(Date.now() + REFRESH_TTL_DAYS * 86_400_000);

  await prisma.refreshToken.updateMany({
    where: { providerId, deviceId, revokedAt: null },
    data:  { revokedAt: new Date() },
  });

  await prisma.refreshToken.create({
    data: { providerId, tokenHash, deviceId, deviceName, expiresAt },
  });

  return rawToken;
}

function setRefreshCookie(reply: any, token: string): void {
  reply.setCookie('rt', token, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge:   REFRESH_TTL_DAYS * 86_400,
    path:     '/auth',
  });
}

// Full HTML-attribute-safe encoding — prevents XSS in server-rendered forms.
// Covers all five dangerous characters: & < > " '
function esc(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// Shared HTML shell for server-rendered forms (reset password, invite accept)
function formPage(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} — Tahlk</title>
<style>
  *{box-sizing:border-box}
  body{font-family:system-ui,sans-serif;background:#f8fafc;margin:0;padding:32px 16px;min-height:100vh}
  .card{background:#fff;border-radius:12px;padding:32px 36px;max-width:440px;margin:0 auto;
        box-shadow:0 1px 4px #0001}
  h1{color:#11284d;font-size:20px;margin-top:0}
  p{color:#374151;font-size:14px;line-height:1.6}
  label{display:block;font-size:12px;font-weight:600;color:#374151;
        text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px;margin-top:14px}
  input{width:100%;padding:9px 12px;border:1px solid #d1d5db;border-radius:6px;
        font-size:14px;outline:none}
  input:focus{border-color:#2563eb;box-shadow:0 0 0 3px #dbeafe}
  button{width:100%;padding:11px;background:#11284d;color:#fff;border:none;border-radius:6px;
         font-size:15px;font-weight:600;cursor:pointer;margin-top:20px}
  button:hover{background:#1e3a5f}
  .msg{font-size:13px;margin-top:12px;padding:10px 14px;border-radius:6px;display:none}
  .msg--ok{background:#dcfce7;color:#166534}
  .msg--err{background:#fee2e2;color:#991b1b}
</style></head>
<body><div class="card">${body}</div></body></html>`;
}

// ── Routes ────────────────────────────────────────────────────────────────────

export const authRoutes: FastifyPluginAsync = async (app) => {
  // POST /auth/register — create org + first provider (admin)
  app.post('/register', async (req, reply) => {
    const parsed = RegisterSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const { orgName, email, password, name, betaCode } = parsed.data;

    if (BETA_CODES.size > 0 && !BETA_CODES.has(betaCode ?? '')) {
      return reply.code(403).send({ error: 'Invalid beta invite code' });
    }

    const existing = await prisma.provider.findUnique({ where: { email } });
    if (existing) return reply.code(409).send({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const org          = await prisma.organization.create({ data: { name: orgName } });
    const provider     = await prisma.provider.create({
      data: { orgId: org.id, email, passwordHash, name: name ?? null, role: 'admin' },
    });

    // Best-effort welcome email — doesn't block the response
    sendWelcomeEmail(email, name ?? email, orgName).catch(e =>
      app.log.warn({ err: e }, 'welcome email failed'),
    );

    return reply.code(201).send({ providerId: provider.id, orgId: org.id });
  });

  // POST /auth/login
  // Strict per-IP limit — 5 attempts/min prevents password spraying without
  // blocking legitimate users who mistype once or twice.
  app.post('/login', {
    config: { rateLimit: { max: 5, timeWindow: '1 minute' } },
  }, async (req, reply) => {
    const parsed = LoginSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const { email, password, deviceId, deviceName } = parsed.data;

    const provider = await prisma.provider.findUnique({ where: { email } });
    const validPassword = provider
      ? await bcrypt.compare(password, provider.passwordHash)
      : await bcrypt.hash(password, BCRYPT_ROUNDS).then(() => false);

    if (!provider || !validPassword) {
      return reply.code(401).send({ error: 'Invalid credentials' });
    }

    const [accessToken, refreshToken] = await Promise.all([
      signAccess(provider.id, provider.orgId, provider.role),
      issueRefreshToken(provider.id, deviceId, deviceName),
    ]);

    setRefreshCookie(reply, refreshToken);

    return {
      accessToken,
      provider: {
        id: provider.id, email: provider.email, name: provider.name,
        credentials: provider.credentials, specialty: provider.specialty,
        role: provider.role, orgId: provider.orgId,
      },
    };
  });

  // POST /auth/refresh — exchange RT cookie for new access token
  app.post('/refresh', async (req, reply) => {
    const parsed = RefreshSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const rawToken = req.cookies['rt'];
    if (!rawToken) return reply.code(401).send({ error: 'No refresh token' });

    const tokenHash = sha256(rawToken);
    const stored    = await prisma.refreshToken.findUnique({
      where:   { tokenHash },
      include: { provider: true },
    });

    if (!stored || stored.revokedAt || stored.expiresAt < new Date()) {
      reply.clearCookie('rt', { path: '/auth' });
      return reply.code(401).send({ error: 'Refresh token invalid or expired' });
    }

    if (stored.deviceId !== parsed.data.deviceId) {
      await prisma.refreshToken.update({
        where: { id: stored.id },
        data:  { revokedAt: new Date() },
      });
      reply.clearCookie('rt', { path: '/auth' });
      return reply.code(401).send({ error: 'Device mismatch — please log in again' });
    }

    const accessToken = await signAccess(
      stored.provider.id, stored.provider.orgId, stored.provider.role,
    );
    return { accessToken };
  });

  // POST /auth/logout
  app.post('/logout', async (req, reply) => {
    const rawToken = req.cookies['rt'];
    if (rawToken) {
      const tokenHash = sha256(rawToken);
      await prisma.refreshToken
        .updateMany({ where: { tokenHash }, data: { revokedAt: new Date() } })
        .catch(() => {});
      reply.clearCookie('rt', { path: '/auth' });
    }
    return { ok: true };
  });

  // ── Password reset ──────────────────────────────────────────────────────────

  // POST /auth/forgot-password
  // Always returns 200 — never reveals whether email exists (prevents user enumeration).
  // Tight limit — reset emails are expensive and a high request rate indicates abuse.
  app.post('/forgot-password', {
    config: { rateLimit: { max: 3, timeWindow: '15 minutes' } },
  }, async (req, reply) => {
    const parsed = ForgotSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const provider = await prisma.provider.findUnique({ where: { email: parsed.data.email } });

    if (provider) {
      const rawToken  = nanoid(48);
      const tokenHash = sha256(rawToken);
      const expiresAt = new Date(Date.now() + 3_600_000); // 1 hour

      // Invalidate any existing unexpired reset tokens for this provider
      await prisma.passwordResetToken.updateMany({
        where: { providerId: provider.id, usedAt: null },
        data:  { usedAt: new Date() },
      });

      await prisma.passwordResetToken.create({
        data: { providerId: provider.id, tokenHash, expiresAt },
      });

      const resetUrl = `${process.env.APP_URL}/auth/reset-password?token=${rawToken}`;
      sendPasswordResetEmail(provider.email, resetUrl).catch(e =>
        app.log.warn({ err: e }, 'reset email failed'),
      );
    }

    return { ok: true };
  });

  // GET /auth/reset-password?token=... — serves the reset form in the browser
  app.get('/reset-password', async (req, reply) => {
    const token = (req.query as Record<string, string>)['token'] ?? '';
    reply.type('text/html').send(formPage('Reset Password', `
      <h1>Set a new password</h1>
      <form id="f">
        <input type="hidden" id="token" value="${esc(token)}">
        <label>New password (12+ characters)</label>
        <input type="password" id="pw" minlength="12" autocomplete="new-password" required>
        <label>Confirm password</label>
        <input type="password" id="pw2" minlength="12" autocomplete="new-password" required>
        <button type="submit">Reset Password</button>
      </form>
      <div class="msg" id="msg"></div>
      <script>
        document.getElementById('f').addEventListener('submit', async e => {
          e.preventDefault();
          const pw = document.getElementById('pw').value;
          const pw2 = document.getElementById('pw2').value;
          const msg = document.getElementById('msg');
          if (pw !== pw2) { msg.className='msg msg--err'; msg.textContent='Passwords do not match.'; msg.style.display=''; return; }
          const btn = e.target.querySelector('button');
          btn.disabled = true; btn.textContent = 'Saving…';
          const r = await fetch('/auth/reset-password', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ token: document.getElementById('token').value, newPassword: pw }),
          });
          const d = await r.json();
          if (r.ok) {
            msg.className='msg msg--ok'; msg.textContent='Password updated! Return to the Tahlk app and log in.';
            e.target.style.display='none';
          } else {
            msg.className='msg msg--err'; msg.textContent=d.error ?? 'Reset failed — link may have expired.';
            btn.disabled=false; btn.textContent='Reset Password';
          }
          msg.style.display='';
        });
      </script>
    `));
  });

  // POST /auth/reset-password
  app.post('/reset-password', async (req, reply) => {
    const parsed = ResetSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const { token, newPassword } = parsed.data;
    const tokenHash = sha256(token);

    const record = await prisma.passwordResetToken.findUnique({
      where: { tokenHash },
    });

    if (!record || record.usedAt || record.expiresAt < new Date()) {
      return reply.code(400).send({ error: 'Reset link is invalid or has expired' });
    }

    const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

    await prisma.$transaction([
      prisma.provider.update({
        where: { id: record.providerId },
        data:  { passwordHash },
      }),
      prisma.passwordResetToken.update({
        where: { id: record.id },
        data:  { usedAt: new Date() },
      }),
      // Revoke all refresh tokens — forces re-login on all devices
      prisma.refreshToken.updateMany({
        where: { providerId: record.providerId, revokedAt: null },
        data:  { revokedAt: new Date() },
      }),
    ]);

    return { ok: true };
  });

  // ── Provider invite acceptance ──────────────────────────────────────────────

  // GET /auth/invite/:token — serves the invite acceptance form in the browser
  app.get('/invite/:token', async (req, reply) => {
    const { token } = req.params as { token: string };
    const tokenHash = sha256(token);

    const invite = await prisma.providerInvite.findUnique({
      where:   { tokenHash },
      include: { org: { select: { name: true } } },
    });

    if (!invite || invite.acceptedAt || invite.expiresAt < new Date()) {
      reply.type('text/html').send(formPage('Invitation Expired', `
        <h1>This invitation has expired</h1>
        <p>Please ask your practice administrator to send a new invitation.</p>
      `));
      return;
    }

    reply.type('text/html').send(formPage('Accept Invitation', `
      <h1>Join ${esc(invite.org.name)}</h1>
      <p>You've been invited to join <strong>${esc(invite.org.name)}</strong> on Tahlk.</p>
      <form id="f">
        <input type="hidden" id="token" value="${esc(token)}">
        <label>Your full name</label>
        <input type="text" id="name" placeholder="Dr. Jane Smith" required>
        <label>Password (12+ characters)</label>
        <input type="password" id="pw" minlength="12" autocomplete="new-password" required>
        <label>Confirm password</label>
        <input type="password" id="pw2" minlength="12" autocomplete="new-password" required>
        <button type="submit">Create Account</button>
      </form>
      <div class="msg" id="msg"></div>
      <script>
        document.getElementById('f').addEventListener('submit', async e => {
          e.preventDefault();
          const pw = document.getElementById('pw').value;
          const pw2 = document.getElementById('pw2').value;
          const msg = document.getElementById('msg');
          if (pw !== pw2) { msg.className='msg msg--err'; msg.textContent='Passwords do not match.'; msg.style.display=''; return; }
          const btn = e.target.querySelector('button');
          btn.disabled = true; btn.textContent = 'Creating account…';
          const r = await fetch('/auth/accept-invite', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({
              token: document.getElementById('token').value,
              name:  document.getElementById('name').value,
              password: pw,
            }),
          });
          const d = await r.json();
          if (r.ok) {
            msg.className='msg msg--ok';
            msg.textContent='Account created! Open the Tahlk app and log in with your email address.';
            e.target.style.display='none';
          } else {
            msg.className='msg msg--err'; msg.textContent=d.error ?? 'Something went wrong.';
            btn.disabled=false; btn.textContent='Create Account';
          }
          msg.style.display='';
        });
      </script>
    `));
  });

  // POST /auth/accept-invite — creates the provider account
  app.post('/accept-invite', async (req, reply) => {
    const parsed = AcceptInviteSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const { token, name, password } = parsed.data;
    const tokenHash = sha256(token);

    const invite = await prisma.providerInvite.findUnique({ where: { tokenHash } });
    if (!invite || invite.acceptedAt || invite.expiresAt < new Date()) {
      return reply.code(400).send({ error: 'Invitation is invalid or has expired' });
    }

    const existing = await prisma.provider.findUnique({ where: { email: invite.email } });
    if (existing) return reply.code(409).send({ error: 'An account with this email already exists' });

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const [provider] = await prisma.$transaction([
      prisma.provider.create({
        data: { orgId: invite.orgId, email: invite.email, passwordHash, name, role: invite.role },
      }),
      prisma.providerInvite.update({
        where: { id: invite.id },
        data:  { acceptedAt: new Date() },
      }),
    ]);

    sendWelcomeEmail(invite.email, name, '').catch(() => {});

    return reply.code(201).send({ providerId: provider.id, orgId: invite.orgId });
  });
};
