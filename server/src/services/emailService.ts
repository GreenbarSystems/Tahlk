// Transactional email via Resend (https://resend.com).
// Lazily initialised so the server starts without RESEND_API_KEY;
// calls log a warning and return without throwing so the request still succeeds
// (password reset / invite still complete server-side; email delivery is best-effort).

import { Resend } from 'resend';

const FROM = process.env.EMAIL_FROM ?? 'Tahlk <no-reply@tahlkscribe.com>';

let _resend: Resend | null = null;

function client(): Resend | null {
  if (!_resend) {
    if (!process.env.RESEND_API_KEY) return null;
    _resend = new Resend(process.env.RESEND_API_KEY);
  }
  return _resend;
}

async function send(to: string, subject: string, html: string): Promise<void> {
  const r = client();
  if (!r) {
    console.warn('[email] RESEND_API_KEY not set — skipping email to', to);
    return;
  }
  const { error } = await r.emails.send({ from: FROM, to, subject, html });
  if (error) console.error('[email] send failed', error);
}

// ── Templates ─────────────────────────────────────────────────────────────────

export async function sendWelcomeEmail(to: string, name: string, orgName: string): Promise<void> {
  await send(
    to,
    'Welcome to Tahlk',
    _wrap(`
      <h1>Welcome to Tahlk, ${esc(name)}!</h1>
      <p>Your account for <strong>${esc(orgName)}</strong> is ready.</p>
      <p>Open the Tahlk desktop app and log in with this email address to get started.</p>
      <p style="color:#6b7280;font-size:13px">
        Tahlk is end-to-end encrypted — your clinical notes are encrypted on your device
        before they leave it. We never have access to your patient content.
      </p>
    `),
  );
}

export async function sendPasswordResetEmail(to: string, resetUrl: string): Promise<void> {
  await send(
    to,
    'Reset your Tahlk password',
    _wrap(`
      <h1>Reset your password</h1>
      <p>We received a request to reset the password for this Tahlk account.</p>
      <p style="margin:24px 0">
        <a href="${esc(resetUrl)}" style="${CTA_STYLE}">Reset Password →</a>
      </p>
      <p style="color:#6b7280;font-size:13px">
        This link expires in 1 hour. If you didn't request a reset, you can ignore this email —
        your password hasn't changed.
      </p>
      <p style="color:#9ca3af;font-size:12px;word-break:break-all">
        Or paste this URL: ${esc(resetUrl)}
      </p>
    `),
  );
}

export async function sendProviderInviteEmail(
  to: string,
  orgName: string,
  inviterName: string,
  inviteUrl: string,
): Promise<void> {
  await send(
    to,
    `You've been invited to join ${orgName} on Tahlk`,
    _wrap(`
      <h1>You're invited!</h1>
      <p>${esc(inviterName)} has invited you to join <strong>${esc(orgName)}</strong> on Tahlk,
         an AI ambient scribe designed for healthcare providers.</p>
      <p style="margin:24px 0">
        <a href="${esc(inviteUrl)}" style="${CTA_STYLE}">Accept Invitation →</a>
      </p>
      <p style="color:#6b7280;font-size:13px">
        This invitation expires in 7 days. After accepting, download the Tahlk desktop app
        and log in with this email address.
      </p>
      <p style="color:#9ca3af;font-size:12px;word-break:break-all">
        Or paste this URL: ${esc(inviteUrl)}
      </p>
    `),
  );
}

// ── Shared layout ─────────────────────────────────────────────────────────────

const CTA_STYLE =
  'display:inline-block;background:#11284d;color:#ffffff;padding:12px 24px;' +
  'border-radius:8px;text-decoration:none;font-weight:600;font-size:15px';

function _wrap(body: string): string {
  return `<!doctype html>
<html><head><meta charset="utf-8">
<style>
  body{font-family:system-ui,-apple-system,sans-serif;background:#f8fafc;margin:0;padding:32px 16px}
  .card{background:#ffffff;border-radius:12px;padding:32px 36px;max-width:540px;margin:0 auto;
        box-shadow:0 1px 4px #0001}
  h1{color:#11284d;font-size:22px;margin-top:0}
  p{color:#374151;line-height:1.6;font-size:15px}
  .footer{text-align:center;color:#9ca3af;font-size:12px;margin-top:24px}
</style></head>
<body>
  <div class="card">${body}</div>
  <div class="footer">
    <p>Tahlk Health, Inc. — HIPAA-compliant ambient AI scribe<br>
    <a href="https://www.tahlkscribe.com/privacy" style="color:#6b7280">Privacy</a> ·
    <a href="https://www.tahlkscribe.com/baa" style="color:#6b7280">BAA</a></p>
  </div>
</body></html>`;
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
