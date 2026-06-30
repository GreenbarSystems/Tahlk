// Practice dashboard — Team tab for Group (Pro/Firm) builds.
// Sections: team stats | invite | pending invites | audit log (admin only).

import { apiFetch } from '../core/api.js';
import { inviteProvider } from '../core/auth.js';
import { toast } from '../utils/format.js';

// ── Render ────────────────────────────────────────────────────────────────────

export async function renderPracticePanel() {
  return `
    <div class="practice-panel">
      <div class="practice-col-main">
        <section class="practice-section" id="team-section">
          <h2 class="practice-heading">Team</h2>
          <div id="team-cards" class="provider-cards">
            <p class="practice-loading">Loading team…</p>
          </div>
        </section>

        <section class="practice-section" id="invite-section">
          <h2 class="practice-heading">Invite a Provider</h2>
          <div class="invite-form" id="invite-form">
            <div class="invite-row">
              <div class="field-row" style="flex:1;margin-bottom:0">
                <label>Email address</label>
                <input type="email" id="invite-email" placeholder="provider@practice.com" />
              </div>
              <div class="field-row" style="margin-bottom:0">
                <label>Role</label>
                <select id="invite-role">
                  <option value="provider">Provider</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <button class="btn btn-primary" id="invite-send-btn" style="align-self:flex-end">Send Invite</button>
            </div>
            <p id="invite-msg" class="invite-msg" style="display:none"></p>
          </div>

          <div id="pending-invites" class="pending-invites">
            <p class="practice-loading">Loading invites…</p>
          </div>
        </section>
      </div>

      <div class="practice-col-audit" id="audit-col">
        <section class="practice-section">
          <div class="practice-heading-row">
            <h2 class="practice-heading">Audit Log</h2>
            <button class="btn btn-ghost btn-sm" id="audit-export-btn">Export CSV</button>
          </div>
          <div class="audit-filters">
            <select id="audit-action-filter">
              <option value="">All actions</option>
              <option value="baa_accepted">BAA accepted</option>
              <option value="pdf_archived">PDF archived</option>
              <option value="pdf_url_requested">PDF accessed</option>
              <option value="provider_invited">Provider invited</option>
              <option value="provider_removed">Provider removed</option>
              <option value="note_signed">Note signed</option>
            </select>
          </div>
          <div id="audit-table-wrap">
            <p class="practice-loading">Loading audit log…</p>
          </div>
          <div class="audit-pagination" id="audit-pagination" style="display:none"></div>
        </section>
      </div>
    </div>
  `;
}

// ── Wire ──────────────────────────────────────────────────────────────────────

export async function wirePracticePanel() {
  // Load all data in parallel — non-blocking independent requests
  _loadTeamStats();
  _loadPendingInvites();
  _loadAuditLog(1);

  // Invite form
  document.getElementById('invite-send-btn')?.addEventListener('click', async () => {
    const email = document.getElementById('invite-email')?.value.trim();
    const role  = document.getElementById('invite-role')?.value || 'provider';
    const msg   = document.getElementById('invite-msg');
    if (!email) { _showInviteMsg('Email is required.', false); return; }

    const btn = document.getElementById('invite-send-btn');
    btn.disabled = true; btn.textContent = 'Sending…';

    try {
      await inviteProvider(email, role);
      _showInviteMsg(`Invite sent to ${email}.`, true);
      document.getElementById('invite-email').value = '';
      _loadPendingInvites(); // refresh pending list
    } catch (e) {
      _showInviteMsg(e.message || 'Invite failed.', false);
    } finally {
      btn.disabled = false; btn.textContent = 'Send Invite';
    }
  });

  // Audit action filter
  document.getElementById('audit-action-filter')?.addEventListener('change', () => {
    _loadAuditLog(1);
  });

  // CSV export
  document.getElementById('audit-export-btn')?.addEventListener('click', _exportAuditCsv);
}

// ── Team stats ────────────────────────────────────────────────────────────────

async function _loadTeamStats() {
  const wrap = document.getElementById('team-cards');
  if (!wrap) return;
  try {
    const res = await apiFetch('/api/org/stats');
    if (!res.ok) throw new Error(`${res.status}`);
    const { providers, since } = await res.json();
    const sinceLabel = new Date(since).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

    wrap.innerHTML = providers.length === 0
      ? '<p class="practice-empty">No providers in this org yet.</p>'
      : providers.map(p => `
          <div class="provider-card">
            <div class="provider-card-avatar">${_initials(p.name)}</div>
            <div class="provider-card-info">
              <div class="provider-card-name">${esc(p.name || p.email)}</div>
              ${p.credentials ? `<div class="provider-card-creds">${esc(p.credentials)}</div>` : ''}
              <div class="provider-card-spec">${esc(_specialtyLabel(p.specialty))}</div>
              <div class="provider-card-role role-badge role-badge--${p.role}">${p.role}</div>
            </div>
            <div class="provider-card-stat">
              <span class="stat-number">${p.encounterCount30d}</span>
              <span class="stat-label">sessions<br>since ${sinceLabel}</span>
            </div>
          </div>
        `).join('');
  } catch (e) {
    wrap.innerHTML = `<p class="practice-error">Could not load team — ${e.message}</p>`;
  }
}

// ── Pending invites ───────────────────────────────────────────────────────────

async function _loadPendingInvites() {
  const wrap = document.getElementById('pending-invites');
  if (!wrap) return;
  try {
    const res = await apiFetch('/api/org/invites');
    if (!res.ok) {
      // Non-admins get 403 — just hide the section quietly
      wrap.innerHTML = '';
      return;
    }
    const { invites } = await res.json();
    if (!invites.length) { wrap.innerHTML = ''; return; }

    wrap.innerHTML = `
      <h3 class="practice-subheading">Pending Invitations</h3>
      <div class="pending-list">
        ${invites.map(inv => `
          <div class="pending-item" data-invite-id="${inv.id}">
            <span class="pending-email">${esc(inv.email)}</span>
            <span class="pending-role role-badge role-badge--${inv.role}">${inv.role}</span>
            <span class="pending-exp">Expires ${_relDate(inv.expiresAt)}</span>
            <button class="btn btn-ghost btn-sm pending-cancel" data-id="${inv.id}">Cancel</button>
          </div>
        `).join('')}
      </div>`;

    wrap.querySelectorAll('.pending-cancel').forEach(btn => {
      btn.addEventListener('click', async () => {
        btn.disabled = true; btn.textContent = '…';
        try {
          const r = await apiFetch(`/api/org/invites/${btn.dataset.id}`, { method: 'DELETE' });
          if (r.ok) btn.closest('.pending-item').remove();
          else toast('Could not cancel invite.');
        } catch { toast('Could not cancel invite.'); }
      });
    });
  } catch {
    wrap.innerHTML = '';
  }
}

// ── Audit log ─────────────────────────────────────────────────────────────────

let _auditPage  = 1;
let _auditPages = 1;
let _auditCache = []; // holds current page for CSV export

async function _loadAuditLog(page) {
  const wrap   = document.getElementById('audit-table-wrap');
  const pgWrap = document.getElementById('audit-pagination');
  if (!wrap) return;

  const action = document.getElementById('audit-action-filter')?.value || '';
  const params = new URLSearchParams({ page: String(page), limit: '50' });
  if (action) params.set('action', action);

  try {
    const res = await apiFetch(`/api/org/audit?${params}`);
    if (!res.ok) {
      wrap.innerHTML = res.status === 403
        ? '<p class="practice-empty">Audit log requires admin role.</p>'
        : `<p class="practice-error">Error ${res.status}</p>`;
      return;
    }
    const { entries, total, pages } = await res.json();
    _auditPage  = page;
    _auditPages = pages;
    _auditCache = entries;

    if (!entries.length) {
      wrap.innerHTML = '<p class="practice-empty">No entries for these filters.</p>';
      if (pgWrap) pgWrap.style.display = 'none';
      return;
    }

    wrap.innerHTML = `
      <table class="audit-table">
        <thead>
          <tr>
            <th>Date / Time</th>
            <th>Action</th>
            <th>Provider</th>
            <th>Encounter</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          ${entries.map(e => `
            <tr>
              <td class="audit-ts">${_fmtDate(e.createdAt)}</td>
              <td><span class="audit-badge audit-badge--${_actionClass(e.action)}">${esc(e.action)}</span></td>
              <td class="audit-provider">${esc(e.providerId ? e.providerId.slice(0, 8) + '…' : '—')}</td>
              <td class="audit-enc">${esc(e.encounterId ? e.encounterId.slice(0, 8) + '…' : '—')}</td>
              <td class="audit-ip">${esc(e.ipAddress || '—')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
      <p class="audit-total">${total} total entries</p>`;

    if (pgWrap) {
      if (pages > 1) {
        pgWrap.style.display = 'flex';
        pgWrap.innerHTML = `
          <button class="btn btn-ghost btn-sm" id="audit-prev" ${page <= 1 ? 'disabled' : ''}>← Prev</button>
          <span class="audit-page-label">Page ${page} of ${pages}</span>
          <button class="btn btn-ghost btn-sm" id="audit-next" ${page >= pages ? 'disabled' : ''}>Next →</button>`;
        document.getElementById('audit-prev')?.addEventListener('click', () => _loadAuditLog(page - 1));
        document.getElementById('audit-next')?.addEventListener('click', () => _loadAuditLog(page + 1));
      } else {
        pgWrap.style.display = 'none';
      }
    }
  } catch (e) {
    wrap.innerHTML = `<p class="practice-error">Could not load audit log — ${e.message}</p>`;
  }
}

function _exportAuditCsv() {
  if (!_auditCache.length) { toast('No audit entries to export.'); return; }
  const rows = [
    ['Date', 'Action', 'Provider ID', 'Encounter ID', 'IP Address'],
    ..._auditCache.map(e => [
      _fmtDate(e.createdAt), e.action, e.providerId || '', e.encounterId || '', e.ipAddress || '',
    ]),
  ];
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `tahlk-audit-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _initials(name) {
  if (!name) return '?';
  const parts = String(name).trim().split(/\s+/);
  return parts.length === 1
    ? parts[0][0].toUpperCase()
    : (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function _specialtyLabel(s) {
  return {
    psychiatry: 'Psychiatry', 'behavioral-health': 'Behavioral Health',
    psychology: 'Psychology', podiatry: 'Podiatry', other: 'Other',
  }[s] || s || '';
}

function _fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function _relDate(iso) {
  if (!iso) return '—';
  const diff = new Date(iso) - Date.now();
  const days = Math.ceil(diff / 86_400_000);
  return days <= 0 ? 'soon' : `in ${days}d`;
}

function _actionClass(action) {
  if (!action) return 'default';
  if (action.includes('pdf'))      return 'pdf';
  if (action.includes('baa'))      return 'baa';
  if (action.includes('provider')) return 'team';
  if (action.includes('signed'))   return 'sign';
  return 'default';
}

function _showInviteMsg(msg, ok) {
  const el = document.getElementById('invite-msg');
  if (!el) return;
  el.textContent = msg;
  el.className = ok ? 'invite-msg invite-msg--ok' : 'invite-msg invite-msg--err';
  el.style.display = 'block';
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
