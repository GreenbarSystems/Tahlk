// Home screen — encounter list, quick-start, session stats.

import { tauriInvoke } from '../core/storageBackend.js';
import { genId, nowISO, todayISO, displayDateShort, escapeHtml, statusLabel } from '../utils/format.js';

export async function renderHomeScreen() {
  const encounters = await tauriInvoke('list_encounters', { limit: 50 }).catch(() => []);
  const todayCount = encounters.filter(e => e.encounter_date === todayISO()).length;
  const signedCount = encounters.filter(e => e.status === 'signed').length;

  return `
    <div class="home-screen">
      <div class="home-top">
        <div class="home-stats">
          <div class="stat-card">
            <div class="stat-num">${todayCount}</div>
            <div class="stat-label">Today</div>
          </div>
          <div class="stat-card">
            <div class="stat-num">${signedCount}</div>
            <div class="stat-label">Signed</div>
          </div>
          <div class="stat-card">
            <div class="stat-num">${encounters.length}</div>
            <div class="stat-label">Total</div>
          </div>
        </div>
        <button class="btn btn-primary btn-lg btn-new-session" id="btn-new-session">
          + New Session
        </button>
      </div>

      <div class="encounter-list">
        <h3 class="list-title">Recent Sessions</h3>
        ${encounters.length === 0 ? `
          <div class="empty-state">
            <p>No sessions yet.</p>
            <p>Click <strong>New Session</strong> to start your first recording.</p>
          </div>
        ` : encounters.map(e => renderEncounterRow(e)).join('')}
      </div>
    </div>
  `;
}

function renderEncounterRow(e) {
  return `
    <div class="encounter-row" data-encounter-id="${escapeHtml(e.id)}" tabindex="0" role="button">
      <div class="enc-date">${escapeHtml(displayDateShort(e.encounter_date))}</div>
      <div class="enc-alias">${e.patient_alias ? escapeHtml(e.patient_alias) : '—'}</div>
      <div class="enc-status">
        <span class="status-chip status-chip--${escapeHtml(e.status)}">${statusLabel(e.status)}</span>
      </div>
    </div>
  `;
}

export async function wireHomeScreen(onOpenEncounter) {
  document.getElementById('btn-new-session')?.addEventListener('click', async () => {
    const encounter = {
      id: genId('enc'),
      provider_id: 'solo',
      encounter_date: todayISO(),
      patient_alias: null,
      status: 'recording',
      audio_path: null,
      created_at: nowISO(),
      signed_at: null,
      signed_hash: null,
    };
    await tauriInvoke('upsert_encounter', { encounter });
    onOpenEncounter(encounter);
  });

  document.querySelectorAll('.encounter-row').forEach(row => {
    const open = async () => {
      const id = row.dataset.encounterId;
      const encounter = await tauriInvoke('get_encounter', { id }).catch(() => null);
      if (encounter) onOpenEncounter(encounter);
    };
    row.addEventListener('click', open);
    row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') open(); });
  });
}
