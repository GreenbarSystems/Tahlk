// Home screen — encounter list, quick-start, session stats.

import { encountersRepo } from '../data/encountersRepo.js';
import { logRecordsListed } from '../core/auditLog.js';
import { userMessage } from '../platform/appError.js';
import { genId, nowISO, todayISO, displayDateShort, escapeHtml, statusLabel, toast } from '../utils/format.js';
import { pickPatient } from './patientPickerModal.js';

export async function renderHomeScreen() {
  // Counts come from indexed COUNT(*) (accurate at any scale); the list is the
  // most-recent 50 rows. Run both in parallel. Previously "Total" was the
  // length of the capped 50-row fetch — wrong past 50 encounters.
  const [stats, encounters] = await Promise.all([
    encountersRepo.stats(todayISO()).catch(() => ({ total: 0, signed: 0, today: 0 })),
    encountersRepo.list(50).catch(() => []),
  ]);

  // Record that this roster of encounter PHI (patient alias + date per row)
  // was displayed — one access event for the whole list, not one per row.
  // Skipped when empty: nothing was disclosed. See auditLog.js::logRecordsListed
  // and HIPAA risk assessment §4 (record-access accounting).
  if (encounters.length > 0) {
    await logRecordsListed('sessions', encounters.length);
  }

  return `
    <div class="home-screen">
      <div class="home-top">
        <button class="btn btn-primary btn-lg btn-new-session" id="btn-new-session">
          + New Session
        </button>
        <div class="home-stats">
          <div class="stat-item">
            <span class="stat-num">${stats.today}</span>
            <span class="stat-label">Today</span>
          </div>
          <div class="stat-item">
            <span class="stat-num">${stats.signed}</span>
            <span class="stat-label">Signed</span>
          </div>
          <div class="stat-item">
            <span class="stat-num">${stats.total}</span>
            <span class="stat-label">Total</span>
          </div>
        </div>
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
  const dateStr   = escapeHtml(displayDateShort(e.encounter_date));
  const aliasStr  = e.patient_alias ? escapeHtml(e.patient_alias) : '';
  const statusStr = statusLabel(e.status);
  const label     = [statusStr, dateStr, aliasStr].filter(Boolean).join(', ');
  return `
    <div class="encounter-row" data-encounter-id="${escapeHtml(e.id)}"
         tabindex="0" role="button" aria-label="${label}">
      <div class="enc-status">
        <span class="status-chip status-chip--${escapeHtml(e.status)}">${statusStr}</span>
      </div>
      <div class="enc-date">${dateStr}</div>
      <div class="enc-alias">${aliasStr || '<span class="enc-no-alias">—</span>'}</div>
    </div>
  `;
}

export async function wireHomeScreen(onOpenEncounter) {
  document.getElementById('btn-new-session')?.addEventListener('click', async () => {
    const patientAlias = await pickPatient();
    const encounter = {
      id: genId('enc'),
      provider_id: 'solo',
      encounter_date: todayISO(),
      patient_alias: patientAlias,
      status: 'recording',
      audio_path: null,
      created_at: nowISO(),
      signed_at: null,
      signed_hash: null,
    };
    // This await previously had no catch, so a save failure (disk full, DB
    // locked, pool exhausted) surfaced as a New Session button that simply did
    // nothing: the rejection escaped as an unhandled promise and the provider
    // got no toast, no reason, no retry cue.
    //
    // The early return keeps the pre-existing ordering guarantee explicit
    // rather than incidental — the panel must only open for a row the DB
    // actually stored, or every later action on it (transcribe, generate,
    // sign) would fail on a missing row, far from the real cause.
    try {
      await encountersRepo.save(encounter);
    } catch (err) {
      toast(`Could not start a new session: ${userMessage(err, 'unknown error')}`);
      return;
    }
    onOpenEncounter(encounter);
  });

  document.querySelectorAll('.encounter-row').forEach(row => {
    const open = async () => {
      const id = row.dataset.encounterId;
      const encounter = await encountersRepo.get(id).catch(() => null);
      if (encounter) onOpenEncounter(encounter);
    };
    row.addEventListener('click', open);
    row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') open(); });
  });
}
