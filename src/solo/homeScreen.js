// Home screen — encounter list, quick-start, session stats.

import { encountersRepo } from '../data/encountersRepo.js';
import { StatCard, EmptyState, Button } from '../ui/index.js';
import { genId, nowISO, todayISO, displayDateShort, escapeHtml, statusLabel } from '../utils/format.js';

export async function renderHomeScreen() {
  // Counts come from indexed COUNT(*) (accurate at any scale); the list is the
  // most-recent 50 rows. Run both in parallel. Previously "Total" was the
  // length of the capped 50-row fetch — wrong past 50 encounters.
  const [stats, encounters] = await Promise.all([
    encountersRepo.stats(todayISO()).catch(() => ({ total: 0, signed: 0, today: 0 })),
    encountersRepo.list(50).catch(() => []),
  ]);

  return `
    <div class="home-screen">
      <div class="home-top">
        <div class="home-stats">
          ${StatCard({ value: stats.today, label: 'Today' })}
          ${StatCard({ value: stats.signed, label: 'Signed' })}
          ${StatCard({ value: stats.total, label: 'Total' })}
        </div>
        ${Button({ id: 'btn-new-session', variant: 'primary', size: 'lg', label: '+ New Session', className: 'btn-new-session' })}
      </div>

      <div class="encounter-list">
        <h3 class="list-title">Recent Sessions</h3>
        ${encounters.length === 0
          ? EmptyState({
              icon: '🗒️',
              title: 'No sessions yet',
              description: 'Click “+ New Session” above to start your first recording.',
            })
          : encounters.map(e => renderEncounterRow(e)).join('')}
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
    await encountersRepo.save(encounter);
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
