// Home screen — outcome stats plus a patient/session split view.
// Left: "Today" (recent sessions) and explicit patient records (+ Add Patient).
// Right: the selected patient's profile + sessions, recent sessions ("Today"),
// or the Add Patient form.

import { tauriInvoke } from '../core/storageBackend.js';
import { genId, nowISO, todayISO, displayDateShort } from '../utils/format.js';
import { providerId } from '../core/capabilities.js';
import { listPatients, getPatient, savePatient } from './patients.js';
import { loadCodingFlags } from '../scribe/codingFlags.js';

let _encounters = [];
let _selected    = { type: 'today' };
let _searchQuery = '';

export async function renderHomeScreen() {
  _encounters  = await tauriInvoke('list_encounters', { limit: 200 }).catch(() => []);
  syncPatientsFromAliases();            // adopt any aliased sessions as patient records
  _selected    = { type: 'today' };
  _searchQuery = '';

  return `
    <div class="home-screen">
      <div class="home-stats">
        ${statCard(newCount(), 'New')}
        ${statCard(awaitingCount(), 'Awaiting review')}
        ${statCard(completedCount(), 'Completed')}
      </div>

      ${renderFlagInbox()}

      <div class="split">
        <aside class="split-nav"><div class="nav-list">${renderNav()}</div></aside>
        <section class="split-main" id="split-main">${renderRightPane()}</section>
      </div>
    </div>
  `;
}

function statCard(num, label, title) {
  return `<div class="stat-card"${title ? ` title="${esc(title)}"` : ''}>
    <div class="stat-num">${num}</div><div class="stat-label">${label}</div></div>`;
}

// ── Left nav ───────────────────────────────────────────────────────────────

function renderNav() {
  const pts = listPatients();
  return `
    <div class="nav-item ${_selected.type === 'today' ? 'nav-item--active' : ''}" data-today="1" role="button" tabindex="0">
      <span class="nav-label">Recent</span>
      <span class="nav-count">${_encounters.length}</span>
    </div>
    <div class="nav-section-row">
      <span class="nav-section">Patients</span>
      <button class="nav-add" id="btn-add-patient">+ Add</button>
    </div>
    ${pts.length ? pts.map(p => {
      const active = _selected.type === 'patient' && _selected.id === p.id ? 'nav-item--active' : '';
      return `<div class="nav-item ${active}" data-patient-id="${esc(p.id)}" role="button" tabindex="0">
        <span class="nav-label">${esc(p.name)}</span>
        <span class="nav-count">${sessionsFor(p).length}</span>
      </div>`;
    }).join('') : `<div class="nav-empty">No patients yet. Click <strong>+ Add</strong> to create one.</div>`}
  `;
}

// ── Right pane ───────────────────────────────────────────────────────────────

function renderRightPane() {
  if (_selected.type === 'add-patient') return renderAddPatient();

  const patient    = _selected.type === 'patient' ? getPatient(_selected.id) : null;
  const allList    = patient ? sessionsFor(patient) : recentSessions();
  const showSearch = !patient;
  const list       = showSearch ? filterBySearch(allList) : allList;
  const title      = patient ? patient.name : 'Recent sessions';
  const subParts   = patient
    ? [patient.mrn && `MRN ${patient.mrn}`, patient.dob && `DOB ${patient.dob}`].filter(Boolean) : [];

  return `
    <div class="pane-head">
      <div class="pane-titles">
        <h3 class="pane-title">${esc(title)}</h3>
        ${subParts.length ? `<div class="pane-sub">${esc(subParts.join('  ·  '))}</div>` : ''}
      </div>
      <button class="btn btn-primary btn-sm" id="btn-new-session">+ New Session</button>
    </div>

    ${showSearch ? `
      <div class="search-bar-row">
        <div class="search-bar">
          <span class="search-icon">⌕</span>
          <input type="text" id="session-search" class="search-input"
                 placeholder="Search patient, date, or status…"
                 value="${esc(_searchQuery)}" autocomplete="off" spellcheck="false" />
          ${_searchQuery ? `<button class="search-clear" id="search-clear" title="Clear search">✕</button>` : ''}
        </div>
        ${_searchQuery ? `<span class="search-count">${list.length} result${list.length !== 1 ? 's' : ''}</span>` : ''}
      </div>` : ''}

    ${list.length ? `<div class="encounter-list">${list.map(e => renderEncounterRow(e, !!patient)).join('')}</div>` : `
      <div class="empty-state">
        ${_searchQuery
          ? `<p>No sessions match <strong>"${esc(_searchQuery)}"</strong>.</p>
             <p><button class="btn btn-ghost btn-sm" id="search-clear-inline">Clear search</button></p>`
          : `<p>No sessions${patient ? ' for this patient yet' : ' yet'}.</p>
             <p>Click <strong>+ New Session</strong> to start a recording.</p>`
        }
      </div>`}
  `;
}

function renderAddPatient() {
  return `
    <div class="pane-head"><div class="pane-titles"><h3 class="pane-title">Add patient</h3></div></div>
    <div class="patient-form">
      <div class="field-row">
        <label>Name or initials <span class="req">*</span></label>
        <input id="pt-name" type="text" placeholder="e.g. J.S. or P-001" maxlength="60" />
      </div>
      <div class="field-row">
        <label>MRN (optional)</label>
        <input id="pt-mrn" type="text" placeholder="Medical record number" maxlength="40" />
      </div>
      <div class="field-row">
        <label>Date of birth (optional)</label>
        <input id="pt-dob" type="date" />
      </div>
      <div class="field-row">
        <label>Notes (optional)</label>
        <input id="pt-notes" type="text" placeholder="Anything to remember" maxlength="120" />
      </div>
      <div class="form-actions">
        <button class="btn btn-primary btn-sm" id="pt-save">Save patient</button>
        <button class="btn btn-ghost btn-sm" id="pt-cancel">Cancel</button>
      </div>
    </div>
  `;
}

function renderEncounterRow(e, hideAlias) {
  const chip = `<span class="status-chip status-chip--${e.status}">${statusLabel(e.status)}</span>`;
  if (hideAlias) {
    // Patient view — the patient is already the pane title, so drop the name column.
    return `
      <div class="encounter-row encounter-row--compact" data-encounter-id="${e.id}" tabindex="0" role="button">
        <div class="enc-date">${displayDateShort(e.encounter_date)}</div>
        <div class="enc-status">${chip}</div>
      </div>
    `;
  }
  return `
    <div class="encounter-row" data-encounter-id="${e.id}" tabindex="0" role="button">
      <div class="enc-date">${displayDateShort(e.encounter_date)}</div>
      <div class="enc-alias">${esc(e.patient_alias || '—')}</div>
      <div class="enc-status">${chip}</div>
    </div>
  `;
}

// ── Data helpers ─────────────────────────────────────────────────────────────

function sessionsFor(patient) {
  const name = String(patient.name || '').trim();
  return _encounters.filter(e => String(e.patient_alias || '').trim() === name);
}

function recentSessions() {
  return [..._encounters].sort((a, b) =>
    String(b.encounter_date || '').localeCompare(String(a.encounter_date || '')) ||
    String(b.created_at || '').localeCompare(String(a.created_at || '')));
}

function filterBySearch(list) {
  const q = _searchQuery.trim().toLowerCase();
  if (!q) return list;
  return list.filter(e =>
    (e.patient_alias  || '').toLowerCase().includes(q) ||
    (e.encounter_date || '').includes(q) ||
    displayDateShort(e.encounter_date || '').toLowerCase().includes(q) ||
    (e.status         || '').toLowerCase().includes(q)
  );
}

function newCount() {
  return _encounters.filter(e => e.status === 'new' || e.status === 'recording' || e.status === 'recording_done').length;
}

function awaitingCount() {
  return _encounters.filter(e => e.status === 'draft').length;
}

function completedCount() {
  return _encounters.filter(e => e.status === 'signed' || e.status === 'exported').length;
}

function flaggedEncounters() {
  return _encounters
    .filter(e => e.status === 'draft')
    .map(e => ({ encounter: e, gaps: (loadCodingFlags(e.id)?.documentation_gaps || []) }))
    .filter(({ gaps }) => gaps.length > 0);
}

function renderFlagInbox() {
  const items = flaggedEncounters();
  if (!items.length) return '';
  return `
    <div class="flag-inbox">
      <div class="flag-inbox-header">
        <span class="flag-inbox-title">Documentation Gaps</span>
        <span class="flag-inbox-count">${items.length}</span>
      </div>
      <div class="flag-inbox-list">
        ${items.map(({ encounter: e, gaps }) => `
          <div class="flag-inbox-row" data-encounter-id="${esc(e.id)}" role="button" tabindex="0">
            <div class="fir-left">
              <span class="fir-alias">${esc(e.patient_alias || 'Unknown patient')}</span>
              <span class="fir-date">${displayDateShort(e.encounter_date)}</span>
            </div>
            <div class="fir-gaps">
              ${gaps.slice(0, 2).map(g => `
                <span class="fir-gap fir-gap--${g.severity || 'warning'}">${g.severity === 'error' ? '✕' : '⚠'} ${esc(g.issue)}</span>`).join('')}
              ${gaps.length > 2 ? `<span class="fir-more">+${gaps.length - 2} more</span>` : ''}
            </div>
            <span class="fir-action">Review →</span>
          </div>`).join('')}
      </div>
    </div>`;
}

// Adopt any session whose patient_alias has no matching patient record as a new
// patient record (one-time, idempotent) so existing data shows up in the list.
function syncPatientsFromAliases() {
  const names = new Set(listPatients().map(p => String(p.name || '').trim()));
  const seen = new Set();
  for (const e of _encounters) {
    const a = String(e.patient_alias || '').trim();
    if (a && !names.has(a) && !seen.has(a)) { savePatient({ name: a }); seen.add(a); }
  }
}

// ── Wiring ───────────────────────────────────────────────────────────────────

export async function wireHomeScreen(onOpenEncounter) {
  wireNav(onOpenEncounter);
  wireRight(onOpenEncounter);
  wireFlagInbox(onOpenEncounter);
}

function wireFlagInbox(onOpenEncounter) {
  document.querySelectorAll('.flag-inbox-row').forEach(row => {
    const open = () => {
      const enc = _encounters.find(e => e.id === row.dataset.encounterId);
      if (enc) onOpenEncounter(enc);
    };
    row.addEventListener('click', open);
    row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') open(); });
  });
}

function rerender(onOpenEncounter) {
  const nav = document.querySelector('.split-nav .nav-list');
  const main = document.getElementById('split-main');
  if (nav) nav.innerHTML = renderNav();
  if (main) main.innerHTML = renderRightPane();
  wireNav(onOpenEncounter);
  wireRight(onOpenEncounter);
}

function wireNav(onOpenEncounter) {
  document.getElementById('btn-add-patient')?.addEventListener('click', () => {
    _selected = { type: 'add-patient' };
    rerender(onOpenEncounter);
  });
  document.querySelectorAll('.split-nav .nav-item').forEach(el => {
    const select = () => {
      _selected = el.dataset.patientId
        ? { type: 'patient', id: el.dataset.patientId }
        : { type: 'today' };
      rerender(onOpenEncounter);
    };
    el.addEventListener('click', select);
    el.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(); }
    });
  });
}

function wireRight(onOpenEncounter) {
  // New Session — assigned to the selected patient (if any).
  document.getElementById('btn-new-session')?.addEventListener('click', async () => {
    const patient = _selected.type === 'patient' ? getPatient(_selected.id) : null;
    const encounter = {
      id: genId('enc'),
      provider_id: providerId(),
      encounter_date: todayISO(),
      patient_alias: patient ? patient.name : null,
      status: 'new',
      audio_path: null,
      created_at: nowISO(),
      signed_at: null,
      signed_hash: null,
    };
    await tauriInvoke('upsert_encounter', { encounter });
    onOpenEncounter(encounter);
  });

  // Add-patient form.
  document.getElementById('pt-save')?.addEventListener('click', () => {
    const name = document.getElementById('pt-name')?.value.trim();
    if (!name) { document.getElementById('pt-name')?.focus(); return; }
    const p = savePatient({
      name,
      mrn: document.getElementById('pt-mrn')?.value.trim() || '',
      dob: document.getElementById('pt-dob')?.value || '',
      notes: document.getElementById('pt-notes')?.value.trim() || '',
    });
    _selected = { type: 'patient', id: p.id };
    rerender(onOpenEncounter);
  });
  document.getElementById('pt-cancel')?.addEventListener('click', () => {
    _selected = { type: 'today' };
    rerender(onOpenEncounter);
  });

  // Search
  document.getElementById('session-search')?.addEventListener('input', e => {
    _searchQuery = e.target.value;
    rerender(onOpenEncounter);
    // Restore focus + caret position after rerender
    const input = document.getElementById('session-search');
    if (input) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
  });

  const clearSearch = () => {
    _searchQuery = '';
    rerender(onOpenEncounter);
    document.getElementById('session-search')?.focus();
  };
  document.getElementById('search-clear')?.addEventListener('click', clearSearch);
  document.getElementById('search-clear-inline')?.addEventListener('click', clearSearch);

  // Session rows.
  document.querySelectorAll('#split-main .encounter-row').forEach(row => {
    const open = () => {
      const enc = _encounters.find(e => e.id === row.dataset.encounterId);
      if (enc) onOpenEncounter(enc);
    };
    row.addEventListener('click', open);
    row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') open(); });
  });
}

function statusLabel(status) {
  return { new: 'New', recording: 'Recording', recording_done: 'Recorded', draft: 'Draft',
           signed: 'Signed', exported: 'Exported' }[status] || status;
}

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/"/g, '&quot;')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
