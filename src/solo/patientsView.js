// Patients view — a lightweight standalone roster (alias, optional DOB, notes).
// Not linked to encounters in this iteration. Follows the render/wire pattern
// used by homeScreen.js: an async render that reads from patientsRepo, and a
// wire step that attaches handlers and re-renders on mutation.

import { patientsRepo } from '../data/patientsRepo.js';
import { genId, nowISO, displayDateShort, escapeHtml, toast } from '../utils/format.js';
import { confirmModal } from './confirmModal.js';
import { iconSearch } from './icons.js';
import { openImportModal } from './patientsImport.js';

export async function renderPatientsView() {
  const patients = await patientsRepo.list().catch(() => []);
  const count = patients.length;

  return `
    <div class="patients-page">
      <div class="patients-header">
        <div class="patients-header-left">
          <h2 class="settings-title">Patients</h2>
          ${count > 0 ? `<span class="patients-count">${Number(count)} on file</span>` : ''}
        </div>
        <button type="button" class="btn btn-primary" id="patient-add-toggle"
                aria-expanded="false" aria-controls="patient-form">+ Add patient</button>
        <button type="button" class="btn btn-secondary btn-sm" id="patient-import-btn"
                title="Import patients from an EHR CSV export">Import from EHR…</button>
      </div>

      <form class="patient-form" id="patient-form" autocomplete="off" hidden>
        <div class="patient-form-head">
          <span class="patient-form-title">Add patient</span>
          <span class="patient-form-editing-hint" id="patient-editing-hint"></span>
        </div>
        <input type="hidden" id="patient-id" value="">
        <div class="patient-form-row">
          <label class="patient-field">
            <span class="patient-field-label">Name / alias <span class="req">*</span></span>
            <input type="text" id="patient-alias" maxlength="200" required
                   placeholder="e.g. J.D. or initials">
          </label>
          <label class="patient-field">
            <span class="patient-field-label">Date of birth</span>
            <input type="date" id="patient-dob">
          </label>
        </div>
        <label class="patient-field">
          <span class="patient-field-label">Notes</span>
          <textarea id="patient-notes" rows="2" maxlength="2000"
                    placeholder="Optional notes"></textarea>
        </label>
        <div class="patient-form-actions">
          <button type="submit" class="btn btn-primary" id="patient-save">Add patient</button>
          <button type="button" class="btn btn-ghost" id="patient-cancel">Cancel</button>
        </div>
      </form>

      ${count > 0 ? `
        <div class="patient-search-wrap">
          <span class="patient-search-icon">${iconSearch()}</span>
          <input type="text" id="patient-search" class="patient-search" autocomplete="off"
                 placeholder="Search this roster…" aria-label="Search patients">
        </div>
      ` : ''}

      ${count === 0 ? `
        <div class="empty-state">
          <p>No patients yet.</p>
          <p>Use <strong>+ Add patient</strong> above to add your first one.</p>
        </div>
      ` : `
        <ul class="patient-list" id="patient-list">
          ${patients.map(p => renderPatientRow(p)).join('')}
        </ul>
        <p class="patient-no-results" id="patient-no-results" hidden>No patients match your search.</p>
      `}
    </div>
  `;
}

function renderPatientRow(p) {
  const alias = escapeHtml(p.alias);
  const id    = escapeHtml(p.id);
  const dob   = p.dob ? escapeHtml(displayDateShort(p.dob)) : '';
  const notes = p.notes ? escapeHtml(p.notes) : '';
  return `
    <li class="patient-row" data-patient-id="${id}">
      <div class="patient-main">
        <div class="patient-alias">${alias}</div>
        ${dob ? `<div class="patient-dob">DOB ${dob}</div>` : ''}
        ${notes ? `<div class="patient-notes">${notes}</div>` : ''}
      </div>
      <div class="patient-actions">
        <button class="btn btn-ghost btn-sm patient-edit" data-patient-id="${id}"
                aria-label="Edit ${alias}">Edit</button>
        <button class="btn btn-ghost btn-sm btn-danger patient-delete" data-patient-id="${id}"
                aria-label="Delete ${alias}">Delete</button>
      </div>
    </li>
  `;
}

// `rerender` re-runs the view (render + wire) after any mutation so the list
// reflects the new state — mirrors how homeScreen re-renders on navigation.
export function wirePatientsView(rerender) {
  const form      = document.getElementById('patient-form');
  const addToggle = document.getElementById('patient-add-toggle');
  const idEl      = document.getElementById('patient-id');
  const aliasEl   = document.getElementById('patient-alias');
  const dobEl     = document.getElementById('patient-dob');
  const notesEl   = document.getElementById('patient-notes');
  const saveBtn   = document.getElementById('patient-save');
  const cancelBtn = document.getElementById('patient-cancel');
  const hintEl    = document.getElementById('patient-editing-hint');

  // Reset the form's fields and add/edit visuals back to a clean "add" state
  // WITHOUT changing whether it's shown — openAdd/openEdit/closeForm own
  // visibility.
  const resetFormFields = () => {
    idEl.value = '';
    aliasEl.value = '';
    dobEl.value = '';
    notesEl.value = '';
    saveBtn.textContent = 'Add patient';
    form?.classList.remove('patient-form--editing');
    if (hintEl) hintEl.textContent = '';
  };

  // The form is collapsed by default and revealed by either the "+ Add
  // patient" toggle (add) or a row's Edit button (edit). The toggle hides
  // while the form is open — Cancel is the way back — and aria-expanded plus
  // focus management follow the standard disclosure pattern.
  const revealForm = () => {
    form.hidden = false;
    if (addToggle) { addToggle.hidden = true; addToggle.setAttribute('aria-expanded', 'true'); }
    form.scrollIntoView({ behavior: 'smooth', block: 'start' });
    aliasEl.focus();
  };

  const openAdd = () => {
    resetFormFields();
    revealForm();
  };

  // textContent (never innerHTML) so the alias can't inject markup — no escape
  // needed and nothing for the interpolation build-guard to flag.
  const openEdit = (p) => {
    idEl.value = p.id;
    aliasEl.value = p.alias || '';
    dobEl.value = p.dob || '';
    notesEl.value = p.notes || '';
    saveBtn.textContent = 'Save changes';
    form.classList.add('patient-form--editing');
    if (hintEl) hintEl.textContent = p.alias ? `Editing ${p.alias}` : 'Editing patient';
    revealForm();
  };

  const closeForm = () => {
    form.hidden = true;
    resetFormFields();
    if (addToggle) {
      addToggle.hidden = false;
      addToggle.setAttribute('aria-expanded', 'false');
      addToggle.focus(); // return focus to the trigger, never orphan it on a hidden node
    }
  };

  addToggle?.addEventListener('click', openAdd);
  cancelBtn?.addEventListener('click', closeForm);
  document.getElementById('patient-import-btn')?.addEventListener('click',
    () => openImportModal(rerender));

  form?.addEventListener('submit', async e => {
    e.preventDefault();
    const alias = aliasEl.value.trim();
    if (!alias) { toast('Name / alias is required.'); aliasEl.focus(); return; }

    const editingId = idEl.value || null;
    const existing = editingId ? await patientsRepo.get(editingId).catch(() => null) : null;
    const now = nowISO();
    const patient = {
      id: editingId || genId('pt'),
      alias,
      dob: dobEl.value || null,
      notes: notesEl.value.trim() || null,
      created_at: existing?.created_at ?? now,
      updated_at: now,
    };
    try {
      await patientsRepo.save(patient);
      toast(editingId ? 'Patient updated.' : 'Patient added.');
      // A successful save re-renders the whole view, which rebuilds the form
      // collapsed — no explicit closeForm needed.
      rerender();
    } catch {
      toast('Could not save patient.');
    }
  });

  // Client-side roster filter. Matches against the visible text of each row
  // (alias + DOB + notes) with no re-fetch, so typing is instant even on a
  // full roster. Mutations re-render the view and reset the query, which is
  // predictable — a fresh list after add/edit/delete.
  const searchEl = document.getElementById('patient-search');
  const noResultsEl = document.getElementById('patient-no-results');
  searchEl?.addEventListener('input', () => {
    const q = searchEl.value.trim().toLowerCase();
    const rows = document.querySelectorAll('.patient-row');
    let shown = 0;
    rows.forEach(row => {
      const hay = (row.querySelector('.patient-main')?.textContent || '').toLowerCase();
      const match = q === '' || hay.includes(q);
      row.hidden = !match;
      if (match) shown++;
    });
    if (noResultsEl) noResultsEl.hidden = shown !== 0;
  });

  // Monotonic request token: the Edit form is a shared singleton, so two
  // overlapping clicks (fast double-click across different rows) both fire
  // a fetch, and whichever resolves last would otherwise win regardless of
  // which was clicked last. Only the fetch belonging to the MOST RECENT
  // click is allowed to populate the form; a stale one is silently
  // discarded when it resolves. Mirrors the encounterId-guard pattern used
  // for the same class of race in encounter/noteSection.js.
  let editRequestToken = 0;
  document.querySelectorAll('.patient-edit').forEach(btn => {
    btn.addEventListener('click', async () => {
      const token = ++editRequestToken;
      const p = await patientsRepo.get(btn.dataset.patientId).catch(() => null);
      if (token !== editRequestToken) return; // superseded by a newer Edit click
      if (!p) { toast('Patient not found.'); return; }
      openEdit(p); // populates fields, enters edit visuals, reveals + focuses
    });
  });

  document.querySelectorAll('.patient-delete').forEach(btn => {
    btn.addEventListener('click', async () => {
      const ok = await confirmModal({
        title: 'Delete patient',
        message: 'This permanently removes the patient from the roster. Continue?',
        confirmLabel: 'Delete',
        confirmClass: 'btn-danger',
      });
      if (!ok) return;
      try {
        await patientsRepo.delete(btn.dataset.patientId);
        toast('Patient deleted.');
        rerender();
      } catch {
        toast('Could not delete patient.');
      }
    });
  });
}
