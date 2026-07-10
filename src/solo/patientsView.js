// Patients view — a lightweight standalone roster (alias, optional DOB, notes).
// Not linked to encounters in this iteration. Follows the render/wire pattern
// used by homeScreen.js: an async render that reads from patientsRepo, and a
// wire step that attaches handlers and re-renders on mutation.

import { patientsRepo } from '../data/patientsRepo.js';
import { genId, nowISO, displayDateShort, escapeHtml, toast } from '../utils/format.js';
import { confirmModal } from './confirmModal.js';

export async function renderPatientsView() {
  const patients = await patientsRepo.list().catch(() => []);

  return `
    <div class="patients-page">
      <div class="patients-header">
        <h2 class="settings-title">Patients</h2>
      </div>

      <form class="patient-form" id="patient-form" autocomplete="off">
        <input type="hidden" id="patient-id" value="">
        <div class="patient-form-row">
          <label class="patient-field">
            <span class="patient-field-label">Name / alias</span>
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
          <button type="button" class="btn btn-ghost patient-cancel-edit" id="patient-cancel"
                  hidden>Cancel</button>
        </div>
      </form>

      <div class="patient-list" id="patient-list">
        ${patients.length === 0 ? `
          <div class="empty-state">
            <p>No patients yet.</p>
            <p>Add one using the form above.</p>
          </div>
        ` : patients.map(p => renderPatientRow(p)).join('')}
      </div>
    </div>
  `;
}

function renderPatientRow(p) {
  const alias = escapeHtml(p.alias);
  const dob   = p.dob ? escapeHtml(displayDateShort(p.dob)) : '';
  const notes = p.notes ? escapeHtml(p.notes) : '';
  return `
    <div class="patient-row" data-patient-id="${escapeHtml(p.id)}">
      <div class="patient-main">
        <div class="patient-alias">${alias}</div>
        ${dob ? `<div class="patient-dob">DOB: ${dob}</div>` : ''}
        ${notes ? `<div class="patient-notes">${notes}</div>` : ''}
      </div>
      <div class="patient-actions">
        <button class="btn btn-ghost btn-sm patient-edit" data-patient-id="${escapeHtml(p.id)}">Edit</button>
        <button class="btn btn-ghost btn-sm patient-delete" data-patient-id="${escapeHtml(p.id)}">Delete</button>
      </div>
    </div>
  `;
}

// `rerender` re-runs the view (render + wire) after any mutation so the list
// reflects the new state — mirrors how homeScreen re-renders on navigation.
export function wirePatientsView(rerender) {
  const form     = document.getElementById('patient-form');
  const idEl     = document.getElementById('patient-id');
  const aliasEl  = document.getElementById('patient-alias');
  const dobEl    = document.getElementById('patient-dob');
  const notesEl  = document.getElementById('patient-notes');
  const saveBtn  = document.getElementById('patient-save');
  const cancelBtn = document.getElementById('patient-cancel');

  const resetForm = () => {
    idEl.value = '';
    aliasEl.value = '';
    dobEl.value = '';
    notesEl.value = '';
    saveBtn.textContent = 'Add patient';
    cancelBtn.hidden = true;
  };

  form?.addEventListener('submit', async e => {
    e.preventDefault();
    const alias = aliasEl.value.trim();
    if (!alias) { toast('Name / alias is required.'); return; }

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
      resetForm();
      rerender();
    } catch {
      toast('Could not save patient.');
    }
  });

  cancelBtn?.addEventListener('click', resetForm);

  document.querySelectorAll('.patient-edit').forEach(btn => {
    btn.addEventListener('click', async () => {
      const p = await patientsRepo.get(btn.dataset.patientId).catch(() => null);
      if (!p) { toast('Patient not found.'); return; }
      idEl.value = p.id;
      aliasEl.value = p.alias || '';
      dobEl.value = p.dob || '';
      notesEl.value = p.notes || '';
      saveBtn.textContent = 'Save changes';
      cancelBtn.hidden = false;
      aliasEl.focus();
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
