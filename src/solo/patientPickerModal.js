// Patient-picker modal — shown when + New Session is clicked.
// Returns Promise<string|null>: the selected patient's alias, or null to skip.
// Nodes are built explicitly (no innerHTML) to match confirmModal.js convention.

import { patientsRepo } from '../data/patientsRepo.js';
import { logRecordsListed } from '../core/auditLog.js';
import { createModal } from '../platform/modal.js';

export function pickPatient() {
  return new Promise(resolve => {
    let resolved = false;
    const done = alias => {
      if (resolved) return;
      resolved = true;
      modal.close();
      resolve(alias);
    };

    const modal = createModal({
      closeOnEscape: true,
      closeOnBackdrop: true,
      onRequestClose: () => done(null),
    });

    const { card } = modal.open();
    card.className += ' patient-picker-card';
    card.setAttribute('aria-label', 'Select a patient for this session');

    const header = document.createElement('div');
    header.className = 'patient-picker-header';
    const title = document.createElement('h2');
    title.className = 'patient-picker-title';
    title.textContent = 'Select a patient';
    const skipBtn = document.createElement('button');
    skipBtn.className = 'btn btn-ghost btn-sm';
    skipBtn.textContent = 'Skip';
    skipBtn.addEventListener('click', () => done(null));
    header.appendChild(title);
    header.appendChild(skipBtn);
    card.appendChild(header);

    const searchWrap = document.createElement('div');
    searchWrap.className = 'patient-picker-search-wrap';
    const searchInput = document.createElement('input');
    searchInput.type = 'search';
    searchInput.className = 'patient-picker-search';
    searchInput.placeholder = 'Search patients…';
    searchInput.setAttribute('autocomplete', 'off');
    searchWrap.appendChild(searchInput);
    card.appendChild(searchWrap);

    const listEl = document.createElement('ul');
    listEl.className = 'patient-picker-list';
    listEl.setAttribute('role', 'listbox');
    listEl.setAttribute('aria-label', 'Patient list');
    card.appendChild(listEl);

    patientsRepo.list().then(patients => {
      // The picker discloses the whole patient roster (alias + DOB) in the
      // new-session flow — a PHI access event outside the per-encounter panel.
      // Logged once when the list loads, not per keystroke of the filter below.
      if (patients.length > 0) {
        logRecordsListed('patients', patients.length).catch(() => {});
      }

      function renderList(query) {
        const q = query.trim().toLowerCase();
        const filtered = q
          ? patients.filter(p => p.alias.toLowerCase().includes(q))
          : patients;
        listEl.innerHTML = '';
        if (filtered.length === 0) {
          const empty = document.createElement('li');
          empty.className = 'patient-picker-empty';
          empty.textContent = q
            ? 'No patients match your search.'
            : 'No patients yet — add them in the Patients tab, or skip.';
          listEl.appendChild(empty);
          return;
        }
        filtered.forEach(p => {
          const li = document.createElement('li');
          li.className = 'patient-picker-item';
          li.setAttribute('tabindex', '0');
          li.setAttribute('role', 'option');
          li.setAttribute('aria-label', p.alias);
          const aliasEl = document.createElement('span');
          aliasEl.className = 'picker-alias';
          aliasEl.textContent = p.alias;
          li.appendChild(aliasEl);
          if (p.dob) {
            const dobEl = document.createElement('span');
            dobEl.className = 'picker-dob';
            dobEl.textContent = p.dob;
            li.appendChild(dobEl);
          }
          const select = () => done(p.alias);
          li.addEventListener('click', select);
          li.addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(); }
          });
          listEl.appendChild(li);
        });
      }

      renderList('');
      searchInput.addEventListener('input', e => renderList(e.target.value));
      searchInput.focus();
    }).catch(() => done(null));
  });
}
