// EHR patient import — 3-step modal: file picker → column mapper → preview.
//
// File reading uses the browser File API (FileReader.readAsText). No Tauri
// file-dialog capability is required; this also makes the flow testable in
// the browser dev-server preview without any stub changes.
//
// No innerHTML: all DOM is built with createElement/textContent.

import { createModal } from '../platform/modal.js';
import { patientsRepo } from '../data/patientsRepo.js';
import { genId, nowISO, toast } from '../utils/format.js';

// ── CSV parser (RFC-4180) ────────────────────────────────────────────────────
// Handles quoted fields (embedded commas, escaped quotes ""), CRLF + LF line
// endings, and a UTF-8 BOM on the first character (Microsoft Excel exports).

export function parseCsv(text) {
  if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);

  const allRows = [];
  let row = [];
  let field = '';
  let quoted = false;
  let i = 0;

  while (i < text.length) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 2; }
        else { quoted = false; i++; }
      } else { field += ch; i++; }
    } else {
      if (ch === '"')  { quoted = true; i++; }
      else if (ch === ',') { row.push(field); field = ''; i++; }
      else if (ch === '\r' && text[i + 1] === '\n') {
        row.push(field); field = '';
        if (row.some(f => f !== '') || allRows.length > 0) allRows.push(row);
        row = []; i += 2;
      } else if (ch === '\n') {
        row.push(field); field = '';
        if (row.some(f => f !== '') || allRows.length > 0) allRows.push(row);
        row = []; i++;
      } else { field += ch; i++; }
    }
  }
  row.push(field);
  if (row.some(f => f !== '')) allRows.push(row);

  const headers  = allRows[0] || [];
  const dataRows = allRows.slice(1).filter(r => r.some(f => f.trim() !== ''));
  return { headers, rows: dataRows };
}

// ── Column auto-suggester ────────────────────────────────────────────────────
// Case-insensitive match against common EHR export header names. Returns the
// actual header string (for use as the <select> preselect value) or null.

export function suggestMappings(headers) {
  const lc = headers.map(h => h.toLowerCase().trim());
  const find = (...terms) => {
    for (let j = 0; j < lc.length; j++) {
      if (terms.some(t => lc[j] === t || lc[j].includes(t))) return headers[j];
    }
    return null;
  };
  return {
    aliasCol:    find('alias', 'initials', 'client name', 'full name', 'name',
                      'first name', 'patient name'),
    dobCol:      find('dob', 'date of birth', 'birth date', 'birthdate',
                      'date_of_birth', 'birth_date'),
    notesCol:    find('notes', 'note', 'comment', 'comments', 'memo'),
    sourceIdCol: find('client id', 'client_id', 'patient id', 'patient_id',
                      'client number', 'mrn', 'chart number', 'id'),
  };
}

// Warn when the alias column selection looks like a real patient name column.
const NAME_COL_PATTERN = /(first|last|full|patient|client)?\s*name/i;

// ── Import executor (called from step 3 confirm) ─────────────────────────────

async function runImport(patients) {
  const now = nowISO();
  for (const p of patients) {
    await patientsRepo.save({ ...p, updated_at: now });
  }
}

// ── Modal flow: step 1 — file picker ─────────────────────────────────────────

export function openImportModal(rerender) {
  const modal = createModal({
    closeOnEscape: true,
    closeOnBackdrop: true,
    onRequestClose: () => modal.close(),
  });
  const { card } = modal.open();
  card.className = 'modal-card import-modal-card';
  showStep1(card, modal, rerender);
}

function showStep1(card, modal, rerender) {
  card.textContent = '';

  const title = el('h3', 'import-modal-title', 'Import patients from EHR');
  const desc  = el('p',  'import-modal-desc',
    'Export a patient list from your EHR system as a CSV file, then select it here.');

  const zone = document.createElement('label');
  zone.className = 'ehr-import-dropzone';
  zone.setAttribute('tabindex', '0');

  const zoneLabel = el('span', 'ehr-import-dropzone-label',
    'Click to choose a CSV file, or drag one here');

  const fileInput = document.createElement('input');
  fileInput.type   = 'file';
  fileInput.accept = '.csv,text/csv';
  fileInput.className = 'ehr-import-file-input';
  fileInput.setAttribute('aria-label', 'Select CSV file');

  zone.appendChild(zoneLabel);
  zone.appendChild(fileInput);

  const errMsg = el('p', 'import-error');
  errMsg.hidden = true;

  const cancelBtn = actionBtn('Cancel', 'btn btn-ghost', () => modal.close());
  const footer = footerRow([cancelBtn]);

  card.appendChild(title);
  card.appendChild(desc);
  card.appendChild(zone);
  card.appendChild(errMsg);
  card.appendChild(footer);

  zone.addEventListener('dragover', e => { e.preventDefault(); zone.dataset.dragOver = '1'; });
  zone.addEventListener('dragleave', () => delete zone.dataset.dragOver);
  zone.addEventListener('drop', e => {
    e.preventDefault();
    delete zone.dataset.dragOver;
    const f = e.dataTransfer?.files[0];
    if (f) readFile(f);
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) readFile(fileInput.files[0]);
  });

  function readFile(file) {
    const ok = file.name.toLowerCase().endsWith('.csv') || file.type === 'text/csv'
            || file.type === 'application/vnd.ms-excel';
    if (!ok) {
      showErr(errMsg, 'Please select a CSV file (.csv).');
      return;
    }
    const reader = new FileReader();
    reader.onload = e => {
      try {
        const { headers, rows } = parseCsv(e.target.result);
        if (headers.length === 0) {
          showErr(errMsg, 'The file appears empty or has no header row.');
          return;
        }
        showStep2(card, modal, rerender, headers, rows);
      } catch {
        showErr(errMsg, 'Could not parse the CSV. Make sure it is a valid CSV export.');
      }
    };
    reader.onerror = () => showErr(errMsg, 'Could not read the file.');
    reader.readAsText(file);
  }
}

// ── Modal flow: step 2 — column mapper ───────────────────────────────────────

function showStep2(card, modal, rerender, headers, rows) {
  card.textContent = '';

  const suggested = suggestMappings(headers);

  const title = el('h3', 'import-modal-title', 'Map columns');
  const desc  = el('p',  'import-modal-desc',
    `Found ${rows.length} patient row${rows.length !== 1 ? 's' : ''}. ` +
    'Choose which CSV column maps to each Tahlk field.');

  const warning = el('div', 'import-warning',
    'You selected a column that may contain real patient names. ' +
    'Patient data is stored encrypted on your device — ensure this device is access-controlled.');
  warning.hidden = true;

  const FIELDS = [
    { key: 'aliasCol',    label: 'Patient alias',    required: true,  sug: suggested.aliasCol },
    { key: 'dobCol',      label: 'Date of birth',     required: false, sug: suggested.dobCol },
    { key: 'notesCol',    label: 'Notes',              required: false, sug: suggested.notesCol },
    { key: 'sourceIdCol', label: 'Patient ID in EHR', required: false, sug: suggested.sourceIdCol },
  ];

  const selects = {};
  const grid = document.createElement('div');
  grid.className = 'col-mapper-grid';

  for (const f of FIELDS) {
    const lbl  = document.createElement('label');
    lbl.className = 'col-mapper-label';

    const lspan = el('span', 'col-mapper-field-name', f.label);
    if (f.required) {
      const req = el('span', 'req', ' *');
      lspan.appendChild(req);
    }
    lbl.appendChild(lspan);

    const sel = document.createElement('select');
    sel.className = 'col-mapper-select';

    if (!f.required) {
      const skip = document.createElement('option');
      skip.value = '';
      skip.textContent = '-- Skip --';
      sel.appendChild(skip);
    }

    for (const h of headers) {
      const opt = document.createElement('option');
      opt.value = h;
      opt.textContent = h;
      if (h === f.sug) opt.selected = true;
      sel.appendChild(opt);
    }

    selects[f.key] = sel;
    lbl.appendChild(sel);
    grid.appendChild(lbl);
  }

  const checkWarning = () => {
    warning.hidden = !NAME_COL_PATTERN.test(selects.aliasCol.value);
  };
  selects.aliasCol.addEventListener('change', checkWarning);
  checkWarning();

  const backBtn = actionBtn('← Back', 'btn btn-ghost',
    () => showStep1(card, modal, rerender));

  const nextBtn = actionBtn('Preview →', 'btn btn-primary', () => {
    const aliasHeader = selects.aliasCol.value;
    if (!aliasHeader) { toast('Choose a column for patient alias.'); return; }

    const idxOf = key => {
      const v = selects[key].value;
      return v ? headers.indexOf(v) : null;
    };

    showStep3(card, modal, rerender, headers, rows, {
      aliasIdx:    headers.indexOf(aliasHeader),
      dobIdx:      idxOf('dobCol'),
      notesIdx:    idxOf('notesCol'),
      sourceIdIdx: idxOf('sourceIdCol'),
    });
  });

  const footer = footerRow([backBtn, nextBtn]);

  card.appendChild(title);
  card.appendChild(desc);
  card.appendChild(warning);
  card.appendChild(grid);
  card.appendChild(footer);
}

// ── Modal flow: step 3 — preview + confirm ────────────────────────────────────

async function showStep3(card, modal, rerender, headers, rows, mapping) {
  card.textContent = '';

  const spinner = el('p', 'import-modal-desc', 'Loading…');
  card.appendChild(spinner);

  const existingPatients = await patientsRepo.list().catch(() => []);
  const sourceIdMap = new Map(
    existingPatients.filter(p => p.source_id).map(p => [p.source_id, p])
  );

  let newCount     = 0;
  let updateCount  = 0;
  let skippedCount = 0;
  const patients   = [];
  const now        = nowISO();

  for (const row of rows) {
    const alias    = (row[mapping.aliasIdx] || '').trim();
    if (!alias) { skippedCount++; continue; }

    const dob      = mapping.dobIdx      !== null ? (row[mapping.dobIdx]      || '').trim() || null : null;
    const notes    = mapping.notesIdx    !== null ? (row[mapping.notesIdx]    || '').trim() || null : null;
    const sourceId = mapping.sourceIdIdx !== null ? (row[mapping.sourceIdIdx] || '').trim() || null : null;

    const existing = sourceId ? sourceIdMap.get(sourceId) : null;
    const tahlkId  = existing ? existing.id : genId('pt');

    if (existing) updateCount++; else newCount++;
    patients.push({
      id:         tahlkId,
      alias,
      dob,
      notes,
      source_id:  sourceId,
      created_at: existing ? existing.created_at : now,
      updated_at: now,
    });
  }

  card.textContent = '';

  const title = el('h3', 'import-modal-title', 'Preview import');

  const total = newCount + updateCount;
  const parts = [];
  if (newCount)     parts.push(`${newCount} new`);
  if (updateCount)  parts.push(`${updateCount} updated`);
  if (skippedCount) parts.push(`${skippedCount} skipped (no alias)`);
  const summary = el('p', 'import-summary', `${total} patient${total !== 1 ? 's' : ''}: ${parts.join(', ')}.`);

  const tableWrap = document.createElement('div');
  tableWrap.className = 'import-preview-wrap';

  const table = document.createElement('table');
  table.className = 'import-preview-table';

  const thead = document.createElement('thead');
  const headRow = document.createElement('tr');
  for (const col of ['Alias', 'Date of Birth', 'EHR ID', 'Tahlk ID']) {
    const th = document.createElement('th');
    th.textContent = col;
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  for (const r of patients.slice(0, 10)) {
    const tr = document.createElement('tr');
    for (const v of [r.alias, r.dob || '', r.source_id || '', r.id]) {
      const td = document.createElement('td');
      td.textContent = v;
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  const previewCount = Math.min(patients.length, 10);
  const remainder    = patients.length - previewCount;
  if (remainder > 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.className = 'import-preview-more';
    td.textContent = `…and ${remainder} more`;
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  tableWrap.appendChild(table);

  const errMsg = el('p', 'import-error');
  errMsg.hidden = true;

  const importBtn = actionBtn(
    `Import ${total} patient${total !== 1 ? 's' : ''}`,
    'btn btn-primary',
    async () => {
      importBtn.disabled = true;
      importBtn.textContent = 'Importing…';
      errMsg.hidden = true;
      try {
        await runImport(patients);
        modal.close();
        const msg = [
          newCount     ? `${newCount} added`       : '',
          updateCount  ? `${updateCount} updated`  : '',
          skippedCount ? `${skippedCount} skipped` : '',
        ].filter(Boolean).join(', ');
        toast(`Import complete: ${msg}.`);
        rerender();
      } catch {
        showErr(errMsg, 'Import failed. Please try again.');
        importBtn.disabled = false;
        importBtn.textContent = `Import ${total} patient${total !== 1 ? 's' : ''}`;
      }
    }
  );
  if (total === 0) importBtn.disabled = true;

  const backBtn = actionBtn('← Back', 'btn btn-ghost',
    () => showStep2(card, modal, rerender, headers, rows));

  const footer = footerRow([backBtn, importBtn]);

  card.appendChild(title);
  card.appendChild(summary);
  card.appendChild(tableWrap);
  card.appendChild(errMsg);
  card.appendChild(footer);
}

// ── DOM helpers ───────────────────────────────────────────────────────────────

function el(tag, className, text) {
  const node = document.createElement(tag);
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function actionBtn(label, className, onClick) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = className;
  btn.textContent = label;
  btn.addEventListener('click', onClick);
  return btn;
}

function footerRow(btns) {
  const footer = document.createElement('div');
  footer.className = 'import-modal-footer';
  for (const b of btns) footer.appendChild(b);
  return footer;
}

function showErr(el, msg) {
  el.textContent = msg;
  el.hidden = false;
}
