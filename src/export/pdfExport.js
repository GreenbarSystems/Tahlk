// Clinical note PDF export — runs entirely in the Tauri webview (no cloud).
//
// jsPDF renders the note into US-Letter binary; the bytes are handed to a Rust
// save-dialog command (export_note_pdf_to_file) that writes them to disk. The
// visual structure mirrors toPlainText/toTherapyNotes in exportFormatter.js:
// a date line, an optional patient-alias line, the note body, and a Tahlk
// attestation footer.
//
// Deliberately decoupled from any cloud archive: unlike the abandoned
// dev/backend-and-audit-fixes branch this is reconstructed from, there is NO
// import of core/api.js, NO S3 upload, and NO network call. Cloud archival is
// frozen with Group tier per docs/adr/0001-freeze-group-tier-and-sync.md.

import { jsPDF } from 'jspdf';
import { invoke } from '../platform/tauri.js';
import { logNoteExported } from '../core/auditLog.js';
import { emit } from '../core/eventBus.js';
import { exportFilename } from './exportFormatter.js';
import { displayDateShort } from '../utils/format.js';

// US Letter in points (jsPDF `unit: 'pt'`).
const PAGE_W = 612;
const PAGE_H = 792;
const MARGIN = 72; // 1 inch
const CONTENT_W = PAGE_W - MARGIN * 2;
const LINE_H = 14.5;
const BODY_BOTTOM = PAGE_H - MARGIN - 40; // leave room for the footer

const NAVY = [17, 40, 77];
const GRAY = [107, 114, 128];
const INK = [20, 20, 20];

// Cloud-archive extension seam. Stays `null` in this codebase — nothing sets
// it — until Group tier unfreezes per ADR 0001's criteria. It mirrors the
// capability-accessor exemption pattern in src/core/capabilities.js (see
// currentProvider/currentUser): core code names a seam that Solo leaves inert
// and a future Group build may inject. Archival is best-effort and must never
// block or fail the local save.
export let archivePdfHook = null;

// Test/Group-injection setter kept explicit so the export stays a `const`-like
// binding at every read site; production Solo never calls this.
export function setArchivePdfHook(fn) {
  archivePdfHook = typeof fn === 'function' ? fn : null;
}

// PHI-safe filename: reuses exportFilename (no patient alias — it can be a real
// name and filenames leak via listings/backups) with a .pdf extension.
export function exportFilenamePdf(encounter) {
  return exportFilename(encounter, 'pdf');
}

// Render the note into a PDF and return its bytes as a Uint8Array. Pure aside
// from jsPDF — no I/O, no network — so it is unit-testable on its own.
export function buildPdf(note, encounter) {
  const doc = new jsPDF({ unit: 'pt', format: 'letter', compress: true });
  let y = MARGIN;

  // Header: date, optional patient alias, encounter id.
  const date = displayDateShort(encounter.encounter_date || encounter.created_at);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(...NAVY);
  doc.text(`Date: ${date}`, MARGIN, y);
  y += 16;
  if (encounter.patient_alias) {
    doc.text(`Patient: ${encounter.patient_alias}`, MARGIN, y);
    y += 16;
  }
  if (encounter.id) {
    doc.setFontSize(9);
    doc.setTextColor(...GRAY);
    doc.text(`Encounter ID: ${encounter.id}`, MARGIN, y);
    y += 14;
  }

  // Rule before the body.
  doc.setDrawColor(210, 215, 220);
  doc.setLineWidth(0.5);
  doc.line(MARGIN, y, PAGE_W - MARGIN, y);
  y += 18;

  // Body — wrap + paginate.
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10.5);
  doc.setTextColor(...INK);
  const lines = doc.splitTextToSize(note || '(No note content)', CONTENT_W);
  for (const line of lines) {
    if (y > BODY_BOTTOM) {
      doc.addPage();
      y = MARGIN;
    }
    doc.text(line, MARGIN, y);
    y += LINE_H;
  }

  // Attestation footer on every page — mirrors toTherapyNotes' footer line.
  const signed = encounter.status === 'signed';
  const footer = signed
    ? '--- Tahlk (AI-assisted) | Reviewed and attested by provider ---'
    : '--- Tahlk (AI-assisted) | DRAFT — provider review and sign-off required ---';
  const total = doc.internal.getNumberOfPages();
  for (let p = 1; p <= total; p++) {
    doc.setPage(p);
    const fy = PAGE_H - MARGIN + 16;
    doc.setDrawColor(210, 215, 220);
    doc.setLineWidth(0.5);
    doc.line(MARGIN, fy - 14, PAGE_W - MARGIN, fy - 14);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(...GRAY);
    doc.text(footer, MARGIN, fy);
    doc.text(`${p} / ${total}`, PAGE_W - MARGIN, fy, { align: 'right' });
  }

  return doc.output('arraybuffer'); // ArrayBuffer of the rendered PDF
}

// Encode an ArrayBuffer/Uint8Array as base64 for the Rust boundary. jsPDF gives
// us binary; the Tauri command decodes it back to raw bytes and writes them.
function toBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// Build the PDF and save it via the native Save-As dialog. After a successful
// local save, the optional cloud-archive hook is invoked best-effort (see
// archivePdfHook above) — it never blocks or fails the local save.
export async function saveToPdf(note, encounter) {
  const buf = buildPdf(note, encounter);
  await invoke('export_note_pdf_to_file', {
    dataBase64: toBase64(buf),
    suggestedName: exportFilenamePdf(encounter),
  });

  await logNoteExported(encounter.id, 'pdf', 'file');
  emit('scribe:note_exported', { encounterId: encounter.id, format: 'pdf' });

  if (archivePdfHook) {
    try { await archivePdfHook(buf, encounter); }
    catch { /* archival is best-effort, never blocks the local save */ }
  }
}
