// Copy / Save-File buttons + export-format selector.
//
// getFormattedNote reads the LIVE textarea + selector values (not a
// snapshot) so edits made after wiring are reflected in the export.

import { toPlainText, toSimplePractice, toTherapyNotes, copyToClipboard, saveToFile } from '../../export/exportFormatter.js';
import { saveToPdf } from '../../export/pdfExport.js';
import { toast } from '../../utils/format.js';
import { userMessage } from '../../platform/appError.js';

export function wireExportSection(ctx) {
  function getFormattedNote() {
    const note = document.getElementById('note-area')?.value || '';
    const fmt = document.getElementById('export-format')?.value || 'plain';
    if (fmt === 'simplepractice') return toSimplePractice(note, ctx.currentEncounter);
    if (fmt === 'therapynotes')   return toTherapyNotes(note, ctx.currentEncounter);
    return toPlainText(note, ctx.currentEncounter);
  }

  // All three handlers below share the same try/catch + failure-toast shape
  // used everywhere else in the app (see noteSection.js's sign handler).
  // Without it, a rejected export (clipboard permission denied, disk full,
  // an invalid save path) surfaced as a silent unhandled promise rejection —
  // no toast, no re-enabled state, nothing the provider could act on; the
  // export would just appear to do nothing.
  document.getElementById('btn-copy')?.addEventListener('click', async () => {
    try {
      const fmt = document.getElementById('export-format')?.value || 'plain';
      await copyToClipboard(getFormattedNote(), ctx.currentEncounter.id, fmt);
      toast('Note copied to clipboard.');
    } catch (e) {
      toast(userMessage(e, 'Could not copy note to clipboard.'));
    }
  });

  document.getElementById('btn-save-file')?.addEventListener('click', async () => {
    try {
      const fmt = document.getElementById('export-format')?.value || 'plain';
      await saveToFile(getFormattedNote(), ctx.currentEncounter, fmt);
      toast('Note saved to file.');
    } catch (e) {
      toast(userMessage(e, 'Could not save note to file.'));
    }
  });

  // PDF renders the raw note (buildPdf lays out its own date/alias/footer), so
  // it takes the live textarea value rather than a pre-formatted string.
  document.getElementById('btn-save-pdf')?.addEventListener('click', async () => {
    try {
      const note = document.getElementById('note-area')?.value || '';
      await saveToPdf(note, ctx.currentEncounter);
      toast('Note saved as PDF.');
    } catch (e) {
      toast(userMessage(e, 'Could not save note as PDF.'));
    }
  });
}
