// Copy / Save-File buttons + export-format selector.
//
// getFormattedNote reads the LIVE textarea + selector values (not a
// snapshot) so edits made after wiring are reflected in the export.

import { toPlainText, toSimplePractice, toTherapyNotes, copyToClipboard, saveToFile } from '../../export/exportFormatter.js';
import { toast } from '../../utils/format.js';

export function wireExportSection(ctx) {
  function getFormattedNote() {
    const note = document.getElementById('note-area')?.value || '';
    const fmt = document.getElementById('export-format')?.value || 'plain';
    if (fmt === 'simplepractice') return toSimplePractice(note, ctx.currentEncounter);
    if (fmt === 'therapynotes')   return toTherapyNotes(note, ctx.currentEncounter);
    return toPlainText(note, ctx.currentEncounter);
  }

  document.getElementById('btn-copy')?.addEventListener('click', async () => {
    const fmt = document.getElementById('export-format')?.value || 'plain';
    await copyToClipboard(getFormattedNote(), ctx.currentEncounter.id, fmt);
    toast('Note copied to clipboard.');
  });

  document.getElementById('btn-save-file')?.addEventListener('click', async () => {
    const fmt = document.getElementById('export-format')?.value || 'plain';
    await saveToFile(getFormattedNote(), ctx.currentEncounter, fmt);
    toast('Note saved to file.');
  });
}
