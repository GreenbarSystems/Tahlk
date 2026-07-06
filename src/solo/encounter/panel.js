// Encounter-panel orchestrator: owns the shared state object (ctx), wires
// each *Section module, and returns dispose() to the caller.
//
// State that multiple sections need lives on ctx:
//   • currentEncounter — mutable snapshot of the encounter row
//   • currentTranscript() / setTranscript() — closure over the transcript
//     string so recordingSection can't accidentally observe a stale copy
//   • providerProfile — read once at open (used at sign-off)
//   • sub(evt, fn) — bus subscription that auto-registers a disposer
//   • onEncounterUpdated — router callback to refresh the encounter list
//
// dispose() drains noteSection's pending edit, cancels its rAF frame, then
// tears down every bus subscription. Safe to call more than once.

import { kvGet } from '../../core/storageBackend.js';
import { encountersRepo } from '../../data/encountersRepo.js';
import { keys } from '../../data/keys.js';
import { on } from '../../core/eventBus.js';
import { TRANSCRIPT_KEY } from './template.js';
import { wireRecordingSection } from './recordingSection.js';
import { wireTranscriptSection } from './transcriptSection.js';
import { wireNoteSection } from './noteSection.js';
import { wireExportSection } from './exportSection.js';
import { runScribeChain } from './autoChain.js';

export function wireEncounterPanel(encounter, onClose, onEncounterUpdated) {
  const providerProfile = kvGet(keys.provider()) || {};

  // Local mutable snapshot — sections read/write this. Kept as one object so
  // section modules see updates from siblings without extra plumbing.
  const currentEncounter = { ...encounter };
  let transcript = kvGet(TRANSCRIPT_KEY(encounter.id)) || '';

  // Collect event-bus subscriptions so they can be torn down when the panel
  // closes. Without this, every panel open leaks handlers that fire against
  // detached DOM nodes from prior encounters.
  const disposers = [];
  const sub = (evt, fn) => { disposers.push(on(evt, fn)); };

  const ctx = {
    currentEncounter,
    providerProfile,
    sub,
    onEncounterUpdated,
    currentTranscript: () => transcript,
    setTranscript: (v) => { transcript = v; },
  };

  const note = wireNoteSection(ctx);
  wireRecordingSection(ctx);
  const transcriptCtl = wireTranscriptSection(ctx);
  wireExportSection(ctx);

  // Auto-chain: once audio is saved, transcribe and then (on success) generate
  // the note without further clicks. Subscribed AFTER wireRecordingSection so
  // that recordingSection's audio_saved handler — which sets audio_path on the
  // encounter synchronously before it awaits — has already run. Manual
  // "Transcribe" / "Generate Note" buttons stay wired for retries and
  // template switches. Transcription failure stops the chain (runScribeChain
  // only generates when transcription succeeded).
  ctx.sub('scribe:audio_saved', () => {
    runScribeChain({
      transcribeNow: transcriptCtl.transcribeNow,
      generateNow: note.generateNow,
    });
  });

  // Unmount: flush the pending edit, cancel any streaming frame, then drop
  // every subscription. Safe to call more than once. Returned so the router
  // can dispose the panel on ANY unmount path (close button, tab navigation,
  // re-render).
  let disposed = false;
  async function dispose() {
    if (disposed) return;
    disposed = true;
    note.cleanup();
    await note.flushPendingEdit();
    disposers.forEach(d => d());
    disposers.length = 0;
  }

  // Close — dispose, then hand control back to the router.
  document.getElementById('btn-close-panel')?.addEventListener('click', async () => {
    await dispose();
    onClose();
  });

  // Patient alias save on blur.
  document.getElementById('patient-alias')?.addEventListener('change', async e => {
    currentEncounter.patient_alias = e.target.value.trim() || null;
    await encountersRepo.save(currentEncounter);
    onEncounterUpdated(currentEncounter);
  });

  return dispose;
}
