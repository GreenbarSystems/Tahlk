// Recording controls — start/stop the mic, react to save + tick events.
// All DOM/event wiring uses ctx.sub() so subscriptions are torn down by
// panel.js dispose().

import { encountersRepo } from '../../data/encountersRepo.js';
import { startRecording, stopRecording, isRecording } from '../../scribe/recorder.js';
import { toast, fmtDuration } from '../../utils/format.js';

export function wireRecordingSection(ctx) {
  const recordBtn = document.getElementById('btn-record');
  const recordLabel = document.getElementById('record-label');
  const recordTimer = document.getElementById('record-timer');

  ctx.sub('scribe:recording_tick', ({ duration }) => {
    if (recordTimer) recordTimer.textContent = fmtDuration(duration);
  });

  ctx.sub('scribe:audio_saved', async ({ path }) => {
    ctx.currentEncounter.audio_path = path;
    ctx.currentEncounter.status = 'recording_done';
    await encountersRepo.save(ctx.currentEncounter);
    ctx.onEncounterUpdated(ctx.currentEncounter);
    document.getElementById('btn-transcribe')?.removeAttribute('disabled');
    toast('Recording saved to device.');
  });

  recordBtn?.addEventListener('click', async () => {
    if (isRecording()) {
      recordBtn.disabled = true;
      recordLabel.textContent = 'Saving…';
      try {
        await stopRecording(ctx.currentEncounter.id);
      } catch (e) {
        toast(e.message);
        recordBtn.disabled = false;
        recordLabel.textContent = 'Start Recording';
      }
    } else {
      try {
        await startRecording();
        recordBtn.classList.add('btn-record--active');
        recordLabel.textContent = 'Stop Recording';
      } catch (e) {
        toast(e.message);
      }
    }
  });

  ctx.sub('scribe:recording_stopped', () => {
    recordBtn?.classList.remove('btn-record--active');
    recordLabel.textContent = 'Re-record';
    recordBtn.disabled = false;
  });
}
