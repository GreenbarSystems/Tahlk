// Recording controls — start/stop the mic, react to save + tick events.
// All DOM/event wiring uses ctx.sub() so subscriptions are torn down by
// panel.js dispose().

import { encountersRepo } from '../../data/encountersRepo.js';
import { startRecording, stopRecording, abortRecording, isRecording, listAudioDevices, setDeviceId, getDeviceId } from '../../scribe/recorder.js';
import { toast, fmtDuration } from '../../utils/format.js';
import { userMessage } from '../../platform/appError.js';

export function wireRecordingSection(ctx) {
  const recordBtn   = document.getElementById('btn-record');
  const recordLabel = document.getElementById('record-label');
  const recordTimer = document.getElementById('record-timer');

  // Device picker: populate on mount; re-populate after first permission grant
  // so browser-supplied labels (empty before grant) become readable names.
  const deviceSelect = document.getElementById('audio-device-select');
  async function populateDevices() {
    if (!deviceSelect) return;
    const devices = await listAudioDevices();
    const current = deviceSelect.value;
    while (deviceSelect.options.length > 1) deviceSelect.remove(1);
    devices.forEach(d => {
      const opt = document.createElement('option');
      opt.value = d.deviceId;
      opt.textContent = d.label || `Microphone ${d.deviceId.slice(0, 6)}…`;
      deviceSelect.appendChild(opt);
    });
    if (getDeviceId()) deviceSelect.value = getDeviceId();
    else if (current) deviceSelect.value = current;
  }
  populateDevices();
  deviceSelect?.addEventListener('change', () => setDeviceId(deviceSelect.value || null));

  ctx.sub('scribe:recording_tick', ({ duration }) => {
    if (recordTimer) recordTimer.textContent = fmtDuration(duration);
  });

  ctx.sub('scribe:audio_saved', async ({ path, encounterId }) => {
    // Only claim a save that belongs to this panel's encounter. The bus is
    // global, so without this an in-flight save from a previously-open
    // encounter could stamp its audio_path onto whatever encounter is open
    // when it lands.
    if (encounterId !== ctx.currentEncounter.id) return;
    ctx.currentEncounter.audio_path = path;
    ctx.currentEncounter.status = 'recording_done';
    await encountersRepo.save(ctx.currentEncounter);
    ctx.onEncounterUpdated(ctx.currentEncounter);
    document.getElementById('btn-transcribe')?.removeAttribute('disabled');
    toast('Recording saved to device.');
  });

  // L11: recordBtn/recordLabel are guarded consistently with `?.` below,
  // matching the pattern already used for recordTimer (line 16) and
  // btn-transcribe (line 24) — previously these two were dereferenced
  // directly with no guard, so a missing/torn-down element (e.g. panel
  // disposed mid-flow) would throw a TypeError instead of silently no-oping.
  recordBtn?.addEventListener('click', async () => {
    if (isRecording()) {
      if (recordBtn) recordBtn.disabled = true;
      if (recordLabel) recordLabel.textContent = 'Saving…';
      try {
        await stopRecording(ctx.currentEncounter.id);
      } catch (e) {
        toast(userMessage(e, 'Could not save the recording.'));
        if (recordBtn) recordBtn.disabled = false;
        if (recordLabel) recordLabel.textContent = 'Start Recording';
      }
    } else {
      try {
        await startRecording(ctx.currentEncounter.id);
        recordBtn?.classList.add('btn-record--active');
        if (recordLabel) recordLabel.textContent = 'Stop Recording';
        // Re-populate device labels now that mic permission has been granted.
        if (deviceSelect) populateDevices().catch(() => {});
      } catch (e) {
        toast(userMessage(e, 'Could not start recording.'));
      }
    }
  });

  ctx.sub('scribe:recording_stopped', () => {
    recordBtn?.classList.remove('btn-record--active');
    if (recordLabel) recordLabel.textContent = 'Re-record';
    if (recordBtn) recordBtn.disabled = false;
  });

  // Teardown for panel.js dispose(). The recorder's state is module-scoped and
  // outlives this panel, so an unmount that leaves it running holds the
  // microphone open and lets the *next* encounter's Stop button save this
  // encounter's audio under that encounter's id.
  //
  // Saves rather than discards: the capture belongs to a real clinical
  // encounter and dropping it is record loss. Persisting it under
  // ctx.currentEncounter.id is correct here because this panel IS the
  // encounter the capture was started under. Abort is the fallback only when
  // the save fails, so the microphone is released on every path.
  async function stopForDispose() {
    if (!isRecording()) return;
    try {
      await stopRecording(ctx.currentEncounter.id);
    } catch {
      abortRecording();
    }
  }

  return { stopForDispose };
}
