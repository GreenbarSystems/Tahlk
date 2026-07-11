// Audio capture via Web Audio API + MediaRecorder.
// Audio chunks are assembled into a WAV blob then persisted to disk
// via the Tauri save_session_audio command. Audio never leaves the device.

import { emit } from '../core/eventBus.js';
import { invoke } from '../platform/tauri.js';

let _mediaRecorder = null;
let _chunks = [];
let _startTime = null;
let _timerInterval = null;
let _stream = null;

export function isRecording() {
  return _mediaRecorder?.state === 'recording';
}

export function recordingDuration() {
  if (!_startTime) return 0;
  return Math.floor((Date.now() - _startTime) / 1000);
}

export async function startRecording() {
  if (isRecording()) return;

  try {
    _stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  } catch (e) {
    const msg = e.name === 'NotAllowedError'
      ? 'Microphone access denied. Allow microphone access in system settings.'
      : `Microphone error: ${e.message}`;
    throw new Error(msg);
  }

  _chunks = [];
  _mediaRecorder = new MediaRecorder(_stream, { mimeType: bestMimeType() });
  _mediaRecorder.ondataavailable = e => { if (e.data.size > 0) _chunks.push(e.data); };
  _mediaRecorder.start(1000); // collect in 1s chunks
  _startTime = Date.now();

  _timerInterval = setInterval(() => {
    emit('scribe:recording_tick', { duration: recordingDuration() });
  }, 1000);

  emit('scribe:recording_started', {});
}

// If the underlying MediaRecorder never fires `onstop` after we call
// `.stop()` — observed in the wild on some platforms when the capture
// device disappears mid-session (e.g. a Bluetooth mic dropping) — the
// Promise below would otherwise hang forever with no way for the caller
// to recover: the Stop button stays disabled, the timer stays stopped,
// and nothing ever resolves or rejects. STOP_TIMEOUT_MS bounds that wait
// so the caller's existing catch/toast path (recordingSection.js) always
// gets a chance to run and re-enable the UI.
const STOP_TIMEOUT_MS = 8000;

export async function stopRecording(encounterId) {
  if (!isRecording()) return null;

  return new Promise((resolve, reject) => {
    let settled = false;

    const timeoutId = setTimeout(() => {
      if (settled) return;
      settled = true;
      clearInterval(_timerInterval);
      _timerInterval = null;
      _mediaRecorder.onstop = null;
      stopStream();
      const err = new Error('Recording did not stop in time. Please try again.');
      emit('scribe:audio_error', { error: err.message, encounterId });
      reject(err);
    }, STOP_TIMEOUT_MS);

    _mediaRecorder.onstop = async () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutId);
      clearInterval(_timerInterval);
      _timerInterval = null;

      try {
        const blob = new Blob(_chunks, { type: _mediaRecorder.mimeType });
        const arrayBuffer = await blob.arrayBuffer();
        const wavBuffer = _mediaRecorder.mimeType.includes('wav')
          ? arrayBuffer
          : await convertToWav(arrayBuffer);

        const base64 = await arrayBufferToBase64(wavBuffer);
        const path = await invoke('save_session_audio', { encounterId, base64Data: base64 });

        stopStream();
        emit('scribe:recording_stopped', { encounterId });
        emit('scribe:audio_saved', { path, encounterId });
        resolve(path);
      } catch (e) {
        stopStream();
        emit('scribe:audio_error', { error: e.message, encounterId });
        reject(e);
      }
    };
    _mediaRecorder.stop();
  });
}

function stopStream() {
  _stream?.getTracks().forEach(t => t.stop());
  _stream = null;
  _startTime = null;
}

function bestMimeType() {
  const candidates = [
    'audio/webm;codecs=opus',
    'audio/webm',
    'audio/ogg;codecs=opus',
    'audio/wav',
  ];
  return candidates.find(t => MediaRecorder.isTypeSupported(t)) || '';
}

// Base64-encode an ArrayBuffer without blocking the main thread. A WAV for a
// long session is tens of MB; the previous char-by-char btoa loop froze the UI.
// FileReader.readAsDataURL does the encoding natively and asynchronously.
function arrayBufferToBase64(buf) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result; // "data:...;base64,XXXX"
      resolve(result.slice(result.indexOf(',') + 1));
    };
    reader.onerror = () => reject(reader.error || new Error('base64 encode failed'));
    reader.readAsDataURL(new Blob([buf]));
  });
}

// whisper.cpp's native sample rate. Producing 16 kHz mono here — rather than
// the ~48 kHz capture rate — shrinks the WAV, the IPC payload, and the on-disk
// file by ~3x and avoids a redundant resample inside whisper.
const TARGET_RATE = 16000;

// Re-encode a compressed recording to 16 kHz mono PCM WAV. The decoded buffer
// is freed as soon as rendering completes, bounding peak memory on long
// sessions to roughly the 16 kHz signal rather than the full 48 kHz capture.
async function convertToWav(compressedBuffer) {
  const decodeCtx = new OfflineAudioContext(1, 1, TARGET_RATE);
  const decoded = await decodeCtx.decodeAudioData(compressedBuffer.slice(0));

  // Resample to 16 kHz mono during render (length scaled to the new rate).
  const frames = Math.max(1, Math.ceil(decoded.duration * TARGET_RATE));
  const wavCtx = new OfflineAudioContext(1, frames, TARGET_RATE);
  const source = wavCtx.createBufferSource();
  source.buffer = decoded;
  source.connect(wavCtx.destination);
  source.start();
  const rendered = await wavCtx.startRendering();

  return encodeWav(rendered.getChannelData(0), TARGET_RATE);
}

function encodeWav(samples, sampleRate) {
  const bitsPerSample = 16;
  const numChannels = 1;
  const byteRate = sampleRate * numChannels * bitsPerSample / 8;
  const blockAlign = numChannels * bitsPerSample / 8;
  const dataSize = samples.length * blockAlign;
  const buffer = new ArrayBuffer(44 + dataSize);
  const view = new DataView(buffer);

  const writeStr = (off, str) => { for (let i = 0; i < str.length; i++) view.setUint8(off + i, str.charCodeAt(i)); };
  writeStr(0, 'RIFF');
  view.setUint32(4, 36 + dataSize, true);
  writeStr(8, 'WAVE');
  writeStr(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);  // PCM
  view.setUint16(22, numChannels, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, byteRate, true);
  view.setUint16(32, blockAlign, true);
  view.setUint16(34, bitsPerSample, true);
  writeStr(36, 'data');
  view.setUint32(40, dataSize, true);

  let offset = 44;
  for (let i = 0; i < samples.length; i++, offset += 2) {
    const s = Math.max(-1, Math.min(1, samples[i]));
    view.setInt16(offset, s < 0 ? s * 0x8000 : s * 0x7FFF, true);
  }
  return buffer;
}
