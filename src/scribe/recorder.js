// Audio capture via Web Audio API + MediaRecorder.
// Audio chunks are assembled into a WAV blob then persisted to disk
// via the Tauri save_session_audio command. Audio never leaves the device.

import { emit } from '../core/eventBus.js';
import { tauriInvoke } from '../core/storageBackend.js';

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

export async function stopRecording(encounterId) {
  if (!isRecording()) return null;

  return new Promise((resolve, reject) => {
    _mediaRecorder.onstop = async () => {
      clearInterval(_timerInterval);
      _timerInterval = null;

      try {
        const blob = new Blob(_chunks, { type: _mediaRecorder.mimeType });
        const arrayBuffer = await blob.arrayBuffer();
        const wavBuffer = _mediaRecorder.mimeType.includes('wav')
          ? arrayBuffer
          : await convertToWav(arrayBuffer, _stream.getAudioTracks()[0].getSettings());

        const base64 = arrayBufferToBase64(wavBuffer);
        const path = await tauriInvoke('save_session_audio', { encounterId, base64Data: base64 });

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

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

// Minimal WAV header writer — whisper.cpp requires PCM WAV.
// If the browser recorded in a compressed format, we re-encode via AudioContext.
async function convertToWav(compressedBuffer, trackSettings) {
  const audioCtx = new OfflineAudioContext(1, 1, trackSettings.sampleRate || 16000);
  const decoded = await audioCtx.decodeAudioData(compressedBuffer.slice(0));
  const sampleRate = decoded.sampleRate;
  const numChannels = decoded.numberOfChannels;
  const numSamples = decoded.length;

  const wavCtx = new OfflineAudioContext(1, numSamples, sampleRate);
  const source = wavCtx.createBufferSource();
  source.buffer = decoded;
  source.connect(wavCtx.destination);
  source.start();
  const rendered = await wavCtx.startRendering();

  return encodeWav(rendered.getChannelData(0), sampleRate);
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
