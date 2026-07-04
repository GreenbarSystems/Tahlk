// Platform adapter — the single boundary over the injected Tauri runtime.
//
// Nothing else in the app may touch `window.__TAURI__` directly. Centralizing
// it here means the transport can be retargeted in one place: a future Group
// tier can swap this module for an HTTP client without the UI, data, or domain
// layers changing. The global is read lazily (per call) because it is injected
// by the WebView before app scripts run but is absent in tests / plain browsers.
//
// Rejection shape contract: `invoke` promises reject with an `AppError`
// ({ code, message }). Callers can branch on `code` (e.g. `no_api_key`) or
// pass the error to `userMessage()` for a display string. See `appError.js`.

import { fromInvoke } from './appError.js';

function runtime() {
  return typeof window !== 'undefined' ? window.__TAURI__ : undefined;
}

export const isTauri =
  typeof window !== 'undefined' &&
  ('__TAURI__' in window || '__TAURI_INTERNALS__' in window);

// Invoke a backend command. Mirrors the historical fallback across Tauri global
// shapes so behavior is identical to the previous inline helper.
//
// Rejections are ALWAYS normalized to an AppError so downstream catch sites
// can rely on `e.code` / `userMessage(e)` without runtime shape checks.
export function invoke(command, args) {
  const t = runtime();
  const raw =
    t?.core?.invoke ? t.core.invoke(command, args) :
    t?.tauri?.invoke ? t.tauri.invoke(command, args) :
    typeof t?.invoke === 'function' ? t.invoke(command, args) :
    Promise.reject(new Error('Tauri invoke unavailable'));
  return raw.catch(e => Promise.reject(fromInvoke(e)));
}

// Subscribe to a backend event. Resolves to an unlisten function (a no-op when
// the event API is unavailable, e.g. non-Tauri dev).
export async function listen(event, handler) {
  const fn = runtime()?.event?.listen;
  if (typeof fn !== 'function') return () => {};
  return fn(event, handler);
}

// Write text to the system clipboard via the Tauri plugin, falling back to the
// Web Clipboard API.
export async function clipboardWriteText(text) {
  const t = runtime();
  const writeText = t?.['clipboard-manager']?.writeText || t?.clipboardManager?.writeText;
  if (writeText) return writeText(text);
  if (typeof navigator !== 'undefined' && navigator.clipboard) {
    return navigator.clipboard.writeText(text);
  }
  throw new Error('Clipboard unavailable');
}

// Read the current clipboard text. Returns null if unavailable.
export async function clipboardReadText() {
  const t = runtime();
  const readText = t?.['clipboard-manager']?.readText || t?.clipboardManager?.readText;
  if (readText) return readText();
  if (typeof navigator !== 'undefined' && navigator.clipboard?.readText) {
    return navigator.clipboard.readText();
  }
  return null;
}
