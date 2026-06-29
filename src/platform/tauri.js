// Platform adapter — the single boundary over the injected Tauri runtime.
//
// Nothing else in the app may touch `window.__TAURI__` directly. Centralizing
// it here means the transport can be retargeted in one place: a future Group
// tier can swap this module for an HTTP client without the UI, data, or domain
// layers changing. The global is read lazily (per call) because it is injected
// by the WebView before app scripts run but is absent in tests / plain browsers.

function runtime() {
  return typeof window !== 'undefined' ? window.__TAURI__ : undefined;
}

export const isTauri =
  typeof window !== 'undefined' &&
  ('__TAURI__' in window || '__TAURI_INTERNALS__' in window);

// Invoke a backend command. Mirrors the historical fallback across Tauri global
// shapes so behavior is identical to the previous inline helper.
export function invoke(command, args) {
  const t = runtime();
  if (t?.core?.invoke) return t.core.invoke(command, args);
  if (t?.tauri?.invoke) return t.tauri.invoke(command, args);
  if (typeof t?.invoke === 'function') return t.invoke(command, args);
  return Promise.reject(new Error('Tauri invoke unavailable'));
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
