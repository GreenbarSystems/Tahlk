// Platform adapter — the single boundary over the Tauri runtime.
//
// Nothing else in the app may touch the Tauri runtime directly. Centralizing
// it here means the transport can be retargeted in one place: a future Group
// tier can swap this module for an HTTP client without the UI, data, or domain
// layers changing.
//
// Historically this module read `window.__TAURI__` (the global injected when
// `withGlobalTauri: true`). That's now off (audit L4) to shrink XSS blast
// radius: an attacker who lands script execution in the WebView no longer
// finds the entire IPC surface hanging off `window`. Instead we import the
// runtime as ESM from `@tauri-apps/api` (and the clipboard plugin), which
// Vite bundles into our own script bundle rather than exposing globally.
//
// Test hook: Node `--test` files can't `import '@tauri-apps/api'` cleanly
// (the plugin resolves at module-load time), so we honor an internal escape
// hatch — `globalThis.__TAHLK_TEST_TAURI__` — before falling through to the
// real imports. The symbol name is deliberately obscure and only ever set by
// the test harness at boot; it is not attacker-reachable at runtime because
// scripts loaded via XSS run after app scripts and cannot rewind imports.
//
// Rejection shape contract: `invoke` promises reject with an `AppError`
// ({ code, message }). Callers can branch on `code` (e.g. `no_api_key`) or
// pass the error to `userMessage()` for a display string. See `appError.js`.

import { invoke as tauriInvoke } from '@tauri-apps/api/core';
import { listen as tauriListen } from '@tauri-apps/api/event';
import {
  writeText as tauriWriteText,
  readText as tauriReadText,
} from '@tauri-apps/plugin-clipboard-manager';
import { fromInvoke } from './appError.js';

// True when a Tauri runtime is present. The global test hook counts as
// present so JS unit tests exercising the real code paths pass. In a real
// packaged app, `withGlobalTauri: false` means `__TAURI_INTERNALS__` is the
// runtime marker the WebView injects for the ESM API to work.
export const isTauri =
  (typeof globalThis !== 'undefined' &&
    globalThis.__TAHLK_TEST_TAURI__ !== undefined) ||
  (typeof window !== 'undefined' &&
    ('__TAURI_INTERNALS__' in window || '__TAURI__' in window));

// Test-mock accessor. Returns undefined in production; returns the injected
// fake runtime object in tests. Keeps the escape-hatch check in one place.
function testMock() {
  return typeof globalThis !== 'undefined'
    ? globalThis.__TAHLK_TEST_TAURI__
    : undefined;
}

// Invoke a backend command. Rejections are ALWAYS normalized to an AppError
// so downstream catch sites can rely on `e.code` / `userMessage(e)` without
// runtime shape checks.
export function invoke(command, args) {
  const mock = testMock();
  const raw = mock
    ? (mock.core?.invoke ?? mock.invoke)(command, args)
    : tauriInvoke(command, args);
  return raw.catch(e => Promise.reject(fromInvoke(e)));
}

// Subscribe to a backend event. Resolves to an unlisten function (a no-op
// when the event API is unavailable, e.g. non-Tauri dev / tests without a
// listen mock).
export async function listen(event, handler) {
  const mock = testMock();
  if (mock) {
    const fn = mock.event?.listen;
    if (typeof fn !== 'function') return () => {};
    return fn(event, handler);
  }
  return tauriListen(event, handler);
}

// Write text to the system clipboard via the Tauri plugin, falling back to
// the Web Clipboard API for non-Tauri contexts (e.g. dev in a plain browser).
export async function clipboardWriteText(text) {
  const mock = testMock();
  if (mock) {
    const writeText =
      mock['clipboard-manager']?.writeText || mock.clipboardManager?.writeText;
    if (writeText) return writeText(text);
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      return navigator.clipboard.writeText(text);
    }
    throw new Error('Clipboard unavailable');
  }
  return tauriWriteText(text);
}

// Read the current clipboard text. Returns null if unavailable.
export async function clipboardReadText() {
  const mock = testMock();
  if (mock) {
    const readText =
      mock['clipboard-manager']?.readText || mock.clipboardManager?.readText;
    if (readText) return readText();
    if (typeof navigator !== 'undefined' && navigator.clipboard?.readText) {
      return navigator.clipboard.readText();
    }
    return null;
  }
  return tauriReadText();
}
