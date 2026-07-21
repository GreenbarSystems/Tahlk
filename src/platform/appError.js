// Typed error at the IPC boundary — JS side.
//
// The Rust `#[tauri::command]` handlers all return `Result<T, AppError>` and
// the AppError enum serializes to `{ code, message }`. That's what Tauri
// hands to a rejected `invoke()` promise. But three other rejection shapes
// still exist in the wild:
//
//   1. Plain string ("Tauri invoke unavailable", legacy Rust code that
//      returned `Result<T, String>`, unit tests that reject with new Error(...)).
//   2. Any Error subclass (network failures inside the JS layer itself,
//      pre-migration mocks that used `Error('disk full')`).
//   3. `null` / `undefined` (never observed in prod but cheap to guard).
//
// `fromInvoke` normalizes all four into an `AppError` whose `code` is a
// stable machine-readable string and whose `message` remains human-readable.
// Every catch site downstream (`userMessage`, branch-on-`no_api_key`) can
// then rely on the same shape — no runtime typeof/instanceof gymnastics.

/**
 * AppError — mirrors the Rust variant discriminator.
 *
 * `code`   — stable, machine-readable identifier. Callers branch on this.
 * `message`— human-readable diagnostic; safe to show in a toast.
 */
export class AppError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'AppError';
    this.code = code;
  }
}

// Normalize whatever Tauri (or a legacy path) rejected `invoke()` with into
// an AppError. Returning the same instance if it's already one keeps stack
// traces intact for real Rust-side errors.
export function fromInvoke(e) {
  if (e instanceof AppError) return e;

  // Rust-side AppError: { code, message } object.
  if (e && typeof e === 'object' && typeof e.code === 'string') {
    return new AppError(e.code, typeof e.message === 'string' ? e.message : e.code);
  }

  // Legacy Rust `Result<T, String>` — rejects with a bare string. Best we
  // can do is bucket it under `internal` so callers still get a stable code.
  if (typeof e === 'string') {
    return new AppError('internal', e);
  }

  // Anything else that carries a message field (Error subclass, mock reject).
  if (e && typeof e.message === 'string') {
    return new AppError('internal', e.message);
  }

  return new AppError('internal', 'Unknown error');
}

// Map an AppError (or anything `fromInvoke` can normalize) to a
// user-facing message. Keep these strings short — they end up in toasts.
//
// `fallback` is used when the code is one we don't have a specific line for
// (defensive: adding a new Rust variant shouldn't require a JS release).
export function userMessage(err, fallback = 'Something went wrong.') {
  const e = fromInvoke(err);
  switch (e.code) {
    case 'no_api_key':
      return 'No Anthropic API key. Open Settings to add one.';
    case 'baa_required':
      // The Rust gate refuses to generate notes until the provider has
      // confirmed their agreements (BAA + EULA with Greenbar). Point them at
      // Settings; the CTA there is the toggle in the “Agreements” section.
      return 'Confirm your agreements in Settings before generating notes.';
    case 'no_model':
      return 'Transcription model is missing. Reinstall Tahlk to restore it.';
    case 'network':
      return 'Network error. Check your connection and try again.';
    case 'auth_failed':
      return 'Anthropic rejected the API key. Check it in Settings.';
    case 'rate_limited':
      return 'Anthropic rate limit hit. Wait a moment and try again.';
    case 'upstream_api':
      return 'Anthropic returned an error. Try again in a moment.';
    case 'upstream_empty':
      return 'Anthropic returned an empty response. Try again.';
    case 'transcription':
      return 'Transcription failed on this device.';
    case 'invalid_input':
      // The frontend violated an invariant — never blame the user for this.
      return fallback;
    case 'precondition_failed':
      // A rule the provider needs explained: a litigation hold blocking a
      // deletion, a signed note refusing an edit. Rust writes these strings
      // for a clinician, so show them verbatim.
      //
      // These used to arrive as `invalid_input` and hit the branch above, so
      // a provider stopped by a legal hold saw "Delete failed: unknown error"
      // — the app knew precisely why and declined to say.
      return e.message && e.message !== e.code ? e.message : fallback;
    case 'storage':
      return 'Could not read or write local data.';
    case 'internal':
    default:
      // If we have a real message (not just the code), use it; otherwise
      // fall back to the caller-supplied line.
      return e.message && e.message !== e.code ? e.message : fallback;
  }
}
