// Selected LLM vendor + model for note generation — single source of truth for
// what the Settings dropdown offers and what the note-generation path resolves.
//
// The Rust side (src-tauri/src/providers/mod.rs) is the CANONICAL resolver: it
// reads these same KV keys and falls back to the vendor's default model when
// unset, so behavior is unchanged out of the box. This module mirrors the id +
// default constants so the JS Settings UI stays in lockstep with the backend.
//
// Only ONE vendor exists today (Anthropic). The registry below is deliberately
// shaped as a list so adding a vendor is a data edit here plus a new Rust
// module + factory arm — the dropdown wiring is already generic.
//
// This is unrelated to the `provider` (clinician) profile — see data/keys.js.

import { kvGet, kvSet } from '../core/storageBackend.js';
import { keys } from '../data/keys.js';

// Vendor registry. `id` must match `Provider::id()` in the Rust side; `models`
// lists selectable model ids with the first entry treated as that vendor's
// default (kept identical to `Provider::default_model()`).
export const LLM_PROVIDERS = [
  {
    id: 'anthropic',
    label: 'Anthropic',
    models: ['claude-haiku-4-5-20251001'],
  },
];

export const LLM_PROVIDER_DEFAULT = 'anthropic';

function providerById(id) {
  return LLM_PROVIDERS.find(p => p.id === id) || null;
}

// Default model for a vendor id — the first listed model, matching the Rust
// `default_model()` fallback. Returns null for an unknown vendor.
export function defaultModelFor(providerId) {
  const p = providerById(providerId);
  return p ? p.models[0] : null;
}

// Resolve the selected vendor id, defaulting to Anthropic when unset or if a
// stale/unknown id was persisted (mirrors the Rust `unwrap_or(Anthropic)`).
export function getLlmProvider() {
  const v = kvGet(keys.llmProvider());
  return providerById(v) ? v : LLM_PROVIDER_DEFAULT;
}

// Resolve the selected model, defaulting to the current vendor's default model
// when unset (mirrors the Rust `unwrap_or_else(default_model)`).
export function getLlmModel() {
  const v = kvGet(keys.llmModel());
  if (typeof v === 'string' && v.trim()) return v;
  return defaultModelFor(getLlmProvider());
}

export function setLlmProvider(providerId) {
  if (!providerById(providerId)) {
    throw new Error(`Unknown LLM provider: ${providerId}`);
  }
  kvSet(keys.llmProvider(), providerId);
}

export function setLlmModel(model) {
  if (typeof model !== 'string' || !model.trim()) {
    throw new Error('LLM model must be a non-empty string');
  }
  kvSet(keys.llmModel(), model.trim());
}
