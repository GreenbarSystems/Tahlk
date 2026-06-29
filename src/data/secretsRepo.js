// Secrets repository — the API key is write-only across the IPC boundary (set
// and presence-check only; there is no getter). Wrapping the commands keeps the
// UI free of command names and makes the write-only contract explicit.

import { invoke } from '../platform/tauri.js';

export const secretsRepo = {
  hasApiKey:   () => invoke('has_api_key'),
  setApiKey:   key => invoke('set_api_key', { key }),
  clearApiKey: () => invoke('clear_api_key'),
};
