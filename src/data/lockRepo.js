// Idle-lock PIN repository — the one place that knows the lock command
// names and argument shapes. Mirrors secretsRepo.js: the PIN itself is
// write-only from here (set/verify/clear), never read back — Rust owns the
// hash comparison so the plaintext PIN never needs to round-trip through
// JS state after the moment it's typed.

import { invoke } from '../platform/tauri.js';

export const lockRepo = {
  isPinSet:  () => invoke('lock_pin_is_set'),
  setPin:    pin => invoke('lock_pin_set', { pin }),
  verifyPin: pin => invoke('lock_pin_verify', { pin }),
  clearPin:  () => invoke('lock_pin_clear'),
};
