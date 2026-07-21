// Auth repository — one place that knows the auth command names and their
// argument shapes. Mirrors lockRepo.js: passwords and recovery codes are
// write-only from JS; Rust owns the crypto and only surfaces derived booleans
// and recovery-code display strings (25-char Crockford base32).

import { invoke } from '../platform/tauri.js';

export const authRepo = {
  // True only when a password has been set on this device.
  isConfigured: () => invoke('auth_is_configured'),

  // First-open: set master password, wrap DEK, write auth_dek_wraps.
  // Returns string[] of 3 recovery code display strings.
  setPassword: password => invoke('auth_set_password', { password }),

  // Subsequent opens: verify password, unwrap DEK (stays in Rust).
  unlockWithPassword: password => invoke('auth_unlock_password', { password }),

  // Forgot-password step 1: verify recovery code (stays in Rust).
  unlockWithRecoveryCode: code => invoke('auth_unlock_recovery', { code }),

  // Forgot-password combined: verify recovery code + set new password atomically.
  // Returns string[] of 3 NEW recovery code display strings (old codes gone).
  resetWithRecoveryCode: (code, new_password) =>
    invoke('auth_reset_with_recovery_code', { code, new_password }),

  // Settings: change the master password (requires knowing the old one).
  changePassword: (old_password, new_password) =>
    invoke('auth_change_password', { old_password, new_password }),

  // Settings: regenerate all three recovery codes (requires current password).
  generateRecoveryCodes: password =>
    invoke('auth_generate_recovery_codes', { password }),

  // Nuclear option: wipe DB + auth_dek_wraps + all keychain entries.
  nukeAndReinstall: () => invoke('auth_nuke_and_reinstall'),
};
