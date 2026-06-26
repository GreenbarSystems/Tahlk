// Append-only audit-log helper. Stamps actor + timestamp; caps at maxEntries.
// Returns the appended entry so callers can mirror it server-side (Group tier).

import { kvGet, kvSet } from './storageBackend.js';
import { currentUser } from './capabilities.js';
import { nowISO } from '../utils/format.js';

export const MAX_AUDIT_ENTRIES = 5000;

export function appendAudit(key, action, details = {}, maxEntries = MAX_AUDIT_ENTRIES) {
  const log = kvGet(key) || [];
  const u = currentUser();
  const entry = {
    actor: u?.name || 'provider',
    actorId: u?.id || null,
    action,
    timestamp: nowISO(),
    ...details,
  };
  log.push(entry);
  if (log.length > maxEntries) log.splice(0, log.length - maxEntries);
  kvSet(key, log);
  return entry;
}
