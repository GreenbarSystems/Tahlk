// Cloud roster sync — pulls the org's provider list from the server and
// merges it into the local KV roster on each authenticated group-mode startup.
// Uses cloud provider IDs as the local roster ID so invite→accept flows
// automatically land in the switcher on the next sync without manual setup.

import { kvGet, kvSet } from '../core/storageBackend.js';
import { isAuthenticated } from '../core/auth.js';
import { apiFetch } from '../core/api.js';

const ROSTER_KEY = 'note_group_v1::roster';
const ACTIVE_KEY = 'note_group_v1::active_provider';

export async function syncRosterFromCloud() {
  if (!isAuthenticated()) return;

  let res;
  try {
    res = await apiFetch('/api/org/providers');
  } catch {
    return; // offline — keep local roster
  }
  if (!res.ok) return;

  const { providers } = await res.json();
  if (!Array.isArray(providers) || providers.length === 0) return;

  const roster = providers.map(p => ({
    id:          p.id,
    name:        p.name  || p.email,
    email:       p.email,
    credentials: p.credentials || '',
    specialty:   p.specialty   || 'psychiatry',
    role:        p.role,
  }));

  kvSet(ROSTER_KEY, roster);

  // If the previously active provider is no longer in the org, default to first
  const currentActive = kvGet(ACTIVE_KEY);
  if (!roster.find(p => p.id === currentActive)) {
    kvSet(ACTIVE_KEY, roster[0].id);
  }
}
